"""MITM TLS proxy: intercepts camera Tuya MQTT traffic, fires motion events to HA.

No Home Assistant dependencies — runs standalone inside the companion add-on.
Motion events are reported by calling the on_motion callback provided at startup.
"""

from __future__ import annotations

import asyncio
import json
import logging
import ssl
import struct
from collections.abc import Awaitable, Callable
from typing import NamedTuple

from .cert_store import get_or_create_cert

_LOGGER = logging.getLogger(__name__)

_ALARM_DP = 185
_UPSTREAM_PORT = 8883  # Real Tuya cloud MQTT port


class CameraEntry(NamedTuple):
    slug: str
    ip: str


class MitmProxy:
    """MITM TLS proxy that intercepts Tuya MQTT and fires motion callbacks.

    Listens on proxy_port. Cameras reach it via iptables PREROUTING REDIRECT
    from port 8883 → proxy_port. Known camera IPs get intercept-only handling
    (no upstream relay → cuts SmartLife). Unknown IPs get transparent relay.
    """

    def __init__(self, on_motion: Callable[[str], Awaitable[None]]) -> None:
        self._on_motion = on_motion
        self._server: asyncio.Server | None = None
        self._cameras: dict[str, CameraEntry] = {}  # ip → entry
        self._sni_map: dict[int, str] = {}  # id(ssl_obj) → SNI domain
        self._port: int = 18883

    @property
    def port(self) -> int:
        return self._port

    @property
    def camera_ips(self) -> list[str]:
        return list(self._cameras)

    def is_running(self) -> bool:
        return self._server is not None

    def update_cameras(self, cameras: list[dict]) -> None:
        self._cameras = {
            c["ip"]: CameraEntry(slug=c["slug"], ip=c["ip"])
            for c in cameras
            if c.get("proxy_enabled") and c.get("ip")
        }

    async def start(self, port: int) -> bool:
        if self._server is not None:
            return True
        self._port = port
        ssl_ctx = await asyncio.get_event_loop().run_in_executor(
            None, self._build_ssl_ctx
        )
        if ssl_ctx is None:
            return False
        try:
            self._server = await asyncio.start_server(
                self._handle, host="0.0.0.0", port=port, ssl=ssl_ctx
            )
            _LOGGER.info("MITM proxy listening on :%d", port)
            return True
        except OSError as exc:
            _LOGGER.error("MITM proxy cannot bind :%d — %s", port, exc)
            return False

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
            _LOGGER.info("MITM proxy stopped")

    # ------------------------------------------------------------------
    # SSL context
    # ------------------------------------------------------------------

    def _build_ssl_ctx(self) -> ssl.SSLContext | None:
        try:
            cert, key = get_or_create_cert("ekaza-proxy.local")
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key)
            ctx.set_servername_callback(self._sni_cb)
            return ctx
        except Exception as exc:
            _LOGGER.error("SSL context error: %s", exc)
            return None

    def _sni_cb(
        self,
        ssl_obj: ssl.SSLObject,
        server_name: str | None,
        _ctx: ssl.SSLContext,
    ) -> None:
        if not server_name:
            return
        self._sni_map[id(ssl_obj)] = server_name
        try:
            cert, key = get_or_create_cert(server_name)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key)
            ssl_obj.context = ctx
        except Exception as exc:
            _LOGGER.warning("SNI callback failed for %s: %s", server_name, exc)

    # ------------------------------------------------------------------
    # Connection dispatch
    # ------------------------------------------------------------------

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        peer_ip = peer[0] if peer else "unknown"
        ssl_obj = writer.transport.get_extra_info("ssl_object")
        domain = self._sni_map.pop(id(ssl_obj), None)

        if not domain:
            _LOGGER.debug("No SNI from %s — dropping", peer_ip)
            writer.close()
            return

        cam = self._cameras.get(peer_ip)
        _LOGGER.info(
            "Connection from %s → %s (camera: %s)",
            peer_ip,
            domain,
            cam.slug if cam else "unknown",
        )

        if cam:
            await self._intercept_only(reader, writer, cam)
        else:
            await self._transparent_relay(reader, writer, domain)

    # ------------------------------------------------------------------
    # Intercept-only (blocks SmartLife, fires motion events)
    # ------------------------------------------------------------------

    async def _intercept_only(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        cam: CameraEntry,
    ) -> None:
        remainder = b""
        try:
            while True:
                try:
                    data = await asyncio.wait_for(reader.read(4096), timeout=120)
                except asyncio.TimeoutError:
                    break
                if not data:
                    break
                remainder = await self._inspect(remainder + data, cam)
        finally:
            try:
                writer.close()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Transparent relay (unknown cameras → real Tuya upstream)
    # ------------------------------------------------------------------

    async def _transparent_relay(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        domain: str,
    ) -> None:
        try:
            upstream_ctx = ssl.create_default_context()
            ur, uw = await asyncio.wait_for(
                asyncio.open_connection(domain, _UPSTREAM_PORT, ssl=upstream_ctx),
                timeout=10,
            )
        except Exception as exc:
            _LOGGER.warning("Upstream %s unreachable: %s", domain, exc)
            writer.close()
            return
        try:
            await asyncio.gather(self._pipe(reader, uw), self._pipe(ur, writer))
        except Exception:
            pass
        finally:
            for w in (writer, uw):
                try:
                    w.close()
                except Exception:
                    pass

    async def _pipe(self, r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        while True:
            try:
                data = await asyncio.wait_for(r.read(4096), timeout=120)
            except asyncio.TimeoutError:
                break
            if not data:
                break
            w.write(data)
            try:
                await w.drain()
            except Exception:
                break

    # ------------------------------------------------------------------
    # MQTT inspection
    # ------------------------------------------------------------------

    async def _inspect(self, buf: bytes, cam: CameraEntry) -> bytes:
        packets, remainder = _parse_mqtt_packets(buf)
        for msg_type, flags, payload in packets:
            if msg_type == 3:  # PUBLISH
                result = _decode_publish(flags, payload)
                if result:
                    topic, body = result
                    _LOGGER.debug(
                        "PUBLISH cam=%s topic=%s len=%d", cam.slug, topic, len(body)
                    )
                    if _has_alarm_dp(body):
                        _LOGGER.info("Motion detected on %s", cam.slug)
                        asyncio.create_task(self._fire(cam.slug))
        return remainder

    async def _fire(self, slug: str) -> None:
        try:
            await self._on_motion(slug)
        except Exception as exc:
            _LOGGER.warning("on_motion callback failed for %s: %s", slug, exc)


# ---------------------------------------------------------------------------
# MQTT wire-protocol helpers
# ---------------------------------------------------------------------------


def _parse_mqtt_packets(buf: bytes) -> tuple[list[tuple[int, int, bytes]], bytes]:
    packets: list[tuple[int, int, bytes]] = []
    offset = 0
    while offset < len(buf):
        if offset + 1 >= len(buf):
            break
        first_byte = buf[offset]
        msg_type = (first_byte >> 4) & 0xF
        flags = first_byte & 0xF
        multiplier, remaining_len, i = 1, 0, offset + 1
        while i < len(buf) and i < offset + 5:
            byte = buf[i]
            remaining_len += (byte & 0x7F) * multiplier
            multiplier *= 128
            i += 1
            if not (byte & 0x80):
                break
        else:
            break
        header_len = i - offset
        total = header_len + remaining_len
        if offset + total > len(buf):
            break
        payload = buf[offset + header_len : offset + total]
        packets.append((msg_type, flags, payload))
        offset += total
    return packets, buf[offset:]


def _decode_publish(flags: int, payload: bytes) -> tuple[str, bytes] | None:
    try:
        if len(payload) < 2:
            return None
        topic_len = struct.unpack(">H", payload[:2])[0]
        if len(payload) < 2 + topic_len:
            return None
        topic = payload[2 : 2 + topic_len].decode("utf-8", errors="ignore")
        body_start = 2 + topic_len
        if ((flags >> 1) & 0x3) > 0:
            body_start += 2
        return topic, payload[body_start:]
    except Exception:
        return None


def _has_alarm_dp(body: bytes) -> bool:
    """Return True if the payload contains Tuya alarm DP 185."""
    try:
        text = body.decode("utf-8", errors="ignore").strip()
        if text.startswith("{"):
            data = json.loads(text)
            dps = data.get("dps") or data.get("data", {}).get("dps") or {}
            if str(_ALARM_DP) in dps or _ALARM_DP in dps:
                return True
    except Exception:
        pass
    # Embedded JSON in binary wrapper
    try:
        start = body.find(b'{"')
        if start >= 0:
            fragment = body[start:].decode("utf-8", errors="ignore")
            depth = end = 0
            for idx, ch in enumerate(fragment):
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        end = idx + 1
                        break
            if end:
                data = json.loads(fragment[:end])
                dps = data.get("dps") or {}
                if str(_ALARM_DP) in dps or _ALARM_DP in dps:
                    return True
    except Exception:
        pass
    return False
