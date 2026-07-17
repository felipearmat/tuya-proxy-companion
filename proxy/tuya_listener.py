"""Local Tuya protocol listener — detects motion from camera DP 212 over LAN.

Maintains a persistent TCP connection to the camera (Tuya local protocol,
port 6668). When DP 212 (ipc_motion alarm payload) fires, calls on_motion.
Error-914 heartbeat/session messages are silently skipped — they are not DP
updates and cannot be decrypted with the static local_key.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
from collections.abc import Awaitable, Callable

_LOGGER = logging.getLogger(__name__)

# DP 212 carries a base64-encoded JSON payload on eKaza EKRW-T5293.
# The payload has {"cmd": "ipc_motion", "alarm": true, ...} on motion events.
_ALARM_DP = 212
_RECONNECT_DELAY = 10
_SOCKET_TIMEOUT = 30  # long enough to receive heartbeats between events

try:
    import tinytuya  # noqa: F401 -- probes availability only; lazy-imported in _listen()

    _TINYTUYA_OK = True
except ImportError:
    _TINYTUYA_OK = False


class TuyaLocalListener:
    """Persistent local Tuya listener for a single camera.

    Runs tinytuya's blocking I/O in a thread executor so the asyncio event
    loop is never blocked. Auto-reconnects after any connection failure.
    """

    def __init__(
        self,
        slug: str,
        ip: str,
        device_id: str,
        local_key: str,
        on_motion: Callable[[str], Awaitable[None]],
    ) -> None:
        self._slug = slug
        self._ip = ip
        self._device_id = device_id
        self._local_key = local_key
        self._on_motion = on_motion
        self._task: asyncio.Task | None = None
        self._running = False

    @property
    def slug(self) -> str:
        return self._slug

    @property
    def is_running(self) -> bool:
        return self._running and self._task is not None and not self._task.done()

    def start(self) -> None:
        if not _TINYTUYA_OK:
            _LOGGER.error(
                "tinytuya not installed — local listener unavailable for %s", self._slug
            )
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())
        _LOGGER.info("Local Tuya listener started for %s (%s)", self._slug, self._ip)

    async def stop(self) -> None:
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        _LOGGER.info("Local Tuya listener stopped for %s", self._slug)

    async def _loop(self) -> None:
        loop = asyncio.get_event_loop()
        while self._running:
            try:
                await loop.run_in_executor(None, self._listen, loop)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                _LOGGER.warning(
                    "Local Tuya %s disconnected (%s) — retrying in %ds",
                    self._slug,
                    exc,
                    _RECONNECT_DELAY,
                )
            if self._running:
                await asyncio.sleep(_RECONNECT_DELAY)

    def _listen(self, loop: asyncio.AbstractEventLoop) -> None:
        import tinytuya

        device = tinytuya.Device(
            dev_id=self._device_id,
            address=self._ip,
            local_key=self._local_key,
            version=3.5,
        )
        device.socket_persistent = True
        device.timeout = _SOCKET_TIMEOUT

        _LOGGER.debug("Local Tuya: opening connection to %s", self._ip)
        device.status()  # triggers TCP connect + protocol 3.5 key exchange
        _LOGGER.info("Local Tuya: connected to %s", self._slug)

        while self._running:
            data = device.receive()
            if not self._running:
                break
            if not isinstance(data, dict):
                continue

            # Err 914 = heartbeat/session message that can't be decrypted with
            # the static local_key — these are expected and safe to skip.
            if data.get("Err") == "914":
                continue

            dps = data.get("dps") or data.get("data", {}).get("dps") or {}
            if not dps:
                continue

            _LOGGER.debug(
                "Local Tuya: DP update from %s: keys=%s", self._slug, list(dps)
            )

            alarm_val = dps.get(str(_ALARM_DP)) or dps.get(_ALARM_DP)
            if not alarm_val:
                continue

            # DP 212 value is a base64-encoded JSON; parse to confirm it's an alarm.
            is_alarm = False
            if isinstance(alarm_val, str):
                try:
                    payload = json.loads(base64.b64decode(alarm_val).decode())
                    _LOGGER.info(
                        "Local Tuya: DP%d payload from %s: cmd=%s alarm=%s",
                        _ALARM_DP,
                        self._slug,
                        payload.get("cmd"),
                        payload.get("alarm"),
                    )
                    is_alarm = (
                        bool(payload.get("alarm")) or payload.get("cmd") == "ipc_motion"
                    )
                except Exception:
                    # If we can't parse it, treat any non-empty value as alarm.
                    is_alarm = True
            else:
                is_alarm = bool(alarm_val)

            if is_alarm:
                _LOGGER.info(
                    "Motion detected (local Tuya DP%d) on %s", _ALARM_DP, self._slug
                )
                asyncio.run_coroutine_threadsafe(self._on_motion(self._slug), loop)
