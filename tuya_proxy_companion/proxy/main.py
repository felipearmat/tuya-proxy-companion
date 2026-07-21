"""Tuya Proxy Companion — HTTP API server + MITM proxy orchestration.

Reads options from /data/options.json (HAOS standard).
Exposes HTTP API on api_port (default 8765) for the eKaza Wizard HA integration.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path

import aiohttp
from aiohttp import web

from .iptables_manager import IptablesManager
from .mitm_proxy import MitmProxy
from .tuya_listener import TuyaLocalListener

_LOGGER = logging.getLogger(__name__)
_OPTIONS_FILE = Path("/data/options.json")
_VERSION = "0.2.0"


def _load_options() -> dict:
    try:
        return json.loads(_OPTIONS_FILE.read_text())
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Frigate / HA event integration
# ---------------------------------------------------------------------------


async def _resolve_frigate_base(session: aiohttp.ClientSession) -> str:
    token = os.environ.get("SUPERVISOR_TOKEN", "")
    if not token:
        return "http://127.0.0.1:5000"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        r = await session.get(
            "http://supervisor/addons",
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=5),
        )
        if r.status == 200:
            data = await r.json()
            for addon in data.get("data", {}).get("addons", []):
                slug = addon.get("slug", "")
                name = addon.get("name", "").lower()
                if "frigate" in slug.lower() or "frigate" in name:
                    info_r = await session.get(
                        f"http://supervisor/addons/{slug}/info",
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=5),
                    )
                    if info_r.status == 200:
                        ip = (await info_r.json()).get("data", {}).get("ip_address")
                        if ip:
                            _LOGGER.debug("Frigate IP resolved: %s", ip)
                            return f"http://{ip}:5000"
    except Exception as exc:
        _LOGGER.debug("Supervisor lookup failed: %s", exc)
    return "http://127.0.0.1:5000"


async def _fire_frigate_motion(slug: str, session: aiohttp.ClientSession) -> None:
    """POST a manual motion event to Frigate for the given camera slug."""
    frigate_base = await _resolve_frigate_base(session)
    url = f"{frigate_base}/api/events/{slug}/motion/create"
    try:
        r = await session.post(
            url,
            json={"duration": 30},
            timeout=aiohttp.ClientTimeout(total=5),
        )
        if r.status == 200:
            _LOGGER.info("Motion event created for %s via Frigate", slug)
        else:
            body = await r.text()
            _LOGGER.debug(
                "Frigate motion event failed %s (%d): %s", slug, r.status, body
            )
    except Exception as exc:
        _LOGGER.warning("Frigate motion POST failed for %s: %s", slug, exc)


# ---------------------------------------------------------------------------
# Application state
# ---------------------------------------------------------------------------


class CompanionApp:
    def __init__(self, opts: dict) -> None:
        self._proxy_port: int = int(opts.get("proxy_port", 18883))
        self._camera_mqtt_port: int = int(opts.get("camera_mqtt_port", 8883))
        self._api_port: int = int(opts.get("api_port", 8765))
        self._session: aiohttp.ClientSession | None = None
        self._iptables = IptablesManager(camera_mqtt_port=self._camera_mqtt_port)
        self._arp_spoof = ArpSpoofManager()
        self._proxy = MitmProxy(on_motion=self._on_motion)
        self._listeners: dict[str, TuyaLocalListener] = {}
        self._cameras: list[dict] = []

    async def _on_motion(self, slug: str) -> None:
        if self._session:
            await _fire_frigate_motion(slug, self._session)

    async def startup(self) -> None:
        self._session = aiohttp.ClientSession()
        asyncio.get_event_loop().create_task(self._start_proxy_with_retry())

    async def _start_proxy_with_retry(self) -> None:
        for attempt in range(1, 7):
            ok = await self._proxy.start(self._proxy_port)
            if ok:
                _LOGGER.info(
                    "Companion ready — proxy on :%d, API on :%d",
                    self._proxy_port,
                    self._api_port,
                )
                return
            _LOGGER.warning(
                "Proxy failed to start on :%d (attempt %d/6), retrying in 10s",
                self._proxy_port,
                attempt,
            )
            await asyncio.sleep(10)
        _LOGGER.error("Proxy could not start on :%d after 6 attempts", self._proxy_port)

    async def shutdown(self) -> None:
        await self._proxy.stop()
        await self._arp_spoof.stop_all()
        await self._iptables.flush()
        for listener in list(self._listeners.values()):
            await listener.stop()
        self._listeners.clear()
        if self._session:
            await self._session.close()

    async def apply_cameras(self, cameras: list[dict]) -> None:
        self._cameras = cameras
        self._proxy.update_cameras(cameras)

        # Reconcile iptables + ARP spoof: add rules for proxy-enabled cameras, remove for others
        enabled_ips = {
            c["ip"] for c in cameras if c.get("proxy_enabled") and c.get("ip")
        }
        active_ips = {r["cam_ip"] for r in self._iptables.active_rules}
        for ip in enabled_ips - active_ips:
            await self._iptables.add(ip, self._proxy_port)
            await self._iptables.enable_gateway(ip)
            await self._arp_spoof.start(ip)
        for ip in active_ips - enabled_ips:
            await self._arp_spoof.stop(ip)
            await self._iptables.disable_gateway(ip)
            await self._iptables.remove(ip)

        # Reconcile local Tuya listeners: start for proxy-enabled cameras with credentials
        desired = {
            c["slug"]: c
            for c in cameras
            if c.get("proxy_enabled")
            and c.get("device_id")
            and c.get("local_key")
            and c.get("ip")
        }
        current_slugs = set(self._listeners)

        for slug in current_slugs - set(desired):
            await self._listeners.pop(slug).stop()

        for slug, cam in desired.items():
            if slug not in current_slugs:
                listener = TuyaLocalListener(
                    slug=slug,
                    ip=cam["ip"],
                    device_id=cam["device_id"],
                    local_key=cam["local_key"],
                    on_motion=self._on_motion,
                )
                self._listeners[slug] = listener
                listener.start()

    def status(self) -> dict:
        return {
            "version": _VERSION,
            "proxy_running": self._proxy.is_running(),
            "proxy_port": self._proxy_port,
            "camera_mqtt_port": self._camera_mqtt_port,
            "cameras": self._cameras,
            "iptables_rules": self._iptables.active_rules,
            "local_listeners": [
                {"slug": slug, "running": lst.is_running}
                for slug, lst in self._listeners.items()
            ],
        }


# ---------------------------------------------------------------------------
# HTTP handlers
# ---------------------------------------------------------------------------


def make_app(companion: CompanionApp) -> web.Application:
    app = web.Application()

    async def handle_status(request: web.Request) -> web.Response:
        return web.json_response(companion.status())

    async def handle_cameras(request: web.Request) -> web.Response:
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "invalid JSON"}, status=400)
        cameras = body.get("cameras", [])
        if not isinstance(cameras, list):
            return web.json_response({"error": "'cameras' must be a list"}, status=400)
        await companion.apply_cameras(cameras)
        return web.json_response({"ok": True, "count": len(cameras)})

    async def handle_proxy_start(request: web.Request) -> web.Response:
        if companion._proxy.is_running():
            return web.json_response({"ok": True, "already_running": True})
        ok = await companion._proxy.start(companion._proxy_port)
        return web.json_response({"ok": ok})

    async def handle_proxy_stop(request: web.Request) -> web.Response:
        await companion._proxy.stop()
        await companion._iptables.flush()
        return web.json_response({"ok": True})

    app.router.add_get("/status", handle_status)
    app.router.add_post("/cameras", handle_cameras)
    app.router.add_post("/proxy/start", handle_proxy_start)
    app.router.add_post("/proxy/stop", handle_proxy_stop)

    return app


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


async def main() -> None:
    log_level = os.environ.get("LOG_LEVEL", "info").upper()
    logging.basicConfig(
        level=getattr(logging, log_level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    opts = _load_options()
    # Environment overrides (from run.sh)
    for key, env in (
        ("proxy_port", "PROXY_PORT"),
        ("camera_mqtt_port", "CAMERA_MQTT_PORT"),
        ("api_port", "API_PORT"),
    ):
        if env in os.environ:
            opts[key] = int(os.environ[env])

    companion = CompanionApp(opts)
    await companion.startup()

    app = make_app(companion)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", companion._api_port)
    await site.start()

    _LOGGER.info("Companion API listening on :%d", companion._api_port)

    try:
        await asyncio.Event().wait()
    finally:
        await companion.shutdown()
        await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
