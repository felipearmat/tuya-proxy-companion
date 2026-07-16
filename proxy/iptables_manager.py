"""iptables PREROUTING REDIRECT management for per-camera MQTT interception."""

from __future__ import annotations

import asyncio
import logging

_LOGGER = logging.getLogger(__name__)


class IptablesManager:
    """Manage per-camera iptables PREROUTING REDIRECT rules.

    Each rule redirects TCP traffic from a specific camera IP on camera_mqtt_port
    to proxy_port, transparently routing the camera's cloud MQTT into the MITM proxy.
    Mosquitto still receives all other traffic on camera_mqtt_port normally.
    """

    def __init__(self, camera_mqtt_port: int = 8883) -> None:
        self._from_port = camera_mqtt_port
        self._active: set[tuple[str, int]] = set()  # (cam_ip, to_port)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def add(self, cam_ip: str, to_port: int) -> bool:
        """Add redirect for cam_ip → to_port. Idempotent."""
        args = self._args(cam_ip, to_port)
        exists, _ = await self._run("-C", *args)
        if exists:
            self._active.add((cam_ip, to_port))
            return True
        ok, msg = await self._run("-A", *args)
        if ok:
            self._active.add((cam_ip, to_port))
            _LOGGER.info(
                "iptables: redirect %s:%d→%d added", cam_ip, self._from_port, to_port
            )
        else:
            _LOGGER.error("iptables: failed to add %s→%d: %s", cam_ip, to_port, msg)
        return ok

    async def remove(self, cam_ip: str) -> None:
        """Remove all redirects for cam_ip."""
        for ip, to_port in list(self._active):
            if ip != cam_ip:
                continue
            args = self._args(ip, to_port)
            exists, _ = await self._run("-C", *args)
            if exists:
                ok, msg = await self._run("-D", *args)
                if ok:
                    _LOGGER.info("iptables: redirect %s removed", ip)
                else:
                    _LOGGER.warning("iptables: remove %s failed: %s", ip, msg)
            self._active.discard((ip, to_port))

    async def flush(self) -> None:
        """Remove all managed redirects."""
        for cam_ip, _ in list(self._active):
            await self.remove(cam_ip)

    @property
    def active_rules(self) -> list[dict]:
        return [
            {"cam_ip": ip, "from_port": self._from_port, "to_port": tp}
            for ip, tp in sorted(self._active)
        ]

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _args(self, cam_ip: str, to_port: int) -> tuple[str, ...]:
        return (
            "-s",
            cam_ip,
            "-p",
            "tcp",
            "--dport",
            str(self._from_port),
            "-j",
            "REDIRECT",
            "--to-port",
            str(to_port),
        )

    async def _run(self, action: str, *args: str) -> tuple[bool, str]:
        cmd = ["iptables", "-t", "nat", action, "PREROUTING", *args]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out, err = await asyncio.wait_for(proc.communicate(), timeout=5)
            return proc.returncode == 0, (err or out).decode().strip()
        except FileNotFoundError:
            return False, "iptables binary not found"
        except Exception as exc:
            return False, str(exc)
