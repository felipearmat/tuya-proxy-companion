"""iptables rule management for per-camera MQTT interception and gateway forwarding."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

_LOGGER = logging.getLogger(__name__)


class IptablesManager:
    """Manage per-camera iptables rules.

    PREROUTING REDIRECT: redirects camera's TCP traffic on camera_mqtt_port to
    proxy_port so the MITM proxy can intercept it (works when camera connects to
    this host via DNS rewrite).

    Gateway mode (enable_gateway / disable_gateway): used together with ARP
    spoofing to intercept camera traffic that bypasses DNS. Sets up ip_forward,
    MASQUERADE, and FORWARD DROP on port 8883 to block Tuya cloud MQTT.
    """

    def __init__(self, camera_mqtt_port: int = 8883) -> None:
        self._from_port = camera_mqtt_port
        self._active: set[tuple[str, int]] = set()  # (cam_ip, to_port)
        self._gateway_ips: set[str] = set()

    # ------------------------------------------------------------------
    # PREROUTING REDIRECT (existing behaviour)
    # ------------------------------------------------------------------

    async def add(self, cam_ip: str, to_port: int) -> bool:
        """Add PREROUTING REDIRECT for cam_ip → to_port. Idempotent."""
        args = self._redirect_args(cam_ip, to_port)
        exists, _ = await self._run_nat("-C", "PREROUTING", *args)
        if exists:
            self._active.add((cam_ip, to_port))
            return True
        ok, msg = await self._run_nat("-A", "PREROUTING", *args)
        if ok:
            self._active.add((cam_ip, to_port))
            _LOGGER.info(
                "iptables: REDIRECT %s:%d→%d added", cam_ip, self._from_port, to_port
            )
        else:
            _LOGGER.error(
                "iptables: REDIRECT add failed %s→%d: %s", cam_ip, to_port, msg
            )
        return ok

    async def remove(self, cam_ip: str) -> None:
        """Remove all PREROUTING REDIRECTs for cam_ip."""
        for ip, to_port in list(self._active):
            if ip != cam_ip:
                continue
            args = self._redirect_args(ip, to_port)
            exists, _ = await self._run_nat("-C", "PREROUTING", *args)
            if exists:
                ok, msg = await self._run_nat("-D", "PREROUTING", *args)
                if ok:
                    _LOGGER.info("iptables: REDIRECT %s removed", ip)
                else:
                    _LOGGER.warning("iptables: REDIRECT remove %s failed: %s", ip, msg)
            self._active.discard((ip, to_port))

    async def flush(self) -> None:
        """Remove all managed PREROUTING REDIRECTs and gateway rules."""
        for cam_ip, _ in list(self._active):
            await self.remove(cam_ip)
        for cam_ip in list(self._gateway_ips):
            await self.disable_gateway(cam_ip)

    @property
    def active_rules(self) -> list[dict]:
        return [
            {"cam_ip": ip, "from_port": self._from_port, "to_port": tp}
            for ip, tp in sorted(self._active)
        ]

    # ------------------------------------------------------------------
    # Gateway mode: ip_forward + MASQUERADE + FORWARD DROP port 8883
    # ------------------------------------------------------------------

    async def enable_gateway(self, cam_ip: str) -> bool:
        """Block all internet traffic from cam_ip via the FORWARD chain.

        Called after ARP spoofing routes the camera's traffic through this host.
        Host ip_forward is typically 1 (Docker sets it), so the FORWARD chain is
        active. Dropping all FORWARD from camera blocks every cloud port; port
        8883 is additionally intercepted by the PREROUTING REDIRECT before it
        even reaches the FORWARD chain.
        """
        try:
            ip_fwd = Path("/proc/sys/net/ipv4/ip_forward").read_text().strip()
            _LOGGER.info("ip_forward=%s (host kernel)", ip_fwd)
        except Exception:
            ip_fwd = "unknown"

        # MASQUERADE: kept for future use; effectively unreachable while FORWARD drops all.
        exists, _ = await self._run_nat(
            "-C", "POSTROUTING", "-s", cam_ip, "-j", "MASQUERADE"
        )
        if not exists:
            ok, msg = await self._run_nat(
                "-A", "POSTROUTING", "-s", cam_ip, "-j", "MASQUERADE"
            )
            if not ok:
                _LOGGER.error("iptables: MASQUERADE add failed for %s: %s", cam_ip, msg)

        # Remove legacy per-port rules left by older versions (idempotent).
        old_drop_8883 = ("-s", cam_ip, "-p", "tcp", "--dport", "8883", "-j", "DROP")
        old_accept = ("-s", cam_ip, "-j", "ACCEPT")
        for old_rule in (old_drop_8883, old_accept):
            exists, _ = await self._run_filter("-C", "FORWARD", *old_rule)
            if exists:
                await self._run_filter("-D", "FORWARD", *old_rule)
                _LOGGER.info("iptables: removed legacy FORWARD rule for %s", cam_ip)

        # DROP all FORWARD from camera — blocks every internet port (443, 8883, 8886…).
        # Port 8883 is already redirected to MITM via PREROUTING before reaching here.
        # Insert at position 1 so it wins over any existing generic ACCEPT rules.
        drop_all = ("-s", cam_ip, "-j", "DROP")
        exists, _ = await self._run_filter("-C", "FORWARD", *drop_all)
        if not exists:
            ok, msg = await self._run_filter("-I", "FORWARD", "1", *drop_all)
            if not ok:
                _LOGGER.error(
                    "iptables: FORWARD DROP all failed for %s: %s", cam_ip, msg
                )

        self._gateway_ips.add(cam_ip)
        _LOGGER.info(
            "iptables: gateway mode enabled for %s (all internet blocked, ip_forward=%s)",
            cam_ip,
            ip_fwd,
        )
        return True

    async def disable_gateway(self, cam_ip: str) -> None:
        """Remove FORWARD and MASQUERADE rules for cam_ip."""
        await self._run_nat("-D", "POSTROUTING", "-s", cam_ip, "-j", "MASQUERADE")
        await self._run_filter("-D", "FORWARD", "-s", cam_ip, "-j", "DROP")
        self._gateway_ips.discard(cam_ip)
        _LOGGER.info("iptables: gateway mode disabled for %s", cam_ip)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _redirect_args(self, cam_ip: str, to_port: int) -> tuple[str, ...]:
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

    async def _run_nat(self, action: str, chain: str, *args: str) -> tuple[bool, str]:
        return await self._exec("iptables", "-t", "nat", action, chain, *args)

    async def _run_filter(
        self, action: str, chain: str, *args: str
    ) -> tuple[bool, str]:
        return await self._exec("iptables", action, chain, *args)

    async def _exec(self, *cmd: str) -> tuple[bool, str]:
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

    # Keep backward-compat alias used by old callers
    async def _run(self, action: str, *args: str) -> tuple[bool, str]:
        return await self._run_nat(action, "PREROUTING", *args)
