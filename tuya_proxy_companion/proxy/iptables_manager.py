"""iptables rule management for per-camera MQTT interception and gateway forwarding."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

_LOGGER = logging.getLogger(__name__)

# Tuya cloud MQTT runs on these ports; all are intercepted by PREROUTING REDIRECT.
_MQTT_INTERCEPT_PORTS = (8883, 8886, 443)


class IptablesManager:
    """Manage per-camera iptables rules.

    PREROUTING REDIRECT: redirects camera's TCP traffic on the configured MQTT
    port (and additional MQTT ports in gateway mode) to proxy_port so the MITM
    proxy can intercept cloud MQTT.

    Gateway mode (enable_gateway / disable_gateway): used together with ARP
    spoofing to intercept camera traffic that bypasses DNS. Redirects all known
    Tuya MQTT ports (8883, 8886, 443) to the MITM proxy and allows all other
    internet traffic so the camera can reach NTP, firmware servers, etc.
    """

    def __init__(self, camera_mqtt_port: int = 8883, proxy_port: int = 18883) -> None:
        self._from_port = camera_mqtt_port
        self._proxy_port = proxy_port
        self._active: set[tuple[str, int]] = set()  # (cam_ip, to_port)
        self._gateway_ips: set[str] = set()

    # ------------------------------------------------------------------
    # PREROUTING REDIRECT (primary port only — add() called by apply_cameras)
    # ------------------------------------------------------------------

    async def add(self, cam_ip: str, to_port: int) -> bool:
        """Add PREROUTING REDIRECT for cam_ip → to_port. Idempotent."""
        args = self._redirect_args(cam_ip, self._from_port, to_port)
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
            args = self._redirect_args(ip, self._from_port, to_port)
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

    @property
    def gateway_ips(self) -> frozenset[str]:
        return frozenset(self._gateway_ips)

    # ------------------------------------------------------------------
    # Gateway mode: PREROUTING intercept on MQTT ports + FORWARD ACCEPT rest
    # ------------------------------------------------------------------

    async def enable_gateway(self, cam_ip: str) -> bool:
        """Intercept Tuya MQTT ports and allow other internet traffic for cam_ip.

        Called after ARP spoofing routes the camera's traffic through this host.
        Redirects ports 8883, 8886, and 443 to the MITM proxy so the camera's
        MQTT connections fail at the TLS layer. All other traffic is forwarded
        normally so the camera can reach NTP, firmware servers, etc. — this
        keeps local DP212 reporting alive without enabling cloud notifications.
        """
        try:
            ip_fwd = Path("/proc/sys/net/ipv4/ip_forward").read_text().strip()
            _LOGGER.info("ip_forward=%s (host kernel)", ip_fwd)
        except Exception:
            ip_fwd = "unknown"

        # MASQUERADE: rewrite src IP on forwarded packets so replies come back.
        exists, _ = await self._run_nat(
            "-C", "POSTROUTING", "-s", cam_ip, "-j", "MASQUERADE"
        )
        if not exists:
            ok, msg = await self._run_nat(
                "-A", "POSTROUTING", "-s", cam_ip, "-j", "MASQUERADE"
            )
            if not ok:
                _LOGGER.error("iptables: MASQUERADE add failed for %s: %s", cam_ip, msg)

        # Remove legacy rules left by v0.2.9 and v0.3.0 (idempotent).
        legacy = [
            ("-s", cam_ip, "-p", "tcp", "--dport", "8883", "-j", "DROP"),  # v0.2.9
            ("-s", cam_ip, "-j", "ACCEPT"),  # v0.2.9
            ("-s", cam_ip, "-j", "DROP"),  # v0.3.0 drop-all
        ]
        for old_rule in legacy:
            exists, _ = await self._run_filter("-C", "FORWARD", *old_rule)
            if exists:
                await self._run_filter("-D", "FORWARD", *old_rule)
                _LOGGER.info("iptables: removed legacy FORWARD rule for %s", cam_ip)

        # PREROUTING REDIRECT for extra MQTT ports (port 8883 handled by add()).
        for port in _MQTT_INTERCEPT_PORTS:
            if port == self._from_port:
                continue  # already added by add()
            args = self._redirect_args(cam_ip, port, self._proxy_port)
            exists, _ = await self._run_nat("-C", "PREROUTING", *args)
            if not exists:
                ok, msg = await self._run_nat("-A", "PREROUTING", *args)
                if ok:
                    _LOGGER.info(
                        "iptables: REDIRECT %s:%d→%d added",
                        cam_ip,
                        port,
                        self._proxy_port,
                    )
                else:
                    _LOGGER.error(
                        "iptables: REDIRECT %s:%d failed: %s", cam_ip, port, msg
                    )

        # FORWARD DROP for MQTT ports: belt-and-suspenders in case PREROUTING
        # is bypassed (e.g. packets already in ESTABLISHED state before spoof).
        # Insert at position 1 so these win before the rules below.
        for port in _MQTT_INTERCEPT_PORTS:
            drop_args = ("-s", cam_ip, "-p", "tcp", "--dport", str(port), "-j", "DROP")
            exists, _ = await self._run_filter("-C", "FORWARD", *drop_args)
            if not exists:
                ok, msg = await self._run_filter("-I", "FORWARD", "1", *drop_args)
                if not ok:
                    _LOGGER.error(
                        "iptables: FORWARD DROP %d failed for %s: %s", port, cam_ip, msg
                    )

        # FORWARD DROP TCP port 80 (plain HTTP — no legitimate cloud data path).
        http_drop = ("-s", cam_ip, "-p", "tcp", "--dport", "80", "-j", "DROP")
        exists, _ = await self._run_filter("-C", "FORWARD", *http_drop)
        if not exists:
            await self._run_filter("-A", "FORWARD", *http_drop)

        # FORWARD ACCEPT UDP DNS (53) and NTP (123) — camera needs these to
        # function; all other UDP (WebRTC DTLS, STUN/TURN, QUIC) is dropped.
        for udp_port in (53, 123):
            udp_accept = (
                "-s",
                cam_ip,
                "-p",
                "udp",
                "--dport",
                str(udp_port),
                "-j",
                "ACCEPT",
            )
            exists, _ = await self._run_filter("-C", "FORWARD", *udp_accept)
            if not exists:
                await self._run_filter("-A", "FORWARD", *udp_accept)

        # FORWARD DROP all other UDP from camera.
        udp_drop = ("-s", cam_ip, "-p", "udp", "-j", "DROP")
        exists, _ = await self._run_filter("-C", "FORWARD", *udp_drop)
        if not exists:
            await self._run_filter("-A", "FORWARD", *udp_drop)

        # FORWARD ACCEPT remaining TCP so the camera can make cloud connection
        # attempts on non-standard ports — these keep DP212 alive (camera stays
        # in "reconnecting" state rather than going fully offline).
        accept_args = ("-s", cam_ip, "-p", "tcp", "-j", "ACCEPT")
        exists, _ = await self._run_filter("-C", "FORWARD", *accept_args)
        if not exists:
            await self._run_filter("-A", "FORWARD", *accept_args)

        self._gateway_ips.add(cam_ip)
        _LOGGER.info(
            "iptables: gateway mode enabled for %s "
            "(MQTT %s → MITM; UDP blocked except DNS/NTP; HTTP blocked; ip_forward=%s)",
            cam_ip,
            "/".join(str(p) for p in _MQTT_INTERCEPT_PORTS),
            ip_fwd,
        )
        return True

    async def disable_gateway(self, cam_ip: str) -> None:
        """Remove FORWARD, MASQUERADE, and extra PREROUTING rules for cam_ip."""
        await self._run_nat("-D", "POSTROUTING", "-s", cam_ip, "-j", "MASQUERADE")

        # Remove extra PREROUTING REDIRECTs added by enable_gateway.
        for port in _MQTT_INTERCEPT_PORTS:
            if port == self._from_port:
                continue
            args = self._redirect_args(cam_ip, port, self._proxy_port)
            await self._run_nat("-D", "PREROUTING", *args)

        # Remove per-port FORWARD DROPs (MQTT ports + HTTP).
        for port in _MQTT_INTERCEPT_PORTS:
            await self._run_filter(
                "-D",
                "FORWARD",
                "-s",
                cam_ip,
                "-p",
                "tcp",
                "--dport",
                str(port),
                "-j",
                "DROP",
            )
        await self._run_filter(
            "-D", "FORWARD", "-s", cam_ip, "-p", "tcp", "--dport", "80", "-j", "DROP"
        )

        # Remove UDP rules (DNS/NTP ACCEPTs + blanket DROP).
        for udp_port in (53, 123):
            await self._run_filter(
                "-D",
                "FORWARD",
                "-s",
                cam_ip,
                "-p",
                "udp",
                "--dport",
                str(udp_port),
                "-j",
                "ACCEPT",
            )
        await self._run_filter("-D", "FORWARD", "-s", cam_ip, "-p", "udp", "-j", "DROP")

        # Remove TCP FORWARD ACCEPT (remaining traffic).
        await self._run_filter(
            "-D", "FORWARD", "-s", cam_ip, "-p", "tcp", "-j", "ACCEPT"
        )

        self._gateway_ips.discard(cam_ip)
        _LOGGER.info("iptables: gateway mode disabled for %s", cam_ip)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _redirect_args(
        self, cam_ip: str, from_port: int, to_port: int
    ) -> tuple[str, ...]:
        return (
            "-s",
            cam_ip,
            "-p",
            "tcp",
            "--dport",
            str(from_port),
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
