"""ARP spoofing to intercept camera outbound traffic through this host.

Sends periodic ARP replies to the camera claiming this host's MAC is the
router's MAC. Combined with ip_forward + iptables FORWARD DROP on port 8883,
this blocks the camera's Tuya cloud MQTT while allowing all other traffic.

Requires CAP_NET_RAW (add NET_RAW to config.json privileged list).
"""

from __future__ import annotations

import asyncio
import fcntl
import logging
import socket
import struct
import subprocess

_LOGGER = logging.getLogger(__name__)

_ARP_INTERVAL = 8  # seconds between poison replies


def _get_default_gateway() -> tuple[str, str] | None:
    """Return (gateway_ip, interface_name) from the kernel default route."""
    try:
        out = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.strip()
        # "default via 192.168.x.1 dev eth0 ..."
        parts = out.split()
        if "via" in parts and "dev" in parts:
            gw = parts[parts.index("via") + 1]
            dev = parts[parts.index("dev") + 1]
            return gw, dev
    except Exception as exc:
        _LOGGER.warning("get_default_gateway: %s", exc)
    return None


def _get_neighbor_mac(ip: str) -> bytes | None:
    """Return MAC bytes for an IP from the kernel ARP cache, or None."""
    try:
        out = subprocess.run(
            ["ip", "neigh", "show", ip],
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.strip()
        # "192.168.x.y dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
        parts = out.split()
        if "lladdr" in parts:
            mac_str = parts[parts.index("lladdr") + 1]
            return bytes(int(b, 16) for b in mac_str.split(":"))
    except Exception:
        pass
    return None


def _get_iface_mac(iface: str) -> bytes | None:
    """Return MAC bytes for a local network interface."""
    SIOCGIFHWADDR = 0x8927
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            info = fcntl.ioctl(
                s.fileno(), SIOCGIFHWADDR, struct.pack("256s", iface[:15].encode())
            )
            return info[18:24]
        finally:
            s.close()
    except Exception as exc:
        _LOGGER.warning("get_iface_mac(%s): %s", iface, exc)
    return None


def _send_arp_reply(
    iface: str,
    sender_ip: str,
    sender_mac: bytes,
    target_ip: str,
    target_mac: bytes,
) -> None:
    """Send one ARP reply: 'sender_ip is at sender_mac' → target."""
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
        try:
            s.bind((iface, 0))
            # Ethernet: dst=target_mac, src=sender_mac, ethertype=0x0806 (ARP)
            eth = struct.pack("!6s6sH", target_mac, sender_mac, 0x0806)
            # ARP reply: hw_type=1(Ethernet), proto=0x0800(IPv4), hw_size=6, proto_size=4, op=2
            arp = struct.pack(
                "!HHBBH6s4s6s4s",
                1,
                0x0800,
                6,
                4,
                2,
                sender_mac,
                socket.inet_aton(sender_ip),
                target_mac,
                socket.inet_aton(target_ip),
            )
            s.send(eth + arp)
        finally:
            s.close()
    except Exception as exc:
        _LOGGER.warning("ARP send failed: %s", exc)


class ArpSpoofManager:
    """Sends periodic ARP replies to route camera traffic through this host.

    For each camera: sends "router_ip is at host_mac" to the camera every
    _ARP_INTERVAL seconds. On stop, sends the correct router_mac to restore.
    """

    def __init__(self) -> None:
        self._tasks: dict[str, asyncio.Task] = {}  # cam_ip → task
        self._cam_macs: dict[str, bytes] = {}  # cam_ip → mac
        self._router_ip: str | None = None
        self._router_mac: bytes | None = None
        self._iface: str | None = None
        self._host_mac: bytes | None = None

    def _init_route_info(self) -> bool:
        if self._router_ip and self._router_mac:
            return True
        info = _get_default_gateway()
        if not info:
            _LOGGER.error("ArpSpoof: no default gateway found")
            return False
        self._router_ip, self._iface = info
        self._host_mac = _get_iface_mac(self._iface)
        if not self._host_mac:
            _LOGGER.error("ArpSpoof: cannot read host MAC for %s", self._iface)
            return False
        # Populate ARP cache for router if empty
        self._router_mac = _get_neighbor_mac(self._router_ip)
        if not self._router_mac:
            subprocess.run(["ping", "-c1", "-W1", self._router_ip], capture_output=True)
            self._router_mac = _get_neighbor_mac(self._router_ip)
        if not self._router_mac:
            _LOGGER.error("ArpSpoof: cannot get router MAC for %s", self._router_ip)
            return False
        _LOGGER.info(
            "ArpSpoof: gateway=%s mac=%s iface=%s",
            self._router_ip,
            ":".join(f"{b:02x}" for b in self._router_mac),
            self._iface,
        )
        return True

    def _resolve_cam_mac(self, cam_ip: str) -> bytes | None:
        mac = _get_neighbor_mac(cam_ip)
        if not mac:
            subprocess.run(["ping", "-c1", "-W1", cam_ip], capture_output=True)
            mac = _get_neighbor_mac(cam_ip)
        return mac

    async def start(self, cam_ip: str) -> None:
        if cam_ip in self._tasks:
            return
        if not self._init_route_info():
            return
        cam_mac = self._resolve_cam_mac(cam_ip)
        if not cam_mac:
            _LOGGER.error("ArpSpoof: cannot get camera MAC for %s", cam_ip)
            return
        self._cam_macs[cam_ip] = cam_mac
        _LOGGER.info(
            "ArpSpoof: starting for camera %s mac=%s",
            cam_ip,
            ":".join(f"{b:02x}" for b in cam_mac),
        )
        task = asyncio.get_event_loop().create_task(self._poison_loop(cam_ip, cam_mac))
        self._tasks[cam_ip] = task

    async def stop(self, cam_ip: str) -> None:
        task = self._tasks.pop(cam_ip, None)
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        cam_mac = self._cam_macs.pop(cam_ip, None)
        # Restore correct router MAC in camera's ARP cache
        if cam_mac and self._router_ip and self._router_mac and self._iface:
            _LOGGER.info("ArpSpoof: restoring ARP for %s", cam_ip)
            _send_arp_reply(
                self._iface,
                sender_ip=self._router_ip,
                sender_mac=self._router_mac,
                target_ip=cam_ip,
                target_mac=cam_mac,
            )

    async def stop_all(self) -> None:
        for cam_ip in list(self._tasks):
            await self.stop(cam_ip)

    async def _poison_loop(self, cam_ip: str, cam_mac: bytes) -> None:
        while True:
            # Tell camera: router's IP → our (host) MAC
            _send_arp_reply(
                self._iface,
                sender_ip=self._router_ip,
                sender_mac=self._host_mac,
                target_ip=cam_ip,
                target_mac=cam_mac,
            )
            await asyncio.sleep(_ARP_INTERVAL)
