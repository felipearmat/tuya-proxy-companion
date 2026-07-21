# Tuya Proxy Companion

A Home Assistant OS add-on for Tuya-based cameras with two independent features:

**Proxy mode** — intercepts the camera's cloud MQTT traffic and routes motion
events (DP 212) locally to [Frigate NVR](https://frigate.video) via the Tuya
local protocol on LAN (port 6668). No internet dependency.

**Privacy blocking mode** — uses ARP spoofing and iptables FORWARD rules to
restrict the camera to the minimum internet access required for local
functionality, blocking SmartLife push notifications and video upload to the
cloud while keeping Frigate recording operational.

Designed to work alongside the
[eKaza Wizard](https://github.com/felipearmat/ekaza-wizard) custom integration.

---

## How it works

The companion uses two complementary approaches to detect motion from Tuya cameras:

### Primary: Local Tuya Protocol (LAN-based)

The camera is reachable on the local network via Tuya's local protocol on
**port 6668 (TCP)**. The companion maintains a persistent connection and
receives DP (Data Point) updates pushed by the camera — no internet path
involved.

1. **Persistent TCP connection** — opened to the camera's LAN IP on startup
   (or when the camera is enabled). Uses the `device_id` and `local_key`
   stored in eKaza Wizard.

2. **Protocol 3.5 key exchange** — the companion authenticates via the Tuya
   local protocol, establishing an encrypted session with the camera.

3. **DP 212 detection** — incoming DP updates are inspected for DP 212 (ipc_motion
   alarm payload). The value is a base64-encoded JSON: `{"cmd":"ipc_motion","alarm":true,...}`.
   When `alarm` is truthy or `cmd` is `"ipc_motion"`, a motion event is posted to Frigate.

4. **Auto-reconnect** — if the connection drops, the companion retries after
   10 seconds. This approach is immune to DNS or cloud routing changes.

```
Camera (LAN)
  │  Tuya local v3.5 (TCP :6668)
  │
  ▼ Companion persistent listener
  └── DP 212 push (ipc_motion) → POST /api/events/{slug}/motion/create → Frigate
```

### Secondary: Cloud MQTT MITM — proxy mode (iptables-based)

Intercepts the camera's cloud MQTT traffic on the primary MQTT port.

1. **iptables PREROUTING REDIRECT** — rewrites destination port 8883 → proxy
   port (default 18883). Requires an AdGuard DNS rewrite so the camera resolves
   its MQTT domain to the HAOS host IP (managed automatically by eKaza Wizard).

2. **TLS MITM** — the proxy presents a self-signed certificate to the camera.
   The camera connects believing it reached the cloud broker.

3. **Motion detection** — parses Tuya MQTT payloads for DP 212 (ipc_motion).

4. **Transparent relay** — unknown cameras are forwarded to the real broker.

```
Camera (LAN)
  │  TCP :8883 → HAOS (via AdGuard DNS rewrite)
  │
  ▼ iptables PREROUTING REDIRECT (host network)
  │  TCP :18883
  │
  ▼ Companion MITM proxy
  ├── Known camera → DP 212 detected → Frigate
  └── Unknown camera → relay to m.tuyaus.com:8883
```

### Privacy blocking mode (ARP spoof + iptables FORWARD)

Activated independently from proxy mode by the **SmartLife/Tuya blocking**
feature in eKaza Wizard's Privacy tab (`privacy_blocked: true` per camera).
Requires proxy mode to also be active.

1. **ARP spoofing** — periodic unicast ARP replies claiming the HAOS MAC as the
   gateway. All camera internet traffic is routed through HAOS (interval: 8 s).

2. **Extra PREROUTING REDIRECTs** — ports 8886 and 443 also redirected to the
   MITM proxy, covering MQTT-over-TLS alternative port and MQTT-over-WebSocket.

3. **FORWARD DROP UDP** — all UDP except DNS (53) and NTP (123) is dropped,
   blocking WebRTC DTLS, STUN/TURN, QUIC-based video upload.

4. **FORWARD DROP HTTP** — TCP port 80 dropped (plain-HTTP clip upload path).

5. **FORWARD ACCEPT TCP** — all remaining TCP is forwarded so the camera can
   make cloud connection attempts on non-standard ports. This keeps the camera
   in "reconnecting" state, which is required for DP 212 local events to flow.

```
Camera (LAN)
  │  ARP reply: gateway MAC = HAOS MAC (every 8 s)
  │
  ▼ All internet-bound traffic routed through HAOS
  │
  ├── TCP :8883, :8886, :443 → PREROUTING REDIRECT → MITM (TLS error → no cloud MQTT)
  ├── UDP (except DNS/NTP) → FORWARD DROP
  ├── TCP :80 → FORWARD DROP
  └── TCP (other) → FORWARD ACCEPT (keeps camera in reconnecting state for DP 212)
```

---

## Requirements

| Requirement | Why |
|---|---|
| `NET_ADMIN` capability | Required to manage iptables rules (MITM path) |
| `host_network: true` | iptables rules apply to the host network stack |
| eKaza Wizard integration | Provides camera list (including `device_id` and `local_key`) |
| Frigate NVR | Receives motion events |

---

## Installation

### As a local add-on (development / self-hosted)

1. Copy the add-on folder to `/addons/tuya_proxy_companion/` on your HAOS host.
2. In Home Assistant: **Settings → Add-ons → Store → ⋮ → Check for updates**.
3. The add-on `Tuya Proxy Companion` should appear under **Local add-ons**.
4. Install → Start.

### From a repository

1. In Home Assistant: **Settings → Add-ons → Store → ⋮ → Repositories**.
2. Add `https://github.com/felipearmat/tuya-proxy-companion`.
3. Search for **Tuya Proxy Companion** and click **Install**.

---

## Configuration

| Option | Default | Description |
|---|---|---|
| `proxy_port` | `18883` | Port the MITM proxy listens on. Change if 18883 is occupied. |
| `camera_mqtt_port` | `8883` | Original MQTT port the cameras connect to (should stay 8883). |
| `api_port` | `8765` | Port for the internal HTTP API used by eKaza Wizard. |
| `log_level` | `info` | Log verbosity: `debug`, `info`, `warning`, `error`. |

These are set via **Settings → Add-ons → Tuya Proxy Companion → Configuration**.

---

## Integration with eKaza Wizard

The companion exposes a local HTTP API on `localhost:8765`. The
[eKaza Wizard](https://github.com/felipearmat/ekaza-wizard) custom integration
auto-detects the companion at startup (no manual configuration needed) and:

- Sends the camera list via `POST /cameras`; each camera carries two flags:
  - `proxy_enabled` — activates PREROUTING REDIRECT + local Tuya listener
  - `privacy_blocked` — activates ARP spoof + gateway FORWARD rules (requires `proxy_enabled`)
- On proxy toggle or SmartLife blocking toggle, the companion is re-synced immediately
- New cameras inherit the current `privacy_blocked` state automatically

If the companion is not installed, eKaza Wizard falls back to an in-process proxy
that lacks iptables support (traffic interception only works if the camera connects
directly on the proxy port, not via iptables redirect).

### API endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/status` | Returns version, proxy state, cameras, iptables rules, `gateway_ips` |
| `POST` | `/cameras` | Sync camera list; reconciles proxy and privacy rules per camera |
| `POST` | `/proxy/start` | Start the MITM proxy (auto-started at boot) |
| `POST` | `/proxy/stop` | Stop proxy and flush all iptables rules |

`/cameras` body: `{"cameras": [{"slug": "...", "ip": "...", "proxy_enabled": bool, "privacy_blocked": bool, "device_id": "...", "local_key": "...", "tuya_mqtt_domain": "..."}]}`

---

## Compatibility

| Architecture | Supported |
|---|---|
| amd64 | ✅ |
| aarch64 | ✅ |
| armv7 | ✅ |
| armhf | ✅ |
| i386 | ✅ |

Tested on:
- HAOS `generic-x86-64` (Samsung RV411, Intel i5-2410M)
- Camera model: eKaza EKRW-T5293 (Tuya protocol 3.5)

---

## Security notes

- The self-signed certificate presented to the camera is generated locally at
  startup and cached in `/data/proxy_certs/`. It is never transmitted outside
  the local network.
- All iptables rules (PREROUTING and FORWARD) are scoped to the specific
  camera's IP address (`-s <cam_ip>`). Other devices on the network are unaffected.
- Privacy blocking mode uses ARP spoofing, which is local to the segment and
  only redirects the camera's default gateway resolution — not a broadcast storm.
- The companion does **not** store or log any camera credentials or Tuya payloads.
- When the add-on stops, all iptables rules are flushed automatically.
