# Tuya Proxy Companion

A Home Assistant OS add-on that acts as a MITM proxy for Tuya-based cameras.
It intercepts the camera's cloud MQTT traffic, detects motion events locally,
and routes them to [Frigate NVR](https://frigate.video) — without any internet
dependency and without blocking the camera from functioning normally in the
SmartLife app.

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

### Secondary: Cloud MQTT MITM (iptables-based)

For cameras where local protocol access is unavailable, the companion can
intercept the camera's cloud MQTT traffic using iptables.

1. **iptables PREROUTING redirect** — a `REDIRECT` rule rewrites destination
   port 8883 → proxy port (default 18883). Traffic is intercepted at the
   network level; no DNS rewrite is needed when the primary local listener is active.

2. **TLS MITM** — the proxy presents a self-signed certificate to the camera.
   The camera connects believing it reached the cloud broker.

3. **Motion detection** — parses Tuya MQTT payloads for DP 212 (ipc_motion).

4. **Transparent relay** — unknown cameras are forwarded to the real broker.

```
Camera (192.168.x.x)
  │  TCP :8883 → m.tuyaus.com (resolved to HA server via AdGuard)
  │
  ▼ iptables PREROUTING REDIRECT (host network)
  │  TCP :18883
  │
  ▼ Companion MITM proxy
  ├── Known camera → DP 185 detected → Frigate
  └── Unknown camera → relay to m.tuyaus.com:8883
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

### From a repository (future)

Once published to a repository, add the URL in
**Settings → Add-ons → Store → ⋮ → Repositories** and install from there.

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

- Sends the list of proxy-enabled cameras via `POST /cameras`
- The companion reconciles iptables rules (adds for enabled, removes for disabled)
- On camera proxy toggle in the Privacy tab, the companion is re-synced immediately

If the companion is not installed, eKaza Wizard falls back to an in-process proxy
that lacks iptables support (traffic interception only works if the camera connects
directly on the proxy port, not via iptables redirect).

### API endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/status` | Returns version, proxy state, active cameras, iptables rules |
| `POST` | `/cameras` | Sync camera list; reconciles iptables rules |
| `POST` | `/proxy/start` | Start the MITM proxy (auto-started at boot) |
| `POST` | `/proxy/stop` | Stop proxy and flush all iptables rules |

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
- The iptables rules are per-camera-IP and surgical: they only affect traffic
  originating from the specific camera's IP address on port 8883. All other
  devices and all other ports are unaffected.
- The companion does **not** store or log any camera credentials or Tuya payloads.
- When the add-on stops, all iptables rules are flushed automatically.
