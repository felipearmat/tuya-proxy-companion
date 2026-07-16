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

Tuya cameras connect to the cloud MQTT broker (`m.tuyaus.com`) on **port 8883
over TLS**. The companion intercepts that traffic by:

1. **iptables PREROUTING redirect** — for each camera with proxy mode enabled,
   a `REDIRECT` rule rewrites the destination port from 8883 → proxy port
   (default 18883) *before* the packet leaves the kernel. This is surgical:
   only packets from that specific camera IP are affected; all other MQTT
   traffic on the network continues to reach the real broker.

2. **TLS MITM** — the proxy presents a self-signed TLS certificate to the
   camera (generated at startup and cached in `/data/proxy_certs/`). The camera
   connects believing it is talking to the cloud broker.

3. **Motion detection** — the proxy parses Tuya MQTT payloads and looks for
   the alarm DP (Data Point 185). When a motion event is detected, it fires a
   manual motion event to Frigate via its HTTP API.

4. **Transparent relay (unknown cameras)** — cameras that are not in the
   proxy-enabled list are forwarded transparently to the real broker, so no
   traffic is disrupted.

```
Camera (192.168.x.x)
  │  TCP :8883 (TLS, to m.tuyaus.com)
  │
  ▼ iptables PREROUTING REDIRECT (host network)
  │  TCP :18883
  │
  ▼ Companion MITM proxy
  ├── Known camera → parse payload → DP 185 detected?
  │     └── yes → POST /api/events/{slug}/motion/create → Frigate
  │     └── no  → discard (camera thinks it reached the cloud)
  └── Unknown camera → relay to m.tuyaus.com:8883 transparently
```

---

## Requirements

| Requirement | Why |
|---|---|
| `NET_ADMIN` capability | Required to manage iptables rules |
| `host_network: true` | iptables rules apply to the host network stack |
| eKaza Wizard integration | Provides camera list and triggers iptables sync |
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
