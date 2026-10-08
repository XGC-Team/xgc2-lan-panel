# XGC2 LAN Panel

Field LAN robot finder. Independent of Core / Agent.

Two Debian packages from one source:

| Package | Installs on | Command |
| --- | --- | --- |
| **xgc2-lan-beacon** | robot | `xgc2-lan-beacon` — be discovered, apply NIC / Wi-Fi |
| **xgc2-lan-probe** | operator laptop | `xgc2-lan-probe` — discover, WebUI on `127.0.0.1:3400` |

Discovery is solicit + unicast reply. The probe asks only while a browser page
is visible. Robots reply to the source IP/port. Close the page and solicit
stops.

## Install

After the official XGC2 APT repository is configured:

```bash
# robot
sudo apt update
sudo apt install xgc2-lan-beacon
# Provision /etc/xgc2/lan-beacon.env with deployment TLS identity and
# explicit caller grants before enabling its service.
sudo systemctl enable --now xgc2-lan-beacon

# laptop
sudo apt update
sudo apt install xgc2-lan-probe
xgc2-lan-probe --tls-cert <client.pem> --tls-key <client-key.pem> \
  --tls-ca <ca.pem> --beacon-grants <targets.json>
# open http://127.0.0.1:3400/
```

Beacon apply needs `nmcli` (NetworkManager). That is a Recommends of the
beacon package, not a hard Depends of the probe.

## Ports

| Role | Port | Bind |
| --- | ---: | --- |
| Discovery UDP | **19518/udp** | robot listens; probe solicits from an ephemeral port |
| Robot control HTTPS with mTLS | **19519/tcp** | all interfaces |
| Operator probe API + UI | **3400/tcp** | `127.0.0.1` |
| Operator Vite (dev only) | **3401/tcp** | `127.0.0.1`, proxies `/api` to 3400 |

## Coverage

Ubuntu **bionic / focal / jammy / noble** × **amd64 / arm64**.

## Development

```bash
./scripts/dev.sh
# UI http://127.0.0.1:3401/  API http://127.0.0.1:3400/api/health
```

```bash
go test ./...
cd web && npm test && npm run build
./.xgc2/scripts/build.sh
```

## Trust

UDP discovery is an untrusted read-only hint. Control uses the native Go XRPC
HTTPS host, verified client certificates and explicit caller SPKI grants.
The probe additionally binds each permitted target ID to its deployment
server DNS name and SPKI. A discovered robot without that grant cannot
receive a command. The browser proxy accepts loopback Host and approved
Origin values and requires JSON mutations. Passwords never appear in
beacons or probe logs.

See [the control and write contract](contracts/xrpc.md) for deployment
inputs, native completion, bounded admission and remaining release gates.
