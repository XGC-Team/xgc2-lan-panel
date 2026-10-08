# LAN discovery and authenticated native control

Baseline `0d64aa5ac3f35fd487681fae13ba12f4d17db6c4`, preserving inherited
edge/go.mod edits. All work is in the isolated product tree. No live NIC,
NetworkManager configuration, service or package deployment is changed.

## Real boundaries and admission

Probe is the operator's loopback browser bridge. Beacon is the robot's existing
discovery/control process. Native UDP remains read-only discovery, with a
bounded version-2 datagram; it neither authorizes targets nor carries commands.
The actual probe -> beacon command consumer uses a shared SDK client pool and
the beacon's native SDK HTTPS host. Network collection and plan generation
remain local libraries, without extra services/listeners.

Both roles resolve `XGC2_XRPC_*` once with hard product ceilings and apply it
through SDK host/client policy. Beacon ceilings/defaults: 16 connections,
8 in-flight calls, 64 KiB request/response, 30 seconds call time. Probe:
32 connections, 16 calls, 64 KiB requests, 128 KiB responses, 30 seconds,
two connections per cached client and 64 service references. Its UDP registry
has 64 entries and expires entries before admitting more. SSE has bounded
subscriber state and a five-second native write deadline. All fixed discovery
and snapshot workers join on shutdown. The immutable SDK enforces native cumulative response writes, including
closing an already committed response on overflow. An incomplete streamed
response has unknown outcome, not a complete success.

Beacon startup creates a fresh instance fence. Its control TLS requires a
verified client certificate plus an explicit canonical SHA256 SPKI grant
(1..64 callers). The probe additionally requires a deployment target binding:
target ID -> verified DNS name + SPKI. CA membership alone cannot authorize a
different identity for a victim ID. Numeric UDP reachability is used only for
fresh-instance dialing; TLS and target grants govern the actual call. There
is no plaintext fallback, generated credential, per-request pairing or hidden
provider-start probe. Unregistered discovered robots remain read-only hints.

Probe listens only on loopback. HTTP Host must also be loopback. Browser
Origin must be the request authority or the explicit loopback Vite origin;
mutations require `application/json`. A cross-origin form or DNS-rebinding Host
cannot use the proxy's client identity. Origin-less local CLI JSON is allowed.

One non-queued beacon writer owns native NetworkManager work. Before admission
a cancelled request has no effect. After admission native work uses its own
30-second domain lifetime, native `nmcli --wait 20`, output <=64 KiB and finite
pipe cleanup. Caller departure cannot release the writer while it runs.
Native success is followed by one provider postcondition read of connection,
address, gateway and DNS. Making a default route reapplies other active NICs
and checks actual `/proc/net/route`, not just saved profile metrics. Applied
and persisted are asserted only after those native checks.

Failed/ambiguous native mutations return `partial_effects` and
`failure_stage=outcome-unknown`, retain the writer for that boot and advertise
owner recovery in authenticated health. No timer assumes NetworkManager has
become quiescent. The owner must inspect/recover native state before restarting
this process and supplying a new instance. This failure mode sacrifices control
availability rather than allowing conflicting work; no rollback or cross-boot
durable completion claim is made. Wrong postconditions after a completed
activation are an explicit partial failure.

Per-boot receipts are bounded to 128 and keyed by caller SPKI/request ID.
Completed duplicates return the same result, conflicting payloads reject, and
in-progress duplicates report unknown outcome. Capacity has no eviction/replay
fallback. Shared SDK caller expiry does not cancel the admitted domain owner.
Remote weak-link and real native recovery require the deployment window.

## Explicit deployment inputs and writes

The beacon service reads `/etc/xgc2/lan-beacon.env`. The deployment owner
supplies `XGC2_LAN_TLS_CERT`, `XGC2_LAN_TLS_KEY`, `XGC2_LAN_TLS_CA`,
`XGC2_LAN_CONTROL_NAME` and `XGC2_LAN_CONTROL_CALLERS`. Missing grants fail
startup with exit 2 and are not endlessly restarted. Probe receives the same
TLS file variables with a client identity and `XGC2_LAN_BEACON_GRANTS` (or CLI
`--beacon-grants`). Inputs are bounded regular files; no HOME fallback exists.

The bounded <=16 KiB target manifest is:

```json
{"schema":"xgc2.lan-control-grants/v1","targets":[{"target_id":"robot-machine-id","server_name":"robot.example","spki_sha256":"<canonical 64 lower-case hex>"}]}
```

| Class | Owner and trigger | Location | Budget/recovery |
| --- | --- | --- | --- |
| Certificates, private keys, target/caller grants | Deployment identity owner; explicit provisioning/rotation | Explicit supplied files, service environment allocation | <=64 KiB certificate/CA, <=16 KiB key/target manifest, <=64 targets/callers. This process only reads them; it neither creates durable roots nor persists secrets. Rotation restarts/rebinds the process. |
| NIC/Wi-Fi profile | Native NetworkManager owner; accepted authenticated command | NetworkManager's existing native profile allocation | Bounded input (DNS4, password128, SSID32), one admitted plan, native persistence and online application/postcondition distinguished. System profile storage/retention is owned by NetworkManager and the deployment owner, not a new application DB. |
| Discovery registry, snapshots and receipts | This process | Bounded memory only | Registry64, receipts128, fixed workers. Maintained five-second collection snapshots serve HTTP/UDP; requests do not launch slow native status probes. Restart produces a new instance and restores no old completion claim. |
| Browser view state | Browser component | Memory | No localStorage/IndexedDB/SQLite writer is introduced. |
| Routine diagnostics | Existing supervisor | stderr | Existing log allocation/rotation; credential argv/output is not emitted in control failures. |

## Evidence and remaining gates

`GOPRIVATE=github.com/XGC-Team go test -race ./...` and
`CGO_ENABLED=0 go build ./cmd/xgc2-lan-panel` pass with immutable SDK
`v0.0.0-20261008184950-0e742265600c`, no local replace. Real native HTTPS tests
exercise CA/client verification, ungranted/anonymous caller rejection before
effects, stale instance, deduplication, completion facts and wrong postcondition.
Independent native TLS grant tests reject another valid same-CA server key
before domain effects; untrusted UDP cannot create/change a target grant.
Browser tests reject cross-origin/simple/rebinding calls. Native subprocess
tests prove output overflow rejection, no work after pre-cancel, and finite
cancelled query exit. Domain tests prove caller cancellation/unknown mutation
do not free the writer; kernel-route fixtures disprove saved-metric success.

No real NIC changes or live service runs were used. Deployment identity/grants,
systemd inputs, actual remote/native recovery, private module build authentication,
package builds and full distro/architecture release matrix remain
Root-window acceptance gates. These source tests do not claim deployment.
