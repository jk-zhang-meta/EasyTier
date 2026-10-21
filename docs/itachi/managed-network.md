# Managed EasyTier: authorization and protocol/port observability

Status: design and acceptance contract. Native implementation is in progress;
see [implementation status](implementation-status.md) for the implemented boundary
and executed checks. A source patch is not a deployment claim. Date: 2026-10-21.

## 1. Product boundary

One managed overlay, not a federation of unrelated FRPS registrations:

```
PersonalWeb (administrator session / licenses / device approval / monitoring)
        | authenticated internal API; browser never receives device secrets
PersonalWeb EasyTier authority module
        | authenticated management connection via the configured HTTPS origin
native EasyTier clients and backbone peers
        | native encrypted overlay; existing routing selects forwarding paths
OS TCP/UDP services (SSH, RDP and explicitly authorized other services)
```

The distributable defaults to the configured management origin
`https://www.itachi.fans`. Users should not need a hand-maintained relay list.
Management returns an authenticated, versioned set of eligible ingress nodes;
native probing/routing selects among them. The domain is a control-plane
bootstrap, not a claim that every data packet transits the website.

Use eligible ingress addresses supplied by management, measured link quality and
native routing, not geographical distance as a performance promise. Start with
RTT-based native selection under explicit path constraints; RTT alone is not a
bandwidth or loss optimum. A private-only backbone policy must forbid public
fallback on backbone edges, while client-to-ingress attachments may be public.
The control plane constrains eligible edges; it does not replace the dataplane
solver. Keep separate observations for ingress choice and end-to-end service path.

PersonalWeb owns product entitlement and operator decisions. EasyTier owns
native device sessions, overlay routing and enforcement. Do not create another
wrapper daemon, a competing routing algorithm, or a second browser-admin account
system. Internal administration stays loopback/private, never a raw public RPC.

## 2. Three independent authorization questions

1. **May this device join this network?** Product entitlement, device approval,
   device-key possession, expiry and revocation.
2. **May this source reach this service?** A policy binds source device/group,
   destination device/group, transport and destination-port range.
3. **May this user log into the target OS?** SSH keys/passwords and Windows/RDP
   authentication remain the target OS's responsibility. Overlay admission does
   not log a user in, share their password or enable an OS service.

Avoid per-pair configuration by assigning approved devices to service groups:
for example `members -> ssh_hosts TCP/22` and an explicitly approved
`rdp_users -> windows_hosts TCP/3389 + UDP/3389` policy. These are proposed
templates, not automatic permission to expose every port. Nonstandard ports
come from the target's service definition. Publish a key-bound name-to-overlay-IP
directory with collision rules, so another device's hostname cannot hijack an
existing identity. Initially expose this directory without silently changing
global OS DNS, default routes or existing SSH configuration; an OS name-resolution
integration needs an explicit reversible installation step and its own test.

Use PersonalWeb's existing licensing patterns, with a distinct `easytier`
product namespace. Do not automatically accept a GhostDesk serial, borrow its
production signing key, or infer ownership from a matching username/hostname.
An operator-managed server can be enrolled by a separately scoped invitation;
end-user licensing and privileged backbone enrollment must not be interchangeable.

### Enrollment and lease lifecycle

1. The installed native service creates its device identity locally. Separate
   the management signing key from the overlay secure-mode key; bind both public
   keys in the device record. Private keys never leave the device.
2. The user enters a product activation/invitation code, or completes a bounded
   browser/device approval flow. An invitation is single-use, short-lived,
   network-scoped and atomically consumed. Do not ship a fleet-wide secret in a
   downloadable installer.
3. The client signs a server challenge with its own locally held management
   private key; the server verifies it with the enrolled public key. A UUID alone is
   not proof of identity. Secure peer handshake proves possession of the bound
   overlay key; do not assume signing and key-agreement keys are interchangeable.
4. The authority issues a short-lived signed grant binding product, audience,
   tenant/network, immutable device ID, both key hashes, grant ID, scopes,
   policy/state revision, not-before and expiry. Initial proposed lease: five
   minutes, refreshed before expiry with jitter; tune only after failure tests.
5. The client obtains network configuration and an eligible ingress directory
   over authenticated transport. It receives only its own credentials and
   permitted configuration, never the backbone's network root secret.
6. Revocation increments durable state, publishes an ordered outbox event and
   terminates affected sessions/credentials. Every enforcing peer verifies the
   current lease and revocation state. Client-only license checks are bypassable
   and are **not** an access-control boundary.

Authorization state and the durable outbox commit in one transaction; retries
use idempotency keys. Persist the applied state/revocation watermark. A reset
or lost state store requires authoritative resynchronization before admitting
managed peers. Do not introduce a username-token or root-secret fallback.
Peer allowlists store public identities/grant-verification material, not copies
of client private keys. A legacy bearer-credential enrollment is not an acceptable
substitute for the new public-key proof-of-possession boundary.

The maximum stale-admission window is bounded by lease expiry plus declared
clock tolerance, even if a push is lost. Existing peer sessions also need expiry
enforcement; checking only a new handshake is insufficient. A management outage
may preserve traffic only while its current lease remains valid. At expiry,
fail closed; do not promise both indefinite offline use and immediate revocation.
Keep existing independent emergency access until this behavior is tested.

Management HTTPS/WSS must validate certificate chain, hostname and validity.
An application signature supplements TLS; it does not justify skipping TLS.
Stock peer-WSS self-signed transport and management WSS have different trust
models: harden the actual management dial path, not every transport globally.

## 3. Protocol and port monitoring: three layers

| Layer | Collector | Evidence that may be claimed |
| --- | --- | --- |
| Service flow | Source/destination endpoint, before encryption / after decryption | Inner IP family, TCP/UDP, five-tuple, packet/byte counts, first/last observation and protocol state |
| Overlay path | Native send/forward/receive path | Actual local forwarding decision and attachment, route revision, direction and time interval |
| Underlay link | Both ends of each peer connection | TCP/UDP/WSS/etc., local/remote endpoint and port, connection ID, RTT, loss metric with method, transferred bytes and reconnects |

A relay forwarding end-to-end-encrypted packets cannot reliably recover inner
SSH/RDP ports. Collect business metadata at endpoints. Do not capture payloads,
passwords, keystrokes, file contents or SSH commands. A configured TCP/22 service
may be labeled SSH, but the port alone does not prove application identity.
RDP TCP/3389 and UDP/3389 are separate observations and policies; ports can vary.

### Service-flow record

Bind the report to `reporter_device_id`, `network_id`, `boot_id`,
`config_revision`, `policy_revision`, `report_sequence`, measurement time and
expiry. Each flow contains:

- A local random `flow_id`, source/destination overlay addresses and peer IDs
  when resolved; IP version; numeric IP protocol; TCP/UDP source and destination
  ports when actually available; observation direction.
- First/last observation and monotonic elapsed duration. Do not trust clocks
  alone for ordering; record collector boot ID and sequence.
- Separate cumulative packet/IP-byte counters by direction. Counts include IP
  headers and retransmissions visible at that hook; they are **not** useful
  application payload or underlay wire-byte counts.
- Optional TCP evidence (SYN sent, SYN-ACK observed, reset, FIN). A complete
  observed handshake proves transport establishment, not SSH authentication or
  a usable remote desktop. Midstream capture stays `midstream_observed`.
- UDP states such as `sent` and `reply_observed`, not a fictitious TCP session.
- Drop/reject evidence and policy-rule ID only from an enforcing hook that
  actually observed the decision; absence of a report is not a denial reason.

Correlate the two endpoints with the normalized tuple, network, device pair,
observation interval and boot identity; preserve ambiguity for tuple reuse/NAT.
Do not demand identical independently generated flow IDs. A future on-wire
correlation ID needs a separately reviewed compatible protocol extension.

IPv4 fragmentation, IPv6 extension headers, non-initial fragments, ICMP errors
and malformed/truncated packets must not manufacture port numbers. The first
version may report these as port-unavailable with explicit reason. Do not
silently ascribe non-initial fragment bytes to an arbitrary flow.

### Path segments, not one permanent path per flow

The route can change within one long-lived connection and can differ by
direction. Record a new path segment on a forwarding/attachment change. A
segment contains local hop, next hop, exact peer connection/attachment,
route revision, direction, timestamps and counters. Use native packet metadata
for correlation only when visible and stable; do not decrypt transit traffic.

The UI has distinct labels:

- `computed`: currently calculated route, not an observed session path;
- `partially_observed`: some forwarding segments are verified;
- `observed`: a correlated continuous chain has evidence for the stated interval;
- `stale` / `unknown`: expired or missing evidence, never silently inferred hops.

A point-in-time route dump plus a service-flow report is insufficient to claim
all packets took the displayed route. If exact per-flow transit correlation is
not available without a wire extension, show endpoint flow + separate observed
link/next-hop information and clearly mark the full path unverified.

### Service checks are a separate evidence source

Configured service definitions select transport, port and permitted probe
source. TCP connect, SSH banner exchange, optional TLS handshake and actual
authorized session outcomes are different check types. Default probes do not
attempt password login. UDP requires a protocol-aware benign request/reply or
passive reply observation; an unanswered arbitrary UDP datagram proves nothing.
Store timeout/refused/policy-denied/unknown separately and identify the probe
source. Never conflate ping, node heartbeat and TCP/UDP service availability.

## 4. Telemetry integrity and bounds

The management channel authenticates the device and grants an `observe:self`
scope. Reports bind identity, network/config revision, boot generation,
strictly increasing sequence, server challenge/window and body digest. Verify
the report before updating replay state. Bound body size and event count, reject
cross-tenant/device spoofing, and keep server receive time separately.
The server authorizes each session/boot generation after a fresh challenge and
persists the generation watermark. A client-reported new `boot_id` alone cannot
reset sequence/replay state or revive an older session generation.

Initial proposed limits: 4,096 tracked flows/device, 60-second idle eviction,
10-second batched reporting, 256 KiB/report, 256 flow rows/report and bounded
queue length. Expose evictions, queue drops and sampling coverage. Cap packet
hot-path work, avoid per-packet allocation/signing, and never block forwarding
on a web request. Telemetry failure must not turn into accidental routing failure.

The 256 KiB value is a burst ceiling, **not** a recurring allocation: 25 devices
sending that amount every ten seconds would send about 1.70 TB in 30 days before
TLS overhead. Report only changed/delta observations, back off on quiet devices,
and enforce byte budgets at both device and fleet levels. An initial proposed
average of 16 KiB/device/minute is about 17.7 GB/month for 25 devices before
overhead, with the same bounded burst ceiling. Add a configurable fleet-wide
monthly telemetry budget and daily alarms using actual ingress/egress accounting.
When capped, preserve authorization traffic and explicitly report reduced
telemetry coverage; do not hide dropped observations or renew stale measurements.

Keep measurement expiry independent from node heartbeat. An unchanged heartbeat
cannot refresh old RTT, flow or probe evidence. Counter resets require boot/epoch
changes; calculate deltas only between matching identities/epochs. Reject
out-of-order reports without decreasing existing counters or freshness.

Recommended initial retention: detailed flow metadata 24 hours, aggregate link
statistics seven days, separately bounded security audit history. Treat those
as private deployment settings, with authenticated administrator access and
documented deletion/export controls. Never place real telemetry in public GitHub.

## 5. Source ownership and native integration points

The following are inspected upstream v2.7.0 locations, not completed patches:

| Responsibility | Native source / required change |
| --- | --- |
| Device registration | `easytier-web/src/central_network/device_auth.rs`: replace username + self-reported UUID trust in the managed path with verified device grants |
| Credentials/state | `easytier-web/src/db/mod.rs`: `get_user_id_by_token` explicitly resolves a username today; add real scoped device identity, expiry/revocation and migration rather than renaming this token |
| Real server entry | `easytier-web/src/main.rs`: connect managed verifier at the handler selected by central-console startup, including reconnect/heartbeat paths |
| Native client control | `easytier-core/src/management/full/web_client.rs`: enrollment/renewal and authenticated configuration transport; never leak credentials in URLs/logs |
| Management TLS boundary | `easytier/src/tunnel/websocket.rs` and actual config-client adapters: distinguish authenticated management WSS from intentionally self-signed peer transport |
| Service packet hooks | `easytier-core/src/peers/peer_manager.rs`, `peers/acl/filter.rs`: endpoint plaintext observation, actual ACL disposition and selected forwarding attachment; share validated parsing, do not create inconsistent ACL/telemetry parsers |
| Link/path counters | Native peer connection stats, `peers/traffic_metrics.rs`, `peers/route/peer_ospf_route.rs` |
| API/wire contract | `easytier-proto/proto/api_instance.proto`, management heartbeat/report types; add fields compatibly and expose paginated bounded queries |

The PersonalWeb source remains a separate project. Its EasyTier admin route
uses existing authenticated sessions and CSRF for writes. It should display
devices, approvals/expiry/revocation, service policies, actual flows, link
attachments and audit events. Public Applications serves reviewed signed/checksummed
platform packages through existing download protections, not an unprotected alias.

GhostDesk is a design reference, not a runtime dependency: reuse the concepts
of key-bound grants, durable revision watermarks, atomic authorization/outbox,
exact endpoint/transport observations, freshness and explicit uncertainty.
Use distinct signing domains and keys. Do not copy its live credentials, product
scope, relay databases or protocol into EasyTier.

## 6. Ordered implementation and acceptance gates

1. **Repository + UI integration.** Pin upstream identity; add the local admin
   entry without renaming existing products. Until connected, API/UI reports
   `not_connected`, not fabricated healthy/zero metrics. No deployment implied.
2. **Native management authorization.** Per-device enrollment, proof-of-key,
   verified management TLS, scoped signed leases, atomic revocation/migrations.
   Test genuine registration/reconnect/renewal and loss/recovery paths.
3. **Peer enforcement.** Verify grants against secure handshake identities on
   trusted peers, expire active sessions, apply service ACLs, synchronize
   revocation. Unauthorized stock clients must not bypass a modified GUI.
4. **Native endpoint/link telemetry.** Bounded collector + authenticated reports
   + revision-aware storage/query API. Correlate only supported observations;
   show missing/partial paths honestly.
5. **Installers and real canary.** Windows service, macOS launchd daemon, Linux
   systemd service. Test startup, background operation, uninstall and credential
   file permissions on each OS/architecture claimed; preserve existing TUNs and
   routes. Retain stable identities on upgrade. Publish corresponding source,
   license notices and checksums as required by upstream LGPL-3.0 licensing.
6. **Fleet transition.** Canary first, matching same-input baseline/modified/
   rollback checks, then staged rollout. Do not abandon existing management
   channels until native authorization and service access both pass.

Security matrix: wrong product/network/audience/key; copied UUID; replayed or
consumed invite; expired/not-yet-valid grant; revoked device while connected;
lost revoke event; stale persisted watermark; authority/peer restart; clock
skew; untrusted/expired/wrong-host TLS; cross-tenant request; unsigned telemetry;
out-of-order/counter-reset report; full queues and collector overload.

Traffic matrix: SSH TCP/22 plus nonstandard SSH; RDP TCP and UDP; forward and
reverse sessions; direct and multihop; route change during a flow; TCP refused,
timeout and reset; UDP send-only vs reply; IPv4/IPv6; fragments/truncation;
encrypted transit with no fabricated service ports; telemetry loss with data
forwarding preserved. Compare actual received content/byte integrity where
testing data delivery, and avoid claiming capacity from advertised link rates.

## 7. Deliberately deferred / rejected

- No replacement of EasyTier's routing by a second centrally invented solver.
- No claim that three native config servers automatically form one consistent
  authorization database; begin with one authoritative management service and
  tested recovery, then design HA if needed.
- No public raw config/RPC endpoint protected only by a username or UUID.
- No indefinitely valid shared client network secret in installers.
- No application identity inferred solely from a port, no payload inspection,
  no claim that a signed endpoint report is hardware-attested truth.
- No global OS DNS/default-route changes, automatic SSH password sharing or
  OS-login bypass as a side effect of joining the overlay.
