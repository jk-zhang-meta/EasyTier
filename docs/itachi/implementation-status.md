# Managed implementation boundary

This fork pins upstream v2.7.0 (8b7f1f0196edb5b580829ed5f135050fb5853478).
Deployment and platform readiness require their own terminal acceptance results.

## Implemented native path

- `easytier-core --managed-state DIR --managed-origin https://www.itachi.fans --daemon`
  runs signed HTTPS enrollment/challenge/sync **inside the native core process**.
  It is not the upstream username/UUID config-server path or a wrapper daemon.
- `--managed-status` initializes local keys and prints only public identity JSON.
  `--managed-import-config` preserves an existing local instance UUID and overlay
  key. Control Ed25519 and overlay X25519 private keys remain local.
- Normal TLS validation, response signing, pinned authority, persisted revision
  watermark and short leases fail closed. No legacy TCP RPC server runs in
  managed mode, including on localhost.
- Managed peer admission and relay sessions require the current **managed-only
  public-key snapshot** for Admin and Credential peers. Network-root possession
  alone is insufficient. Active sessions are closed after revocation/expiry;
  management outages do not create indefinite leases.
- Source-group and source-IP ACL checks are conjunctive. Secure sessions reject
  unencrypted payloads before AEAD/tail processing. Inner packet ports use the
  same bounded strict parser as ACL enforcement.
- Service-flow collection covers native plaintext endpoint TCP/UDP hooks and
  actual local ingress attachments. It records IP bytes, not useful payload,
  does not inspect application content and does not prove OS login.
- Signed changed-row telemetry preserves original timestamps and requires a
  positive authority acknowledgement before committing its cursor. Failed
  telemetry does not block a valid lease refresh. Computed routes and partial
  observations are not represented as a verified end-to-end path.

## Authority and product boundary

The authority is an integrated module in the separate PersonalWeb application,
using its authenticated administrator session and CSRF protections. Pending
public devices require operator approval; the implementation does not claim
that a new paid-license/invitation issuance product has been delivered. Backbone
approval additionally requires a private inventory pin of UUID, Ed25519 and
X25519 public keys. Only backbones receive their private root-network template;
leaf clients do not receive root secrets or another device private key.

Approvals, groups, service ACLs, backbone ingress metadata and bounded actual
flow/link observations are exposed by the PersonalWeb UI. The shared origin
is control-plane bootstrap, not a claim that data traverses the website.
OS SSH/RDP still requires a running service and valid OS credentials. Global
DNS, default routes, FRP, SSH configurations and Tailscale are not modified.

## Distribution boundary

The six-target workflow builds this exact native source and packages native
Linux systemd, macOS launchd and Windows SCM service installers. Packages default
to the public management origin and contain no enrollment private keys.
Installers accept a fresh installation or an identical verified package only;
other upgrades deliberately fail. Fresh-install rollback removes the owned
service and preserves its identity and package. It is not rollback to an
unknown earlier software version. Checksums are integrity metadata, **not** an
independent publisher signature. No Authenticode/notarization claim is made.

Native focused tests and platform CI must pass before a package is published.
Private test logs, inventories, actual flow records, server credentials and
operational results are retained outside this public repository.

## Automatic relay enrollment

A server installation explicitly opts into relay mode. It advertises bounded
listen endpoints and public ingress addresses in its signed enrollment/sync.
A scoped, expiring, single-use deployment invitation binds the device UUID,
control public key, overlay public key, relay role and advertised ingress.
Merely claiming to be a relay does not grant authority. Ordinary client
installation remains a leaf and never silently becomes a relay.

The central registry distributes only enabled, approved relays with their own
live leases. Each receiving core applies the changing connector set through
its existing native configuration APIs, not a process or instance restart.
A relay can bootstrap with no other active ingress. New relay membership,
expiry, revocation, re-enrollment and failed invitations require lifecycle
tests; no public endpoint is considered reachable just because it was reported.
The registry is dynamic, not a hard-coded inventory of three server addresses.

### Linux/macOS server provisioning

The verified Unix installer has an explicit server mode; ordinary Windows/macOS/
Linux end-user installation remains a leaf. A fresh server can prepare its real
identity before consuming an identity-bound invitation:

```sh
sudo bash install.sh --relay --prepare \
  --relay-listen tcp://0.0.0.0:57220 \
  --relay-advertise tcp://PUBLIC_IP:57220 --relay-region REGION
```

The preparation prints only public identity and creates no service. The
authorized control-plane operator issues a short-lived one-use invitation bound
to those UUID/Ed25519/X25519 identities and exact public addresses. Transfer it
privately into a root-owned mode-0600 file, not command arguments or logs. Resume
with the **same package and public arguments**, omit `--prepare`, and add
`--relay-invitation-file /absolute/private/invitation`. This starts the OS-native
background service. The same identity is retained. An installed instance does
not accept arbitrary ticket, package or mode changes.

This bootstrap separates approving a server from managing routes: subsequent
registration, heartbeat and discovery are automatic. Existing clients need no
new per-server peer list. No anonymous download grants relay authority. A server
with no invitation can register as pending for explicit administrator approval;
that is not a claim of automatic privilege.

The current native sync cadence is jittered 25–35 seconds. The authority
advertisement lifetime is at most 120 seconds and also bounded by the relay's
own live lease. Changes propagate on subsequent successful signed syncs, not
instantaneously. Computed routes remain distinct from observed flow paths.
