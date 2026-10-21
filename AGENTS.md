# Managed EasyTier fork

## Scope and source of truth
- This is an independent fork of `EasyTier/EasyTier`, not the parent workspace.
- Keep `origin` as the personal fork and `upstream` as the original project.
- The initial managed-network branch is based on upstream `v2.7.0`, commit
  `8b7f1f0196edb5b580829ed5f135050fb5853478` (a prerelease, not a stable-release claim).
- Preserve upstream licensing, attribution and platform support.

## Operating constraints
- Keep build trees, dependency caches, test output and indexes in host-local
  runtime outside synchronized source storage.
- Never commit deployment inventories, private addresses, enrollment tokens,
  passwords, private keys, session databases or real flow records.
- Integrate with PersonalWeb; do not create a second standalone client daemon
  or a parallel home-grown packet-forwarding implementation.
- Keep management transport authentication separate from peer transport trust.
  Do not globally break self-signed peer WSS while hardening management WSS.
- Preserve existing device identities and unrelated networking services during
  any later migration. Source changes alone do not authorize a deployment.

## Verification oracles
- Before and after edits, record repository status, branch and exact base.
- Use upstream focused Rust tests from a host-local source snapshot. Tests of
  managed authorization must enter through the real registration and handshake
  paths, not only call a verifier helper directly.
- A monitor is accepted only after real TCP and UDP traffic is correlated to
  protocol/port metadata and actual forwarding observations. Ping is insufficient.
- Reject revoked/expired/wrong-device grants and replayed reports. Missing or
  stale measurements stay unknown rather than becoming zero or online.

## Workflow and completion
- The architecture and staged acceptance contract are in
  [the managed-network design](docs/itachi/managed-network.md).
- Keep mutable task state, receipts and rollback exercises in private runtime.
- Require independent security review and rollback before production auth or
  policy changes. An administrative UI shell is not a completed control plane.
- Publish only reviewed source and verified releases; no deployment secrets.

## Map
- `easytier-web/`: native central configuration service and administrative APIs.
- `easytier-core/`: packet processing, secure peer admission, ACLs and routing.
- `easytier/`: native transport/runtime adapters and platform entrypoints.
- `easytier-proto/`: shared wire/API types; extend compatibly.
- `easytier-gui/`: desktop integration; use native service mechanisms for startup.
