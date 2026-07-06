# pki-orchestrator

A VM-resident agent that mediates post-boot control of a deployed VM on behalf
of [EC-PKI-Playground](https://github.com/Arnesh-EC/EC-PKI-Playground).

## Vision

`configgen` generates this agent's first-boot configuration, `isokit` packs it
into the VM's boot ISO, and `vmkit` deploys the VM. Once the VM boots, the
orchestrator runs as a persistent Windows Service, phones home to the
EC-PKI-Playground backend to establish two-way communication, and then
executes a **role-differentiated command surface**: guests get a narrow,
allowlisted set of commands; operators get the broad/arbitrary set, gated by
the backend's already-reserved `Capability.VM_EXEC_ARBITRARY`
(`backend/src/app/core/authz.py`). The end goal is to compose an entire PKI
topology on the EC-PKI-Playground dashboard, hit deploy, and have this agent
carry out the build (AD DS forest promotion, ADCS install, CDP/AIA
configuration, domain join, cert enrollment — see
`pki-lab-guides/vm-building.md` for the manual reference process) behind the
scenes, streaming progress back to the frontend.

Windows Server is the only target for now; Linux support is a stated future
goal.

## Out of scope for v0 / v1

v0 proved the core architecture — role-gated command dispatch, PowerShell
execution, Windows Service lifecycle — with a small, real, testable slice
and no networking at all. v1 (this revision) wires up the actual phone-home
mechanism: the orchestrator connects out to the backend, receives dispatched
commands, and streams their progress back — see "Phone-home" below. Still
deliberately **not** included:

- **Automatic, ISO-embedded registration.** The backend-issued `vm_id`/
  `agent_token` pair (see below) is copied into `orchestrator.toml` by a
  human today, standing in for what a real deployment will do automatically
  once the `isokit`/`configgen` gaps below close.
- The full ADCS command catalog from `vm-building.md` (AD DS forest
  promotion, CA install, template publishing, OCSP configuration, etc.) —
  only 3 commands are implemented, chosen to exercise every point on the role
  spectrum (see below).
- Packaging/deployment integration with `configgen`/`isokit`/`vmkit`.

## Future integration points

Gaps identified in the sibling repos while designing this one, so they don't
need rediscovering later:

- **isokit** (`build_script_iso`) only accepts text scripts, force-decoded as
  UTF-8 with rewritten line endings — it cannot embed a compiled binary today.
  Shipping this orchestrator's binary via the boot ISO will need a new
  binary-embedding API there.
- **vmkit** has no guest-level communication (no VMware Tools/VIX guest-exec,
  no IP/hostname readback) — there is no existing way for the backend to
  correlate an inbound "phone home" call to a specific VM record. `vm_id` +
  `agent_token` (see "Phone-home" below) are the correlation mechanism that
  will eventually be baked into the config ISO automatically; today they're
  copied in by hand.
- **configgen** has no plugin/extension point for emitting an "install the
  orchestrator" first-boot step — only hostname/network/local-password
  renderers exist today.

## Phone-home

`connect` (and, on Windows, `service run`) opens a long-lived WebSocket to
`{backend.url}/api/orchestrator/connect?vm_id=&token=` and stays connected,
reconnecting with capped backoff on any drop. Each inbound frame is a
dispatched command tagged with a job id and the role the backend
authenticated the calling human as:

```json
{"job_id": "...", "command": "cert.verify", "params": {"path": "..."}, "role": "guest"}
```

The **backend is the authoritative capability gate** — it checks the human's
role via its own `require_capability` before ever forwarding a command, and
that forwarded `role` is what `CommandRegistry::dispatch` checks here, not
`identity.role` from local config (which is only a fallback for the one-shot
`run` CLI path, which has no backend in the loop). This local dispatch check
is a second, structural gate, not the primary one.

Progress streams back as `{"job_id": "...", "state": <OpRunState>}` frames,
which the backend relays onto the existing `/api/ws/jobs/{job_id}` transport
— no new frontend plumbing needed to watch it.

Get a `vm_id`/`agent_token` pair via `POST /api/orchestrator/register` on the
backend before running `connect`; see the backend's own docs for the request
shape.

## Command surface (v0)

| Command | Capability | Guest-eligible? | Source |
|---|---|---|---|
| `hostname.rename` | `VmUpdate` | No | `Rename-Computer` pattern, used repeatedly across `vm-building.md` |
| `cert.verify` | `VmRead` | **Yes** | `certutil -verify -urlfetch`, the guide's own health-check command |
| `powershell.exec_arbitrary` | `VmExecArbitrary` | **No** (by construction) | Reserved escape hatch — must never reach a guest |

`cert.verify` is deliberately guest-eligible to prove the *allowed* path
through the registry, not just the forbidden one. `powershell.exec_arbitrary`
is the load-bearing negative case: `CommandRegistry::dispatch` must reject it
for `Role::Guest` before the handler ever runs.

### Planned (not yet implemented)

The full catalog this orchestrator will eventually need, drawn from
`pki-lab-guides/vm-building.md`'s two-tier ADCS lab (DC01/CA01/CA02/SRV1/WIN11).
Each will be added as its own command handler once the v0 pattern above is
validated:

| Planned command | Capability | Notes |
|---|---|---|
| `ad.promote_forest` | `VmExecArbitrary` | AD DS forest promotion + DNS |
| `ca.install_standalone_root` | `VmExecArbitrary` | CAPolicy.inf + standalone root CA install |
| `ca.configure_registry` | `VmExecArbitrary` | `certutil -setreg` cluster (CRL periods, auditing) |
| `ca.configure_cdp_aia` | `VmExecArbitrary` | AIA/CDP publication URLs |
| `ca.sign_request` / `ca.install_subordinate` | `VmExecArbitrary` | Cross-CA CSR signing pass |
| `ca.publish_template` | `VmExecArbitrary` | `Add-CATemplate` |
| `iis.configure_cert_enroll_share` | `VmExecArbitrary` | Web CDP/AIA hosting |
| `ocsp.configure_revocation` | `VmExecArbitrary` | **COM-only** (`CertAdm.OCSPAdmin`) — no clean PowerShell path per the guide; will need a distinct `windows-rs`-based executor, not the `.ps1` shell-out path used everywhere else |
| `domain.join` | `VmExecArbitrary` | `Add-Computer` |

## Architecture

- `authz.rs` — local mirror of the backend's `Role`/`Capability`/
  `ROLE_CAPABILITIES`. Wire values must match `authz.py`'s `.value` strings
  exactly; there is no automated sync between the two languages.
- `report.rs` — `OpRunState`/`OpStatus` mirror the backend's
  `app/core/jobs/models.py::OpRunState` shape, so a future backend adapter is
  a serializer, not a redesign.
- `registry.rs` — `CommandRegistry::dispatch` checks the caller's role against
  a handler's required capability *before* calling into it — structurally
  impossible for a new handler to forget its own gate.
- `powershell.rs` — `PowerShellExecutor` trait, with a real
  `std::process::Command`-based implementation and a mock for tests. Shells
  out rather than binding COM, since every v0 command has a plain PowerShell
  equivalent and this is what's testable from a non-Windows dev machine.
- `commands/` — the 3 v0 handlers.
- `phonehome.rs` — the WebSocket client: connects, dispatches inbound
  commands via `spawn_blocking` (dispatch/PowerShell execution are
  synchronous and must not block the async reactor), streams `OpRunState`
  progress back, reconnects with capped backoff. `handle_command` (the
  framing/dispatch translation) is a plain sync function, unit-tested with
  an in-memory channel standing in for the socket.
- `cli.rs` — `run` (one-shot local dispatch, no backend), `connect` (phone
  home and serve commands, any OS), `service` (Windows SCM integration).
- `service/` — `console.rs::run_loop` bridges the sync CLI/SCM entry points
  to the async `phonehome::run_forever` with a dedicated Tokio runtime, and
  is shared by both the `connect` path and the real SCM-invoked path — one
  control-flow implementation, not two. `scm.rs` (Windows-only,
  `cfg(windows)`) wraps the `windows-service` crate for
  `service {install,uninstall,run}` — not compiled on Linux, so it's
  validated by CI's `windows-latest` job. The phone-home loop runs on its
  own thread there since it never returns in normal operation; the SCM
  thread only waits for a stop signal (no in-loop graceful shutdown yet).

## Usage

```sh
cp orchestrator.example.toml orchestrator.toml
cargo run -- run cert.verify --param path=/path/to/cert.cer
# {"status":"running","percent":50.0,"phase":"verifying"}
# {"status":"done","percent":100.0,"result":{"chain_ok":false,"raw":""}}
# { "chain_ok": false, "raw": "" }
```

Each `--param key=value` becomes a command parameter; `--config` (default
`orchestrator.toml`) selects which config file's `role` governs the dispatch.
A guest-role config rejects `powershell.exec_arbitrary` before any shell runs:

```sh
cargo run -- run powershell.exec_arbitrary --param script="echo hi"
# Error: role Guest lacks capability VmExecArbitrary required by 'powershell.exec_arbitrary'
```

To phone home instead of dispatching locally, fill in `identity.vm_id`,
`identity.agent_token`, and `backend.url` (from `POST /api/orchestrator/register`
on the backend) in `orchestrator.toml`, then:

```sh
cargo run -- connect --config orchestrator.toml
```

On Windows, to install as a service (which calls the same phone-home loop):

```powershell
pki-orchestrator.exe service install
```

## Testing

`cargo test` runs everything that doesn't require a real Windows box, a live
shell, or a live backend: config parsing, capability/role gating (including
the guest ↔ `VmExecArbitrary` invariant), all 3 command handlers driven
through a mock PowerShell executor, and the phone-home framing/dispatch
translation (`phonehome::handle_command`) driven through an in-memory
channel. Real `powershell.exe` invocation, a real WebSocket connection to a
running backend, and Windows Service Control Manager lifecycle are exercised
only in CI's `windows-latest` job / manual testing — see the CI workflow for
what actually runs where, and the top-level plan's Verification section for
the manual end-to-end phone-home walkthrough.
