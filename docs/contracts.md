# System Contracts

Stable contracts. Do not change without updating this document.

## Binaries

| Binary | Crate | Purpose |
|--------|-------|---------|
| `facelock` | facelock-cli | Unified CLI (daemon, auth, enroll, test, setup, etc.) |
| `pam_facelock.so` | pam-facelock | PAM authentication module |
| `facelock-polkit-agent` | facelock-polkit | Polkit face authentication agent |

## CLI Subcommands

| Command | Purpose |
|---------|---------|
| `facelock setup` | Interactive setup wizard (camera, models, inference device, encryption, enrollment, PAM); also manages `facelock` group membership (creates the group if missing, adds the invoking user) |
| `facelock setup --systemd` | Install/enable systemd units |
| `facelock setup --pam` | Install PAM module to `/etc/pam.d/` |
| `facelock enroll` | Capture and store a face |
| `facelock test` | Test face recognition |
| `facelock list` | List enrolled face models |
| `facelock remove <id>` | Remove a specific model |
| `facelock clear` | Remove all models for a user |
| `facelock preview` | Live camera preview |
| `facelock devices` | List V4L2 cameras |
| `facelock status` | Check system status |
| `facelock config` | Show/edit configuration |
| `facelock daemon` | Run persistent daemon |
| `facelock auth --user X` | One-shot auth (PAM helper) |
| `facelock tpm status` | TPM status |
| `facelock hyprlock enable\|disable\|status` | Manage hyprlock lock-screen integration (user, no root); `enable` accepts `--no-icon` to skip the cosmetic face glyph |
| `facelock encrypt` | Encrypt face database |
| `facelock decrypt` | Decrypt face database |
| `facelock reseal` | Re-seal the TPM AES key under current PCRs (recovery after a firmware/kernel change) |
| `facelock tpm seal-key` / `unseal-key` | Migrate keyfile↔tpm key protection |
| `facelock tpm unseal-check` | Read-only: verify the sealed key still unseals (PCR policy satisfied) |
| `facelock audit` | View audit log |
| `facelock bench` | Benchmarks |
| `facelock restart` | Restart daemon |

## Operating Modes

| Mode | Config | PAM Behavior | CLI Behavior |
|------|--------|-------------|-------------|
| Daemon | `daemon.mode = "daemon"` (default) | D-Bus IPC to daemon | Uses daemon if available, falls back to direct |
| Oneshot | `daemon.mode = "oneshot"` | Spawns `facelock auth` | Operates directly (no daemon) |

The CLI silently falls back to direct mode when the daemon is not available on D-Bus, regardless of config mode.

### facelock auth Exit Codes

| Code | Meaning | PAM Code |
|------|---------|----------|
| 0 | Face matched | PAM_SUCCESS |
| 1 | No match / timeout / dark | PAM_AUTH_ERR |
| 2 | Error / no enrolled faces | PAM_IGNORE |

## Filesystem Paths

| Path | Owner | Mode | Purpose |
|------|-------|------|---------|
| `/etc/facelock/config.toml` | root:root | 644 | Configuration |
| `/var/lib/facelock/facelock.db` | root:facelock | 640 | Face embeddings |
| `/var/lib/facelock/models/` | root:root | 755 | ONNX models |
| `/var/log/facelock/audit.jsonl` | root:facelock | 640 | Structured audit log |
| `/var/log/facelock/snapshots/` | root:facelock | 750 | Auth snapshots |
| `/usr/bin/facelock` | root:root | 755 | CLI binary |
| `/lib/security/pam_facelock.so` | root:root | 755 | PAM module |

All paths overridable via config. `FACELOCK_CONFIG` is honored for unprivileged processes, but privileged PAM/root auth flows ignore the environment and use either an explicit `--config` path or `/etc/facelock/config.toml`.
Runtime-created DB sidecars (`-wal`, `-shm`), audit logs, and snapshots are created with explicit restrictive modes. The packaged systemd unit also sets `UMask=0027`.

### Audit Log Entries

`audit.jsonl` is JSONL; each line carries `timestamp`, `user`, `result` (`success`, `failure`, `error`, `rate_limited`, `suppressed`) and, when known, `similarity`, `frame_count`, `duration_ms`, `device`, `model_label`, `error`.

`source` names the code path that produced the entry — `daemon` (the `Authenticate` D-Bus method), `oneshot` (the `facelock auth` helper PAM spawns), or `test` (direct-mode `facelock test`, which runs the recognition loop in-process). It records the **enforcement path, not the caller's intent**: `facelock test` against a running daemon goes through `Authenticate` and is logged as `daemon`, because it runs the full `pre_check` gates (rate limiting, `require_ir`, SSH/lid abort) and its failures count against the rate limit. Only `test` skips those gates, so a `success` stamped `test` is a recognition result, not a policy-approved authentication. The field is absent on entries written before it existed.

## Config Schema

TOML format. All keys optional — camera auto-detected, sensible defaults for everything.

### Sections

| Section | Key fields |
|---------|-----------|
| `[device]` | `path` (Option), `max_height`, `rotation`, `warmup_frames`, `dark_threshold`, `dark_pixel_value`, `ir_emitter`, `camera_release_secs` |
| `[recognition]` | `threshold`, `timeout_secs`, `detector_model`, `detector_sha256`, `embedder_model`, `embedder_sha256`, `threads`, `execution_provider` |
| `[daemon]` | `mode` (DaemonMode enum), `model_dir`, `idle_timeout_secs` |
| `[storage]` | `db_path` |
| `[security]` | `disabled`, `suppress_unknown`, `require_landmark_liveness`, `require_ir`, `require_frame_variance`, `frame_variance_max_similarity`, `ir_texture_min_stddev`, `min_auth_frames`, `bind_templates_to_device`, `device_match_granularity`, `bind_legacy_templates`, `bind_device_aad`, `allow_plaintext`, `abort_if_ssh`, `abort_if_lid_closed`, `pam_policy`, `rate_limit` |
| `[notification]` | `mode` (off/terminal/desktop/both), `notify_prompt`, `notify_on_success`, `notify_on_failure` |
| `[snapshots]` | `mode` (off/all/failure/success), `dir` |
| `[encryption]` | `method` (keyfile/tpm/none — **default keyfile**), `key_path`, `sealed_key_path` |
| `[audit]` | `enabled`, `path`, `rotate_size_mb` |
| `[tpm]` | `seal_database`, `pcr_binding`, `pcr_indices`, `tcti` |
| `[polkit]` | `face_eligible_actions` |

`[polkit].face_eligible_actions` is the allowlist of polkit `action_id`s for which
the face authentication agent may offer face auth. Default:
`["org.freedesktop.login1.lock-sessions"]`. Any action not in the list is declined
by the agent. An empty list disables face for all actions. High-risk actions
(pkexec, PackageKit, udisks mount, accounts-service) are excluded by default.

**Scope:** this allowlist governs the **agent model** only. Under the **PAM model**
(`pam_facelock.so` as `auth sufficient` in `/etc/pam.d/*`, the common Howdy-style
deployment that also covers `sudo`), the list is ignored: face is attempted for
every action in that PAM stack, always with password fallback because the line is
`sufficient`, never `required`. See `docs/security.md` §7a/§7b for the two models.

**NOTE (agent model only):** polkit registers a single authentication agent per
session and does not chain agents. When this agent declines a non-allowlisted
action it returns an error, which — depending on the desktop's agent
registration — may present as an authorization denial rather than a
fallthrough to a password dialog. The intended UX (non-eligible actions
handled by the desktop's normal password agent) is unverified pending
live-desktop testing and may require a design change. Behavior here is
fail-closed: a non-eligible action is never face-authorized.

**Encryption defaults (Plan 04).** `encryption.method` defaults to `keyfile`: face
templates are encrypted at rest by default. The keyfile is auto-generated at mode `0600`
on first use if absent. `method = "none"` (plaintext) is **refused at enrollment** unless
`security.allow_plaintext = true`. Auth always degrades to password on a decrypt failure —
never a lockout.

**Hard device binding (opt-in).** `security.bind_device_aad = true` folds the enrolling
camera's `device_id` into the AES-GCM AAD, so a template cannot be decrypted under a
different camera. Default false (fails closed on unstable ids). Complements the advisory
device coupling of Plan 02.

**TPM sealed-key format & unseal semantics (Plan 04).** The sealed-key blob is versioned:
`0x01` = no PCR policy; `0x03` = PCR-bound, and self-describes its PCR index list. A
PCR-bound object is created with `userWithAuth = false`, and unseal starts a real policy
session and replays `PolicyPCR` — so a changed bound PCR makes unseal **fail** (finding #5).
`facelock reseal` re-seals the key under the current PCRs (recovery path).

### Camera Auto-Detection

When `device.path` is omitted:
1. Enumerate `/dev/video0` through `/dev/video63`
2. Filter to VIDEO_CAPTURE devices
3. Classify every node's IR provenance (quirks `force_ir` authoritative; name
   token / format-corroboration heuristic otherwise), with node-level
   disambiguation for multi-node USB devices: when several nodes share one
   quirk-matched VID:PID and at least one has an IR-like format (GREY/Y16 or
   the quirk's `format_preference`), only the format-bearing node(s) are IR
4. Prefer a quirks-confirmed IR node with a native IR format, then any
   quirks-confirmed IR node, then a name-token IR node
5. Fall back to first available device

## Database Schema

SQLite with WAL mode and foreign keys:

```sql
CREATE TABLE face_models (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user TEXT NOT NULL,
    label TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    embedder_model TEXT NOT NULL DEFAULT '',  -- V5: embedder that produced the embeddings
    device_id TEXT,                           -- V6: enrolling camera fingerprint "vid:pid:serial" (NULL = legacy/uncoupled)
    UNIQUE(user, label)
);

CREATE TABLE face_embeddings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    model_id INTEGER NOT NULL REFERENCES face_models(id) ON DELETE CASCADE,
    embedding BLOB NOT NULL,  -- 512 x f32 = 2048 bytes (or encrypted blob)
    sealed INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE rate_limit (
    user TEXT NOT NULL,
    attempt_time INTEGER NOT NULL
);
```

Only failed authentication attempts are recorded in `rate_limit`. Daemon mode and oneshot mode share the same SQLite-backed window, so daemon restarts do not clear lockout state.

**Schema version** is tracked in `schema_version`; migrations are additive and forward-only. Current version: **6**. Migration V6 adds the nullable `face_models.device_id` column (Plan 02 device coupling); pre-V6 databases open cleanly, keep their rows, and leave `device_id` NULL. NULL rows are governed by `security.bind_legacy_templates` (default allow-with-warn), so upgrades never lock a user out.

`device_id` is the canonical fingerprint (`"vid:pid:serial"`) of the camera that enrolled the template. It is **model-granularity at best and forgeable by a programmable USB device** — advisory defense-in-depth, NOT attestation. See `docs/security.md` §Device Coupling.

## IPC Protocol

D-Bus system bus (`org.facelock.Daemon`). Only used in daemon mode.

The daemon registers on the system bus via D-Bus activation.

- **Bus name**: `org.facelock.Daemon`
- **Object path**: `/org/facelock/Daemon`
- **Interface**: `org.facelock.Daemon`

### Methods
`Authenticate`, `Enroll`, `ListModels`, `RemoveModel`, `ClearModels`, `PreviewFrame`, `PreviewDetectFrame`, `ListDevices`, `ReleaseCamera`, `Ping`, `Shutdown`

Method authorization contract:
- `Authenticate`, `ListModels`, `PreviewDetectFrame`: root or the matching Unix user.
- `Enroll`, `RemoveModel`, `ClearModels`, `PreviewFrame`, `Shutdown`: root only.
- `ReleaseCamera`: root or the Unix user that owns the active preview camera session.
- `ListDevices`, `Ping`: resolve caller UID before replying and rely on the system bus policy for admission control.

Raw camera frames require privilege. `PreviewFrame` remains root-only.
`PreviewDetectFrame` returns the `jpeg_data` frame bytes to root
unconditionally; a non-root caller receives them **only** after an
interactive polkit authorization for the action
**`org.facelock.preview-frames`** (shipped in `dbus/org.facelock.policy`,
installed to `/usr/share/polkit-1/actions/org.facelock.policy`; defaults
`allow_any=no`, `allow_inactive=no`, `allow_active=auth_self_keep`). The
daemon checks the caller via
`org.freedesktop.PolicyKit1.Authority.CheckAuthorization` (subject = the
caller's unique bus name, `AllowUserInteraction=true`); the first frame
request triggers the caller's polkit agent prompt. While unauthorized —
denied, prompt pending, polkit unreachable, or any D-Bus error — the daemon
**fails closed**: `jpeg_data` is empty and the caller receives detection and
recognition metadata (bounding boxes, confidence, similarity, recognized)
only.

The polkit verdict is cached per caller **connection** (keyed by unique bus
name): granted verdicts for at most 120 s, denied/errored verdicts for 15 s,
and every cached verdict dies when the caller's bus connection closes
(whichever comes first). Clients that want frames across a preview session
must therefore keep one D-Bus connection open for the whole session.

Method timeouts: `Enroll` runs synchronously inside the method call for up to
`Config::enroll_timeout_secs()` seconds server-side (`3 × max(recognition.timeout_secs, 5)`
seconds — i.e. minimum 15s). Clients MUST use a method timeout **greater
than** this deadline plus startup/inference margin for `Enroll` (the CLI uses
deadline + 15s); the shared 15-second client timeout applies to every other
method. A client timeout at or below the server deadline aborts the call while
the daemon is still enrolling.

Enrollment behavior is mode-independent: oneshot (`facelock enroll` in direct
mode) and the daemon's `Enroll` method run the same capture loop, so the
quality gate and the angle-diversity check apply in both.

Capture concurrency: `Authenticate`, `Enroll`, `PreviewFrame`, and
`PreviewDetectFrame` are serialized by an in-flight capture guard. While one
capture is in progress, a concurrent call to any of these methods fails
**immediately** with an `org.freedesktop.DBus.Error.Failed` error whose
message contains `daemon busy` (no queuing on the internal handler lock).
Clients (PAM included) must treat this like any other daemon error — degrade
to the next auth mechanism (password), never a lockout.

### Signals
- `AuthAttempted(user: s, matched: b)` — emitted after each authentication
  attempt. The payload intentionally carries **no similarity score** (the raw
  biometric score is an information leak / spoof-tuning oracle). The system
  bus policy (`dbus/org.facelock.Daemon.conf`) denies signal reception from
  the daemon by default; only root and members of the `facelock` group may
  receive it.

### Response types
`AuthResult`, `Enrolled`, `Models`, `Removed`, `Frame`, `DetectFrame`, `Devices`, `Ok`, `Error`

`Models` carries `ModelInfo { id, user, label, created_at, embedder_model, device_id }`. `device_id` (added Plan 02) is the enrolling camera's canonical fingerprint; D-Bus has no Option type, so an **empty string is the NULL sentinel** for legacy/uncoupled templates (same convention as `AuthResult`).

### Authenticate error encoding

`Authenticate` returns `AuthResult (matched: b, model_id: i, label: s, similarity: d)`.
Sentinel `model_id` values (only meaningful with `matched == false`):

| model_id | Meaning |
|----------|---------|
| >= 0 | Matched model id (with `matched == true`) |
| -1 | No match / no enrolled faces |
| -2 | Recoverable daemon error; `label` carries the error message (rate limited, IR required, camera/storage failure) |
| -3 | Suppressed: no enrolled models and `security.suppress_unknown = true` |

Recoverable errors travel **in-band** (model_id `-2`), not as D-Bus errors, so
clients can distinguish "the daemon decided auth cannot proceed" from "the
daemon is unavailable". D-Bus errors remain for authorization failures,
daemon-busy, and transport problems. In particular, a rate-limited state is a
daemon decision and must never make the PAM client retry via a root oneshot.

### Daemon peer verification (PAM client)

Before trusting an `Authenticate` reply, the PAM module resolves the owner of
`org.facelock.Daemon` (`GetNameOwner`, activating the service first if
needed), requires the owner UID to be 0 (`GetConnectionUnixUser`), and pins
the method call to the owner's unique bus name. A non-root owner is refused:
the module falls through (oneshot fallback / password), never `PAM_SUCCESS`.

## PAM Semantics

| Outcome | PAM Code |
|---------|----------|
| Face matched | `PAM_SUCCESS` (0) |
| No match | `PAM_AUTH_ERR` (7) |
| Rate limited (daemon, model_id -2) | `PAM_AUTH_ERR` (7) — no oneshot fallback |
| IR required / internal daemon error (model_id -2) | `PAM_IGNORE` (25) — no oneshot fallback |
| Suppressed (model_id -3) | `PAM_AUTHINFO_UNAVAIL` (9) |
| Daemon unavailable / untrusted (non-root) peer | oneshot fallback, else `PAM_IGNORE` (25) |
| Config missing, unparseable, or untrusted (not root-owned / group- or world-writable, incl. parents) | `PAM_IGNORE` (25) |
| Timeout (structured zbus timeout or overall deadline) | `PAM_AUTH_ERR` (7) |

PAM module never blocks indefinitely. All operations have timeouts, including
D-Bus connection establishment (overall deadline on a worker thread).

The oneshot fallback spawns `facelock auth` with a sanitized environment:
`env_clear()` plus an allow-list of `SSH_CONNECTION`, `SSH_TTY`, and a pinned
`PATH=/usr/bin:/bin`. No other variables (`LD_*`, `XDG_*`, `DBUS_*`, ...) are
inherited. Stdin is `/dev/null`.

### Syslog Format

```
pam_facelock(<service>): <result> for user <username>
```

## Polkit Agent Semantics

The `facelock-polkit-agent` offers face authentication for polkit actions, but
scoped to an allowlist — face is **not** a universal key for every privileged action.

| Outcome | Agent behavior |
|---------|----------------|
| `action_id` not in `polkit.face_eligible_actions` | Declines (returns `org.freedesktop.DBus.Error.Failed`) — see fallthrough-vs-denial caveat below |
| Allowlisted action, face matches | Responds success to polkit authority |
| Allowlisted action, no match / daemon error | Declines (same caveat) |
| Username cannot be resolved to a uid | Refuses to respond; **never** sends UID 0 for an unresolved name |

**NOTE (agent model only):** polkit registers a single authentication agent per
session and does not chain agents. When this agent declines, the decline
returns an error, which — depending on the desktop's agent registration — may
present as an authorization denial rather than a fallthrough to a password
dialog. The intended UX (non-eligible actions handled by the desktop's normal
password agent) is unverified pending live-desktop testing. Behavior here is
fail-closed: a non-eligible action is never face-authorized. Does not apply to
the PAM model, which always falls through to the password prompt.

A decline never fails open to root, and never causes this agent itself to grant
authorization it should not — but see the caveat above on whether polkit
treats a decline as a fall-through to another agent or as an outright denial.

## Anti-Spoofing

| Defense | Config | Default |
|---------|--------|---------|
| IR camera enforcement | `security.require_ir` | **true** |
| Frame variance check | `security.require_frame_variance` | **true** |
| Frame variance cutoff | `security.frame_variance_max_similarity` | 0.985 |
| IR texture cutoff (raw frame) | `security.ir_texture_min_stddev` | 10.0 |
| Landmark liveness | `security.require_landmark_liveness` | **false** |
| Minimum auth frames (= variance window size) | `security.min_auth_frames` | 3 |
| Frame variance default const | `DEFAULT_FRAME_VARIANCE_MAX_SIMILARITY` | 0.985 |

IR classification requires a whole `ir`/`infrared` name token or a quirks `force_ir`
entry; a GREY/Y16 format alone is not treated as IR. A `force_ir` quirk is
device-level ("this USB device has an IR sensor"): when the device exposes multiple
capture nodes and at least one has an IR-like format, only the format-bearing
node(s) classify IR (see `docs/security.md` §A). Frame variance is passive
anti-photo only (does not stop video replay); it is evaluated over a sliding window
of the most recent `min_auth_frames` matched frames (see `docs/security.md` §B), with
a 0.985 cutoff rejecting truly static input (≳0.999) with margin; the
field-measured frozen-human band is 0.98–0.995, and the default sits inside it —
a fully frozen user recovers via the sliding window as soon as they move
slightly. IR texture is measured on the raw frame, never CLAHE. These defaults
must not be weakened without security review.

## Models

| Model | File | Size | Default |
|-------|------|------|---------|
| SCRFD 2.5G | `scrfd_2.5g_bnkps.onnx` | ~3MB | Yes |
| ArcFace R50 | `w600k_r50.onnx` | ~166MB | Yes |
| SCRFD 10G | `det_10g.onnx` | ~17MB | Optional |
| ArcFace R100 | `glintr100.onnx` | ~249MB | Optional |

Configurable via `recognition.detector_model` and `recognition.embedder_model`.
Bundled model filenames are verified against the manifest hash at load time. Custom model files require matching `recognition.detector_sha256` or `recognition.embedder_sha256`.
