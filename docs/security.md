# Security Model

## Threat Model

facelock is a **local biometric authentication system**. The threat model assumes:

- **Attacker has physical access** to the machine (the entire point of face auth is physical-presence scenarios like unlocking a laptop)
- **Attacker may have a photo or video** of the enrolled user
- **Attacker does not have root** (if they do, game over regardless)
- **Attacker cannot modify files** in `/etc/facelock/`, `/var/lib/facelock/`, or `/lib/security/`

## Privacy Guarantees

Facelock is designed to keep biometric data under the user's exclusive control:

- **Local-only inference**: All face detection and recognition runs on-device via ONNX Runtime. No images, embeddings, or metadata are ever transmitted over the network.
- **No telemetry**: Facelock contains zero analytics, tracking, or phone-home code. After the one-time model download during `facelock setup`, it never contacts any server.
- **No cloud dependencies**: Authentication works fully offline. No account registration, no API keys, no external services.
- **Data stays on disk**: Face embeddings are stored in a local SQLite database (`/var/lib/facelock/facelock.db`) with restrictive permissions (640, root:facelock). Optional AES-256-GCM encryption with TPM-sealed keys provides defense in depth.
- **Open source**: All code is MIT/Apache-2.0 licensed. No proprietary blobs or obfuscated network calls. Privacy claims are verifiable by reading the source.

## Attack Vectors & Mitigations

### 1. Photo/Video Spoofing (CRITICAL)

**Attack**: Hold a photo or video of the enrolled user in front of the camera.

**Why this matters**: This is the #1 attack against face authentication. Without mitigation, anyone with a Facebook photo can unlock the machine.

**Mitigations** (layered, implement all):

#### A. IR Camera Enforcement (Required)

Add `security.require_ir` config flag, **default true**:

```toml
[security]
require_ir = true  # Refuse to authenticate on RGB-only cameras
```

Implementation (`facelock-camera/src/device.rs`, `ir_source_with_quirks`):

```rust
// IR classification is honest about its evidence, surfaced as IrSource:
//   Quirk  – hardware quirks DB force_ir = true (authoritative, both directions)
//   Format – native IR format (GREY/Y16) CORROBORATED by an IR name token
//   Name   – an "ir"/"infrared" name *token* (tokenized, not substring)
//   None   – not IR
//
// Per-node precedence:
// 1. quirks DB force_ir is authoritative;
// 2. a native GREY/Y16 format counts ONLY when corroborated by a name token;
// 3. a name token alone is sufficient;
// 4. otherwise not-IR.
pub fn ir_source_with_quirks(device, quirks) -> IrSource { ... }

// Node-level disambiguation for multi-node USB devices: force_ir means "this
// USB device HAS an IR sensor", not "every capture node of it is IR". One
// physical camera can expose several V4L2 nodes under one VID:PID (Logitech
// BRIO 046d:085e: /dev/video0 = RGB YUYV/MJPG, /dev/video2 = IR native GREY).
// When multiple nodes share a quirk-matched USB identity AND at least one has
// an IR-like format (GREY/Y16, or the quirk's format_preference), only the
// node(s) with that format classify IR; siblings fall back to the quirk-free
// heuristic. If NO node has an IR-like format, force_ir is trusted for all
// (some quirk entries exist precisely because the camera advertises no
// IR-like format). Anything gating require_ir uses these sibling-aware forms:
pub fn classify_ir_sources(devices, quirks) -> Vec<IrSource> { ... }
pub fn ir_source_resolved(device, quirks) -> IrSource { ... } // enumerates siblings

// In the auth flow (daemon pre_check and oneshot), before recognition:
if config.security.require_ir && !device_is_ir {
    return DaemonResponse::Error {
        message: "IR camera required for authentication. Set security.require_ir = false to override (NOT RECOMMENDED).".into()
    };
}
```

**Rationale**: Phone screens and printed photos do not emit infrared light correctly. An IR camera sees a flat, textureless surface where a real face would have depth and skin texture in IR. This single check eliminates the vast majority of spoofing attacks.

**Why mere GREY/Y16 availability is not enough (H1)**: many ordinary RGB UVC webcams *enumerate* a GREY format alongside YUYV/MJPG. The previous heuristic (`contains("ir")` OR any GREY/Y16 format) misclassified those as IR, silently defeating `require_ir = true`. It also matched the substring "ir" inside unrelated names ("Sirius", "AIR-Cam"). The classifier now requires a whole `ir`/`infrared` **token** or a **quirks `force_ir`** entry, and treats a GREY/Y16 format as IR **only when corroborated** by one of those. This is why `require_ir` is now load-bearing rather than trivially bypassable.

**Why `force_ir` is device-level, not node-level (hardware-verified regression)**: on a real Logitech BRIO, treating every quirk-matched node as IR made *both* `/dev/video0` (the RGB sensor) and `/dev/video2` (the IR sensor) classify IR — so setup stopped auto-selecting and auto-detect captured from the RGB sensor (white LED) instead of the IR sensor. The sibling-format disambiguation above restores per-node honesty: exactly one BRIO node is `[IR]`, and auto-detection prefers the format-corroborated IR node.

**Limitation**: classification is still heuristic without a hardware allow-list. Some genuine IR cameras report neither an IR name token nor a known quirk; add a quirks `force_ir` entry (`/etc/facelock/quirks.d/`) for such hardware (and set `format_preference` to the IR node's native format, e.g. `"GREY"`, when the camera exposes multiple capture nodes). The `facelock devices` command displays whether each camera is detected as IR. Device *identity* pinning (rather than capability heuristics) is implemented as its robust successor — see §1.D Device Coupling (Plan 02).

#### B. Frame Variance Check (Required)

Require minimum variance across consecutive matched frames during authentication.
The check is evaluated over a **sliding window** of the most recent
`min_auth_frames` matched-frame embeddings (`FrameVarianceWindow` in
`facelock-core/src/types.rs`): the gate passes only when the window is full AND
every consecutive pair inside it has cosine similarity at or below the cutoff
(`security.frame_variance_max_similarity`, default **0.985**,
`DEFAULT_FRAME_VARIANCE_MAX_SIMILARITY`).

**Why a sliding window**: an earlier version accumulated every matched frame for
the whole session and required *all* consecutive pairs to drift. One too-still
pair at any moment then made success permanently unreachable — a user who
started still and then moved could never recover (hardware-verified lockout).
The window forgets old frames: once it fills with moving frames the gate passes.
The anti-photo property is preserved because a truly static input keeps *every*
pair above the cutoff in *every* window, so no window ever passes, regardless of
session length. Embeddings evicted from the window are zeroized at eviction.

**Field-measured consecutive-pair similarity** (Logitech BRIO IR node, real user):

| Input | Consecutive-pair cosine similarity |
|-------|-----------------------------------|
| Truly static (photo on a stand, paused replay) | ≳ 0.999 |
| Frozen, non-blinking live human | 0.98 – 0.995 |
| Naturally moving live human | well below 0.98 |

The default cutoff (0.985) sits *inside* the frozen-human band — deliberately
stricter than the top of the band (0.995) for extra margin against static
replays that carry sensor-noise-level drift. The honest tradeoff: a fully
frozen, non-blinking user may not pass at 0.985, but because the gate is a
sliding window it recovers the moment they move slightly — the worst case is a
brief delay, never a lockout, and the PAM stack falls through to password
regardless. (An earlier default of 0.97 assumed a 0.02–0.10 live-drift range
that is empirically wrong for a still user — it caused hard false-reject
lockups where auth reported "no match" despite 0.91–0.98 recognition
similarity. The window-less design of that era turned stillness into a
permanent failure; the sliding window is what makes the stricter 0.985 default
safe to ship.)

**Honest scope — this does NOT stop video replay.** Frame-variance only rules out a
*static* image (printed photo, single frozen frame). A recorded video of the enrolled
user contains genuine inter-frame motion and will pass this check. Frame-variance is a
cheap passive defense-in-depth filter whose honest job is rejecting perfectly-static
input; **IR enforcement plus the raw-frame texture check (§A, §C) are the load-bearing
anti-spoof defenses**, and active liveness (opt-in landmark/blink) is the answer to
video replay.

**False-reject tradeoff**: `frame_variance_max_similarity` is the user-tunable
knob and stays purely passive either way. Loosen toward 0.995 (top of the
frozen-human band) if a very still user finds the delay annoying; tighten toward
0.97 for paranoia, accepting that holding still delays auth until you move.
Raising it above ~0.998 starts admitting sensor-noise-level drift and defeats
the check. When the timeout expires with matching frames but an unsatisfied variance gate,
`facelock test` says so explicitly, and per-window min/max pair similarities are
logged at debug level (values only, never embeddings) for tuning.

Config:
```toml
[security]
require_frame_variance = true         # Reject static images (photo attack defense)
frame_variance_max_similarity = 0.985 # Max consecutive-frame similarity in the window
min_auth_frames = 3                   # Matched frames required = variance window size
```

#### C. Dark Frame / IR Texture Validation (Recommended)

In IR mode, verify that the face region has expected IR texture characteristics:
- Real skin has micro-texture visible in IR
- Photos/screens appear as flat, uniform surfaces in IR
- Compute standard deviation of pixel intensity within the face bounding box
- Reject faces with abnormally low texture variance

```rust
pub fn check_ir_texture(gray: &[u8], bbox: &BoundingBox, width: u32, min_stddev: f32) -> bool {
    let face_pixels = extract_bbox_region(gray, bbox, width);
    if face_pixels.is_empty() { return false; }
    let mean: f32 = face_pixels.iter().map(|&p| p as f32).sum::<f32>() / face_pixels.len() as f32;
    let variance: f32 = face_pixels.iter().map(|&p| (p as f32 - mean).powi(2)).sum::<f32>() / face_pixels.len() as f32;
    variance.sqrt() > min_stddev
}
```

**Run on the RAW frame, not CLAHE (H3)**: this check MUST see the raw grayscale frame.
The auth loop previously fed a **CLAHE**-equalized frame into `check_ir_texture`. CLAHE
(Contrast-Limited Adaptive Histogram Equalization) stretches local contrast, which
*inflates* the std_dev of an otherwise flat photo/screen and pushes it above the cutoff —
i.e. CLAHE was masking exactly the spoof this check exists to catch. CLAHE now belongs
only to the recognition/embedding path; texture measurement uses `frame.gray` directly.

**Raw-frame calibration**: on the raw frame, flat surfaces (photos/screens in IR) score
std_dev **< 5**, real IR skin scores **> 15**. The cutoff `security.ir_texture_min_stddev`
defaults to **10.0** (between the two bands). Lower it if real faces are being rejected;
raise it toward 15 to be stricter. Applied on IR devices only (RGB texture is too variable).

#### D. Device Coupling — Template↔Camera Binding (Plan 02, default on)

**Attack it addresses**: the realistic attacker unplugs the enrolled IR camera and plugs
in *their own* camera — a commodity RGB webcam or a different-model unit — to feed a spoof
frame into the recognition path. The IR heuristics above (§A–C) are capability checks on
*whatever camera is currently attached*; they do not verify it is the *same* camera the
user enrolled on. Device coupling closes that gap by **identity** rather than capability.

Each enrolled template records a fingerprint of the camera that captured it — the canonical
string `"vid:pid:serial"` read from sysfs (`idVendor`/`idProduct`/`serial`), stored in
`face_models.device_id` (schema V6). At auth, the live camera is fingerprinted once and every
candidate template whose fingerprint does not match at the configured granularity is
**skipped before its embeddings are ever compared**. A skipped template can only produce
"no match", so a swapped-in camera **degrades to the password fallback** — it can never
reach a success, and it never causes a lockout (fail SOFT, matching the biometric-is-
`sufficient`-never-`required` contract).

Config (`[security]`):

```toml
bind_templates_to_device = true      # default; skip templates from a non-matching camera
device_match_granularity = "model"   # "model" = VID:PID (default), "unit" = VID:PID:serial
bind_legacy_templates    = true      # default; allow-with-warn for pre-V6 / NULL-device rows
```

- **`model`** (default) compares VID:PID only. Invisible to single-camera users; blocks a
  cross-model swap. Identical same-model cameras are accepted (documented behavior).
- **`unit`** additionally requires a matching serial. Blocks even a same-model swap, but only
  works on cameras that expose a stable serial — enrollment at `unit` on a serial-less camera
  is refused with an explanatory error rather than silently downgrading.
- **Legacy / unidentifiable cameras**: a pre-V6 template (NULL `device_id`) or one enrolled
  on a camera exposing no USB identity is stored NULL and governed by `bind_legacy_templates`.
  Default allow-with-warn so an upgrade never breaks existing enrollments; a one-line log
  nudges re-enrollment. Set it `false` to require every template to carry a matching id.
- **Enroll per camera**: enrolling the same user on a second camera creates a *second* template
  with its own `device_id` (the store already allows multiple models per user). Each template
  then authenticates only on its own camera. `facelock list` shows each template's camera.

**Honest threat framing — this is advisory defense-in-depth, NOT attestation.** `VID:PID` is
**model granularity**: every unit of the same model shares it. `serial` is unit-unique *when
present*, but vendors frequently omit or duplicate it. Most importantly, a **programmable USB
device can forge any of these fields** — consumer UVC cameras have no signed-frame
attestation, so there is no cryptographic root of trust to bind to. Device coupling raises the
bar against the attacker who buys/plugs a *commodity* camera; it does not stop an attacker who
builds a USB device that impersonates the enrolled camera's descriptors. It is one layer, not
a guarantee.

**Plan 04 seam — now wired (opt-in)**: `facelock_core::types::device_binding_aad()` defines
the AAD bytes for folding `device_id` into the AES-GCM Additional Authenticated Data. Plan 04
wires this through enroll and the decrypt path behind `security.bind_device_aad` (default
false): when enabled, each encrypted template is bound to its enrolling camera's id and cannot
be decrypted under a different one. It stays **opt-in** because hard binding fails closed on
the unstable/absent ids described above — enabling it on such hardware would degrade every
auth to password. Default-off keeps the never-lockout guarantee for everyone else.

### 2. Model Tampering

**Attack**: Replace ONNX model files with adversarial models that always match (or match specific attackers).

**Mitigations**:

#### A. SHA256 Verification at Load Time (Required)

Verify model integrity not just at download, but every time the daemon loads models:

```rust
impl FaceEngine {
    pub fn load(config: &RecognitionConfig, model_dir: &Path) -> Result<Self> {
        let manifest = load_manifest();

        for model in &manifest.default_models() {
            let path = model_dir.join(&model.filename);
            if !verify_model(&path, &model.sha256)? {
                return Err(FacelockError::Detection(format!(
                    "Model integrity check failed for {}. Expected SHA256: {}. \
                     Re-run `facelock setup` to re-download.",
                    model.filename, model.sha256
                )));
            }
        }
        // ... load models
    }
}
```

#### B. File Permissions on Model Directory (Required)

```bash
# Models owned by root, not writable by others
chown -R root:root /var/lib/facelock/models
chmod 755 /var/lib/facelock/models
chmod 644 /var/lib/facelock/models/*.onnx
```

### 3. Embedding / Database Security

**Attack**: Read or modify the SQLite database to extract biometric data or inject fake embeddings.

**Mitigations**:

#### A. Database File Permissions (Required)

```bash
# Database owned by root, readable only by root and facelock group
chown root:facelock /var/lib/facelock/facelock.db
chmod 640 /var/lib/facelock/facelock.db
```

Runtime note:
- The daemon/setup paths must also secure SQLite `-wal` and `-shm` sidecar files to `0640`
- Audit logs and snapshots must be created with explicit restrictive modes instead of relying on ambient umask
- The systemd service should set `UMask=0027` as a baseline defense-in-depth default

#### B. Embedding Sensitivity Warning (Required)

Face embeddings are **biometric data**. Unlike passwords, they cannot be changed. Document this:
- The database contains irreversible biometric templates
- If compromised, the user's face embeddings cannot be "rotated" like a password
- Embeddings should be treated as sensitive personal data

#### C. Encryption at Rest (Implemented — encrypted by default, Plan 04)

Face templates are **encrypted at rest by default** (`encryption.method = "keyfile"`, finding
#8). Embeddings are AES-256-GCM encrypted with a 256-bit key held in a key file
(`keyfile`) or a TPM-sealed key (`tpm`). The keyfile is auto-generated at mode `0600` on
first use if absent, in a single `open(2)` create-at-mode (no create-then-`chmod` window —
finding #11). The TPM method seals the AES key at rest; it is unsealed at daemon startup and
held in memory.

Plaintext storage (`method = "none"`) is an explicit opt-out: enrollment **refuses** to write
plaintext biometric templates unless `security.allow_plaintext = true`, and warns prominently
when it does. This never affects auth — a decrypt failure degrades to the password fallback,
never a lockout.

**Hard device binding (opt-in, `security.bind_device_aad`).** When enabled, the enrolling
camera's `device_id` is folded into the AES-GCM Additional Authenticated Data, so a template
sealed under one camera cannot be decrypted under another — the cryptographic complement to
the advisory device coupling in §1.D. Default off: hard binding fails closed on unstable or
absent device ids, so it is opt-in only.

**TPM PCR binding is enforced (finding #5).** With `tpm.pcr_binding = true`, the sealed key
object is created with `userWithAuth = false` and its PCR selection is recorded in the sealed
blob (version byte `0x03`). Unseal starts a *real* policy session and replays `PolicyPCR`
against the current PCRs, so a firmware/kernel change to a bound PCR makes the key refuse to
unseal (face auth then falls through to password). Recovery is `sudo facelock reseal`, which
re-seals the key under the current PCR state (recovering the key from the existing blob if the
PCRs still match, otherwise from the `encryption.key` backup). **Keeping that plaintext
`encryption.key` backup is the recommended setup**: it makes reseal recovery painless — no
re-enrollment after a firmware/kernel PCR change. The honest tradeoff is that, while the backup
exists, the `tpm` method's at-rest confidentiality against anyone who can read the file reduces
to that keyfile's `0600` (root-only) protection. `pcr_binding` remains **default false** —
enabling it is a deliberate operator choice that commits to the reseal workflow. See
`docs/configuration.md` for the `[encryption]` and `[tpm]` sections.

### 4. D-Bus IPC Security

**Attack**: Unauthorized user sends D-Bus messages to the daemon to trigger auth, enroll faces, or extract data.

**Mitigations**:

#### A. D-Bus System Bus Policy (Required)

Access to the daemon is restricted by the D-Bus system bus policy defined in `dbus/org.facelock.Daemon.conf`. Only root and members of the `facelock` group are allowed to send messages to the daemon interface. The policy file is installed to `/usr/share/dbus-1/system.d/` and enforced by the bus daemon itself. Setup and package install may also refresh a legacy `/etc/dbus-1/system.d/` copy when present, but `/usr/share/...` is the canonical install path.

The daemon must also verify the caller UID via `GetConnectionUnixUser` on every method call and apply method-level authorization:
- `Authenticate`, `ListModels`, `PreviewDetectFrame`: root or the matching Unix user
- `Enroll`, `RemoveModel`, `ClearModels`, `PreviewFrame`, `Shutdown`: root only
- `ReleaseCamera`: root or the Unix user that owns the active preview camera session
- `ListDevices`: root or a caller in the `facelock` group

The policy also self-contains two explicit defaults rather than relying on system-wide bus defaults:
- `<deny own="org.facelock.Daemon"/>` in the default context (name-squatting protection; only root may own the name).
- `<deny receive_sender="org.facelock.Daemon" receive_type="signal"/>` in the default context, with explicit allows for root and the `facelock` group (see below).

#### A2. PAM Peer-UID Verification (Required)

The trust check runs in both directions: before trusting an `Authenticate`
reply, the PAM module resolves the owner of `org.facelock.Daemon` via
`GetNameOwner`, verifies that owner's UID is 0 via `GetConnectionUnixUser`,
and pins the method call to the owner's *unique* bus name so the owner cannot
change between check and call. If the name is owned by a non-root process
(e.g. because the bus policy file was misconfigured or replaced), the module
refuses the reply and degrades — it never returns `PAM_SUCCESS` on the word
of an unverified peer. This removes the single point of failure on the
`org.facelock.Daemon.conf` policy file.

#### A3. In-Band Recoverable Error Encoding (Required)

Recoverable authentication errors (rate limited, IR required, camera or
storage failure) are returned in-band as `AuthResult { model_id: -2, label:
<message> }` rather than as D-Bus errors. A D-Bus error reply is
indistinguishable from "daemon broken", which would make the PAM module fall
back to a fresh root oneshot attempt — silently escalating past daemon-side
state such as the rate-limit window. With in-band encoding the PAM module
classifies the error itself: rate limited maps to `PAM_AUTH_ERR` (face-auth
budget exhausted, password modules still run), everything else to
`PAM_IGNORE`. D-Bus errors remain reserved for authorization failures and
transport-level problems, which do fall back to the oneshot path.

#### A4. Auth-Attempt Signal Hygiene (Implemented)

**Attack**: Any local user adds a match rule (or runs `dbus-monitor`) and passively observes `AuthAttempted` broadcast signals to learn who authenticates when — and, if the payload carried the raw similarity score, uses it as a spoof-tuning oracle (iterate on a photo/mask until the score climbs).

**Mitigations**:
- The `AuthAttempted` signal payload is `(user: s, matched: b)` only. It **never** carries the similarity score; the raw biometric score is available only in the `Authenticate` method reply to the authorized caller.
- The bus policy denies delivery of the daemon's signals in the default context; only root and `facelock`-group members may receive them.

#### A5. Raw Frame Access Parity (Implemented — polkit-authorized)

**Attack**: `PreviewFrame` is root-only, but a `facelock`-group member pulls raw camera/IR frames through the weaker-gated `PreviewDetectFrame` "detect" variant instead — silently, with no user consent.

**Mitigation**: `PreviewFrame` stays root-only. `PreviewDetectFrame` serves the `jpeg_data` frame bytes to root unconditionally; for a non-root caller the daemon requires an **interactive polkit authorization** for `org.facelock.preview-frames` (defaults: `allow_any=no`, `allow_inactive=no`, `allow_active=auth_self_keep` — the caller must type their own password in an active local session, and polkit keeps the grant only ~5 minutes). The daemon calls `CheckAuthorization` with `AllowUserInteraction=true` on the caller's unique bus name; the check runs in the background and never blocks the reply or holds the capture slot, so a pending prompt cannot starve `Authenticate`.

**Fail closed**: while the verdict is pending, denied, timed out, or polkit is unreachable (any D-Bus error), the frame bytes are stripped and the caller gets detection/recognition metadata only (bounding boxes, confidence, similarity, recognized). Verdicts are cached per caller connection — granted for at most 120 s, denied for 15 s — and evicted the moment the caller's bus connection closes (`NameOwnerChanged`), so a grant can never outlive the connection it was issued to. This preserves the enroll/preview UX (the preview window prompts once via the user's polkit agent, then shows live frames) without ever handing out camera/IR imagery silently.

`auth_self_keep` rather than `auth_admin`: the resource is the caller's *own* camera preview (the bus policy already restricts daemon access to root/`facelock` group, and `PreviewDetectFrame` to the matching Unix user). Requiring the user's own password is proportionate consent for camera imagery; `auth_admin` would lock non-admin users out of enroll feedback entirely, which is the UX regression this design fixes.

**Residual — similarity in detect metadata (accepted, self-scoped).** The stripped-frame response still returns per-face recognition metadata — bounding boxes, confidence, and the recognition *similarity* score — so the enroll/preview UI can give live quality feedback ("your face is recognized well, hold still to capture"). A raw similarity score is a spoof-tuning oracle in general (iterate a photo/mask until the number climbs), which is exactly why A4 removed it from the broadcast `AuthAttempted` signal. Here it is deliberately **retained but bounded**: `PreviewDetectFrame` is authorized only for **root or the caller's matching Unix user** (see the method-level authorization list above), so a non-root caller can read the similarity only for *their own* face against *their own* templates. There is no cross-user query path — obtaining another account's tuning score would require being root or being that user, in which case the score reveals nothing they could not already obtain by authenticating. The continuous score therefore serves enroll UX without functioning as an oracle against another account. This residual is accepted rather than coarsened; a future option is to bucket the score (`weak`/`good`/`strong`) if the self-scoped exposure is ever deemed too precise.

#### A6. Capture Contention Guard (Implemented)

**Attack**: Local DoS — an authorized caller loops `Authenticate`/`PreviewDetectFrame`, keeping the global handler mutex held so every other caller (including root) queues up to the 10-second handler-lock timeout per request.

**Mitigation**: A cheap in-flight capture guard is checked *before* the expensive handler lock. If a capture is already in flight, a concurrent `Authenticate`/`Enroll`/`PreviewFrame`/`PreviewDetectFrame` call is rejected **immediately** with a `daemon busy` error instead of queueing. PAM treats this like any daemon error (`PAM_IGNORE`) and falls through to password — degraded, never locked out. Per-user rate limiting is unchanged and orthogonal.

#### B. D-Bus Message Size Limits (Enforced by Bus)

The D-Bus bus daemon enforces message size limits (typically 128MB by default, configurable in the bus configuration). This prevents oversized messages from consuming daemon memory without requiring application-level size checks.

#### C. Persistent Rate Limiting (Implemented)

Throttle authentication attempts to prevent brute-force:

```rust
let rate_limiter = RateLimiter::new(5, 60);
if !rate_limiter.check(&store, user)? {
    return Err("rate limited");
}

// ... authentication attempt ...

if auth_failed {
    rate_limiter.record_failure(&store, user)?;
}
```

Implementation note:
- Failed attempts are stored in the shared SQLite `rate_limit` table
- Daemon mode and oneshot mode use the same window and thresholds
- Restarting the daemon must not reset a user's lockout state

### 5. PAM Module Hardening

#### A0. Config File Trust (Required)

The PAM module runs in a root context, so `/etc/facelock/config.toml` is an
attack vector: a writable config could redirect `auth_bin`, disable
anti-spoofing knobs, or change the daemon mode. Before parsing, the module
verifies that the config file **and every parent directory** are root-owned
and not group- or world-writable. The file check uses `fstat` on the opened
descriptor so the validated inode is exactly the one read (no TOCTOU). An
untrusted config is treated like a missing config: the module logs the
reason and returns `PAM_IGNORE` (fail closed, fall through to password).

#### A1. Sanitized Oneshot Child Environment (Required)

The oneshot fallback spawns `facelock auth` as root. When the PAM caller is
fully root (euid == uid, no `AT_SECURE`), the dynamic linker honors
`LD_PRELOAD`/`LD_*` from the inherited environment — allowing arbitrary code
injection into a root process. The module therefore spawns the child with
`env_clear()` and an allow-list:

- `SSH_CONNECTION` / `SSH_TTY` — forwarded so the child's own SSH-abort
  check keeps working
- `PATH=/usr/bin:/bin` — pinned, never inherited

Everything else (`LD_*`, `XDG_*`, `DBUS_*`, ...) is dropped. The desktop
notification path constructs its own session-bus address from the target UID
and does not need inherited XDG variables. The child's stdin is `/dev/null`.

#### A. Audit Logging (Required)

Log all authentication attempts with outcomes:

```rust
fn identify(pamh: *mut libc::c_void) -> libc::c_int {
    let user = pam_get_user(pamh);
    let service = pam_get_service(pamh);  // "sudo", "login", etc.
    let result = do_auth(user, service);

    // Log to syslog (PAM convention)
    // Format: pam_facelock(service): auth result for user
    syslog(LOG_AUTH | severity, "pam_facelock({}): {} for user {}",
           service, result_str, user);

    result
}
```

This creates an audit trail in `/var/log/auth.log` or journald.

#### B. Service-Specific Policy (Recommended)

Allow different PAM services to have different security levels:

```toml
[security.pam_policy]
# Only allow face auth for these PAM services
allowed_services = ["sudo", "polkit-1"]
# Never allow face auth for these (always fall through to password)
denied_services = ["login", "sshd", "su"]
```

### 6. Daemon Process Hardening

#### A. Capability Dropping (Recommended)

After initialization, drop unnecessary capabilities:

```rust
// After opening camera, loading models, connecting to D-Bus:
// Drop all capabilities except what's needed for ongoing operation
use caps::{CapSet, Capability};
caps::clear(None, CapSet::Effective)?;
caps::clear(None, CapSet::Permitted)?;
// Only keep what's needed: nothing (camera fd already open, D-Bus session attached)
```

#### B. systemd Hardening (Implemented)

The systemd unit (`systemd/facelock-daemon.service`) includes layered hardening:

**Phase 1 (shipped):** `ProtectSystem=strict`, `InaccessiblePaths=/home /root`, `ReadWritePaths=/var/lib/facelock /var/log/facelock`, `PrivateTmp=yes`, `NoNewPrivileges=yes`, `UMask=0027`

**Phase 2 (shipped):** `ProtectKernelTunables/Modules/ControlGroups=yes`, `RestrictNamespaces=yes`, `LockPersonality=yes`, `RestrictRealtime=yes`, `RestrictSUIDSGID=yes`

**Phase 3 (shipped — capabilities, seccomp, network):**

- `CapabilityBoundingSet=CAP_SETUID CAP_SETGID` / `AmbientCapabilities=CAP_SETUID CAP_SETGID` —
  the daemon retains **exactly** these two capabilities and no others. Device access needs no
  caps (`/dev/video*` and `/dev/tpmrm0` are root-owned and opened via standard file
  permissions), but the desktop-notification path execs `runuser -u <user> -- notify-send` to
  drop into the user's session bus, and `runuser` calls `setgroups()`/`setuid()`, which require
  `CAP_SETGID` + `CAP_SETUID`. They are declared **Ambient** (not merely in the bounding set) so
  the caps survive the exec into the non-setuid `runuser` under `NoNewPrivileges=yes`. The daemon
  also narrows its in-process capability set to exactly these two after initialization
  (`drop_capabilities()` in `facelock-cli`, holding them in effective/permitted/inheritable);
  everything else is dropped.
  - **This was empirically required.** An earlier revision set both directives **empty** on the
    theory that the daemon needs no capabilities. That was wrong: on real hardware it broke
    notifications with `runuser: cannot set groups: Operation not permitted`.
  - **Direct-D-Bus-as-root is NOT a viable alternative.** Having root connect straight to the
    user's session bus (skipping setuid entirely) does not work under `dbus-broker`, which rejects
    UID 0 on a user session bus — `sudo DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus
    notify-send test` fails with `Error sending data: Broken pipe`. The setuid-via-`runuser`
    path — and therefore these two capabilities — is required for notification delivery.
  - Notifications remain best-effort/fire-and-forget: they never block or fail the auth path, so
    even if delivery fails the biometric result and PAM fall-through are unaffected.
  - **End-to-end delivery is validated only on the maintainer's real hardware under systemd.**
    The unit tests assert the retained capability mask and `systemctl show` asserts the directive
    set; neither proves a notification actually pops.
- `RestrictAddressFamilies=AF_UNIX AF_NETLINK` + `IPAddressDeny=any` — the daemon only talks
  local sockets (system D-Bus, per-user session bus for notifications, kernel netlink). All
  inference is local; a compromised daemon cannot open TCP/IP sockets or exfiltrate over the
  network.
- `SystemCallFilter=@system-service` + `SystemCallErrorNumber=EPERM` +
  `SystemCallArchitectures=native` — allowlist seccomp. `@system-service` includes `ioctl`
  (V4L2), `capget`/`capset` (in-process drop), and the memory-management syscalls ONNX Runtime
  needs. Blocked syscalls return `EPERM` instead of killing the process, so an unexpected
  syscall degrades to a normal auth error (PAM falls through to password) rather than a crash
  loop — never a lockout.
- `ProtectProc=invisible` + `ProcSubset=pid` — other processes and non-PID `/proc` contents are
  hidden from the daemon.
- `ProtectHostname=yes`.

**Intentionally omitted directives (and why):**

- `ProtectClock=yes` — implies `DeviceAllow=char-rtc`, which switches the unit to a
  device-cgroup allowlist and breaks `/dev/video*` camera access (see below). `clock_settime`
  and related syscalls are already denied with `EPERM` by `SystemCallFilter=@system-service`.
- `DevicePolicy`/`DeviceAllow` — cgroup device ACLs interfered with camera auto-detection.
  Standard Unix permissions still restrict `/dev/video*` and `/dev/tpmrm0`.
- `MemoryDenyWriteExecute=yes` — breaks ONNX Runtime JIT paths such as CUDA and TensorRT.
- `User=` — the daemon must open the camera/TPM as root; non-root operation has not been
  validated on real hardware.

**Exposure score:** `systemd-analyze security --offline=true` reports **2.6 (OK)** for the
Phase 1–3 unit, down from 7.1 (MEDIUM) with Phase 1–2 only. (The score rose from 2.2 to 2.6
when the empty capability sets were corrected to `CAP_SETUID CAP_SETGID` — the two caps the
notification privilege-drop genuinely needs; the small increase is the honest cost of a working
notification path.) Verify with:
```bash
systemd-analyze security facelock-daemon.service
```

**Regression coverage:** `just test-deb-pkg` / `just test-rpm-pkg` boot the package container
with systemd as PID 1 (`test/run-pkg-validate-systemd.sh`) and assert via `systemctl show`
that the installed unit carries the Phase 3 directives, that the daemon starts and answers on
D-Bus inside the sandbox, and that an `AF_INET` socket cannot be created under the same
directive set (outbound TCP blocked).

### 7. Polkit / sudo Face Auth (Implemented)

Face auth can satisfy polkit and `sudo` authorization through **two independent
deployment models**. They have different scoping semantics, so it matters which
one a given host uses:

| Model | How it's wired | Scoping | Fallback |
|-------|----------------|---------|----------|
| **Agent model** | `facelock-polkit-agent` registers as the session's polkit authentication agent | `polkit.face_eligible_actions` allowlist (below) | Agent declines non-eligible actions |
| **PAM model** (Howdy-style) | `pam_facelock.so` added as `auth sufficient` in `/etc/pam.d/{sudo,polkit-1,…}` | **None** — face is attempted for *every* action under that PAM stack | Password, always (see below) |

Most real installs (including the Omarchy/hyprlock setup this project targets)
use the **PAM model**, because it is the only one that also covers `sudo` and
login. On those hosts the agent allowlist does **not** apply — it is an
agent-only control and `pam_facelock.so` never consults it.

#### 7a. PAM model — accepted posture (unscoped, password-backed)

When `pam_facelock.so` is placed as `auth sufficient` in a PAM stack, **any**
action routed through that stack (every `pkexec`/polkit prompt, every `sudo`)
will attempt a face match first. This is the same posture as a fingerprint
reader or Howdy: the biometric is a convenience factor across the board, not a
per-action capability.

This is **accepted by design**, and safe, because of two invariants the module
guarantees:

- **`sufficient`, never `required`.** A failed or unavailable face match (camera
  busy, no IR, timeout, spoof rejection, rate-limited) falls through to the next
  line in the stack — normally `pam_unix.so` / the password prompt. Face auth can
  only ever *add* a way in, never *remove* the password. Verified on this host:
  `pkexec echo hello` face-authorized; covering the camera fell back to the
  password dialog.
- **All the anti-spoof and trust-boundary defenses still apply** on every one of
  those attempts — `require_ir`, frame-variance liveness, rate limiting, SSH/lid
  abort, and the PAM service allowlist (`security.pam_policy.allowed_services`,
  which *does* gate the PAM path). So "unscoped across actions" does not mean
  "unscoped across defenses."

Operators who want face auth for only some actions under the PAM model should
control it at the PAM layer (which service files include `pam_facelock.so`), not
via `polkit.face_eligible_actions` (which the PAM path ignores). Per-action
scoping *inside* a single PAM stack is not offered; if you need it, use the agent
model instead, or omit `pam_facelock.so` from the stacks you want password-only.

#### 7b. Agent model — action allowlist

The `facelock-polkit-agent` lets a face match satisfy polkit authorization
requests. Two hardening rules keep this from becoming a universal root key:

**Action allowlist.** Face auth is offered only for polkit `action_id`s in
`polkit.face_eligible_actions`. The default is a single low-risk action
(`org.freedesktop.login1.lock-sessions`). High-risk actions — pkexec
(`org.freedesktop.policykit.exec`), PackageKit install/remove, udisks mount, and
accounts-service user administration — are **excluded by default**, so a single
face match cannot authorize arbitrary privileged operations. Users may extend the
list deliberately (like widening a fingerprint reader's reach); an empty list
disables face for all actions.

When an action is not eligible, the agent **declines** (returns a D-Bus
`Failed` error).

> **NOTE (agent model only):** polkit registers a single authentication agent
> per session and does not chain agents. When this agent declines a
> non-allowlisted action it returns an error, which — depending on the desktop's
> agent registration — may present as an authorization denial rather than a
> fallthrough to a password dialog. The intended UX (non-eligible actions handled
> by the desktop's normal password agent) is unverified pending live-desktop
> testing. Behavior is fail-closed: a non-eligible action is never
> face-authorized. This caveat does **not** apply to the PAM model (§7a), which
> always falls through to the password prompt. If the fallthrough UX matters to
> you and is unverified on your desktop, prefer the PAM model.

**Fail closed on unresolved user.** When responding to the polkit authority, the
agent resolves the target username to a uid. If the name does not resolve, the
agent refuses to respond. It never substitutes UID 0 — the previous
`unwrap_or(0)` behavior would have authenticated an unresolvable name as root.

## Security Configuration Reference

```toml
[security]
disabled = false
abort_if_ssh = true          # Refuse face auth over SSH
abort_if_lid_closed = true   # Refuse if laptop lid closed
require_ir = true            # CRITICAL: refuse non-IR cameras (anti-spoof, load-bearing)
require_frame_variance = true # Reject static images (photo defense; NOT video replay)
frame_variance_max_similarity = 0.985 # Max pair similarity in the sliding window (static >= ~0.999)
ir_texture_min_stddev = 10.0 # Min raw-frame face std_dev for IR texture (flat < 5, real > 15)
require_landmark_liveness = false # Require landmark movement between frames (off by default)
min_auth_frames = 3          # Minimum frames before accepting (variance check)
suppress_unknown = false     # Log unknown faces (true = suppress unknown-face log entries)

[notification]
mode = "terminal"            # Show "Identifying face..." on login screen

[security.pam_policy]
allowed_services = ["sudo", "polkit-1"]
denied_services = ["login", "sshd"]

[security.rate_limit]
max_attempts = 5             # Max auth attempts per user
window_secs = 60             # Rate limit window

[polkit]
# Polkit actions eligible for face auth *under the agent model only*. Non-listed
# actions are declined by the agent. High-risk actions excluded by default;
# empty = face off. NOTE: this list is ignored under the PAM model (pam_facelock.so
# in /etc/pam.d/*), where face is attempted for every action with password fallback.
# See "Polkit / sudo Face Auth" §7a/§7b above for the two models.
face_eligible_actions = ["org.freedesktop.login1.lock-sessions"]
```

## Summary: Security Implementation Priority

| Priority | Mitigation | Spec |
|----------|-----------|------|
| **P0** | IR camera enforcement (`require_ir`) | 02-camera, 05-daemon |
| **P0** | Frame variance check (anti-photo) | 05-daemon |
| **P0** | Model SHA256 at load time | 03-face-engine |
| **P0** | D-Bus system bus policy | 05-daemon |
| **P0** | D-Bus message size limits (bus-enforced) | 01-core-types |
| **P0** | PAM audit logging | 06-pam-module |
| **P0** | Database file permissions | 10-build-install |
| **P1** | IR texture validation | 02-camera, 05-daemon |
| **P1** | Rate limiting | 05-daemon |
| **P1** | systemd hardening | 10-build-install |
| **P1** | Capability dropping | 05-daemon |
| **P1** | Service-specific PAM policy | 06-pam-module |
| **P2** | Embedding encryption at rest | 04-face-store |
| **P2** | Memory zeroing on drop | 01-core-types |
| **P2** | Constant-time similarity comparison | 01-core-types |
