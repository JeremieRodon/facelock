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

**Limitation**: classification is still heuristic without a hardware allow-list. Some genuine IR cameras report neither an IR name token nor a known quirk; add a quirks `force_ir` entry (`/etc/facelock/quirks.d/`) for such hardware (and set `format_preference` to the IR node's native format, e.g. `"GREY"`, when the camera exposes multiple capture nodes). The `facelock devices` command displays whether each camera is detected as IR. Device *identity* pinning (rather than capability heuristics) is the successor fix (Plan 02).

#### B. Frame Variance Check (Required)

Require minimum variance across consecutive matched frames during authentication.
The check is evaluated over a **sliding window** of the most recent
`min_auth_frames` matched-frame embeddings (`FrameVarianceWindow` in
`facelock-core/src/types.rs`): the gate passes only when the window is full AND
every consecutive pair inside it has cosine similarity at or below the cutoff
(`security.frame_variance_max_similarity`, default **0.995**,
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

The default cutoff (0.995) sits at the top of the frozen-human band: a live user
holding naturally still at a login prompt passes, perfectly static input never
does. (An earlier default of 0.97 assumed a 0.02–0.10 live-drift range that is
empirically wrong for a still user — it caused hard false-reject lockups where
auth reported "no match" despite 0.91–0.98 recognition similarity.)

**Honest scope — this does NOT stop video replay.** Frame-variance only rules out a
*static* image (printed photo, single frozen frame). A recorded video of the enrolled
user contains genuine inter-frame motion and will pass this check. Frame-variance is a
cheap passive defense-in-depth filter whose honest job is rejecting perfectly-static
input; **IR enforcement plus the raw-frame texture check (§A, §C) are the load-bearing
anti-spoof defenses**, and active liveness (opt-in landmark/blink) is the answer to
video replay.

**False-reject tradeoff**: lowering the cutoff below 0.995 rejects users who hold
naturally still; raising it above ~0.998 starts admitting sensor-noise-level drift.
`frame_variance_max_similarity` is the tuning knob and stays purely passive either
way. When the timeout expires with matching frames but an unsatisfied variance gate,
`facelock test` says so explicitly, and per-window min/max pair similarities are
logged at debug level (values only, never embeddings) for tuning.

Config:
```toml
[security]
require_frame_variance = true         # Reject static images (photo attack defense)
frame_variance_max_similarity = 0.995 # Max consecutive-frame similarity in the window
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

#### C. Encryption at Rest (Implemented)

For high-security deployments, embeddings can be encrypted with AES-256-GCM using either a plaintext key file (`encryption.method = "keyfile"`) or a TPM-sealed key (`encryption.method = "tpm"`). The TPM method seals the AES key at rest; it is unsealed at daemon startup and held in memory. See `docs/configuration.md` for the `[encryption]` and `[tpm]` sections.

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

**Deferred device/seccomp phase:** `DevicePolicy`/`DeviceAllow` is intentionally omitted because cgroup device ACLs interfered with camera auto-detection, and seccomp filtering is deferred to future work. Standard Unix permissions still restrict `/dev/video*` and `/dev/tpmrm0`.

**GPU compatibility note:** `MemoryDenyWriteExecute=yes` is still intentionally omitted because it breaks ONNX Runtime JIT paths such as CUDA and TensorRT. Verify hardening score with:
```bash
systemd-analyze security facelock-daemon.service
```

## Security Configuration Reference

```toml
[security]
disabled = false
abort_if_ssh = true          # Refuse face auth over SSH
abort_if_lid_closed = true   # Refuse if laptop lid closed
require_ir = true            # CRITICAL: refuse non-IR cameras (anti-spoof, load-bearing)
require_frame_variance = true # Reject static images (photo defense; NOT video replay)
frame_variance_max_similarity = 0.995 # Max pair similarity in the sliding window (static >= ~0.999)
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
