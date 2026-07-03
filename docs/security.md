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

Implementation:
```rust
// In camera capture, check if the negotiated format indicates IR
fn is_ir_camera(device: &DeviceInfo) -> bool {
    // IR cameras typically support GREY (8-bit grayscale) or Y16 (16-bit)
    // as their native format. RGB-only cameras are not IR.
    device.formats.iter().any(|f| {
        matches!(f.fourcc.as_str(), "GREY" | "Y16 " | "YUYV")
            && device.name.to_lowercase().contains("ir")
            || device.name.to_lowercase().contains("infrared")
    })
}

// In daemon auth flow, before attempting recognition:
if config.security.require_ir && !is_ir_camera(&device_info) {
    return DaemonResponse::Error {
        message: "IR camera required for authentication. Set security.require_ir = false to override (NOT RECOMMENDED).".into()
    };
}
```

**Rationale**: Phone screens and printed photos do not emit infrared light correctly. An IR camera sees a flat, textureless surface where a real face would have depth and skin texture in IR. This single check eliminates the vast majority of spoofing attacks.

**Limitation**: IR camera detection by format/name is heuristic. Some cameras report YUYV but are actually IR. The `facelock devices` command should display whether each camera is detected as IR.

#### B. Frame Variance Check (Required)

Require minimum variance across consecutive frames during authentication:

```rust
/// Check that frames have sufficient variance (not a static image)
fn check_frame_variance(embeddings: &[(Detection, FaceEmbedding)], min_frames: usize) -> bool {
    if embeddings.len() < min_frames {
        return false;
    }
    // Compute pairwise similarity between consecutive embeddings
    // Real faces have micro-movements causing slight embedding variation
    // A static photo produces near-identical embeddings (similarity > 0.99)
    let mut max_similarity = 0.0f32;
    for window in embeddings.windows(2) {
        let sim = cosine_similarity(&window[0].1, &window[1].1);
        max_similarity = max_similarity.max(sim);
    }
    // If ALL consecutive frames are too similar, likely a static image
    // Real faces typically vary by 0.02-0.10 between frames
    max_similarity < 0.998  // FRAME_VARIANCE_THRESHOLD in facelock-core/types.rs
}
```

Config:
```toml
[security]
require_frame_variance = true  # Reject static images (photo attack defense)
min_auth_frames = 3            # Minimum frames before accepting match
```

#### C. Dark Frame / IR Texture Validation (Recommended)

In IR mode, verify that the face region has expected IR texture characteristics:
- Real skin has micro-texture visible in IR
- Photos/screens appear as flat, uniform surfaces in IR
- Compute standard deviation of pixel intensity within the face bounding box
- Reject faces with abnormally low texture variance

```rust
fn check_ir_texture(gray: &[u8], bbox: &BoundingBox, width: u32) -> bool {
    // Extract face region pixels
    let face_pixels = extract_region(gray, bbox, width);
    // Compute standard deviation
    let mean: f32 = face_pixels.iter().map(|&p| p as f32).sum::<f32>() / face_pixels.len() as f32;
    let variance: f32 = face_pixels.iter().map(|&p| (p as f32 - mean).powi(2)).sum::<f32>() / face_pixels.len() as f32;
    let std_dev = variance.sqrt();
    // Real IR faces have std_dev > ~15; flat surfaces are < 5
    std_dev > 10.0
}
```

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

**Phase 3 (shipped — capabilities, seccomp, network):**

- `CapabilityBoundingSet=` / `AmbientCapabilities=` (both **empty**) — the daemon needs no
  Linux capabilities: `/dev/video*` and `/dev/tpmrm0` are root-owned and opened via standard
  file permissions, and the daemon additionally drops all capabilities in-process after
  initialization (`drop_capabilities()` in `facelock-cli`). If real-hardware testing shows the
  `runuser`/`su` notification privilege-drop path needs capabilities, the documented relaxation
  is `CapabilityBoundingSet=CAP_SETUID CAP_SETGID` (note: with `NoNewPrivileges=yes` the
  in-process capability drop already prevents child processes from regaining capabilities, so
  the bounding set contents do not change post-drop behavior).
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

**Exposure score:** `systemd-analyze security --offline=true` reports **2.2 (OK)** for the
Phase 1–3 unit, down from 7.1 (MEDIUM) with Phase 1–2 only. Verify with:
```bash
systemd-analyze security facelock-daemon.service
```

**Regression coverage:** `just test-deb-pkg` / `just test-rpm-pkg` boot the package container
with systemd as PID 1 (`test/run-pkg-validate-systemd.sh`) and assert via `systemctl show`
that the installed unit carries the Phase 3 directives, that the daemon starts and answers on
D-Bus inside the sandbox, and that an `AF_INET` socket cannot be created under the same
directive set (outbound TCP blocked).

## Security Configuration Reference

```toml
[security]
disabled = false
abort_if_ssh = true          # Refuse face auth over SSH
abort_if_lid_closed = true   # Refuse if laptop lid closed
require_ir = true            # CRITICAL: refuse RGB-only cameras (anti-spoof)
require_frame_variance = true # Reject static images (photo defense)
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
