# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Setup manages facelock group membership** (#89): `sudo facelock setup` now
  creates the `facelock` system group if missing and adds the invoking
  sudo/doas user to it (the interactive wizard asks first; non-interactive mode
  adds without prompting, and prints a manual `usermod` command when no
  invoking user can be determined), so daemon commands like `facelock
  preview`/`test` work after setup without a manual `usermod`. A log-out/log-in
  reminder is printed.

### Changed

### Fixed

- **Bare D-Bus AccessDenied errors** (#89): when the system bus policy rejects
  a caller that is not root or in the `facelock` group, the CLI now appends an
  actionable hint (add user to group, re-login, or re-run setup) instead of a
  bare "AccessDenied".

### Security

## [0.1.4] - 2026-05-31

Robustness pass: setup-wizard UX improvements, an `facelock-bin` AUR package, and a sweep of workspace dependency bumps with the cross-cutting API-change fixes they required.

### Added

- **AUR `facelock-bin` package**: prebuilt-binary AUR variant alongside source-build `facelock` and VCS `facelock-git`. The release workflow now publishes all three on tag push.
- **Setup wizard: PAM edit preview and confirmation**: setup shows exactly which lines will be added to each PAM service file (with top-of-file fallback described) and asks for confirmation before mutating anything on disk.
- **Setup wizard: display-manager and screen-locker detection**: setup detects installed display managers and lockers (Hyprland, sway, SDDM, GDM, etc.) and offers per-service opt-in via multi-select. SDDM and GDM integrations are marked experimental.

### Changed

- **Workspace dependency bumps**: clap 4.5→4.6, dialoguer 0.11→0.12, indicatif 0.17→0.18, ndarray 0.16→0.17, nix 0.29→0.31, rand 0.9→0.10, reqwest 0.12→0.13, rusqlite 0.32→0.40, sha2 0.10→0.11, signal-hook 0.3→0.4, tokio 1.50→1.52, tracing-subscriber 0.3.22→0.3.23, wayland-client 0.31.13→0.31.14, xkbcommon 0.8→0.9, plus libc, serde_json, toml, and `trixie` container patches.
- **CI: GitHub Release published via PAT**: switched from `GITHUB_TOKEN` to a PAT so Packit's release-event listener fires reliably for COPR builds.
- **GitHub Actions versions**: `actions/checkout@v6`, `actions/upload-pages-artifact@v5`, `actions/deploy-pages@v5`, `softprops/action-gh-release@v3`, `cachix/install-nix-action@v31`, plus consolidated GitHub artifact actions.

### Fixed

- **Uninstall cleanup**: closed gaps across all four uninstall paths (deb purge, rpm erase, makepkg/AUR remove, `just uninstall`). The installed systemd unit name is now captured *before* deletion, and user-data handling messaging is clearer.
- **`facelock clear` requires root before prompting**, not after — previously asked the confirmation question and then errored on missing privileges.
- **AUR publish script**: distinguishes "AUR repo doesn't exist yet" from other clone failures (previously masked real errors with a fresh `git init`), and derives the GitHub repo name from `GITHUB_REPOSITORY` instead of hardcoding it.
- **`facelock-git` AUR version display**: bumped the static `pkgver=` (used by AUR's web page because `pkgver()` doesn't run in the SRCINFO container) and extended `just release` to keep it in sync going forward.
- **Cross-version dependency portability**: SHA256 hex encoding rewritten by-byte (in both `facelock-face::models` and `facelock-cli::commands::setup`) so the code compiles against `sha2 0.10`'s `GenericArray` and `0.11`'s `hybrid_array::Array`. SQLite timestamps in `facelock-store` cast through `i64` to avoid rusqlite 0.40 type mismatches. CLI setup wizard uses `&options[..]` so `Select::items` is correct under both `dialoguer 0.11` (slice arg) and `0.12` (generic `IntoIterator` arg, clippy-clean). TPM crate migrated to `rand` 0.10's `thread_rng → rng` and `RngCore → Rng` rename.

## [0.1.3] - 2026-05-20

### Changed

- **COPR publishing**: migrated from the GitHub webhook to [Packit](https://packit.dev). The `publish-copr` job and the `COPR_WEBHOOK_URL` secret are removed; COPR builds are now driven by `.packit.yaml` on GitHub Release publish. The COPR RPM is built from source and depends on Fedora's system `onnxruntime` package.

### Fixed

- **ONNX Runtime API floor**: lowered the `ort` crate API feature from `api-24` to `api-20`. `api-24` required ONNX Runtime 1.24+ at runtime, which no shipped or bundled runtime provided (the bundled CPU ORT and Fedora's `onnxruntime` are 1.20.x–1.22.x), so face inference would fail to initialize. facelock uses only baseline ONNX Runtime APIs, so `api-20` loses no functionality.

## [0.1.2] - 2026-05-17

Patch release fixing the AUR publish job. No runtime code changes.

### Fixed

- **AUR publish**: `publish-aur.sh` now runs `makepkg --printsrcinfo` as a non-root `builder` user inside the Arch container (makepkg refuses to run as root). Host-runner ownership is restored after the container exits.

## [0.1.1] - 2026-05-17

Patch release fixing publish-job failures from the v0.1.0 release workflow run. No runtime code changes.

### Fixed

- **APT publish**: `publish-apt.sh` no longer exits when a `gpg-agent` is already running on the GitHub runner — falls back to `gpgconf --launch gpg-agent`
- **COPR publish**: added `.copr/Makefile` so the COPR `make srpm` build method can produce the source RPM from `dist/facelock.spec` via `git archive` + `rpmbuild -bs`

## [0.1.0] - 2026-05-17

Initial open-source release.

### Added

- **Core pipeline**: SCRFD face detection + ArcFace 512-dim embedding with ONNX Runtime
- **PAM module**: Thin cdylib with D-Bus daemon and oneshot subprocess modes
- **Daemon**: Persistent process with model caching, ~200ms warm auth latency
- **CLI**: Unified `facelock` binary — setup, enroll, test, preview, bench, audit, and more
- **Anti-spoofing**: IR camera enforcement, frame variance checks, landmark liveness detection
- **D-Bus**: System bus interface (`org.facelock.Daemon`) with deny-all policy and caller UID verification
- **GPU**: Runtime-selectable execution providers (CPU, CUDA, ROCm, OpenVINO) via `execution_provider` config — no compile-time flags
- **Setup wizard**: Interactive model-quality and inference-device selection, streaming download progress bar, only downloads the models actually selected in config
- **Status command**: Reports inference provider and ORT library location, enrolled face count for the current user, security posture (IR enforcement, liveness, `min_auth_frames`), and notification state (`73a5c00`)
- **Models**: Self-hosted ONNX assets distributed via GitHub release downloads (no third-party model fetches in the auth path)
- **Packaging**: deb, rpm, PKGBUILD (`facelock` and `facelock-git`), Nix flake, signed APT repository with two channels — `main` (TPM-enabled, Debian trixie+ / Ubuntu 25.04+) and `legacy` (non-TPM, Debian bookworm / Ubuntu 24.04) — systemd/D-Bus activation, OpenRC/runit/s6 (`c70999b`)
- **CI/CD**: Build/test/lint pipeline, TPM tests via swtpm, container PAM smoke tests, end-to-end `.deb` and `.rpm` package install validation
- **Documentation**: mdBook, man pages, ADRs, security posture assessment, threat model

### Security

- **Constant-time matching**: Embedding comparison via `subtle` crate to prevent timing side-channels
- **Encryption at rest**: AES-256-GCM software encryption for stored face embeddings
- **TPM key sealing**: Optional TPM-backed key protection for the encryption key
- **Model integrity**: SHA256 verification of ONNX model files at load time
- **Rate limiting**: 5 auth attempts per user per 60 seconds (default), enforced in daemon
- **D-Bus authorization**: Daemon verifies caller UID via `GetConnectionUnixUser` before executing methods
- **Enrollment restriction**: Root-required enrollment enforced in auth paths (`c01a655`)
- **PAM env hardening**: Hardened PAM environment handling to prevent injection (`c01a655`)
- **systemd hardening**: `ProtectSystem=strict`, `NoNewPrivileges`, `InaccessiblePaths`, and related service restrictions

### Fixed

- **PAM install output**: Conditional install messages — suppressed when PAM entry already present (`c12a970`)
- **PAM uninstall**: Uninstall now removes entries from all relevant PAM services, not just the primary one (`c12a970`)

[0.1.3]: https://github.com/tyvsmith/facelock/releases/tag/v0.1.3
[0.1.0]: https://github.com/tyvsmith/facelock/releases/tag/v0.1.0
