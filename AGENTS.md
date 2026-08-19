# AGENTS.md — Facelock

## Project Overview

Facelock is a Linux face authentication PAM module written in Rust. Single unified binary (`facelock`) handles CLI, daemon, one-shot auth, and benchmarks. The PAM module (`pam_facelock.so`) is a thin client that either connects to the daemon or spawns `facelock auth`. IPC uses the D-Bus system bus (`org.facelock.Daemon`), not Unix sockets.

## Repository Structure

Cargo workspace with 11 crates:

| Crate | Type | Purpose |
|-------|------|---------|
| `facelock-core` | lib | Config, types, errors, D-Bus interface, traits |
| `facelock-camera` | lib | V4L2 capture, auto-detection, preprocessing |
| `facelock-face` | lib | ONNX inference (SCRFD + ArcFace) |
| `facelock-store` | lib | SQLite face embedding storage |
| `facelock-daemon` | lib | Auth/enroll logic, rate limiting, liveness, audit, D-Bus server |
| `facelock-cli` | bin | Unified CLI (`facelock` binary, includes `bench` subcommand) |
| `facelock-bench` | bin | Standalone benchmark and calibration utility |
| `pam-facelock` | cdylib | PAM module (libc + toml + serde + zbus only) |
| `facelock-tpm` | lib | TPM-sealed key encryption, software AES-256-GCM |
| `facelock-polkit` | bin | Polkit authentication agent |
| `facelock-test-support` | lib | Mocks and fixtures for testing |

## Build & Verify

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo run --bin facelock -- --help
```

## GPU Support (Optional)

GPU acceleration is a runtime option — no special build flags needed. Install a
GPU-enabled ONNX Runtime package and set `execution_provider` in config:

```bash
sudo pacman -S onnxruntime-opt-cuda   # NVIDIA
# Then edit /etc/facelock/config.toml: execution_provider = "cuda"
```

Supported providers: `cpu` (default), `cuda` (NVIDIA), `rocm` (AMD), `openvino` (Intel).

## Core Rules

- Do not change binary names, paths, config keys, database schema, or auth semantics without updating `docs/contracts.md`.
- Keep the PAM module free of heavy dependencies (no ort, no v4l, no facelock-core).
- Keep all inference local. No cloud services, no runtime model downloads in the auth path.
- Prefer minimal dependencies and clear crate boundaries.

## Security Rules

- **Read `docs/security.md`** before implementing any auth-related code.
- `security.require_ir` defaults to **true**. Never weaken this default.
- Frame variance checks must be in the auth path.
- Model files SHA256-verified at load time.
- D-Bus system bus policy: deny-all default; every local user may send `Authenticate` only (daemon checks caller UID == target user), root gets the whole interface incl. signals; no group policy (ADR 010).
- D-Bus daemon verifies caller UID via `GetConnectionUnixUser` before executing methods.
- D-Bus message size limits enforced by the bus daemon.
- PAM module logs all auth attempts to syslog.
- Database is 0600 root:root, model files 0644 under a 0755 root:root directory; the state directory is 0711 root:root (ADR 010).
- Rate limiting enforced in daemon (5 attempts/user/60s default).
- Constant-time embedding comparison via `subtle` crate (prevents timing side-channels).
- systemd service hardened with ProtectSystem=strict, NoNewPrivileges, InaccessiblePaths, etc.

## Code Style

- `thiserror` for library error types, `anyhow` in binaries.
- Return `Result<T>` over panicking. Never `unwrap()` in library code.
- `tracing` for structured logging. Control verbosity via `RUST_LOG` env filter.
- `#[cfg(test)]` modules in each source file for tests.

## Dependency Rules

| Crate | Dependencies |
|-------|-------------|
| facelock-core | serde, toml, thiserror, tracing, subtle, zeroize, zvariant |
| facelock-camera | facelock-core, v4l, image, tracing |
| facelock-face | facelock-core, ort, ndarray, image, sha2 |
| facelock-store | facelock-core, rusqlite (bundled), bytemuck, thiserror |
| facelock-daemon | facelock-core, facelock-camera, facelock-face, facelock-store, facelock-tpm, signal-hook, nix, zbus (tokio), tokio |
| facelock-cli | facelock-core + all above, clap, reqwest, zbus, tokio, dialoguer |
| facelock-bench | facelock-core, facelock-camera, facelock-face, facelock-store, clap, anyhow, tracing |
| pam-facelock | **libc, toml, serde, zbus ONLY** |
| facelock-tpm | facelock-core, tracing, aes-gcm, rand, zeroize, tss-esapi (optional) |
| facelock-polkit | facelock-core, zbus, tokio, nix, anyhow |

## Testing Strategy

| Tier | What | How |
|------|------|-----|
| 1 | Unit tests | `cargo test --workspace` |
| 2 | Hardware tests | `cargo test --workspace -- --ignored` |
| 3 | Arch container PAM smoke | `just test-arch-pam` |
| 3b | Arch container E2E (daemon) | `just test-arch-integration` |
| 3c | Arch container E2E (oneshot) | `just test-arch-oneshot` |
| 4 | VM testing | Disposable VM with snapshots |
| 5 | Host PAM | After tiers 3-4, with root shell backup |

**Never** install `pam_facelock.so` or edit `/etc/pam.d/*` on the host until container tests pass.

## Workspace Conventions

- Version declared once in root `Cargo.toml`, inherited via `version.workspace = true`.
- Inter-crate deps use relative paths (`path = "../facelock-core"`).
- Release profile: LTO + single codegen unit + strip.

## Releasing

- `just release X.Y.Z` bumps version in Cargo.toml, PKGBUILD, spec, debian/changelog.
- Tag `vX.Y.Z` triggers CI to build binaries, .deb, and .rpm.
- Update `CHANGELOG.md` before committing the release.
- See `docs/releasing.md` for full process and versioning contract.

## Commits, PRs, and Issues

Applies to anything an agent authors in this repository, including runs
triggered from GitHub (`@claude` in a comment or issue).

- Titles: `<type>(<scope>): <subject>`. Types: `feat` `fix` `refactor` `polish` `docs` `test` `ci` `chore` `perf` `build` `style` `revert`.
- No AI attribution anywhere: no "Generated with Claude Code" footer, no `Co-Authored-By` trailer, no mention of Claude, AI, agents, or assistants in a title, body, commit message, or changelog entry.
- Open PRs as drafts. The maintainer marks them ready.
- PR and issue bodies are bullets: verb-first fragments, lowercase, no terminal period. Prose only for the `Why`, capped at four sentences. A small PR is two or three bullets with no headings.
- Never paste command output, CI logs, or pass/fail tables into a PR. Naming a check under `Validation` is fine; reporting its result is not.
- Every PR says why the change exists. If it cannot be derived, ask; never invent one.
- Docs are part of the deliverable. A change to paths, config keys, CLI flags, D-Bus interface, or behavior updates `docs/` (and `docs/contracts.md` where it applies) in the same PR.
