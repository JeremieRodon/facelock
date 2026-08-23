---
paths:
  - "test/**"
  - "justfile"
  - "crates/**/tests/**"
  - ".github/workflows/**"
---

# Testing Strategy

| Tier | What | How |
|------|------|-----|
| 1 | Unit tests | `cargo test --workspace` |
| 2 | Hardware tests | `cargo test --workspace -- --ignored` |
| 3 | Arch container PAM smoke | `just test-arch-pam` |
| 3b | Arch container E2E (daemon) | `just test-arch-integration` |
| 3c | Arch container E2E (oneshot) | `just test-arch-oneshot` |
| 3e | Fedora package lifecycle, every declared release | `just test-rpm-lanes` |
| 3a | Arch container E2E, camera-free | `just test-arch-camera-free` |
| 3b | Arch container E2E (daemon), needs a camera | `just test-arch-integration` |
| 3c | Arch container E2E (oneshot), needs a camera | `just test-arch-oneshot` |
| 4 | VM testing | Disposable VM with snapshots |
| 5 | Host PAM | After tiers 3-4, with root shell backup |

**Never** install `pam_facelock.so` or edit `/etc/pam.d/*` on the host until container tests pass.

Fedora recipes take a release and default to 44 (`just test-rpm-pkg 43`). Tier 3e
covers all three declared targets at the depth `dist/release-matrix.json` gives
each; Rawhide is experimental and never a lane.

## Which E2E tier a new assertion belongs in

Tier 3a is everything in the two E2E suites that reaches its subject before any
capture: bus policy, D-Bus authorization, pre-flight rejections and their exit
codes, schema migrations, the shape of the status document. CI runs it on every
pull request. Tiers 3b and 3c keep only what a real sensor produces: a frame, a
match, a device fingerprint, a warm-hold timing.

Put a new assertion in 3a unless it needs a frame. An assertion parked in 3b or
3c that did not need one is unwatched: those tiers run on one machine, and three
of their assertions rotted there undetected (#139).

Tiers 3b and 3c are gated at release time, not at review time.
`just test-arch-camera-required` runs both and records the commit they passed
at; `just release-preflight` fails until that record names HEAD.
