---
paths:
  - "crates/pam-facelock/**"
---

# PAM Dependency Ceiling

`pam-facelock` depends on **libc, toml, serde, zbus ONLY**. No ort, no v4l, no
facelock-core.

Why: this keeps the shared library small and avoids dragging heavy dependencies
into every PAM-using process. The module is a thin client that either connects
to the daemon or spawns `facelock auth`, so inference and camera code belong on
the other side of that boundary, never linked into `pam_facelock.so`.
