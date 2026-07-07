#!/usr/bin/env bash
# Boot a package-test container (deb-e2e / rpm-e2e image) with systemd as
# PID 1 and run /pkg-validate.sh inside it via podman exec.
#
# Running under a real systemd lets pkg-validate.sh verify the Phase 3
# hardening directives of facelock-daemon.service (systemctl show), start
# the daemon inside the sandbox, and probe the seccomp/address-family
# restrictions with transient units.
#
# Usage: test/run-pkg-validate-systemd.sh <image>
set -euo pipefail

IMAGE="${1:?usage: run-pkg-validate-systemd.sh <image>}"

# Bind-mount repo ONNX models (if present) so the daemon-start test can run:
# `facelock daemon` loads models at startup. Models are large and gitignored,
# so this is best-effort — pkg-validate.sh skips the daemon-start test
# honestly when the mount is absent.
mounts=()
shopt -s nullglob
onnx=(models/*.onnx)
shopt -u nullglob
if [ "${#onnx[@]}" -gt 0 ]; then
    mounts=(-v "$PWD/models:/var/lib/facelock/models")
else
    echo "NOTE: no models/*.onnx in repo — daemon-start test will be skipped"
fi

# --systemd=always: podman sets up /run, /tmp, cgroups and SIGRTMIN+3 for a
#   systemd payload.
# --security-opt unmask=ALL: leave /proc unmasked so systemd can set up
#   ProtectProc=/ProcSubset= (they need a fresh procfs mount, which the
#   kernel refuses when parts of /proc are overmounted).
cid=$(podman run -d --rm --systemd=always --security-opt unmask=ALL \
    "${mounts[@]}" "$IMAGE" /lib/systemd/systemd)
trap 'podman rm -f "$cid" >/dev/null 2>&1 || true' EXIT

# Wait for systemd to finish booting (degraded is fine — minimal containers
# routinely have a failed getty/timesyncd; the validation doesn't need them).
booted=""
for _ in $(seq 1 120); do
    state=$(podman exec "$cid" systemctl is-system-running 2>/dev/null || true)
    case "$state" in
        running|degraded) booted=1; break ;;
    esac
    sleep 1
done
if [ -z "$booted" ]; then
    echo "ERROR: systemd did not reach running/degraded state" >&2
    podman exec "$cid" systemctl --failed --no-pager 2>&1 || true
    exit 1
fi

podman exec "$cid" /pkg-validate.sh
