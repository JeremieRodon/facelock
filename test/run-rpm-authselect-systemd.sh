#!/usr/bin/env bash
set -euo pipefail

image="${1:?usage: run-rpm-authselect-systemd.sh IMAGE}"
# --cap-add DAC_OVERRIDE: same reason as run-pkg-validate-systemd.sh — the
# lifecycle authenticates through real pam_unix, and Fedora's mode-0000
# /etc/shadow is unreadable to root without the cap under a podman whose
# default_capabilities omit it.
cid="$(podman run -d --rm --systemd=always --security-opt unmask=ALL \
    --cap-add DAC_OVERRIDE \
    "$image" /lib/systemd/systemd)"
trap 'podman rm -f "$cid" >/dev/null 2>&1 || true' EXIT

booted=
for _ in $(seq 1 120); do
    state="$(podman exec "$cid" systemctl is-system-running 2>/dev/null || true)"
    case "$state" in
        running|degraded) booted=1; break ;;
    esac
    sleep 1
done
[ -n "$booted" ] || {
    podman exec "$cid" systemctl --failed --no-pager || true
    echo "Fedora authselect test container did not boot" >&2
    exit 1
}

podman exec "$cid" /rpm-authselect-lifecycle.sh
