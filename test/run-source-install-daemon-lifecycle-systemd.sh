#!/usr/bin/env bash
set -euo pipefail

image=${1:?usage: run-source-install-daemon-lifecycle-systemd.sh <image>}
cases=(
    unmasked-active
    unmasked-inactive
    first-install
    persistent-symlink-mask
    persistent-regular-mask
    runtime-symlink-mask
    runtime-regular-mask
    both-masks
    stale-persistent-mask
    stale-runtime-mask
    persistent-override-runtime-mask
    persistent-mask-runtime-override
    active-stale-mask-refused
    active-effective-mask-refused
    manager-disk-mismatch-refused
    persistent-control-conflict
    runtime-control-conflict
    cleanup-initial-reload-failure
    cleanup-final-reload-failure
    cleanup-mask-race
    cleanup-definition-race
    cleanup-fragment-race
    cleanup-owner-race
    cleanup-pre-restart-mask-race
    recipe-admin-overrides-preserved
    recipe-fake-manager-overrides-preserved
    recipe-known-legacy-retired
    recipe-first-install-failure-retry
    recipe-first-install-hup-retry
)
if [ "$#" -gt 1 ]; then
    cases=("$2")
fi

for case_name in "${cases[@]}"; do
    container="$(podman run -d --rm --systemd=always \
        "$image" /usr/lib/systemd/systemd)"
    cleanup() {
        podman rm -f "$container" >/dev/null 2>&1 || true
    }
    trap cleanup EXIT

    booted=
    for _ in $(seq 1 120); do
        state="$(podman exec "$container" \
            systemctl is-system-running 2>/dev/null || true)"
        case "$state" in
            running | degraded)
                if podman exec "$container" busctl --system call \
                    org.freedesktop.DBus /org/freedesktop/DBus \
                    org.freedesktop.DBus NameHasOwner s \
                    org.facelock.Daemon >/dev/null 2>&1; then
                    booted=true
                    break
                fi
                ;;
        esac
        sleep 1
    done
    if [ "$booted" != true ]; then
        podman exec "$container" systemctl --failed --no-pager 2>&1 || true
        exit 1
    fi

    if ! podman exec "$container" \
        /source-install-lifecycle/test/source-install-daemon-lifecycle-systemd.sh \
        "$case_name"; then
        podman logs "$container" 2>&1 || true
        exit 1
    fi
    cleanup
    trap - EXIT
done

echo "source-install daemon lifecycle real systemd: OK"
