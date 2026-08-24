#!/usr/bin/env bash
# Packit configuration schema gate.
#
# Runs `packit config validate --offline -c .packit.yaml` inside the
# digest-pinned Fedora image built from test/Containerfile.packit. The host
# needs podman and nothing else: no `packit`, no Python RPM bindings, no pipx
# venv that happens to see the system `rpm` module.
#
# Called by `just test-packit-config` and by `just release-preflight`.
#
# There is no skip path. This is a release gate, and a release gate that passes
# when it did not run is the failure this repository has been removing. Preflight
# already requires podman (`check_cmd podman`), so a host without podman is
# already a failing preflight; this reports the same answer with a reason.
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE=facelock-packit-validate

if ! command -v podman >/dev/null 2>&1; then
    echo "FAIL: podman not found; the Packit config gate runs only in its pinned Fedora container" >&2
    echo "      install podman, or run the check on a host that has it — it is not skippable" >&2
    exit 1
fi

# Preflight prints a terse summary, so the image build is quiet unless it fails.
build_log="$(mktemp)"
trap 'rm -f -- "$build_log"' EXIT
if ! podman build -t "$IMAGE" -f "$REPO_ROOT/test/Containerfile.packit" "$REPO_ROOT" >"$build_log" 2>&1; then
    cat "$build_log" >&2
    echo "FAIL: could not build the pinned Packit image" >&2
    exit 1
fi

podman run --rm -v "$REPO_ROOT:/repo:ro" "$IMAGE" \
    packit config validate --offline -c .packit.yaml
echo "Packit config schema: OK"
