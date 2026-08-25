#!/usr/bin/env bash
# Free the runner disk the packaging lanes need.
#
# A hosted runner ships with ~15GB of toolchains no facelock lane touches.
# The Debian and Fedora lanes each build several container images, an ORT
# bundle and a vendored Cargo tree, so a lane that dies on ENOSPC 30 minutes in
# reads exactly like a packaging regression. Cheaper to delete first.
set -euo pipefail

echo "before:"
df -h /

sudo rm -rf \
    /usr/share/dotnet \
    /usr/local/lib/android \
    /opt/ghc \
    /usr/local/share/boost \
    /usr/local/.ghcup \
    "${AGENT_TOOLSDIRECTORY:-/opt/hostedtoolcache}" 2>/dev/null || true

echo "after:"
df -h /
