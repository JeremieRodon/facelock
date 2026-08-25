#!/usr/bin/env bash
# Runner-side dependencies every packaging lane needs.
#
# The lanes themselves run inside digest-pinned distro containers; the runner
# only has to drive them. `just` is the entry point for every recipe, `podman`
# builds and boots the images, `python3` reads dist/release-matrix.json to
# resolve suite and Fedora lane images.
set -euo pipefail

# Ubuntu 24.04 ships just 1.21.0, which cannot parse this justfile at all --
# it rejects the `[private]` attribute on a variable assignment and dies on
# `_ort-version :=` before running anything. Pin the version the maintainer
# runs locally instead of tracking whatever the distro has, so a lane failure
# means a packaging regression rather than a toolchain skew.
#
# To bump: raise JUST_VERSION and take the matching line from the release's
# published SHA256SUMS file.
JUST_VERSION=1.46.0
JUST_SHA256=79966e6e353f535ee7d1c6221641bcc8e3381c55b0d0a6dc6e54b34f9db36eaa
JUST_ARCHIVE="just-${JUST_VERSION}-x86_64-unknown-linux-musl.tar.gz"

sudo apt-get update
sudo apt-get install -y --no-install-recommends podman python3

workdir="$(mktemp -d)"
trap 'rm -rf -- "$workdir"' EXIT
curl -fsSL --retry 3 -o "$workdir/$JUST_ARCHIVE" \
    "https://github.com/casey/just/releases/download/${JUST_VERSION}/${JUST_ARCHIVE}"
echo "$JUST_SHA256  $workdir/$JUST_ARCHIVE" | sha256sum -c -
tar -C "$workdir" -xzf "$workdir/$JUST_ARCHIVE" just
sudo install -m 0755 "$workdir/just" /usr/local/bin/just

# Recorded because a lane that fails on an unsupported just syntax or an old
# podman is otherwise indistinguishable from a real packaging regression.
just --version
podman --version
python3 --version
