#!/usr/bin/env bash
# Resolve the digest-pinned base image for one Fedora lifecycle lane.
#
# dist/release-matrix.json is the only authority for which Fedora releases are
# release targets and which image each one is pinned to, so lanes read it here
# instead of hardcoding a digest per Containerfile. Three things fail closed:
#
#   * a release that is not a declared Fedora target (Rawhide included — it is
#     explicitly optional/experimental and never a lifecycle lane)
#   * platform rows for the same release that disagree on the image, or an
#     image that is not digest-pinned
#   * a release past its checked-in EOL gate
#
# The EOL gate reuses the matrix mechanism: `fedora.<release>_eol_gate` plus the
# RELEASE_MATRIX_TODAY override that test/check-release-matrix.py already reads.
# Fedora 43 goes EOL on 2026-12-02, and on that date this stops the lane with a
# message rather than letting it quietly rot against an unmaintained release.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
release="${1:?usage: fedora-lane-image.sh <fedora-release>}"
[ "$#" -eq 1 ] || {
    echo "usage: fedora-lane-image.sh <fedora-release>" >&2
    exit 2
}

RELEASE_MATRIX_TODAY="${RELEASE_MATRIX_TODAY:-}" \
python3 - "$repo_root/dist/release-matrix.json" "$release" <<'PY'
import json
import os
import re
import sys
from datetime import date

matrix_path, release = sys.argv[1], sys.argv[2]


def fail(message):
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


if not re.fullmatch(r"[1-9][0-9]*", release):
    fail(
        f"Fedora lane release must be a release number, got {release!r}; "
        "Rawhide is optional/experimental and cannot be a lifecycle lane"
    )

with open(matrix_path, encoding="utf-8") as handle:
    matrix = json.load(handle)

fedora = matrix.get("fedora", {})
declared = set(fedora.get("staging_copr_targets", []))
if f"fedora-{release}-x86_64" not in declared:
    fail(
        f"Fedora {release} is not a declared release target: {sorted(declared)}"
    )

rows = [
    row
    for row in matrix.get("platforms", [])
    if row.get("release_target") is True
    and re.fullmatch(rf"Fedora {release}(?: .*)?", row.get("platform", ""))
]
if not rows:
    fail(f"release matrix declares no Fedora {release} platform row")

images = {row.get("image") for row in rows}
if len(images) != 1:
    fail(f"Fedora {release} platform rows disagree on the base image: {sorted(images)}")
image = images.pop()
if not isinstance(image, str) or not re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", image):
    fail(f"Fedora {release} image is not digest-pinned: {image!r}")

gate = fedora.get(f"{release}_eol_gate")
if gate is not None:
    for row in rows:
        row_gate = row.get("eol_gate")
        if row_gate is not None and row_gate != gate:
            fail(
                f"{row['id']} eol_gate {row_gate!r} disagrees with "
                f"fedora.{release}_eol_gate {gate!r}"
            )
    eol = date.fromisoformat(gate)
    today = date.fromisoformat(
        os.environ.get("RELEASE_MATRIX_TODAY") or date.today().isoformat()
    )
    if today >= eol:
        fail(
            f"Fedora {release} reached its {eol.isoformat()} EOL gate: retire the "
            f"lane and its release-matrix row, or move the gate deliberately"
        )

print(image)
PY
