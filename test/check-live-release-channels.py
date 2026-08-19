#!/usr/bin/env python3
"""Compare public release-channel state with the checked-in authority."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = ROOT / "dist" / "release-matrix.json"


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path: Path, description: str) -> object:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot read {description}: {error}")


parser = argparse.ArgumentParser()
parser.add_argument(
    "--response-file",
    type=Path,
    help="read a COPR project response fixture instead of the public API",
)
args = parser.parse_args()

matrix = load_json(MATRIX_PATH, "release matrix")
try:
    production = matrix["copr_channels"]["production"]
    owner = production["owner"]
    project = production["project"]
    api_url = production["api_url"]
    expected_chroots = set(production["expected_enabled_chroots"])
except (KeyError, TypeError) as error:
    fail(f"release matrix has no complete production COPR authority: {error}")

if args.response_file:
    response = load_json(args.response_file, "COPR response fixture")
else:
    request = urllib.request.Request(api_url, headers={"User-Agent": "facelock-release-matrix/1"})
    try:
        with urllib.request.urlopen(request, timeout=20) as remote:
            response = json.load(remote)
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as error:
        fail(f"cannot read the public production COPR API: {error}")

if not isinstance(response, dict):
    fail("production COPR API response is not an object")
if response.get("ownername") != owner or response.get("name") != project:
    fail(
        "production COPR identity drifted: "
        f"expected {owner}/{project}, got {response.get('ownername')}/{response.get('name')}"
    )
chroot_repos = response.get("chroot_repos")
if not isinstance(chroot_repos, dict) or not all(isinstance(chroot, str) for chroot in chroot_repos):
    fail("production COPR API response has no valid chroot_repos object")

live_chroots = set(chroot_repos)
if live_chroots != expected_chroots:
    missing = sorted(expected_chroots - live_chroots)
    extra = sorted(live_chroots - expected_chroots)
    fail(
        f"production COPR {owner}/{project} chroots drifted; "
        f"expected={sorted(expected_chroots)}, live={sorted(live_chroots)}, "
        f"missing={missing}, extra={extra}"
    )

print(f"live release channel contract: OK (production COPR {owner}/{project})")
