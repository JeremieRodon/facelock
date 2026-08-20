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
    required_chroot_list = production["required_supported_chroots"]
    optional_chroot_list = production["optional_experimental_chroots"]
except (KeyError, TypeError) as error:
    fail(f"release matrix has no complete production COPR authority: {error}")

if not isinstance(required_chroot_list, list) or not all(
    isinstance(chroot, str) for chroot in required_chroot_list
):
    fail("release matrix production COPR required supported chroots are invalid")
if not isinstance(optional_chroot_list, list) or not all(
    isinstance(chroot, str) for chroot in optional_chroot_list
):
    fail("release matrix production COPR optional experimental chroots are invalid")
required_chroots = set(required_chroot_list)
optional_chroots = set(optional_chroot_list)
if len(required_chroots) != len(required_chroot_list):
    fail("release matrix production COPR required supported chroots contain duplicates")
if len(optional_chroots) != len(optional_chroot_list):
    fail("release matrix production COPR optional experimental chroots contain duplicates")
if not required_chroots.isdisjoint(optional_chroots):
    fail("release matrix production COPR required and optional chroots overlap")
allowed_chroots = required_chroots | optional_chroots

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
expected_full_name = f"{owner}/{project}"
if (
    response.get("ownername") != owner
    or response.get("name") != project
    or response.get("full_name") != expected_full_name
):
    fail(
        "production COPR identity drifted: "
        f"expected {expected_full_name}, "
        f"got owner={response.get('ownername')!r}, name={response.get('name')!r}, "
        f"full_name={response.get('full_name')!r}"
    )
chroot_repos = response.get("chroot_repos")
if not isinstance(chroot_repos, dict) or not all(isinstance(chroot, str) for chroot in chroot_repos):
    fail("production COPR API response has no valid chroot_repos object")

live_chroots = set(chroot_repos)
missing = sorted(required_chroots - live_chroots)
extra = sorted(live_chroots - allowed_chroots)
if missing or extra:
    fail(
        f"production COPR {owner}/{project} chroots drifted; "
        f"required={sorted(required_chroots)}, optional={sorted(optional_chroots)}, "
        f"live={sorted(live_chroots)}, "
        f"missing={missing}, extra={extra}"
    )

print(
    f"live release channel contract: OK (production COPR {owner}/{project}; "
    f"live={sorted(live_chroots)})"
)
