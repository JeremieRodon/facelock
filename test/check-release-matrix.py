#!/usr/bin/env python3
"""Fail closed when release target declarations drift from the alpha matrix."""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import date
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = ROOT / "dist" / "release-matrix.json"


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


try:
    matrix = json.loads(MATRIX_PATH.read_text())
except FileNotFoundError:
    fail(f"missing checked-in release matrix: {MATRIX_PATH.relative_to(ROOT)}")
except json.JSONDecodeError as error:
    fail(f"invalid release matrix JSON: {error}")

expected_rows = [
    ("debian-13", "Debian 13 trixie", "amd64", "TPM, staged APT/direct deb", "bundled ORT 1.20.1", "full"),
    ("debian-12", "Debian 12 bookworm LTS", "amd64", "legacy, staged APT/direct deb", "bundled ORT 1.20.1", "full"),
    ("ubuntu-26.04", "Ubuntu 26.04 LTS", "amd64", "TPM, staged APT/direct deb", "bundled ORT 1.20.1", "full"),
    ("ubuntu-24.04", "Ubuntu 24.04 LTS", "amd64", "legacy, staged APT/direct deb", "bundled ORT 1.20.1", "full"),
    ("fedora-43", "Fedora 43", "x86_64", "staging COPR", "system ORT", "full"),
    ("fedora-44-copr", "Fedora 44", "x86_64", "staging COPR", "system ORT", "full"),
    ("fedora-45", "Fedora 45 branched", "x86_64", "staging COPR", "system ORT", "build/runtime smoke"),
    ("fedora-rawhide", "Fedora Rawhide (Fedora 46 development)", "x86_64", "development", "system ORT", "build/runtime smoke"),
    ("fedora-44-direct", "Fedora 44", "x86_64", "direct RPM", "bundled ORT 1.20.1", "full"),
    ("arch-2026-08-18", "Arch Linux Archive snapshot 2026-08-18", "x86_64", "PKGBUILD and binary recipe", "system ORT", "full"),
]
actual_rows = [
    (
        row["id"],
        row["platform"],
        row["architecture"],
        row["variant"],
        row.get("runtime"),
        row["lifecycle_depth"],
    )
    for row in matrix.get("platforms", [])
]
require(actual_rows == expected_rows, "platform/architecture/variant/runtime/lifecycle rows differ from issue #234")
require(matrix.get("reviewed_on") == "2026-08-18", "matrix review date must be 2026-08-18")
require(matrix.get("fedora", {}).get("43_eol_gate") == "2026-12-02", "Fedora 43 EOL gate drifted")
today = date.fromisoformat(os.environ.get("RELEASE_MATRIX_TODAY", date.today().isoformat()))
fedora_43_eol = date.fromisoformat(matrix["fedora"]["43_eol_gate"])
require(today < fedora_43_eol, f"Fedora 43 reached its {fedora_43_eol.isoformat()} EOL gate; revise the matrix")
require(matrix.get("fedora", {}).get("branched") == "45", "Fedora 45 must remain a separate branched target")
require(matrix.get("fedora", {}).get("rawhide_development_release") == "46", "Rawhide must identify Fedora 46 development")
copr_channels = matrix.get("copr_channels", {})
production_copr = copr_channels.get("production", {})
staging_copr = copr_channels.get("staging", {})
expected_copr_targets = {"fedora-43-x86_64", "fedora-44-x86_64", "fedora-45-x86_64"}
require(production_copr.get("owner") == "tyvsmith", "production COPR owner drifted")
require(production_copr.get("project") == "facelock", "production COPR project drifted")
require(
    production_copr.get("api_url")
    == "https://copr.fedorainfracloud.org/api_3/project?ownername=tyvsmith&projectname=facelock",
    "production COPR public API drifted",
)
require(set(production_copr.get("expected_enabled_chroots", [])) == expected_copr_targets, "production COPR chroot authority drifted")
require(production_copr.get("prerelease_publication") is False, "production COPR must exclude prereleases")
require(staging_copr.get("project") == "facelock-testing", "staging COPR identity drifted")
require(staging_copr.get("provisioning_issue") == 236, "staging COPR provisioning must remain owned by issue #236")
require(staging_copr.get("managed_by_this_change") is False, "issue #234 cannot provision staging COPR")
require(set(matrix.get("fedora", {}).get("staging_copr_targets", [])) == expected_copr_targets, "staging COPR target authority drifted")
require(matrix.get("arch", {}).get("snapshot") == "2026-08-18", "Arch snapshot drifted")
arch_repository = matrix.get("arch", {}).get("repository")
require(
    arch_repository == "https://archive.archlinux.org/repos/2026/08/18/$repo/os/$arch",
    "Arch archive repository drifted",
)
for row in matrix.get("platforms", []):
    image = row.get("image")
    if image is not None:
        require(
            re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", image) is not None,
            f"{row['id']} image is not digest-pinned: {image!r}",
        )

expected_suites = {"trixie", "bookworm", "resolute", "noble"}
suite_map = matrix.get("apt_suites", {})
require(set(suite_map) == expected_suites, "canonical APT suite set drifted")
expected_suite_contracts = {
    "trixie": {
        "platform_id": "debian-13",
        "platform": "Debian 13",
        "architecture": "amd64",
        "variant": "tpm",
        "revision_suffix": "~deb13u1",
    },
    "bookworm": {
        "platform_id": "debian-12",
        "platform": "Debian 12",
        "architecture": "amd64",
        "variant": "legacy",
        "revision_suffix": "~deb12u1",
    },
    "resolute": {
        "platform_id": "ubuntu-26.04",
        "platform": "Ubuntu 26.04",
        "architecture": "amd64",
        "variant": "tpm",
        "revision_suffix": "~ubuntu26.04.1",
    },
    "noble": {
        "platform_id": "ubuntu-24.04",
        "platform": "Ubuntu 24.04",
        "architecture": "amd64",
        "variant": "legacy",
        "revision_suffix": "~ubuntu24.04.1",
    },
}
platforms_by_id = {row["id"]: row for row in matrix.get("platforms", [])}
for suite, expected in expected_suite_contracts.items():
    details = suite_map[suite]
    for field, value in expected.items():
        require(details.get(field) == value, f"APT suite {suite} {field} drifted: {details.get(field)!r}")
    platform_row = platforms_by_id.get(expected["platform_id"])
    require(platform_row is not None, f"APT suite {suite} references a missing platform row")
    require(platform_row["architecture"] == expected["architecture"], f"APT suite {suite} architecture disagrees with its platform row")
    require(platform_row["image"] == details.get("image"), f"APT suite {suite} image disagrees with its platform row")
    require(
        platform_row["variant"].lower().split(",", 1)[0] == expected["variant"],
        f"APT suite {suite} variant disagrees with its platform row",
    )

apt_config = (ROOT / "dist/apt/conf/distributions").read_text()
declared_suites = set(re.findall(r"^Codename:\s*(\S+)\s*$", apt_config, re.MULTILINE))
require(declared_suites == expected_suites, f"APT config suites {sorted(declared_suites)} != {sorted(expected_suites)}")
require("Codename: main" not in apt_config and "Codename: legacy" not in apt_config, "ambiguous APT suites remain")

try:
    packit = json.loads((ROOT / ".packit.yaml").read_text())
    packit_jobs = packit["jobs"]
    require(isinstance(packit_jobs, list), "Packit jobs must be a list")
except (KeyError, TypeError, json.JSONDecodeError) as error:
    fail(f"Packit config must remain valid JSON-subset YAML: {error}")
production_jobs = [
    job
    for job in packit_jobs
    if isinstance(job, dict) and job.get("job") == "copr_build" and job.get("project") == "facelock"
]
require(len(production_jobs) == 1, f"Packit must define exactly one production COPR job, found {len(production_jobs)}")
production_job = production_jobs[0]
require(
    production_job.get("owner") == production_copr["owner"],
    "Packit production COPR owner disagrees with the release matrix",
)
production_trigger = production_job.get("trigger")
require(
    production_trigger in {"ignore", "release"},
    f"Packit production COPR trigger must be 'ignore' or 'release', got {production_trigger!r}",
)
release_version = os.environ.get("RELEASE_MATRIX_VERSION")
if release_version is not None:
    require(
        re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(alpha|beta|rc)\.(0|[1-9][0-9]*))?", release_version)
        is not None,
        f"invalid RELEASE_MATRIX_VERSION: {release_version!r}",
    )
if release_version is not None and "-" not in release_version:
    require(
        production_trigger == "release",
        "stable release config must deliberately restore the production COPR release job",
    )
elif release_version is not None:
    require(
        production_trigger == "ignore",
        "prerelease-tagged Packit config can select a release-triggered production COPR job",
    )
packit_target_list = production_job.get("targets")
require(
    isinstance(packit_target_list, list) and all(isinstance(target, str) for target in packit_target_list),
    "Packit production COPR targets must be a list of strings",
)
packit_targets = set(packit_target_list)
require(len(packit_target_list) == len(packit_targets), "Packit production COPR targets must be unique")
require(packit_targets == expected_copr_targets, f"Packit targets drifted: {sorted(packit_targets)}")
require("fedora-rawhide-x86_64" not in packit_targets, "Rawhide/F46 must not be conflated with Fedora 45 staging COPR")

workflow = (ROOT / ".github/workflows/release.yml").read_text()
for suite, details in suite_map.items():
    expected_block = re.compile(
        rf"(?m)^\s+- suite: {re.escape(suite)}\s*$\n"
        rf"^\s+variant: {re.escape(details['variant'])}\s*$\n"
        rf"^\s+architecture: {re.escape(details['architecture'])}\s*$\n"
        rf"^\s+image: {re.escape(details['image'])}\s*$"
    )
    require(expected_block.search(workflow) is not None, f"release workflow suite/variant/architecture/image drifted for {suite}")
publication_inputs = re.findall(
    r'"(trixie|bookworm|resolute|noble)=\$\(ls debs/(trixie|bookworm|resolute|noble)/facelock_\*\.deb\)"',
    workflow,
)
require(
    len(publication_inputs) == 4 and set(publication_inputs) == {(suite, suite) for suite in expected_suites},
    f"stable APT publication inputs drifted or duplicated: {publication_inputs}",
)
deb_builder = (ROOT / ".github/workflows/scripts/build-deb.sh").read_text()
require(
    'release_debian_binary_basename "$VERSION" "$REVISION" "$SUITE" amd64' in deb_builder,
    "Debian artifact architecture no longer matches the amd64 release matrix",
)
apt_publisher = (ROOT / ".github/workflows/scripts/publish-apt.sh").read_text()
require(
    'source "$SCRIPT_DIR/../../../scripts/release-versions.sh"' in apt_publisher,
    "APT publisher does not source the central release version contract",
)
require(
    'EXPECTED_SUFFIX="$(release_debian_suite_suffix "$SUITE")"' in apt_publisher,
    "APT publisher does not derive suite suffixes from the central release version contract",
)
for suffix in ("~deb13u1", "~deb12u1", "~ubuntu26.04.1", "~ubuntu24.04.1"):
    require(suffix not in apt_publisher, f"APT publisher duplicates the central suite suffix {suffix}")
direct_fedora_image = next(row["image"] for row in matrix["platforms"] if row["id"] == "fedora-44-direct")
require(f"image: {direct_fedora_image}" in workflow, "direct RPM workflow must pin Fedora 44 by digest")
require("prerelease: ${{ needs.metadata.outputs.prerelease }}" in workflow, "GitHub Release prerelease output is not wired")
require(workflow.count("needs.metadata.outputs.prerelease == 'false'") >= 2, "stable APT/AUR guards are not derived from validated metadata")
require("project: facelock" not in workflow, "workflow contains a selectable production COPR project")

arch_image = next(row["image"] for row in matrix["platforms"] if row["id"] == "arch-2026-08-18")
aur_publisher = (ROOT / ".github/workflows/scripts/publish-aur.sh").read_text()
require(arch_image in aur_publisher, "AUR publication helper does not use the immutable Arch matrix image")


def require_arch_mirror_before_each_pacman(relative_path: str) -> None:
    content = (ROOT / relative_path).read_text()
    pacman_commands = list(re.finditer(r"(?m)^\s*(?:RUN\s+)?pacman\s", content))
    require(pacman_commands, f"expected an Arch package invocation in {relative_path}")
    boundary = 0
    for command in pacman_commands:
        require(
            arch_repository in content[boundary : command.start()].replace(r"\$", "$"),
            f"{relative_path} does not configure the exact Arch snapshot before every pacman invocation",
        )
        boundary = command.end()


for arch_consumer in (".github/workflows/ci.yml", ".github/workflows/scripts/publish-aur.sh", "test/Containerfile"):
    require_arch_mirror_before_each_pacman(arch_consumer)
ci_workflow = (ROOT / ".github/workflows/ci.yml").read_text()
justfile = (ROOT / "justfile").read_text()
live_channel_command = "python3 test/check-live-release-channels.py"
require(live_channel_command in ci_workflow, "CI does not compare live release channels with the checked-in authority")
require(live_channel_command in justfile, "release preflight does not compare live release channels with the checked-in authority")
require("ARCH_SNAPSHOT" not in justfile, "unused ARCH_SNAPSHOT signaling remains")

for pkgbuild_name in ("PKGBUILD", "PKGBUILD-bin"):
    pkgbuild = (ROOT / "dist" / pkgbuild_name).read_text()
    require(re.search(r"^_tag=", pkgbuild, re.MULTILINE) is not None, f"dist/{pkgbuild_name} has no upstream _tag")
    require("v$_tag" in pkgbuild, f"dist/{pkgbuild_name} does not fetch the upstream _tag")

docs = (ROOT / "docs/releasing.md").read_text()
for phrase in (
    "0.2.0~alpha.1-1~deb13u1",
    "0.2.0-0.1.alpha.1",
    "0.2.0alpha1-1",
    "Fedora 43",
    "2026-12-02",
    "Fedora 45 branched",
    "Fedora Rawhide (Fedora 46 development)",
    "Arch Linux Archive snapshot 2026-08-18",
    "stable-tagged config",
):
    require(phrase in docs, f"release documentation omits matrix/version phrase: {phrase}")

contracts = (ROOT / "docs/contracts.md").read_text()
for phrase in (
    "## Release Channels and APT Paths",
    "https://tysmith.me/facelock/apt/dists/trixie/Release",
    "https://tysmith.me/facelock/apt/dists/bookworm/Release",
    "https://tysmith.me/facelock/apt/dists/resolute/Release",
    "https://tysmith.me/facelock/apt/dists/noble/Release",
    "`main` and `legacy`",
    "stable APT, stable AUR, or production COPR",
    "issue #236",
):
    require(phrase in contracts, f"system contracts omit release-channel phrase: {phrase}")

release_skill = (ROOT / ".claude/skills/release/SKILL.md").read_text()
for phrase in (
    "Tags are parsed strictly as `vX.Y.Z` or `vX.Y.Z-{alpha,beta,rc}.N`.",
    "A bare invocation derives the version from `Cargo.toml` and classifies it with the same parser.",
):
    require(phrase in release_skill, f"release skill omits strict preflight classification: {phrase}")
require("a tag matching" not in release_skill, "release skill still describes substring prerelease classification")
require("Running it bare skips" not in release_skill, "release skill still claims bare preflight skips classification")

copr_build_test = (ROOT / "test/copr-build.sh").read_text()
packit_schema_command = "packit config validate --offline -c .packit.yaml"
require(
    packit_schema_command in copr_build_test,
    "COPR-equivalent gate does not run Packit's real offline schema validator",
)
require(packit_schema_command in justfile, "release preflight does not run Packit's schema validator when available")

install_docs = {
    "README.md": (ROOT / "README.md").read_text(),
    "book/src/quickstart.md": (ROOT / "book/src/quickstart.md").read_text(),
    "website/index.html": (ROOT / "website/index.html").read_text(),
}
apt_platform_mappings = (
    ("Debian 13", "trixie", "TPM"),
    ("Debian 12", "bookworm", "legacy"),
    ("Ubuntu 26.04", "resolute", "TPM"),
    ("Ubuntu 24.04", "noble", "legacy"),
)
retired_apt_source = re.compile(
    r"https://tysmith\.me/facelock/apt\s+(?:main|legacy)\s+facelock",
    re.IGNORECASE,
)
for relative_path, content in install_docs.items():
    require(retired_apt_source.search(content) is None, f"{relative_path} still configures a retired APT suite")
    require("https://tysmith.me/facelock/apt" in content, f"{relative_path} omits the public APT base")
    for platform, suite, variant in apt_platform_mappings:
        mapping = re.compile(
            rf"(?im)^.*{re.escape(platform)}.*{re.escape(suite)}.*{re.escape(variant)}.*$"
        )
        require(mapping.search(content) is not None, f"{relative_path} omits {platform}/{suite}/{variant} mapping")

readme = install_docs["README.md"]
require("four suite-specific `.deb` artifacts" in readme, "README release wording does not name the four Debian artifacts")
roadmap = (ROOT / "docs/testing-roadmap.md").read_text()
for phrase in (
    "four suite-specific `.deb` artifacts",
    "trixie, bookworm, resolute, and noble",
):
    require(phrase in roadmap, f"testing roadmap omits release artifact inventory: {phrase}")
require(retired_apt_source.search(roadmap) is None, "testing roadmap still names retired APT suites")

print("release matrix contract: OK")
