#!/usr/bin/env python3
"""Verify that agent-facing docs still describe the tree they claim to describe.

`.claude/rules/*.md` and `.claude/skills/*/SKILL.md` assert facts about this
repository: which paths a rule governs, which just recipes exist, which files a
release bumps. Nothing else checks those claims, and a rule scoped to a path
that no longer exists fails silently -- it simply never loads.

Two kinds of check:

  mechanical   the claim is machine-verifiable, so verify it
  coupling     the claim restates an invariant owned by code or config, which
               cannot be verified; instead require that a change to the owning
               file is accompanied by a look at the rule (--base only)

Run with --base REF to enable the coupling check against a merge base.
Stdlib only: this runs in a bare archlinux container.
"""
from __future__ import annotations

import argparse
import glob
import os
import re
import subprocess
import sys

RULES = ".claude/rules/*.md"
SKILLS = ".claude/skills/*/SKILL.md"

failures: list[str] = []
notes: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"  {'ok  ' if ok else 'FAIL'}  {name}" + (f"  --  {detail}" if detail else ""))
    if not ok:
        failures.append(name)


def agent_docs() -> list[str]:
    return sorted(glob.glob(RULES) + glob.glob(SKILLS))


def frontmatter(path: str) -> dict[str, object]:
    """Parse the small frontmatter subset used here: scalars and '- ' lists."""
    text = open(path, encoding="utf-8").read()
    if not text.startswith("---"):
        return {}
    body = text.split("---", 2)[1]
    out: dict[str, object] = {}
    key = None
    for line in body.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if re.match(r"^\s+- ", line):
            if key:
                out.setdefault(key, []).append(line.split("- ", 1)[1].strip().strip("\"'"))
        elif ":" in line:
            key, _, val = line.partition(":")
            key = key.strip()
            val = val.strip().strip("\"'")
            out[key] = val if val else []
    return out


def just_recipes() -> set[str]:
    out = subprocess.run(["just", "--list"], capture_output=True, text=True).stdout
    return set(re.findall(r"^\s+([a-z][a-z0-9-]*)", out, re.M))


def justfile() -> str:
    return open("justfile", encoding="utf-8").read()


# ---------------------------------------------------------------- mechanical

def check_globs() -> None:
    for path in sorted(glob.glob(RULES)):
        paths = frontmatter(path).get("paths") or []
        dead = [p for p in paths if not glob.glob(p, recursive=True)]
        check(
            f"globs resolve: {os.path.basename(path)}",
            not dead and bool(paths),
            "no paths: declared" if not paths else (f"dead: {dead}" if dead else ""),
        )


def check_recipes() -> None:
    recipes = just_recipes()
    referenced: set[str] = set()
    for path in agent_docs():
        # Only the backticked form. Bare "just packaging syntax" is prose.
        referenced |= set(re.findall(r"`just ([a-z][a-z0-9-]+)[^`]*`", open(path, encoding="utf-8").read()))
    missing = referenced - recipes
    check("just recipes referenced exist", not missing, f"missing: {sorted(missing)}" if missing else f"{len(referenced)} referenced")


def check_crate_map() -> None:
    listed = set(re.findall(r"^- `(facelock-[a-z-]+|pam-facelock)`", open("AGENTS.md", encoding="utf-8").read(), re.M))
    actual = {d for d in os.listdir("crates") if os.path.isdir(os.path.join("crates", d))}
    check("AGENTS.md crate map matches crates/", listed == actual,
          f"only in map: {sorted(listed - actual)}, only on disk: {sorted(actual - listed)}" if listed != actual else f"{len(actual)} crates")


def check_pam_guard() -> None:
    rule = ".claude/rules/pam-boundary.md"
    if not os.path.exists(rule):
        return
    m = re.search(r"grep -Eq '\^\(([^)]+)\)\$'", justfile())
    if not m:
        check("async-io guard list in sync", False, "could not find the guard in check-pam-standalone")
        return
    guard = set(m.group(1).split("|"))
    documented = set(re.findall(r"\b(async-[a-z]+|polling)\b", open(rule, encoding="utf-8").read()))
    check("async-io guard list in sync", guard == documented,
          f"justfile-only: {sorted(guard - documented)}, rule-only: {sorted(documented - guard)}" if guard != documented else f"{len(guard)} crates")


def check_release_files() -> None:
    skill = ".claude/skills/release/SKILL.md"
    if not os.path.exists(skill):
        return
    recipe = re.search(r"^release version:\n((?:[ \t].*\n|\n)*)", justfile(), re.M)
    if not recipe:
        check("release version files in sync", False, "release recipe not found")
        return
    bumped = set(re.findall(r"✓ (Cargo\.toml|dist/[A-Za-z0-9_./-]+)", recipe.group(1)))
    named = set(re.findall(r"^\| `([A-Za-z0-9_./-]+)` \|", open(skill, encoding="utf-8").read(), re.M))
    check("release version files in sync", bumped <= named,
          f"bumped but undocumented: {sorted(bumped - named)}" if bumped - named else f"{len(bumped)} files")


def check_release_jobs() -> None:
    skill = ".claude/skills/release/SKILL.md"
    wf = ".github/workflows/release.yml"
    if not (os.path.exists(skill) and os.path.exists(wf)):
        return
    text = open(wf, encoding="utf-8").read()
    jobs_block = text.split("\njobs:", 1)[-1]
    jobs = set(re.findall(r"^  ([a-z][a-z0-9-]*):$", jobs_block, re.M))
    body = open(skill, encoding="utf-8").read()
    missing = {j for j in jobs if j not in body}
    check("release.yml jobs documented", not missing, f"undocumented: {sorted(missing)}" if missing else f"{len(jobs)} jobs")
    stated = re.search(r"which has (\d+) jobs", body)
    if stated:
        check("release.yml job count", int(stated.group(1)) == len(jobs), f"skill says {stated.group(1)}, workflow has {len(jobs)}")


def check_paths_exist() -> None:
    missing: set[tuple[str, str]] = set()
    pattern = re.compile(r"`((?:docs|crates|dist|test|systemd|dbus|polkit|po|\.github)/[A-Za-z0-9_./-]+)`")
    for path in agent_docs():
        for ref in pattern.findall(open(path, encoding="utf-8").read()):
            if not os.path.exists(ref):
                missing.add((os.path.basename(path), ref))
    check("referenced repo paths exist", not missing, str(sorted(missing)) if missing else "")


# ------------------------------------------------------------------ coupling

def check_coupling(base: str) -> None:
    """A rule restates invariants owned elsewhere. If an owner moved and the
    rule did not, someone has to confirm the rule is still true."""
    diff = subprocess.run(["git", "diff", "--name-only", f"{base}...HEAD"],
                          capture_output=True, text=True)
    if diff.returncode != 0:
        notes.append(f"coupling check skipped: cannot diff against {base}")
        return
    changed = set(diff.stdout.split())
    if not changed:
        notes.append("coupling check skipped: no changes against base")
        return

    for path in sorted(glob.glob(RULES) + glob.glob(SKILLS)):
        fm = frontmatter(path)
        owners = fm.get("derives-from") or []
        if not owners:
            continue
        tripped = sorted({
            c for c in changed
            for o in owners
            if c == o or (o.endswith("/**") and c.startswith(o[:-2]))
        })
        if tripped and path not in changed:
            check(
                f"coupling: {os.path.basename(os.path.dirname(path)) or ''}/{os.path.basename(path)}".lstrip("/"),
                False,
                f"owners changed without review: {tripped}. Confirm the rule is still "
                f"accurate, then bump `reviewed:` in its frontmatter.",
            )
        elif tripped:
            check(f"coupling: {os.path.basename(path)}", True, "owners changed, rule updated")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base", help="merge base to diff against; enables the coupling check")
    args = ap.parse_args()

    if not os.path.exists("justfile"):
        print("error: run from the repository root", file=sys.stderr)
        return 2

    print("agent docs -- mechanical checks")
    check_globs()
    check_recipes()
    check_crate_map()
    check_pam_guard()
    check_release_files()
    check_release_jobs()
    check_paths_exist()

    if args.base:
        print("\nagent docs -- coupling checks")
        check_coupling(args.base)

    for note in notes:
        print(f"  note  {note}")

    if failures:
        print(f"\n{len(failures)} check(s) failed: {', '.join(failures)}")
        return 1
    print("\nall agent-doc checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
