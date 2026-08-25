#!/usr/bin/env bash
# Decide whether a diff can affect a built package.
#
# Usage: classify-changes.sh [BASE_REF [HEAD_REF]]
#
# Emits `packaging=true|false` on stdout and, when running under Actions, into
# $GITHUB_OUTPUT so downstream jobs can gate on it with
# `if: needs.changes.outputs.packaging == 'true'`.
#
# Why this and not a filter action or GitHub's own `paths:`
#
#   A third-party filter action would be a fourth pinned SHA to review on the
#   Monday Renovate opens the bump (#235 pinned every action by commit and took
#   automerge away from them on purpose).
#
#   GitHub's native `paths:` filter skips the *workflow*, and a required check
#   that never runs sits "expected -- waiting for status" forever, so a PR that
#   touches no packaging can never merge. A job-level `if:` reports a real
#   "skipped" conclusion instead, which branch protection accepts.
#
# The filter is deliberately generous. A false positive costs 30-60 minutes of
# runner time; a false negative ships a broken package.
set -euo pipefail

# What a package is built from, plus what its scriptlets execute at install,
# upgrade and removal time.
#
#   debian/ dist/ .packit.yaml       the recipes themselves
#   systemd/ dbus/ config/           payload the packages install and validate
#   scripts/                         release identity, ORT/vendor bundles, and
#                                    the source-install daemon lifecycle the
#                                    deb and rpm gates re-enter
#   test/                            the harnesses the gates are made of
#   justfile                         every lane's entry point
#   .github/workflows/               these gates, and the release workflow
#
# And the Rust the maintainer scripts call. `%preun`, Arch's `pre_remove` and
# Debian's `prerm` all run `facelock pam remove --all`, so a change to the PAM
# command can abort a package removal without touching a packaging file.
# lifecycle.rs owns the purge exclusion interval a Debian purge runs inside,
# and daemon.rs is what postinst try-restarts and what pkg-validate.sh starts
# under the hardened unit.
#
# Note that `*` in a bash pattern match crosses `/`, so `dist/*` is `dist/**`.
PACKAGING_PATHS=(
    'debian/*'
    'dist/*'
    'systemd/*'
    'dbus/*'
    'config/*'
    'scripts/*'
    'test/Containerfile*'
    'test/*deb*'
    'test/*rpm*'
    'test/*pkg*'
    'test/arch-package/*'
    'justfile'
    '.packit.yaml'
    '.github/workflows/*'
    '.github/actions/*'
    'crates/facelock-cli/src/commands/pam.rs'
    'crates/facelock-cli/src/commands/daemon.rs'
    'crates/facelock-cli/src/lifecycle.rs'
)

decide() {
    local value="$1" reason="$2"
    echo "packaging=$value  ($reason)"
    if [ -n "${GITHUB_OUTPUT:-}" ]; then
        echo "packaging=$value" >>"$GITHUB_OUTPUT"
    fi
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
        echo "packaging gates: **$value** -- $reason" >>"$GITHUB_STEP_SUMMARY"
    fi
    exit 0
}

event="${GITHUB_EVENT_NAME:-local}"
base="${1:-${BASE_SHA:-}}"
head="${2:-HEAD}"

# Only a pull request is filtered. The nightly matrix and a manual dispatch are
# unfiltered by design -- they exist to catch what path filtering cannot.
if [ "$event" != "pull_request" ] && [ "$#" -eq 0 ]; then
    decide true "$event runs the full matrix unfiltered"
fi

if [ -z "$base" ]; then
    decide true "no merge base to diff against"
fi

if ! files="$(git diff --name-only "$base...$head" 2>&1)"; then
    echo "$files" >&2
    decide true "cannot diff $base...$head"
fi

if [ -z "$files" ]; then
    decide true "empty diff against $base"
fi

matched=()
while IFS= read -r file; do
    [ -n "$file" ] || continue
    for pattern in "${PACKAGING_PATHS[@]}"; do
        # shellcheck disable=SC2053  # the right side is a pattern on purpose
        if [[ $file == $pattern ]]; then
            matched+=("$file")
            break
        fi
    done
done <<<"$files"

echo "changed files: $(echo "$files" | wc -l)"
if [ ${#matched[@]} -gt 0 ]; then
    printf 'packaging path: %s\n' "${matched[@]}"
    decide true "${#matched[@]} changed file(s) reach a package"
fi

decide false "no changed file reaches a package"
