#!/usr/bin/env bash
# Exercise .github/workflows/scripts/classify-changes.sh against real merge-base
# diffs in a throwaway repository.
#
# The classifier decides whether the packaging gates run on a pull request. A
# pattern that stops matching does not fail anything -- it silently reports
# "skipped" for every deb, rpm and Arch lane, and the pull request goes green
# without a package having been built. That is the failure this file exists to
# make loud.
#
# The `rust-only` case is not an oversight. It pins the documented residual risk
# (docs/releasing.md): a change touching no packaging path is not gated by its
# own pull request, only by the nightly matrix and the release gate.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script="$repo_root/.github/workflows/scripts/classify-changes.sh"
[ -x "$script" ] || {
    echo "classifier is missing or not executable: $script" >&2
    exit 1
}

work="$(mktemp -d "${TMPDIR:-/tmp}/facelock-classify.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT
cd "$work"

git init --quiet -b main .
mkdir -p docs debian dist test .github/workflows \
    crates/facelock-cli/src/commands crates/facelock-daemon/src
for f in \
    README.md \
    docs/releasing.md \
    debian/control \
    dist/facelock.spec \
    justfile \
    .packit.yaml \
    systemd/facelock-daemon.service \
    crates/facelock-cli/src/lifecycle.rs \
    crates/facelock-cli/src/commands/pam.rs \
    crates/facelock-cli/src/commands/enroll.rs \
    crates/facelock-daemon/src/handler.rs \
    test/deb-package-contract.sh \
    test/Containerfile.rpm-e2e \
    .github/workflows/ci.yml
do
    mkdir -p "$(dirname "$f")"
    printf 'base\n' > "$f"
done
git add -A
git -c user.email=test@example.invalid -c user.name=test commit --quiet -m base
base="$(git rev-parse HEAD)"

failures=0
classification() {
    GITHUB_EVENT_NAME="$1" bash "$script" "${@:2}" 2>/dev/null |
        sed -n 's/^packaging=\([a-z]*\).*/\1/p'
}

expect_diff() {
    local want="$1" name="$2"
    shift 2
    git checkout --quiet -B "case-$name" "$base"
    for path in "$@"; do printf 'changed\n' >> "$path"; done
    git add -A
    git -c user.email=test@example.invalid -c user.name=test commit --quiet -m "$name"
    local got
    got="$(classification pull_request "$base" HEAD)"
    if [ "$got" = "$want" ]; then
        echo "  ok    $name -> $got"
    else
        echo "  FAIL  $name -> ${got:-<none>}, expected $want"
        failures=$((failures + 1))
    fi
}

expect_event() {
    local want="$1" event="$2"
    local got
    got="$(classification "$event")"
    if [ "$got" = "$want" ]; then
        echo "  ok    $event -> $got"
    else
        echo "  FAIL  $event -> ${got:-<none>}, expected $want"
        failures=$((failures + 1))
    fi
}

echo "classify-changes -- a diff that reaches a package"
expect_diff true debian debian/control
expect_diff true spec dist/facelock.spec
expect_diff true systemd-unit systemd/facelock-daemon.service
expect_diff true packit .packit.yaml
expect_diff true justfile justfile
expect_diff true test-harness test/deb-package-contract.sh
expect_diff true containerfile test/Containerfile.rpm-e2e
expect_diff true workflow .github/workflows/ci.yml
expect_diff true pam-command crates/facelock-cli/src/commands/pam.rs
expect_diff true purge-lifecycle crates/facelock-cli/src/lifecycle.rs
expect_diff true mixed docs/releasing.md debian/control

echo "classify-changes -- a diff that does not"
expect_diff false docs-only docs/releasing.md README.md
expect_diff false rust-only crates/facelock-cli/src/commands/enroll.rs crates/facelock-daemon/src/handler.rs

echo "classify-changes -- unfiltered events and fail-open"
expect_event true schedule
expect_event true workflow_dispatch
expect_event true pull_request   # no base to diff against

if [ "$failures" -ne 0 ]; then
    echo "$failures classification case(s) failed" >&2
    exit 1
fi
echo "classify-changes contract: OK"
