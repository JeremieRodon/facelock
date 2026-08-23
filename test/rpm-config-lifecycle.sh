#!/usr/bin/env bash
# Booted Fedora proof of what %config(noreplace) does to /etc/facelock/config.toml
# across an upgrade.
#
# The observed RPM contract, confirmed against rpm on Fedora and pinned here:
#
#   unmodified on disk, packaged config changed  -> file replaced with the new
#                                                   packaged bytes, no .rpmnew,
#                                                   no .rpmsave
#   modified on disk, packaged config changed    -> administrator bytes kept
#                                                   byte-for-byte, new packaged
#                                                   bytes land in .rpmnew,
#                                                   no .rpmsave
#
# `.rpmsave` belongs to erase, not upgrade; test/pkg-validate.sh pins that half.
# An assertion that accepts either outcome pins nothing, so every case here
# names exactly one file layout and exactly one set of bytes.
#
# Runs after test/pkg-validate.sh, which leaves the package uninstalled.
set -euo pipefail

baseline_rpm=/facelock-test-package.rpm
upgrade_rpm=/facelock-test-upgrade.rpm
config=/etc/facelock/config.toml
pass_count=0

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

pass() {
    printf 'TEST: %s ... PASS\n' "$1"
    pass_count=$((pass_count + 1))
}

# Digest of the config file as the package records it, not as some copy of the
# tree happens to look. Field 4 of --dump is the file digest.
packaged_config_digest() {
    rpm -qp --dump "$1" 2>/dev/null |
        awk -v path="$config" '$1 == path { print $4; found = 1 } END { exit !found }'
}

packaged_config_flags() {
    rpm -qp --queryformat '[%{FILENAMES} %{FILEFLAGS:fflags}\n]' "$1" 2>/dev/null |
        awk -v path="$config" '$1 == path { print $2; found = 1 } END { exit !found }'
}

on_disk_digest() {
    sha256sum "$1" | awk '{ print $1 }'
}

require_absent() {
    [ ! -e "$1" ] && [ ! -L "$1" ] || fail "$2: $1 exists"
}

reset_state() {
    if rpm -q facelock >/dev/null 2>&1; then
        rpm -e facelock >/dev/null
    fi
    rm -f -- "$config" "$config".rpmnew "$config".rpmsave "$config".rpmorig
}

for required in "$baseline_rpm" "$upgrade_rpm"; do
    [ -f "$required" ] || fail "missing required package: $required"
done

baseline_digest="$(packaged_config_digest "$baseline_rpm")" ||
    fail "$baseline_rpm does not package $config"
upgrade_digest="$(packaged_config_digest "$upgrade_rpm")" ||
    fail "$upgrade_rpm does not package $config"
[ "$baseline_digest" != "$upgrade_digest" ] ||
    fail "both packages ship identical config bytes, so no upgrade case is observable"

for candidate in "$baseline_rpm" "$upgrade_rpm"; do
    flags="$(packaged_config_flags "$candidate")" || fail "$candidate does not list $config"
    case "$flags" in
        *c*n*|*n*c*) ;;
        *) fail "$candidate does not declare $config as config(noreplace), flags: $flags" ;;
    esac
done
pass "both packages declare the config file as config(noreplace)"

reset_state
trap 'reset_state || true' EXIT

dnf install -y "$baseline_rpm" >/dev/null
[ "$(on_disk_digest "$config")" = "$baseline_digest" ] ||
    fail "fresh install did not lay down the packaged config bytes"
pass "fresh install lays down exactly the packaged config bytes"

dnf upgrade -y "$upgrade_rpm" >/dev/null
[ "$(on_disk_digest "$config")" = "$upgrade_digest" ] ||
    fail "upgrade left an unmodified config that is not the new packaged file"
require_absent "$config.rpmnew" "unmodified upgrade diverted the new config"
require_absent "$config.rpmsave" "unmodified upgrade saved a config nobody edited"
pass "unmodified config is replaced in place by the new packaged config on upgrade"

reset_state
dnf install -y "$baseline_rpm" >/dev/null
printf '\n# administrator edit kept across the upgrade\n' >>"$config"
admin_digest="$(on_disk_digest "$config")"
[ "$admin_digest" != "$baseline_digest" ] || fail "the administrator edit did not change the file"

dnf upgrade -y "$upgrade_rpm" >/dev/null
[ "$(on_disk_digest "$config")" = "$admin_digest" ] ||
    fail "upgrade overwrote an administrator-modified config"
grep -qxF '# administrator edit kept across the upgrade' "$config" ||
    fail "administrator edit is gone from the retained config"
[ -f "$config.rpmnew" ] || fail "upgrade did not divert the new packaged config to .rpmnew"
[ "$(on_disk_digest "$config.rpmnew")" = "$upgrade_digest" ] ||
    fail ".rpmnew does not hold the new packaged config bytes"
require_absent "$config.rpmsave" "upgrade saved an .rpmsave that belongs to erase"
pass "modified config survives upgrade byte-for-byte with the new file as .rpmnew"

rpm -q facelock >/dev/null || fail "package is not installed after the upgrade cases"
pass "the upgraded package stays installed through both config cases"

printf '\n=== RPM config(noreplace) upgrade results: %d passed, 0 failed ===\n' "$pass_count"
