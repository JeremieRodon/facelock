#!/usr/bin/env bash
# Prove the exact candidate resolves and configures from a pristine suite base,
# before the separate systemd/PAM/TPM harness installs overlapping packages.
set -euo pipefail

PACKAGE=/facelock-test-package.deb
APT_LOG=/tmp/facelock-dependency-closure-apt.log
SUITE_BASE_PACKAGES=/facelock-suite-base-packages

fail() {
    echo "FAIL [Debian dependency closure]: $*" >&2
    exit 1
}

# shellcheck source=/dev/null
. /deb-declared-depends.sh

[ -f "$PACKAGE" ] && [ ! -L "$PACKAGE" ] ||
    fail "candidate package is not a regular file"
[ "$(stat -c %a "$PACKAGE")" = 444 ] ||
    fail "candidate package must be mounted mode 0444"
mount_options="$(awk -v target="$PACKAGE" '$5 == target { print $6; exit }' \
    /proc/self/mountinfo)"
case ",$mount_options," in
    *,ro,*) ;;
    *) fail "candidate package is not an exact read-only mount: $mount_options" ;;
esac
if dpkg-query -W -f='${db:Status-Status}\n' facelock 2>/dev/null |
    grep -qx installed; then
    fail "clean dependency stage already contains Facelock"
fi

# The booted lifecycle gate decides which of its declared dependencies the test
# harness pre-satisfied by reading the suite manifest recorded during the image
# build. That verdict is only as good as the record, so prove it here, on the
# one stage that is supposed to be nothing but the suite base.
[ -s "$SUITE_BASE_PACKAGES" ] ||
    fail "image build recorded no pristine suite package set"
dpkg-query -W -f='${Package}\n' | LC_ALL=C sort -u >/tmp/facelock-live-packages
cmp -s "$SUITE_BASE_PACKAGES" /tmp/facelock-live-packages || {
    diff -u "$SUITE_BASE_PACKAGES" /tmp/facelock-live-packages >&2 || true
    fail "recorded suite package set does not match this pristine stage"
}

candidate_hash="$(sha256sum "$PACKAGE" | cut -d' ' -f1)"
before_packages="$(dpkg-query -W -f='${binary:Package}\n' | wc -l)"
: >"$APT_LOG"
apt-get update >>"$APT_LOG" 2>&1
if ! apt-get install -y --no-install-recommends "$PACKAGE" >>"$APT_LOG" 2>&1; then
    cat "$APT_LOG" >&2
    fail "APT could not resolve the exact candidate from the pristine suite base"
fi
if grep -Eqi \
    'correcting dependencies|fix-broken|unmet dependencies|dependency problems - leaving unconfigured' \
    "$APT_LOG"; then
    cat "$APT_LOG" >&2
    fail "APT repaired or masked an incomplete dependency transaction"
fi

candidate_version="$(dpkg-deb --field "$PACKAGE" Version)"
[ "$(dpkg-query -W -f='${db:Status-Status}' facelock)" = installed ] ||
    fail "candidate is not fully installed"
[ "$(dpkg-query -W -f='${Version}' facelock)" = "$candidate_version" ] ||
    fail "installed version does not match the exact candidate"
after_packages="$(dpkg-query -W -f='${binary:Package}\n' | wc -l)"
[ "$after_packages" -gt "$((before_packages + 1))" ] ||
    fail "clean-base transaction did not install any dependency package"
declared_dependency_groups "$PACKAGE" |
    assert_dependency_groups_satisfied "pristine suite base"
[ -z "$(dpkg --audit)" ] || fail "dpkg reports an incomplete transaction"
apt-get check >>"$APT_LOG" 2>&1 || {
    cat "$APT_LOG" >&2
    fail "APT dependency closure is not healthy after candidate installation"
}

for elf in \
    /usr/bin/facelock \
    /usr/bin/facelock-polkit-agent \
    /lib/security/pam_facelock.so \
    /usr/lib/facelock/libonnxruntime.so; do
    [ -f "$elf" ] || fail "installed ELF payload missing: $elf"
    if ldd "$elf" 2>&1 | grep -Fq 'not found'; then
        ldd "$elf" >&2 || true
        fail "installed ELF payload has an unresolved library: $elf"
    fi
done
/usr/bin/facelock --version >/dev/null ||
    fail "installed CLI cannot execute after dependency resolution"
[ "$(sha256sum "$PACKAGE" | cut -d' ' -f1)" = "$candidate_hash" ] ||
    fail "read-only candidate changed during dependency validation"

echo "TEST: Debian exact candidate resolves from pristine suite base ... PASS"
