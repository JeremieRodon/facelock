#!/bin/bash
set -euo pipefail

PASS=0
FAIL=0

run_test() {
    local name="$1"
    local cmd="$2"
    local expected_result="${3:-0}"

    echo -n "TEST: $name ... "
    # Run command without pipefail so piped greps work correctly
    if bash -c "$cmd" > /tmp/test-output 2>&1; then
        result=0
    else
        result=$?
    fi

    if [ "$expected_result" = "any" ] || [ "$result" -eq "$expected_result" ]; then
        echo "PASS"
        PASS=$((PASS + 1))
    else
        echo "FAIL (exit=$result, expected=$expected_result)"
        cat /tmp/test-output
        FAIL=$((FAIL + 1))
    fi
}

echo "=== PAM Container Tests ==="
echo ""

# Test 1: Module loads without crash
run_test "Module loads without crash" \
    "pamtester facelock-test testuser authenticate" \
    "any"

# Test 2: PAM returns PAM_IGNORE when daemon not running
# pamtester returns non-zero when auth fails, but the module shouldn't crash
run_test "Module returns gracefully when daemon not running" \
    "pamtester facelock-test testuser authenticate < /dev/null" \
    "any"

# Test 3: Module handles missing config gracefully
run_test "Module handles missing config" \
    "mv /etc/facelock/config.toml /etc/facelock/config.toml.bak && pamtester facelock-test testuser authenticate; mv /etc/facelock/config.toml.bak /etc/facelock/config.toml" \
    "any"

# Test 4: Disabled config returns PAM_IGNORE
run_test "Module respects disabled config" \
    "sed -i 's/disabled = false/disabled = true/' /etc/facelock/config.toml && pamtester facelock-test testuser authenticate; sed -i 's/disabled = true/disabled = false/' /etc/facelock/config.toml" \
    "any"

# Test 5: PAM symbols are exported
run_test "pam_sm_authenticate symbol exists" \
    "nm -D /lib/security/pam_facelock.so | grep -q pam_sm_authenticate" \
    0

run_test "pam_sm_setcred symbol exists" \
    "nm -D /lib/security/pam_facelock.so | grep -q pam_sm_setcred" \
    0

# --- Spec 28: Privilege enforcement ---

run_test "facelock setup requires root" \
    "su -s /bin/bash testuser -c 'facelock setup 2>&1' | grep -q 'Root required'" \
    0

run_test "facelock daemon requires root" \
    "su -s /bin/bash testuser -c 'facelock daemon 2>&1' | grep -q 'Root required'" \
    0

# --- #174: `facelock pam add | remove | status` against the real /etc/pam.d ---
#
# The verb is the only writer of /etc/pam.d, and everything that decides
# whether it writes is machine state a tempdir test cannot stand in for: the
# root check, the pam_facelock.so-is-installed check, the hard-coded
# /etc/pam.d base, and the C-locale text of the refusals. This block proves
# the whole path as root on a live system — install, idempotence, the status
# probe's 0/1 scale, the sensitive-service gate, two-phase validation, name
# confinement, removal, and the `setup --pam` alias landing in the same file.
#
# It writes only to service files it creates itself (facelock-scratch*) and
# removes them at the end, so it is safe to run twice; sudo and the sensitive
# services are read and never written — the one row that aims at a sensitive
# service asserts a refusal, and saves and restores the file either way. jq is
# not in the image, so the --json documents are asserted with python.

PAM_LINE_TEXT='auth      sufficient pam_facelock.so'

# The `action` word for the first service in a `facelock pam --json` document.
cat > /tmp/pam-action.py <<'EOF'
import json, sys
print(json.load(open(sys.argv[1]))["services"][0]["action"])
EOF

# Exit 0 only if the facelock line is present AND is the file's first `auth`
# line — the placement contract, asserted by index rather than by eyeball.
cat > /tmp/pam-first-auth.py <<'EOF'
import sys
line = "auth      sufficient pam_facelock.so"
lines = open(sys.argv[1]).read().splitlines()
auth = [i for i, text in enumerate(lines) if text.lstrip().startswith("auth")]
sys.exit(0 if line in lines and auth and lines[auth[0]] == line else 1)
EOF

# Two throwaway service files with a realistic body. Nothing consumes them.
rm -f /etc/pam.d/facelock-scratch /etc/pam.d/facelock-scratch2 \
      /etc/pam.d/facelock-scratch.facelock-backup \
      /etc/pam.d/facelock-scratch2.facelock-backup
cat > /etc/pam.d/facelock-scratch <<'EOF'
#%PAM-1.0
auth       include        system-auth
account    include        system-auth
session    include        system-auth
EOF
chmod 644 /etc/pam.d/facelock-scratch
cp /etc/pam.d/facelock-scratch /etc/pam.d/facelock-scratch2

run_test "pam status: existing file without the line is 'missing', exit 1" \
    "facelock pam status --service facelock-scratch --json > /tmp/pam-status.json 2>/dev/null; test \$? -eq 1 && python3 /tmp/pam-action.py /tmp/pam-status.json | grep -qx missing" \
    0

run_test "pam status: an absent service file is exit 2" \
    "facelock pam status --service facelock-does-not-exist > /dev/null 2>&1; test \$? -eq 2" \
    0

# The pair `pam add --if-present` was always half of: install the optional
# integrations, then verify them. Without --if-present here, verifying an
# integration the host does not have is exit 2 and a `set -e` script dies on a
# service it deliberately made optional.
run_test "pam status --if-present: an absent service file is exit 0" \
    "facelock pam status --service facelock-does-not-exist --if-present" \
    0

run_test "pam add: 'installed', backup written, line is the first auth line" \
    "facelock pam add --service facelock-scratch --json > /tmp/pam-add.json 2>/dev/null; test \$? -eq 0 && python3 /tmp/pam-action.py /tmp/pam-add.json | grep -qx installed && test -f /etc/pam.d/facelock-scratch.facelock-backup && python3 /tmp/pam-first-auth.py /etc/pam.d/facelock-scratch" \
    0

sha256sum /etc/pam.d/facelock-scratch > /tmp/pam-scratch.sha

run_test "pam add is idempotent: 'unchanged' and the file is byte-identical" \
    "facelock pam add --service facelock-scratch --json > /tmp/pam-add2.json 2>/dev/null; test \$? -eq 0 && python3 /tmp/pam-action.py /tmp/pam-add2.json | grep -qx unchanged && sha256sum -c --status /tmp/pam-scratch.sha" \
    0

run_test "pam status exits 0 once the line is present" \
    "facelock pam status --service facelock-scratch" \
    0

# --- P1b (#170): the module probe ---
#
# This is the only tier where pam_facelock.so is genuinely installed, so it is
# where a regressed probe shows: `just install-files` puts it at
# /lib/security, the first candidate. The key is top-level and additive, and
# `null` here would mean `pam add` is about to refuse on a machine that has
# the module.
cat > /tmp/pam-module-path.py <<'EOF'
import json, sys
print(json.load(open(sys.argv[1])).get("module_path"))
EOF

run_test "pam status --json reports where the module was found" \
    "facelock pam status --service facelock-scratch --json > /tmp/pam-module.json 2>/dev/null; python3 /tmp/pam-module-path.py /tmp/pam-module.json | grep -qx /lib/security/pam_facelock.so" \
    0

rm -f /tmp/pam-module.json /tmp/pam-module-path.py

# The sensitive-service gate. Arch's `pam` package ships /etc/pam.d/system-auth,
# so that is what this normally runs against; the loop keeps the row honest if
# the base image ever changes which of the three exists. The refusal is decided
# in the validation phase, before any prompt, so --no-confirm cannot unlock it.
PAM_SENSITIVE=""
for svc in system-auth password-auth common-auth system-login login sshd; do
    if [ -f "/etc/pam.d/$svc" ]; then
        PAM_SENSITIVE="$svc"
        break
    fi
done

if [ -n "$PAM_SENSITIVE" ]; then
    # Belt and braces: the sha256 below detects a regression, and the copy
    # taken here undoes one. This is the container's own auth stack, and every
    # row after this one runs through it, so a failure must not be allowed to
    # leak into them as a second, mystifying failure.
    cp -p "/etc/pam.d/$PAM_SENSITIVE" /tmp/pam-sensitive.orig
    sha256sum "/etc/pam.d/$PAM_SENSITIVE" > /tmp/pam-sensitive.sha
    run_test "pam add refuses sensitive service $PAM_SENSITIVE under --no-confirm" \
        "facelock pam add --service $PAM_SENSITIVE --no-confirm > /tmp/pam-sensitive.out 2>&1; test \$? -ne 0 && grep -q 'sensitive PAM service' /tmp/pam-sensitive.out && sha256sum -c --status /tmp/pam-sensitive.sha" \
        0
    # The alias has its own refusal, naming its own flag: `setup --yes` is the
    # documented exception that means both "do not ask" and "unlock the gate",
    # so the message has to say --yes and not --allow-sensitive. Without this
    # row the alias could lose the gate entirely and only the verb would notice.
    run_test "setup --pam refuses sensitive service $PAM_SENSITIVE without --yes" \
        "facelock setup --pam --service $PAM_SENSITIVE > /tmp/pam-sensitive-alias.out 2>&1; test \$? -ne 0 && grep -q 'sensitive PAM service' /tmp/pam-sensitive-alias.out && grep -q -- '--yes' /tmp/pam-sensitive-alias.out && sha256sum -c --status /tmp/pam-sensitive.sha" \
        0
    cp -p /tmp/pam-sensitive.orig "/etc/pam.d/$PAM_SENSITIVE"
    rm -f "/etc/pam.d/$PAM_SENSITIVE.facelock-backup" /tmp/pam-sensitive.orig \
          /tmp/pam-sensitive-alias.out
else
    echo "SKIP: no sensitive service file in the image to test the gate"
fi

sha256sum /etc/pam.d/facelock-scratch2 > /tmp/pam-scratch2.sha

# Two-phase: the second service is rejected in validation, so the first one —
# which would otherwise have been written by the time the failure happened —
# is untouched, has no backup, and no JSON document is emitted at all.
run_test "pam add validates every service before writing any" \
    "facelock pam add --service facelock-scratch2 --service facelock-does-not-exist --json > /tmp/pam-twophase.out 2>&1; test \$? -ne 0 && sha256sum -c --status /tmp/pam-scratch2.sha && ! test -e /etc/pam.d/facelock-scratch2.facelock-backup && ! grep -q '\"services\"' /tmp/pam-twophase.out" \
    0

# The message grep is what makes this row mean anything: without `confined`,
# `../facelock-escape` resolves to /etc/facelock-escape, which does not exist,
# so the command would still exit non-zero (file-not-found) and --dry-run would
# still write nothing — every `! test -e` would hold on the broken path too.
run_test "pam add rejects a service name that escapes /etc/pam.d" \
    "facelock pam add --service ../facelock-escape --dry-run > /tmp/pam-escape.out 2>&1; test \$? -ne 0 && grep -q 'Invalid PAM service name' /tmp/pam-escape.out && ! test -e /etc/facelock-escape && ! test -e /etc/facelock-escape.facelock-backup && ! test -e /etc/pam.d/facelock-escape" \
    0

# The authselect shape, on a real /etc/pam.d rather than a tempdir: a service
# file that is a symlink out of the directory is refused, not written through.
# The target is checked by hash because the failure mode this guards against is
# a *successful-looking* run that edited a file elsewhere — exit status alone
# would not have caught it.
cat > /tmp/facelock-outside <<'EOF'
#%PAM-1.0
auth       include        system-auth
EOF
sha256sum /tmp/facelock-outside > /tmp/facelock-outside.sha
ln -sfn /tmp/facelock-outside /etc/pam.d/facelock-scratch-link

run_test "pam add refuses a service file symlinked out of /etc/pam.d" \
    "facelock pam add --service facelock-scratch-link --no-confirm > /tmp/pam-symlink.out 2>&1; test \$? -ne 0 && grep -q 'is a symlink to' /tmp/pam-symlink.out && sha256sum -c --status /tmp/facelock-outside.sha && ! test -e /tmp/facelock-outside.facelock-backup && ! test -e /etc/pam.d/facelock-scratch-link.facelock-backup" \
    0

rm -f /etc/pam.d/facelock-scratch-link /tmp/facelock-outside \
      /tmp/facelock-outside.sha /tmp/pam-symlink.out

run_test "pam remove: 'removed' and no facelock line left" \
    "facelock pam remove --service facelock-scratch --json > /tmp/pam-remove.json 2>/dev/null; test \$? -eq 0 && python3 /tmp/pam-action.py /tmp/pam-remove.json | grep -qx removed && ! grep -q pam_facelock.so /etc/pam.d/facelock-scratch" \
    0

# The `setup --pam` alias must reach the same writer and the same bytes.
# Placement, not just presence: the alias and the verb share one writer, and
# the thing that would prove they had stopped sharing it is the line landing
# somewhere else. Asserted by index, with the same probe the verb's row uses.
run_test "setup --pam alias installs the line as the first auth line" \
    "facelock setup --pam --service facelock-scratch --yes > /dev/null 2>&1; test \$? -eq 0 && grep -qxF '$PAM_LINE_TEXT' /etc/pam.d/facelock-scratch && python3 /tmp/pam-first-auth.py /etc/pam.d/facelock-scratch" \
    0

run_test "setup --pam --remove alias removes the line" \
    "facelock setup --pam --service facelock-scratch --remove --yes --if-present > /dev/null 2>&1; test \$? -eq 0 && ! grep -q pam_facelock.so /etc/pam.d/facelock-scratch" \
    0

rm -f /etc/pam.d/facelock-scratch

run_test "setup --pam --remove --if-present succeeds on an absent service file" \
    "facelock setup --pam --service facelock-scratch --remove --yes --if-present" \
    0

# The add side of the same flag. A provisioning script configures a set of
# optional integrations in one pass; before this, the alias could only say
# "add", so a machine without hyprlock failed the whole run. Absence must be a
# successful no-op that creates nothing. Both halves are asserted: a `setup
# --pam` that reached exit 0 by writing a service file out of thin air would
# satisfy an exit-code-only row.
run_test "setup --pam --if-present succeeds on an absent service file" \
    "facelock setup --pam --service facelock-scratch --yes --if-present > /dev/null 2>&1; test \$? -eq 0 && ! test -e /etc/pam.d/facelock-scratch" \
    0

# ...and the default is still a hard error, which is what catches a typo'd
# --service rather than silently configuring nothing.
run_test "setup --pam without --if-present still fails on an absent service file" \
    "facelock setup --pam --service facelock-scratch --yes > /dev/null 2>&1; test \$? -ne 0 && ! test -e /etc/pam.d/facelock-scratch" \
    0

# --- P1: vendor pam.d resolution ---
#
# Linux-PAM reads /etc/pam.d first and /usr/lib/pam.d second, and packages have
# moved their configuration there: on this image `polkit` ships
# /usr/lib/pam.d/polkit-1 and /etc/pam.d/polkit-1 does not exist. No tempdir
# test can prove the real directories are the ones facelock reaches, and no row
# above ever exercised a service that exists *only* in a vendor directory —
# which is exactly how the bug shipped.
#
# The vendor file is hashed before and after every row. Exit status alone would
# not catch the failure that matters: a successful-looking run that edited the
# package's own file.

VENDOR_PAM_DIR=/usr/lib/pam.d
mkdir -p "$VENDOR_PAM_DIR"
rm -f "$VENDOR_PAM_DIR/facelock-vendor-scratch" \
      "$VENDOR_PAM_DIR/facelock-vendor-scratch.facelock-backup" \
      /etc/pam.d/facelock-vendor-scratch \
      /etc/pam.d/facelock-vendor-scratch.facelock-backup
cat > "$VENDOR_PAM_DIR/facelock-vendor-scratch" <<'EOF'
#%PAM-1.0
auth       include        system-auth
account    include        system-auth
session    include        system-auth
EOF
chmod 644 "$VENDOR_PAM_DIR/facelock-vendor-scratch"
sha256sum "$VENDOR_PAM_DIR/facelock-vendor-scratch" > /tmp/pam-vendor.sha
# The file's bytes are one assertion; the directory's contents are another. A
# stray temp file, a backup, or any new entry in a package-owned directory
# passes every per-file hash, so the whole listing is snapshotted too.
ls -a "$VENDOR_PAM_DIR" | LC_ALL=C sort > /tmp/pam-vendor-dir.before

run_test "pam status: a vendor-only service is 'vendor-only', exit 1" \
    "facelock pam status --service facelock-vendor-scratch --json > /tmp/pam-vendor-status.json 2>/dev/null; test \$? -eq 1 && python3 /tmp/pam-action.py /tmp/pam-vendor-status.json | grep -qx vendor-only && grep -q '$VENDOR_PAM_DIR/facelock-vendor-scratch' /tmp/pam-vendor-status.json && sha256sum -c --status /tmp/pam-vendor.sha" \
    0

# The headline row: the service is configured without the package's file being
# touched, and the override says in its own bytes where it came from.
run_test "pam add on a vendor-only service creates an /etc override" \
    "facelock pam add --service facelock-vendor-scratch --json > /tmp/pam-vendor-add.json 2>/dev/null; test \$? -eq 0 && python3 /tmp/pam-action.py /tmp/pam-vendor-add.json | grep -qx overridden && test -f /etc/pam.d/facelock-vendor-scratch && python3 /tmp/pam-first-auth.py /etc/pam.d/facelock-vendor-scratch && test \$(grep -c '^# Copied from $VENDOR_PAM_DIR/facelock-vendor-scratch' /etc/pam.d/facelock-vendor-scratch) -eq 1 && sha256sum -c --status /tmp/pam-vendor.sha && ! test -e $VENDOR_PAM_DIR/facelock-vendor-scratch.facelock-backup" \
    0

# Second add: the override now shadows the vendor file, so this is an ordinary
# in-place no-op — one header, not two, and still nothing written to /usr.
run_test "pam add again edits the override, writes no second header" \
    "facelock pam add --service facelock-vendor-scratch --json > /tmp/pam-vendor-add2.json 2>/dev/null; test \$? -eq 0 && python3 /tmp/pam-action.py /tmp/pam-vendor-add2.json | grep -qx unchanged && test \$(grep -c '^# Copied from ' /etc/pam.d/facelock-vendor-scratch) -eq 1 && sha256sum -c --status /tmp/pam-vendor.sha" \
    0

run_test "pam remove takes the line out of the override, not the vendor file" \
    "facelock pam remove --service facelock-vendor-scratch --json > /tmp/pam-vendor-remove.json 2>/dev/null; test \$? -eq 0 && python3 /tmp/pam-action.py /tmp/pam-vendor-remove.json | grep -qx removed && test -f /etc/pam.d/facelock-vendor-scratch && ! grep -q pam_facelock.so /etc/pam.d/facelock-vendor-scratch && sha256sum -c --status /tmp/pam-vendor.sha" \
    0

rm -f /etc/pam.d/facelock-vendor-scratch /etc/pam.d/facelock-vendor-scratch.facelock-backup

run_test "pam remove on a vendor-only service is a no-op, exit 0" \
    "facelock pam remove --service facelock-vendor-scratch --json > /tmp/pam-vendor-remove2.json 2>/dev/null; test \$? -eq 0 && python3 /tmp/pam-action.py /tmp/pam-vendor-remove2.json | grep -qx vendor-only && ! test -e /etc/pam.d/facelock-vendor-scratch && sha256sum -c --status /tmp/pam-vendor.sha" \
    0

# A genuinely absent service still errors — and the message names every
# directory searched, not just the first. "Not found in /etc/pam.d" would send
# an operator to create a file a vendor directory may already hold.
run_test "an absent service names every directory searched" \
    "facelock pam add --service facelock-nowhere-scratch > /tmp/pam-nowhere.out 2>&1; test \$? -ne 0 && grep -q '/etc/pam.d/facelock-nowhere-scratch' /tmp/pam-nowhere.out && grep -q '$VENDOR_PAM_DIR/facelock-nowhere-scratch' /tmp/pam-nowhere.out" \
    0

run_test "the vendor directory gained and lost nothing" \
    "ls -a $VENDOR_PAM_DIR | LC_ALL=C sort > /tmp/pam-vendor-dir.after && diff -u /tmp/pam-vendor-dir.before /tmp/pam-vendor-dir.after" \
    0

rm -f "$VENDOR_PAM_DIR/facelock-vendor-scratch" /tmp/pam-vendor.sha \
      /tmp/pam-vendor-dir.before /tmp/pam-vendor-dir.after \
      /tmp/pam-vendor-status.json /tmp/pam-vendor-add.json \
      /tmp/pam-vendor-add2.json /tmp/pam-vendor-remove.json \
      /tmp/pam-vendor-remove2.json /tmp/pam-nowhere.out

# The real thing, on the stock image: `sudo facelock setup --pam --service
# polkit-1` is the invocation omarchy#7040 runs under `set -e`, and it exited 1
# on every current Arch box. The guard is not a way out of the assertion — if
# the layout is not the one this row exists for, it says so loudly rather than
# passing quietly.
if [ -f /usr/lib/pam.d/polkit-1 ] && [ ! -e /etc/pam.d/polkit-1 ]; then
    sha256sum /usr/lib/pam.d/polkit-1 > /tmp/pam-polkit.sha
    run_test "polkit-1 ships in the vendor directory and setup --pam configures it" \
        "facelock setup --pam --service polkit-1 --yes > /tmp/pam-polkit.out 2>&1; test \$? -eq 0 && grep -qxF '$PAM_LINE_TEXT' /etc/pam.d/polkit-1 && python3 /tmp/pam-first-auth.py /etc/pam.d/polkit-1 && sha256sum -c --status /tmp/pam-polkit.sha" \
        0
    run_test "pam status now answers 0 for polkit-1" \
        "facelock pam status --service polkit-1" \
        0
    rm -f /etc/pam.d/polkit-1 /etc/pam.d/polkit-1.facelock-backup \
          /tmp/pam-polkit.sha /tmp/pam-polkit.out
else
    # Not a skip. This is the only end-to-end row for the bug the whole gap
    # exists to fix, so an image that stops presenting the layout must cost a
    # red suite rather than quietly delete the coverage.
    echo "FAIL: polkit-1 is not vendor-only in this image \
(expected /usr/lib/pam.d/polkit-1 to exist and /etc/pam.d/polkit-1 not to) — \
the end-to-end vendor row did not run; fix the image or move the row to a \
service that is vendor-only"
    FAIL=$((FAIL + 1))
fi

rm -f /etc/pam.d/facelock-scratch /etc/pam.d/facelock-scratch2 \
      /etc/pam.d/facelock-scratch.facelock-backup \
      /etc/pam.d/facelock-scratch2.facelock-backup \
      /etc/pam.d/facelock-scratch-link /tmp/facelock-outside \
      /etc/pam.d/facelock-vendor-scratch \
      /etc/pam.d/facelock-vendor-scratch.facelock-backup \
      /usr/lib/pam.d/facelock-vendor-scratch \
      /tmp/pam-action.py /tmp/pam-first-auth.py

# --- Spec 29: Smart PAM skip (no enrolled faces) ---

# In oneshot mode with no enrolled faces, facelock auth should exit 2 (PAM_IGNORE)
run_test "facelock auth exits 2 when no faces enrolled" \
    "facelock auth --user testuser --config /etc/facelock/config.toml; test \$? -eq 2" \
    0

# pamtester should pass through (PAM_IGNORE from face → pam_deny catches it)
# The key: it should be FAST (no camera timeout)
run_test "No enrolled faces: pamtester completes quickly" \
    "timeout 3 pamtester facelock-test testuser authenticate 2>&1; test \$? -ne 124" \
    0

# --- Spec 30: PAM conversation messages ---

# When notification.enabled = true (default), "Identifying face..." should appear
run_test "PAM shows 'Identifying face...' text" \
    "pamtester facelock-test testuser authenticate 2>&1 | grep -q 'Identifying face'" \
    0

# When notification mode = off, no text message
run_test "PAM respects notification mode=off" \
    "sed -i '/^\[notification\]/,/^\[/{s/.*mode.*/mode = \"off\"/}' /etc/facelock/config.toml 2>/dev/null || (echo -e '\n[notification]\nmode = \"off\"' >> /etc/facelock/config.toml); pamtester facelock-test testuser authenticate 2>&1 | grep -qv 'Identifying face'; sed -i '/mode = \"off\"/d' /etc/facelock/config.toml" \
    0

# --- Spec 29: Smart PAM with oneshot config ---

run_test "Oneshot mode: no enrolled faces returns quickly" \
    "sed -i '/^\[daemon\]/a mode = \"oneshot\"' /etc/facelock/config.toml; timeout 3 pamtester facelock-test testuser authenticate 2>&1; rc=\$?; sed -i '/^mode = \"oneshot\"/d' /etc/facelock/config.toml; test \$rc -ne 124" \
    0

# --- Plan 05: PAM trust-boundary hardening (all camera-free) ---

# (a) A group/world-writable config must be rejected: the module ignores it
# and fails closed (PAM_IGNORE -> pam_deny). The 'Identifying face' prompt
# only appears once the config is accepted, so its absence plus an auth
# failure proves the module rejected the file instead of trusting it.
run_test "Group-writable config rejected, fails closed" \
    "chmod 664 /etc/facelock/config.toml; pamtester facelock-test testuser authenticate < /dev/null > /tmp/gw-out 2>&1; rc=\$?; chmod 644 /etc/facelock/config.toml; test \$rc -ne 0 && ! grep -q 'Identifying face' /tmp/gw-out" \
    0

run_test "World-writable config rejected, fails closed" \
    "chmod 666 /etc/facelock/config.toml; pamtester facelock-test testuser authenticate < /dev/null > /tmp/ww-out 2>&1; rc=\$?; chmod 644 /etc/facelock/config.toml; test \$rc -ne 0 && ! grep -q 'Identifying face' /tmp/ww-out" \
    0

run_test "Config accepted again after restoring 644" \
    "pamtester facelock-test testuser authenticate 2>&1 | grep -q 'Identifying face'" \
    0

# (b) env_clear: LD_PRELOAD must never reach the spawned oneshot child while
# SSH_CONNECTION must survive. A constructor-marker .so logs every process it
# is loaded into; a root-owned capture stub stands in for the auth binary so
# the exact child environment can be asserted.
cat > /tmp/preload-marker.c <<'EOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
__attribute__((constructor)) static void mark(void) {
    char exe[512] = {0};
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    FILE *f = fopen("/tmp/preload-log", "a");
    if (f) { fprintf(f, "%s\n", n > 0 ? exe : "?"); fclose(f); }
}
EOF
gcc -shared -fPIC -o /tmp/preload-marker.so /tmp/preload-marker.c
printf '#!/bin/bash\nenv > /tmp/oneshot-child-env\nexit 2\n' > /usr/local/bin/facelock-env-capture
chmod 755 /usr/local/bin/facelock-env-capture
rm -f /tmp/preload-log /tmp/oneshot-child-env

# Intercept the oneshot spawn by BEING /usr/bin/facelock for the duration
# rather than pointing an auth_bin config key at the stub: the PAM module
# spawns the oneshot binary by that fixed path (post-#109 the key does not
# exist; pre-#109 its default is the same path and nothing here sets it), so
# the swap works on both sides of that change and the assertions can never
# pass vacuously through an ignored redirect.
sed -i '/^\[daemon\]/a mode = "oneshot"' /etc/facelock/config.toml
sed -i '/^\[security\]/a abort_if_ssh = false' /etc/facelock/config.toml
mv /usr/bin/facelock /usr/bin/facelock.orig
install -m 755 /usr/local/bin/facelock-env-capture /usr/bin/facelock
env LD_PRELOAD=/tmp/preload-marker.so SSH_CONNECTION='192.0.2.1 1111 192.0.2.2 22' \
    pamtester facelock-test testuser authenticate < /dev/null > /dev/null 2>&1 || true
mv -f /usr/bin/facelock.orig /usr/bin/facelock
sed -i '/^mode = "oneshot"/d;/^abort_if_ssh = false/d' /etc/facelock/config.toml

run_test "env_clear: marker was active in the PAM process" \
    "grep -q pamtester /tmp/preload-log" \
    0

run_test "env_clear: LD_PRELOAD marker not loaded by oneshot child" \
    "test -f /tmp/oneshot-child-env && ! grep -q '^LD_PRELOAD=' /tmp/oneshot-child-env && ! grep -q bash /tmp/preload-log" \
    0

run_test "env_clear: SSH_CONNECTION survives to oneshot child" \
    "grep -q '^SSH_CONNECTION=192.0.2.1' /tmp/oneshot-child-env" \
    0

run_test "env_clear: oneshot child PATH pinned to /usr/bin:/bin" \
    "grep -qx 'PATH=/usr/bin:/bin' /tmp/oneshot-child-env" \
    0

# (c) Peer-UID check: a non-root process owning org.facelock.Daemon and
# replying matched=true must never produce PAM_SUCCESS. A deliberately
# loosened bus policy simulates a broken/compromised policy file.
cat > /usr/share/dbus-1/system.d/zz-facelock-peer-test.conf <<'EOF'
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <policy user="testuser">
    <allow own="org.facelock.Daemon"/>
  </policy>
  <policy context="default">
    <allow send_destination="org.facelock.Daemon"/>
  </policy>
</busconfig>
EOF
mkdir -p /run/dbus
dbus-uuidgen --ensure=/etc/machine-id > /dev/null 2>&1 || true
dbus-daemon --system --fork --nopidfile
runuser -u testuser -- python3 /fake-facelock-daemon.py > /tmp/fake-daemon.log 2>&1 &
FAKE_PID=$!
for _ in $(seq 1 40); do
    dbus-send --system --print-reply --dest=org.freedesktop.DBus \
        /org/freedesktop/DBus org.freedesktop.DBus.NameHasOwner \
        string:org.facelock.Daemon 2>/dev/null | grep -q 'boolean true' && break
    sleep 0.25
done

run_test "Peer-UID harness: fake non-root daemon replies matched=true" \
    "dbus-send --system --print-reply --dest=org.facelock.Daemon /org/facelock/Daemon org.facelock.Daemon.Authenticate string:testuser | grep -q 'boolean true'" \
    0

run_test "Peer-UID: non-root daemon owner yields no PAM_SUCCESS" \
    "! timeout 15 pamtester facelock-test testuser authenticate < /dev/null" \
    0

kill "$FAKE_PID" 2>/dev/null || true
rm -f /usr/share/dbus-1/system.d/zz-facelock-peer-test.conf

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
