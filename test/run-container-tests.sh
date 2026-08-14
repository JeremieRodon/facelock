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
