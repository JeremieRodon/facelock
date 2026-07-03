#!/bin/bash
set -euo pipefail

PASS=0
FAIL=0
LIVE_TIMEOUT="${FACELOCK_LIVE_TIMEOUT:-90s}"

run_test() {
    local name="$1"
    local cmd="$2"
    local expected_result="${3:-0}"

    echo -n "TEST: $name ... "
    set +o pipefail
    if eval "$cmd" > /tmp/test-output 2>&1; then
        result=0
    else
        result=$?
    fi
    set -o pipefail

    if [ "$expected_result" = "any" ] || [ "$result" -eq "$expected_result" ]; then
        echo "PASS"
        PASS=$((PASS + 1))
        return 0
    else
        echo "FAIL (exit=$result, expected=$expected_result)"
        cat /tmp/test-output
        FAIL=$((FAIL + 1))
        return 1
    fi
}

run_test_contains() {
    local name="$1"
    local cmd="$2"
    local pattern="$3"

    echo -n "TEST: $name ... "
    set +o pipefail
    if eval "$cmd" > /tmp/test-output 2>&1; then
        result=0
    else
        result=$?
    fi
    set -o pipefail

    if [ "$result" -eq 0 ] && grep -q -- "$pattern" /tmp/test-output; then
        echo "PASS"
        PASS=$((PASS + 1))
        return 0
    fi

    echo "FAIL (exit=$result, pattern=$pattern)"
    cat /tmp/test-output
    FAIL=$((FAIL + 1))
    return 1
}

wait_for_daemon() {
    local deadline=$((SECONDS + 30))
    local output=""

    while [ "$SECONDS" -lt "$deadline" ]; do
        output="$(facelock status 2>&1 || true)"
        if printf '%s\n' "$output" | grep -q '\[ok\] responding'; then
            return 0
        fi
        sleep 1
    done

    printf '%s\n' "$output"
    return 1
}

echo "=== Integration Tests (with camera) ==="
echo ""

# Use the installed config (written by Containerfile), override db path
# to a writable location since default may not be writable in containers
sed -i 's|db_path.*|db_path = "/tmp/facelock-test.db"|' /etc/facelock/config.toml 2>/dev/null || true

# Start a real system bus so CLI commands use the D-Bus daemon path.
mkdir -p /run/dbus
dbus-uuidgen --ensure=/etc/machine-id >/dev/null 2>&1 || true
dbus-daemon --system --fork --nopidfile

cleanup() {
    if [ -n "${DAEMON_PID:-}" ]; then
        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    pkill dbus-daemon 2>/dev/null || true
}
trap cleanup EXIT

# Start daemon in background
facelock daemon &
DAEMON_PID=$!
sleep 2

# Verify daemon is running
run_test "Daemon responds to ping" \
    "wait_for_daemon" || exit 1

# Test device listing
run_test_contains "Device listing works" \
    "facelock devices" \
    "/dev/video" || exit 1

# Test enrollment (will capture faces from camera)
run_test_contains "Enroll a face" \
    "timeout --foreground $LIVE_TIMEOUT facelock enroll --user testuser --label test-face --skip-setup-check" \
    "Face enrolled successfully" || exit 1

# Test listing enrolled models
run_test_contains "List enrolled models" \
    "facelock list --user testuser" \
    "test-face"

# Test authentication via CLI
run_test_contains "Authenticate enrolled face (CLI)" \
    "timeout --foreground $LIVE_TIMEOUT facelock test --user testuser" \
    "Matched model"

# Test authentication via PAM (the real auth path)
run_test "Authenticate enrolled face (PAM)" \
    "timeout --foreground $LIVE_TIMEOUT pamtester facelock-test testuser authenticate"

# --- Plan 05: rate-limited daemon state must never escalate to a fresh oneshot ---

# Force a rate-limited state by inserting failed attempts directly into the
# shared SQLite window (default: 5 attempts / 60s). Requires enrolled models
# (rate limiting is checked after the has-models pre-check).
run_test "Rate limit: seed failed attempts" \
    "sqlite3 /tmp/facelock-test.db \"INSERT INTO rate_limit (user, attempt_time) SELECT 'testuser', strftime('%s','now') FROM (VALUES (1),(2),(3),(4),(5),(6));\""

run_test_contains "Rate limit: daemon encodes recoverable error in-band (model_id=-2)" \
    "dbus-send --system --print-reply --dest=org.facelock.Daemon /org/facelock/Daemon org.facelock.Daemon.Authenticate string:testuser" \
    "int32 -2"

# With the in-band encoding the PAM module classifies the error itself
# (rate limited -> PAM_AUTH_ERR) instead of retrying as a root oneshot.
# A marker auth_bin proves no oneshot child is ever spawned.
run_test "Rate limit: PAM fails without oneshot escalation" \
    "printf '#!/bin/bash\ntouch /tmp/oneshot-invoked\nexit 2\n' > /usr/local/bin/oneshot-marker && chmod 755 /usr/local/bin/oneshot-marker && sed -i '/^\[daemon\]/a auth_bin = \"/usr/local/bin/oneshot-marker\"' /etc/facelock/config.toml && rm -f /tmp/oneshot-invoked; timeout 30 pamtester facelock-test testuser authenticate < /dev/null; rc=\$?; sed -i '/^auth_bin = /d' /etc/facelock/config.toml; test \$rc -ne 0 && test ! -f /tmp/oneshot-invoked"

run_test "Rate limit: clear seeded attempts" \
    "sqlite3 /tmp/facelock-test.db \"DELETE FROM rate_limit WHERE user = 'testuser';\""

# Clean up
run_test "Clear enrolled models" \
    "facelock clear --user testuser --yes"

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
