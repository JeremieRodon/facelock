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

# Start polkitd so PreviewDetectFrame's frame authorization exercises a real
# polkit round-trip. No authentication agent is registered in the container,
# so interactive authorization is impossible — the daemon must FAIL CLOSED
# (stripped frames) unless an explicit test rule grants the action.
POLKITD_PID=""
if [ -x /usr/lib/polkit-1/polkitd ]; then
    /usr/lib/polkit-1/polkitd --no-debug > /tmp/polkitd.log 2>&1 &
    POLKITD_PID=$!
    sleep 1
fi

cleanup() {
    if [ -n "${DAEMON_PID:-}" ]; then
        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    rm -f /etc/polkit-1/rules.d/90-facelock-test.rules
    if [ -n "${POLKITD_PID:-}" ]; then
        kill "$POLKITD_PID" 2>/dev/null || true
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

# --- Device coupling (Plan 02, daemon path) ---
# The daemon runs migrations at startup and records the live camera fingerprint
# in face_models.device_id at enroll. Verify V6 applied, enroll recorded a
# device_id, a forged/mismatched id falls through to no-match, and a legacy NULL
# id still authenticates. (Reads/writes go through the WAL, which the daemon's
# own connection sees on its next query.)
# Resolve the DB path the daemon actually uses (config db_path if uncommented,
# else the compiled default /var/lib/facelock/facelock.db).
# `grep` exiting 1 on no-match must not abort the script (set -e + pipefail), so
# tolerate it; fall back to the compiled default when db_path is unset.
DB="$({ grep -E '^[[:space:]]*db_path[[:space:]]*=' /etc/facelock/config.toml 2>/dev/null || true; } | tail -1 | sed -E 's/^[^=]*=[[:space:]]*"?([^"]*)"?[[:space:]]*$/\1/')"
[ -n "$DB" ] || DB="/var/lib/facelock/facelock.db"

SCHEMA_VER="$(sqlite3 "$DB" 'SELECT MAX(version) FROM schema_version' 2>/dev/null || echo 0)"
run_test "V6 schema migration applied on daemon startup (db=$DB)" \
    "[ \"$SCHEMA_VER\" -ge 6 ]" 0

# --- Encryption at rest (Plan 04, finding #8) ---
# Encryption defaults to keyfile, so the daemon enroll above must have stored
# ciphertext (sealed=1, version byte 0x02, length != raw 2048), and the auth
# tests above already round-tripped enroll->auth through the decrypt path.
# CAMERA-REQUIRED: depends on the live daemon enroll above.
ENC_SEALED="$(sqlite3 "$DB" "SELECT fe.sealed FROM face_embeddings fe JOIN face_models fm ON fe.model_id=fm.id WHERE fm.user='testuser' LIMIT 1" 2>/dev/null || echo '?')"
ENC_LEN="$(sqlite3 "$DB" "SELECT LENGTH(fe.embedding) FROM face_embeddings fe JOIN face_models fm ON fe.model_id=fm.id WHERE fm.user='testuser' LIMIT 1" 2>/dev/null || echo 0)"
ENC_VB="$(sqlite3 "$DB" "SELECT hex(substr(fe.embedding,1,1)) FROM face_embeddings fe JOIN face_models fm ON fe.model_id=fm.id WHERE fm.user='testuser' LIMIT 1" 2>/dev/null || echo '')"
run_test "fresh enroll stores encrypted blob, not raw f32 (sealed=$ENC_SEALED len=$ENC_LEN vb=$ENC_VB)" \
    "[ \"$ENC_SEALED\" = 1 ] && [ \"$ENC_VB\" = '02' ] && [ \"$ENC_LEN\" -ne 2048 ]" 0

DEVID="$(sqlite3 "$DB" "SELECT COALESCE(device_id,'') FROM face_models WHERE user='testuser' LIMIT 1" 2>/dev/null || echo '')"
if [ -n "$DEVID" ]; then
    run_test "enrolled template has non-null device_id (daemon, camera-fingerprinted): '$DEVID'" "true" 0
else
    echo "TEST: enrolled template device_id ... SKIP (live camera exposed no USB identity in-container; coupling degrades to legacy-allow)"
fi

# Swap-in regression gate: a forged, non-matching device_id must fall through to
# no-match, never authenticate.
sqlite3 "$DB" "PRAGMA busy_timeout=8000; UPDATE face_models SET device_id='ffff:ffff:forged' WHERE user='testuser'" || true
echo -n "TEST: facelock test reports no match on forged device_id (coupling; no success) ... "
set +o pipefail
timeout --foreground "$LIVE_TIMEOUT" facelock test --user testuser > /tmp/test-output 2>&1 || true
set -o pipefail
if grep -q "No match" /tmp/test-output; then
    echo "PASS"; PASS=$((PASS + 1))
else
    echo "FAIL"; cat /tmp/test-output; FAIL=$((FAIL + 1))
fi

# Legacy NULL device_id still authenticates (allow-with-warn; no lockout).
sqlite3 "$DB" "PRAGMA busy_timeout=8000; UPDATE face_models SET device_id=NULL WHERE user='testuser'" || true
run_test_contains "facelock test matches again on legacy NULL device_id (daemon)" \
    "timeout --foreground $LIVE_TIMEOUT facelock test --user testuser" \
    "Matched"

# --- Plan 05: rate-limited daemon state must never escalate to a fresh oneshot ---

# Resolve the database the daemon actually uses (config db_path or default).
FACELOCK_DB="$(sed -n 's/^[[:space:]]*db_path[[:space:]]*=[[:space:]]*"\(.*\)"/\1/p' /etc/facelock/config.toml | head -1)"
FACELOCK_DB="${FACELOCK_DB:-/var/lib/facelock/facelock.db}"

# Force a rate-limited state by inserting failed attempts directly into the
# shared SQLite window (default: 5 attempts / 60s). Requires enrolled models
# (rate limiting is checked after the has-models pre-check).
run_test "Rate limit: seed failed attempts" \
    "sqlite3 $FACELOCK_DB \"INSERT INTO rate_limit (user, attempt_time) SELECT 'testuser', strftime('%s','now') FROM (VALUES (1),(2),(3),(4),(5),(6));\""

run_test_contains "Rate limit: daemon encodes recoverable error in-band (model_id=-2)" \
    "dbus-send --system --print-reply --dest=org.facelock.Daemon /org/facelock/Daemon org.facelock.Daemon.Authenticate string:testuser" \
    "int32 -2"

# With the in-band encoding the PAM module classifies the error itself
# (rate limited -> PAM_AUTH_ERR) instead of retrying as a root oneshot.
# Swapping a marker stub in at /usr/bin/facelock proves no oneshot child is
# ever spawned (the module spawns that fixed path; an auth_bin config
# redirect would be ignored and make this test vacuous). The daemon keeps
# answering from its already-exec'd binary while the file is swapped.
run_test "Rate limit: PAM fails without oneshot escalation" \
    "printf '#!/bin/bash\ntouch /tmp/oneshot-invoked\nexit 2\n' > /usr/local/bin/oneshot-marker && chmod 755 /usr/local/bin/oneshot-marker && rm -f /tmp/oneshot-invoked && mv /usr/bin/facelock /usr/bin/facelock.orig && install -m 755 /usr/local/bin/oneshot-marker /usr/bin/facelock; timeout 30 pamtester facelock-test testuser authenticate < /dev/null; rc=\$?; mv -f /usr/bin/facelock.orig /usr/bin/facelock; test \$rc -ne 0 && test ! -f /tmp/oneshot-invoked"

run_test "Rate limit: clear seeded attempts" \
    "sqlite3 $FACELOCK_DB \"DELETE FROM rate_limit WHERE user = 'testuser';\""

# --- D-Bus hardening assertions (security plan 06) ---

# sigwatcher: unprivileged, NOT in the facelock group (signal eavesdropper).
# testuser: added to the facelock group (bus policy allows it to send).
useradd -m sigwatcher 2>/dev/null || true
usermod -aG facelock testuser

# (a) Signal hardening — needs the daemon up plus one auth attempt to emit
# the signal. Unprivileged users must not receive AuthAttempted, and the
# payload must carry no similarity score (no 'double' argument).
runuser -u sigwatcher -- dbus-monitor --system \
    "type='signal',interface='org.facelock.Daemon'" > /tmp/sig-unpriv.log 2>&1 &
UNPRIV_MON_PID=$!
dbus-monitor --system \
    "type='signal',interface='org.facelock.Daemon'" > /tmp/sig-root.log 2>&1 &
ROOT_MON_PID=$!
sleep 2
timeout --foreground "$LIVE_TIMEOUT" facelock test --user testuser > /dev/null 2>&1 || true
sleep 2
kill "$UNPRIV_MON_PID" "$ROOT_MON_PID" 2>/dev/null || true
wait "$UNPRIV_MON_PID" "$ROOT_MON_PID" 2>/dev/null || true

run_test "AuthAttempted signal visible to root monitor" \
    "grep -q 'member=AuthAttempted' /tmp/sig-root.log"

run_test "AuthAttempted payload carries no similarity score" \
    "! grep -A3 'member=AuthAttempted' /tmp/sig-root.log | grep -q 'double'"

run_test "Unprivileged user receives no AuthAttempted signal" \
    "! grep -q 'member=AuthAttempted' /tmp/sig-unpriv.log"

# Policy: the default context explicitly denies owning the daemon name —
# only root may own org.facelock.Daemon.
check_own_denied() {
    local out rc
    set +e
    out=$(runuser -u sigwatcher -- dbus-send --system --print-reply \
        --dest=org.freedesktop.DBus /org/freedesktop/DBus \
        org.freedesktop.DBus.RequestName string:org.facelock.Daemon uint32:0 2>&1)
    rc=$?
    set -e
    echo "$out"
    [ "$rc" -ne 0 ] || { echo "RequestName unexpectedly succeeded"; return 1; }
    echo "$out" | grep -qiE "not allowed to own|AccessDenied" || return 1
    return 0
}
run_test "Unprivileged user cannot own org.facelock.Daemon" \
    "check_own_denied"

# (b) PreviewDetectFrame authz parity — a facelock-group non-root caller may
# call it for itself, but the reply must not contain raw frame bytes
# (dbus-send renders non-empty byte arrays as hex; a JPEG starts with ff d8).
check_preview_detect_frame_stripped() {
    local out
    if ! out=$(runuser -u testuser -- dbus-send --system --print-reply \
        --reply-timeout=60000 \
        --dest=org.facelock.Daemon /org/facelock/Daemon \
        org.facelock.Daemon.PreviewDetectFrame string:testuser 2>&1); then
        echo "$out"
        return 1
    fi
    echo "$out"
    echo "$out" | grep -q "method return" || return 1
    if echo "$out" | grep -qi "ff d8"; then
        echo "reply contains JPEG frame bytes (ff d8) — should be stripped"
        return 1
    fi
    return 0
}
run_test "PreviewDetectFrame returns no raw frame to non-root caller" \
    "check_preview_detect_frame_stripped"

# (b2) Packaging contract — the polkit action for frame authorization is
# installed alongside the D-Bus policy.
run_test "polkit action policy installed" \
    "[ -f /usr/share/polkit-1/actions/org.facelock.policy ] && grep -q 'org.facelock.preview-frames' /usr/share/polkit-1/actions/org.facelock.policy"

# (b3) AUTHORIZED PATH: with an explicit polkit rule granting
# org.facelock.preview-frames, a non-root preview session (one bus
# connection across frames) receives real frame bytes. The first frame is
# metadata-only while the daemon's polkit check is in flight; subsequent
# frames must carry jpeg bytes (jpeg_size > 0).
check_preview_frames_authorized() {
    mkdir -p /etc/polkit-1/rules.d
    cat > /etc/polkit-1/rules.d/90-facelock-test.rules <<'RULES'
polkit.addRule(function(action, subject) {
    if (action.id == "org.facelock.preview-frames") {
        return polkit.Result.YES;
    }
});
RULES
    sleep 2 # polkitd reloads rules.d via inotify
    timeout --foreground 30 runuser -u testuser -- \
        facelock preview --text-only 2>/dev/null | head -15 > /tmp/preview-authz.log || true
    rm -f /etc/polkit-1/rules.d/90-facelock-test.rules
    sleep 2 # let polkitd drop the rule before the fail-closed re-check
    cat /tmp/preview-authz.log
    grep -q '"jpeg_size":[1-9]' /tmp/preview-authz.log || return 1
    return 0
}

if [ -n "$POLKITD_PID" ] && kill -0 "$POLKITD_PID" 2>/dev/null; then
    run_test "PreviewDetectFrame serves frames to polkit-authorized caller" \
        "check_preview_frames_authorized"

    # (b4) The grant must not leak: with the rule gone, a fresh caller is
    # stripped again (fail closed).
    run_test "PreviewDetectFrame stripped again after polkit rule removal" \
        "check_preview_detect_frame_stripped"
else
    echo "SKIP: polkitd unavailable — polkit-authorized frame path not exercised"
fi

# Release the preview camera session before the concurrency test
dbus-send --system --print-reply --dest=org.facelock.Daemon /org/facelock/Daemon \
    org.facelock.Daemon.ReleaseCamera > /dev/null 2>&1 || true

# (c) CAMERA-REQUIRED: mutex-DoS guard — race two simultaneous Authenticate
# calls. Exactly one wins the capture slot; the other must be rejected
# immediately with a "busy" error (milliseconds), never queued toward the
# 10s handler-lock timeout.
timed_authenticate() {
    # $1 = output file, $2 = meta file (rc + elapsed_ms), $3 = run as user ("" = root)
    local s e rc
    s=$(date +%s%N)
    if [ -n "$3" ]; then
        runuser -u "$3" -- dbus-send --system --print-reply --reply-timeout=30000 \
            --dest=org.facelock.Daemon /org/facelock/Daemon \
            org.facelock.Daemon.Authenticate string:testuser > "$1" 2>&1
        rc=$?
    else
        dbus-send --system --print-reply --reply-timeout=30000 \
            --dest=org.facelock.Daemon /org/facelock/Daemon \
            org.facelock.Daemon.Authenticate string:testuser > "$1" 2>&1
        rc=$?
    fi
    e=$(date +%s%N)
    echo "$rc $(((e - s) / 1000000))" > "$2"
}

check_concurrent_auth_busy() {
    set +e
    timed_authenticate /tmp/auth-a.out /tmp/auth-a.meta "" &
    local pid_a=$!
    timed_authenticate /tmp/auth-b.out /tmp/auth-b.meta testuser &
    local pid_b=$!
    wait "$pid_a" "$pid_b"
    set -e

    local rc_a ms_a rc_b ms_b
    read -r rc_a ms_a < /tmp/auth-a.meta
    read -r rc_b ms_b < /tmp/auth-b.meta
    echo "call A (root):     rc=$rc_a elapsed=${ms_a}ms"
    echo "call B (testuser): rc=$rc_b elapsed=${ms_b}ms"
    echo "--- A reply:"
    cat /tmp/auth-a.out
    echo "--- B reply:"
    cat /tmp/auth-b.out

    local busy=0 busy_ms=0
    if grep -qi "busy" /tmp/auth-a.out; then
        busy=$((busy + 1))
        busy_ms=$ms_a
    fi
    if grep -qi "busy" /tmp/auth-b.out; then
        busy=$((busy + 1))
        busy_ms=$ms_b
    fi
    [ "$busy" -eq 1 ] || { echo "expected exactly one busy rejection, got $busy"; return 1; }
    # Rejected immediately — well under the 10s handler-lock stall
    [ "$busy_ms" -lt 5000 ] || { echo "busy rejection took ${busy_ms}ms (stall)"; return 1; }
    return 0
}
run_test "Concurrent Authenticate rejected immediately with busy" \
    "check_concurrent_auth_busy"

# The busy guard must not starve legitimate sequential auth: once the
# concurrent capture finished, a new Authenticate must run a full capture
# (match or no-match depending on who is in front of the camera), and must
# NOT be rejected with a busy error.
check_sequential_auth_not_starved() {
    local out rc
    set +e
    out=$(timeout --foreground "$LIVE_TIMEOUT" facelock test --user testuser 2>&1)
    rc=$?
    set -e
    echo "$out"
    if echo "$out" | grep -qi "busy"; then
        echo "sequential auth was rejected as busy (starved by the guard)"
        return 1
    fi
    echo "$out" | grep -qE "Matched model|No match" || return 1
    return 0
}
run_test "Sequential auth not starved after busy rejection" \
    "check_sequential_auth_not_starved"

# Clean up
run_test "Clear enrolled models" \
    "facelock clear --user testuser --yes"

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
