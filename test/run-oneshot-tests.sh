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

echo "=== Oneshot Mode Tests (fully daemonless, with camera) ==="
echo ""

# Use installed config, set oneshot mode and writable paths
sed -i 's|db_path.*|db_path = "/tmp/facelock-test.db"|' /etc/facelock/config.toml 2>/dev/null || true
# Force oneshot mode — no daemon for these tests
sed -i '/^\[daemon\]/a mode = "oneshot"' /etc/facelock/config.toml

# Verify no daemon is running
run_test "No daemon socket exists" \
    "test ! -S /tmp/facelock.sock" \
    0

# --- CLI commands in oneshot mode (no daemon) ---

# Device listing
run_test_contains "facelock devices (oneshot)" \
    "facelock devices" \
    "/dev/video" || exit 1

# --- Multi-node IR classification regression gate (BRIO fix) ---
# A force_ir quirk means "this USB device HAS an IR sensor", not "every capture
# node of it is IR". The Logitech BRIO (046d:085e) exposes an RGB node
# (YUYV/MJPG) and an IR node (native GREY) under one VID:PID; previously BOTH
# classified [IR], breaking setup auto-select and making auto-detect capture
# from the RGB sensor. These assertions prove node-level disambiguation.
# CAMERA-REQUIRED: BRIO-conditional; skipped when no BRIO is mounted.
DEVICES_OUT="$(facelock devices)"
if echo "$DEVICES_OUT" | grep -qi "BRIO"; then
    echo "BRIO detected — running multi-node IR classification assertions"

    run_test "exactly one [IR] node for multi-node quirk camera (BRIO)" \
        "test \"\$(facelock devices | grep -c '\[IR\]')\" -eq 1"

    # The single [IR] node must be the GREY-native sensor node.
    run_test "the [IR] node is the GREY-native node" \
        "facelock devices | awk '/\[IR\]/{f=1} f && NF==0{f=0} f' | grep -q 'GREY'"

    IR_NODE="$(echo "$DEVICES_OUT" | awk '/\[IR\]/{print $1}')"
    echo "IR node: $IR_NODE"

    # Auto-detection must select the IR (GREY) node, not the RGB sibling.
    # `facelock auth --user nobody` logs the auto-detected device before it
    # exits (2) on the unknown user — no live face needed. RUST_LOG is set
    # explicitly: the auth subcommand's default filter has never emitted logs
    # (it names the package, facelock_cli, not the bin crate, facelock).
    run_test "auto-detect selects the IR (GREY) node" \
        "RUST_LOG=info facelock auth --user nobody --config /etc/facelock/config.toml 2>&1 | grep 'auto-detected camera' | grep -q -- \"$IR_NODE\""

    # The negotiated capture format on the auto-detected node must be GREY.
    # A timed-out enroll still opens the camera and logs the negotiated format;
    # no live face is needed (exit code intentionally ignored). The log line
    # contains ANSI styling between field names and values, so match the
    # message and the bare format value rather than 'format=GREY'.
    run_test "negotiated capture format is GREY on auto-detected node" \
        "RUST_LOG=info timeout --foreground 10 facelock enroll --user formatprobe --label probe --skip-setup-check > /tmp/format-probe.log 2>&1 || true; grep 'camera format negotiated' /tmp/format-probe.log | grep -q 'GREY'"
    facelock clear --user formatprobe --yes > /dev/null 2>&1 || true
else
    echo "SKIP: no BRIO present — multi-node IR classification assertions skipped"
fi
# --- End multi-node IR regression gate ---

# Enrollment (direct, no daemon)
run_test_contains "facelock enroll (oneshot)" \
    "timeout --foreground $LIVE_TIMEOUT facelock enroll --user testuser --label test-face --skip-setup-check" \
    "Face enrolled successfully" || exit 1

# List enrolled models (direct DB access)
run_test_contains "facelock list (oneshot)" \
    "facelock list --user testuser" \
    "test-face"

# Test auth via CLI (direct)
run_test_contains "facelock test (oneshot)" \
    "timeout --foreground $LIVE_TIMEOUT facelock test --user testuser" \
    "Matched in"

# facelock auth binary (used by PAM module)
run_test "facelock auth authenticates (oneshot)" \
    "timeout --foreground $LIVE_TIMEOUT facelock auth --user testuser --config /etc/facelock/config.toml"

# Anti-spoof (Plan 01, H1 fix): with require_ir = true, a camera that is NOT a
# confirmed IR device MUST be refused (exit 2). To make this deterministic on any
# host — including hosts whose test camera is a genuine IR device with a quirks
# force_ir entry — we temporarily move the system quirks DB aside so the camera is
# classified by the heuristic alone. Under the fixed heuristic, a camera that only
# enumerates GREY/YUYV with no "ir"/"infrared" name token is NOT IR (previously it
# was misclassified as IR by the mere presence of a GREY format), so require_ir
# refuses. Restores the quirks DB afterward.
# CAMERA-REQUIRED: only meaningful on a host with /dev/video*; skipped headless.
QUIRKS_SYS="/usr/share/facelock/quirks.d"
QUIRKS_BAK="/tmp/facelock-quirks.bak"
rm -rf "$QUIRKS_BAK"
[ -d "$QUIRKS_SYS" ] && mv "$QUIRKS_SYS" "$QUIRKS_BAK"
cp /etc/facelock/config.toml /tmp/facelock-requireir.toml
if grep -q '^require_ir' /tmp/facelock-requireir.toml; then
    sed -i 's|^require_ir.*|require_ir = true|' /tmp/facelock-requireir.toml
else
    sed -i '/^\[security\]/a require_ir = true' /tmp/facelock-requireir.toml
fi
run_test "facelock auth refuses non-IR camera when require_ir=true (anti-spoof, H1)" \
    "facelock auth --user testuser --config /tmp/facelock-requireir.toml" \
    2
# Restore the system quirks DB.
[ -d "$QUIRKS_BAK" ] && rm -rf "$QUIRKS_SYS" && mv "$QUIRKS_BAK" "$QUIRKS_SYS"

# PAM authentication (the real deal — no daemon)
run_test "pamtester authenticates (oneshot, no daemon)" \
    "timeout --foreground $LIVE_TIMEOUT pamtester facelock-test testuser authenticate"

# facelock auth rejects unknown user
run_test "facelock auth rejects unknown user" \
    "facelock auth --user nobody --config /etc/facelock/config.toml" \
    2

# Clear models (direct DB access)
run_test "facelock clear (oneshot)" \
    "facelock clear --user testuser --yes"

# Verify models cleared
run_test_contains "facelock list empty after clear (oneshot)" \
    "facelock list --user testuser" \
    "No face models"

# Still no daemon socket
run_test "Still no daemon socket" \
    "test ! -S /tmp/facelock.sock" \
    0

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
