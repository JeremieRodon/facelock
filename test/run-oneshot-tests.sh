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

# Test auth via CLI (direct). The success line is
# "Matched (similarity: X.XX) in Y.YYs" — match the stable prefix.
run_test_contains "facelock test (oneshot)" \
    "timeout --foreground $LIVE_TIMEOUT facelock test --user testuser" \
    "Matched (similarity:"

# --- Device coupling (Plan 02, oneshot/direct path) ---
# The template enrolled above records the live camera's fingerprint in
# face_models.device_id (schema V6). These assertions prove: the migration
# applied, enroll records a device_id, a forged/mismatched id falls through to
# no-match (never a success), and a legacy NULL id still authenticates.
# Resolve the DB path facelock actually uses (config db_path if uncommented,
# else the compiled default). container-config.toml sets no db_path, so this
# yields /var/lib/facelock/facelock.db — the path enroll above wrote to.
db_path_from_config() {
    local p
    p="$(grep -E '^[[:space:]]*db_path[[:space:]]*=' "$1" 2>/dev/null | tail -1 | sed -E 's/^[^=]*=[[:space:]]*"?([^"]*)"?[[:space:]]*$/\1/')"
    [ -n "$p" ] && echo "$p" || echo "/var/lib/facelock/facelock.db"
}
# Force db_path in a config file (uncomment/replace, or append [storage] if absent).
set_db_path() {
    local cfg="$1" path="$2"
    if grep -qE '^[[:space:]]*#?[[:space:]]*db_path' "$cfg"; then
        sed -i -E "s|^[[:space:]]*#?[[:space:]]*db_path.*|db_path = \"$path\"|" "$cfg"
    elif grep -qE '^\[storage\]' "$cfg"; then
        sed -i "/^\[storage\]/a db_path = \"$path\"" "$cfg"
    else
        printf '\n[storage]\ndb_path = "%s"\n' "$path" >> "$cfg"
    fi
}

DB="$(db_path_from_config /etc/facelock/config.toml)"

# --- Encryption at rest (Plan 04, finding #8) ---
# With encryption defaulting to keyfile, the fresh enroll above must have stored
# CIPHERTEXT, not a raw 2048-byte f32 embedding. Assert: sealed flag set, the blob
# starts with the software-encryption version byte 0x02, and its length differs
# from the 2048-byte raw size. Then a full enroll->auth cycle already round-tripped
# above (facelock test / facelock auth), proving the decrypt path works.
# CAMERA-REQUIRED: depends on the live enroll above.
ENC_SEALED="$(sqlite3 "$DB" "SELECT fe.sealed FROM face_embeddings fe JOIN face_models fm ON fe.model_id=fm.id WHERE fm.user='testuser' LIMIT 1" 2>/dev/null || echo '?')"
ENC_LEN="$(sqlite3 "$DB" "SELECT LENGTH(fe.embedding) FROM face_embeddings fe JOIN face_models fm ON fe.model_id=fm.id WHERE fm.user='testuser' LIMIT 1" 2>/dev/null || echo 0)"
ENC_VB="$(sqlite3 "$DB" "SELECT hex(substr(fe.embedding,1,1)) FROM face_embeddings fe JOIN face_models fm ON fe.model_id=fm.id WHERE fm.user='testuser' LIMIT 1" 2>/dev/null || echo '')"
run_test "fresh enroll stores encrypted blob, not raw f32 (sealed=$ENC_SEALED len=$ENC_LEN vb=$ENC_VB)" \
    "[ \"$ENC_SEALED\" = 1 ] && [ \"$ENC_VB\" = '02' ] && [ \"$ENC_LEN\" -ne 2048 ]" 0
# The default key file must exist and be private (0600), created at-mode.
KEYF="/etc/facelock/encryption.key"
KEYMODE="$(stat -c '%a' "$KEYF" 2>/dev/null || echo '?')"
run_test "encryption key auto-generated at 0600 ($KEYF mode=$KEYMODE)" \
    "[ -f \"$KEYF\" ] && [ \"$KEYMODE\" = 600 ]" 0

# Migration applied on first store open (enroll).
SCHEMA_VER="$(sqlite3 "$DB" 'SELECT MAX(version) FROM schema_version' 2>/dev/null || echo 0)"
run_test "V6 schema migration applied (oneshot; db=$DB)" \
    "[ \"$SCHEMA_VER\" -ge 6 ]" 0

# (a) After enroll, the model row carries a device_id. Whether it is NON-NULL
#     depends on the live camera exposing a USB identity via sysfs in-container;
#     report it either way (camera-dependent), and hard-assert non-null when a
#     fingerprint was available.
DEVID="$(sqlite3 "$DB" "SELECT COALESCE(device_id,'') FROM face_models WHERE user='testuser' LIMIT 1" 2>/dev/null || echo '')"
if [ -n "$DEVID" ]; then
    run_test "enrolled template has non-null device_id (oneshot, camera-fingerprinted): '$DEVID'" "true" 0
else
    echo "TEST: enrolled template device_id ... SKIP (live camera exposed no USB identity in-container; coupling degrades to legacy-allow)"
fi

# (b) Swap-in regression gate: a forged, non-matching device_id must fall through
#     to no-match (exit 1), never authenticate. Deterministic regardless of the
#     live camera's real fingerprint.
sqlite3 "$DB" "UPDATE face_models SET device_id='ffff:ffff:forged' WHERE user='testuser'" || true
run_test "facelock auth falls through on forged device_id (coupling; no success)" \
    "timeout --foreground $LIVE_TIMEOUT facelock auth --user testuser --config /etc/facelock/config.toml" \
    1

# (c) Legacy NULL device_id still authenticates (allow-with-warn; no lockout,
#     no data loss) — restores a real match on the same camera.
sqlite3 "$DB" "UPDATE face_models SET device_id=NULL WHERE user='testuser'" || true
run_test "facelock auth succeeds on legacy NULL device_id (allow-with-warn)" \
    "timeout --foreground $LIVE_TIMEOUT facelock auth --user testuser --config /etc/facelock/config.toml" \
    0

# (d) A pre-V6 database migrates cleanly on open: seed schema V5, open it via a
#     store-opening command, then confirm the column was added, the version
#     bumped to >=6, and the legacy row survived with a NULL device_id.
PREV6="/tmp/facelock-prev6.db"
rm -f "$PREV6" "$PREV6-wal" "$PREV6-shm"
sqlite3 "$PREV6" "
CREATE TABLE schema_version (version INTEGER PRIMARY KEY);
CREATE TABLE face_models (id INTEGER PRIMARY KEY AUTOINCREMENT, user TEXT NOT NULL, label TEXT NOT NULL, created_at INTEGER NOT NULL, embedder_model TEXT NOT NULL DEFAULT '', UNIQUE(user,label));
CREATE TABLE face_embeddings (id INTEGER PRIMARY KEY AUTOINCREMENT, model_id INTEGER NOT NULL REFERENCES face_models(id) ON DELETE CASCADE, embedding BLOB NOT NULL, sealed INTEGER NOT NULL DEFAULT 0);
CREATE TABLE rate_limit (user TEXT NOT NULL, attempt_time INTEGER NOT NULL);
INSERT INTO schema_version (version) VALUES (5);
INSERT INTO face_models (user,label,created_at,embedder_model) VALUES ('legacyuser','legacy-face',1700000000,'w600k_r50.onnx');
" || true
cp /etc/facelock/config.toml /tmp/facelock-prev6.toml
set_db_path /tmp/facelock-prev6.toml "$PREV6"
# Opening the store (via any command) runs migrations; auth on a user with no
# embeddings exits non-zero after migrating — we only care about the migration.
timeout --foreground 20s facelock auth --user legacyuser --config /tmp/facelock-prev6.toml >/dev/null 2>&1 || true
PREV6_VER="$(sqlite3 "$PREV6" 'SELECT MAX(version) FROM schema_version' 2>/dev/null || echo 0)"
PREV6_COL="$(sqlite3 "$PREV6" "SELECT COUNT(*) FROM pragma_table_info('face_models') WHERE name='device_id'" 2>/dev/null || echo 0)"
PREV6_ROW="$(sqlite3 "$PREV6" "SELECT label FROM face_models WHERE user='legacyuser'" 2>/dev/null || echo '')"
PREV6_DID="$(sqlite3 "$PREV6" "SELECT COALESCE(device_id,'NULL') FROM face_models WHERE user='legacyuser'" 2>/dev/null || echo '?')"
run_test "pre-V6 DB migrates cleanly, preserves row, device_id NULL (v=$PREV6_VER col=$PREV6_COL row=$PREV6_ROW did=$PREV6_DID)" \
    "[ \"$PREV6_VER\" -ge 6 ] && [ \"$PREV6_COL\" = 1 ] && [ \"$PREV6_ROW\" = legacy-face ] && [ \"$PREV6_DID\" = NULL ]" 0
rm -f "$PREV6" "$PREV6-wal" "$PREV6-shm" /tmp/facelock-prev6.toml

# facelock auth binary (used by PAM module)
run_test "facelock auth authenticates (oneshot)" \
    "timeout --foreground $LIVE_TIMEOUT facelock auth --user testuser --config /etc/facelock/config.toml"

# Anti-spoof (Plan 01, H1 fix): with require_ir = true, a camera that is NOT an IR
# device MUST be refused (exit 2).
#
# The rule being exercised (crates/facelock-camera/src/device.rs): IR-ness is
# DERIVED from the capture formats a node actually enumerates. A node whose format
# set is ENTIRELY mono (GREY/Y8/Y10/Y12/Y16) is a genuine IR sensor node; a node
# that enumerates any colour format (YUYV/MJPG/NV12/...) is NOT IR, even when it
# also offers a mono mode. The free-text device name is never sufficient either
# way (#98) — it is only a tiebreak hint during auto-detection.
#
# The camera under test therefore has to be CHOSEN, not auto-detected. On a host
# whose best camera is a real IR sensor — the Logitech BRIO's /dev/video2
# enumerates GREY and nothing else — auto-detection correctly returns an IR
# device, require_ir correctly admits it and auth correctly succeeds; asserting a
# refusal there fails while the product behaves exactly right. So: pick a node
# that enumerates at least one colour format, pin it via device.path, and skip
# when the host exposes no such node (e.g. only an IR camera is passed through).
#
# The system quirks DB is still moved aside for the duration, so the pinned node
# is classified by its format evidence alone and not by a shipped force_ir entry.
# CAMERA-REQUIRED: only meaningful on a host with /dev/video*; skipped headless.
QUIRKS_SYS="/usr/share/facelock/quirks.d"
QUIRKS_BAK="/tmp/facelock-quirks.bak"
# Restore the system quirks DB. Idempotent: a no-op once the DB is back in place,
# so it is safe to call both inline (happy path) and from the EXIT trap.
restore_quirks() {
    if [ -d "$QUIRKS_BAK" ]; then
        rm -rf "$QUIRKS_SYS"
        mv "$QUIRKS_BAK" "$QUIRKS_SYS"
    fi
}
# Pin device.path in a config copy. Inserted under the [device] header rather than
# sed-replacing `path` lines: `path` is not a unique key name (the [audit] section
# has one too), so a blind substitution would rewrite the wrong line.
pin_device_path() {
    local cfg="$1" node="$2"
    if grep -qE '^\[device\]' "$cfg"; then
        sed -i "/^\[device\]/a path = \"$node\"" "$cfg"
    else
        printf '\n[device]\npath = "%s"\n' "$node" >> "$cfg"
    fi
}
rm -rf "$QUIRKS_BAK"
# Guarantee restoration on ANY exit: under `set -euo pipefail` a failing test below
# aborts the script before the inline restore runs, which would leave the quirks DB
# moved aside and corrupt shared state for later tests in the same CI job.
trap restore_quirks EXIT
[ -d "$QUIRKS_SYS" ] && mv "$QUIRKS_SYS" "$QUIRKS_BAK"
cp /etc/facelock/config.toml /tmp/facelock-requireir.toml
if grep -q '^require_ir' /tmp/facelock-requireir.toml; then
    sed -i 's|^require_ir.*|require_ir = true|' /tmp/facelock-requireir.toml
else
    sed -i '/^\[security\]/a require_ir = true' /tmp/facelock-requireir.toml
fi
# Enumerated with the quirks DB already aside, so `is_ir` here means exactly
# what the auth gate will decide for the same nodes. `--json` is serde-derived
# (facelock_core::ipc::IpcDeviceInfo, see main.rs's `devices` subcommand)
# rather than the human-readable renderer this used to awk-parse: a renderer
# layout change (columns, wording, the `[IR]` tag) can no longer silently
# break this selection the way it could before — see `select_camera_node`
# below for how a genuinely broken selector is told apart from "this host
# has no camera of that kind" (the loud-skip requirement this replaces).
NOQUIRK_DEVICES_JSON="$(facelock devices --json)"

# Parses $NOQUIRK_DEVICES_JSON once to assert it is a non-empty array before
# either selection below decides anything. A malformed/non-array payload
# (from json.load or the isinstance check) exits non-zero, and because this
# runs under `set -euo pipefail` with no `|| true`, that aborts the whole
# script instead of being swallowed into an empty selection — a broken
# producer fails loud. Zero devices is the one legitimate reason both
# selections below skip: nothing was passed through to classify.
DEVICE_COUNT="$(printf '%s' "$NOQUIRK_DEVICES_JSON" | python3 -c '
import json, sys

devices = json.load(sys.stdin)
if not isinstance(devices, list):
    sys.exit(f"selector error: expected a JSON array of devices, got {type(devices).__name__}")
print(len(devices))
')"

# Prints the path of the first device in $NOQUIRK_DEVICES_JSON matching $1
# ("non_ir" or "ir"), or nothing (exit 0) if every device classified fine but
# none matched — the legitimate skip case. jq is not in this test image (see
# test/Containerfile); python3 is (the fake-daemon harness already requires
# it), so it parses the JSON.
#
# A device missing an expected key, or of the wrong type, is a genuine
# selector/schema break — not "no camera" — so it is left to raise
# (KeyError/TypeError) and propagate as a non-zero exit rather than being
# caught and mapped to an empty result. Combined with $DEVICE_COUNT above,
# that is what turns "the awk selects nothing" into "the script fails" for a
# broken selector, per the plan this replaces.
#
# NON_IR selection mirrors the old awk's format-evidence rule (not the is_ir
# field) deliberately: if the classifier ever regressed and marked a colour
# node is_ir=true, this still finds it and the assertion says so instead of
# quietly skipping. IR_NOQUIRK selection uses is_ir directly — the JSON
# equivalent of the old renderer's `[IR]` tag.
read -r -d '' SELECT_CAMERA_NODE_PY <<'PYEOF' || true
import json
import sys

want = sys.argv[1]
devices = json.load(sys.stdin)
if not isinstance(devices, list):
    sys.exit(f"selector error: expected a JSON array of devices, got {type(devices).__name__}")

IR_FOURCCS = {"GREY", "Y8", "Y10", "Y12", "Y16"}

for dev in devices:
    path = dev["path"]
    is_ir = dev["is_ir"]
    fourccs = [fmt["fourcc"].strip() for fmt in dev["formats"]]

    if want == "non_ir" and any(fc not in IR_FOURCCS for fc in fourccs):
        print(path)
        sys.exit(0)
    if want == "ir" and is_ir:
        print(path)
        sys.exit(0)
PYEOF
select_camera_node() {
    python3 -c "$SELECT_CAMERA_NODE_PY" "$1"
}

if [ "$DEVICE_COUNT" -eq 0 ]; then
    echo "TEST: facelock auth refuses non-IR camera when require_ir=true ... SKIP (facelock devices --json enumerated no cameras)"
    echo "TEST: require_ir=true admits a genuine IR node ... SKIP (facelock devices --json enumerated no cameras)"
else
    NON_IR_NODE="$(printf '%s' "$NOQUIRK_DEVICES_JSON" | select_camera_node non_ir)"
    if [ -n "$NON_IR_NODE" ]; then
        cp /tmp/facelock-requireir.toml /tmp/facelock-requireir-nonir.toml
        pin_device_path /tmp/facelock-requireir-nonir.toml "$NON_IR_NODE"
        run_test "facelock auth refuses non-IR camera when require_ir=true (anti-spoof, H1; pinned $NON_IR_NODE)" \
            "facelock auth --user testuser --config /tmp/facelock-requireir-nonir.toml" \
            2
        # Exit 2 is shared by every pre-flight rejection — and by a config parse error,
        # which is what a stale device.path pin in the source config would produce. Pin
        # the rejection to the IR gate itself so neither can read as a pass. Piping
        # into grep makes the test's status grep's, as in the auto-detect assertion above.
        run_test "the refusal above is the IR gate, not another pre-flight rejection" \
            "facelock auth --user testuser --config /tmp/facelock-requireir-nonir.toml 2>&1 | grep -q 'IR camera required but device is not IR'"
    else
        echo "TEST: facelock auth refuses non-IR camera when require_ir=true ... SKIP (no node enumerates a colour format; nothing on this host classifies as non-IR)"
    fi
    # Converse half of the contract: with a genuinely IR node pinned, that same
    # require_ir = true config must NOT refuse. Asserted as "the gate did not fire and
    # the run reached capture" rather than "auth exited 0": a successful match would
    # additionally need a live face in front of THIS node at this instant and a
    # template enrolled from it, neither of which holds on an arbitrary host. The exit
    # code is ignored for the same reason; the probe log is teed so a failure here
    # reports the camera error that caused it instead of an empty output.
    IR_NODE_NOQUIRK="$(printf '%s' "$NOQUIRK_DEVICES_JSON" | select_camera_node ir)"
    if [ -n "$IR_NODE_NOQUIRK" ]; then
        cp /tmp/facelock-requireir.toml /tmp/facelock-requireir-ir.toml
        pin_device_path /tmp/facelock-requireir-ir.toml "$IR_NODE_NOQUIRK"
        run_test "require_ir=true admits a genuine IR node (converse, H1; pinned $IR_NODE_NOQUIRK)" \
            "RUST_LOG=info timeout --foreground 20 facelock auth --user testuser --config /tmp/facelock-requireir-ir.toml 2>&1 | tee /tmp/ir-admit-probe.log || true; ! grep -q 'IR camera required but device is not IR' /tmp/ir-admit-probe.log && grep -q 'camera format negotiated' /tmp/ir-admit-probe.log"
    else
        echo "TEST: require_ir=true admits a genuine IR node ... SKIP (no [IR]-classified node; this host exposes no mono-only sensor)"
    fi
fi
# Restore the system quirks DB inline so the remaining tests see it, then drop the
# trap now that shared state is consistent again.
restore_quirks
trap - EXIT

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
