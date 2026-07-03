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
