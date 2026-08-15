#!/bin/bash
# State-layout conformance tests (camera-free).
#
# Asserts the exact on-disk contract from docs/contracts.md:
#
#   /var/lib/facelock/       0710 root:facelock    traverse-only, not listable
#     facelock.db            0600 root:root
#     facelock.db-wal/-shm   0600 root:root
#     models/                0755 root:root        public, SHA256-verified
#     enrolled/              0710 root:facelock
#       <user>               0600 <user>:<user>
#   /var/log/facelock/       0700 root:root
#     snapshots/             0700 root:root
#
# The image is built with `just install-files`, so this is the one place the
# packaging wiring (install recipe + built-in defaults) is exercised end to
# end. It also asserts the semantics the modes exist for: a facelock group
# member can traverse to a marker it knows by name but cannot list the state
# directory or read the database, and a user outside the group can reach
# nothing at all.
set -uo pipefail

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

# stat-based assertion: mode owner group, e.g. assert_path /var/lib/facelock 710 root facelock
assert_path() {
    local path="$1" mode="$2" owner="$3" group="$4"
    run_test "$path is $mode $owner:$group" \
        "[ \"\$(stat -c '%a %U %G' $path)\" = '$mode $owner $group' ]" \
        0
}

echo "=== State Layout Tests ==="
echo ""

# ---------------------------------------------------------------------------
# The static layout, as `just install-files` shipped it
# ---------------------------------------------------------------------------

assert_path /var/lib/facelock          710 root facelock
assert_path /var/lib/facelock/models   755 root root
assert_path /var/lib/facelock/enrolled 710 root facelock
assert_path /var/log/facelock          700 root root
assert_path /var/log/facelock/snapshots 700 root root

# ---------------------------------------------------------------------------
# The binary converges a loosened install back onto the layout
# ---------------------------------------------------------------------------

# Simulate a pre-0710 install: group-readable database, wide directories.
install -m 640 -o root -g facelock /dev/null /var/lib/facelock/facelock.db
chmod 755 /var/lib/facelock
chmod 711 /var/lib/facelock/enrolled

# Any root invocation that touches the store applies the layout first; `list`
# is the cheapest one that needs no camera. Its own exit code is irrelevant
# here (the seeded database is empty).
facelock list --user testuser > /dev/null 2>&1 || true

assert_path /var/lib/facelock             710 root facelock
assert_path /var/lib/facelock/enrolled    710 root facelock
assert_path /var/lib/facelock/facelock.db 600 root root

# ---------------------------------------------------------------------------
# Nothing under the state directory is reachable or readable by "other"
# ---------------------------------------------------------------------------

# models/ is the single entry allowed to carry "other" bits (public data
# behind the 0710 parent); everything else must carry none.
run_test "no entry under the state dir is other-accessible (models/ excepted)" \
    "[ -z \"\$(find /var/lib/facelock -mindepth 1 -path /var/lib/facelock/models -prune -o -perm /o+rwx -print)\" ]" \
    0

run_test "the state dir itself grants 'other' nothing" \
    "[ \$(( 0\$(stat -c '%a' /var/lib/facelock) & 07 )) -eq 0 ]" \
    0

# ---------------------------------------------------------------------------
# Group semantics: traverse-only, not listable, database unreadable
# ---------------------------------------------------------------------------

usermod -aG facelock testuser
useradd -m outsider

# A marker for testuser, as enrollment would write it.
install -m 600 -o testuser -g testuser /dev/null /var/lib/facelock/enrolled/testuser
echo '{"models":2,"updated":"2026-08-13T00:00:00Z"}' > /var/lib/facelock/enrolled/testuser

run_test "group member reads own marker through 0710 dirs" \
    "runuser -u testuser -- cat /var/lib/facelock/enrolled/testuser" \
    0

run_test "group member cannot list the state dir" \
    "runuser -u testuser -- ls /var/lib/facelock" \
    2

run_test "group member cannot list enrolled/" \
    "runuser -u testuser -- ls /var/lib/facelock/enrolled" \
    2

run_test "group member cannot read the database" \
    "runuser -u testuser -- cat /var/lib/facelock/facelock.db" \
    1

run_test "group member can read a model file by name" \
    "touch /var/lib/facelock/models/probe.onnx && chmod 644 /var/lib/facelock/models/probe.onnx && runuser -u testuser -- cat /var/lib/facelock/models/probe.onnx && rm /var/lib/facelock/models/probe.onnx" \
    0

run_test "non-member cannot traverse the state dir at all" \
    "runuser -u outsider -- cat /var/lib/facelock/enrolled/testuser" \
    1

run_test "non-member cannot list models/ either" \
    "runuser -u outsider -- ls /var/lib/facelock/models" \
    2

run_test "non-member cannot read the audit log directory" \
    "runuser -u outsider -- ls /var/log/facelock" \
    2

# ---------------------------------------------------------------------------
# is-enrolled answers from the marker, per group membership
# ---------------------------------------------------------------------------

run_test "is-enrolled exits 0 for an enrolled group member" \
    "runuser -u testuser -- facelock is-enrolled" \
    0

run_test "is-enrolled exits 1 for a user outside the group" \
    "runuser -u outsider -- facelock is-enrolled" \
    1

run_test "is-enrolled --json reports the model count" \
    "runuser -u testuser -- facelock is-enrolled --json | grep -q '\"models\":2'" \
    0

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
