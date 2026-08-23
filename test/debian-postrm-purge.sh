#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# CI's documentation container runs as root, while the maintainer script
# deliberately disables its disposable-root override for privileged callers.
# Re-exec the fixture matrix as the checkout owner (or nobody for a root-owned
# checkout) so the production guard remains real.
if [ "$(/usr/bin/id -u)" -eq 0 ] && [ -z "${FACELOCK_PURGE_TEST_REEXEC:-}" ]; then
    test_uid="$(stat -c %u "$repo_root")"
    test_gid="$(stat -c %g "$repo_root")"
    if [ "$test_uid" -eq 0 ]; then
        test_uid="$(/usr/bin/id -u nobody)"
        test_gid="$(/usr/bin/id -g nobody)"
    fi
    exec /usr/bin/setpriv \
        --reuid="$test_uid" \
        --regid="$test_gid" \
        --clear-groups \
        env FACELOCK_PURGE_TEST_REEXEC=1 bash "$0" "$@"
fi

postrm="$repo_root/debian/postrm"
tmp_root="$(mktemp -d)"
failures=0

cleanup() {
    chmod -R u+rwx "$tmp_root" 2>/dev/null || true
    rm -rf -- "$tmp_root"
}
trap cleanup EXIT HUP INT TERM

fail() {
    echo "FAIL: $*" >&2
    failures=$((failures + 1))
}

assert_exists() {
    local path="$1"
    local context="$2"

    if [ ! -e "$path" ] && [ ! -L "$path" ]; then
        fail "$context: expected $path to remain"
    fi
}

assert_absent() {
    local path="$1"
    local context="$2"

    if [ -e "$path" ] || [ -L "$path" ]; then
        fail "$context: expected $path to be removed"
    fi
}

assert_output_contains() {
    local path="$1"
    local expected="$2"
    local context="$3"

    if ! grep -Fq -- "$expected" "$path"; then
        fail "$context: missing output: $expected"
    fi
}

assert_output_not_contains() {
    local path="$1"
    local unexpected="$2"
    local context="$3"

    if grep -Fq -- "$unexpected" "$path"; then
        fail "$context: unexpected output: $unexpected"
    fi
}

new_case() {
    local name="$1"
    local root="$tmp_root/$name"

    install -d -m 0700 "$root"
    printf '%s\n' "$root"
}

make_roots() {
    local root="$1"

    install -d -m 0755 "$root/etc/facelock"
    install -d -m 0711 "$root/var/lib/facelock"
    install -d -m 0700 "$root/var/log/facelock"
}

run_postrm() {
    local root="$1"
    local argument="$2"
    local stdout="$root/stdout"
    local stderr="$root/stderr"
    shift 2

    if ! env \
        FACELOCK_PURGE_TEST_ROOT="$root" \
        FACELOCK_PURGE_TEST_UID="$(id -u)" \
        FACELOCK_PURGE_TEST_GID="$(id -g)" \
        "$@" \
        sh "$postrm" "$argument" >"$stdout" 2>"$stderr"; then
        fail "$argument under $root returned non-zero"
    fi
}

start_paused_postrm() {
    local root="$1"
    local control="$2"

    env \
        FACELOCK_PURGE_TEST_ROOT="$root" \
        FACELOCK_PURGE_TEST_UID="$(id -u)" \
        FACELOCK_PURGE_TEST_GID="$(id -g)" \
        FACELOCK_PURGE_TEST_PAUSE_ROOT=/var/lib/facelock \
        FACELOCK_PURGE_TEST_PAUSE_DIR="$control" \
        sh "$postrm" purge >"$root/stdout" 2>"$root/stderr" &
    paused_postrm_pid=$!
}

start_point_paused_postrm() {
    local root="$1"
    local control="$2"
    local argument="$3"
    local point="$4"
    local logical="$5"

    env \
        FACELOCK_PURGE_TEST_ROOT="$root" \
        FACELOCK_PURGE_TEST_UID="$(id -u)" \
        FACELOCK_PURGE_TEST_GID="$(id -g)" \
        FACELOCK_PURGE_TEST_PAUSE_DIR="$control" \
        FACELOCK_PURGE_TEST_PAUSE_POINT="$point" \
        FACELOCK_PURGE_TEST_PAUSE_LOGICAL="$logical" \
        sh "$postrm" "$argument" >"$root/stdout" 2>"$root/stderr" &
    paused_postrm_pid=$!
}

wait_for_pause() {
    local control="$1"
    local attempt

    for ((attempt = 0; attempt < 500; attempt++)); do
        if [ -e "$control/ready" ]; then
            return 0
        fi
        if ! kill -0 "$paused_postrm_pid" 2>/dev/null; then
            break
        fi
        sleep 0.01
    done
    return 1
}

finish_paused_postrm() {
    local control="$1"

    : >"$control/resume"
    if ! wait "$paused_postrm_pid"; then
        fail "paused purge returned non-zero"
    fi
}

finish_paused_postrm_bounded() {
    local control="$1"
    local unblock_fifo="${2:-}"
    local attempt

    : >"$control/resume"
    for ((attempt = 0; attempt < 100; attempt++)); do
        if ! kill -0 "$paused_postrm_pid" 2>/dev/null; then
            if ! wait "$paused_postrm_pid"; then
                fail "paused purge returned non-zero"
            fi
            return
        fi
        sleep 0.01
    done

    fail "paused lifecycle helper did not finish within one second"
    if [ -n "$unblock_fifo" ]; then
        printf 'unblock\n' >"$unblock_fifo" &
        unblock_writer_pid=$!
    fi
    if ! wait "$paused_postrm_pid"; then
        fail "paused purge returned non-zero after deadlock recovery"
    fi
    if [ -n "${unblock_writer_pid:-}" ]; then
        wait "$unblock_writer_pid" || true
        unset unblock_writer_pid
    fi
}

# A complete safe tree is removed, including the deliberately user-owned
# enrollment-marker leaf. Names outside the three compiled roots are inert.
case_root="$(new_case safe-tree)"
make_roots "$case_root"
install -d -m 0755 "$case_root/var/lib/facelock/models"
install -d -m 0711 "$case_root/var/lib/facelock/enrolled"
install -d -m 0700 "$case_root/var/log/facelock/snapshots"
printf 'db\n' >"$case_root/var/lib/facelock/facelock.db"
printf 'model\n' >"$case_root/var/lib/facelock/models/scrfd.onnx"
printf 'marker\n' >"$case_root/var/lib/facelock/enrolled/alice"
chmod 0600 "$case_root/var/lib/facelock/enrolled/alice"
printf 'key\n' >"$case_root/etc/facelock/encryption.key"
printf 'audit\n' >"$case_root/var/log/facelock/audit.jsonl"
install -d -m 0700 "$case_root/outside"
printf 'sentinel\n' >"$case_root/outside/sentinel"
run_postrm "$case_root" purge
assert_exists "$case_root/etc/facelock" "safe purge root anchor"
assert_exists "$case_root/var/lib/facelock" "safe purge root anchor"
assert_exists "$case_root/var/log/facelock" "safe purge root anchor"
assert_absent "$case_root/etc/facelock/encryption.key" "safe purge key"
assert_absent "$case_root/var/lib/facelock/facelock.db" "safe purge database"
assert_absent "$case_root/var/lib/facelock/enrolled/alice" "safe purge marker"
assert_absent "$case_root/var/log/facelock/audit.jsonl" "safe purge audit"
assert_exists "$case_root/outside/sentinel" "fixed-root confinement"

# Enrollment markers are the sole deliberate ownership exception: the daemon
# chowns each direct marker to its user. fakeroot lets an unprivileged fixture
# present that ownership to the real embedded Perl traversal.
case_root="$(new_case user-owned-marker)"
# The single-quoted script is intentionally expanded by its child bash.
# shellcheck disable=SC2016
if ! command -v fakeroot >/dev/null 2>&1; then
    fail "fakeroot is required to exercise user-owned enrollment markers"
elif ! fakeroot bash -c '
    set -euo pipefail
    root="$1"
    postrm="$2"
    install -d -m 0755 "$root/etc/facelock"
    install -d -m 0711 "$root/var/lib/facelock/enrolled"
    install -d -m 0700 "$root/var/log/facelock"
    printf "marker\n" >"$root/var/lib/facelock/enrolled/alice"
    chmod 0600 "$root/var/lib/facelock/enrolled/alice"
    chown 1234:1234 "$root/var/lib/facelock/enrolled/alice" 2>/dev/null || true
    test "$(stat -c %u:%g "$root/var/lib/facelock/enrolled/alice")" = 1234:1234
    env \
        FACELOCK_PURGE_TEST_ROOT="$root" \
        FACELOCK_PURGE_TEST_UID=0 \
        FACELOCK_PURGE_TEST_GID=0 \
        sh "$postrm" purge >"$root/stdout" 2>"$root/stderr"
    ! test -e "$root/var/lib/facelock/enrolled/alice"
' _ "$case_root" "$postrm"; then
    fail "safe direct user-owned enrollment marker was not removed"
fi

# Wrong ownership on one ordinary descendant is refused without preventing a
# safe sibling from being removed. This complements the traversal-anchor case
# below and exercises the per-entry ownership branch under fakeroot.
case_root="$(new_case wrong-owner-descendant)"
# shellcheck disable=SC2016
if ! command -v fakeroot >/dev/null 2>&1; then
    fail "fakeroot is required to exercise wrong-owner descendants"
elif ! fakeroot bash -c '
    set -euo pipefail
    root="$1"
    postrm="$2"
    install -d -m 0755 "$root/etc/facelock"
    install -d -m 0711 "$root/var/lib/facelock"
    install -d -m 0700 "$root/var/log/facelock"
    printf "keep\n" >"$root/var/lib/facelock/wrong-owner"
    printf "remove\n" >"$root/var/lib/facelock/safe"
    chown 1234:1234 "$root/var/lib/facelock/wrong-owner" 2>/dev/null || true
    test "$(stat -c %u:%g "$root/var/lib/facelock/wrong-owner")" = 1234:1234
    env \
        FACELOCK_PURGE_TEST_ROOT="$root" \
        FACELOCK_PURGE_TEST_UID=0 \
        FACELOCK_PURGE_TEST_GID=0 \
        sh "$postrm" purge >"$root/stdout" 2>"$root/stderr"
    test -e "$root/var/lib/facelock/wrong-owner"
    ! test -e "$root/var/lib/facelock/safe"
' _ "$case_root" "$postrm"; then
    fail "wrong-owner descendant isolation failed"
fi

# Ordinary remove remains preservation-only.
case_root="$(new_case ordinary-remove)"
make_roots "$case_root"
printf 'db\n' >"$case_root/var/lib/facelock/facelock.db"
run_postrm "$case_root" remove
assert_exists "$case_root/var/lib/facelock/facelock.db" "ordinary remove"
assert_output_contains "$case_root/stdout" \
    "Ordinary removal preserves user data" "ordinary remove"
assert_output_contains "$case_root/stdout" \
    "If package purge was requested" "ordinary remove"

# remove sees the conffile before dpkg's purge phase removes it, so it reports
# configured external state without touching either the config or the target.
case_root="$(new_case ordinary-remove-external)"
make_roots "$case_root"
install -d -m 0700 "$case_root/srv/external-models"
printf 'sentinel\n' >"$case_root/srv/external-models/sentinel"
printf '%s\n' '[daemon]' 'model_dir = "/srv/external-models"' \
    >"$case_root/etc/facelock/config.toml"
run_postrm "$case_root" remove
assert_exists "$case_root/etc/facelock/config.toml" "remove conffile preservation"
assert_exists "$case_root/srv/external-models/sentinel" "remove external-path preservation"
assert_output_contains "$case_root/stderr" \
    "daemon.model_dir=/srv/external-models" "remove external report"

# Facelock's TOML parser accepts dotted keys at the document root. The bounded
# maintainer-script classifier must not silently miss the same configured path.
case_root="$(new_case dotted-external-path)"
make_roots "$case_root"
install -d -m 0700 "$case_root/srv/dotted-models"
printf 'sentinel\n' >"$case_root/srv/dotted-models/sentinel"
printf '%s\n' 'daemon.model_dir = "/srv/dotted-models"' \
    >"$case_root/etc/facelock/config.toml"
run_postrm "$case_root" remove
assert_exists "$case_root/srv/dotted-models/sentinel" "dotted external path"
assert_output_contains "$case_root/stderr" \
    "daemon.model_dir=/srv/dotted-models" "dotted external report"

# Dotted keys remain relative to their active table. This is a nested
# notification value, not the root daemon.model_dir field.
case_root="$(new_case scoped-dotted-path)"
make_roots "$case_root"
printf '%s\n' '[notification]' 'daemon.model_dir = "/srv/not-root-daemon"' \
    >"$case_root/etc/facelock/config.toml"
run_postrm "$case_root" remove
assert_output_not_contains "$case_root/stderr" \
    "daemon.model_dir=/srv/not-root-daemon" "table-scoped dotted key"

# Quoted table and key names have the same TOML meaning as their bare forms.
case_root="$(new_case quoted-external-path)"
make_roots "$case_root"
install -d -m 0700 "$case_root/srv/quoted-models"
printf 'sentinel\n' >"$case_root/srv/quoted-models/sentinel"
printf '%s\n' '["daemon"]' '"model_dir" = "/srv/quoted-models"' \
    >"$case_root/etc/facelock/config.toml"
run_postrm "$case_root" remove
assert_exists "$case_root/srv/quoted-models/sentinel" "quoted external path"
assert_output_contains "$case_root/stderr" \
    "daemon.model_dir=/srv/quoted-models" "quoted external report"

# Multiline strings are valid TOML but deliberately outside the bounded value
# decoder. They must produce a controlled classification warning rather than
# silently disappearing from the removal report.
case_root="$(new_case multiline-external-path)"
make_roots "$case_root"
install -d -m 0700 "$case_root/srv/multiline-models"
printf 'sentinel\n' >"$case_root/srv/multiline-models/sentinel"
printf '%s\n' \
    'daemon.model_dir = """' \
    '/srv/multiline-models"""' \
    >"$case_root/etc/facelock/config.toml"
run_postrm "$case_root" remove
assert_exists "$case_root/srv/multiline-models/sentinel" "multiline external path"
assert_output_contains "$case_root/stderr" \
    "configuration could not be fully classified" "multiline classification warning"

# A root symlink and a descendant symlink are both retained without touching
# their outside targets. Safe siblings may still be removed.
case_root="$(new_case symlinks)"
install -d -m 0700 "$case_root/outside-root"
printf 'root sentinel\n' >"$case_root/outside-root/sentinel"
install -d -m 0755 "$case_root/etc"
ln -s "$case_root/outside-root" "$case_root/etc/facelock"
install -d -m 0711 "$case_root/var/lib/facelock"
install -d -m 0700 "$case_root/var/log/facelock"
printf 'outside child\n' >"$case_root/outside-child"
ln -s "$case_root/outside-child" "$case_root/var/lib/facelock/escape"
printf 'safe\n' >"$case_root/var/lib/facelock/safe"
run_postrm "$case_root" purge
assert_exists "$case_root/etc/facelock" "symlink root refusal"
assert_exists "$case_root/outside-root/sentinel" "symlink root target"
assert_exists "$case_root/var/lib/facelock/escape" "symlink descendant refusal"
assert_exists "$case_root/outside-child" "symlink descendant target"
assert_absent "$case_root/var/lib/facelock/safe" "cleanup around symlink"
assert_output_contains "$case_root/stderr" "/etc/facelock" "symlink root report"
assert_output_contains "$case_root/stderr" "/var/lib/facelock/escape" "symlink child report"

# Every fixed ancestor is opened without following links. A symlink at
# /var/lib therefore cannot redirect the compiled state root into another tree.
case_root="$(new_case intermediate-ancestor-symlink)"
install -d -m 0755 "$case_root/etc/facelock"
install -d -m 0755 "$case_root/var"
install -d -m 0700 "$case_root/var/log/facelock"
install -d -m 0711 "$case_root/outside-lib/facelock"
printf 'outside sentinel\n' >"$case_root/outside-lib/facelock/sentinel"
ln -s "$case_root/outside-lib" "$case_root/var/lib"
run_postrm "$case_root" purge
assert_exists "$case_root/var/lib" "intermediate ancestor symlink"
assert_exists "$case_root/outside-lib/facelock/sentinel" \
    "intermediate ancestor symlink target"
assert_output_contains "$case_root/stderr" "/var/lib" \
    "intermediate ancestor symlink report"

# Once the root descriptor is pinned, replacing the public root pathname with
# a symlink cannot redirect child deletion. The pause is available only under
# the unprivileged disposable-root test override.
case_root="$(new_case opened-root-replacement)"
make_roots "$case_root"
printf 'opened root child\n' >"$case_root/var/lib/facelock/opened-child"
install -d -m 0700 "$case_root/outside-root" "$case_root/control"
printf 'outside sentinel\n' >"$case_root/outside-root/sentinel"
start_paused_postrm "$case_root" "$case_root/control"
if wait_for_pause "$case_root/control"; then
    mv "$case_root/var/lib/facelock" "$case_root/var/lib/opened-facelock"
    ln -s "$case_root/outside-root" "$case_root/var/lib/facelock"
    finish_paused_postrm "$case_root/control"
else
    fail "purge did not pause after opening the compiled root"
    wait "$paused_postrm_pid" || true
fi
assert_exists "$case_root/outside-root/sentinel" "opened root replacement target"
assert_exists "$case_root/var/lib/facelock" "opened root replacement link"
assert_exists "$case_root/var/lib/opened-facelock/opened-child" \
    "opened root replacement moved original"

# Replacing a public parent after the root is open is equally inert: all child
# operations remain relative to the retained original parent/root handles.
case_root="$(new_case opened-parent-replacement)"
make_roots "$case_root"
printf 'opened root child\n' >"$case_root/var/lib/facelock/opened-child"
install -d -m 0700 "$case_root/outside-lib/facelock" "$case_root/control"
printf 'outside sentinel\n' >"$case_root/outside-lib/facelock/sentinel"
start_paused_postrm "$case_root" "$case_root/control"
if wait_for_pause "$case_root/control"; then
    mv "$case_root/var/lib" "$case_root/var/lib-opened"
    ln -s "$case_root/outside-lib" "$case_root/var/lib"
    finish_paused_postrm "$case_root/control"
else
    fail "purge did not pause after opening the root below its parent"
    wait "$paused_postrm_pid" || true
fi
assert_exists "$case_root/outside-lib/facelock/sentinel" "opened parent replacement target"
assert_exists "$case_root/var/lib" "opened parent replacement link"
assert_exists "$case_root/var/lib-opened/facelock/opened-child" \
    "opened parent replacement moved original"

# A regular entry replaced after verification must be quarantined and proved
# by identity before deletion. Neither the moved original nor the replacement
# may be deleted by the check-to-operation gap.
case_root="$(new_case regular-pre-quarantine-swap)"
make_roots "$case_root"
install -d -m 0700 "$case_root/control"
printf 'original\n' >"$case_root/var/lib/facelock/victim"
start_point_paused_postrm "$case_root" "$case_root/control" purge \
    before-regular-quarantine /var/lib/facelock/victim
if wait_for_pause "$case_root/control"; then
    mv "$case_root/var/lib/facelock/victim" "$case_root/moved-original"
    printf 'replacement\n' >"$case_root/var/lib/facelock/victim"
    finish_paused_postrm_bounded "$case_root/control"
else
    fail "purge did not pause before regular-entry quarantine"
    wait "$paused_postrm_pid" || true
fi
assert_exists "$case_root/moved-original" "regular swap moved original"
assert_exists "$case_root/var/lib/facelock/victim" "regular swap replacement"

# Selecting an absent quarantine name is not deletion authority. A collision
# created after name selection but before the move must never be overwritten;
# the helper may use a later no-replace candidate for the admitted source.
case_root="$(new_case regular-quarantine-name-collision)"
make_roots "$case_root"
install -d -m 0700 "$case_root/control"
printf 'original\n' >"$case_root/var/lib/facelock/victim"
read -r victim_device victim_inode < <(
    stat -c '%d %i' "$case_root/var/lib/facelock/victim"
)
quarantine_name="$(printf '.facelock-purge-%x-%x-%02x' \
    "$victim_device" "$victim_inode" 0)"
quarantine_path="$case_root/var/lib/facelock/$quarantine_name"
start_point_paused_postrm "$case_root" "$case_root/control" purge \
    before-regular-quarantine-move /var/lib/facelock/victim
if wait_for_pause "$case_root/control"; then
    ln -s "$case_root/outside-collision-target" "$quarantine_path"
    finish_paused_postrm_bounded "$case_root/control"
else
    fail "purge did not pause after selecting a regular quarantine name"
    wait "$paused_postrm_pid" || true
fi
assert_exists "$quarantine_path" "regular quarantine collision"
assert_absent "$case_root/var/lib/facelock/victim" \
    "regular source admitted after collision"
assert_output_contains "$case_root/stderr" \
    "/var/lib/facelock/$quarantine_name (quarantine name collision)" \
    "regular quarantine collision report"

# No replacing-rename fallback is permitted when the exact kernel primitive is
# unavailable. The disposable-only syscall override proves fail-closed state.
case_root="$(new_case renameat2-unavailable)"
make_roots "$case_root"
printf 'retain\n' >"$case_root/var/lib/facelock/victim"
run_postrm "$case_root" purge FACELOCK_PURGE_TEST_RENAMEAT2_SYSCALL=999999
assert_exists "$case_root/var/lib/facelock/victim" \
    "unsupported atomic quarantine primitive"
assert_output_contains "$case_root/stderr" \
    "/var/lib/facelock/victim (cannot quarantine entry atomically:" \
    "unsupported atomic quarantine diagnostic"

# The post-rename identity proof is load-bearing too: replacing the quarantine
# name must preserve both the verified original and the substituted object.
case_root="$(new_case regular-post-quarantine-swap)"
make_roots "$case_root"
install -d -m 0700 "$case_root/control"
printf 'original\n' >"$case_root/var/lib/facelock/victim"
start_point_paused_postrm "$case_root" "$case_root/control" purge \
    after-regular-quarantine /var/lib/facelock/victim
if wait_for_pause "$case_root/control"; then
    quarantine_path="$(find "$case_root/var/lib/facelock" -maxdepth 1 \
        -type f -name '.facelock-purge-*' -print -quit)"
    if [ -z "$quarantine_path" ]; then
        fail "purge paused without a regular-file quarantine"
    else
        mv "$quarantine_path" "$case_root/quarantined-original"
        printf 'replacement\n' >"$quarantine_path"
    fi
    finish_paused_postrm_bounded "$case_root/control"
else
    fail "purge did not pause after regular-entry quarantine"
    wait "$paused_postrm_pid" || true
fi
assert_exists "$case_root/quarantined-original" \
    "post-quarantine swap moved original"
assert_exists "$case_root/var/lib/facelock/victim" \
    "post-quarantine swap replacement"

# Recovery uses the same no-replace primitive. A public name created at the
# restore boundary must preserve both that replacement and the quarantined
# original instead of silently replacing either object.
case_root="$(new_case regular-recovery-name-collision)"
make_roots "$case_root"
install -d -m 0700 "$case_root/control"
printf 'original\n' >"$case_root/var/lib/facelock/victim"
read -r victim_device victim_inode < <(
    stat -c '%d %i' "$case_root/var/lib/facelock/victim"
)
quarantine_name="$(printf '.facelock-purge-%x-%x-%02x' \
    "$victim_device" "$victim_inode" 0)"
quarantine_path="$case_root/var/lib/facelock/$quarantine_name"
start_point_paused_postrm "$case_root" "$case_root/control" purge \
    before-regular-restore-move /var/lib/facelock/victim
if wait_for_pause "$case_root/control"; then
    printf 'public replacement\n' >"$case_root/var/lib/facelock/victim"
    finish_paused_postrm_bounded "$case_root/control"
else
    fail "purge did not pause before regular quarantine recovery"
    wait "$paused_postrm_pid" || true
fi
assert_exists "$case_root/var/lib/facelock/victim" \
    "regular recovery public collision"
assert_exists "$quarantine_path" "regular recovery quarantined original"
assert_output_contains "$case_root/stderr" \
    "/var/lib/facelock/victim (replacement appeared while the verified entry was quarantined)" \
    "regular recovery public collision report"
assert_output_contains "$case_root/stderr" \
    "/var/lib/facelock/$quarantine_name (quarantined entry retained for recovery)" \
    "regular recovery quarantine report"

# The admitted inode stays open through unlink. A hard link introduced at the
# commit boundary cannot be erased through an unknown path, but the remaining
# link must be detected and reported instead of claiming complete deletion.
case_root="$(new_case regular-final-hardlink)"
make_roots "$case_root"
install -d -m 0700 "$case_root/control"
printf 'original\n' >"$case_root/var/lib/facelock/victim"
start_point_paused_postrm "$case_root" "$case_root/control" purge \
    before-regular-delete /var/lib/facelock/victim
if wait_for_pause "$case_root/control"; then
    quarantine_path="$(find "$case_root/var/lib/facelock" -maxdepth 1 \
        -type f -name '.facelock-purge-*' -print -quit)"
    if [ -z "$quarantine_path" ]; then
        fail "purge paused without a final regular quarantine"
    else
        ln "$quarantine_path" "$case_root/outside-hardlink"
    fi
    finish_paused_postrm_bounded "$case_root/control"
else
    fail "purge did not pause before regular quarantine deletion"
    wait "$paused_postrm_pid" || true
fi
assert_exists "$case_root/outside-hardlink" "post-unlink external hard link"
assert_absent "$case_root/var/lib/facelock/victim" \
    "post-unlink public source"
assert_output_contains "$case_root/stderr" \
    "external hard-link remnant retained: /var/lib/facelock/victim (inode remains linked after quarantine unlink)" \
    "post-unlink hard-link report"

# Opening a path that changed from regular to FIFO must be nonblocking. A
# blocked maintainer script would strand dpkg, even though post-open identity
# validation would eventually reject the FIFO.
case_root="$(new_case config-fifo-swap)"
make_roots "$case_root"
install -d -m 0700 "$case_root/control"
printf '%s\n' '[daemon]' 'model_dir = "/srv/original"' \
    >"$case_root/etc/facelock/config.toml"
start_point_paused_postrm "$case_root" "$case_root/control" remove \
    before-config-open /etc/facelock/config.toml
if wait_for_pause "$case_root/control"; then
    mv "$case_root/etc/facelock/config.toml" "$case_root/config-original"
    mkfifo "$case_root/etc/facelock/config.toml"
    finish_paused_postrm_bounded "$case_root/control" \
        "$case_root/etc/facelock/config.toml"
else
    fail "remove did not pause before configuration open"
    wait "$paused_postrm_pid" || true
fi
assert_exists "$case_root/config-original" "configuration FIFO swap original"
assert_exists "$case_root/etc/facelock/config.toml" \
    "configuration FIFO swap replacement"

case_root="$(new_case regular-fifo-swap)"
make_roots "$case_root"
install -d -m 0700 "$case_root/control"
printf 'original\n' >"$case_root/var/lib/facelock/victim"
start_point_paused_postrm "$case_root" "$case_root/control" purge \
    before-regular-open /var/lib/facelock/victim
if wait_for_pause "$case_root/control"; then
    mv "$case_root/var/lib/facelock/victim" "$case_root/regular-original"
    mkfifo "$case_root/var/lib/facelock/victim"
    finish_paused_postrm_bounded "$case_root/control" \
        "$case_root/var/lib/facelock/victim"
else
    fail "purge did not pause before regular-file open"
    wait "$paused_postrm_pid" || true
fi
assert_exists "$case_root/regular-original" "regular FIFO swap original"
assert_exists "$case_root/var/lib/facelock/victim" \
    "regular FIFO swap replacement"

# Empty-directory removal has the same final path race as regular unlinking.
# A replacement installed after validation must survive, and the verified
# original moved outside the compiled root must remain untouched.
case_root="$(new_case directory-pre-quarantine-swap)"
make_roots "$case_root"
install -d -m 0700 "$case_root/control"
install -d -m 0700 "$case_root/var/lib/facelock/empty"
start_point_paused_postrm "$case_root" "$case_root/control" purge \
    before-directory-quarantine /var/lib/facelock/empty
if wait_for_pause "$case_root/control"; then
    mv "$case_root/var/lib/facelock/empty" "$case_root/moved-empty"
    install -d -m 0700 "$case_root/var/lib/facelock/empty"
    finish_paused_postrm_bounded "$case_root/control"
else
    fail "purge did not pause before directory quarantine"
    wait "$paused_postrm_pid" || true
fi
assert_exists "$case_root/moved-empty" "directory swap moved original"
assert_exists "$case_root/var/lib/facelock/empty" "directory swap replacement"

case_root="$(new_case directory-quarantine-name-collision)"
make_roots "$case_root"
install -d -m 0700 "$case_root/control"
install -d -m 0700 "$case_root/var/lib/facelock/empty"
read -r empty_device empty_inode < <(
    stat -c '%d %i' "$case_root/var/lib/facelock/empty"
)
quarantine_name="$(printf '.facelock-purge-%x-%x-%02x' \
    "$empty_device" "$empty_inode" 0)"
quarantine_path="$case_root/var/lib/facelock/$quarantine_name"
start_point_paused_postrm "$case_root" "$case_root/control" purge \
    before-directory-quarantine-move /var/lib/facelock/empty
if wait_for_pause "$case_root/control"; then
    ln -s "$case_root/outside-directory-collision" "$quarantine_path"
    finish_paused_postrm_bounded "$case_root/control"
else
    fail "purge did not pause after selecting a directory quarantine name"
    wait "$paused_postrm_pid" || true
fi
assert_exists "$quarantine_path" "directory quarantine collision"
assert_absent "$case_root/var/lib/facelock/empty" \
    "empty directory admitted after collision"
assert_output_contains "$case_root/stderr" \
    "/var/lib/facelock/$quarantine_name (quarantine name collision)" \
    "directory quarantine collision report"

case_root="$(new_case directory-post-quarantine-swap)"
make_roots "$case_root"
install -d -m 0700 "$case_root/control"
install -d -m 0700 "$case_root/var/lib/facelock/empty"
start_point_paused_postrm "$case_root" "$case_root/control" purge \
    after-directory-quarantine /var/lib/facelock/empty
if wait_for_pause "$case_root/control"; then
    quarantine_path="$(find "$case_root/var/lib/facelock" -maxdepth 1 \
        -type d -name '.facelock-purge-*' -print -quit)"
    if [ -z "$quarantine_path" ]; then
        fail "purge paused without a directory quarantine"
    else
        mv "$quarantine_path" "$case_root/quarantined-empty-original"
        install -d -m 0700 "$quarantine_path"
    fi
    finish_paused_postrm_bounded "$case_root/control"
else
    fail "purge did not pause after directory quarantine"
    wait "$paused_postrm_pid" || true
fi
assert_exists "$case_root/quarantined-empty-original" \
    "post-quarantine directory moved original"
assert_exists "$case_root/var/lib/facelock/empty" \
    "post-quarantine directory replacement"

case_root="$(new_case directory-recovery-name-collision)"
make_roots "$case_root"
install -d -m 0700 "$case_root/control"
install -d -m 0700 "$case_root/var/lib/facelock/empty"
read -r empty_device empty_inode < <(
    stat -c '%d %i' "$case_root/var/lib/facelock/empty"
)
quarantine_name="$(printf '.facelock-purge-%x-%x-%02x' \
    "$empty_device" "$empty_inode" 0)"
quarantine_path="$case_root/var/lib/facelock/$quarantine_name"
start_point_paused_postrm "$case_root" "$case_root/control" purge \
    before-directory-restore-move /var/lib/facelock/empty
if wait_for_pause "$case_root/control"; then
    install -d -m 0700 "$case_root/var/lib/facelock/empty"
    printf 'replacement\n' >"$case_root/var/lib/facelock/empty/sentinel"
    finish_paused_postrm_bounded "$case_root/control"
else
    fail "purge did not pause before directory quarantine recovery"
    wait "$paused_postrm_pid" || true
fi
assert_exists "$case_root/var/lib/facelock/empty/sentinel" \
    "directory recovery public collision"
assert_exists "$quarantine_path" "directory recovery quarantined original"
assert_output_contains "$case_root/stderr" \
    "/var/lib/facelock/empty (replacement appeared while the verified directory was quarantined)" \
    "directory recovery public collision report"
assert_output_contains "$case_root/stderr" \
    "/var/lib/facelock/$quarantine_name (quarantined directory retained for recovery)" \
    "directory recovery quarantine report"

# A directory that gains a child immediately before rmdir is not empty and
# must be restored atomically instead of being stranded at its hidden name.
case_root="$(new_case directory-final-nonempty)"
make_roots "$case_root"
install -d -m 0700 "$case_root/control"
install -d -m 0700 "$case_root/var/lib/facelock/empty"
start_point_paused_postrm "$case_root" "$case_root/control" purge \
    before-directory-delete /var/lib/facelock/empty
if wait_for_pause "$case_root/control"; then
    quarantine_path="$(find "$case_root/var/lib/facelock" -maxdepth 1 \
        -type d -name '.facelock-purge-*' -print -quit)"
    if [ -z "$quarantine_path" ]; then
        fail "purge paused without a final directory quarantine"
    else
        printf 'late child\n' >"$quarantine_path/late-child"
    fi
    finish_paused_postrm_bounded "$case_root/control"
else
    fail "purge did not pause before directory quarantine deletion"
    wait "$paused_postrm_pid" || true
fi
assert_exists "$case_root/var/lib/facelock/empty/late-child" \
    "nonempty quarantine restored directory"
if find "$case_root/var/lib/facelock" -maxdepth 1 \
    -type d -name '.facelock-purge-*' -print -quit | grep -q .; then
    fail "nonempty directory remained stranded under a quarantine name"
fi
assert_output_contains "$case_root/stderr" \
    "/var/lib/facelock/empty (directory changed during quarantine and was restored)" \
    "nonempty directory recovery report"

# PAM rollback/provenance belongs to the earlier binary-backed cleanup. If any
# entry remains by postrm, the self-contained purge must treat the directory as
# opaque evidence rather than interpreting or generically deleting its files.
case_root="$(new_case nonempty-pam-backups)"
make_roots "$case_root"
install -d -m 0700 "$case_root/var/lib/facelock/pam-backups"
printf 'administrator rollback bytes\n' \
    >"$case_root/var/lib/facelock/pam-backups/administrator-note"
printf '{"state":"unknown"}\n' \
    >"$case_root/var/lib/facelock/pam-backups/unresolved.json"
chmod 0600 "$case_root/var/lib/facelock/pam-backups/administrator-note" \
    "$case_root/var/lib/facelock/pam-backups/unresolved.json"
printf 'safe sibling\n' >"$case_root/var/lib/facelock/safe"
run_postrm "$case_root" purge
assert_exists "$case_root/var/lib/facelock/pam-backups/administrator-note" \
    "opaque PAM rollback bytes"
assert_exists "$case_root/var/lib/facelock/pam-backups/unresolved.json" \
    "opaque PAM provenance"
assert_absent "$case_root/var/lib/facelock/safe" \
    "safe sibling around PAM rollback state"
assert_output_contains "$case_root/stderr" \
    "/var/lib/facelock/pam-backups (PAM rollback state remains after removal cleanup)" \
    "opaque PAM rollback report"

# The exact rollback path is itself opaque unless it is a trusted empty
# directory. A hostile or damaged regular-file replacement must not be treated
# as ordinary state merely because its bytes happen to be safely openable.
case_root="$(new_case regular-pam-backups)"
make_roots "$case_root"
printf 'opaque rollback-path replacement\n' \
    >"$case_root/var/lib/facelock/pam-backups"
chmod 0600 "$case_root/var/lib/facelock/pam-backups"
sha256sum "$case_root/var/lib/facelock/pam-backups" \
    >"$case_root/pam-backups.sha256"
pam_backups_metadata="$(
    stat -c '%F|%u|%g|%a|%h|%s' \
        "$case_root/var/lib/facelock/pam-backups"
)"
run_postrm "$case_root" purge
assert_exists "$case_root/var/lib/facelock/pam-backups" \
    "opaque regular PAM rollback path"
if ! sha256sum -c --status "$case_root/pam-backups.sha256"; then
    fail "opaque regular PAM rollback path bytes changed"
fi
if [ "$(stat -c '%F|%u|%g|%a|%h|%s' \
    "$case_root/var/lib/facelock/pam-backups")" != "$pam_backups_metadata" ]; then
    fail "opaque regular PAM rollback path metadata changed"
fi
assert_output_contains "$case_root/stderr" \
    "/var/lib/facelock/pam-backups (PAM rollback state path is not a trusted empty directory)" \
    "opaque regular PAM rollback path report"

case_root="$(new_case empty-pam-backups)"
make_roots "$case_root"
install -d -m 0700 "$case_root/var/lib/facelock/pam-backups"
run_postrm "$case_root" purge
assert_absent "$case_root/var/lib/facelock/pam-backups" \
    "empty PAM rollback directory"

# A multiply-linked regular file is retained and the second name is unchanged.
case_root="$(new_case hardlink)"
make_roots "$case_root"
printf 'shared\n' >"$case_root/outside-hardlink"
ln "$case_root/outside-hardlink" "$case_root/var/lib/facelock/shared"
printf 'safe\n' >"$case_root/var/lib/facelock/safe"
run_postrm "$case_root" purge
assert_exists "$case_root/var/lib/facelock/shared" "hard-link refusal"
assert_exists "$case_root/outside-hardlink" "hard-link outside name"
assert_absent "$case_root/var/lib/facelock/safe" "cleanup around hard link"
assert_output_contains "$case_root/stderr" "/var/lib/facelock/shared" "hard-link report"

# Ownership is proven relative to the production root owner. The test override
# makes an otherwise ordinary fixture model a wrong-owner root.
case_root="$(new_case wrong-owner)"
make_roots "$case_root"
printf 'keep\n' >"$case_root/var/lib/facelock/keep"
run_postrm "$case_root" purge FACELOCK_PURGE_TEST_UID=424242 FACELOCK_PURGE_TEST_GID=424242
assert_exists "$case_root/var/lib/facelock/keep" "wrong-owner root refusal"
assert_output_contains "$case_root/stderr" "/var/lib/facelock" "wrong-owner report"

# Mount points are rejected even when a bind mount would share st_dev with its
# parent. A synthetic mountinfo file exercises the same parser without a host
# mount or namespace mutation.
case_root="$(new_case mountpoint)"
make_roots "$case_root"
install -d -m 0700 "$case_root/var/lib/facelock/mounted"
printf 'mounted\n' >"$case_root/var/lib/facelock/mounted/keep"
printf 'safe\n' >"$case_root/var/lib/facelock/safe"
printf '31 24 0:25 / %s rw,relatime - tmpfs tmpfs rw\n' \
    "$case_root/var/lib/facelock/mounted" >"$case_root/mountinfo"
run_postrm "$case_root" purge FACELOCK_PURGE_TEST_MOUNTINFO="$case_root/mountinfo"
assert_exists "$case_root/var/lib/facelock/mounted/keep" "mount-point refusal"
assert_absent "$case_root/var/lib/facelock/safe" "cleanup around mount point"
assert_output_contains "$case_root/stderr" "/var/lib/facelock/mounted" "mount-point report"

# mountinfo's path field uses octal escapes. Decode them before comparison so
# a same-device bind mounted on a name with whitespace cannot evade the gate.
case_root="$(new_case mountpoint-escaped)"
make_roots "$case_root"
mount_path="$case_root/var/lib/facelock/mounted space"
install -d -m 0700 "$mount_path"
printf 'mounted\n' >"$mount_path/keep"
escaped_mount="${mount_path// /\\040}"
printf '31 24 0:25 / %s rw,relatime - tmpfs tmpfs rw\n' \
    "$escaped_mount" >"$case_root/mountinfo"
run_postrm "$case_root" purge FACELOCK_PURGE_TEST_MOUNTINFO="$case_root/mountinfo"
assert_exists "$mount_path/keep" "escaped mount-point refusal"
assert_output_contains "$case_root/stderr" "/var/lib/facelock/mounted space" \
    "escaped mount-point report"

# If mount topology cannot be proven, the helper conservatively reports every
# compiled root without probing public paths, preserves all state, and still
# lets the package-manager lifecycle finish.
case_root="$(new_case missing-mountinfo)"
make_roots "$case_root"
printf 'keep\n' >"$case_root/var/lib/facelock/keep"
run_postrm "$case_root" purge \
    FACELOCK_PURGE_TEST_MOUNTINFO="$case_root/does-not-exist"
assert_exists "$case_root/var/lib/facelock/keep" "missing mountinfo refusal"
assert_output_contains "$case_root/stderr" "mount topology is unavailable" \
    "missing mountinfo report"

# An unlink failure is reported, other roots are still attempted, and purge
# remains successful so dpkg is not stranded in a half-purged state.
case_root="$(new_case partial-failure)"
make_roots "$case_root"
install -d -m 0700 "$case_root/var/lib/facelock/readonly"
printf 'blocked\n' >"$case_root/var/lib/facelock/readonly/blocked"
chmod 0555 "$case_root/var/lib/facelock/readonly"
printf 'safe\n' >"$case_root/etc/facelock/safe"
run_postrm "$case_root" purge
assert_exists "$case_root/var/lib/facelock/readonly/blocked" "partial failure remnant"
assert_absent "$case_root/etc/facelock/safe" "partial failure isolation"
assert_output_contains "$case_root/stderr" "/var/lib/facelock/readonly/blocked" "partial failure report"

# Unsafe directories and non-regular leaves are retained independently while
# safe siblings continue to be removed.
case_root="$(new_case unsafe-node-types)"
make_roots "$case_root"
install -d -m 0775 "$case_root/var/lib/facelock/group-writable"
printf 'keep\n' >"$case_root/var/lib/facelock/group-writable/keep"
mkfifo "$case_root/var/lib/facelock/pipe"
printf 'safe\n' >"$case_root/var/lib/facelock/safe"
run_postrm "$case_root" purge
assert_exists "$case_root/var/lib/facelock/group-writable/keep" \
    "unsafe directory mode refusal"
assert_exists "$case_root/var/lib/facelock/pipe" "special-file refusal"
assert_absent "$case_root/var/lib/facelock/safe" "cleanup around unsafe node types"
assert_output_contains "$case_root/stderr" "/var/lib/facelock/group-writable" \
    "unsafe directory mode report"
assert_output_contains "$case_root/stderr" "/var/lib/facelock/pipe" \
    "special-file report"

# Traversal limits are inclusive. A directory exactly at the configured test
# depth remains eligible, while the next directory is retained and reported.
case_root="$(new_case depth-limit-boundary)"
make_roots "$case_root"
install -d -m 0700 "$case_root/var/lib/facelock/one/two"
printf 'at boundary\n' >"$case_root/var/lib/facelock/one/two/leaf"
run_postrm "$case_root" purge FACELOCK_PURGE_TEST_MAX_DEPTH=2
assert_absent "$case_root/var/lib/facelock/one/two/leaf" \
    "inclusive traversal depth boundary"

case_root="$(new_case depth-limit-refusal)"
make_roots "$case_root"
install -d -m 0700 "$case_root/var/lib/facelock/one/two/three"
printf 'beyond boundary\n' >"$case_root/var/lib/facelock/one/two/three/keep"
run_postrm "$case_root" purge FACELOCK_PURGE_TEST_MAX_DEPTH=2
assert_exists "$case_root/var/lib/facelock/one/two/three/keep" \
    "traversal depth refusal"
assert_output_contains "$case_root/stderr" "depth limit exceeded (2)" \
    "traversal depth report"

# The node ceiling is likewise inclusive and stops an oversized traversal
# without unbounded enumeration or Perl recursion diagnostics.
case_root="$(new_case node-limit-boundary)"
make_roots "$case_root"
printf 'one\n' >"$case_root/var/lib/facelock/one"
printf 'two\n' >"$case_root/var/lib/facelock/two"
run_postrm "$case_root" purge FACELOCK_PURGE_TEST_MAX_NODES=2
assert_absent "$case_root/var/lib/facelock/one" "inclusive traversal node boundary"
assert_absent "$case_root/var/lib/facelock/two" "inclusive traversal node boundary"

case_root="$(new_case node-limit-refusal)"
make_roots "$case_root"
printf 'one\n' >"$case_root/var/lib/facelock/one"
printf 'two\n' >"$case_root/var/lib/facelock/two"
printf 'three\n' >"$case_root/var/lib/facelock/three"
run_postrm "$case_root" purge FACELOCK_PURGE_TEST_MAX_NODES=2
if [ -d "$case_root/var/lib/facelock" ]; then
    remaining_nodes="$(find "$case_root/var/lib/facelock" -mindepth 1 -maxdepth 1 | wc -l)"
else
    remaining_nodes=0
fi
if [ "$remaining_nodes" -ne 1 ]; then
    fail "node limit refusal: expected exactly one retained child, found $remaining_nodes"
fi
assert_output_contains "$case_root/stderr" "node limit exceeded (2)" \
    "traversal node report"
assert_output_contains "$case_root/stderr" \
    "facelock purge: remnant retained: /var/lib/facelock (node limit exceeded (2))" \
    "traversal retained-root report"
if grep -Fq -- "Deep recursion" "$case_root/stderr"; then
    fail "bounded traversal emitted a raw Perl recursion warning"
fi

# A compiled root that is not a directory is itself an exact reported remnant.
case_root="$(new_case non-directory-root)"
install -d -m 0755 "$case_root/etc"
printf 'keep\n' >"$case_root/etc/facelock"
install -d -m 0711 "$case_root/var/lib/facelock"
install -d -m 0700 "$case_root/var/log/facelock"
run_postrm "$case_root" purge
assert_exists "$case_root/etc/facelock" "non-directory root refusal"
assert_output_contains "$case_root/stderr" "/etc/facelock" \
    "non-directory root report"

# Only the six configured path fields are classified. External values are
# named and left untouched; values lexically inside compiled roots are eligible
# for the bounded traversal and are not described as external.
case_root="$(new_case external-paths)"
make_roots "$case_root"
install -d -m 0700 "$case_root/srv/facelock/models"
printf 'external sentinel\n' >"$case_root/srv/facelock/models/sentinel"
printf 'external db\n' >"$case_root/var/lib/external.db"
printf '%s\n' \
    '[daemon]' \
    'model_dir = "/srv/facelock/models"' \
    '[storage]' \
    'db_path = "/var/lib/facelock/../external.db"' \
    '[encryption]' \
    'key_path = "/keys/facelock.key"' \
    'sealed_key_path = "/keys/facelock.sealed"' \
    '[audit]' \
    'path = "/logs/facelock.jsonl"' \
    '[snapshots]' \
    'dir = "/snapshots/facelock"' \
    >"$case_root/etc/facelock/config.toml"
run_postrm "$case_root" purge
assert_exists "$case_root/srv/facelock/models/sentinel" "external configured path"
assert_exists "$case_root/var/lib/external.db" "lexically external database path"
assert_output_contains "$case_root/stderr" "daemon.model_dir=/srv/facelock/models" "external model report"
assert_output_contains "$case_root/stderr" \
    "storage.db_path=/var/lib/facelock/../external.db" "lexical external report"
assert_output_contains "$case_root/stderr" "encryption.key_path=/keys/facelock.key" "external key report"
assert_output_contains "$case_root/stderr" "encryption.sealed_key_path=/keys/facelock.sealed" "external sealed-key report"
assert_output_contains "$case_root/stderr" "audit.path=/logs/facelock.jsonl" "external audit report"
assert_output_contains "$case_root/stderr" "snapshots.dir=/snapshots/facelock" "external snapshot report"

case_root="$(new_case configured-inside-root)"
make_roots "$case_root"
printf '%s\n' '[storage]' 'db_path = "/var/lib/facelock/facelock.db"' \
    >"$case_root/etc/facelock/config.toml"
run_postrm "$case_root" purge
if grep -Fq -- "storage.db_path=/var/lib/facelock/facelock.db" "$case_root/stderr"; then
    fail "inside configured database path was reported as external"
fi

# Basic-string escapes are decoded for classification but control characters
# are escaped again before diagnostics reach a terminal or package-manager log.
case_root="$(new_case external-control-path)"
make_roots "$case_root"
printf '%s\n' '[daemon]' 'model_dir = "/srv/line\nbreak"' \
    >"$case_root/etc/facelock/config.toml"
run_postrm "$case_root" purge
assert_output_contains "$case_root/stderr" \
    'daemon.model_dir=/srv/line\x0abreak' "external control-path report"

# A multiply-linked conffile is not trusted for parsing or deletion. Its other
# name and all bytes remain available as provenance for manual inspection.
case_root="$(new_case hardlinked-config)"
make_roots "$case_root"
printf '%s\n' '[daemon]' 'model_dir = "/srv/external"' \
    >"$case_root/etc/facelock/config.toml"
ln "$case_root/etc/facelock/config.toml" "$case_root/config-second-name"
run_postrm "$case_root" purge
assert_exists "$case_root/etc/facelock/config.toml" "hard-linked config refusal"
assert_exists "$case_root/config-second-name" "hard-linked config provenance"
assert_output_contains "$case_root/stderr" "/etc/facelock/config.toml" \
    "hard-linked config report"

# A configuration object that classification explicitly reports as retained
# must not be removed by the generic fixed-root walk later in the same purge.
case_root="$(new_case oversized-config)"
make_roots "$case_root"
truncate -s 1048577 "$case_root/etc/facelock/config.toml"
run_postrm "$case_root" purge
assert_exists "$case_root/etc/facelock/config.toml" "oversized config retention"
assert_output_contains "$case_root/stderr" "/etc/facelock/config.toml" \
    "oversized config report"

case_root="$(new_case directory-config)"
make_roots "$case_root"
install -d -m 0700 "$case_root/etc/facelock/config.toml"
printf 'directory sentinel\n' >"$case_root/etc/facelock/config.toml/sentinel"
run_postrm "$case_root" purge
assert_exists "$case_root/etc/facelock/config.toml/sentinel" \
    "directory config retention"
assert_output_contains "$case_root/stderr" "/etc/facelock/config.toml" \
    "directory config report"

# /etc/pam.d is outside the recursive roots. An incomplete service edit and its
# rollback provenance survive purge byte-for-byte.
case_root="$(new_case pam-provenance)"
make_roots "$case_root"
install -d -m 0755 "$case_root/etc/pam.d"
printf 'auth sufficient pam_facelock.so\nauth required pam_unix.so\n' \
    >"$case_root/etc/pam.d/sudo"
printf 'auth required pam_unix.so\n' >"$case_root/etc/pam.d/sudo.facelock-backup"
sha256sum "$case_root/etc/pam.d/sudo" "$case_root/etc/pam.d/sudo.facelock-backup" \
    >"$case_root/pam.sha256"
run_postrm "$case_root" purge
if ! sha256sum -c --status "$case_root/pam.sha256"; then
    fail "purge changed incomplete PAM integration or provenance"
fi

# Missing roots and a repeated purge are both successful no-ops.
case_root="$(new_case idempotent)"
run_postrm "$case_root" purge
run_postrm "$case_root" purge

# The canonical native source must ship this exact self-contained maintainer
# script. test/deb-maintscript-contract.sh separately proves that debhelper
# expands it into the binary package control archive.
[ -x "$postrm" ] || fail "native Debian postrm is not executable"
[ "$(grep -Foc '#DEBHELPER#' "$postrm")" -eq 1 ] ||
    fail "native Debian postrm must contain exactly one debhelper marker"
if grep -Eq '^Depends:.*perl-base' "$repo_root/debian/control"; then
    fail "package metadata redundantly depends on the Essential perl-base package"
fi
# shellcheck disable=SC2016
if ! grep -Fq '$opened[0] != $root->{dev}' "$postrm"; then
    fail "purge helper omits the independent root-device comparison"
fi
# shellcheck disable=SC2016
if ! grep -Fq 'facelock_renameat2_syscall=316' "$postrm" ||
    ! grep -Fq 'syscall($renameat2_syscall, $parent_fd' "$postrm"; then
    fail "purge helper omits the audited amd64 renameat2 syscall"
fi
if grep -Eq '(^|[^[:alnum:]_])rename[[:space:]]*\(' "$postrm"; then
    fail "purge helper contains a replacing Perl rename call"
fi
if ! grep -Eq '^Architecture:[[:space:]]*amd64[[:space:]]*$' \
    "$repo_root/debian/control"; then
    fail "raw renameat2 syscall is not bound to amd64 package metadata"
fi

if [ "$failures" -ne 0 ]; then
    echo "debian postrm purge: $failures failure(s)" >&2
    exit 1
fi

echo "debian postrm purge: OK"
