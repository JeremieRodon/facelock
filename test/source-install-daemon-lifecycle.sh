#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
justfile="$repo_root/justfile"
lifecycle_script="$repo_root/scripts/source-install-daemon-lifecycle.sh"
lifecycle_checker="$repo_root/test/check-source-install-lifecycle.py"
containerfile="$repo_root/test/Containerfile"

fail() {
    echo "source-install daemon lifecycle: $*" >&2
    exit 1
}

assert_lock_available() {
    local name="$1"
    local lock_path="$2"
    local lock_dir="${lock_path%/*}"

    flock -n "$lock_path" true || fail "$name left the source-install lifecycle lock held"
    [ -d "$lock_dir" ] && [ ! -L "$lock_dir" ] ||
        fail "$name left an unsafe lifecycle lock directory"
    [ "$(stat -c '%a' "$lock_dir")" = 755 ] ||
        fail "$name left a wrongly permissioned lifecycle lock directory"
    [ "$(stat -c '%u:%g' "$lock_dir")" = \
        "$(stat -c '%u:%g' "${lock_path%/run/*}")" ] ||
        fail "$name left a wrongly owned lifecycle lock directory"
    [ "$(stat -c '%a' "$lock_path")" = 600 ] ||
        fail "$name left a non-private source-install lifecycle lock"
    [ "$(stat -c '%h' "$lock_path")" = 1 ] ||
        fail "$name left a multiply-linked source-install lifecycle lock"
    [ "$(stat -c '%u:%g' "$lock_path")" = \
        "$(stat -c '%u:%g' "${lock_path%/run/*}")" ] ||
        fail "$name left a wrongly owned source-install lifecycle lock"
}

legacy_lock_literal='facelock-source-install'".lock"
! grep -Fq "$legacy_lock_literal" "$lifecycle_script" ||
    fail "lifecycle helper retains the retired source-only lock literal"
python3 - "$lifecycle_script" <<'PY'
import pathlib
import sys

text = pathlib.Path(sys.argv[1]).read_text()
start = text.index("facelock_source_install_restore_daemon() {")
end = text.index("facelock_source_install_finish_daemon() {", start)
restore = text[start:end]
commit = restore.index("facelock_source_install_commit_legacy_migration")
barrier_removal = restore.index("facelock_source_install_quarantine_owned_barrier")
restart = restore.index("facelock_source_install_restart_active_daemon")
if not commit < barrier_removal < restart:
    raise SystemExit(
        "legacy publication must precede barrier removal and daemon restart"
    )
rollback = restore.index("facelock_source_install_rollback_legacy_migration", commit)
reload_after_rollback = restore.index("systemctl daemon-reload", rollback)
dbus_after_rollback = restore.index(
    "facelock_source_install_reload_dbus_activation", reload_after_rollback
)
if not rollback < reload_after_rollback < dbus_after_rollback:
    raise SystemExit("rollback must be followed by manager and D-Bus revalidation")
if 'local publication_allowed="${2:-false}"' not in restore:
    raise SystemExit("daemon restoration lacks an explicit publication authorization")
stage_start = text.index(
    "facelock_source_install_stage_and_record_legacy_migration() {"
)
stage_end = text.index("\n}\n", stage_start)
stage = text[stage_start:stage_end]
critical_on = stage.index("FACELOCK_SOURCE_INSTALL_CRITICAL=true")
invoke = stage.index("facelock_source_install_invoke_legacy_stage")
record = stage.index("facelock_source_install_record_legacy_migration", invoke)
critical_off = stage.index("FACELOCK_SOURCE_INSTALL_CRITICAL=false", record)
if not critical_on < invoke < record < critical_off:
    raise SystemExit("legacy stage and exact record must share one signal-critical interval")
PY

[ -f "$lifecycle_script" ] ||
    fail "missing scripts/source-install-daemon-lifecycle.sh"
[ -f "$lifecycle_checker" ] ||
    fail "missing test/check-source-install-lifecycle.py"

python3 "$lifecycle_checker" "$justfile" "$containerfile"
python3 "$repo_root/test/check-source-install-lifecycle-test.py"

default_assets_actual="$(
    # The path is resolved from this script.
    # shellcheck disable=SC1090,SC1091
    source "$lifecycle_script"
    facelock_source_install_default_assets
)"
default_assets_expected="$(printf '%s\n' \
    /etc/systemd/system.control/facelock-daemon.service \
    /run/systemd/system.control/facelock-daemon.service \
    /run/systemd/transient/facelock-daemon.service \
    /run/systemd/generator.early/facelock-daemon.service \
    /etc/systemd/system/facelock-daemon.service \
    /etc/systemd/system.attached/facelock-daemon.service \
    /run/systemd/system/facelock-daemon.service \
    /run/systemd/system.attached/facelock-daemon.service \
    /run/systemd/generator/facelock-daemon.service \
    /usr/local/lib/systemd/system/facelock-daemon.service \
    /usr/lib/systemd/system/facelock-daemon.service \
    /lib/systemd/system/facelock-daemon.service \
    /run/systemd/generator.late/facelock-daemon.service \
    /etc/dbus-1/system-services/org.facelock.Daemon.service \
    /run/dbus-1/system-services/org.facelock.Daemon.service \
    /usr/local/share/dbus-1/system-services/org.facelock.Daemon.service \
    /usr/share/dbus-1/system-services/org.facelock.Daemon.service \
    /lib/dbus-1/system-services/org.facelock.Daemon.service)"
[ "$default_assets_actual" = "$default_assets_expected" ] ||
    fail "default activation-asset search paths are incomplete or reordered"

tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/facelock-source-install-daemon.XXXXXX")"
trap 'rm -rf -- "$tmp_root"' EXIT
mkdir -p "$tmp_root/bin" "$tmp_root/run/systemd/system" \
    "$tmp_root/run/systemd/system.control"

mkdir -p "$tmp_root/locale-bin" "$tmp_root/locale-trusted-directory"
cat >"$tmp_root/locale-bin/stat" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

[ "${LC_ALL:-}" = C ] || exit 97
exec "$FACELOCK_REAL_STAT" "$@"
SH
chmod 755 "$tmp_root/locale-bin/stat"
FACELOCK_REAL_STAT="$(command -v stat)" \
    PATH="$tmp_root/locale-bin:$PATH" \
    bash -c '
        set -euo pipefail
        source "$1"
        FACELOCK_SOURCE_INSTALL_TRUST_UID="$("$FACELOCK_REAL_STAT" -c %u -- "$2")"
        FACELOCK_SOURCE_INSTALL_TRUST_GID="$("$FACELOCK_REAL_STAT" -c %g -- "$2")"
        facelock_source_install_directory_is_trusted "$2"
    ' _ "$lifecycle_script" "$tmp_root/locale-trusted-directory" ||
    fail "lifecycle metadata checks depend on the caller locale"

assert_recipe_mutation_rejected() {
    local name="$1"
    local needle="$2"
    local replacement="$3"
    local mutated="$tmp_root/$name.justfile"
    local output="$tmp_root/$name.output"

    python3 - "$justfile" "$mutated" "$needle" "$replacement" <<'PY'
import pathlib
import sys

source, destination, needle, replacement = sys.argv[1:]
text = pathlib.Path(source).read_text()
if text.count(needle) != 1:
    raise SystemExit(f"mutation needle count is {text.count(needle)}, expected 1: {needle!r}")
pathlib.Path(destination).write_text(text.replace(needle, replacement, 1))
PY

    if python3 "$lifecycle_checker" "$mutated" "$containerfile" >"$output" 2>&1; then
        fail "structural checker accepted $name mutation"
    fi
    echo "source-install lifecycle mutation rejected: $name"
}

assert_recipe_mutation_rejected before_boundary \
    '    facelock_source_install_begin' \
    $'    touch /tmp/facelock-before-boundary\n    facelock_source_install_begin'
assert_recipe_mutation_rejected after_boundary \
    '    facelock_source_install_complete' \
    $'    facelock_source_install_complete\n    touch /tmp/facelock-after-boundary'
assert_recipe_mutation_rejected prefixed_systemctl \
    '    # Binaries' \
    $'    command systemctl enable facelock-daemon.service\n\n    # Binaries'
assert_recipe_mutation_rejected absolute_systemctl \
    '    # Binaries' \
    $'    /usr/bin/systemctl enable facelock-daemon.service\n\n    # Binaries'
assert_recipe_mutation_rejected assigned_systemctl \
    '    # Binaries' \
    $'    manager=systemctl\n    "$manager" enable facelock-daemon.service\n\n    # Binaries'
assert_recipe_mutation_rejected interpreter_before_boundary \
    '    source scripts/source-install-daemon-lifecycle.sh' \
    $'    python3 -c "open(\047/tmp/unsafe\047, \047w\047)"\n    source scripts/source-install-daemon-lifecycle.sh'
assert_recipe_mutation_rejected sed_before_boundary \
    '    source scripts/source-install-daemon-lifecycle.sh' \
    $'    sed -i s/old/new/ /tmp/unsafe\n    source scripts/source-install-daemon-lifecycle.sh'
assert_recipe_mutation_rejected redirection_before_boundary \
    '    source scripts/source-install-daemon-lifecycle.sh' \
    $'    echo unsafe >/tmp/facelock-before-boundary\n    source scripts/source-install-daemon-lifecycle.sh'
assert_recipe_mutation_rejected commented_activation \
    '    install -Dm644 dbus/org.facelock.Daemon.service /usr/share/dbus-1/system-services/org.facelock.Daemon.service' \
    '    # install -Dm644 dbus/org.facelock.Daemon.service /usr/share/dbus-1/system-services/org.facelock.Daemon.service'
assert_recipe_mutation_rejected extra_cp_writer \
    '    # Binaries' \
    $'    cp /tmp/unsafe /usr/bin/facelock\n\n    # Binaries'
assert_recipe_mutation_rejected extra_install_writer \
    '    # Binaries' \
    $'    install -Dm755 /tmp/unsafe /usr/bin/facelock\n\n    # Binaries'
assert_recipe_mutation_rejected extra_rsync_writer \
    '    # Binaries' \
    $'    rsync /tmp/unsafe /usr/bin/facelock\n\n    # Binaries'
assert_recipe_mutation_rejected relative_privileged_sudo \
    '    /usr/bin/sudo /usr/bin/env PATH=/usr/bin:/bin /usr/bin/just install-files' \
    '    sudo /usr/bin/env PATH=/usr/bin:/bin /usr/bin/just install-files'
assert_recipe_mutation_rejected relative_privileged_env \
    '    /usr/bin/sudo /usr/bin/env PATH=/usr/bin:/bin /usr/bin/just uninstall-files' \
    '    /usr/bin/sudo env PATH=/usr/bin:/bin /usr/bin/just uninstall-files'

assert_container_mutation_rejected() {
    local name="$1"
    local needle="$2"
    local replacement="$3"
    local mutated="$tmp_root/$name.Containerfile"
    local output="$tmp_root/$name.output"

    python3 - "$containerfile" "$mutated" "$needle" "$replacement" <<'PY'
import pathlib
import sys

source, destination, needle, replacement = sys.argv[1:]
text = pathlib.Path(source).read_text()
if text.count(needle) != 1:
    raise SystemExit(f"mutation needle count is {text.count(needle)}, expected 1: {needle!r}")
pathlib.Path(destination).write_text(text.replace(needle, replacement, 1))
PY

    if python3 "$lifecycle_checker" "$justfile" "$mutated" >"$output" 2>&1; then
        fail "structural checker accepted $name mutation"
    fi
    echo "source-install lifecycle mutation rejected: $name"
}

assert_container_mutation_rejected commented_container_helper \
    'COPY scripts/source-install-daemon-lifecycle.sh /build/scripts/source-install-daemon-lifecycle.sh' \
    '# COPY scripts/source-install-daemon-lifecycle.sh /build/scripts/source-install-daemon-lifecycle.sh'
assert_container_mutation_rejected commented_container_migration_helper \
    'COPY scripts/migrate-legacy-system-assets.sh /build/scripts/migrate-legacy-system-assets.sh' \
    '# COPY scripts/migrate-legacy-system-assets.sh /build/scripts/migrate-legacy-system-assets.sh'
assert_container_mutation_rejected commented_container_legacy_manifest \
    'COPY dist/ /build/dist/' \
    '# COPY dist/ /build/dist/'
assert_container_mutation_rejected commented_container_marker \
    'COPY test/source-install-offline-image.marker /build/test/source-install-offline-image.marker' \
    '# COPY test/source-install-offline-image.marker /build/test/source-install-offline-image.marker'
assert_container_mutation_rejected ordinary_container_install \
    "RUN FACELOCK_SOURCE_INSTALL_OFFLINE_IMAGE=container-build \\" \
    "RUN just install-files \\"
assert_container_mutation_rejected extra_container_install \
    '    just install-files' \
    $'    just install-files\nRUN just install-files'

cat >"$tmp_root/bin/systemctl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

printf 'systemctl' >>"$FACELOCK_SYSTEMCTL_LOG"
printf ' %s' "$@" >>"$FACELOCK_SYSTEMCTL_LOG"
printf '\n' >>"$FACELOCK_SYSTEMCTL_LOG"

layout_prefix="${FACELOCK_RUNTIME_DIR%/run/systemd/system}"
if [ "$*" = 'start facelock-daemon.service' ]; then
    : >"$layout_prefix/start-attempted"
fi
if [ "${FACELOCK_REQUIRE_RESTORE_LOCK:-false}" = true ] &&
    [ -e "${FACELOCK_AFTER_WRITE_FILE:-/nonexistent}" ] &&
    [ -n "${FACELOCK_LOCK_PATH:-}" ] &&
    flock -n "$FACELOCK_LOCK_PATH" true; then
    echo "restoration command ran without the lifecycle lock" >&2
    exit 96
fi

if [ "${1:-}" = show ]; then
    case "${2:-}" in
        facelock-daemon.service)
            if [ "$*" = 'show facelock-daemon.service --property=LoadState --property=ActiveState --property=FragmentPath --no-pager' ]; then
                layout_prefix="${FACELOCK_RUNTIME_DIR%/run/systemd/system}"
                manager_fragment_path="${FACELOCK_MANAGER_FRAGMENT_PATH:-$layout_prefix/manager-fragment-path}"
                manager_fragment=
                [ ! -f "$manager_fragment_path" ] ||
                    manager_fragment="$(cat "$manager_fragment_path")"
                case "${FACELOCK_BARRIER_SNAPSHOT_MUTATION:-none}" in
                    none) ;;
                    blank) manager_fragment= ;;
                    wrong)
                        manager_fragment="$layout_prefix/etc/systemd/system/facelock-daemon.service"
                        ;;
                    duplicate)
                        printf 'LoadState=masked\nActiveState=%s\nFragmentPath=%s\nFragmentPath=%s\n' \
                            "$([ -f "$layout_prefix/active-state" ] && cat "$layout_prefix/active-state" || printf '%s' "$FACELOCK_ACTIVE_STATE")" \
                            "$manager_fragment" "$manager_fragment"
                        exit 0
                        ;;
                    *) exit 98 ;;
                esac
                if [ "$(cat "$FACELOCK_MANAGER_MASK_STATE")" = masked ]; then
                    printf 'LoadState=masked\n'
                else
                    printf 'LoadState=%s\n' "$FACELOCK_LOAD_STATE"
                fi
                if [ -f "$layout_prefix/active-state" ]; then
                    printf 'ActiveState=%s\n' "$(cat "$layout_prefix/active-state")"
                else
                    printf 'ActiveState=%s\n' "$FACELOCK_ACTIVE_STATE"
                fi
                printf 'FragmentPath=%s\n' "$manager_fragment"
                if [ ! -e "$layout_prefix/stop-observed" ] &&
                    [ "$manager_fragment" = \
                        "$layout_prefix/run/systemd/system.control/facelock-daemon.service" ]; then
                    : >"$layout_prefix/prestop-proof-observed"
                fi
                exit 0
            fi
            if [ "$*" = 'show facelock-daemon.service --property=LoadState --property=ActiveState --no-pager' ]; then
                if [ "$(cat "$FACELOCK_MANAGER_MASK_STATE")" = masked ]; then
                    printf 'LoadState=masked\n'
                else
                    printf 'LoadState=%s\n' "$FACELOCK_LOAD_STATE"
                fi
                layout_prefix="${FACELOCK_RUNTIME_DIR%/run/systemd/system}"
                if [ -f "$layout_prefix/active-state" ]; then
                    printf 'ActiveState=%s\n' "$(cat "$layout_prefix/active-state")"
                else
                    printf 'ActiveState=%s\n' "$FACELOCK_ACTIVE_STATE"
                fi
                exit 0
            fi
            if [ "$FACELOCK_SHOW_STATUS" -ne 0 ]; then
                exit "$FACELOCK_SHOW_STATUS"
            fi
            layout_prefix="${FACELOCK_RUNTIME_DIR%/run/systemd/system}"
            barrier="$layout_prefix/run/systemd/system.control/facelock-daemon.service"
            if [ -e "$layout_prefix/start-attempted" ] &&
                [ -n "${FACELOCK_MUTATE_MASK_BEFORE_START_RETRY:-}" ] &&
                [ ! -e "$layout_prefix/start-retry-mask-mutated" ]; then
                : >"$layout_prefix/start-retry-mask-mutated"
                rm -f -- "$FACELOCK_MUTATE_MASK_BEFORE_START_RETRY"
                ln -s /dev/null "$FACELOCK_MUTATE_MASK_BEFORE_START_RETRY"
                printf '%s\n' masked >"$FACELOCK_MANAGER_MASK_STATE"
                printf '%s\n' "$FACELOCK_MUTATE_MASK_BEFORE_START_RETRY" \
                    >"${FACELOCK_MANAGER_FRAGMENT_PATH:-$layout_prefix/manager-fragment-path}"
            fi
            if { [ -e "${FACELOCK_AFTER_WRITE_FILE:-/nonexistent}" ] ||
                [ -e "$layout_prefix/stop-observed" ] ||
                compgen -G "$barrier.facelock-remove.*" >/dev/null; } &&
                [ ! -e "$barrier" ] && [ ! -L "$barrier" ]; then
                manager_fragment_path="${FACELOCK_MANAGER_FRAGMENT_PATH:-$layout_prefix/manager-fragment-path}"
                manager_fragment=
                [ ! -f "$manager_fragment_path" ] ||
                    manager_fragment="$(cat "$manager_fragment_path")"
                if [ "$(cat "$FACELOCK_MANAGER_MASK_STATE")" = masked ]; then
                    printf 'LoadState=masked\nActiveState=%s\n' \
                        "$([ -f "$layout_prefix/active-state" ] && \
                            cat "$layout_prefix/active-state" || \
                            printf '%s' "$FACELOCK_ACTIVE_STATE")"
                    case "$manager_fragment" in
                        "$layout_prefix/etc/systemd/system/"*)
                            printf 'UnitFileState=masked\n'
                            ;;
                        *) printf 'UnitFileState=masked-runtime\n' ;;
                    esac
                    printf 'FragmentPath=%s\nDropInPaths=\n' "$manager_fragment"
                elif [ "$FACELOCK_LOAD_STATE" = not-found ] &&
                    [ -z "$manager_fragment" ]; then
                    printf '%s\n' \
                        'LoadState=not-found' \
                        'ActiveState=inactive' \
                        'UnitFileState=' \
                        'FragmentPath=' \
                        'DropInPaths='
                else
                    printf 'LoadState=loaded\nActiveState=%s\n' \
                        "$([ -f "$layout_prefix/active-state" ] && \
                            cat "$layout_prefix/active-state" || \
                            printf '%s' "$FACELOCK_ACTIVE_STATE")"
                    printf 'UnitFileState=%s\nFragmentPath=%s\nExecStart=%s\nDropInPaths=%s\n' \
                        "${FACELOCK_UNIT_FILE_STATE:-static}" \
                        "$manager_fragment" \
                        "${FACELOCK_DAEMON_EXEC_START:-/usr/bin/facelock daemon}" \
                        "${FACELOCK_DROP_IN_PATHS:-}"
                fi
                exit 0
            fi
            if [ -n "${FACELOCK_SERVICE_SNAPSHOT_OVERRIDE:-}" ]; then
                printf '%s\n' "$FACELOCK_SERVICE_SNAPSHOT_OVERRIDE"
            else
                layout_prefix="${FACELOCK_RUNTIME_DIR%/run/systemd/system}"
                fragment_path="${FACELOCK_FRAGMENT_PATH_OVERRIDE:-}"
                if [ -z "$fragment_path" ]; then
                    case "$FACELOCK_LOAD_STATE:${FACELOCK_MASK_STATE:+$(cat "$FACELOCK_MASK_STATE")}" in
                        masked:runtime)
                            fragment_path="$layout_prefix/run/systemd/system/facelock-daemon.service"
                            ;;
                        masked:persistent)
                            fragment_path="$layout_prefix/etc/systemd/system/facelock-daemon.service"
                            ;;
                        *)
                            for candidate in \
                                "$layout_prefix/assets/facelock-daemon.service" \
                                "$layout_prefix/facelock-daemon.service" \
                                "$layout_prefix/usr/lib/systemd/system/facelock-daemon.service"; do
                                if [ -e "$candidate" ] || [ -L "$candidate" ]; then
                                    fragment_path="$candidate"
                                    break
                                fi
                            done
                            ;;
                    esac
                fi
                printf 'LoadState=%s\n' "$FACELOCK_LOAD_STATE"
                printf 'ActiveState=%s\n' "$FACELOCK_ACTIVE_STATE"
                printf 'UnitFileState=%s\n' "$FACELOCK_UNIT_FILE_STATE"
                printf 'FragmentPath=%s\n' "$fragment_path"
                if [ "$FACELOCK_LOAD_STATE" = loaded ]; then
                    printf 'ExecStart=%s\n' \
                        "${FACELOCK_DAEMON_EXEC_START:-/usr/bin/facelock daemon}"
                fi
                printf 'DropInPaths=%s\n' "${FACELOCK_DROP_IN_PATHS:-}"
            fi
            ;;
        dbus.service)
            if [ "${FACELOCK_DBUS_SHOW_STATUS:-0}" -ne 0 ]; then
                exit "$FACELOCK_DBUS_SHOW_STATUS"
            fi
            if [ -n "${FACELOCK_DBUS_SNAPSHOT_OVERRIDE:-}" ]; then
                printf '%s\n' "$FACELOCK_DBUS_SNAPSHOT_OVERRIDE"
            else
                printf 'Id=%s\n' "${FACELOCK_DBUS_ID:-dbus-broker.service}"
                printf 'Names=%s\n' \
                    "${FACELOCK_DBUS_NAMES:-dbus-broker.service dbus.service}"
                printf 'Following=%s\n' "${FACELOCK_DBUS_FOLLOWING:-}"
                printf 'LoadState=%s\n' "${FACELOCK_DBUS_LOAD_STATE:-loaded}"
                printf 'ActiveState=%s\n' "${FACELOCK_DBUS_ACTIVE_STATE:-active}"
                layout_prefix="${FACELOCK_RUNTIME_DIR%/run/systemd/system}"
                printf 'FragmentPath=%s\n' \
                    "${FACELOCK_DBUS_FRAGMENT_PATH:-$layout_prefix/usr/lib/systemd/system/dbus-broker.service}"
                printf 'DropInPaths=%s\n' "${FACELOCK_DBUS_DROP_IN_PATHS:-}"
                printf 'ExecStart=%s\n' \
                    "${FACELOCK_DBUS_EXEC_START:-/usr/bin/dbus-broker-launch --scope system}"
            fi
            ;;
    esac
fi

if [ -n "${FACELOCK_FAIL_COMMAND:-}" ] &&
    { [ "${FACELOCK_FAIL_BEFORE_WRITE:-false}" = true ] ||
        [ -e "${FACELOCK_AFTER_WRITE_FILE:-/nonexistent}" ]; } &&
    [ "$*" = "$FACELOCK_FAIL_COMMAND" ] &&
    [ "$(cat "$FACELOCK_FAILURES_REMAINING")" -gt 0 ]; then
    remaining="$(cat "$FACELOCK_FAILURES_REMAINING")"
    printf '%s\n' "$((remaining - 1))" >"$FACELOCK_FAILURES_REMAINING"
    exit 1
fi

case "${1:-}" in
    mask | unmask)
        echo "systemctl must not own the source-install barrier" >&2
        exit 97
        ;;
    start)
        if [ "$(cat "$FACELOCK_MANAGER_MASK_STATE")" != none ]; then
            exit 1
        fi
        layout_prefix="${FACELOCK_RUNTIME_DIR%/run/systemd/system}"
        printf '%s\n' active >"$layout_prefix/active-state"
        if [ -n "${FACELOCK_DBUS_SERVICE_TO_MUTATE_AFTER_START:-}" ]; then
            printf '%s\n' \
                '[D-BUS Service]' \
                'Name=org.facelock.Daemon' \
                'Exec=/usr/bin/facelock daemon' \
                >"$FACELOCK_DBUS_SERVICE_TO_MUTATE_AFTER_START"
        fi
        ;;
    stop)
        layout_prefix="${FACELOCK_RUNTIME_DIR%/run/systemd/system}"
        if [ "${FACELOCK_REQUIRE_PRESTOP_PROOF:-false}" = true ] &&
            [ ! -e "$layout_prefix/prestop-proof-observed" ]; then
            echo "stop occurred before the owned barrier was proven" >&2
            exit 96
        fi
        printf '%s\n' inactive >"$layout_prefix/active-state"
        : >"$layout_prefix/stop-observed"
        if [ -n "${FACELOCK_MUTATE_MASK_AFTER_STOP:-}" ]; then
            unlink -- "$FACELOCK_MUTATE_MASK_AFTER_STOP"
            ln -s /dev/zero "$FACELOCK_MUTATE_MASK_AFTER_STOP"
        fi
        case "${FACELOCK_MUTATE_AFTER_STOP:-}" in
            config)
                printf '%s\n' \
                    '<busconfig>' \
                    '<servicedir>/opt/post-stop-services</servicedir>' \
                    '<standard_system_servicedirs/>' \
                    '</busconfig>' \
                    >"$layout_prefix/usr/share/dbus-1/system.conf"
                ;;
            definition)
                printf '%s\n' \
                    '[D-BUS Service]' \
                    'Name=org.facelock.Daemon' \
                    'Exec=/usr/bin/facelock daemon' \
                    >"$layout_prefix/assets/org.facelock.Daemon.service"
                ;;
        esac
        ;;
    daemon-reload)
        layout_prefix="${FACELOCK_RUNTIME_DIR%/run/systemd/system}"
        manager_fragment_path="${FACELOCK_MANAGER_FRAGMENT_PATH:-$layout_prefix/manager-fragment-path}"
        persistent_control_dir="${FACELOCK_PERSISTENT_CONTROL_DIR:-$layout_prefix/etc/systemd/system.control}"
        runtime_control_dir="${FACELOCK_RUNTIME_CONTROL_DIR:-$layout_prefix/run/systemd/system.control}"
        barrier="$runtime_control_dir/facelock-daemon.service"
        if [ -e "${FACELOCK_AFTER_WRITE_FILE:-/nonexistent}" ] &&
            [ ! -e "$barrier" ] && [ ! -L "$barrier" ] &&
            [ "${FACELOCK_FAIL_FINAL_RELOAD:-false}" = true ]; then
            exit 1
        fi
        if [ -e "${FACELOCK_AFTER_WRITE_FILE:-/nonexistent}" ] &&
            [ -n "${FACELOCK_MUTATE_MASK_ON_CLEANUP_RELOAD:-}" ] &&
            [ ! -e "$layout_prefix/cleanup-mask-mutated" ]; then
            : >"$layout_prefix/cleanup-mask-mutated"
            rm -f -- "$FACELOCK_MUTATE_MASK_ON_CLEANUP_RELOAD"
            ln -s /dev/null "$FACELOCK_MUTATE_MASK_ON_CLEANUP_RELOAD"
        fi
        if [ -e "${FACELOCK_AFTER_WRITE_FILE:-/nonexistent}" ] &&
            [ ! -e "$barrier" ] && [ ! -L "$barrier" ] &&
            [ "${FACELOCK_MUTATE_DBUS_ON_FINAL_RELOAD:-false}" = true ] &&
            [ ! -e "$layout_prefix/final-dbus-mutated" ]; then
            : >"$layout_prefix/final-dbus-mutated"
            printf '%s\n' \
                '<busconfig>' \
                '<servicedir>/opt/post-removal-services</servicedir>' \
                '<standard_system_servicedirs/>' \
                '</busconfig>' \
                >"$layout_prefix/usr/share/dbus-1/system.conf"
        fi
        selected_unit=
        for candidate in \
            "$persistent_control_dir/facelock-daemon.service" \
            "$runtime_control_dir/facelock-daemon.service" \
            "$layout_prefix/etc/systemd/system/facelock-daemon.service" \
            "$FACELOCK_RUNTIME_DIR/facelock-daemon.service"; do
            if [ -e "$candidate" ] || [ -L "$candidate" ]; then
                selected_unit="$candidate"
                break
            fi
        done
        if [ -z "$selected_unit" ]; then
            for candidate in \
                "${FACELOCK_FRAGMENT_PATH_OVERRIDE:-}" \
                "$layout_prefix/assets/facelock-daemon.service" \
                "$layout_prefix/usr/lib/systemd/system/facelock-daemon.service"; do
                [ -n "$candidate" ] || continue
                if [ -e "$candidate" ] || [ -L "$candidate" ]; then
                    selected_unit="$candidate"
                    break
                fi
            done
        fi
        if [ "${FACELOCK_IGNORE_BARRIER:-false}" = true ]; then
            printf '%s\n' none >"$FACELOCK_MANAGER_MASK_STATE"
            : >"$manager_fragment_path"
        elif [ -n "$selected_unit" ] && {
            { [ -L "$selected_unit" ] &&
                [ "$(readlink -- "$selected_unit")" = /dev/null ]; } ||
                { [ -f "$selected_unit" ] && [ ! -s "$selected_unit" ] && {
                    [ "$selected_unit" = \
                        "$persistent_control_dir/facelock-daemon.service" ] ||
                        [ "$selected_unit" = \
                            "$runtime_control_dir/facelock-daemon.service" ] ||
                        [ "$selected_unit" = \
                            "$layout_prefix/etc/systemd/system/facelock-daemon.service" ] ||
                        [ "$selected_unit" = \
                            "$FACELOCK_RUNTIME_DIR/facelock-daemon.service" ];
                }; };
        }; then
            printf '%s\n' masked >"$FACELOCK_MANAGER_MASK_STATE"
            printf '%s\n' "$selected_unit" >"$manager_fragment_path"
        else
            printf '%s\n' none >"$FACELOCK_MANAGER_MASK_STATE"
            printf '%s\n' "$selected_unit" >"$manager_fragment_path"
        fi
        if [ -e "${FACELOCK_AFTER_WRITE_FILE:-/nonexistent}" ] &&
            [ ! -e "$barrier" ] && [ ! -L "$barrier" ] &&
            [ -n "${FACELOCK_FINAL_FRAGMENT_OVERRIDE:-}" ]; then
            printf '%s\n' "$FACELOCK_FINAL_FRAGMENT_OVERRIDE" \
                >"$manager_fragment_path"
        fi
        if [ -n "${FACELOCK_MUTATE_BARRIER_ON_RELOAD:-}" ] &&
            [ ! -e "$layout_prefix/barrier-reload-mutated" ]; then
            : >"$layout_prefix/barrier-reload-mutated"
            printf 'tampered\n' >>"$FACELOCK_MUTATE_BARRIER_ON_RELOAD"
        fi
        ;;
esac
SH
chmod +x "$tmp_root/bin/systemctl"

cat >"$tmp_root/bin/busctl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

printf 'busctl' >>"$FACELOCK_SYSTEMCTL_LOG"
printf ' %s' "$@" >>"$FACELOCK_SYSTEMCTL_LOG"
printf '\n' >>"$FACELOCK_SYSTEMCTL_LOG"

case "$*" in
    *' ReloadConfig')
        layout_prefix="${FACELOCK_RUNTIME_DIR%/run/systemd/system}"
        reload_count_file="$layout_prefix/dbus-reload-count"
        reload_count=0
        [ ! -f "$reload_count_file" ] || reload_count="$(cat "$reload_count_file")"
        reload_count=$((reload_count + 1))
        printf '%s\n' "$reload_count" >"$reload_count_file"
        if [ "${FACELOCK_DBUS_TAMPER_ON_RELOAD:-false}" = true ] ||
            [ "${FACELOCK_DBUS_TAMPER_ON_RELOAD_NUMBER:-0}" -eq "$reload_count" ]; then
            printf '%s\n' \
                '<busconfig>' \
                '<servicedir>/opt/admin-dbus-services</servicedir>' \
                '<standard_system_servicedirs/>' \
                '</busconfig>' \
                >"$layout_prefix/usr/share/dbus-1/system.conf"
        fi
        if [ "${FACELOCK_OWNER_AFTER_CLEANUP_RELOAD:-false}" = true ] &&
            [ "$reload_count" -ge 2 ]; then
            : >"$layout_prefix/cleanup-owner"
        fi
        exit "${FACELOCK_BUSCTL_RELOAD_STATUS:-0}"
        ;;
    *' NameHasOwner s org.facelock.Daemon')
        layout_prefix="${FACELOCK_RUNTIME_DIR%/run/systemd/system}"
        barrier="$layout_prefix/run/systemd/system.control/facelock-daemon.service"
        if [ -n "${FACELOCK_MUTATE_MASK_ON_OWNER:-}" ] &&
            [ ! -e "$layout_prefix/owner-mask-mutated" ]; then
            : >"$layout_prefix/owner-mask-mutated"
            unlink -- "$FACELOCK_MUTATE_MASK_ON_OWNER"
            ln -s /dev/zero "$FACELOCK_MUTATE_MASK_ON_OWNER"
        fi
        if [ -n "${FACELOCK_MUTATE_ORDINARY_ON_OWNER:-}" ] &&
            [ ! -e "$layout_prefix/owner-ordinary-mutated" ]; then
            : >"$layout_prefix/owner-ordinary-mutated"
            printf '%s\n' '[Service]' \
                'ExecStart=/usr/bin/facelock daemox' \
                >"$FACELOCK_MUTATE_ORDINARY_ON_OWNER"
        fi
        if [ -e "${FACELOCK_AFTER_WRITE_FILE:-/nonexistent}" ] &&
            [ ! -e "$barrier" ] && [ ! -L "$barrier" ] &&
            [ "${FACELOCK_OWNER_AFTER_FINAL_RELOAD:-false}" = true ]; then
            printf 'b true\n'
        elif [ -e "$layout_prefix/cleanup-owner" ]; then
            printf 'b true\n'
        elif [ "${FACELOCK_OWNER_AFTER_STOP:-false}" = true ] &&
            [ -e "$layout_prefix/stop-observed" ]; then
            printf 'b true\n'
        elif [ "${FACELOCK_DBUS_OWNER_OVERRIDE:-}" = true ]; then
            printf 'b true\n'
        elif [ "${FACELOCK_DBUS_OWNER_OVERRIDE:-}" = false ]; then
            printf 'b false\n'
        elif [ -f "$layout_prefix/active-state" ]; then
            printf 'b %s\n' "$([ "$(cat "$layout_prefix/active-state")" = active ] && printf true || printf false)"
        elif [ "$FACELOCK_ACTIVE_STATE" = active ]; then
            printf 'b true\n'
        else
            printf 'b false\n'
        fi
        ;;
    *) exit 2 ;;
esac
SH
chmod +x "$tmp_root/bin/busctl"

cat >"$tmp_root/bin/dbus-activate" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

systemctl start facelock-daemon.service
SH
chmod +x "$tmp_root/bin/dbus-activate"

cat >"$tmp_root/bin/mv" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

if [ -n "${FACELOCK_REPLACE_BEFORE_QUARANTINE:-}" ]; then
    source_path="${@: -2:1}"
    if [ "$source_path" = "$FACELOCK_REPLACE_BEFORE_QUARANTINE" ]; then
        if [ "${FACELOCK_REPLACE_DIRECTORY_BEFORE_QUARANTINE:-false}" = true ]; then
            /usr/bin/rmdir -- "$source_path"
            /usr/bin/mkdir -m 0755 -- "$source_path"
            : >"$source_path/replacement"
        else
            /usr/bin/rm -f -- "$source_path"
            printf '%s\n' replacement >"$source_path"
        fi
    fi
fi
if [ -n "${FACELOCK_MUTATE_MASK_BEFORE_QUARANTINE:-}" ]; then
    source_path="${@: -2:1}"
    case "$source_path" in
        */system.control/facelock-daemon.service)
            if [ ! -e "${FACELOCK_MUTATE_MASK_BEFORE_QUARANTINE}.mutated" ]; then
                : >"${FACELOCK_MUTATE_MASK_BEFORE_QUARANTINE}.mutated"
                rm -f -- "$FACELOCK_MUTATE_MASK_BEFORE_QUARANTINE"
                ln -s /dev/null "$FACELOCK_MUTATE_MASK_BEFORE_QUARANTINE"
            fi
            ;;
    esac
fi
if [ -n "${FACELOCK_MUTATE_MASK_BEFORE_RESTART:-}" ]; then
    source_path="${@: -2:1}"
    case "$source_path" in
        */system.control)
            if [ ! -e "${FACELOCK_MUTATE_MASK_BEFORE_RESTART}.mutated" ]; then
                : >"${FACELOCK_MUTATE_MASK_BEFORE_RESTART}.mutated"
                rm -f -- "$FACELOCK_MUTATE_MASK_BEFORE_RESTART"
                ln -s /dev/null "$FACELOCK_MUTATE_MASK_BEFORE_RESTART"
            fi
            ;;
    esac
fi
if [ -n "${FACELOCK_ADD_ENTRY_BEFORE_DIRECTORY_QUARANTINE:-}" ]; then
    source_path="${@: -2:1}"
    if [ "$source_path" = \
        "$FACELOCK_ADD_ENTRY_BEFORE_DIRECTORY_QUARANTINE" ]; then
        : >"$source_path/administrator-unit.service"
    fi
fi
if [ "${FACELOCK_MOVE_BARRIER_THEN_FAIL:-false}" = true ]; then
    source_path="${@: -2:1}"
    case "$source_path" in
        */system.control/facelock-daemon.service)
            marker="${source_path%/run/systemd/system.control/*}/move-then-fail-fired"
            if [ ! -e "$marker" ]; then
                : >"$marker"
                /usr/bin/mv "$@"
                exit 1
            fi
            ;;
    esac
fi
exec /usr/bin/mv "$@"
SH
chmod +x "$tmp_root/bin/mv"

cat >"$tmp_root/bin/rm" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

target="${@: -1}"
if [ -n "${FACELOCK_FAIL_MIGRATION_UNLINK_NUMBER:-}" ]; then
    case "$target" in
        */.facelock-migrate-*)
            count=0
            [ ! -f "$FACELOCK_MIGRATION_UNLINK_COUNT" ] ||
                count="$(cat "$FACELOCK_MIGRATION_UNLINK_COUNT")"
            count=$((count + 1))
            printf '%s\n' "$count" >"$FACELOCK_MIGRATION_UNLINK_COUNT"
            if [ "$count" -eq "$FACELOCK_FAIL_MIGRATION_UNLINK_NUMBER" ]; then
                exit 71
            fi
            ;;
    esac
fi
case "${FACELOCK_BARRIER_REMOVE_FAULT:-none}:$target" in
    before:*.facelock-remove.*)
        exit 1
        ;;
    after:*.facelock-remove.*)
        marker="${target%/*}/barrier-remove-after-fired"
        if [ ! -e "$marker" ]; then
            : >"$marker"
            /usr/bin/rm "$@"
            exit 1
        fi
        ;;
esac
exec /usr/bin/rm "$@"
SH
chmod +x "$tmp_root/bin/rm"

cat >"$tmp_root/bin/mkdir" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

/usr/bin/mkdir "$@"
target="${@: -1}"
if [ -n "${FACELOCK_MUTATE_CREATED_BARRIER_DIR:-}" ] &&
    [ "$target" = "$FACELOCK_MUTATE_CREATED_BARRIER_DIR" ]; then
    chmod 0777 -- "$target"
fi
SH
chmod +x "$tmp_root/bin/mkdir"

mkdir -p "$tmp_root/readlink-fail-bin"
cat >"$tmp_root/readlink-fail-bin/readlink" <<'SH'
#!/usr/bin/env bash
exit 1
SH
chmod +x "$tmp_root/readlink-fail-bin/readlink"

write_dbus_service() {
    local path="$1"
    local delegation="${2:-systemd}"

    {
        printf '%s\n' '[D-BUS Service]'
        printf '%s\n' 'Name=org.facelock.Daemon'
        printf '%s\n' 'Exec=/usr/bin/facelock daemon'
        printf '%s\n' 'User=root'
        if [ "$delegation" = systemd ]; then
            printf '%s\n' 'SystemdService=facelock-daemon.service'
        fi
    } >"$path"
}

write_standard_dbus_config() {
    local root="$1"

    mkdir -p "$root/usr/share/dbus-1" "$root/usr/bin" \
        "$root/usr/lib/systemd/system"
    : >"$root/usr/bin/dbus-broker-launch"
    : >"$root/usr/bin/facelock"
    chmod 755 "$root/usr/bin/dbus-broker-launch" "$root/usr/bin/facelock"
    : >"$root/usr/lib/systemd/system/dbus-broker.service"
    printf '%s\n' \
        '<busconfig>' \
        '  <standard_system_servicedirs/>' \
        '  <include ignore_missing="yes">/etc/dbus-1/system.conf</include>' \
        '  <includedir>system.d</includedir>' \
        '  <includedir>/etc/dbus-1/system.d</includedir>' \
        '  <include ignore_missing="yes">/etc/dbus-1/system-local.conf</include>' \
        '  <include if_selinux_enabled="yes" selinux_root_relative="yes">contexts/dbus_contexts</include>' \
        '</busconfig>' >"$root/usr/share/dbus-1/system.conf"
}

run_case() {
    local name="$1"
    local load_state="$2"
    local active_state="$3"
    local unit_file_state="$4"
    local show_status="$5"
    local assets="$6"
    local expected_status="$7"
    local initial_mask="$8"
    local inject_activation="$9"
    local expected="${10}"
    local control_conflict="${11:-none}"
    local ignore_barrier="${12:-false}"
    local busctl_reload_status="${13:-0}"
    local dbus_owner_override="${14:-}"
    local dbus_tamper_on_reload="${15:-false}"
    local retain_barrier="${16:-false}"
    local case_root="$tmp_root/$name"
    local actual="$case_root/actual"
    local expected_path="$case_root/expected"
    local stderr_path="$case_root/stderr"
    local mask_state="$case_root/mask-state"
    local manager_mask_state="$case_root/manager-mask-state"
    local manager_fragment_path="$case_root/manager-fragment-path"
    local barrier="$case_root/run/systemd/system.control/facelock-daemon.service"
    local runtime_unit="$case_root/run/systemd/system/facelock-daemon.service"
    local persistent_unit="$case_root/etc/systemd/system/facelock-daemon.service"
    local persistent_mask_before runtime_mask_before
    local persistent_target_before runtime_target_before
    local fragment_path_override=
    local status

    mkdir -p "$case_root/etc/systemd/system" \
        "$case_root/etc/systemd/system.control" \
        "$case_root/run/systemd/system" \
        "$case_root/run/systemd/system.control" \
        "$case_root/assets"
    write_standard_dbus_config "$case_root"
    case "$assets" in
        present)
            : >"$case_root/assets/facelock-daemon.service"
            write_dbus_service "$case_root/assets/org.facelock.Daemon.service"
            ;;
        direct)
            : >"$case_root/assets/facelock-daemon.service"
            write_dbus_service \
                "$case_root/assets/org.facelock.Daemon.service" direct
            ;;
        unit_symlink)
            ln -s /dev/null "$case_root/assets/facelock-daemon.service"
            write_dbus_service "$case_root/assets/org.facelock.Daemon.service"
            ;;
        alternate)
            write_dbus_service "$case_root/assets/alternate.service"
            ;;
    esac

    : >"$actual"
    if [ -n "$expected" ]; then
        printf '%s\n' "$expected" >"$expected_path"
    else
        : >"$expected_path"
    fi
    printf '%s\n' none >"$mask_state"
    if [ "$load_state" = masked ]; then
        printf '%s\n' masked >"$manager_mask_state"
    else
        printf '%s\n' none >"$manager_mask_state"
    fi
    : >"$manager_fragment_path"
    case "$initial_mask" in
        runtime | runtime-symlink)
            ln -s /dev/null "$runtime_unit"
            printf '%s\n' runtime >"$mask_state"
            ;;
        runtime-regular)
            : >"$runtime_unit"
            chmod 644 "$runtime_unit"
            printf '%s\n' runtime >"$mask_state"
            ;;
        persistent | persistent-symlink)
            ln -s /dev/null "$persistent_unit"
            printf '%s\n' persistent >"$mask_state"
            ;;
        persistent-regular)
            : >"$persistent_unit"
            chmod 644 "$persistent_unit"
            printf '%s\n' persistent >"$mask_state"
            ;;
        both-symlink)
            ln -s /dev/null "$persistent_unit"
            ln -s /dev/null "$runtime_unit"
            printf '%s\n' persistent >"$mask_state"
            ;;
        both-regular)
            : >"$persistent_unit"
            : >"$runtime_unit"
            chmod 644 "$persistent_unit" "$runtime_unit"
            printf '%s\n' persistent >"$mask_state"
            ;;
        persistent-symlink-runtime-regular)
            ln -s /dev/null "$persistent_unit"
            : >"$runtime_unit"
            chmod 644 "$runtime_unit"
            printf '%s\n' persistent >"$mask_state"
            ;;
        persistent-regular-runtime-symlink)
            : >"$persistent_unit"
            chmod 644 "$persistent_unit"
            ln -s /dev/null "$runtime_unit"
            printf '%s\n' persistent >"$mask_state"
            ;;
        nonmask-runtime | runtime-override)
            printf '%s\n' '[Service]' 'ExecStart=/usr/bin/facelock daemon' \
                >"$runtime_unit"
            fragment_path_override="$runtime_unit"
            ;;
        persistent-override)
            printf '%s\n' '[Service]' 'ExecStart=/usr/bin/facelock daemon' \
                >"$persistent_unit"
            fragment_path_override="$persistent_unit"
            ;;
        persistent-override-runtime-mask)
            printf '%s\n' '[Service]' 'ExecStart=/usr/bin/facelock daemon' \
                >"$persistent_unit"
            ln -s /dev/null "$runtime_unit"
            fragment_path_override="$persistent_unit"
            ;;
        persistent-mask-runtime-override)
            ln -s /dev/null "$persistent_unit"
            printf '%s\n' '[Service]' 'ExecStart=/usr/bin/facelock daemon' \
                >"$runtime_unit"
            printf '%s\n' persistent >"$mask_state"
            ;;
        dangling-runtime)
            ln -s /missing-facelock-mask "$runtime_unit"
            ;;
        untrusted-runtime)
            : >"$runtime_unit"
            chmod 666 "$runtime_unit"
            ;;
        none) ;;
        *) fail "$name has unknown physical mask layout $initial_mask" ;;
    esac
    persistent_mask_before=absent
    persistent_target_before=
    runtime_mask_before=absent
    runtime_target_before=
    if [ -e "$persistent_unit" ] || [ -L "$persistent_unit" ]; then
        persistent_mask_before="$(stat -c '%d:%i:%u:%g:%a:%h:%s:%F' -- \
            "$persistent_unit")"
        [ ! -L "$persistent_unit" ] ||
            persistent_target_before="$(readlink -- "$persistent_unit")"
    fi
    if [ -e "$runtime_unit" ] || [ -L "$runtime_unit" ]; then
        runtime_mask_before="$(stat -c '%d:%i:%u:%g:%a:%h:%s:%F' -- \
            "$runtime_unit")"
        [ ! -L "$runtime_unit" ] ||
            runtime_target_before="$(readlink -- "$runtime_unit")"
    fi
    if [ "$load_state" = masked ]; then
        case "$(cat "$mask_state")" in
            persistent) printf '%s\n' "$persistent_unit" >"$manager_fragment_path" ;;
            runtime) printf '%s\n' "$runtime_unit" >"$manager_fragment_path" ;;
        esac
    fi
    case "$control_conflict" in
        persistent)
            printf '%s\n' override >"$case_root/etc/systemd/system.control/facelock-daemon.service"
            ;;
        runtime)
            printf '%s\n' override >"$barrier"
            ;;
    esac

    set +e
    PATH="$tmp_root/bin:$PATH" \
        FACELOCK_SYSTEMCTL_LOG="$actual" \
        FACELOCK_SHOW_STATUS="$show_status" \
        FACELOCK_LOAD_STATE="$load_state" \
        FACELOCK_ACTIVE_STATE="$active_state" \
        FACELOCK_UNIT_FILE_STATE="$unit_file_state" \
        FACELOCK_MASK_STATE="$mask_state" \
        FACELOCK_MANAGER_MASK_STATE="$manager_mask_state" \
        FACELOCK_MANAGER_FRAGMENT_PATH="$manager_fragment_path" \
        FACELOCK_FRAGMENT_PATH_OVERRIDE="$fragment_path_override" \
        FACELOCK_IGNORE_BARRIER="$ignore_barrier" \
        FACELOCK_REQUIRE_PRESTOP_PROOF=true \
        FACELOCK_BUSCTL_RELOAD_STATUS="$busctl_reload_status" \
        FACELOCK_DBUS_OWNER_OVERRIDE="$dbus_owner_override" \
        FACELOCK_DBUS_TAMPER_ON_RELOAD="$dbus_tamper_on_reload" \
        FACELOCK_PERSISTENT_CONTROL_DIR="$case_root/etc/systemd/system.control" \
        FACELOCK_RUNTIME_CONTROL_DIR="$case_root/run/systemd/system.control" \
        FACELOCK_RUNTIME_DIR="$case_root/run/systemd/system" \
        bash -c '
            set -euo pipefail
            source "$1"
            layout_prefix="${2%/run/systemd/system}"
            facelock_source_install_begin_daemon "$2" "$3" "$4" \
                "$layout_prefix/etc/systemd/system/facelock-daemon.service" \
                "$layout_prefix/run/systemd/system/facelock-daemon.service"
            barrier_dir="${2%/system}/system.control"
            barrier="$barrier_dir/facelock-daemon.service"
            [ -f "$barrier" ]
            [ ! -L "$barrier" ]
            [ ! -s "$barrier" ]
            path_metadata="$(stat -Lc "%d:%i:%u:%g:%a:%h:%s:%F" -- "$barrier")"
            fd_metadata="$(stat -Lc "%d:%i:%u:%g:%a:%h:%s:%F" -- "/proc/$$/fd/$FACELOCK_SOURCE_INSTALL_BARRIER_FD")"
            [ "$path_metadata" = "$fd_metadata" ]
            IFS=: read -r _ _ uid gid mode links size kind <<<"$path_metadata"
            [ "$uid:$gid" = "$(stat -Lc "%u:%g" -- "${2%/run/systemd/system}")" ]
            [ "$mode" = 600 ]
            [ "$links" -eq 1 ]
            [ "$size" -eq 0 ]
            [[ "$kind" = regular\ *file ]]
            if [ "$5" = yes ]; then
                if dbus-activate; then
                    echo "activation escaped the source-install barrier" >&2
                    exit 90
                fi
            fi
            case "$7" in
                absent)
                    : >"$3"
                    printf "%s\n" \
                        "[D-BUS Service]" \
                        "Name=org.facelock.Daemon" \
                        "Exec=/usr/bin/facelock daemon" \
                        "User=root" \
                        "SystemdService=facelock-daemon.service" >"$4"
                    ;;
            esac
            printf "%s\n" write >>"$FACELOCK_SYSTEMCTL_LOG"
            facelock_source_install_complete_daemon "$2"
            [ ! -e "$barrier" ]
            [ ! -L "$barrier" ]
        ' _ \
        "$lifecycle_script" \
        "$case_root/run/systemd/system" \
        "$case_root/assets/facelock-daemon.service" \
        "$case_root/assets/org.facelock.Daemon.service" \
        "$inject_activation" \
        "$initial_mask" \
        "$assets" \
        2>"$stderr_path"
    status=$?
    set -e

    if [ "$expected_status" = success ] && [ "$status" -ne 0 ]; then
        cat "$stderr_path" >&2
        fail "$name unexpectedly failed with status $status"
    fi
    if [ "$expected_status" = failure ] && [ "$status" -eq 0 ]; then
        fail "$name unexpectedly succeeded"
    fi
    if [ "$expected_status" = success ] && [ -s "$stderr_path" ]; then
        cat "$stderr_path" >&2
        fail "$name wrote unexpected stderr"
    fi
    if [ "$expected_status" = failure ] &&
        ! grep -Fq 'no files were changed' "$stderr_path"; then
        cat "$stderr_path" >&2
        fail "$name did not explain its pre-mutation refusal"
    fi

    diff -u "$expected_path" "$actual" ||
        fail "$name command ordering or activation state changed"
    if [ "$persistent_mask_before" != absent ]; then
        [ "$(stat -c '%d:%i:%u:%g:%a:%h:%s:%F' -- "$persistent_unit")" = \
            "$persistent_mask_before" ] || fail "$name changed persistent mask metadata"
        [ ! -L "$persistent_unit" ] ||
            [ "$(readlink -- "$persistent_unit")" = "$persistent_target_before" ] ||
            fail "$name changed persistent mask target"
    fi
    if [ "$runtime_mask_before" != absent ]; then
        [ "$(stat -c '%d:%i:%u:%g:%a:%h:%s:%F' -- "$runtime_unit")" = \
            "$runtime_mask_before" ] || fail "$name changed runtime mask metadata"
        [ ! -L "$runtime_unit" ] ||
            [ "$(readlink -- "$runtime_unit")" = "$runtime_target_before" ] ||
            fail "$name changed runtime mask target"
    fi
    case "$control_conflict:$load_state:$initial_mask" in
        persistent:*)
            [ -f "$case_root/etc/systemd/system.control/facelock-daemon.service" ] &&
                [ "$(cat "$case_root/etc/systemd/system.control/facelock-daemon.service")" = override ] ||
                fail "$name changed the pre-existing control unit"
            ;;
        runtime:*)
            [ -f "$barrier" ] && [ "$(cat "$barrier")" = override ] ||
                fail "$name changed the pre-existing control unit"
            ;;
        none:*:runtime | none:*:runtime-symlink)
            [ -L "$runtime_unit" ] && [ "$(readlink "$runtime_unit")" = /dev/null ] ||
                fail "$name changed the pre-existing runtime mask"
            ;;
        none:*:runtime-regular)
            [ -f "$runtime_unit" ] && [ ! -s "$runtime_unit" ] &&
                [ ! -L "$runtime_unit" ] ||
                fail "$name changed the pre-existing runtime regular mask"
            ;;
        none:*:persistent | none:*:persistent-symlink)
            [ -L "$persistent_unit" ] &&
                [ "$(readlink "$persistent_unit")" = /dev/null ] ||
                fail "$name changed the pre-existing persistent mask"
            ;;
        none:*:persistent-regular)
            [ -f "$persistent_unit" ] && [ ! -s "$persistent_unit" ] &&
                [ ! -L "$persistent_unit" ] ||
                fail "$name changed the pre-existing persistent regular mask"
            ;;
        none:*:both-symlink)
            [ -L "$persistent_unit" ] && [ "$(readlink "$persistent_unit")" = /dev/null ] &&
                [ -L "$runtime_unit" ] && [ "$(readlink "$runtime_unit")" = /dev/null ] ||
                fail "$name changed one of the pre-existing masks"
            ;;
        none:*:both-regular)
            [ -f "$persistent_unit" ] && [ ! -s "$persistent_unit" ] &&
                [ ! -L "$persistent_unit" ] &&
                [ -f "$runtime_unit" ] && [ ! -s "$runtime_unit" ] &&
                [ ! -L "$runtime_unit" ] ||
                fail "$name changed one of the pre-existing regular masks"
            ;;
        none:*:none)
            if [ "$retain_barrier" != true ]; then
                [ ! -e "$barrier" ] && [ ! -L "$barrier" ] ||
                    fail "$name left its owned activation barrier installed"
            fi
            ;;
    esac
    if [ "$expected_status" = success ] &&
        [ "$(cat "$mask_state")" != none ]; then
        [ "$(cat "$manager_mask_state")" = masked ] ||
            fail "$name did not restore the manager's administrative mask state"
        case "$(cat "$mask_state")" in
            persistent)
                [ "$(cat "$manager_fragment_path")" = "$persistent_unit" ] ||
                    fail "$name did not restore the persistent mask winner"
                ;;
            runtime)
                [ "$(cat "$manager_fragment_path")" = "$runtime_unit" ] ||
                    fail "$name did not restore the runtime mask winner"
                ;;
        esac
    elif [ "$expected_status" = success ]; then
        [ "$(cat "$manager_mask_state")" = none ] ||
            fail "$name left the manager masked after removing its barrier"
        case "$initial_mask" in
            runtime-override | nonmask-runtime)
                [ "$(cat "$manager_fragment_path")" = "$runtime_unit" ] ||
                    fail "$name did not restore the runtime override winner"
                ;;
            persistent-override | persistent-override-runtime-mask)
                [ "$(cat "$manager_fragment_path")" = "$persistent_unit" ] ||
                    fail "$name did not restore the persistent override winner"
                ;;
        esac
    fi
    assert_lock_available "$name" "$case_root/run/facelock/lifecycle.lock"
}

show_command='systemctl show facelock-daemon.service --property=LoadState --property=ActiveState --property=UnitFileState --property=FragmentPath --property=ExecStart --property=DropInPaths --no-pager'
dbus_show_command='systemctl show dbus.service --property=Id --property=Names --property=Following --property=LoadState --property=ActiveState --property=FragmentPath --property=DropInPaths --property=ExecStart --no-pager'
barrier_show_command='systemctl show facelock-daemon.service --property=LoadState --property=ActiveState --property=FragmentPath --no-pager'
dbus_reload_command='busctl --system call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus ReloadConfig'
dbus_owner_command='busctl --system call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus NameHasOwner s org.facelock.Daemon'

run_daemon_exec_topology_case() {
    local name="$1"
    local exec_start="$2"
    local expected_status="$3"
    local mutation="${4:-none}"
    local case_root="$tmp_root/$name"
    local unit="$case_root/assets/facelock-daemon.service"
    local executable="$case_root/usr/bin/facelock"
    local status

    mkdir -p "$case_root/assets" "$case_root/usr/bin"
    : >"$unit"
    : >"$executable"
    chmod 755 "$executable"
    case "$mutation" in
        none) ;;
        missing) rm -f "$executable" ;;
        symlink)
            rm -f "$executable"
            ln -s /usr/bin/false "$executable"
            ;;
        hardlink) ln "$executable" "$case_root/facelock-alias" ;;
        group_writable) chmod 775 "$executable" ;;
        world_writable) chmod 757 "$executable" ;;
        non_executable) chmod 644 "$executable" ;;
        owner_executable) chmod 700 "$executable" ;;
        parent_untrusted) chmod 777 "$case_root/usr/bin" ;;
        size_above_16m) truncate -s 16777217 "$executable" ;;
        size_256m) truncate -s 268435456 "$executable" ;;
        size_above_256m) truncate -s 268435457 "$executable" ;;
        *) fail "$name has unknown daemon executable mutation $mutation" ;;
    esac

    set +e
    bash -c '
        set -euo pipefail
        source "$1"
        IFS=: read -r FACELOCK_SOURCE_INSTALL_TRUST_UID \
            FACELOCK_SOURCE_INSTALL_TRUST_GID < <(stat -Lc "%u:%g" -- "$2")
        facelock_source_install_effective_unit_is_trusted \
            "$3" "$4" "" "$2" "$3"
    ' _ "$lifecycle_script" "$case_root" "$unit" "$exec_start"
    status=$?
    set -e

    [ "$status" -eq "$expected_status" ] ||
        fail "$name exited $status, expected $expected_status"
}

daemon_structured_exec='{ path=/usr/bin/facelock ; argv[]=/usr/bin/facelock daemon ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }'
run_daemon_exec_topology_case daemon_exec_plain \
    '/usr/bin/facelock daemon' 0
run_daemon_exec_topology_case daemon_exec_structured \
    "$daemon_structured_exec" 0
run_daemon_exec_topology_case daemon_exec_prefix \
    "prefix $daemon_structured_exec" 1
run_daemon_exec_topology_case daemon_exec_suffix \
    "$daemon_structured_exec suffix" 1
run_daemon_exec_topology_case daemon_exec_extra_record \
    "$daemon_structured_exec ; $daemon_structured_exec" 1
run_daemon_exec_topology_case daemon_exec_extra_argv \
    '{ path=/usr/bin/facelock ; argv[]=/usr/bin/facelock daemon --unsafe ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }' 1
run_daemon_exec_topology_case daemon_exec_wrong_path \
    '/usr/local/bin/facelock daemon' 1
run_daemon_exec_topology_case daemon_exec_substring_only \
    '{ unexpected=yes ; path=/usr/bin/facelock ; argv[]=/usr/bin/facelock daemon ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }' 1
run_daemon_exec_topology_case daemon_exec_ignore_errors \
    '{ path=/usr/bin/facelock ; argv[]=/usr/bin/facelock daemon ; ignore_errors=yes ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }' 1
run_daemon_exec_topology_case daemon_exec_trailing_semicolon \
    '{ path=/usr/bin/facelock ; argv[]=/usr/bin/facelock daemon ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 ; }' 1
run_daemon_exec_topology_case daemon_exec_status_cr_suffix \
    "${daemon_structured_exec% \}}"$'\r }' 1
run_daemon_exec_topology_case daemon_exec_status_lf_suffix \
    "${daemon_structured_exec% \}}"$'\n }' 1
run_daemon_exec_topology_case daemon_exec_empty '' 1
run_daemon_exec_topology_case daemon_executable_missing \
    '/usr/bin/facelock daemon' 1 missing
run_daemon_exec_topology_case daemon_executable_symlink \
    '/usr/bin/facelock daemon' 1 symlink
run_daemon_exec_topology_case daemon_executable_hardlink \
    '/usr/bin/facelock daemon' 1 hardlink
run_daemon_exec_topology_case daemon_executable_group_writable \
    '/usr/bin/facelock daemon' 1 group_writable
run_daemon_exec_topology_case daemon_executable_world_writable \
    '/usr/bin/facelock daemon' 1 world_writable
run_daemon_exec_topology_case daemon_executable_non_executable \
    '/usr/bin/facelock daemon' 1 non_executable
run_daemon_exec_topology_case daemon_executable_owner_executable \
    '/usr/bin/facelock daemon' 0 owner_executable
run_daemon_exec_topology_case daemon_executable_parent_untrusted \
    '/usr/bin/facelock daemon' 1 parent_untrusted
run_daemon_exec_topology_case daemon_executable_above_16m \
    '/usr/bin/facelock daemon' 0 size_above_16m
run_daemon_exec_topology_case daemon_executable_256m \
    '/usr/bin/facelock daemon' 0 size_256m
run_daemon_exec_topology_case daemon_executable_above_256m \
    '/usr/bin/facelock daemon' 1 size_above_256m

write_dbus_snapshot() {
    local topology="$1"
    local mutation="$2"
    local exec_start="$3"
    local id names fragment_path
    local following="" load_state=loaded active_state=active drop_in_paths=""
    local key value
    local -a keys=(Id Names Following LoadState ActiveState FragmentPath DropInPaths ExecStart)

    case "$topology" in
        broker)
            id=dbus-broker.service
            names='dbus-broker.service dbus.service'
            fragment_path='@CASE_ROOT@/usr/lib/systemd/system/dbus-broker.service'
            ;;
        daemon)
            id=dbus.service
            names=dbus.service
            fragment_path='@CASE_ROOT@/usr/lib/systemd/system/dbus.service'
            ;;
        *) fail "unknown D-Bus topology $topology" ;;
    esac
    case "$mutation" in
        none) ;;
        following) following=dbus.socket ;;
        not_loaded) load_state=not-found ;;
        inactive) active_state=inactive ;;
        drop_in) drop_in_paths='@CASE_ROOT@/etc/systemd/system/dbus.service.d/override.conf' ;;
        names_reverse) names='dbus.service dbus-broker.service' ;;
        names_extra) names="$names dbus-extra.service" ;;
        names_duplicate) names="$names dbus.service" ;;
        wrong_id) id=dbus.service ;;
        wrong_fragment) fragment_path='@CASE_ROOT@/usr/lib/systemd/system/dbus.service' ;;
        lib_fragment) fragment_path="${fragment_path/\/usr\/lib\//\/lib\/}" ;;
        unknown | missing_* | duplicate_*) ;;
        *) fail "unknown D-Bus snapshot mutation $mutation" ;;
    esac

    for key in "${keys[@]}"; do
        [ "$mutation" != "missing_$key" ] || continue
        case "$key" in
            Id) value="$id" ;;
            Names) value="$names" ;;
            Following) value="$following" ;;
            LoadState) value="$load_state" ;;
            ActiveState) value="$active_state" ;;
            FragmentPath) value="$fragment_path" ;;
            DropInPaths) value="$drop_in_paths" ;;
            ExecStart) value="$exec_start" ;;
        esac
        printf '%s=%s\n' "$key" "$value"
        if [ "$mutation" = "duplicate_$key" ]; then
            printf '%s=%s\n' "$key" "$value"
        fi
    done
    if [ "$mutation" = unknown ]; then
        printf 'Unexpected=value\n'
    fi
}

run_dbus_topology_case() {
    local name="$1"
    local topology="$2"
    local mutation="$3"
    local exec_start="$4"
    local expected_status="$5"
    local asset_mutation="${6:-none}"
    local case_root="$tmp_root/$name"
    local executable fragment_path snapshot status

    mkdir -p "$case_root/run/systemd/system"
    write_standard_dbus_config "$case_root"
    : >"$case_root/usr/bin/dbus-daemon"
    chmod 755 "$case_root/usr/bin/dbus-daemon"
    : >"$case_root/usr/lib/systemd/system/dbus.service"
    case "$topology" in
        broker)
            executable="$case_root/usr/bin/dbus-broker-launch"
            fragment_path="$case_root/usr/lib/systemd/system/dbus-broker.service"
            ;;
        daemon)
            executable="$case_root/usr/bin/dbus-daemon"
            fragment_path="$case_root/usr/lib/systemd/system/dbus.service"
            ;;
    esac
    case "$asset_mutation" in
        none) ;;
        executable_missing) rm -f "$executable" ;;
        executable_symlink)
            rm -f "$executable"
            ln -s /usr/bin/false "$executable"
            ;;
        executable_hardlink) ln "$executable" "$case_root/dbus-executable-alias" ;;
        executable_mode) chmod 777 "$executable" ;;
        executable_parent_mode) chmod 777 "$case_root/usr/bin" ;;
        fragment_symlink)
            rm -f "$fragment_path"
            ln -s /dev/null "$fragment_path"
            ;;
        fragment_hardlink) ln "$fragment_path" "$case_root/dbus-fragment-alias" ;;
        fragment_mode) chmod 666 "$fragment_path" ;;
        fragment_size) truncate -s 1048577 "$fragment_path" ;;
        fragment_parent_mode) chmod 777 "$case_root/usr/lib/systemd/system" ;;
        fragment_merged_lib)
            ln -s usr/lib "$case_root/lib"
            fragment_path="${fragment_path/\/usr\/lib\//\/lib\/}"
            ;;
        fragment_newline_alias)
            mkdir -p "$case_root/usr/"$'lib\n/systemd/system'
            : >"$case_root/usr/"$'lib\n/systemd/system/'"${fragment_path##*/}"
            ln -s $'usr/lib\n' "$case_root/lib"
            fragment_path="${fragment_path/\/usr\/lib\//\/lib\/}"
            ;;
        fragment_independent_lib)
            fragment_path="${fragment_path/\/usr\/lib\//\/lib\/}"
            mkdir -p "${fragment_path%/*}"
            : >"$fragment_path"
            ;;
        *) fail "$name has unknown D-Bus asset mutation $asset_mutation" ;;
    esac
    snapshot="$(write_dbus_snapshot "$topology" "$mutation" "$exec_start")"
    snapshot="${snapshot//@CASE_ROOT@/$case_root}"
    : >"$case_root/actual"

    set +e
    PATH="$tmp_root/bin:$PATH" \
        FACELOCK_SYSTEMCTL_LOG="$case_root/actual" \
        FACELOCK_DBUS_SNAPSHOT_OVERRIDE="$snapshot" \
        FACELOCK_RUNTIME_DIR="$case_root/run/systemd/system" \
        bash -c '
            set -euo pipefail
            source "$1"
            FACELOCK_SOURCE_INSTALL_DBUS_LAYOUT_PREFIX="$2"
            IFS=: read -r FACELOCK_SOURCE_INSTALL_TRUST_UID \
                FACELOCK_SOURCE_INSTALL_TRUST_GID < <(stat -Lc "%u:%g" -- "$2")
            facelock_source_install_dbus_uses_systemd_activation
        ' _ "$lifecycle_script" "$case_root"
    status=$?
    set -e

    [ "$status" -eq "$expected_status" ] ||
        fail "$name exited $status, expected $expected_status"
    [ "$(cat "$case_root/actual")" = "$dbus_show_command" ] ||
        fail "$name used an unexpected manager query"
}

broker_structured_exec='{ path=/usr/bin/dbus-broker-launch ; argv[]=/usr/bin/dbus-broker-launch --scope system --audit ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }'
dbus_daemon_args='--system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only'
run_dbus_topology_case dbus_broker_scope_space broker none \
    '/usr/bin/dbus-broker-launch --scope system' 0
run_dbus_topology_case dbus_broker_scope_equals broker none \
    '/usr/bin/dbus-broker-launch --scope=system' 0
run_dbus_topology_case dbus_broker_audit broker none \
    '/usr/bin/dbus-broker-launch --scope system --audit' 0
run_dbus_topology_case dbus_broker_equals_audit broker none \
    '/usr/bin/dbus-broker-launch --scope=system --audit' 0
run_dbus_topology_case dbus_broker_structured broker none \
    "$broker_structured_exec" 0
run_dbus_topology_case dbus_broker_structured_trailing_semicolon broker none \
    '{ path=/usr/bin/dbus-broker-launch ; argv[]=/usr/bin/dbus-broker-launch --scope system ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 ; }' 1
run_dbus_topology_case dbus_broker_structured_scope_space broker none \
    '{ path=/usr/bin/dbus-broker-launch ; argv[]=/usr/bin/dbus-broker-launch --scope system ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }' 0
run_dbus_topology_case dbus_broker_structured_scope_equals broker none \
    '{ path=/usr/bin/dbus-broker-launch ; argv[]=/usr/bin/dbus-broker-launch --scope=system ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }' 0
run_dbus_topology_case dbus_broker_structured_equals_audit broker none \
    '{ path=/usr/bin/dbus-broker-launch ; argv[]=/usr/bin/dbus-broker-launch --scope=system --audit ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }' 0
run_dbus_topology_case dbus_broker_names_reordered broker names_reverse \
    '/usr/bin/dbus-broker-launch --scope system' 0
for dbus_daemon_argv0 in /usr/bin/dbus-daemon dbus-daemon @dbus-daemon; do
    run_dbus_topology_case \
        "dbus_daemon_structured_${dbus_daemon_argv0//[^[:alnum:]]/_}" daemon none \
        "{ path=/usr/bin/dbus-daemon ; argv[]=$dbus_daemon_argv0 $dbus_daemon_args ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }" 0
done
run_dbus_topology_case dbus_daemon_plain daemon none \
    "/usr/bin/dbus-daemon $dbus_daemon_args" 0
run_dbus_topology_case dbus_broker_merged_lib broker lib_fragment \
    '/usr/bin/dbus-broker-launch --scope system' 0 fragment_merged_lib
run_dbus_topology_case dbus_daemon_merged_lib daemon lib_fragment \
    "/usr/bin/dbus-daemon $dbus_daemon_args" 0 fragment_merged_lib
run_dbus_topology_case dbus_broker_independent_lib broker lib_fragment \
    '/usr/bin/dbus-broker-launch --scope system' 1 fragment_independent_lib
run_dbus_topology_case dbus_broker_newline_lib_alias broker lib_fragment \
    '/usr/bin/dbus-broker-launch --scope system' 1 fragment_newline_alias

for dbus_property in Id Names Following LoadState ActiveState FragmentPath DropInPaths ExecStart; do
    run_dbus_topology_case "dbus_missing_${dbus_property,,}" broker \
        "missing_$dbus_property" '/usr/bin/dbus-broker-launch --scope system' 1
    run_dbus_topology_case "dbus_duplicate_${dbus_property,,}" broker \
        "duplicate_$dbus_property" '/usr/bin/dbus-broker-launch --scope system' 1
done
run_dbus_topology_case dbus_unknown_property broker unknown \
    '/usr/bin/dbus-broker-launch --scope system' 1
run_dbus_topology_case dbus_following_unit broker following \
    '/usr/bin/dbus-broker-launch --scope system' 1
run_dbus_topology_case dbus_not_loaded broker not_loaded \
    '/usr/bin/dbus-broker-launch --scope system' 1
run_dbus_topology_case dbus_not_active broker inactive \
    '/usr/bin/dbus-broker-launch --scope system' 1
run_dbus_topology_case dbus_drop_in broker drop_in \
    '/usr/bin/dbus-broker-launch --scope system' 1
run_dbus_topology_case dbus_names_extra broker names_extra \
    '/usr/bin/dbus-broker-launch --scope system' 1
run_dbus_topology_case dbus_names_duplicate broker names_duplicate \
    '/usr/bin/dbus-broker-launch --scope system' 1
run_dbus_topology_case dbus_wrong_id broker wrong_id \
    '/usr/bin/dbus-broker-launch --scope system' 1
run_dbus_topology_case dbus_wrong_fragment broker wrong_fragment \
    '/usr/bin/dbus-broker-launch --scope system' 1
run_dbus_topology_case dbus_executable_mismatch broker none \
    "/usr/bin/dbus-daemon $dbus_daemon_args" 1
run_dbus_topology_case dbus_broker_extra_arg broker none \
    '/usr/bin/dbus-broker-launch --scope system --verbose' 1
run_dbus_topology_case dbus_broker_reordered broker none \
    '/usr/bin/dbus-broker-launch --audit --scope system' 1
run_dbus_topology_case dbus_daemon_reordered daemon none \
    '/usr/bin/dbus-daemon --system --nofork --address=systemd: --nopidfile --systemd-activation --syslog-only' 1
run_dbus_topology_case dbus_daemon_wrong_structured_path daemon none \
    "{ path=/usr/local/bin/dbus-daemon ; argv[]=/usr/bin/dbus-daemon $dbus_daemon_args ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }" 1
for dbus_asset_mutation in executable_missing executable_symlink \
    executable_hardlink executable_mode executable_parent_mode \
    fragment_symlink fragment_hardlink fragment_mode fragment_size \
    fragment_parent_mode; do
    run_dbus_topology_case "dbus_$dbus_asset_mutation" broker none \
        '/usr/bin/dbus-broker-launch --scope system' 1 "$dbus_asset_mutation"
done

run_dbus_definition_topology_case() {
    local name="$1"
    local expected_status="$2"
    local content="$3"
    local case_root="$tmp_root/$name"
    local definition="$case_root/usr/share/dbus-1/system-services/org.facelock.Daemon.service"
    local status

    mkdir -p "${definition%/*}"
    printf '%s\n' "$content" >"$definition"

    set +e
    bash -c '
        set -euo pipefail
        source "$1"
        FACELOCK_SOURCE_INSTALL_DBUS_LAYOUT_PREFIX="$2"
        IFS=: read -r FACELOCK_SOURCE_INSTALL_TRUST_UID \
            FACELOCK_SOURCE_INSTALL_TRUST_GID < <(stat -Lc "%u:%g" -- "$2")
        facelock_source_install_dbus_definition_delegates "$3"
    ' _ "$lifecycle_script" "$case_root" "$definition"
    status=$?
    set -e

    [ "$status" -eq "$expected_status" ] ||
        fail "$name exited $status, expected $expected_status"
}

run_private_dbus_name_precedence_case() (
    set -euo pipefail

    local case_name="$1"
    local definition_name="$2"
    local description="$3"
    local case_root="$tmp_root/$case_name"
    local higher_dir="$case_root/higher"
    local lower_dir="$case_root/lower"
    local higher_definition="$higher_dir/org.facelock.Daemon.service"
    local lower_definition="$lower_dir/org.facelock.Daemon.service"
    local higher_executable="$case_root/activate-higher"
    local lower_executable="$case_root/activate-lower"
    local higher_marker="$case_root/higher.marker"
    local lower_marker="$case_root/lower.marker"
    local socket_path="$case_root/bus"
    local config="$case_root/bus.conf"
    local bus_pid="" status

    cleanup_private_bus() {
        if [ -n "$bus_pid" ] && kill -0 "$bus_pid" 2>/dev/null; then
            kill "$bus_pid" 2>/dev/null || true
            wait "$bus_pid" 2>/dev/null || true
        fi
    }
    trap cleanup_private_bus EXIT HUP INT TERM

    mkdir -p "$higher_dir" "$lower_dir"
    printf '%s\n' \
        '#!/usr/bin/env bash' \
        "printf '%s\\n' higher >'$higher_marker'" >"$higher_executable"
    printf '%s\n' \
        '#!/usr/bin/env bash' \
        "printf '%s\\n' lower >'$lower_marker'" >"$lower_executable"
    chmod 755 "$higher_executable" "$lower_executable"
    printf '%s\n' \
        '[D-BUS Service]' \
        "Name=$definition_name" \
        "Exec=$higher_executable" \
        'SystemdService=facelock-daemon.service' >"$higher_definition"
    printf '%s\n' \
        '[D-BUS Service]' \
        'Name=org.facelock.Daemon' \
        "Exec=$lower_executable" >"$lower_definition"
    printf '%s\n' \
        '<busconfig>' \
        '  <type>session</type>' \
        "  <listen>unix:path=$socket_path</listen>" \
        '  <auth>EXTERNAL</auth>' \
        '  <policy context="default">' \
        '    <allow send_destination="*"/>' \
        '    <allow receive_sender="*"/>' \
        '    <allow own="*"/>' \
        '  </policy>' \
        "  <servicedir>$higher_dir</servicedir>" \
        "  <servicedir>$lower_dir</servicedir>" \
        '</busconfig>' >"$config"

    dbus-daemon --config-file="$config" --nofork --nopidfile \
        >"$case_root/dbus.log" 2>&1 &
    bus_pid=$!
    for _ in {1..100}; do
        [ -S "$socket_path" ] && break
        kill -0 "$bus_pid" 2>/dev/null || break
        sleep 0.01
    done
    [ -S "$socket_path" ] || {
        cat "$case_root/dbus.log" >&2
        fail "private D-Bus precedence bus did not start"
    }
    timeout 5s dbus-send --bus="unix:path=$socket_path" \
        --type=method_call --dest=org.facelock.Daemon \
        / org.freedesktop.DBus.Peer.Ping >/dev/null 2>&1 || true
    for _ in {1..100}; do
        [ -e "$lower_marker" ] && break
        sleep 0.01
    done
    [ -e "$lower_marker" ] || {
        cat "$case_root/dbus.log" >&2
        fail "private D-Bus did not select the lower exact direct definition"
    }
    [ ! -e "$higher_marker" ] ||
        fail "private D-Bus selected the higher $description definition"
    cleanup_private_bus
    bus_pid=""

    printf '%s\n' \
        '[D-BUS Service]' \
        "Name=$definition_name" \
        'Exec=/usr/bin/facelock daemon' \
        'User=root' \
        'SystemdService=facelock-daemon.service' >"$higher_definition"
    set +e
    bash -c '
        set -euo pipefail
        source "$1"
        FACELOCK_SOURCE_INSTALL_DBUS_LAYOUT_PREFIX="$2"
        IFS=: read -r FACELOCK_SOURCE_INSTALL_TRUST_UID \
            FACELOCK_SOURCE_INSTALL_TRUST_GID < <(stat -Lc "%u:%g" -- "$2")
        FACELOCK_SOURCE_INSTALL_DBUS_ASSETS=("$3" "$4")
        facelock_source_install_dbus_definition_is_safe
    ' _ "$lifecycle_script" "$case_root" \
        "$higher_definition" "$lower_definition"
    status=$?
    set -e
    [ "$status" -eq 1 ] ||
        fail "helper accepted a higher $description definition over lower direct activation"
)

run_private_dbus_name_precedence_case \
    dbus_private_trailing_name_precedence \
    'org.facelock.Daemon   ' trailing-space
run_private_dbus_name_precedence_case \
    dbus_private_leading_tab_name_precedence \
    $' \torg.facelock.Daemon' leading-tab

canonical_dbus_definition="$(printf '%s\n' \
    '[D-BUS Service]' \
    'Name=org.facelock.Daemon' \
    'Exec=/usr/bin/facelock daemon' \
    'User=root' \
    'SystemdService=facelock-daemon.service')"
run_dbus_definition_topology_case dbus_definition_exact 0 \
    "$canonical_dbus_definition"
run_dbus_definition_topology_case dbus_definition_comments 0 \
    "$(printf '%s\n' \
        '# trusted service definition' \
        '' \
        '[D-BUS Service]' \
        '# exact activation contract' \
        'Name=org.facelock.Daemon' \
        'Exec=/usr/bin/facelock daemon' \
        'User=root' \
        'SystemdService=facelock-daemon.service')"
run_dbus_definition_topology_case dbus_definition_compatible_whitespace 0 \
    "$(printf '%s\n' \
        '   ' \
        '[D-BUS Service]' \
        'Name   =   org.facelock.Daemon' \
        'Exec =   /usr/bin/facelock daemon' \
        'User  =  root' \
        'SystemdService = facelock-daemon.service')"
run_dbus_definition_topology_case dbus_definition_leading_name_tab 1 \
    "${canonical_dbus_definition/Name=org.facelock.Daemon/$'Name=\torg.facelock.Daemon'}"
run_dbus_definition_topology_case dbus_definition_leading_exec_tab 1 \
    "${canonical_dbus_definition/Exec=\/usr\/bin\/facelock daemon/$'Exec=\t/usr/bin/facelock daemon'}"
run_dbus_definition_topology_case dbus_definition_leading_user_tab 1 \
    "${canonical_dbus_definition/User=root/$'User=\troot'}"
run_dbus_definition_topology_case dbus_definition_leading_systemd_service_tab 1 \
    "${canonical_dbus_definition/SystemdService=facelock-daemon.service/$'SystemdService=\tfacelock-daemon.service'}"
run_dbus_definition_topology_case dbus_definition_trailing_name_spaces 1 \
    "${canonical_dbus_definition/Name=org.facelock.Daemon/Name=org.facelock.Daemon   }"
run_dbus_definition_topology_case dbus_definition_trailing_exec_spaces 1 \
    "${canonical_dbus_definition/Exec=\/usr\/bin\/facelock daemon/Exec=\/usr\/bin\/facelock daemon   }"
run_dbus_definition_topology_case dbus_definition_trailing_user_spaces 1 \
    "${canonical_dbus_definition/User=root/User=root   }"
run_dbus_definition_topology_case dbus_definition_trailing_systemd_service_spaces 1 \
    "${canonical_dbus_definition/SystemdService=facelock-daemon.service/SystemdService=facelock-daemon.service   }"
run_dbus_definition_topology_case dbus_definition_trailing_name_tab 1 \
    "${canonical_dbus_definition/Name=org.facelock.Daemon/$'Name=org.facelock.Daemon\t'}"
run_dbus_definition_topology_case dbus_definition_trailing_exec_tab 1 \
    "${canonical_dbus_definition/Exec=\/usr\/bin\/facelock daemon/$'Exec=/usr/bin/facelock daemon\t'}"
run_dbus_definition_topology_case dbus_definition_trailing_user_tab 1 \
    "${canonical_dbus_definition/User=root/$'User=root\t'}"
run_dbus_definition_topology_case dbus_definition_trailing_systemd_service_tab 1 \
    "${canonical_dbus_definition/SystemdService=facelock-daemon.service/$'SystemdService=facelock-daemon.service\t'}"
run_dbus_definition_topology_case dbus_definition_semicolon_comment 1 \
    $'; rejected comment\n'"$canonical_dbus_definition"
run_dbus_definition_topology_case dbus_definition_indented_comment 1 \
    $' # rejected comment\n'"$canonical_dbus_definition"
run_dbus_definition_topology_case dbus_definition_indented_section 1 \
    "${canonical_dbus_definition/'[D-BUS Service]'/' [D-BUS Service]'}"
run_dbus_definition_topology_case dbus_definition_leading_whitespace_key 1 \
    "${canonical_dbus_definition/Name=org.facelock.Daemon/ Name=org.facelock.Daemon}"
run_dbus_definition_topology_case dbus_definition_tab_before_equals 1 \
    "${canonical_dbus_definition/Name=org.facelock.Daemon/$'Name\t=org.facelock.Daemon'}"
run_dbus_definition_topology_case dbus_definition_missing_name 1 \
    "${canonical_dbus_definition//$'Name=org.facelock.Daemon\n'/}"
run_dbus_definition_topology_case dbus_definition_duplicate_name 1 \
    "${canonical_dbus_definition/Name=org.facelock.Daemon/$'Name=org.facelock.Daemon\nName=org.facelock.Daemon'}"
run_dbus_definition_topology_case dbus_definition_wrong_name 1 \
    "${canonical_dbus_definition/Name=org.facelock.Daemon/Name=org.facelock.Other}"
run_dbus_definition_topology_case dbus_definition_missing_exec 1 \
    "${canonical_dbus_definition//$'Exec=/usr/bin/facelock daemon\n'/}"
run_dbus_definition_topology_case dbus_definition_duplicate_exec 1 \
    "${canonical_dbus_definition/Exec=\/usr\/bin\/facelock daemon/$'Exec=/usr/bin/facelock daemon\nExec=/usr/bin/facelock daemon'}"
run_dbus_definition_topology_case dbus_definition_wrong_exec 1 \
    "${canonical_dbus_definition/Exec=\/usr\/bin\/facelock daemon/Exec=\/usr\/local\/bin\/facelock daemon}"
run_dbus_definition_topology_case dbus_definition_missing_user 1 \
    "${canonical_dbus_definition//$'User=root\n'/}"
run_dbus_definition_topology_case dbus_definition_duplicate_user 1 \
    "${canonical_dbus_definition/User=root/$'User=root\nUser=root'}"
run_dbus_definition_topology_case dbus_definition_wrong_user 1 \
    "${canonical_dbus_definition/User=root/User=facelock}"
run_dbus_definition_topology_case dbus_definition_missing_systemd_service 1 \
    "${canonical_dbus_definition//$'SystemdService=facelock-daemon.service'/}"
run_dbus_definition_topology_case dbus_definition_duplicate_systemd_service 1 \
    "$canonical_dbus_definition"$'\nSystemdService=facelock-daemon.service'
run_dbus_definition_topology_case dbus_definition_wrong_systemd_service 1 \
    "${canonical_dbus_definition/SystemdService=facelock-daemon.service/SystemdService=other.service}"
run_dbus_definition_topology_case dbus_definition_unknown_key 1 \
    "$canonical_dbus_definition"$'\nActivationPolicy=permissive'
run_dbus_definition_topology_case dbus_definition_duplicate_section 1 \
    "$canonical_dbus_definition"$'\n[D-BUS Service]\nName=org.facelock.Daemon\nExec=/usr/bin/facelock daemon\nUser=root\nSystemdService=facelock-daemon.service'
run_dbus_definition_topology_case dbus_definition_extra_section 1 \
    "$canonical_dbus_definition"$'\n[Other]\nName=org.facelock.Daemon'
run_dbus_definition_topology_case dbus_definition_pre_section_known_key 1 \
    $'Exec=/usr/bin/false\n'"$canonical_dbus_definition"
run_dbus_definition_topology_case dbus_definition_pre_section_unknown_key 1 \
    $'ActivationPolicy=permissive\n'"$canonical_dbus_definition"

run_dbus_definition_raw_byte_case() {
    local name="$1"
    local mutation="$2"
    local expected_status="${3:-1}"
    local case_root="$tmp_root/$name"
    local definition="$case_root/usr/share/dbus-1/system-services/org.facelock.Daemon.service"
    local payload status

    case "$mutation" in
        malformed_preamble)
            payload='malformed preamble\n[D-BUS Service]\nName=org.facelock.Daemon\nExec=/usr/bin/facelock daemon\nUser=root\nSystemdService=facelock-daemon.service\n'
            ;;
        ff_comment)
            payload='# invalid byte: \xff\n[D-BUS Service]\nName=org.facelock.Daemon\nExec=/usr/bin/facelock daemon\nUser=root\nSystemdService=facelock-daemon.service\n'
            ;;
        truncated_multibyte_comment)
            payload='# truncated sequence: \xc3\n[D-BUS Service]\nName=org.facelock.Daemon\nExec=/usr/bin/facelock daemon\nUser=root\nSystemdService=facelock-daemon.service\n'
            ;;
        canonical_crlf)
            payload='[D-BUS Service]\r\nName=org.facelock.Daemon\r\nExec=/usr/bin/facelock daemon\r\nUser=root\r\nSystemdService=facelock-daemon.service\r\n'
            ;;
        embedded_cr_comment)
            payload='# embedded\rreturn\n[D-BUS Service]\nName=org.facelock.Daemon\nExec=/usr/bin/facelock daemon\nUser=root\nSystemdService=facelock-daemon.service\n'
            ;;
        control_comment)
            payload='# control: \x01\n[D-BUS Service]\nName=org.facelock.Daemon\nExec=/usr/bin/facelock daemon\nUser=root\nSystemdService=facelock-daemon.service\n'
            ;;
        unterminated_trailing_cr)
            payload='[D-BUS Service]\nName=org.facelock.Daemon\nExec=/usr/bin/facelock daemon\nUser=root\nSystemdService=facelock-daemon.service\r'
            ;;
        nul_name_key)
            payload='[D-BUS Service]\nNa\0me=org.facelock.Daemon\nExec=/usr/bin/facelock daemon\nUser=root\nSystemdService=facelock-daemon.service\n'
            ;;
        nul_exec_key)
            payload='[D-BUS Service]\nName=org.facelock.Daemon\nEx\0ec=/usr/bin/facelock daemon\nUser=root\nSystemdService=facelock-daemon.service\n'
            ;;
        nul_user_key)
            payload='[D-BUS Service]\nName=org.facelock.Daemon\nExec=/usr/bin/facelock daemon\nUs\0er=root\nSystemdService=facelock-daemon.service\n'
            ;;
        nul_systemd_service_key)
            payload='[D-BUS Service]\nName=org.facelock.Daemon\nExec=/usr/bin/facelock daemon\nUser=root\nSystemd\0Service=facelock-daemon.service\n'
            ;;
        nul_name_value)
            payload='[D-BUS Service]\nName=org.facelock.\0Daemon\nExec=/usr/bin/facelock daemon\nUser=root\nSystemdService=facelock-daemon.service\n'
            ;;
        nul_exec_value)
            payload='[D-BUS Service]\nName=org.facelock.Daemon\nExec=/usr/bin/facelock\0 daemon\nUser=root\nSystemdService=facelock-daemon.service\n'
            ;;
        nul_user_value)
            payload='[D-BUS Service]\nName=org.facelock.Daemon\nExec=/usr/bin/facelock daemon\nUser=ro\0ot\nSystemdService=facelock-daemon.service\n'
            ;;
        nul_systemd_service_value)
            payload='[D-BUS Service]\nName=org.facelock.Daemon\nExec=/usr/bin/facelock daemon\nUser=root\nSystemdService=facelock-daemon.\0service\n'
            ;;
        *) fail "$name has unknown raw D-Bus mutation $mutation" ;;
    esac
    mkdir -p "${definition%/*}"
    printf '%b' "$payload" >"$definition"

    set +e
    bash -c '
        set -euo pipefail
        source "$1"
        FACELOCK_SOURCE_INSTALL_DBUS_LAYOUT_PREFIX="$2"
        IFS=: read -r FACELOCK_SOURCE_INSTALL_TRUST_UID \
            FACELOCK_SOURCE_INSTALL_TRUST_GID < <(stat -Lc "%u:%g" -- "$2")
        facelock_source_install_dbus_definition_delegates "$3"
    ' _ "$lifecycle_script" "$case_root" "$definition"
    status=$?
    set -e

    [ "$status" -eq "$expected_status" ] ||
        fail "$name exited $status, expected $expected_status for raw bytes"
}

run_dbus_definition_raw_byte_case dbus_definition_malformed_preamble \
    malformed_preamble
run_dbus_definition_raw_byte_case dbus_definition_ff_comment ff_comment
run_dbus_definition_raw_byte_case dbus_definition_truncated_multibyte_comment \
    truncated_multibyte_comment
run_dbus_definition_raw_byte_case dbus_definition_canonical_crlf \
    canonical_crlf 0
run_dbus_definition_raw_byte_case dbus_definition_embedded_cr_comment \
    embedded_cr_comment
run_dbus_definition_raw_byte_case dbus_definition_control_comment \
    control_comment
run_dbus_definition_raw_byte_case dbus_definition_unterminated_trailing_cr \
    unterminated_trailing_cr
for dbus_definition_nul_mutation in nul_name_key nul_exec_key nul_user_key \
    nul_systemd_service_key nul_name_value nul_exec_value nul_user_value \
    nul_systemd_service_value; do
    run_dbus_definition_raw_byte_case \
        "dbus_definition_$dbus_definition_nul_mutation" \
        "$dbus_definition_nul_mutation"
done

inactive_barrier_success_log="$(printf '%s\n' \
    "$show_command" \
    "$dbus_show_command" \
    "$dbus_reload_command" \
    "$dbus_owner_command" \
    'systemctl daemon-reload' \
    "$barrier_show_command" \
    'systemctl stop facelock-daemon.service' \
    "$barrier_show_command" \
    "$dbus_owner_command" \
    'systemctl start facelock-daemon.service' \
    'write' \
    'systemctl daemon-reload' \
    "$dbus_reload_command" \
    "$barrier_show_command" \
    "$dbus_owner_command" \
    'systemctl daemon-reload' \
    "$show_command" \
    "$dbus_owner_command" \
    "$show_command" \
    "$dbus_owner_command")"

run_case active loaded active disabled 0 present success none yes "$(printf '%s\n' \
    "$show_command" \
    "$dbus_show_command" \
    "$dbus_reload_command" \
    "$dbus_owner_command" \
    'systemctl daemon-reload' \
    "$barrier_show_command" \
    'systemctl stop facelock-daemon.service' \
    "$barrier_show_command" \
    "$dbus_owner_command" \
    'systemctl start facelock-daemon.service' \
    'write' \
    'systemctl daemon-reload' \
    "$dbus_reload_command" \
    "$barrier_show_command" \
    "$dbus_owner_command" \
    'systemctl daemon-reload' \
    "$show_command" \
    "$dbus_owner_command" \
    "$show_command" \
    "$dbus_owner_command" \
    "$show_command" \
    "$dbus_owner_command" \
    'systemctl start facelock-daemon.service' \
    "$show_command" \
    "$dbus_owner_command")"

run_case inactive_disabled loaded inactive disabled 0 present success none yes "$(printf '%s\n' \
    "$show_command" \
    "$dbus_show_command" \
    "$dbus_reload_command" \
    "$dbus_owner_command" \
    'systemctl daemon-reload' \
    "$barrier_show_command" \
    'systemctl stop facelock-daemon.service' \
    "$barrier_show_command" \
    "$dbus_owner_command" \
    'systemctl start facelock-daemon.service' \
    'write' \
    'systemctl daemon-reload' \
    "$dbus_reload_command" \
        "$barrier_show_command" \
        "$dbus_owner_command" \
        'systemctl daemon-reload' \
        "$show_command" \
        "$dbus_owner_command" \
        "$show_command" \
        "$dbus_owner_command")"

run_case probe_error loaded inactive disabled 1 present failure none no "$(printf '%s\n' \
    "$show_command")"

run_case transitional loaded activating enabled 0 present failure none no "$(printf '%s\n' \
    "$show_command")"

run_case failed_state loaded failed enabled 0 present failure none no "$(printf '%s\n' \
    "$show_command")"

run_case bad_unit_file_state loaded inactive bad 0 present failure none no "$(printf '%s\n' \
    "$show_command")"

run_case unknown_unit_file_state loaded inactive future-state 0 present failure none no "$(printf '%s\n' \
    "$show_command")"

run_case missing_unit_file_state loaded inactive '' 0 present failure none no "$(printf '%s\n' \
    "$show_command")"

run_case first_install not-found inactive '' 0 absent success none yes "$(printf '%s\n' \
    "$show_command" \
    "$dbus_show_command" \
    "$dbus_reload_command" \
    "$dbus_owner_command" \
    'systemctl daemon-reload' \
    "$barrier_show_command" \
    'systemctl stop facelock-daemon.service' \
    "$barrier_show_command" \
    "$dbus_owner_command" \
    'systemctl start facelock-daemon.service' \
    'write' \
    'systemctl daemon-reload' \
    "$dbus_reload_command" \
    "$barrier_show_command" \
    "$dbus_owner_command" \
    'systemctl daemon-reload' \
    "$show_command" \
    "$dbus_owner_command" \
    "$show_command" \
    "$dbus_owner_command")"

run_case inconsistent_not_found not-found inactive '' 0 present failure none no "$(printf '%s\n' \
    "$show_command")"

run_case first_install_alternate not-found inactive '' 0 alternate failure none no "$(printf '%s\n' \
    "$show_command")"

run_case inactive_runtime_mask masked inactive masked-runtime 0 present success runtime yes "$(printf '%s\n' \
    "$show_command" \
    "$dbus_show_command" \
    "$dbus_reload_command" \
    "$dbus_owner_command" \
    'systemctl daemon-reload' \
    "$barrier_show_command" \
    'systemctl stop facelock-daemon.service' \
    "$barrier_show_command" \
    "$dbus_owner_command" \
    'systemctl start facelock-daemon.service' \
    'write' \
    'systemctl daemon-reload' \
    "$dbus_reload_command" \
    "$barrier_show_command" \
    "$dbus_owner_command" \
    'systemctl daemon-reload' \
    "$show_command" \
    "$dbus_owner_command" \
    "$show_command" \
    "$dbus_owner_command")"

run_case inactive_persistent_mask masked inactive masked 0 present success persistent yes "$(printf '%s\n' \
    "$show_command" \
    "$dbus_show_command" \
    "$dbus_reload_command" \
    "$dbus_owner_command" \
    'systemctl daemon-reload' \
    "$barrier_show_command" \
    'systemctl stop facelock-daemon.service' \
    "$barrier_show_command" \
    "$dbus_owner_command" \
    'systemctl start facelock-daemon.service' \
    'write' \
    'systemctl daemon-reload' \
    "$dbus_reload_command" \
    "$barrier_show_command" \
    "$dbus_owner_command" \
    'systemctl daemon-reload' \
    "$show_command" \
    "$dbus_owner_command" \
    "$show_command" \
    "$dbus_owner_command")"

run_case inactive_runtime_regular_mask masked inactive masked-runtime 0 present \
    success runtime-regular yes "$inactive_barrier_success_log"
run_case inactive_persistent_regular_mask masked inactive masked 0 present \
    success persistent-regular yes "$inactive_barrier_success_log"
run_case inactive_both_symlink_masks masked inactive masked 0 present \
    success both-symlink yes "$inactive_barrier_success_log"
run_case inactive_both_regular_masks masked inactive masked 0 present \
    success both-regular yes "$inactive_barrier_success_log"
run_case inactive_persistent_symlink_runtime_regular_masks masked inactive masked \
    0 present success persistent-symlink-runtime-regular yes \
    "$inactive_barrier_success_log"
run_case inactive_persistent_regular_runtime_symlink_masks masked inactive masked \
    0 present success persistent-regular-runtime-symlink yes \
    "$inactive_barrier_success_log"

run_case stale_runtime_symlink_mask loaded inactive disabled 0 present \
    success runtime-symlink yes "$inactive_barrier_success_log"
run_case stale_runtime_regular_mask loaded inactive disabled 0 present \
    success runtime-regular yes "$inactive_barrier_success_log"
run_case stale_persistent_symlink_mask loaded inactive disabled 0 present \
    success persistent-symlink yes "$inactive_barrier_success_log"
run_case stale_persistent_regular_mask loaded inactive disabled 0 present \
    success persistent-regular yes "$inactive_barrier_success_log"
run_case stale_both_masks loaded inactive disabled 0 present \
    success both-symlink yes "$inactive_barrier_success_log"
run_case stale_static_persistent_mask loaded inactive static 0 present \
    success persistent-symlink yes "$inactive_barrier_success_log"

run_case loaded_inactive_persistent_mask loaded inactive masked 0 present failure persistent no "$(printf '%s\n' \
    "$show_command")"

run_case loaded_inactive_runtime_mask_false_schema loaded inactive masked-runtime 0 \
    present failure runtime no "$(printf '%s\n' "$show_command")"

run_case active_admin_mask loaded active disabled 0 present failure runtime no "$(printf '%s\n' \
    "$show_command")"

run_case active_persistent_admin_mask loaded active enabled 0 present failure \
    persistent no "$(printf '%s\n' "$show_command")"
run_case active_effective_mask masked active masked-runtime 0 present failure \
    runtime no "$(printf '%s\n' "$show_command")"
run_case not_found_with_mask not-found inactive '' 0 absent failure runtime no \
    "$(printf '%s\n' "$show_command")"
run_case manager_mask_without_disk masked inactive masked 0 present failure none no \
    "$(printf '%s\n' "$show_command")"
run_case manager_runtime_disk_persistent masked inactive masked-runtime 0 present \
    failure persistent no "$(printf '%s\n' "$show_command")"
run_case manager_persistent_disk_runtime masked inactive masked 0 present failure \
    runtime no "$(printf '%s\n' "$show_command")"

run_case runtime_override_preserved_by_identity loaded inactive disabled 0 present \
    success runtime-override yes "$inactive_barrier_success_log"
run_case persistent_override_preserved loaded inactive enabled 0 present \
    success persistent-override yes "$inactive_barrier_success_log"
run_case persistent_override_beats_runtime_mask loaded inactive enabled 0 present \
    success persistent-override-runtime-mask yes "$inactive_barrier_success_log"
run_case persistent_mask_beats_runtime_override masked inactive masked 0 present \
    success persistent-mask-runtime-override yes "$inactive_barrier_success_log"
run_case dangling_runtime_refused loaded inactive disabled 0 present failure \
    dangling-runtime no ''
run_case untrusted_runtime_refused loaded inactive disabled 0 present failure \
    untrusted-runtime no ''

run_case persistent_control_conflict_with_mask loaded inactive disabled 0 present \
    failure runtime no '' persistent
run_case runtime_control_conflict_with_mask loaded inactive disabled 0 present \
    failure persistent no '' runtime

run_revalidation_refusal_case() {
    local name="$1"
    local fault="$2"
    local case_root="$tmp_root/$name"
    local runtime_mask="$case_root/run/systemd/system/facelock-daemon.service"
    local barrier="$case_root/run/systemd/system.control/facelock-daemon.service"
    local status

    mkdir -p "$case_root/etc/systemd/system" \
        "$case_root/etc/systemd/system.control" \
        "$case_root/run/systemd/system" \
        "$case_root/run/systemd/system.control" "$case_root/assets"
    write_standard_dbus_config "$case_root"
    : >"$case_root/assets/facelock-daemon.service"
    write_dbus_service "$case_root/assets/org.facelock.Daemon.service"
    : >"$case_root/actual"
    printf '%s\n' none >"$case_root/mask-state"
    printf '%s\n' none >"$case_root/manager-mask-state"
    : >"$case_root/manager-fragment-path"
    case "$fault" in
        mask_before_create | mask_after_stop)
            ln -s /dev/null "$runtime_mask"
            printf '%s\n' runtime >"$case_root/mask-state"
            ;;
        ordinary_content_before_create)
            printf '%s\n' '[Service]' \
                'ExecStart=/usr/bin/facelock daemon' >"$runtime_mask"
            ;;
    esac

    set +e
    PATH="$tmp_root/bin:$PATH" \
        FACELOCK_SYSTEMCTL_LOG="$case_root/actual" \
        FACELOCK_SHOW_STATUS=0 \
        FACELOCK_LOAD_STATE=loaded \
        FACELOCK_ACTIVE_STATE=inactive \
        FACELOCK_UNIT_FILE_STATE=disabled \
        FACELOCK_MASK_STATE="$case_root/mask-state" \
        FACELOCK_MANAGER_MASK_STATE="$case_root/manager-mask-state" \
        FACELOCK_MANAGER_FRAGMENT_PATH="$case_root/manager-fragment-path" \
        FACELOCK_RUNTIME_DIR="$case_root/run/systemd/system" \
        FACELOCK_PERSISTENT_CONTROL_DIR="$case_root/etc/systemd/system.control" \
        FACELOCK_RUNTIME_CONTROL_DIR="$case_root/run/systemd/system.control" \
        FACELOCK_REQUIRE_PRESTOP_PROOF=true \
        FACELOCK_BARRIER_SNAPSHOT_MUTATION="$(case "$fault" in \
            fragment_blank) printf blank ;; fragment_wrong) printf wrong ;; \
            fragment_duplicate) printf duplicate ;; *) printf none ;; esac)" \
        FACELOCK_MUTATE_BARRIER_ON_RELOAD="$([ "$fault" = barrier_content ] && \
            printf '%s' "$barrier")" \
        FACELOCK_MUTATE_MASK_ON_OWNER="$([ "$fault" = mask_before_create ] && \
            printf '%s' "$runtime_mask")" \
        FACELOCK_MUTATE_ORDINARY_ON_OWNER="$([ "$fault" = ordinary_content_before_create ] && \
            printf '%s' "$runtime_mask")" \
        FACELOCK_FRAGMENT_PATH_OVERRIDE="$([ "$fault" = ordinary_content_before_create ] && \
            printf '%s' "$runtime_mask")" \
        FACELOCK_MUTATE_MASK_AFTER_STOP="$([ "$fault" = mask_after_stop ] && \
            printf '%s' "$runtime_mask")" \
        FACELOCK_OWNER_AFTER_STOP="$([ "$fault" = owner_after_stop ] && \
            printf true || printf false)" \
        bash -c '
            set -euo pipefail
            source "$1"
            facelock_source_install_begin_daemon "$2" "$3" "$4" "$5"
            printf "%s\n" write >>"$FACELOCK_SYSTEMCTL_LOG"
        ' _ "$lifecycle_script" "$case_root/run/systemd/system" \
        "$case_root/assets/facelock-daemon.service" \
        "$case_root/assets/org.facelock.Daemon.service" \
        "$runtime_mask" \
        2>"$case_root/stderr"
    status=$?
    set -e

    [ "$status" -eq 1 ] || fail "$name did not fail closed"
    ! grep -Fxq write "$case_root/actual" || fail "$name crossed the write boundary"
    case "$fault" in
        mask_after_stop | owner_after_stop)
            grep -Fxq 'systemctl stop facelock-daemon.service' \
                "$case_root/actual" || fail "$name did not reach its post-stop check"
            ;;
        *)
            ! grep -Fxq 'systemctl stop facelock-daemon.service' \
                "$case_root/actual" || fail "$name stopped before its pre-stop proof"
            ;;
    esac
    assert_lock_available "$name" "$case_root/run/facelock/lifecycle.lock"
}

run_revalidation_refusal_case barrier_fragment_blank fragment_blank
run_revalidation_refusal_case barrier_fragment_wrong fragment_wrong
run_revalidation_refusal_case barrier_fragment_duplicate fragment_duplicate
run_revalidation_refusal_case barrier_content_changed barrier_content
run_revalidation_refusal_case mask_changed_before_barrier mask_before_create
run_revalidation_refusal_case ordinary_changed_before_barrier \
    ordinary_content_before_create
run_revalidation_refusal_case mask_changed_after_stop mask_after_stop
run_revalidation_refusal_case dbus_owned_after_stop owner_after_stop

run_initial_reload_retry_case() {
    local failures="$1"
    local case_root="$tmp_root/initial_reload_retry_$failures"
    local attempts status

    mkdir -p "$case_root/etc/systemd/system.control" \
        "$case_root/run/systemd/system" \
        "$case_root/run/systemd/system.control" "$case_root/assets"
    write_standard_dbus_config "$case_root"
    : >"$case_root/assets/facelock-daemon.service"
    write_dbus_service "$case_root/assets/org.facelock.Daemon.service"
    : >"$case_root/actual"
    printf '%s\n' none >"$case_root/mask-state"
    printf '%s\n' none >"$case_root/manager-mask-state"
    : >"$case_root/manager-fragment-path"
    printf '%s\n' "$failures" >"$case_root/failures-remaining"

    set +e
    PATH="$tmp_root/bin:$PATH" \
        FACELOCK_SYSTEMCTL_LOG="$case_root/actual" \
        FACELOCK_SHOW_STATUS=0 \
        FACELOCK_LOAD_STATE=loaded \
        FACELOCK_ACTIVE_STATE=inactive \
        FACELOCK_UNIT_FILE_STATE=disabled \
        FACELOCK_MASK_STATE="$case_root/mask-state" \
        FACELOCK_MANAGER_MASK_STATE="$case_root/manager-mask-state" \
        FACELOCK_MANAGER_FRAGMENT_PATH="$case_root/manager-fragment-path" \
        FACELOCK_RUNTIME_DIR="$case_root/run/systemd/system" \
        FACELOCK_PERSISTENT_CONTROL_DIR="$case_root/etc/systemd/system.control" \
        FACELOCK_RUNTIME_CONTROL_DIR="$case_root/run/systemd/system.control" \
        FACELOCK_REQUIRE_PRESTOP_PROOF=true \
        FACELOCK_FAIL_BEFORE_WRITE=true \
        FACELOCK_FAIL_COMMAND=daemon-reload \
        FACELOCK_FAILURES_REMAINING="$case_root/failures-remaining" \
        bash -c '
            set -euo pipefail
            source "$1"
            facelock_source_install_begin_daemon "$2" "$3" "$4"
            printf "%s\n" write >>"$FACELOCK_SYSTEMCTL_LOG"
            facelock_source_install_complete_daemon "$2"
        ' _ "$lifecycle_script" "$case_root/run/systemd/system" \
        "$case_root/assets/facelock-daemon.service" \
        "$case_root/assets/org.facelock.Daemon.service" \
        2>"$case_root/stderr"
    status=$?
    set -e

    [ "$status" -eq 0 ] || {
        cat "$case_root/stderr" >&2
        fail "initial reload with $failures failures did not recover"
    }
    attempts="$(awk '
        $0 == "systemctl stop facelock-daemon.service" { exit }
        $0 == "systemctl daemon-reload" { count++ }
        END { print count + 0 }
    ' "$case_root/actual")"
    [ "$attempts" -eq "$((failures + 1))" ] ||
        fail "initial reload with $failures failures used $attempts attempts"
    grep -Fxq write "$case_root/actual" ||
        fail "initial reload retry $failures never reached writes"
    assert_lock_available "initial_reload_retry_$failures" \
        "$case_root/run/facelock/lifecycle.lock"
}

run_initial_reload_retry_case 1
run_initial_reload_retry_case 2

run_case runtime_override_preserved loaded inactive disabled 0 present success runtime yes "$(printf '%s\n' \
    "$show_command" \
    "$dbus_show_command" \
    "$dbus_reload_command" \
    "$dbus_owner_command" \
    'systemctl daemon-reload' \
    "$barrier_show_command" \
    'systemctl stop facelock-daemon.service' \
    "$barrier_show_command" \
    "$dbus_owner_command" \
    'systemctl start facelock-daemon.service' \
    'write' \
    'systemctl daemon-reload' \
    "$dbus_reload_command" \
    "$barrier_show_command" \
    "$dbus_owner_command" \
    'systemctl daemon-reload' \
    "$show_command" \
    "$dbus_owner_command" \
    "$show_command" \
    "$dbus_owner_command")"

run_case persistent_control_conflict loaded inactive disabled 0 present failure none no '' persistent

run_case runtime_control_conflict loaded inactive disabled 0 present failure none no '' runtime

run_case direct_dbus_definition loaded inactive disabled 0 direct failure none no "$(printf '%s\n' \
    "$show_command" \
    "$dbus_show_command")"

run_case symlinked_loaded_unit loaded inactive disabled 0 unit_symlink failure none no \
    "$show_command"

run_selected_definition_cardinality_case() {
    local name="$1"
    local layout="$2"
    local case_root="$tmp_root/$name"
    local status

    mkdir -p "$case_root/run/systemd/system" "$case_root/run/facelock" \
        "$case_root/assets"
    write_standard_dbus_config "$case_root"
    : >"$case_root/assets/facelock-daemon.service"
    case "$layout" in
        zero) ;;
        duplicate)
            write_dbus_service \
                "$case_root/assets/org.facelock.Daemon.service"
            write_dbus_service "$case_root/assets/alternate.service"
            ;;
    esac
    : >"$case_root/actual"
    printf '%s\n' none >"$case_root/mask-state"
    printf '%s\n' none >"$case_root/manager-mask-state"

    set +e
    PATH="$tmp_root/bin:$PATH" \
        FACELOCK_SYSTEMCTL_LOG="$case_root/actual" \
        FACELOCK_SHOW_STATUS=0 \
        FACELOCK_LOAD_STATE=loaded \
        FACELOCK_ACTIVE_STATE=inactive \
        FACELOCK_UNIT_FILE_STATE=disabled \
        FACELOCK_MASK_STATE="$case_root/mask-state" \
        FACELOCK_MANAGER_MASK_STATE="$case_root/manager-mask-state" \
        FACELOCK_RUNTIME_DIR="$case_root/run/systemd/system" \
        bash -c '
            set -euo pipefail
            source "$1"
            facelock_source_install_begin_daemon "$2" "$3" "$4"
            printf "%s\n" write >>"$FACELOCK_SYSTEMCTL_LOG"
        ' _ \
        "$lifecycle_script" \
        "$case_root/run/systemd/system" \
        "$case_root/assets/facelock-daemon.service" \
        "$case_root/assets/org.facelock.Daemon.service" \
        2>"$case_root/stderr"
    status=$?
    set -e

    [ "$status" -eq 1 ] || fail "$name did not fail closed"
    [ "$(cat "$case_root/actual")" = "$(printf '%s\n' \
        "$show_command" "$dbus_show_command")" ] ||
        fail "$name crossed the lifecycle mutation boundary"
    grep -Fq 'selected D-Bus activation definition' "$case_root/stderr" ||
        fail "$name lacked a selected-definition diagnostic"
    assert_lock_available "$name" "$case_root/run/facelock/lifecycle.lock"
}

run_selected_definition_cardinality_case dbus_zero_selected zero
run_selected_definition_cardinality_case dbus_duplicate_selected duplicate

run_malformed_snapshot_case() {
    local name="$1"
    local target="$2"
    local snapshot="$3"
    local expected_diagnostic="${4:-}"
    local asset_layout="${5:-present}"
    local case_root="$tmp_root/$name"
    local status

    snapshot="${snapshot//@CASE_ROOT@/$case_root}"
    mkdir -p "$case_root/etc/systemd/system" \
        "$case_root/run/systemd/system" "$case_root/assets"
    write_standard_dbus_config "$case_root"
    case "$asset_layout" in
        present)
            : >"$case_root/assets/facelock-daemon.service"
            write_dbus_service "$case_root/assets/org.facelock.Daemon.service"
            ;;
        absent) ;;
        *) fail "$name has unknown asset layout $asset_layout" ;;
    esac
    if [ "$target" = service ] &&
        grep -Fqx 'LoadState=masked' <<<"$snapshot"; then
        if grep -Fq "$case_root/run/systemd/system/facelock-daemon.service" \
            <<<"$snapshot"; then
            ln -s /dev/null \
                "$case_root/run/systemd/system/facelock-daemon.service"
        else
            ln -s /dev/null \
                "$case_root/etc/systemd/system/facelock-daemon.service"
        fi
    fi
    : >"$case_root/actual"

    set +e
    if [ "$target" = service ]; then
        PATH="$tmp_root/bin:$PATH" \
            FACELOCK_SYSTEMCTL_LOG="$case_root/actual" \
            FACELOCK_SHOW_STATUS=0 \
            FACELOCK_LOAD_STATE=loaded \
            FACELOCK_ACTIVE_STATE=inactive \
            FACELOCK_UNIT_FILE_STATE=disabled \
            FACELOCK_SERVICE_SNAPSHOT_OVERRIDE="$snapshot" \
            FACELOCK_RUNTIME_DIR="$case_root/run/systemd/system" \
            bash -c 'set -euo pipefail; source "$1"; facelock_source_install_begin_daemon "$2" "$3" "$4"' _ \
            "$lifecycle_script" "$case_root/run/systemd/system" \
            "$case_root/assets/facelock-daemon.service" \
            "$case_root/assets/org.facelock.Daemon.service" \
            2>"$case_root/stderr"
    else
        PATH="$tmp_root/bin:$PATH" \
            FACELOCK_SYSTEMCTL_LOG="$case_root/actual" \
            FACELOCK_SHOW_STATUS=0 \
            FACELOCK_LOAD_STATE=loaded \
            FACELOCK_ACTIVE_STATE=inactive \
            FACELOCK_UNIT_FILE_STATE=disabled \
            FACELOCK_DBUS_SNAPSHOT_OVERRIDE="$snapshot" \
            FACELOCK_RUNTIME_DIR="$case_root/run/systemd/system" \
            bash -c 'set -euo pipefail; source "$1"; facelock_source_install_begin_daemon "$2" "$3" "$4"' _ \
            "$lifecycle_script" "$case_root/run/systemd/system" \
            "$case_root/assets/facelock-daemon.service" \
            "$case_root/assets/org.facelock.Daemon.service" \
            2>"$case_root/stderr"
    fi
    status=$?
    set -e

    [ "$status" -eq 1 ] || fail "$name accepted a malformed manager snapshot"
    if [ -n "$expected_diagnostic" ]; then
        grep -Fq "$expected_diagnostic" "$case_root/stderr" ||
            fail "$name lacked its state-schema diagnostic"
    fi
    if [ "$target" = service ]; then
        [ "$(cat "$case_root/actual")" = "$show_command" ] ||
            fail "$name crossed the lifecycle mutation boundary"
    else
        [ "$(cat "$case_root/actual")" = "$(printf '%s\n' \
            "$show_command" "$dbus_show_command")" ] ||
            fail "$name crossed the lifecycle mutation boundary"
    fi
    assert_lock_available "$name" "$case_root/run/facelock/lifecycle.lock"
}

run_malformed_snapshot_case service_duplicate_load service "$(printf '%s\n' \
    'LoadState=not-found' 'LoadState=loaded' 'ActiveState=inactive' \
    'UnitFileState=disabled' 'FragmentPath=/usr/lib/systemd/system/facelock-daemon.service' \
    'ExecStart=/usr/bin/facelock daemon' 'DropInPaths=')"
run_malformed_snapshot_case service_missing_active service "$(printf '%s\n' \
    'LoadState=loaded' 'UnitFileState=disabled')"
run_malformed_snapshot_case loaded_missing_exec_start service "$(printf '%s\n' \
    'LoadState=loaded' 'ActiveState=inactive' 'UnitFileState=disabled' \
    'FragmentPath=/usr/lib/systemd/system/facelock-daemon.service' \
    'DropInPaths=')" 'incomplete loaded-unit state'
run_malformed_snapshot_case loaded_empty_exec_start service "$(printf '%s\n' \
    'LoadState=loaded' 'ActiveState=inactive' 'UnitFileState=disabled' \
    'FragmentPath=/usr/lib/systemd/system/facelock-daemon.service' \
    'ExecStart=' 'DropInPaths=')" 'incomplete loaded-unit state'
run_malformed_snapshot_case loaded_duplicate_exec_start service "$(printf '%s\n' \
    'LoadState=loaded' 'ActiveState=inactive' 'UnitFileState=disabled' \
    'FragmentPath=/usr/lib/systemd/system/facelock-daemon.service' \
    'ExecStart=/usr/bin/facelock daemon' \
    'ExecStart=/usr/bin/facelock daemon' 'DropInPaths=')" \
    'duplicate or missing unit-state properties'
run_malformed_snapshot_case not_found_duplicate_active service "$(printf '%s\n' \
    'LoadState=not-found' 'ActiveState=inactive' 'ActiveState=inactive' \
    'UnitFileState=' 'FragmentPath=' 'DropInPaths=')" \
    'duplicate or missing unit-state properties' absent
run_malformed_snapshot_case not_found_unexpected_exec_start service "$(printf '%s\n' \
    'LoadState=not-found' 'ActiveState=inactive' 'UnitFileState=' \
    'FragmentPath=' 'ExecStart=/usr/bin/facelock daemon' 'DropInPaths=')" \
    'inconsistent not-found unit state' absent
run_malformed_snapshot_case not_found_unexpected_empty_exec_start service "$(printf '%s\n' \
    'LoadState=not-found' 'ActiveState=inactive' 'UnitFileState=' \
    'FragmentPath=' 'ExecStart=' 'DropInPaths=')" \
    'inconsistent not-found unit state' absent
run_malformed_snapshot_case not_found_unexpected_unit_file_state service "$(printf '%s\n' \
    'LoadState=not-found' 'ActiveState=inactive' 'UnitFileState=not-found' \
    'FragmentPath=' 'DropInPaths=')" 'inconsistent not-found unit state' absent
run_malformed_snapshot_case not_found_unexpected_fragment service "$(printf '%s\n' \
    'LoadState=not-found' 'ActiveState=inactive' 'UnitFileState=' \
    'FragmentPath=@CASE_ROOT@/usr/lib/systemd/system/facelock-daemon.service' \
    'DropInPaths=')" 'inconsistent not-found unit state' absent
run_malformed_snapshot_case not_found_unexpected_drop_in service "$(printf '%s\n' \
    'LoadState=not-found' 'ActiveState=inactive' 'UnitFileState=' \
    'FragmentPath=' \
    'DropInPaths=@CASE_ROOT@/etc/systemd/system/facelock-daemon.service.d/override.conf')" \
    'inconsistent not-found unit state' absent
run_malformed_snapshot_case not_found_unexpected_active_state service "$(printf '%s\n' \
    'LoadState=not-found' 'ActiveState=active' 'UnitFileState=' \
    'FragmentPath=' 'DropInPaths=')" 'inconsistent not-found unit state' absent
run_malformed_snapshot_case masked_duplicate_fragment service "$(printf '%s\n' \
    'LoadState=masked' 'ActiveState=inactive' 'UnitFileState=masked' \
    'FragmentPath=@CASE_ROOT@/etc/systemd/system/facelock-daemon.service' \
    'FragmentPath=@CASE_ROOT@/etc/systemd/system/facelock-daemon.service' \
    'DropInPaths=')" 'duplicate or missing unit-state properties'
run_malformed_snapshot_case masked_unexpected_exec_start service "$(printf '%s\n' \
    'LoadState=masked' 'ActiveState=inactive' 'UnitFileState=masked' \
    'FragmentPath=@CASE_ROOT@/etc/systemd/system/facelock-daemon.service' \
    'ExecStart=/usr/bin/facelock daemon' 'DropInPaths=')" \
    'inconsistent masked unit state'
run_malformed_snapshot_case masked_unexpected_empty_exec_start service "$(printf '%s\n' \
    'LoadState=masked' 'ActiveState=inactive' 'UnitFileState=masked' \
    'FragmentPath=@CASE_ROOT@/etc/systemd/system/facelock-daemon.service' \
    'ExecStart=' 'DropInPaths=')" 'inconsistent masked unit state'
run_malformed_snapshot_case masked_missing_unit_file_state service "$(printf '%s\n' \
    'LoadState=masked' 'ActiveState=inactive' \
    'FragmentPath=@CASE_ROOT@/etc/systemd/system/facelock-daemon.service' \
    'DropInPaths=')" 'duplicate or missing unit-state properties'
run_malformed_snapshot_case masked_unknown_unit_file_state service "$(printf '%s\n' \
    'LoadState=masked' 'ActiveState=inactive' 'UnitFileState=future-mask' \
    'FragmentPath=@CASE_ROOT@/etc/systemd/system/facelock-daemon.service' \
    'DropInPaths=')" 'inconsistent mask for facelock-daemon.service'
run_malformed_snapshot_case masked_missing_fragment service "$(printf '%s\n' \
    'LoadState=masked' 'ActiveState=inactive' 'UnitFileState=masked' \
    'FragmentPath=' 'DropInPaths=')" 'inconsistent mask for facelock-daemon.service'
run_malformed_snapshot_case masked_unexpected_drop_in service "$(printf '%s\n' \
    'LoadState=masked' 'ActiveState=inactive' 'UnitFileState=masked' \
    'FragmentPath=@CASE_ROOT@/etc/systemd/system/facelock-daemon.service' \
    'DropInPaths=@CASE_ROOT@/etc/systemd/system/facelock-daemon.service.d/override.conf')" \
    'inconsistent masked unit state'
run_malformed_snapshot_case masked_runtime_with_persistent_fragment service "$(printf '%s\n' \
    'LoadState=masked' 'ActiveState=inactive' 'UnitFileState=masked-runtime' \
    'FragmentPath=@CASE_ROOT@/etc/systemd/system/facelock-daemon.service' \
    'DropInPaths=')" 'inconsistent mask for facelock-daemon.service'
run_malformed_snapshot_case masked_persistent_with_runtime_fragment service "$(printf '%s\n' \
    'LoadState=masked' 'ActiveState=inactive' 'UnitFileState=masked' \
    'FragmentPath=@CASE_ROOT@/run/systemd/system/facelock-daemon.service' \
    'DropInPaths=')" 'inconsistent mask for facelock-daemon.service'
run_malformed_snapshot_case dbus_duplicate_active dbus "$(printf '%s\n' \
    'ActiveState=inactive' 'ActiveState=active' \
    'ExecStart=/usr/bin/dbus-broker-launch --scope system')"
run_malformed_snapshot_case dbus_missing_exec dbus 'ActiveState=active'

run_case dbus_reload_error loaded inactive disabled 0 present failure none no "$(printf '%s\n' \
    "$show_command" \
    "$dbus_show_command" \
    "$dbus_reload_command" \
    "$dbus_reload_command" \
    "$dbus_reload_command")" none false 1

run_case dbus_owner_mismatch loaded inactive disabled 0 present failure none no "$(printf '%s\n' \
    "$show_command" \
    "$dbus_show_command" \
    "$dbus_reload_command" \
    "$dbus_owner_command")" none false 0 true

run_case dbus_config_changed_during_reload loaded inactive disabled 0 present failure none no "$(printf '%s\n' \
    "$show_command" \
    "$dbus_show_command" \
    "$dbus_reload_command" \
    "$dbus_owner_command")" none false 0 '' true

run_dbus_precedence_case() {
    local name="$1"
    local layout="$2"
    local case_root="$tmp_root/$name"
    local high="$case_root/etc/dbus-1/system-services/org.facelock.Daemon.service"
    local low="$case_root/usr/share/dbus-1/system-services/org.facelock.Daemon.service"
    local status

    mkdir -p "$case_root/run/systemd/system" "${high%/*}" "${low%/*}"
    write_standard_dbus_config "$case_root"
    : >"$case_root/facelock-daemon.service"
    if [ "$layout" = higher_directory ]; then
        write_dbus_service "$high" direct
    else
        write_dbus_service "$high"
        write_dbus_service "${high%/*}/alternate.service" direct
    fi
    write_dbus_service "$low"
    : >"$case_root/actual"

    set +e
    PATH="$tmp_root/bin:$PATH" \
        FACELOCK_SYSTEMCTL_LOG="$case_root/actual" \
        FACELOCK_SHOW_STATUS=0 \
        FACELOCK_LOAD_STATE=loaded \
        FACELOCK_ACTIVE_STATE=inactive \
        FACELOCK_UNIT_FILE_STATE=disabled \
        FACELOCK_RUNTIME_DIR="$case_root/run/systemd/system" \
        bash -c '
            set -euo pipefail
            source "$1"
            facelock_source_install_begin_daemon "$2" "$3" "$4" "$5"
        ' _ \
        "$lifecycle_script" \
        "$case_root/run/systemd/system" \
        "$case_root/facelock-daemon.service" \
        "$high" "$low" \
        2>"$case_root/stderr"
    status=$?
    set -e

    [ "$status" -eq 1 ] || fail "$name did not fail closed"
    [ "$(cat "$case_root/actual")" = "$(printf '%s\n' \
        "$show_command" "$dbus_show_command")" ] ||
        fail "$name did not honor D-Bus activation selection"
    grep -Fq 'selected D-Bus activation definition' "$case_root/stderr" ||
        fail "$name lacked a delegation diagnostic"
    assert_lock_available "$name" \
        "$case_root/run/facelock/lifecycle.lock"
}

run_dbus_precedence_case dbus_higher_directory higher_directory
run_dbus_precedence_case dbus_same_directory same_directory

run_custom_dbus_servicedir_case() {
    local case_root="$tmp_root/dbus_custom_servicedir"
    local custom_dir="$case_root/opt/admin-dbus-services"
    local selected="$case_root/usr/share/dbus-1/system-services/org.facelock.Daemon.service"
    local status

    mkdir -p "$case_root/run/systemd/system" "$custom_dir" \
        "${selected%/*}" "$case_root/usr/share/dbus-1" \
        "$case_root/etc/dbus-1" "$case_root/usr/bin" \
        "$case_root/usr/lib/systemd/system"
    : >"$case_root/usr/bin/dbus-broker-launch"
    : >"$case_root/usr/bin/facelock"
    chmod 755 "$case_root/usr/bin/dbus-broker-launch" \
        "$case_root/usr/bin/facelock"
    : >"$case_root/usr/lib/systemd/system/dbus-broker.service"
    : >"$case_root/facelock-daemon.service"
    write_dbus_service "$selected"
    write_dbus_service "$custom_dir/facelock-direct.service" direct
    printf '%s\n' \
        '<busconfig>' \
        '  <include ignore_missing="yes">/etc/dbus-1/system.conf</include>' \
        '  <standard_system_servicedirs/>' \
        '</busconfig>' >"$case_root/usr/share/dbus-1/system.conf"
    printf '%s\n' \
        '<busconfig>' \
        '  <servicedir>/opt/admin-dbus-services</servicedir>' \
        '</busconfig>' >"$case_root/etc/dbus-1/system.conf"
    : >"$case_root/actual"
    printf '%s\n' none >"$case_root/mask-state"
    printf '%s\n' none >"$case_root/manager-mask-state"

    set +e
    PATH="$tmp_root/bin:$PATH" \
        FACELOCK_SYSTEMCTL_LOG="$case_root/actual" \
        FACELOCK_SHOW_STATUS=0 \
        FACELOCK_LOAD_STATE=loaded \
        FACELOCK_ACTIVE_STATE=inactive \
        FACELOCK_UNIT_FILE_STATE=disabled \
        FACELOCK_MASK_STATE="$case_root/mask-state" \
        FACELOCK_MANAGER_MASK_STATE="$case_root/manager-mask-state" \
        FACELOCK_RUNTIME_DIR="$case_root/run/systemd/system" \
        bash -c '
            set -euo pipefail
            source "$1"
            facelock_source_install_begin_daemon "$2" "$3" "$4"
            printf "%s\n" write >>"$FACELOCK_SYSTEMCTL_LOG"
            facelock_source_install_complete_daemon "$2"
        ' _ \
        "$lifecycle_script" \
        "$case_root/run/systemd/system" \
        "$case_root/facelock-daemon.service" \
        "$selected" \
        2>"$case_root/stderr"
    status=$?
    set -e

    [ "$status" -eq 1 ] ||
        fail "custom D-Bus servicedir did not fail closed"
    ! grep -Fxq write "$case_root/actual" ||
        fail "custom D-Bus servicedir allowed lifecycle mutation"
    grep -Fq 'D-Bus activation configuration' "$case_root/stderr" ||
        fail "custom D-Bus servicedir lacked a configuration diagnostic"
    assert_lock_available dbus_custom_servicedir \
        "$case_root/run/facelock/lifecycle.lock"
}

run_custom_dbus_servicedir_case

run_case barrier_not_applied loaded inactive disabled 0 present failure none no "$(printf '%s\n' \
    "$show_command" \
    "$dbus_show_command" \
    "$dbus_reload_command" \
    "$dbus_owner_command" \
    'systemctl daemon-reload' \
    "$barrier_show_command" \
    'systemctl daemon-reload' \
    "$dbus_reload_command" \
    "$barrier_show_command")" none true 0 '' false true

run_dbus_proof_failure_case() {
    local name="$1"
    local active_state="$2"
    local exec_start="$3"
    local show_status="$4"
    local case_root="$tmp_root/$name"
    local status

    mkdir -p "$case_root/run/systemd/system" "$case_root/run/facelock" \
        "$case_root/assets"
    write_standard_dbus_config "$case_root"
    : >"$case_root/assets/facelock-daemon.service"
    write_dbus_service "$case_root/assets/org.facelock.Daemon.service"
    : >"$case_root/actual"

    set +e
    PATH="$tmp_root/bin:$PATH" \
        FACELOCK_SYSTEMCTL_LOG="$case_root/actual" \
        FACELOCK_SHOW_STATUS=0 \
        FACELOCK_LOAD_STATE=loaded \
        FACELOCK_ACTIVE_STATE=inactive \
        FACELOCK_UNIT_FILE_STATE=disabled \
        FACELOCK_DBUS_SHOW_STATUS="$show_status" \
        FACELOCK_DBUS_ACTIVE_STATE="$active_state" \
        FACELOCK_DBUS_EXEC_START="$exec_start" \
        FACELOCK_MASK_STATE="$case_root/mask-state" \
        FACELOCK_MANAGER_MASK_STATE="$case_root/manager-mask-state" \
        FACELOCK_RUNTIME_DIR="$case_root/run/systemd/system" \
        bash -c '
            set -euo pipefail
            source "$1"
            facelock_source_install_begin_daemon "$2" "$3" "$4"
            printf "%s\n" write >>"$FACELOCK_SYSTEMCTL_LOG"
        ' _ \
        "$lifecycle_script" \
        "$case_root/run/systemd/system" \
        "$case_root/assets/facelock-daemon.service" \
        "$case_root/assets/org.facelock.Daemon.service" \
        2>"$case_root/stderr"
    status=$?
    set -e

    [ "$status" -eq 1 ] || fail "$name exited $status instead of failing closed"
    [ ! -e "$case_root/run/systemd/system.control/facelock-daemon.service" ] ||
        fail "$name established a barrier before proving D-Bus delegation"
    [ "$(cat "$case_root/actual")" = "$(printf '%s\n' \
        "$show_command" "$dbus_show_command")" ] ||
        fail "$name command ordering changed"
    grep -Fq 'D-Bus activation' "$case_root/stderr" ||
        fail "$name lacked a D-Bus activation diagnostic"
    assert_lock_available "$name" "$case_root/run/facelock/lifecycle.lock"
}

run_dbus_proof_failure_case dbus_probe_error active \
    '/usr/bin/dbus-broker-launch --scope system' 1
run_dbus_proof_failure_case dbus_inactive inactive \
    '/usr/bin/dbus-broker-launch --scope system' 0
run_dbus_proof_failure_case dbus_direct_exec active \
    '/usr/bin/dbus-daemon --system' 0
run_dbus_proof_failure_case dbus_daemon_wrong_scope active \
    '/usr/bin/dbus-daemon --session --systemd-activation' 0
run_dbus_proof_failure_case dbus_custom_config active \
    '/usr/bin/dbus-broker-launch --scope system --config-file=/opt/system.conf' 0

run_path_trust_case() {
    local name="$1"
    local mutation="$2"
    local case_root="$tmp_root/$name"
    local unit="$case_root/assets/facelock-daemon.service"
    local definition="$case_root/assets/org.facelock.Daemon.service"
    local config="$case_root/usr/share/dbus-1/system.conf"
    local executable="$case_root/usr/bin/dbus-broker-launch"
    local dbus_fragment="$case_root/usr/lib/systemd/system/dbus-broker.service"
    local status

    mkdir -p "$case_root/run/systemd/system" "$case_root/run/facelock" \
        "$case_root/assets"
    write_standard_dbus_config "$case_root"
    : >"$unit"
    write_dbus_service "$definition"
    case "$mutation" in
        unit_hardlink) ln "$unit" "$case_root/unit-alias" ;;
        unit_mode) chmod 666 "$unit" ;;
        unit_size) truncate -s 1048577 "$unit" ;;
        unit_parent_mode) chmod 777 "$case_root/assets" ;;
        config_symlink)
            mv "$config" "$case_root/config-target"
            ln -s "$case_root/config-target" "$config"
            ;;
        config_hardlink) ln "$config" "$case_root/config-alias" ;;
        config_mode) chmod 666 "$config" ;;
        config_size) truncate -s 1048577 "$config" ;;
        config_parent_mode) chmod 777 "$case_root/usr/share/dbus-1" ;;
        config_include_parent_symlink)
            mkdir -p "$case_root/etc"
            ln -s "$case_root/missing-dbus-config" "$case_root/etc/dbus-1"
            ;;
        definition_symlink)
            mv "$definition" "$case_root/definition-target"
            ln -s "$case_root/definition-target" "$definition"
            ;;
        definition_hardlink) ln "$definition" "$case_root/definition-alias" ;;
        definition_mode) chmod 666 "$definition" ;;
        definition_size) truncate -s 65537 "$definition" ;;
        executable_symlink)
            rm "$executable"
            ln -s /usr/bin/false "$executable"
            ;;
        executable_hardlink) ln "$executable" "$case_root/executable-alias" ;;
        executable_mode) chmod 777 "$executable" ;;
        executable_size) truncate -s 16777217 "$executable" ;;
        dbus_fragment_symlink)
            rm "$dbus_fragment"
            ln -s /dev/null "$dbus_fragment"
            ;;
        dbus_fragment_hardlink) ln "$dbus_fragment" "$case_root/dbus-fragment-alias" ;;
        dbus_fragment_mode) chmod 666 "$dbus_fragment" ;;
        barrier_dir_mode)
            mkdir -p "$case_root/run/systemd/system.control"
            chmod 777 "$case_root/run/systemd/system.control"
            ;;
    esac
    : >"$case_root/actual"
    printf '%s\n' none >"$case_root/mask-state"
    printf '%s\n' none >"$case_root/manager-mask-state"

    set +e
    PATH="$tmp_root/bin:$PATH" \
        FACELOCK_SYSTEMCTL_LOG="$case_root/actual" \
        FACELOCK_SHOW_STATUS=0 \
        FACELOCK_LOAD_STATE=loaded \
        FACELOCK_ACTIVE_STATE=inactive \
        FACELOCK_UNIT_FILE_STATE=disabled \
        FACELOCK_MASK_STATE="$case_root/mask-state" \
        FACELOCK_MANAGER_MASK_STATE="$case_root/manager-mask-state" \
        FACELOCK_RUNTIME_DIR="$case_root/run/systemd/system" \
        bash -c '
            set -euo pipefail
            source "$1"
            facelock_source_install_begin_daemon "$2" "$3" "$4"
            printf "%s\n" write >>"$FACELOCK_SYSTEMCTL_LOG"
            facelock_source_install_complete_daemon "$2"
        ' _ "$lifecycle_script" "$case_root/run/systemd/system" \
        "$unit" "$definition" 2>"$case_root/stderr"
    status=$?
    set -e

    [ "$status" -eq 1 ] || fail "$name accepted untrusted path metadata"
    ! grep -Fxq write "$case_root/actual" ||
        fail "$name crossed the lifecycle mutation boundary"
    [ ! -e "$case_root/run/systemd/system.control/facelock-daemon.service" ] ||
        fail "$name left an activation barrier"
    assert_lock_available "$name" "$case_root/run/facelock/lifecycle.lock"
}

for path_trust_mutation in \
    unit_hardlink unit_mode unit_size unit_parent_mode \
    config_symlink config_hardlink config_mode config_size config_parent_mode \
    config_include_parent_symlink \
    definition_symlink definition_hardlink definition_mode definition_size \
    executable_symlink executable_hardlink executable_mode executable_size \
    dbus_fragment_symlink dbus_fragment_hardlink dbus_fragment_mode \
    barrier_dir_mode; do
run_path_trust_case "path_trust_$path_trust_mutation" "$path_trust_mutation"
done

run_created_barrier_directory_recovery_case() {
    local name=created_barrier_directory_trust_race
    local case_root="$tmp_root/$name"
    local barrier_dir="$case_root/run/systemd/system.control"
    local status

    mkdir -p "$case_root/run/systemd/system" "$case_root/assets"
    write_standard_dbus_config "$case_root"
    : >"$case_root/assets/facelock-daemon.service"
    write_dbus_service "$case_root/assets/org.facelock.Daemon.service"
    : >"$case_root/actual"
    printf '%s\n' none >"$case_root/mask-state"
    printf '%s\n' none >"$case_root/manager-mask-state"

    set +e
    PATH="$tmp_root/bin:$PATH" \
        FACELOCK_SYSTEMCTL_LOG="$case_root/actual" \
        FACELOCK_SHOW_STATUS=0 \
        FACELOCK_LOAD_STATE=loaded \
        FACELOCK_ACTIVE_STATE=inactive \
        FACELOCK_UNIT_FILE_STATE=disabled \
        FACELOCK_MASK_STATE="$case_root/mask-state" \
        FACELOCK_MANAGER_MASK_STATE="$case_root/manager-mask-state" \
        FACELOCK_RUNTIME_DIR="$case_root/run/systemd/system" \
        FACELOCK_MUTATE_CREATED_BARRIER_DIR="$barrier_dir" \
        bash -c '
            set -euo pipefail
            source "$1"
            facelock_source_install_begin_daemon "$2" "$3" "$4"
        ' _ "$lifecycle_script" "$case_root/run/systemd/system" \
        "$case_root/assets/facelock-daemon.service" \
        "$case_root/assets/org.facelock.Daemon.service" \
        2>"$case_root/stderr"
    status=$?
    set -e

    [ "$status" -eq 1 ] || fail "$name admitted a raced control directory"
    [ -d "$barrier_dir" ] && [ ! -L "$barrier_dir" ] &&
        [ "$(stat -c '%a' -- "$barrier_dir")" = 777 ] ||
        fail "$name moved or deleted the concurrently changed public directory"
    ! grep -Fxq write "$case_root/actual" ||
        fail "$name crossed the lifecycle mutation boundary"
    assert_lock_available "$name" "$case_root/run/facelock/lifecycle.lock"
}

run_created_barrier_directory_recovery_case

run_merged_usr_alias_case() {
    local case_root="$tmp_root/merged_usr_alias"
    local bad_root="$tmp_root/noncanonical_lib_alias"

    mkdir -p "$case_root/usr/lib/dbus-1/system-services"
    ln -s usr/lib "$case_root/lib"
    printf '%s\n' \
        '[D-BUS Service]' \
        'Name=org.example.Harmless' \
        'SystemdService=example.service' \
        >"$case_root/usr/lib/dbus-1/system-services/org.example.Harmless.service"
    bash -c '
        set -euo pipefail
        source "$1"
        FACELOCK_SOURCE_INSTALL_DBUS_LAYOUT_PREFIX="$2"
        IFS=: read -r FACELOCK_SOURCE_INSTALL_TRUST_UID \
            FACELOCK_SOURCE_INSTALL_TRUST_GID < <(stat -Lc "%u:%g" -- "$2")
        FACELOCK_SOURCE_INSTALL_DBUS_ASSETS=(
            "$2/lib/dbus-1/system-services/org.facelock.Daemon.service"
        )
        facelock_source_install_dbus_definition_is_absent
    ' _ "$lifecycle_script" "$case_root" ||
        fail "canonical merged-/usr lib alias was rejected"

    mkdir -p "$bad_root/usr/local/lib/dbus-1/system-services"
    ln -s usr/local/lib "$bad_root/lib"
    if bash -c '
        set -euo pipefail
        source "$1"
        FACELOCK_SOURCE_INSTALL_DBUS_LAYOUT_PREFIX="$2"
        IFS=: read -r FACELOCK_SOURCE_INSTALL_TRUST_UID \
            FACELOCK_SOURCE_INSTALL_TRUST_GID < <(stat -Lc "%u:%g" -- "$2")
        FACELOCK_SOURCE_INSTALL_DBUS_ASSETS=(
            "$2/lib/dbus-1/system-services/org.facelock.Daemon.service"
        )
        facelock_source_install_dbus_definition_is_absent
    ' _ "$lifecycle_script" "$bad_root"; then
        fail "noncanonical lib alias was accepted"
    fi
}

run_merged_usr_alias_case

run_post_stop_reconciliation_case() {
    local name="$1"
    local mutation="$2"
    local case_root="$tmp_root/$name"
    local status

    mkdir -p "$case_root/run/systemd/system" "$case_root/assets"
    write_standard_dbus_config "$case_root"
    : >"$case_root/assets/facelock-daemon.service"
    write_dbus_service "$case_root/assets/org.facelock.Daemon.service"
    : >"$case_root/actual"
    printf '%s\n' none >"$case_root/mask-state"
    printf '%s\n' none >"$case_root/manager-mask-state"

    set +e
    PATH="$tmp_root/bin:$PATH" \
        FACELOCK_SYSTEMCTL_LOG="$case_root/actual" \
        FACELOCK_SHOW_STATUS=0 \
        FACELOCK_LOAD_STATE=loaded \
        FACELOCK_ACTIVE_STATE=active \
        FACELOCK_UNIT_FILE_STATE=disabled \
        FACELOCK_MASK_STATE="$case_root/mask-state" \
        FACELOCK_MANAGER_MASK_STATE="$case_root/manager-mask-state" \
        FACELOCK_RUNTIME_DIR="$case_root/run/systemd/system" \
        FACELOCK_MUTATE_AFTER_STOP="$mutation" \
        FACELOCK_OWNER_AFTER_STOP="$([ "$mutation" = owner ] && printf true || printf false)" \
        bash -c '
            set -euo pipefail
            source "$1"
            facelock_source_install_begin_daemon "$2" "$3" "$4"
            printf "%s\n" write >>"$FACELOCK_SYSTEMCTL_LOG"
            facelock_source_install_complete_daemon "$2"
        ' _ "$lifecycle_script" "$case_root/run/systemd/system" \
        "$case_root/assets/facelock-daemon.service" \
        "$case_root/assets/org.facelock.Daemon.service" \
        2>"$case_root/stderr"
    status=$?
    set -e

    [ "$status" -eq 1 ] || fail "$name did not fail closed"
    ! grep -Fxq write "$case_root/actual" ||
        fail "$name crossed the lifecycle mutation boundary"
    assert_lock_available "$name" "$case_root/run/facelock/lifecycle.lock"
}

run_post_stop_reconciliation_case post_stop_config_mutation config
run_post_stop_reconciliation_case post_stop_definition_mutation definition
run_post_stop_reconciliation_case post_stop_owner owner

run_missing_systemd_case() {
    local case_root="$tmp_root/missing_systemd"
    local status

    mkdir -p "$case_root/assets"
    set +e
    PATH="$tmp_root/bin:$PATH" \
        FACELOCK_SYSTEMCTL_LOG="$case_root/actual" \
        bash -c '
            set -euo pipefail
            source "$1"
            facelock_source_install_begin_daemon "$2" "$3" "$4"
            printf "%s\n" write >"$5"
        ' _ \
        "$lifecycle_script" \
        "$case_root/run/systemd/system" \
        "$case_root/assets/facelock-daemon.service" \
        "$case_root/assets/org.facelock.Daemon.service" \
        "$case_root/write"
    status=$?
    set -e

    [ "$status" -eq 1 ] || fail "missing systemd runtime exited $status instead of failing closed"
    [ ! -e "$case_root/write" ] || fail "missing systemd runtime allowed a source-install write"
    [ ! -e "$case_root/actual" ] || fail "missing systemd runtime invoked systemctl"
}

run_missing_systemd_case

run_invalid_lock_directory_case() {
    local kind="$1"
    local name="invalid_lock_directory_$kind"
    local case_root="$tmp_root/$name"
    local status

    mkdir -p "$case_root/run/systemd/system" "$case_root/assets"
    write_standard_dbus_config "$case_root"
    : >"$case_root/assets/facelock-daemon.service"
    write_dbus_service "$case_root/assets/org.facelock.Daemon.service"
    case "$kind" in
        writable)
            mkdir "$case_root/run/facelock"
            chmod 777 "$case_root/run/facelock"
            ;;
        symlink)
            mkdir "$case_root/lock-dir-target"
            ln -s "$case_root/lock-dir-target" "$case_root/run/facelock"
            ;;
        *) fail "$name has an unknown fixture" ;;
    esac

    set +e
    PATH="$tmp_root/bin:$PATH" \
        FACELOCK_SYSTEMCTL_LOG="$case_root/actual" \
        bash -c '
            set -euo pipefail
            source "$1"
            facelock_source_install_begin_daemon "$2" "$3" "$4"
        ' _ "$lifecycle_script" "$case_root/run/systemd/system" \
        "$case_root/assets/facelock-daemon.service" \
        "$case_root/assets/org.facelock.Daemon.service" \
        2>"$case_root/stderr"
    status=$?
    set -e

    [ "$status" -eq 1 ] || fail "$name was accepted"
    [ ! -e "$case_root/actual" ] || fail "$name allowed a manager probe"
    [ ! -e "$case_root/run/facelock/lifecycle.lock" ] ||
        fail "$name created a lock through an unsafe directory"
}

run_invalid_lock_directory_case writable
run_invalid_lock_directory_case symlink

run_busy_lock_case() {
    local case_root="$tmp_root/busy_lock"
    local lock_path="$case_root/run/facelock/lifecycle.lock"
    local holder_pid status

    mkdir -p "$case_root/run/systemd/system" "$case_root/run/facelock" \
        "$case_root/assets"
    write_standard_dbus_config "$case_root"
    : >"$case_root/assets/facelock-daemon.service"
    write_dbus_service "$case_root/assets/org.facelock.Daemon.service"
    : >"$lock_path"
    chmod 600 "$lock_path"
    # Positional parameters belong to the child shell.
    # shellcheck disable=SC2016
    flock -n "$lock_path" bash -c '
        : >"$1"
        while [ ! -e "$2" ]; do sleep 0.01; done
    ' _ "$case_root/ready" "$case_root/release" &
    holder_pid=$!
    while [ ! -e "$case_root/ready" ]; do sleep 0.01; done

    set +e
    PATH="$tmp_root/bin:$PATH" \
        FACELOCK_SYSTEMCTL_LOG="$case_root/actual" \
        FACELOCK_SHOW_STATUS=0 \
        FACELOCK_LOAD_STATE=loaded \
        FACELOCK_ACTIVE_STATE=inactive \
        FACELOCK_UNIT_FILE_STATE=disabled \
        FACELOCK_MASK_STATE="$case_root/mask-state" \
        FACELOCK_MANAGER_MASK_STATE="$case_root/manager-mask-state" \
        FACELOCK_RUNTIME_DIR="$case_root/run/systemd/system" \
        bash -c '
            set -euo pipefail
            source "$1"
            facelock_source_install_begin_daemon "$2" "$3" "$4"
        ' _ \
        "$lifecycle_script" \
        "$case_root/run/systemd/system" \
        "$case_root/assets/facelock-daemon.service" \
        "$case_root/assets/org.facelock.Daemon.service" \
        2>"$case_root/stderr"
    status=$?
    set -e
    : >"$case_root/release"
    wait "$holder_pid"

    [ "$status" -eq 1 ] || fail "concurrent source install exited $status instead of failing closed"
    [ ! -e "$case_root/actual" ] || fail "concurrent source install probed after lock refusal"
    grep -Fq 'another source install is already running' "$case_root/stderr" ||
        fail "concurrent source install lacked a lock diagnostic"
    assert_lock_available busy_lock "$lock_path"
}

run_busy_lock_case

run_invalid_lock_case() {
    local case_root="$tmp_root/invalid_lock"
    local lock_path="$case_root/run/facelock/lifecycle.lock"
    local status

    mkdir -p "$case_root/run/systemd/system" "$case_root/run/facelock" \
        "$case_root/assets"
    write_standard_dbus_config "$case_root"
    : >"$case_root/assets/facelock-daemon.service"
    write_dbus_service "$case_root/assets/org.facelock.Daemon.service"
    mkfifo -m 600 "$lock_path"

    set +e
    # Positional parameters belong to the child shell.
    # shellcheck disable=SC2016
    timeout 2s env \
        PATH="$tmp_root/bin:$PATH" \
        FACELOCK_SYSTEMCTL_LOG="$case_root/actual" \
        FACELOCK_SHOW_STATUS=0 \
        FACELOCK_LOAD_STATE=loaded \
        FACELOCK_ACTIVE_STATE=inactive \
        FACELOCK_UNIT_FILE_STATE=disabled \
        bash -c '
            set -euo pipefail
            source "$1"
            facelock_source_install_begin_daemon "$2" "$3" "$4"
        ' _ \
        "$lifecycle_script" \
        "$case_root/run/systemd/system" \
        "$case_root/assets/facelock-daemon.service" \
        "$case_root/assets/org.facelock.Daemon.service" \
        2>"$case_root/stderr"
    status=$?
    set -e

    [ "$status" -eq 1 ] ||
        fail "invalid lifecycle lock exited $status instead of promptly failing closed"
    [ ! -e "$case_root/actual" ] || fail "invalid lifecycle lock allowed a state probe"
    [ -p "$lock_path" ] || fail "invalid lifecycle lock was changed"
    grep -Fq 'lifecycle lock is unavailable' "$case_root/stderr" ||
        fail "invalid lifecycle lock lacked a refusal diagnostic"
}

run_invalid_lock_case

run_hardlinked_lock_case() {
    local case_root="$tmp_root/hardlinked_lock"
    local lock_path="$case_root/run/facelock/lifecycle.lock"
    local status

    mkdir -p "$case_root/run/systemd/system" "$case_root/run/facelock" \
        "$case_root/assets"
    write_standard_dbus_config "$case_root"
    : >"$case_root/assets/facelock-daemon.service"
    write_dbus_service "$case_root/assets/org.facelock.Daemon.service"
    : >"$lock_path"
    chmod 600 "$lock_path"
    ln "$lock_path" "$case_root/lock-alias"

    set +e
    PATH="$tmp_root/bin:$PATH" \
        FACELOCK_SYSTEMCTL_LOG="$case_root/actual" \
        FACELOCK_SHOW_STATUS=0 \
        FACELOCK_LOAD_STATE=loaded \
        FACELOCK_ACTIVE_STATE=inactive \
        FACELOCK_UNIT_FILE_STATE=disabled \
        FACELOCK_RUNTIME_DIR="$case_root/run/systemd/system" \
        bash -c 'set -euo pipefail; source "$1"; facelock_source_install_begin_daemon "$2" "$3" "$4"' _ \
        "$lifecycle_script" "$case_root/run/systemd/system" \
        "$case_root/assets/facelock-daemon.service" \
        "$case_root/assets/org.facelock.Daemon.service" \
        2>"$case_root/stderr"
    status=$?
    set -e

    [ "$status" -eq 1 ] || fail "hard-linked lifecycle lock was accepted"
    [ ! -e "$case_root/actual" ] || fail "hard-linked lifecycle lock allowed a probe"
    [ "$(stat -c '%h' "$lock_path")" = 2 ] ||
        fail "hard-linked lifecycle lock was changed"
}

run_hardlinked_lock_case

run_offline_image_case() {
    local name="$1"
    local surface="$2"
    local expected_status="$3"
    local case_root="$tmp_root/offline_$name"
    local status
    local busy_fd=

    mkdir -p "$case_root/proc/1" "$case_root/run/dbus" "$case_root/run/systemd" \
        "$case_root/build/scripts" "$case_root/build/test" \
        "$case_root/build/dbus" "$case_root/build/systemd" \
        "$case_root/build/dist"
    printf '%s\n' buildkit >"$case_root/proc/1/comm"
    ln -s /usr/bin/buildkit "$case_root/proc/1/exe"
    : >"$case_root/.dockerenv"
    cp "$lifecycle_script" "$case_root/build/scripts/source-install-daemon-lifecycle.sh"
    cp "$repo_root/scripts/migrate-legacy-system-assets.sh" \
        "$case_root/build/scripts/migrate-legacy-system-assets.sh"
    cp "$repo_root/dist/legacy-system-assets.sha256" "$case_root/build/dist/"
    cp "$justfile" "$case_root/build/justfile"
    cp "$containerfile" "$case_root/build/test/Containerfile"
    cp "$repo_root/test/source-install-offline-image.marker" \
        "$case_root/build/test/source-install-offline-image.marker"
    cp "$repo_root/dbus/org.facelock.Daemon.conf" "$case_root/build/dbus/"
    cp "$repo_root/dbus/org.facelock.Daemon.service" "$case_root/build/dbus/"
    cp "$repo_root/systemd/facelock-daemon.service" "$case_root/build/systemd/"
    case "$surface" in
        clean) ;;
        no_marker) rm -f "$case_root/.dockerenv" ;;
        no_repository_marker)
            rm -f "$case_root/build/test/source-install-offline-image.marker"
            ;;
        bad_repository_marker)
            printf '%s\n' forged >"$case_root/build/test/source-install-offline-image.marker"
            ;;
        missing_pid1_exe) rm -f "$case_root/proc/1/exe" ;;
        systemd_runtime) mkdir -p "$case_root/run/systemd/system" ;;
        systemd_manager) : >"$case_root/run/systemd/private" ;;
        dbus_socket) : >"$case_root/run/dbus/system_bus_socket" ;;
        other_manager) mkdir -p "$case_root/run/openrc" ;;
        installed_binary)
            mkdir -p "$case_root/usr/bin"
            : >"$case_root/usr/bin/facelock"
            ;;
        activation_asset)
            mkdir -p "$case_root/usr/local/share/dbus-1/system-services"
            : >"$case_root/usr/local/share/dbus-1/system-services/org.facelock.Daemon.service"
            ;;
        alternate_activation_asset)
            mkdir -p "$case_root/etc/dbus-1/system-services"
            write_dbus_service \
                "$case_root/etc/dbus-1/system-services/alternate.service" direct
            ;;
        unrelated_activation_asset)
            mkdir -p "$case_root/etc/dbus-1/system-services"
            printf '%s\n' \
                '[D-BUS Service]' \
                'Exec=/usr/bin/unrelated' \
                'Name=org.example.Unrelated' \
                >"$case_root/etc/dbus-1/system-services/unrelated.service"
            ;;
        daemon_process)
            mkdir -p "$case_root/proc/23"
            ln -s /usr/bin/facelock "$case_root/proc/23/exe"
            ;;
        unreadable_process)
            mkdir -p "$case_root/proc/23"
            ln -s /usr/bin/unrelated "$case_root/proc/23/exe"
            ;;
        systemd_pid1) printf '%s\n' systemd >"$case_root/proc/1/comm" ;;
        busy_lock)
            mkdir -p "$case_root/run/facelock"
            : >"$case_root/run/facelock/lifecycle.lock"
            chmod 600 "$case_root/run/facelock/lifecycle.lock"
            exec {busy_fd}<>"$case_root/run/facelock/lifecycle.lock"
            flock -n "$busy_fd"
            ;;
    esac

    set +e
    if [ "$surface" = dbus_override ]; then
        # Positional parameters belong to the child shell.
        # shellcheck disable=SC2016
        env -u DBUS_STARTER_ADDRESS -u DBUS_SESSION_BUS_ADDRESS \
            DBUS_SYSTEM_BUS_ADDRESS=unix:path=/tmp/fake-system-bus \
            FACELOCK_SOURCE_INSTALL_OFFLINE_IMAGE=container-build \
            FACELOCK_SOURCE_INSTALL_OFFLINE_MARKER="$case_root/build/test/source-install-offline-image.marker" \
            bash -c '
                set -euo pipefail
                cd "$2/build"
                source "$1"
                facelock_source_install_begin "$2"
                printf "%s\n" write >"$3"
                facelock_source_install_complete
            ' _ "$case_root/build/scripts/source-install-daemon-lifecycle.sh" "$case_root" "$case_root/write" \
            2>"$case_root/stderr"
        status=$?
    elif [ "$surface" = unreadable_process ]; then
        # Positional parameters belong to the child shell.
        # shellcheck disable=SC2016
        env -u DBUS_SYSTEM_BUS_ADDRESS -u DBUS_STARTER_ADDRESS \
            -u DBUS_SESSION_BUS_ADDRESS \
            PATH="$tmp_root/readlink-fail-bin:$PATH" \
            FACELOCK_SOURCE_INSTALL_OFFLINE_IMAGE=container-build \
            FACELOCK_SOURCE_INSTALL_OFFLINE_MARKER="$case_root/build/test/source-install-offline-image.marker" \
            bash -c '
                set -euo pipefail
                cd "$2/build"
                source "$1"
                facelock_source_install_begin "$2"
                printf "%s\n" write >"$3"
                facelock_source_install_complete
            ' _ "$case_root/build/scripts/source-install-daemon-lifecycle.sh" "$case_root" "$case_root/write" \
            2>"$case_root/stderr"
        status=$?
    else
        # Positional parameters belong to the child shell.
        # shellcheck disable=SC2016
        env -u DBUS_SYSTEM_BUS_ADDRESS -u DBUS_STARTER_ADDRESS \
            -u DBUS_SESSION_BUS_ADDRESS \
            FACELOCK_SOURCE_INSTALL_OFFLINE_IMAGE=container-build \
            FACELOCK_SOURCE_INSTALL_OFFLINE_MARKER="$case_root/build/test/source-install-offline-image.marker" \
            bash -c '
                set -euo pipefail
                cd "$2/build"
                source "$1"
                facelock_source_install_begin "$2"
                printf "%s\n" write >"$3"
                facelock_source_install_complete
            ' _ "$case_root/build/scripts/source-install-daemon-lifecycle.sh" "$case_root" "$case_root/write" \
            2>"$case_root/stderr"
        status=$?
    fi
    set -e
    if [ -n "$busy_fd" ]; then
        exec {busy_fd}>&-
    fi

    [ "$status" -eq "$expected_status" ] ||
        { cat "$case_root/stderr" >&2; fail "offline image $name exited $status, expected $expected_status"; }
    if [ "$expected_status" -eq 0 ]; then
        [ -f "$case_root/write" ] || fail "clean offline image did not proceed"
        [ ! -s "$case_root/stderr" ] || fail "clean offline image wrote unexpected stderr"
        assert_lock_available "$name" \
            "$case_root/run/facelock/lifecycle.lock"
    else
        [ ! -e "$case_root/write" ] || fail "offline image $name allowed a write"
        grep -Fq 'offline image' "$case_root/stderr" ||
            fail "offline image $name lacked a refusal diagnostic"
    fi
}

run_offline_image_case clean clean 0
run_offline_image_case no_marker no_marker 1
run_offline_image_case no_repository_marker no_repository_marker 1
run_offline_image_case bad_repository_marker bad_repository_marker 1
run_offline_image_case missing_pid1_exe missing_pid1_exe 1
run_offline_image_case systemd_runtime systemd_runtime 1
run_offline_image_case systemd_manager systemd_manager 1
run_offline_image_case dbus_socket dbus_socket 1
run_offline_image_case other_manager other_manager 1
run_offline_image_case installed_binary installed_binary 1
run_offline_image_case dbus_override dbus_override 1
run_offline_image_case activation_asset activation_asset 1
run_offline_image_case alternate_activation_asset alternate_activation_asset 1
run_offline_image_case unrelated_activation_asset unrelated_activation_asset 0
run_offline_image_case daemon_process daemon_process 1
run_offline_image_case unreadable_process unreadable_process 1
run_offline_image_case systemd_pid1 systemd_pid1 1
run_offline_image_case busy_lock busy_lock 1

run_prepare_failure_case() {
    local name="$1"
    local fail_command="$2"
    local expected="$3"
    local failure_count="${4:-1}"
    local case_root="$tmp_root/$name"
    local actual="$case_root/actual"
    local expected_path="$case_root/expected"
    local mask_state="$case_root/mask-state"
    local manager_mask_state="$case_root/manager-mask-state"
    local failures_remaining="$case_root/failures-remaining"
    local status

    mkdir -p "$case_root/run/systemd/system" "$case_root/assets"
    write_standard_dbus_config "$case_root"
    : >"$case_root/assets/facelock-daemon.service"
    write_dbus_service "$case_root/assets/org.facelock.Daemon.service"
    : >"$actual"
    printf '%s\n' "$expected" >"$expected_path"
    printf '%s\n' none >"$mask_state"
    printf '%s\n' none >"$manager_mask_state"
    printf '%s\n' "$failure_count" >"$failures_remaining"

    set +e
    PATH="$tmp_root/bin:$PATH" \
        FACELOCK_SYSTEMCTL_LOG="$actual" \
        FACELOCK_SHOW_STATUS=0 \
        FACELOCK_LOAD_STATE=loaded \
        FACELOCK_ACTIVE_STATE=active \
        FACELOCK_UNIT_FILE_STATE=disabled \
        FACELOCK_MASK_STATE="$mask_state" \
        FACELOCK_MANAGER_MASK_STATE="$manager_mask_state" \
        FACELOCK_RUNTIME_DIR="$case_root/run/systemd/system" \
        FACELOCK_FAIL_BEFORE_WRITE=true \
        FACELOCK_FAIL_COMMAND="$fail_command" \
        FACELOCK_FAILURES_REMAINING="$failures_remaining" \
        bash -c '
            set -euo pipefail
            source "$1"
            facelock_source_install_begin_daemon "$2" "$3" "$4"
        ' _ \
        "$lifecycle_script" \
        "$case_root/run/systemd/system" \
        "$case_root/assets/facelock-daemon.service" \
        "$case_root/assets/org.facelock.Daemon.service"
    status=$?
    set -e

    [ "$status" -eq 1 ] ||
        fail "$name exited $status instead of reporting preparation failure"
    [ "$(cat "$mask_state")" = none ] ||
        fail "$name left the temporary activation barrier installed"
    [ ! -e "$case_root/run/systemd/system.control/facelock-daemon.service" ] ||
        fail "$name left the owned activation barrier installed"
    diff -u "$expected_path" "$actual" ||
        fail "$name preparation-failure restoration ordering changed"
    assert_lock_available "$name" "$case_root/run/facelock/lifecycle.lock"
}

run_prepare_failure_case barrier_reload_failure daemon-reload "$(printf '%s\n' \
    "$show_command" \
    "$dbus_show_command" \
    "$dbus_reload_command" \
    "$dbus_owner_command" \
    'systemctl daemon-reload' \
    'systemctl daemon-reload' \
    'systemctl daemon-reload' \
    'systemctl daemon-reload' \
    "$dbus_reload_command" \
    "$barrier_show_command" \
    "$dbus_owner_command" \
    'systemctl daemon-reload' \
    "$show_command" \
    "$dbus_owner_command" \
    "$show_command" \
    "$dbus_owner_command")" 3

run_prepare_failure_case stop_failure 'stop facelock-daemon.service' "$(printf '%s\n' \
    "$show_command" \
    "$dbus_show_command" \
    "$dbus_reload_command" \
    "$dbus_owner_command" \
    'systemctl daemon-reload' \
    "$barrier_show_command" \
    'systemctl stop facelock-daemon.service' \
    'systemctl daemon-reload' \
    "$dbus_reload_command" \
    "$barrier_show_command" \
    "$dbus_owner_command" \
    'systemctl daemon-reload' \
    "$show_command" \
    "$dbus_owner_command" \
    "$show_command" \
    "$dbus_owner_command")"

run_barrier_tamper_case() {
    local case_root="$tmp_root/barrier_tamper"
    local actual="$case_root/actual"
    local expected="$case_root/expected"
    local mask_state="$case_root/mask-state"
    local manager_mask_state="$case_root/manager-mask-state"
    local barrier="$case_root/run/systemd/system.control/facelock-daemon.service"
    local status

    mkdir -p "$case_root/run/systemd/system" "$case_root/assets"
    write_standard_dbus_config "$case_root"
    : >"$case_root/assets/facelock-daemon.service"
    write_dbus_service "$case_root/assets/org.facelock.Daemon.service"
    : >"$actual"
    printf '%s\n' none >"$mask_state"
    printf '%s\n' none >"$manager_mask_state"
    printf '%s\n' \
        "$show_command" \
        "$dbus_show_command" \
        "$dbus_reload_command" \
        "$dbus_owner_command" \
        'systemctl daemon-reload' \
        "$barrier_show_command" \
        'systemctl stop facelock-daemon.service' \
        "$barrier_show_command" \
        "$dbus_owner_command" \
        'write' \
        'systemctl daemon-reload' >"$expected"

    set +e
    PATH="$tmp_root/bin:$PATH" \
        FACELOCK_SYSTEMCTL_LOG="$actual" \
        FACELOCK_SHOW_STATUS=0 \
        FACELOCK_LOAD_STATE=loaded \
        FACELOCK_ACTIVE_STATE=active \
        FACELOCK_UNIT_FILE_STATE=disabled \
        FACELOCK_MASK_STATE="$mask_state" \
        FACELOCK_MANAGER_MASK_STATE="$manager_mask_state" \
        FACELOCK_RUNTIME_DIR="$case_root/run/systemd/system" \
        bash -c '
            set -euo pipefail
            source "$1"
            facelock_source_install_begin_daemon "$2" "$3" "$4"
            printf "%s\n" write >>"$FACELOCK_SYSTEMCTL_LOG"
            rm -f -- "$5"
            ln -s /dev/null "$5"
            facelock_source_install_complete_daemon "$2"
        ' _ \
        "$lifecycle_script" \
        "$case_root/run/systemd/system" \
        "$case_root/assets/facelock-daemon.service" \
        "$case_root/assets/org.facelock.Daemon.service" \
        "$barrier" \
        2>"$case_root/stderr"
    status=$?
    set -e

    [ "$status" -eq 1 ] || fail "changed barrier exited $status instead of failing closed"
    [ -L "$barrier" ] && [ "$(readlink "$barrier")" = /dev/null ] ||
        fail "cleanup removed or changed a barrier it did not own"
    grep -Fq 'safely reconcile the masked D-Bus activation state' "$case_root/stderr" ||
        fail "changed barrier failure lacked a cleanup diagnostic"
    diff -u "$expected" "$actual" ||
        fail "changed barrier cleanup attempted to reactivate the daemon"
    assert_lock_available barrier_tamper "$case_root/run/facelock/lifecycle.lock"
}

run_barrier_tamper_case

run_barrier_quarantine_race_case() {
    local name="${1:-barrier_quarantine_race}"
    local race="${2:-replacement}"
    local case_root="$tmp_root/$name"
    local barrier="$case_root/run/systemd/system.control/facelock-daemon.service"
    local status

    mkdir -p "$case_root/run/systemd/system" "$case_root/assets"
    write_standard_dbus_config "$case_root"
    : >"$case_root/assets/facelock-daemon.service"
    write_dbus_service "$case_root/assets/org.facelock.Daemon.service"
    : >"$case_root/actual"
    printf '%s\n' none >"$case_root/mask-state"
    printf '%s\n' none >"$case_root/manager-mask-state"

    set +e
    PATH="$tmp_root/bin:$PATH" \
        FACELOCK_SYSTEMCTL_LOG="$case_root/actual" \
        FACELOCK_SHOW_STATUS=0 \
        FACELOCK_LOAD_STATE=loaded \
        FACELOCK_ACTIVE_STATE=active \
        FACELOCK_UNIT_FILE_STATE=disabled \
        FACELOCK_MASK_STATE="$case_root/mask-state" \
        FACELOCK_MANAGER_MASK_STATE="$case_root/manager-mask-state" \
        FACELOCK_RUNTIME_DIR="$case_root/run/systemd/system" \
        FACELOCK_REPLACE_BEFORE_QUARANTINE="$([ "$race" = replacement ] && \
            printf '%s' "$barrier" || printf '')" \
        FACELOCK_MOVE_BARRIER_THEN_FAIL="$([ "$race" = move_then_fail ] && \
            printf true || printf false)" \
        bash -c '
            set -euo pipefail
            source "$1"
            facelock_source_install_begin_daemon "$2" "$3" "$4"
            printf "%s\n" write >>"$FACELOCK_SYSTEMCTL_LOG"
            facelock_source_install_complete_daemon "$2"
        ' _ "$lifecycle_script" "$case_root/run/systemd/system" \
        "$case_root/assets/facelock-daemon.service" \
        "$case_root/assets/org.facelock.Daemon.service" \
        2>"$case_root/stderr"
    status=$?
    set -e

    if [ "$race" = replacement ]; then
        [ "$status" -eq 1 ] || fail "$name did not fail closed"
        [ -f "$barrier" ] && [ "$(cat "$barrier")" = replacement ] ||
            fail "$name did not restore the raced replacement to its public path"
        [ "$(cat "$case_root/manager-mask-state")" = masked ] ||
            fail "$name reloaded away the cached manager mask"
        ! grep -Fq 'systemctl start facelock-daemon.service' "$case_root/actual" ||
            fail "$name restarted the daemon"
    else
        [ "$status" -eq 0 ] || fail "$name did not recover the completed move"
        [ ! -e "$barrier" ] && [ ! -L "$barrier" ] ||
            fail "$name left the owned barrier installed"
        grep -Fq 'systemctl start facelock-daemon.service' "$case_root/actual" ||
            fail "$name did not restore the initially active daemon"
    fi
    assert_lock_available "$name" \
        "$case_root/run/facelock/lifecycle.lock"
}

run_barrier_quarantine_race_case
run_barrier_quarantine_race_case barrier_quarantine_move_then_fail \
    move_then_fail

run_barrier_directory_quarantine_race_case() {
    local case_root="$tmp_root/barrier_directory_quarantine_race"
    local barrier_dir="$case_root/run/systemd/system.control"
    local status

    mkdir -p "$case_root/run/systemd/system" "$case_root/assets"
    write_standard_dbus_config "$case_root"
    : >"$case_root/assets/facelock-daemon.service"
    write_dbus_service "$case_root/assets/org.facelock.Daemon.service"
    : >"$case_root/actual"
    printf '%s\n' none >"$case_root/mask-state"
    printf '%s\n' none >"$case_root/manager-mask-state"

    set +e
    PATH="$tmp_root/bin:$PATH" \
        FACELOCK_SYSTEMCTL_LOG="$case_root/actual" \
        FACELOCK_SHOW_STATUS=0 \
        FACELOCK_LOAD_STATE=loaded \
        FACELOCK_ACTIVE_STATE=inactive \
        FACELOCK_UNIT_FILE_STATE=disabled \
        FACELOCK_MASK_STATE="$case_root/mask-state" \
        FACELOCK_MANAGER_MASK_STATE="$case_root/manager-mask-state" \
        FACELOCK_RUNTIME_DIR="$case_root/run/systemd/system" \
        FACELOCK_REPLACE_BEFORE_QUARANTINE="$barrier_dir" \
        FACELOCK_REPLACE_DIRECTORY_BEFORE_QUARANTINE=true \
        bash -c '
            set -euo pipefail
            source "$1"
            facelock_source_install_begin_daemon "$2" "$3" "$4"
            printf "%s\n" write >>"$FACELOCK_SYSTEMCTL_LOG"
            facelock_source_install_complete_daemon "$2"
        ' _ "$lifecycle_script" "$case_root/run/systemd/system" \
        "$case_root/assets/facelock-daemon.service" \
        "$case_root/assets/org.facelock.Daemon.service" \
        2>"$case_root/stderr"
    status=$?
    set -e

    [ "$status" -eq 1 ] || fail "barrier-directory quarantine race did not fail closed"
    [ -f "$barrier_dir/replacement" ] ||
        fail "barrier-directory quarantine race did not restore the replacement directory"
    assert_lock_available barrier_directory_quarantine_race \
        "$case_root/run/facelock/lifecycle.lock"
}

run_barrier_directory_quarantine_race_case

run_barrier_directory_unrelated_entry_case() {
    local name=barrier_directory_unrelated_entry
    local case_root="$tmp_root/$name"
    local barrier_dir="$case_root/run/systemd/system.control"
    local status

    mkdir -p "$case_root/run/systemd/system" "$case_root/assets"
    write_standard_dbus_config "$case_root"
    : >"$case_root/assets/facelock-daemon.service"
    write_dbus_service "$case_root/assets/org.facelock.Daemon.service"
    : >"$case_root/actual"
    printf '%s\n' none >"$case_root/mask-state"
    printf '%s\n' none >"$case_root/manager-mask-state"

    set +e
    PATH="$tmp_root/bin:$PATH" \
        FACELOCK_SYSTEMCTL_LOG="$case_root/actual" \
        FACELOCK_SHOW_STATUS=0 \
        FACELOCK_LOAD_STATE=loaded \
        FACELOCK_ACTIVE_STATE=inactive \
        FACELOCK_UNIT_FILE_STATE=disabled \
        FACELOCK_MASK_STATE="$case_root/mask-state" \
        FACELOCK_MANAGER_MASK_STATE="$case_root/manager-mask-state" \
        FACELOCK_RUNTIME_DIR="$case_root/run/systemd/system" \
        FACELOCK_ADD_ENTRY_BEFORE_DIRECTORY_QUARANTINE="$barrier_dir" \
        bash -c '
            set -euo pipefail
            source "$1"
            facelock_source_install_begin_daemon "$2" "$3" "$4"
            printf "%s\n" write >>"$FACELOCK_SYSTEMCTL_LOG"
            facelock_source_install_complete_daemon "$2"
        ' _ "$lifecycle_script" "$case_root/run/systemd/system" \
        "$case_root/assets/facelock-daemon.service" \
        "$case_root/assets/org.facelock.Daemon.service" \
        2>"$case_root/stderr"
    status=$?
    set -e

    [ "$status" -eq 1 ] || fail "$name did not fail closed"
    [ -f "$barrier_dir/administrator-unit.service" ] ||
        fail "$name moved or deleted the unrelated public entry"
    assert_lock_available "$name" "$case_root/run/facelock/lifecycle.lock"
}

run_barrier_directory_unrelated_entry_case

run_dbus_tamper_case() {
    local name="$1"
    local tamper="$2"
    local case_root="$tmp_root/$name"
    local actual="$case_root/actual"
    local dbus_service="$case_root/assets/org.facelock.Daemon.service"
    local dbus_config="$case_root/usr/share/dbus-1/system.conf"
    local barrier="$case_root/run/systemd/system.control/facelock-daemon.service"
    local status

    mkdir -p "$case_root/run/systemd/system" "$case_root/assets"
    write_standard_dbus_config "$case_root"
    : >"$case_root/assets/facelock-daemon.service"
    write_dbus_service "$dbus_service"
    : >"$actual"
    printf '%s\n' none >"$case_root/mask-state"
    printf '%s\n' none >"$case_root/manager-mask-state"

    set +e
    PATH="$tmp_root/bin:$PATH" \
        FACELOCK_SYSTEMCTL_LOG="$actual" \
        FACELOCK_SHOW_STATUS=0 \
        FACELOCK_LOAD_STATE=loaded \
        FACELOCK_ACTIVE_STATE=active \
        FACELOCK_UNIT_FILE_STATE=disabled \
        FACELOCK_MASK_STATE="$case_root/mask-state" \
        FACELOCK_MANAGER_MASK_STATE="$case_root/manager-mask-state" \
        FACELOCK_RUNTIME_DIR="$case_root/run/systemd/system" \
        bash -c '
            set -euo pipefail
            source "$1"
            facelock_source_install_begin_daemon "$2" "$3" "$4"
            printf "%s\n" write >>"$FACELOCK_SYSTEMCTL_LOG"
            case "$6" in
                definition)
                    printf "%s\n" \
                        "[D-BUS Service]" \
                        "Name=org.facelock.Daemon" \
                        "Exec=/usr/bin/facelock daemon" >"$4"
                    ;;
                config)
                    printf "%s\n" \
                        "<busconfig>" \
                        "<servicedir>/opt/admin-dbus-services</servicedir>" \
                        "<standard_system_servicedirs/>" \
                        "</busconfig>" >"$5"
                    ;;
            esac
            facelock_source_install_complete_daemon "$2"
        ' _ \
        "$lifecycle_script" \
        "$case_root/run/systemd/system" \
        "$case_root/assets/facelock-daemon.service" \
        "$dbus_service" \
        "$dbus_config" \
        "$tamper" \
        2>"$case_root/stderr"
    status=$?
    set -e

    [ "$status" -eq 1 ] || fail "changed D-Bus $tamper did not fail closed"
    [ -f "$barrier" ] && [ ! -s "$barrier" ] ||
        fail "changed D-Bus $tamper removed the systemd barrier"
    [ "$(cat "$actual")" = "$(printf '%s\n' \
        "$show_command" "$dbus_show_command" \
        "$dbus_reload_command" "$dbus_owner_command" \
        'systemctl daemon-reload' "$barrier_show_command" \
        'systemctl stop facelock-daemon.service' \
        "$barrier_show_command" "$dbus_owner_command" 'write' \
        'systemctl daemon-reload')" ] ||
        fail "changed D-Bus $tamper attempted unsafe cleanup or restart"
    grep -Fq 'safely reconcile the masked D-Bus activation state' \
        "$case_root/stderr" ||
        fail "changed D-Bus $tamper lacked a cleanup diagnostic"
    assert_lock_available "$name" \
        "$case_root/run/facelock/lifecycle.lock"
}

run_dbus_tamper_case dbus_definition_tamper definition
run_dbus_tamper_case dbus_config_tamper config

run_cleanup_reload_reconciliation_case() {
    local name="$1"
    local fault="$2"
    local case_root="$tmp_root/$name"
    local barrier="$case_root/run/systemd/system.control/facelock-daemon.service"
    local status

    mkdir -p "$case_root/run/systemd/system" "$case_root/assets"
    write_standard_dbus_config "$case_root"
    : >"$case_root/assets/facelock-daemon.service"
    write_dbus_service "$case_root/assets/org.facelock.Daemon.service"
    : >"$case_root/actual"
    printf '%s\n' none >"$case_root/mask-state"
    printf '%s\n' none >"$case_root/manager-mask-state"

    set +e
    PATH="$tmp_root/bin:$PATH" \
        FACELOCK_SYSTEMCTL_LOG="$case_root/actual" \
        FACELOCK_SHOW_STATUS=0 \
        FACELOCK_LOAD_STATE=loaded \
        FACELOCK_ACTIVE_STATE=active \
        FACELOCK_UNIT_FILE_STATE=disabled \
        FACELOCK_MASK_STATE="$case_root/mask-state" \
        FACELOCK_MANAGER_MASK_STATE="$case_root/manager-mask-state" \
        FACELOCK_RUNTIME_DIR="$case_root/run/systemd/system" \
        FACELOCK_DBUS_TAMPER_ON_RELOAD_NUMBER="$([ "$fault" = config ] && printf 2 || printf 0)" \
        FACELOCK_OWNER_AFTER_CLEANUP_RELOAD="$([ "$fault" = owner ] && printf true || printf false)" \
        bash -c '
            set -euo pipefail
            source "$1"
            facelock_source_install_begin_daemon "$2" "$3" "$4"
            printf "%s\n" write >>"$FACELOCK_SYSTEMCTL_LOG"
            facelock_source_install_complete_daemon "$2"
        ' _ "$lifecycle_script" "$case_root/run/systemd/system" \
        "$case_root/assets/facelock-daemon.service" \
        "$case_root/assets/org.facelock.Daemon.service" \
        2>"$case_root/stderr"
    status=$?
    set -e

    [ "$status" -eq 1 ] || fail "$name did not fail closed"
    [ -f "$barrier" ] && [ ! -s "$barrier" ] ||
        fail "$name removed the barrier after unsafe cache reload"
    ! grep -Fq 'systemctl start facelock-daemon.service' "$case_root/actual" ||
        fail "$name restarted after unsafe cache reload"
    assert_lock_available "$name" "$case_root/run/facelock/lifecycle.lock"
}

run_cleanup_reload_reconciliation_case cleanup_reload_config_mutation config
run_cleanup_reload_reconciliation_case cleanup_reload_owner owner

run_cleanup_state_machine_refusal_case() {
    local name="$1"
    local fault="$2"
    local case_root="$tmp_root/$name"
    local barrier="$case_root/run/systemd/system.control/facelock-daemon.service"
    local runtime_mask="$case_root/run/systemd/system/facelock-daemon.service"
    local after_write="$case_root/after-write"
    local failures_remaining="$case_root/failures-remaining"
    local expect_recovered_barrier="${3:-true}"
    local status

    mkdir -p "$case_root/etc/systemd/system" \
        "$case_root/run/systemd/system" "$case_root/assets"
    write_standard_dbus_config "$case_root"
    : >"$case_root/assets/facelock-daemon.service"
    write_dbus_service "$case_root/assets/org.facelock.Daemon.service"
    : >"$case_root/actual"
    printf '%s\n' none >"$case_root/mask-state"
    printf '%s\n' none >"$case_root/manager-mask-state"
    printf '%s\n' 0 >"$failures_remaining"
    if [ "$fault" = initial_reload ]; then
        printf '%s\n' 3 >"$failures_remaining"
    fi

    set +e
    PATH="$tmp_root/bin:$PATH" \
        FACELOCK_SYSTEMCTL_LOG="$case_root/actual" \
        FACELOCK_SHOW_STATUS=0 \
        FACELOCK_LOAD_STATE=loaded \
        FACELOCK_ACTIVE_STATE=active \
        FACELOCK_UNIT_FILE_STATE=disabled \
        FACELOCK_MASK_STATE="$case_root/mask-state" \
        FACELOCK_MANAGER_MASK_STATE="$case_root/manager-mask-state" \
        FACELOCK_RUNTIME_DIR="$case_root/run/systemd/system" \
        FACELOCK_AFTER_WRITE_FILE="$after_write" \
        FACELOCK_FAIL_COMMAND="$([ "$fault" = initial_reload ] && \
            printf daemon-reload || printf '')" \
        FACELOCK_FAILURES_REMAINING="$failures_remaining" \
        FACELOCK_FAIL_FINAL_RELOAD="$([ "$fault" = final_reload ] && \
            printf true || printf false)" \
        FACELOCK_MUTATE_MASK_ON_CLEANUP_RELOAD="$([ "$fault" = cleanup_mask ] && \
            printf '%s' "$runtime_mask" || printf '')" \
        FACELOCK_MUTATE_MASK_BEFORE_QUARANTINE="$([ "$fault" = quarantine_mask ] && \
            printf '%s' "$runtime_mask" || printf '')" \
        FACELOCK_FINAL_FRAGMENT_OVERRIDE="$([ "$fault" = final_fragment ] && \
            printf '%s' "$case_root/run/systemd/transient/facelock-daemon.service" || printf '')" \
        FACELOCK_OWNER_AFTER_FINAL_RELOAD="$([ "$fault" = final_owner ] && \
            printf true || printf false)" \
        FACELOCK_MUTATE_DBUS_ON_FINAL_RELOAD="$([ "$fault" = final_dbus ] && \
            printf true || printf false)" \
        FACELOCK_BARRIER_REMOVE_FAULT="$(case "$fault" in \
            removal_before) printf before ;; removal_after) printf after ;; \
            *) printf none ;; esac)" \
        bash -c '
            set -euo pipefail
            source "$1"
            facelock_source_install_begin_daemon "$2" "$3" "$4"
            printf "%s\n" write >>"$FACELOCK_SYSTEMCTL_LOG"
            : >"$FACELOCK_AFTER_WRITE_FILE"
            facelock_source_install_complete_daemon "$2"
        ' _ "$lifecycle_script" "$case_root/run/systemd/system" \
        "$case_root/assets/facelock-daemon.service" \
        "$case_root/assets/org.facelock.Daemon.service" \
        2>"$case_root/stderr"
    status=$?
    set -e

    [ "$status" -eq 1 ] || fail "$name did not report unsafe cleanup"
    if [ "$expect_recovered_barrier" = true ]; then
        [ -f "$barrier" ] && [ ! -L "$barrier" ] && [ ! -s "$barrier" ] ||
            fail "$name did not recover the owned barrier"
        [ "$(cat "$case_root/manager-mask-state")" = masked ] ||
            fail "$name did not retain the manager-effective barrier"
    else
        [ ! -e "$barrier" ] && [ ! -L "$barrier" ] ||
            fail "$name recreated a barrier after losing its held inode"
    fi
    ! grep -Fq 'systemctl start facelock-daemon.service' "$case_root/actual" ||
        fail "$name restarted without complete cleanup proof"
    if [ "$fault" = cleanup_mask ] || [ "$fault" = quarantine_mask ]; then
        [ -L "$runtime_mask" ] && [ "$(readlink -- "$runtime_mask")" = /dev/null ] ||
            fail "$name changed the concurrently installed administrator mask"
    fi
    assert_lock_available "$name" "$case_root/run/facelock/lifecycle.lock"
}

run_cleanup_state_machine_refusal_case cleanup_initial_reload_exhausted initial_reload
run_cleanup_state_machine_refusal_case cleanup_final_reload_exhausted final_reload
run_cleanup_state_machine_refusal_case cleanup_mask_changed_on_reload cleanup_mask
run_cleanup_state_machine_refusal_case cleanup_mask_changed_before_quarantine \
    quarantine_mask
run_cleanup_state_machine_refusal_case cleanup_final_fragment_mismatch final_fragment
run_cleanup_state_machine_refusal_case cleanup_final_owner_race final_owner
run_cleanup_state_machine_refusal_case cleanup_final_dbus_race final_dbus
run_cleanup_state_machine_refusal_case cleanup_barrier_remove_refused \
    removal_before
run_cleanup_state_machine_refusal_case cleanup_barrier_removed_but_unconfirmed \
    removal_after false

run_first_install_unconfirmed_recovery_case() {
    local name=first_install_unconfirmed_barrier_recovery
    local case_root="$tmp_root/$name"
    local barrier="$case_root/run/systemd/system.control/facelock-daemon.service"
    local failures_remaining="$case_root/failures-remaining"
    local status

    mkdir -p "$case_root/etc/systemd/system" \
        "$case_root/run/systemd/system" "$case_root/assets"
    write_standard_dbus_config "$case_root"
    : >"$case_root/actual"
    printf '%s\n' none >"$case_root/mask-state"
    printf '%s\n' none >"$case_root/manager-mask-state"
    printf '%s\n' 3 >"$failures_remaining"

    set +e
    PATH="$tmp_root/bin:$PATH" \
        FACELOCK_SYSTEMCTL_LOG="$case_root/actual" \
        FACELOCK_SHOW_STATUS=0 \
        FACELOCK_LOAD_STATE=not-found \
        FACELOCK_ACTIVE_STATE=inactive \
        FACELOCK_UNIT_FILE_STATE='' \
        FACELOCK_MASK_STATE="$case_root/mask-state" \
        FACELOCK_MANAGER_MASK_STATE="$case_root/manager-mask-state" \
        FACELOCK_RUNTIME_DIR="$case_root/run/systemd/system" \
        FACELOCK_FAIL_COMMAND=daemon-reload \
        FACELOCK_FAIL_BEFORE_WRITE=true \
        FACELOCK_FAILURES_REMAINING="$failures_remaining" \
        bash -c '
            set -euo pipefail
            source "$1"
            facelock_source_install_begin_daemon "$2" "$3" "$4"
        ' _ "$lifecycle_script" "$case_root/run/systemd/system" \
        "$case_root/assets/facelock-daemon.service" \
        "$case_root/assets/org.facelock.Daemon.service" \
        2>"$case_root/stderr"
    status=$?
    set -e

    [ "$status" -eq 1 ] || fail "$name lost the preparation failure status"
    [ ! -e "$barrier" ] && [ ! -L "$barrier" ] ||
        fail "$name did not retire its created-but-unconfirmed barrier"
    ! grep -Fq 'systemctl start facelock-daemon.service' "$case_root/actual" ||
        fail "$name attempted to start a daemon that was initially absent"
    assert_lock_available "$name" "$case_root/run/facelock/lifecycle.lock"
}

run_first_install_unconfirmed_recovery_case

run_final_restart_window_refusal_case() {
    local name=cleanup_pre_restart_mask_race
    local case_root="$tmp_root/$name"
    local barrier="$case_root/run/systemd/system.control/facelock-daemon.service"
    local runtime_mask="$case_root/run/systemd/system/facelock-daemon.service"
    local after_write="$case_root/after-write"
    local status

    mkdir -p "$case_root/etc/systemd/system" \
        "$case_root/run/systemd/system" "$case_root/assets"
    write_standard_dbus_config "$case_root"
    : >"$case_root/assets/facelock-daemon.service"
    write_dbus_service "$case_root/assets/org.facelock.Daemon.service"
    : >"$case_root/actual"
    printf '%s\n' none >"$case_root/mask-state"
    printf '%s\n' none >"$case_root/manager-mask-state"

    set +e
    PATH="$tmp_root/bin:$PATH" \
        FACELOCK_SYSTEMCTL_LOG="$case_root/actual" \
        FACELOCK_SHOW_STATUS=0 \
        FACELOCK_LOAD_STATE=loaded \
        FACELOCK_ACTIVE_STATE=active \
        FACELOCK_UNIT_FILE_STATE=disabled \
        FACELOCK_MASK_STATE="$case_root/mask-state" \
        FACELOCK_MANAGER_MASK_STATE="$case_root/manager-mask-state" \
        FACELOCK_RUNTIME_DIR="$case_root/run/systemd/system" \
        FACELOCK_AFTER_WRITE_FILE="$after_write" \
        FACELOCK_MUTATE_MASK_BEFORE_RESTART="$runtime_mask" \
        bash -c '
            set -euo pipefail
            source "$1"
            facelock_source_install_begin_daemon "$2" "$3" "$4"
            printf "%s\n" write >>"$FACELOCK_SYSTEMCTL_LOG"
            : >"$FACELOCK_AFTER_WRITE_FILE"
            facelock_source_install_complete_daemon "$2"
        ' _ "$lifecycle_script" "$case_root/run/systemd/system" \
        "$case_root/assets/facelock-daemon.service" \
        "$case_root/assets/org.facelock.Daemon.service" \
        2>"$case_root/stderr"
    status=$?
    set -e

    [ "$status" -eq 1 ] || fail "$name did not reject the last-window race"
    [ ! -e "$barrier" ] && [ ! -L "$barrier" ] ||
        fail "$name unexpectedly recreated the retired barrier"
    [ -L "$runtime_mask" ] && [ "$(readlink -- "$runtime_mask")" = /dev/null ] ||
        fail "$name changed the concurrently installed administrator mask"
    ! grep -Fq 'systemctl start facelock-daemon.service' "$case_root/actual" ||
        fail "$name restarted after the last cleanup proof changed"
    assert_lock_available "$name" "$case_root/run/facelock/lifecycle.lock"
}

run_final_restart_window_refusal_case

run_restart_proof_refusal_case() {
    local name="$1"
    local fault="$2"
    local case_root="$tmp_root/$name"
    local runtime_mask="$case_root/run/systemd/system/facelock-daemon.service"
    local dbus_service="$case_root/assets/org.facelock.Daemon.service"
    local failures_remaining="$case_root/failures-remaining"
    local after_write="$case_root/after-write"
    local status start_count

    mkdir -p "$case_root/etc/systemd/system" \
        "$case_root/run/systemd/system" "$case_root/assets"
    write_standard_dbus_config "$case_root"
    : >"$case_root/assets/facelock-daemon.service"
    write_dbus_service "$dbus_service"
    : >"$case_root/actual"
    printf '%s\n' none >"$case_root/mask-state"
    printf '%s\n' none >"$case_root/manager-mask-state"
    printf '%s\n' "$([ "$fault" = retry_mask ] && printf 1 || printf 0)" \
        >"$failures_remaining"

    set +e
    PATH="$tmp_root/bin:$PATH" \
        FACELOCK_SYSTEMCTL_LOG="$case_root/actual" \
        FACELOCK_SHOW_STATUS=0 \
        FACELOCK_LOAD_STATE=loaded \
        FACELOCK_ACTIVE_STATE=active \
        FACELOCK_UNIT_FILE_STATE=disabled \
        FACELOCK_MASK_STATE="$case_root/mask-state" \
        FACELOCK_MANAGER_MASK_STATE="$case_root/manager-mask-state" \
        FACELOCK_RUNTIME_DIR="$case_root/run/systemd/system" \
        FACELOCK_AFTER_WRITE_FILE="$after_write" \
        FACELOCK_FAIL_COMMAND="$([ "$fault" = retry_mask ] && \
            printf 'start facelock-daemon.service' || printf '')" \
        FACELOCK_FAILURES_REMAINING="$failures_remaining" \
        FACELOCK_MUTATE_MASK_BEFORE_START_RETRY="$([ "$fault" = retry_mask ] && \
            printf '%s' "$runtime_mask" || printf '')" \
        FACELOCK_DBUS_SERVICE_TO_MUTATE_AFTER_START="$([ "$fault" = post_start_dbus ] && \
            printf '%s' "$dbus_service" || printf '')" \
        bash -c '
            set -euo pipefail
            source "$1"
            facelock_source_install_begin_daemon "$2" "$3" "$4"
            printf "%s\n" write >>"$FACELOCK_SYSTEMCTL_LOG"
            : >"$FACELOCK_AFTER_WRITE_FILE"
            facelock_source_install_complete_daemon "$2"
        ' _ "$lifecycle_script" "$case_root/run/systemd/system" \
        "$case_root/assets/facelock-daemon.service" "$dbus_service" \
        2>"$case_root/stderr"
    status=$?
    set -e

    [ "$status" -eq 1 ] || fail "$name accepted an unproved restart state"
    start_count="$(grep -Fxc 'systemctl start facelock-daemon.service' \
        "$case_root/actual" || true)"
    [ "$start_count" -eq 1 ] || fail "$name issued $start_count restart attempts"
    if [ "$fault" = retry_mask ]; then
        [ -L "$runtime_mask" ] && [ "$(readlink -- "$runtime_mask")" = /dev/null ] ||
            fail "$name changed the concurrent administrator mask"
    fi
    assert_lock_available "$name" "$case_root/run/facelock/lifecycle.lock"
}

run_restart_proof_refusal_case restart_retry_mask_race retry_mask
run_restart_proof_refusal_case restart_post_start_dbus_race post_start_dbus

run_release_signal_window_case() {
    local name=release_signal_restores_once
    local case_root="$tmp_root/$name"
    local after_write="$case_root/after-write"
    local release_count="$case_root/release-count"
    local status

    mkdir -p "$case_root/run/systemd/system" "$case_root/assets"
    write_standard_dbus_config "$case_root"
    : >"$case_root/assets/facelock-daemon.service"
    write_dbus_service "$case_root/assets/org.facelock.Daemon.service"
    : >"$case_root/actual"
    : >"$release_count"
    printf '%s\n' none >"$case_root/mask-state"
    printf '%s\n' none >"$case_root/manager-mask-state"

    set +e
    PATH="$tmp_root/bin:$PATH" \
        FACELOCK_SYSTEMCTL_LOG="$case_root/actual" \
        FACELOCK_SHOW_STATUS=0 \
        FACELOCK_LOAD_STATE=loaded \
        FACELOCK_ACTIVE_STATE=active \
        FACELOCK_UNIT_FILE_STATE=disabled \
        FACELOCK_MASK_STATE="$case_root/mask-state" \
        FACELOCK_MANAGER_MASK_STATE="$case_root/manager-mask-state" \
        FACELOCK_RUNTIME_DIR="$case_root/run/systemd/system" \
        FACELOCK_AFTER_WRITE_FILE="$after_write" \
        FACELOCK_REQUIRE_RESTORE_LOCK=true \
        FACELOCK_LOCK_PATH="$case_root/run/facelock/lifecycle.lock" \
        FACELOCK_RELEASE_COUNT="$release_count" \
        bash -c '
            set -euo pipefail
            source "$1"
            facelock_source_install_release_lock() {
                if [ "$FACELOCK_SOURCE_INSTALL_LOCK_HELD" = true ]; then
                    exec {FACELOCK_SOURCE_INSTALL_LOCK_FD}>&-
                    FACELOCK_SOURCE_INSTALL_LOCK_FD=
                    FACELOCK_SOURCE_INSTALL_LOCK_HELD=false
                fi
                printf "release\n" >>"$FACELOCK_RELEASE_COUNT"
                if [ ! -e "${FACELOCK_RELEASE_COUNT}.signaled" ]; then
                    : >"${FACELOCK_RELEASE_COUNT}.signaled"
                    kill -HUP "$$"
                fi
            }
            facelock_source_install_begin_daemon "$2" "$3" "$4"
            printf "%s\n" write >>"$FACELOCK_SYSTEMCTL_LOG"
            : >"$FACELOCK_AFTER_WRITE_FILE"
            facelock_source_install_complete_daemon "$2"
        ' _ "$lifecycle_script" "$case_root/run/systemd/system" \
        "$case_root/assets/facelock-daemon.service" \
        "$case_root/assets/org.facelock.Daemon.service" \
        2>"$case_root/stderr"
    status=$?
    set -e

    [ "$status" -eq 129 ] || fail "$name exited $status instead of 129"
    [ "$(grep -c '^release$' "$release_count")" -eq 1 ] ||
        fail "$name re-entered restoration after lock release"
    assert_lock_available "$name" "$case_root/run/facelock/lifecycle.lock"
}

run_release_signal_window_case

run_restoration_case() {
    local name="$1"
    local trigger="$2"
    local fail_command="$3"
    local failure_count="$4"
    local expected_status="$5"
    local expected="$6"
    local case_root="$tmp_root/$name"
    local actual="$case_root/actual"
    local expected_path="$case_root/expected"
    local stderr_path="$case_root/stderr"
    local mask_state="$case_root/mask-state"
    local manager_mask_state="$case_root/manager-mask-state"
    local after_write="$case_root/after-write"
    local failures_remaining="$case_root/failures-remaining"
    local status

    mkdir -p "$case_root/run/systemd/system" "$case_root/assets"
    write_standard_dbus_config "$case_root"
    : >"$case_root/assets/facelock-daemon.service"
    write_dbus_service "$case_root/assets/org.facelock.Daemon.service"
    : >"$actual"
    printf '%s\n' "$expected" >"$expected_path"
    printf '%s\n' none >"$mask_state"
    printf '%s\n' none >"$manager_mask_state"
    printf '%s\n' "$failure_count" >"$failures_remaining"

    set +e
    PATH="$tmp_root/bin:$PATH" \
        FACELOCK_SYSTEMCTL_LOG="$actual" \
        FACELOCK_SHOW_STATUS=0 \
        FACELOCK_LOAD_STATE=loaded \
        FACELOCK_ACTIVE_STATE=active \
        FACELOCK_UNIT_FILE_STATE=disabled \
        FACELOCK_MASK_STATE="$mask_state" \
        FACELOCK_MANAGER_MASK_STATE="$manager_mask_state" \
        FACELOCK_RUNTIME_DIR="$case_root/run/systemd/system" \
        FACELOCK_AFTER_WRITE_FILE="$after_write" \
        FACELOCK_FAIL_COMMAND="$fail_command" \
        FACELOCK_FAILURES_REMAINING="$failures_remaining" \
        bash -c '
            set -euo pipefail
            source "$1"
            facelock_source_install_begin_daemon "$2" "$3" "$4"
            printf "%s\n" write >>"$FACELOCK_SYSTEMCTL_LOG"
            : >"$FACELOCK_AFTER_WRITE_FILE"
            case "$5" in
                write_failure) false ;;
                HUP | INT | TERM) kill -s "$5" "$$" ;;
                complete) facelock_source_install_complete_daemon "$2" ;;
            esac
        ' _ \
        "$lifecycle_script" \
        "$case_root/run/systemd/system" \
        "$case_root/assets/facelock-daemon.service" \
        "$case_root/assets/org.facelock.Daemon.service" \
        "$trigger" \
        2>"$stderr_path"
    status=$?
    set -e

    [ "$status" -eq "$expected_status" ] || {
        cat "$stderr_path" >&2
        fail "$name exited $status, expected $expected_status"
    }
    [ "$(cat "$mask_state")" = none ] ||
        fail "$name left the temporary activation barrier installed"
    [ ! -e "$case_root/run/systemd/system.control/facelock-daemon.service" ] ||
        fail "$name left the owned activation barrier installed"
    diff -u "$expected_path" "$actual" ||
        fail "$name restoration ordering changed"
    assert_lock_available "$name" "$case_root/run/facelock/lifecycle.lock"
}

active_prepare_log="$(printf '%s\n' \
    "$show_command" \
    "$dbus_show_command" \
    "$dbus_reload_command" \
    "$dbus_owner_command" \
    'systemctl daemon-reload' \
    "$barrier_show_command" \
    'systemctl stop facelock-daemon.service' \
    "$barrier_show_command" \
    "$dbus_owner_command" \
    'write')"
active_restore_before_restart_log="$(printf '%s\n' \
    'systemctl daemon-reload' \
    "$dbus_reload_command" \
    "$barrier_show_command" \
    "$dbus_owner_command" \
    'systemctl daemon-reload' \
    "$show_command" \
    "$dbus_owner_command" \
    "$show_command" \
    "$dbus_owner_command")"
active_restore_log="$active_restore_before_restart_log
$(printf '%s\n' \
    "$show_command" \
    "$dbus_owner_command" \
    'systemctl start facelock-daemon.service')"
active_restore_log="$active_restore_log
$(printf '%s\n' \
    "$show_command" \
    "$dbus_owner_command")"

run_restoration_case write_failure write_failure '' 0 1 \
    "$active_prepare_log
$active_restore_log"
run_restoration_case hangup HUP '' 0 129 \
    "$active_prepare_log
$active_restore_log"
run_restoration_case interrupt INT '' 0 130 \
    "$active_prepare_log
$active_restore_log"
run_restoration_case terminate TERM '' 0 143 \
    "$active_prepare_log
$active_restore_log"

run_restoration_case reload_retry complete 'daemon-reload' 1 0 \
    "$active_prepare_log
$(printf '%s\n' \
    'systemctl daemon-reload' \
    'systemctl daemon-reload' \
    "$dbus_reload_command" \
    "$barrier_show_command" \
    "$dbus_owner_command" \
    'systemctl daemon-reload' \
    "$show_command" \
    "$dbus_owner_command" \
    "$show_command" \
    "$dbus_owner_command" \
    "$show_command" \
    "$dbus_owner_command" \
    'systemctl start facelock-daemon.service' \
    "$show_command" \
    "$dbus_owner_command")"

run_restoration_case start_retry complete 'start facelock-daemon.service' 1 0 \
    "$active_prepare_log
$active_restore_before_restart_log
$(printf '%s\n' \
    "$show_command" \
    "$dbus_owner_command" \
    'systemctl start facelock-daemon.service' \
    "$show_command" \
    "$dbus_owner_command" \
    'systemctl start facelock-daemon.service' \
    "$show_command" \
    "$dbus_owner_command")"

run_restoration_case start_exhausted complete 'start facelock-daemon.service' 3 1 \
    "$active_prepare_log
$active_restore_before_restart_log
$(printf '%s\n' \
    "$show_command" \
    "$dbus_owner_command" \
    'systemctl start facelock-daemon.service' \
    "$show_command" \
    "$dbus_owner_command" \
    'systemctl start facelock-daemon.service' \
    "$show_command" \
    "$dbus_owner_command" \
    'systemctl start facelock-daemon.service')"

seed_known_legacy_assets() {
    local case_root="$1"
    local record source_relative canonical_relative legacy_relative
    local -a assets=(
        'systemd-unit|systemd/facelock-daemon.service|usr/lib/systemd/system/facelock-daemon.service|etc/systemd/system/facelock-daemon.service'
        'dbus-policy|dbus/org.facelock.Daemon.conf|usr/share/dbus-1/system.d/org.facelock.Daemon.conf|etc/dbus-1/system.d/org.facelock.Daemon.conf'
        'dbus-activation|dbus/org.facelock.Daemon.service|usr/share/dbus-1/system-services/org.facelock.Daemon.service|etc/dbus-1/system-services/org.facelock.Daemon.service'
    )

    mkdir -p "$case_root/usr/lib/systemd/system" \
        "$case_root/usr/share/dbus-1/system.d" \
        "$case_root/usr/share/dbus-1/system-services" \
        "$case_root/etc/systemd/system" \
        "$case_root/etc/dbus-1/system.d" \
        "$case_root/etc/dbus-1/system-services" \
        "$case_root/run/systemd/system"
    for record in "${assets[@]}"; do
        IFS='|' read -r _ source_relative canonical_relative legacy_relative <<<"$record"
        install -m 644 "$repo_root/$source_relative" "$case_root/$canonical_relative"
        install -m 644 "$repo_root/$source_relative" "$case_root/$legacy_relative"
    done
}

run_planned_legacy_retirement_case() {
    local name=planned_legacy_retirement
    local case_root="$tmp_root/$name"
    local record legacy_relative
    local -a assets=(
        'systemd-unit|systemd/facelock-daemon.service|usr/lib/systemd/system/facelock-daemon.service|etc/systemd/system/facelock-daemon.service'
        'dbus-policy|dbus/org.facelock.Daemon.conf|usr/share/dbus-1/system.d/org.facelock.Daemon.conf|etc/dbus-1/system.d/org.facelock.Daemon.conf'
        'dbus-activation|dbus/org.facelock.Daemon.service|usr/share/dbus-1/system-services/org.facelock.Daemon.service|etc/dbus-1/system-services/org.facelock.Daemon.service'
    )

    seed_known_legacy_assets "$case_root"

    {
        set -euo pipefail
        # shellcheck disable=SC1090,SC1091
        source "$lifecycle_script"
        export FACELOCK_SOURCE_INSTALL_DBUS_LAYOUT_PREFIX="$case_root"
        export FACELOCK_SOURCE_INSTALL_TRUST_UID
        FACELOCK_SOURCE_INSTALL_TRUST_UID="$(stat -c %u -- "$case_root")"
        export FACELOCK_SOURCE_INSTALL_TRUST_GID
        FACELOCK_SOURCE_INSTALL_TRUST_GID="$(stat -c %g -- "$case_root")"
        FACELOCK_SOURCE_INSTALL_PERSISTENT_MASK_PATH="$case_root/etc/systemd/system/facelock-daemon.service"
        FACELOCK_SOURCE_INSTALL_RUNTIME_MASK_PATH="$case_root/run/systemd/system/facelock-daemon.service"

        facelock_source_install_plan_legacy_assets || {
            echo "$name: planning failed" >&2
            exit 1
        }
        [ "$FACELOCK_SOURCE_INSTALL_PERSISTENT_UNIT_PLANNED_RETIRE" = true ] || {
            echo "$name: persistent retirement was not planned" >&2
            exit 1
        }
        facelock_source_install_snapshot_physical_mask \
            "$FACELOCK_SOURCE_INSTALL_PERSISTENT_MASK_PATH" \
            FACELOCK_SOURCE_INSTALL_PERSISTENT_MASK_SNAPSHOT \
            FACELOCK_SOURCE_INSTALL_PERSISTENT_MASK_FD || {
            echo "$name: persistent snapshot failed" >&2
            exit 1
        }
        facelock_source_install_snapshot_physical_mask \
            "$FACELOCK_SOURCE_INSTALL_RUNTIME_MASK_PATH" \
            FACELOCK_SOURCE_INSTALL_RUNTIME_MASK_SNAPSHOT \
            FACELOCK_SOURCE_INSTALL_RUNTIME_MASK_FD || {
            echo "$name: runtime snapshot failed" >&2
            exit 1
        }

        "$repo_root/scripts/migrate-legacy-system-assets.sh" \
            --source-protected --stage "$case_root" || {
            echo "$name: staging failed" >&2
            exit 1
        }
        facelock_source_install_record_legacy_migration || {
            echo "$name: staged identity recording failed" >&2
            exit 1
        }
        facelock_source_install_physical_masks_are_current || {
            echo "$name: staged physical identity proof failed" >&2
            exit 1
        }
        [ -f "$case_root/etc/systemd/system/.facelock-migrate-systemd-unit" ]
        [ -f "$case_root/etc/dbus-1/system.d/.facelock-migrate-dbus-policy" ]
        [ -f "$case_root/etc/dbus-1/system-services/.facelock-migrate-dbus-activation" ]
        facelock_source_install_commit_legacy_migration || {
            echo "$name: commit failed" >&2
            exit 1
        }
        facelock_source_install_physical_masks_are_current || {
            echo "$name: committed physical identity proof failed" >&2
            exit 1
        }
        facelock_source_install_release_physical_mask_fds
    } || fail "$name did not accept the planned exact-known retirement"

    for record in "${assets[@]}"; do
        IFS='|' read -r _ _ _ legacy_relative <<<"$record"
        [ ! -e "$case_root/$legacy_relative" ] && [ ! -L "$case_root/$legacy_relative" ] ||
            fail "$name retained $legacy_relative"
    done
    [ ! -e "$case_root/etc/systemd/system/.facelock-migrate-systemd-unit" ] ||
        fail "$name retained the systemd quarantine"
    [ ! -e "$case_root/etc/dbus-1/system.d/.facelock-migrate-dbus-policy" ] ||
        fail "$name retained the D-Bus policy quarantine"
    [ ! -e "$case_root/etc/dbus-1/system-services/.facelock-migrate-dbus-activation" ] ||
        fail "$name retained the D-Bus activation quarantine"
}

run_planned_legacy_retirement_case

run_modified_dbus_admin_case() {
    local name=modified_dbus_admin
    local case_root="$tmp_root/$name"
    local policy="$case_root/etc/dbus-1/system.d/org.facelock.Daemon.conf"
    local activation="$case_root/etc/dbus-1/system-services/org.facelock.Daemon.service"

    seed_known_legacy_assets "$case_root"
    printf '%s\n' 'administrator policy' >"$policy"
    cat >"$activation" <<'EOF'
[D-BUS Service]
Name=org.facelock.Daemon
SystemdService=facelock-daemon.service
EOF
    chmod 644 "$policy" "$activation"

    {
        set -euo pipefail
        # shellcheck disable=SC1090,SC1091
        source "$lifecycle_script"
        FACELOCK_SOURCE_INSTALL_DBUS_LAYOUT_PREFIX="$case_root"
        FACELOCK_SOURCE_INSTALL_TRUST_UID="$(stat -c %u -- "$case_root")"
        FACELOCK_SOURCE_INSTALL_TRUST_GID="$(stat -c %g -- "$case_root")"
        facelock_source_install_plan_legacy_assets
        "$repo_root/scripts/migrate-legacy-system-assets.sh" \
            --source-protected --stage "$case_root"
        facelock_source_install_record_legacy_migration
        facelock_source_install_commit_legacy_migration
    } || fail "$name rejected trusted administrator D-Bus definitions"

    [ "$(cat "$policy")" = 'administrator policy' ] ||
        fail "$name changed the administrator D-Bus policy"
    grep -Fxq 'SystemdService=facelock-daemon.service' "$activation" ||
        fail "$name changed the administrator D-Bus activation definition"
    [ ! -e "$case_root/etc/dbus-1/system.d/.facelock-migrate-dbus-policy" ] ||
        fail "$name created a policy quarantine"
    [ ! -e "$case_root/etc/dbus-1/system-services/.facelock-migrate-dbus-activation" ] ||
        fail "$name created an activation quarantine"
}

run_modified_dbus_admin_case

run_commit_failure_rolls_back_case() {
    local name=commit_failure_rolls_back
    local case_root="$tmp_root/$name"
    local status

    seed_known_legacy_assets "$case_root"
    set +e
    CASE_ROOT="$case_root" REPO_ROOT="$repo_root" LIFECYCLE_SCRIPT="$lifecycle_script" \
        bash -c '
            set -euo pipefail
            source "$LIFECYCLE_SCRIPT"
            FACELOCK_SOURCE_INSTALL_DBUS_LAYOUT_PREFIX="$CASE_ROOT"
            FACELOCK_SOURCE_INSTALL_TRUST_UID="$(stat -c %u -- "$CASE_ROOT")"
            FACELOCK_SOURCE_INSTALL_TRUST_GID="$(stat -c %g -- "$CASE_ROOT")"
            facelock_source_install_plan_legacy_assets
            "$REPO_ROOT/scripts/migrate-legacy-system-assets.sh" \
                --source-protected --stage "$CASE_ROOT"
            facelock_source_install_record_legacy_migration
            rm() {
                case "${*: -1}" in
                    */.facelock-migrate-*) return 1 ;;
                    *) command rm "$@" ;;
                esac
            }
            if facelock_source_install_commit_legacy_migration; then
                exit 97
            fi
            facelock_source_install_rollback_legacy_migration
        ' 2>"$case_root/stderr"
    status=$?
    set -e

    [ "$status" -eq 0 ] || {
        cat "$case_root/stderr" >&2
        fail "$name failed to restore staged assets"
    }
    for legacy in \
        etc/systemd/system/facelock-daemon.service \
        etc/dbus-1/system.d/org.facelock.Daemon.conf \
        etc/dbus-1/system-services/org.facelock.Daemon.service; do
        [ -f "$case_root/$legacy" ] || fail "$name did not restore $legacy"
    done
}

run_commit_failure_rolls_back_case

run_after_stage_rollback_case() {
    local trigger="$1"
    local expected_status="$2"
    local name="rollback_after_stage_$trigger"
    local case_root="$tmp_root/$name"
    local status

    seed_known_legacy_assets "$case_root"
    set +e
    CASE_ROOT="$case_root" REPO_ROOT="$repo_root" LIFECYCLE_SCRIPT="$lifecycle_script" \
        bash -c '
            set -euo pipefail
            source "$LIFECYCLE_SCRIPT"
            FACELOCK_SOURCE_INSTALL_DBUS_LAYOUT_PREFIX="$CASE_ROOT"
            FACELOCK_SOURCE_INSTALL_TRUST_UID="$(stat -c %u -- "$CASE_ROOT")"
            FACELOCK_SOURCE_INSTALL_TRUST_GID="$(stat -c %g -- "$CASE_ROOT")"
            facelock_source_install_plan_legacy_assets
            "$REPO_ROOT/scripts/migrate-legacy-system-assets.sh" \
                --source-protected --stage "$CASE_ROOT"
            facelock_source_install_record_legacy_migration
            FACELOCK_SOURCE_INSTALL_SYSTEMD_RUNTIME_DIR=
            if [ "$1" = signal ]; then
                facelock_source_install_arm_daemon_restore
                kill -TERM "$$"
                exit 99
            fi
            facelock_source_install_finish_daemon 1
        ' _ "$trigger" 2>"$case_root/stderr"
    status=$?
    set -e

    [ "$status" -eq "$expected_status" ] || {
        cat "$case_root/stderr" >&2
        fail "$name exited $status, expected $expected_status"
    }
    for legacy in \
        etc/systemd/system/facelock-daemon.service \
        etc/dbus-1/system.d/org.facelock.Daemon.conf \
        etc/dbus-1/system-services/org.facelock.Daemon.service; do
        [ -f "$case_root/$legacy" ] || fail "$name did not restore $legacy"
    done
    [ ! -e "$case_root/etc/systemd/system/.facelock-migrate-systemd-unit" ] ||
        fail "$name retained the systemd quarantine"
    [ ! -e "$case_root/etc/dbus-1/system.d/.facelock-migrate-dbus-policy" ] ||
        fail "$name retained the D-Bus policy quarantine"
    [ ! -e "$case_root/etc/dbus-1/system-services/.facelock-migrate-dbus-activation" ] ||
        fail "$name retained the D-Bus activation quarantine"
}

run_after_stage_rollback_case failure 1
run_after_stage_rollback_case signal 143

run_rollback_collision_never_publishes_case() {
    local name=rollback_collision_never_publishes
    local case_root="$tmp_root/$name"
    local output="$case_root/output"
    local status

    seed_known_legacy_assets "$case_root"
    set +e
    CASE_ROOT="$case_root" REPO_ROOT="$repo_root" LIFECYCLE_SCRIPT="$lifecycle_script" \
        bash -c '
            set -euo pipefail
            source "$LIFECYCLE_SCRIPT"
            FACELOCK_SOURCE_INSTALL_DBUS_LAYOUT_PREFIX="$CASE_ROOT"
            FACELOCK_SOURCE_INSTALL_TRUST_UID="$(stat -c %u -- "$CASE_ROOT")"
            FACELOCK_SOURCE_INSTALL_TRUST_GID="$(stat -c %g -- "$CASE_ROOT")"
            facelock_source_install_plan_legacy_assets
            "$REPO_ROOT/scripts/migrate-legacy-system-assets.sh" \
                --source-protected --stage "$CASE_ROOT"
            facelock_source_install_record_legacy_migration
            printf "%s\n" collision >"$CASE_ROOT/etc/systemd/system/facelock-daemon.service"
            chmod 644 "$CASE_ROOT/etc/systemd/system/facelock-daemon.service"
            FACELOCK_SOURCE_INSTALL_SYSTEMD_RUNTIME_DIR=
            facelock_source_install_finish_daemon 1
        ' >"$output" 2>&1
    status=$?
    set -e

    [ "$status" -ne 0 ] || fail "$name unexpectedly succeeded"
    [ -f "$case_root/etc/systemd/system/.facelock-migrate-systemd-unit" ] ||
        fail "$name unlinked the rollback-blocked quarantine"
    ! grep -Fq 'Removed exact known legacy system asset' "$output" ||
        fail "$name entered publication after rollback failed"
}

run_rollback_collision_never_publishes_case

run_unrecorded_mixed_prefix_recovery_case() {
    local name=unrecorded_mixed_prefix_recovery
    local case_root="$tmp_root/$name"
    local public quarantine

    seed_known_legacy_assets "$case_root"
    public="$case_root/etc/systemd/system/facelock-daemon.service"
    quarantine="$case_root/etc/systemd/system/.facelock-migrate-systemd-unit"
    {
        set -euo pipefail
        # shellcheck disable=SC1090,SC1091
        source "$lifecycle_script"
        FACELOCK_SOURCE_INSTALL_DBUS_LAYOUT_PREFIX="$case_root"
        FACELOCK_SOURCE_INSTALL_TRUST_UID="$(stat -c %u -- "$case_root")"
        FACELOCK_SOURCE_INSTALL_TRUST_GID="$(stat -c %g -- "$case_root")"
        facelock_source_install_plan_legacy_assets
        mv -Tn -- "$public" "$quarantine"
        [ "$FACELOCK_SOURCE_INSTALL_LEGACY_MIGRATION_RECORDED" = false ]
        facelock_source_install_rollback_legacy_migration
    } || fail "$name could not reconcile a staged-but-unrecorded prefix"
    [ -f "$public" ] && [ ! -e "$quarantine" ] ||
        fail "$name did not restore the preplanned public identity"
}

run_unrecorded_mixed_prefix_recovery_case

run_unrecorded_interrupted_recovery_case() {
    local name=unrecorded_initial_interrupted_recovery
    local case_root="$tmp_root/$name"
    local public quarantine

    seed_known_legacy_assets "$case_root"
    public="$case_root/etc/dbus-1/system.d/org.facelock.Daemon.conf"
    quarantine="$case_root/etc/dbus-1/system.d/.facelock-migrate-dbus-policy"
    mv -Tn -- "$public" "$quarantine"
    {
        set -euo pipefail
        # shellcheck disable=SC1090,SC1091
        source "$lifecycle_script"
        export FACELOCK_SOURCE_INSTALL_DBUS_LAYOUT_PREFIX="$case_root"
        export FACELOCK_SOURCE_INSTALL_TRUST_UID
        FACELOCK_SOURCE_INSTALL_TRUST_UID="$(stat -c %u -- "$case_root")"
        export FACELOCK_SOURCE_INSTALL_TRUST_GID
        FACELOCK_SOURCE_INSTALL_TRUST_GID="$(stat -c %g -- "$case_root")"
        facelock_source_install_plan_legacy_assets
        mv -Tn -- "$quarantine" "$public"
        facelock_source_install_rollback_legacy_migration
    } || fail "$name could not restore the initial interrupted quarantine"
    [ ! -e "$public" ] && [ -f "$quarantine" ] ||
        fail "$name changed the preplanned interrupted identity"
}

run_unrecorded_interrupted_recovery_case

run_unrecorded_mixed_prefix_collision_case() {
    local name=unrecorded_mixed_prefix_collision
    local case_root="$tmp_root/$name"
    local public quarantine status

    seed_known_legacy_assets "$case_root"
    public="$case_root/etc/systemd/system/facelock-daemon.service"
    quarantine="$case_root/etc/systemd/system/.facelock-migrate-systemd-unit"
    set +e
    CASE_ROOT="$case_root" PUBLIC="$public" QUARANTINE="$quarantine" \
        LIFECYCLE_SCRIPT="$lifecycle_script" bash -c '
            set -euo pipefail
            source "$LIFECYCLE_SCRIPT"
            FACELOCK_SOURCE_INSTALL_DBUS_LAYOUT_PREFIX="$CASE_ROOT"
            FACELOCK_SOURCE_INSTALL_TRUST_UID="$(stat -c %u -- "$CASE_ROOT")"
            FACELOCK_SOURCE_INSTALL_TRUST_GID="$(stat -c %g -- "$CASE_ROOT")"
            facelock_source_install_plan_legacy_assets
            mv -Tn -- "$PUBLIC" "$QUARANTINE"
            printf "%s\n" collision >"$PUBLIC"
            chmod 644 "$PUBLIC"
            ! facelock_source_install_rollback_legacy_migration
        ' 2>"$case_root/stderr"
    status=$?
    set -e

    [ "$status" -eq 0 ] || fail "$name did not reject the ambiguous pair"
    [ -f "$public" ] && [ -f "$quarantine" ] ||
        fail "$name did not preserve both ambiguous names"
}

run_unrecorded_mixed_prefix_collision_case

run_parent_signal_during_stage_case() {
    local signal="$1"
    local expected_status="$2"
    local name="parent_${signal,,}_during_stage"
    local case_root="$tmp_root/$name"
    local status

    seed_known_legacy_assets "$case_root"
    set +e
    CASE_ROOT="$case_root" REPO_ROOT="$repo_root" \
        LIFECYCLE_SCRIPT="$lifecycle_script" FACELOCK_TEST_SIGNAL="$signal" \
        bash -c '
            set -euo pipefail
            source "$LIFECYCLE_SCRIPT"
            FACELOCK_SOURCE_INSTALL_DBUS_LAYOUT_PREFIX="$CASE_ROOT"
            FACELOCK_SOURCE_INSTALL_TRUST_UID="$(stat -c %u -- "$CASE_ROOT")"
            FACELOCK_SOURCE_INSTALL_TRUST_GID="$(stat -c %g -- "$CASE_ROOT")"
            FACELOCK_SOURCE_INSTALL_SYSTEMD_RUNTIME_DIR=
            facelock_source_install_plan_legacy_assets
            facelock_source_install_arm_daemon_restore
            facelock_source_install_invoke_legacy_stage() {
                "$REPO_ROOT/scripts/migrate-legacy-system-assets.sh" \
                    --source-protected --stage "$1" &
                child=$!
                kill -s "$FACELOCK_TEST_SIGNAL" "$$"
                wait "$child"
            }
            facelock_source_install_stage_and_record_legacy_migration "$CASE_ROOT"
        ' 2>"$case_root/stderr"
    status=$?
    set -e

    [ "$status" -eq "$expected_status" ] || {
        cat "$case_root/stderr" >&2
        fail "$name exited $status, expected $expected_status"
    }
    for legacy in \
        etc/systemd/system/facelock-daemon.service \
        etc/dbus-1/system.d/org.facelock.Daemon.conf \
        etc/dbus-1/system-services/org.facelock.Daemon.service; do
        [ -f "$case_root/$legacy" ] || fail "$name did not restore $legacy"
    done
    ! find "$case_root/etc" -name '.facelock-migrate-*' -print -quit | grep -q . ||
        fail "$name retained a candidate quarantine"
}

run_parent_signal_during_stage_case TERM 143
run_parent_signal_during_stage_case HUP 129

run_partial_commit_retains_barrier_case() {
    local name=partial_commit_retains_barrier
    local case_root="$tmp_root/$name"
    local barrier="$case_root/run/systemd/system.control/facelock-daemon.service"
    local status

    seed_known_legacy_assets "$case_root"
    write_standard_dbus_config "$case_root"
    : >"$case_root/actual"
    printf '%s\n' none >"$case_root/mask-state"
    printf '%s\n' none >"$case_root/manager-mask-state"
    set +e
    PATH="$tmp_root/bin:$PATH" \
        FACELOCK_SYSTEMCTL_LOG="$case_root/actual" \
        FACELOCK_SHOW_STATUS=0 \
        FACELOCK_LOAD_STATE=loaded \
        FACELOCK_ACTIVE_STATE=active \
        FACELOCK_UNIT_FILE_STATE=disabled \
        FACELOCK_MASK_STATE="$case_root/mask-state" \
        FACELOCK_MANAGER_MASK_STATE="$case_root/manager-mask-state" \
        FACELOCK_FRAGMENT_PATH_OVERRIDE="$case_root/etc/systemd/system/facelock-daemon.service" \
        FACELOCK_RUNTIME_DIR="$case_root/run/systemd/system" \
        FACELOCK_FAIL_MIGRATION_UNLINK_NUMBER=2 \
        FACELOCK_MIGRATION_UNLINK_COUNT="$case_root/migration-unlink-count" \
        CASE_ROOT="$case_root" REPO_ROOT="$repo_root" \
        LIFECYCLE_SCRIPT="$lifecycle_script" bash -c '
            set -euo pipefail
            source "$LIFECYCLE_SCRIPT"
            facelock_source_install_begin_daemon \
                "$CASE_ROOT/run/systemd/system" \
                "$CASE_ROOT/usr/lib/systemd/system/facelock-daemon.service" \
                "$CASE_ROOT/usr/share/dbus-1/system-services/org.facelock.Daemon.service" \
                "$CASE_ROOT/etc/systemd/system/facelock-daemon.service" \
                "$CASE_ROOT/etc/dbus-1/system-services/org.facelock.Daemon.service"
            facelock_source_install_stage_and_record_legacy_migration "$CASE_ROOT"
            facelock_source_install_complete_daemon "$CASE_ROOT/run/systemd/system"
        ' 2>"$case_root/stderr"
    status=$?
    set -e

    [ "$status" -ne 0 ] || fail "$name unexpectedly succeeded"
    [ -f "$barrier" ] && [ ! -L "$barrier" ] && [ ! -s "$barrier" ] ||
        fail "$name did not retain the activation barrier"
    [ "$(cat "$case_root/manager-mask-state")" = masked ] ||
        fail "$name did not retain the manager-effective barrier"
    ! grep -Fq 'systemctl start facelock-daemon.service' "$case_root/actual" ||
        fail "$name restarted after partial migration publication"
}

run_partial_commit_retains_barrier_case

echo "source-install daemon lifecycle: OK"
