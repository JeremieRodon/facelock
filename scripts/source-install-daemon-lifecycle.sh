#!/usr/bin/env bash

FACELOCK_SOURCE_INSTALL_DAEMON_WAS_ACTIVE=false
FACELOCK_SOURCE_INSTALL_BARRIER_CREATED=false
FACELOCK_SOURCE_INSTALL_PREPARED=false
FACELOCK_SOURCE_INSTALL_RESTORING=false
FACELOCK_SOURCE_INSTALL_CRITICAL=false
FACELOCK_SOURCE_INSTALL_DEFERRED_SIGNAL=0
FACELOCK_SOURCE_INSTALL_SYSTEMD_RUNTIME_DIR=/run/systemd/system
FACELOCK_SOURCE_INSTALL_BARRIER_PATH=
FACELOCK_SOURCE_INSTALL_BARRIER_FD=
FACELOCK_SOURCE_INSTALL_BARRIER_QUARANTINE_PATH=
FACELOCK_SOURCE_INSTALL_BARRIER_QUARANTINED=false
FACELOCK_SOURCE_INSTALL_BARRIER_DIR_PATH=
FACELOCK_SOURCE_INSTALL_BARRIER_DIR_CREATED=false
FACELOCK_SOURCE_INSTALL_BARRIER_DIR_FD=
FACELOCK_SOURCE_INSTALL_STOP_SUCCEEDED=false
FACELOCK_SOURCE_INSTALL_LOCK_HELD=false
FACELOCK_SOURCE_INSTALL_LOCK_FD=
FACELOCK_SOURCE_INSTALL_DBUS_ASSETS=()
FACELOCK_SOURCE_INSTALL_INSTALLED_ASSETS=()
FACELOCK_SOURCE_INSTALL_DBUS_LAYOUT_PREFIX=
FACELOCK_SOURCE_INSTALL_TRUST_UID=
FACELOCK_SOURCE_INSTALL_TRUST_GID=
FACELOCK_SOURCE_INSTALL_PERSISTENT_MASK_PATH=
FACELOCK_SOURCE_INSTALL_PERSISTENT_MASK_SNAPSHOT=absent
FACELOCK_SOURCE_INSTALL_PERSISTENT_MASK_FD=
FACELOCK_SOURCE_INSTALL_RUNTIME_MASK_PATH=
FACELOCK_SOURCE_INSTALL_RUNTIME_MASK_SNAPSHOT=absent
FACELOCK_SOURCE_INSTALL_RUNTIME_MASK_FD=
FACELOCK_SOURCE_INSTALL_HAS_PHYSICAL_MASK=false
FACELOCK_SOURCE_INSTALL_PHYSICAL_MASK_WINNER=
FACELOCK_SOURCE_INSTALL_PERSISTENT_CONTROL_PATH=
FACELOCK_SOURCE_INSTALL_INITIAL_UNIT_NOT_FOUND=false
FACELOCK_SOURCE_INSTALL_INITIAL_DBUS_DEFINITION_ABSENT=false
FACELOCK_SOURCE_INSTALL_LEGACY_PLAN=()
FACELOCK_SOURCE_INSTALL_LEGACY_MIGRATION_RECORDED=false
FACELOCK_SOURCE_INSTALL_LEGACY_MIGRATION_COMMITTED=false
FACELOCK_SOURCE_INSTALL_LEGACY_RECONCILIATION_FAILED=false
FACELOCK_SOURCE_INSTALL_PERSISTENT_UNIT_PLANNED_RETIRE=false
FACELOCK_SOURCE_INSTALL_IDENTITY_RESULT=
FACELOCK_SOURCE_INSTALL_REPOSITORY_ROOT="$(
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P
)"

facelock_source_install_stat() {
    LC_ALL=C stat "$@"
}

facelock_source_install_retry() {
    local attempt=1

    while ! "$@"; do
        if [ "$attempt" -ge 3 ]; then
            return 1
        fi
        attempt=$((attempt + 1))
    done
}

facelock_source_install_handle_signal() {
    local signal="$1"
    local status

    case "$signal" in
        HUP) status=129 ;;
        INT) status=130 ;;
        TERM) status=143 ;;
        *) status=1 ;;
    esac

    if [ "$FACELOCK_SOURCE_INSTALL_CRITICAL" = true ] ||
        [ "$FACELOCK_SOURCE_INSTALL_RESTORING" = true ]; then
        FACELOCK_SOURCE_INSTALL_DEFERRED_SIGNAL="$status"
        return 0
    fi
    exit "$status"
}

facelock_source_install_arm_daemon_restore() {
    trap 'facelock_source_install_exit_handler' EXIT
    trap 'facelock_source_install_handle_signal HUP' HUP
    trap 'facelock_source_install_handle_signal INT' INT
    trap 'facelock_source_install_handle_signal TERM' TERM
}

facelock_source_install_default_assets() {
    printf '%s\n' \
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
        /lib/dbus-1/system-services/org.facelock.Daemon.service
}

facelock_source_install_create_barrier() {
    local barrier_dir="$1"
    local had_noclobber=false
    local create_status=0
    local directory_mode original_umask

    FACELOCK_SOURCE_INSTALL_BARRIER_DIR_PATH="$barrier_dir"
    if [ -L "$barrier_dir" ] || {
        [ -e "$barrier_dir" ] && [ ! -d "$barrier_dir" ];
    }; then
        return 1
    fi
    facelock_source_install_parents_are_trusted \
        "$barrier_dir" "${FACELOCK_SOURCE_INSTALL_DBUS_LAYOUT_PREFIX:-/}" || return 1
    if [ ! -d "$barrier_dir" ]; then
        if mkdir -m 0755 -- "$barrier_dir"; then
            FACELOCK_SOURCE_INSTALL_BARRIER_DIR_CREATED=true
            if ! exec {FACELOCK_SOURCE_INSTALL_BARRIER_DIR_FD}<"$barrier_dir"; then
                rmdir -- "$barrier_dir" || true
                FACELOCK_SOURCE_INSTALL_BARRIER_DIR_CREATED=false
                return 1
            fi
        elif [ -L "$barrier_dir" ] || [ ! -d "$barrier_dir" ]; then
            return 1
        fi
    fi
    facelock_source_install_directory_is_trusted "$barrier_dir" || return 1
    directory_mode="$(stat -Lc '%a' -- "$barrier_dir")" || return 1
    [ "$directory_mode" = 755 ] || return 1

    FACELOCK_SOURCE_INSTALL_BARRIER_PATH="$barrier_dir/facelock-daemon.service"
    FACELOCK_SOURCE_INSTALL_BARRIER_FD=
    case "$-" in
        *C*) had_noclobber=true ;;
    esac
    original_umask="$(umask)" || return 1
    umask 077
    set -o noclobber
    if { exec {FACELOCK_SOURCE_INSTALL_BARRIER_FD}> \
        "$FACELOCK_SOURCE_INSTALL_BARRIER_PATH"; } 2>/dev/null; then
        FACELOCK_SOURCE_INSTALL_BARRIER_CREATED=true
    else
        create_status=$?
    fi
    if [ "$had_noclobber" = false ]; then
        set +o noclobber
    fi
    umask "$original_umask"
    if [ "$create_status" -eq 0 ] &&
        ! facelock_source_install_owned_barrier_is_current; then
        create_status=1
    fi
    return "$create_status"
}

facelock_source_install_owned_barrier_dir_is_current() {
    [ -n "$FACELOCK_SOURCE_INSTALL_BARRIER_DIR_FD" ] &&
        [ -d "$FACELOCK_SOURCE_INSTALL_BARRIER_DIR_PATH" ] &&
        [ ! -L "$FACELOCK_SOURCE_INSTALL_BARRIER_DIR_PATH" ] &&
        [ "$FACELOCK_SOURCE_INSTALL_BARRIER_DIR_PATH" -ef \
            "/proc/$$/fd/$FACELOCK_SOURCE_INSTALL_BARRIER_DIR_FD" ]
}

facelock_source_install_owned_barrier_is_current() {
    local path_metadata fd_metadata uid gid mode links size kind

    [ -n "$FACELOCK_SOURCE_INSTALL_BARRIER_FD" ] &&
        [ -f "$FACELOCK_SOURCE_INSTALL_BARRIER_PATH" ] &&
        [ ! -L "$FACELOCK_SOURCE_INSTALL_BARRIER_PATH" ] &&
        [ ! -s "$FACELOCK_SOURCE_INSTALL_BARRIER_PATH" ] &&
        [ "$FACELOCK_SOURCE_INSTALL_BARRIER_PATH" -ef \
            "/proc/$$/fd/$FACELOCK_SOURCE_INSTALL_BARRIER_FD" ] || return 1
    path_metadata="$(facelock_source_install_stat -Lc '%d:%i:%u:%g:%a:%h:%s:%F' -- \
        "$FACELOCK_SOURCE_INSTALL_BARRIER_PATH")" || return 1
    fd_metadata="$(facelock_source_install_stat -Lc '%d:%i:%u:%g:%a:%h:%s:%F' -- \
        "/proc/$$/fd/$FACELOCK_SOURCE_INSTALL_BARRIER_FD")" || return 1
    [ "$path_metadata" = "$fd_metadata" ] || return 1
    IFS=: read -r _ _ uid gid mode links size kind <<<"$path_metadata"
    [ "$uid" = "$FACELOCK_SOURCE_INSTALL_TRUST_UID" ] &&
        [ "$gid" = "$FACELOCK_SOURCE_INSTALL_TRUST_GID" ] &&
        [ "$mode" = 600 ] && [ "$links" -eq 1 ] && [ "$size" -eq 0 ] &&
        [[ "$kind" = regular\ *file ]]
}

facelock_source_install_quarantined_barrier_is_current() {
    local path_metadata fd_metadata uid gid mode links size kind

    [ "$FACELOCK_SOURCE_INSTALL_BARRIER_QUARANTINED" = true ] &&
        [ -n "$FACELOCK_SOURCE_INSTALL_BARRIER_QUARANTINE_PATH" ] &&
        [ -n "$FACELOCK_SOURCE_INSTALL_BARRIER_FD" ] &&
        [ -f "$FACELOCK_SOURCE_INSTALL_BARRIER_QUARANTINE_PATH" ] &&
        [ ! -L "$FACELOCK_SOURCE_INSTALL_BARRIER_QUARANTINE_PATH" ] &&
        [ ! -s "$FACELOCK_SOURCE_INSTALL_BARRIER_QUARANTINE_PATH" ] &&
        [ "$FACELOCK_SOURCE_INSTALL_BARRIER_QUARANTINE_PATH" -ef \
            "/proc/$$/fd/$FACELOCK_SOURCE_INSTALL_BARRIER_FD" ] || return 1
    path_metadata="$(facelock_source_install_stat -Lc '%d:%i:%u:%g:%a:%h:%s:%F' -- \
        "$FACELOCK_SOURCE_INSTALL_BARRIER_QUARANTINE_PATH")" || return 1
    fd_metadata="$(facelock_source_install_stat -Lc '%d:%i:%u:%g:%a:%h:%s:%F' -- \
        "/proc/$$/fd/$FACELOCK_SOURCE_INSTALL_BARRIER_FD")" || return 1
    [ "$path_metadata" = "$fd_metadata" ] || return 1
    IFS=: read -r _ _ uid gid mode links size kind <<<"$path_metadata"
    [ "$uid" = "$FACELOCK_SOURCE_INSTALL_TRUST_UID" ] &&
        [ "$gid" = "$FACELOCK_SOURCE_INSTALL_TRUST_GID" ] &&
        [ "$mode" = 600 ] && [ "$links" -eq 1 ] && [ "$size" -eq 0 ] &&
        [[ "$kind" = regular\ *file ]]
}

facelock_source_install_quarantine_owned_barrier() {
    local quarantine_path

    if [ "$FACELOCK_SOURCE_INSTALL_BARRIER_QUARANTINED" = true ]; then
        facelock_source_install_quarantined_barrier_is_current &&
            [ ! -e "$FACELOCK_SOURCE_INSTALL_BARRIER_PATH" ] &&
            [ ! -L "$FACELOCK_SOURCE_INSTALL_BARRIER_PATH" ]
        return
    fi
    if ! facelock_source_install_owned_barrier_is_current; then
        return 1
    fi
    quarantine_path="${FACELOCK_SOURCE_INSTALL_BARRIER_PATH}.facelock-remove.$$.$RANDOM"
    if [ -e "$quarantine_path" ] || [ -L "$quarantine_path" ]; then
        return 1
    fi
    FACELOCK_SOURCE_INSTALL_BARRIER_QUARANTINE_PATH="$quarantine_path"
    FACELOCK_SOURCE_INSTALL_BARRIER_QUARANTINED=true
    if mv -T --no-clobber -- \
        "$FACELOCK_SOURCE_INSTALL_BARRIER_PATH" "$quarantine_path" &&
        facelock_source_install_quarantined_barrier_is_current &&
        [ ! -e "$FACELOCK_SOURCE_INSTALL_BARRIER_PATH" ] &&
        [ ! -L "$FACELOCK_SOURCE_INSTALL_BARRIER_PATH" ]; then
        return 0
    fi
    if facelock_source_install_quarantined_barrier_is_current &&
        [ ! -e "$FACELOCK_SOURCE_INSTALL_BARRIER_PATH" ] &&
        [ ! -L "$FACELOCK_SOURCE_INSTALL_BARRIER_PATH" ]; then
        return 1
    fi
    if { [ -e "$quarantine_path" ] || [ -L "$quarantine_path" ]; } &&
        [ ! -e "$FACELOCK_SOURCE_INSTALL_BARRIER_PATH" ] &&
        [ ! -L "$FACELOCK_SOURCE_INSTALL_BARRIER_PATH" ] &&
        mv -T --no-clobber -- "$quarantine_path" \
            "$FACELOCK_SOURCE_INSTALL_BARRIER_PATH"; then
        FACELOCK_SOURCE_INSTALL_BARRIER_QUARANTINE_PATH=
        FACELOCK_SOURCE_INSTALL_BARRIER_QUARANTINED=false
    elif [ ! -e "$quarantine_path" ] && [ ! -L "$quarantine_path" ]; then
        FACELOCK_SOURCE_INSTALL_BARRIER_QUARANTINE_PATH=
        FACELOCK_SOURCE_INSTALL_BARRIER_QUARANTINED=false
    fi
    return 1
}

facelock_source_install_restore_quarantined_barrier() {
    facelock_source_install_quarantined_barrier_is_current || return 1
    if [ -e "$FACELOCK_SOURCE_INSTALL_BARRIER_PATH" ] ||
        [ -L "$FACELOCK_SOURCE_INSTALL_BARRIER_PATH" ] ||
        ! mv -T --no-clobber -- \
            "$FACELOCK_SOURCE_INSTALL_BARRIER_QUARANTINE_PATH" \
            "$FACELOCK_SOURCE_INSTALL_BARRIER_PATH" ||
        ! facelock_source_install_owned_barrier_is_current; then
        return 1
    fi
    FACELOCK_SOURCE_INSTALL_BARRIER_QUARANTINE_PATH=
    FACELOCK_SOURCE_INSTALL_BARRIER_QUARANTINED=false
}

facelock_source_install_remove_quarantined_barrier() {
    facelock_source_install_quarantined_barrier_is_current || return 1
    if ! rm -f -- "$FACELOCK_SOURCE_INSTALL_BARRIER_QUARANTINE_PATH" ||
        [ -e "$FACELOCK_SOURCE_INSTALL_BARRIER_QUARANTINE_PATH" ] ||
        [ -L "$FACELOCK_SOURCE_INSTALL_BARRIER_QUARANTINE_PATH" ]; then
        return 1
    fi
    exec {FACELOCK_SOURCE_INSTALL_BARRIER_FD}>&-
    FACELOCK_SOURCE_INSTALL_BARRIER_FD=
    FACELOCK_SOURCE_INSTALL_BARRIER_QUARANTINE_PATH=
    FACELOCK_SOURCE_INSTALL_BARRIER_QUARANTINED=false
}

facelock_source_install_remove_owned_barrier_dir() {
    local barrier_dir="$FACELOCK_SOURCE_INSTALL_BARRIER_DIR_PATH"
    local quarantine_dir entry directory_mode

    if ! facelock_source_install_owned_barrier_dir_is_current ||
        ! facelock_source_install_directory_is_trusted "$barrier_dir" ||
        ! directory_mode="$(facelock_source_install_stat -Lc '%a' -- "$barrier_dir")" ||
        [ "$directory_mode" != 755 ] ||
        { IFS= read -r -d '' entry < <(
            find "$barrier_dir" -mindepth 1 -maxdepth 1 -print0 -quit
        ) && [ -n "$entry" ]; }; then
        return 1
    fi
    quarantine_dir="$barrier_dir.facelock-remove.$$.$RANDOM"
    if [ -e "$quarantine_dir" ] || [ -L "$quarantine_dir" ]; then
        return 1
    fi
    if ! mv -T --no-clobber -- "$barrier_dir" "$quarantine_dir" ||
        [ ! "$quarantine_dir" -ef \
            "/proc/$$/fd/$FACELOCK_SOURCE_INSTALL_BARRIER_DIR_FD" ] ||
        ! facelock_source_install_directory_is_trusted "$quarantine_dir" ||
        ! directory_mode="$(facelock_source_install_stat -Lc '%a' -- "$quarantine_dir")" ||
        [ "$directory_mode" != 755 ] ||
        { IFS= read -r -d '' entry < <(
            find "$quarantine_dir" -mindepth 1 -maxdepth 1 -print0 -quit
        ) && [ -n "$entry" ]; }; then
        if { [ -e "$quarantine_dir" ] || [ -L "$quarantine_dir" ]; } &&
            [ ! -e "$barrier_dir" ] && [ ! -L "$barrier_dir" ] &&
            mv -T --no-clobber -- "$quarantine_dir" "$barrier_dir"; then
            :
        fi
        return 1
    fi
    if ! rmdir -- "$quarantine_dir"; then
        if [ ! -e "$barrier_dir" ] && [ ! -L "$barrier_dir" ]; then
            mv -T --no-clobber -- "$quarantine_dir" "$barrier_dir" || true
        fi
        return 1
    fi
    exec {FACELOCK_SOURCE_INSTALL_BARRIER_DIR_FD}>&-
    FACELOCK_SOURCE_INSTALL_BARRIER_DIR_FD=
}

facelock_source_install_ensure_lock_directory() {
    local lock_dir="$1"
    local boundary="${2:-/}"
    local original_umask mode

    facelock_source_install_existing_parents_are_trusted \
        "$lock_dir/lifecycle.lock" "$boundary" || return 1
    if [ ! -e "$lock_dir" ] && [ ! -L "$lock_dir" ]; then
        original_umask="$(umask)"
        umask 022
        if ! mkdir -m 755 -- "$lock_dir"; then
            umask "$original_umask"
            [ -d "$lock_dir" ] && [ ! -L "$lock_dir" ] || return 1
        else
            umask "$original_umask"
        fi
    fi
    facelock_source_install_directory_is_trusted "$lock_dir" &&
        mode="$(facelock_source_install_stat -Lc '%a' -- "$lock_dir")" &&
        [ "$mode" = 755 ] &&
        facelock_source_install_parents_are_trusted \
            "$lock_dir/lifecycle.lock" "$boundary"
}

facelock_source_install_acquire_lock() {
    local lock_path="$1"
    local boundary="${2:-/}"
    local original_umask
    local probe_path="$lock_path.facelock-lock.$$.$RANDOM"
    local uid gid mode links size kind

    facelock_source_install_parents_are_trusted "$lock_path" "$boundary" ||
        return 1
    if [ -e "$probe_path" ] || [ -L "$probe_path" ]; then
        return 1
    fi
    original_umask="$(umask)"
    umask 077
    if [ -e "$lock_path" ] || [ -L "$lock_path" ]; then
        if ! ln -P -- "$lock_path" "$probe_path"; then
            umask "$original_umask"
            return 1
        fi
    else
        local had_noclobber=false
        case "$-" in
            *C*) had_noclobber=true ;;
        esac
        set -o noclobber
        if ! { : >"$probe_path"; } 2>/dev/null; then
            [ "$had_noclobber" = true ] || set +o noclobber
            umask "$original_umask"
            return 1
        fi
        [ "$had_noclobber" = true ] || set +o noclobber
        chmod 600 -- "$probe_path" || {
            rm -f -- "$probe_path"
            umask "$original_umask"
            return 1
        }
        if ! ln -- "$probe_path" "$lock_path"; then
            rm -f -- "$probe_path"
            umask "$original_umask"
            return 1
        fi
    fi
    if [ -L "$probe_path" ] || [ ! -f "$probe_path" ] ||
        ! IFS=: read -r uid gid mode links size kind < <(
            facelock_source_install_stat -Lc '%u:%g:%a:%h:%s:%F' -- "$probe_path"
        ) ||
        [ "$uid" != "$FACELOCK_SOURCE_INSTALL_TRUST_UID" ] ||
        [ "$gid" != "$FACELOCK_SOURCE_INSTALL_TRUST_GID" ] ||
        [ "$mode" != 600 ] || [ "$links" -ne 2 ] || [ "$size" -ne 0 ]; then
        rm -f -- "$probe_path"
        umask "$original_umask"
        return 1
    fi
    case "$kind" in
        regular\ *file) ;;
        *)
            rm -f -- "$probe_path"
            umask "$original_umask"
            return 1
            ;;
    esac
    if ! exec {FACELOCK_SOURCE_INSTALL_LOCK_FD}<>"$probe_path"; then
        rm -f -- "$probe_path"
        umask "$original_umask"
        return 1
    fi
    umask "$original_umask"
    if [ ! "$probe_path" -ef "/proc/$$/fd/$FACELOCK_SOURCE_INSTALL_LOCK_FD" ] ||
        [ ! "$lock_path" -ef "/proc/$$/fd/$FACELOCK_SOURCE_INSTALL_LOCK_FD" ] ||
        ! flock -n "$FACELOCK_SOURCE_INSTALL_LOCK_FD"; then
        rm -f -- "$probe_path"
        exec {FACELOCK_SOURCE_INSTALL_LOCK_FD}>&-
        FACELOCK_SOURCE_INSTALL_LOCK_FD=
        return 1
    fi
    if ! rm -f -- "$probe_path" ||
        [ -L "$lock_path" ] || [ ! -f "$lock_path" ] ||
        [ ! "$lock_path" -ef "/proc/$$/fd/$FACELOCK_SOURCE_INSTALL_LOCK_FD" ] ||
        ! IFS=: read -r uid gid mode links size kind < <(
            facelock_source_install_stat -Lc '%u:%g:%a:%h:%s:%F' -- \
                "/proc/$$/fd/$FACELOCK_SOURCE_INSTALL_LOCK_FD"
        ) ||
        [ "$uid" != "$FACELOCK_SOURCE_INSTALL_TRUST_UID" ] ||
        [ "$gid" != "$FACELOCK_SOURCE_INSTALL_TRUST_GID" ] ||
        [ "$mode" != 600 ] || [ "$links" -ne 1 ] || [ "$size" -ne 0 ] ||
        [[ "$kind" != regular\ *file ]]; then
        exec {FACELOCK_SOURCE_INSTALL_LOCK_FD}>&-
        FACELOCK_SOURCE_INSTALL_LOCK_FD=
        return 1
    fi
    FACELOCK_SOURCE_INSTALL_LOCK_HELD=true
    return 0
}

facelock_source_install_release_lock() {
    if [ "$FACELOCK_SOURCE_INSTALL_LOCK_HELD" = true ]; then
        exec {FACELOCK_SOURCE_INSTALL_LOCK_FD}>&-
        FACELOCK_SOURCE_INSTALL_LOCK_FD=
        FACELOCK_SOURCE_INSTALL_LOCK_HELD=false
    fi
}

facelock_source_install_path_is_beneath() {
    local path="$1"
    local boundary="$2"

    case "$path:$boundary" in
        *'/../'* | *'/./'* | *'//'* | */..:* | */.:*) return 1 ;;
    esac
    if [ "$boundary" = / ]; then
        case "$path" in
            /*) return 0 ;;
        esac
    else
        case "$path" in
            "$boundary" | "$boundary"/*) return 0 ;;
        esac
    fi
    return 1
}

facelock_source_install_directory_is_trusted() {
    local path="$1"
    local directory_fd
    local mode uid gid kind
    local status=0

    [ -d "$path" ] && [ ! -L "$path" ] || return 1
    exec {directory_fd}<"$path" || return 1
    if [ ! "$path" -ef "/proc/$$/fd/$directory_fd" ] ||
        ! IFS=: read -r uid gid mode kind < <(
            facelock_source_install_stat -Lc '%u:%g:%a:%F' -- "/proc/$$/fd/$directory_fd"
        ) ||
        [ "$uid" != "$FACELOCK_SOURCE_INSTALL_TRUST_UID" ] ||
        [ "$gid" != "$FACELOCK_SOURCE_INSTALL_TRUST_GID" ] ||
        [ "$kind" != directory ] ||
        [ "$((8#$mode & 8#022))" -ne 0 ]; then
        status=1
    fi
    exec {directory_fd}>&-
    return "$status"
}

facelock_source_install_standard_directory_alias_is_trusted() {
    local path="$1"
    local boundary="$2"
    local lib_path usr_path usr_lib_path target uid gid links kind

    if [ "$boundary" = / ]; then
        lib_path=/lib
        usr_path=/usr
        usr_lib_path=/usr/lib
    else
        lib_path="$boundary/lib"
        usr_path="$boundary/usr"
        usr_lib_path="$boundary/usr/lib"
    fi
    [ "$path" = "$lib_path" ] && [ -L "$path" ] || return 1
    IFS= read -r -d '' target < <(readlink -z -- "$path") || return 1
    [ "$target" = usr/lib ] || return 1
    IFS=: read -r uid gid links kind < <(
        facelock_source_install_stat -c '%u:%g:%h:%F' -- "$path"
    ) || return 1
    [ "$uid" = "$FACELOCK_SOURCE_INSTALL_TRUST_UID" ] &&
        [ "$gid" = "$FACELOCK_SOURCE_INSTALL_TRUST_GID" ] &&
        [ "$links" -eq 1 ] &&
        [ "$kind" = symbolic\ link ] &&
        facelock_source_install_directory_is_trusted "$usr_path" &&
        facelock_source_install_directory_is_trusted "$usr_lib_path"
}

facelock_source_install_existing_parents_are_trusted() {
    local path="$1"
    local boundary="$2"
    local relative component current

    facelock_source_install_path_is_beneath "$path" "$boundary" || return 1
    facelock_source_install_directory_is_trusted "$boundary" || return 1
    relative="${path#"$boundary"}"
    relative="${relative#/}"
    current="${boundary%/}"
    [ -n "$current" ] || current=/
    while [ -n "$relative" ]; do
        component="${relative%%/*}"
        if [ "$component" = "$relative" ]; then
            break
        fi
        relative="${relative#*/}"
        if [ "$current" = / ]; then
            current="/$component"
        else
            current="$current/$component"
        fi
        if [ -L "$current" ]; then
            facelock_source_install_standard_directory_alias_is_trusted \
                "$current" "$boundary" || return 1
            continue
        fi
        [ -e "$current" ] || return 0
        facelock_source_install_directory_is_trusted "$current" || return 1
    done
}

facelock_source_install_parents_are_trusted() {
    local path="$1"
    local boundary="$2"
    local relative component current

    facelock_source_install_path_is_beneath "$path" "$boundary" || return 1
    facelock_source_install_directory_is_trusted "$boundary" || return 1
    relative="${path#"$boundary"}"
    relative="${relative#/}"
    current="${boundary%/}"
    [ -n "$current" ] || current=/
    while [ -n "$relative" ]; do
        component="${relative%%/*}"
        if [ "$component" = "$relative" ]; then
            break
        fi
        relative="${relative#*/}"
        if [ "$current" = / ]; then
            current="/$component"
        else
            current="$current/$component"
        fi
        if [ -L "$current" ]; then
            facelock_source_install_standard_directory_alias_is_trusted \
                "$current" "$boundary" || return 1
        else
            facelock_source_install_directory_is_trusted "$current" || return 1
        fi
    done
}

facelock_source_install_regular_file_is_trusted() {
    local path="$1"
    local boundary="$2"
    local max_size="$3"
    local require_executable="${4:-false}"
    local file_fd
    local uid gid mode links size kind
    local status=0

    facelock_source_install_parents_are_trusted "$path" "$boundary" || return 1
    [ -f "$path" ] && [ ! -L "$path" ] || return 1
    exec {file_fd}<"$path" || return 1
    if [ ! "$path" -ef "/proc/$$/fd/$file_fd" ] ||
        ! IFS=: read -r uid gid mode links size kind < <(
            facelock_source_install_stat -Lc '%u:%g:%a:%h:%s:%F' -- "/proc/$$/fd/$file_fd"
        ); then
        status=1
    else
        case "$kind" in
            regular\ *file) ;;
            *) status=1 ;;
        esac
        if [ "$uid" != "$FACELOCK_SOURCE_INSTALL_TRUST_UID" ] ||
            [ "$gid" != "$FACELOCK_SOURCE_INSTALL_TRUST_GID" ] ||
            [ "$links" -ne 1 ] ||
            [ "$size" -gt "$max_size" ] ||
            [ "$((8#$mode & 8#022))" -ne 0 ] || {
                [ "$require_executable" = true ] &&
                    [ "$((8#$mode & 8#111))" -eq 0 ];
            }; then
            status=1
        fi
    fi
    exec {file_fd}>&-
    return "$status"
}

facelock_source_install_repository_file_is_trusted() {
    local path="$1"
    local max_size="$2"
    local saved_uid="$FACELOCK_SOURCE_INSTALL_TRUST_UID"
    local saved_gid="$FACELOCK_SOURCE_INSTALL_TRUST_GID"
    local status=0

    if ! IFS=: read -r FACELOCK_SOURCE_INSTALL_TRUST_UID \
        FACELOCK_SOURCE_INSTALL_TRUST_GID < <(
        stat -Lc '%u:%g' -- "$FACELOCK_SOURCE_INSTALL_REPOSITORY_ROOT"
    ) || ! facelock_source_install_regular_file_is_trusted \
        "$path" "$FACELOCK_SOURCE_INSTALL_REPOSITORY_ROOT" "$max_size"; then
        status=1
    fi
    FACELOCK_SOURCE_INSTALL_TRUST_UID="$saved_uid"
    FACELOCK_SOURCE_INSTALL_TRUST_GID="$saved_gid"
    return "$status"
}

facelock_source_install_exec_status_value_is_bounded() {
    local value="$1"

    [ -n "$value" ] && [ "${#value}" -le 256 ] || return 1
    case "$value" in
        *$'\n'* | *$'\r'* | *';'* | *'{'* | *'}'*) return 1 ;;
    esac
}

facelock_source_install_parse_structured_exec_start() {
    local exec_start="$1"
    local body field value index
    local -a fields

    FACELOCK_SOURCE_INSTALL_EXEC_PATH=
    FACELOCK_SOURCE_INSTALL_EXEC_ARGV=
    case "$exec_start" in
        *$'\n'* | *$'\r'*) return 1 ;;
    esac
    case "$exec_start" in
        '{ '*' }') ;;
        *) return 1 ;;
    esac
    body="${exec_start#\{ }"
    body="${body% \}}"
    field="${body%"${body##*[![:space:]]}"}"
    case "$field" in
        *';') return 1 ;;
    esac
    IFS=';' read -r -a fields <<<"$body"
    [ "${#fields[@]}" -eq 8 ] || return 1
    for index in "${!fields[@]}"; do
        field="${fields[$index]}"
        field="${field#"${field%%[![:space:]]*}"}"
        field="${field%"${field##*[![:space:]]}"}"
        fields[index]="$field"
    done
    case "${fields[0]}" in
        path=?*) FACELOCK_SOURCE_INSTALL_EXEC_PATH="${fields[0]#path=}" ;;
        *) return 1 ;;
    esac
    case "${fields[1]}" in
        'argv[]='?*) FACELOCK_SOURCE_INSTALL_EXEC_ARGV="${fields[1]#argv[]=}" ;;
        *) return 1 ;;
    esac
    [ "${fields[2]}" = ignore_errors=no ] || return 1
    for index in 3 4 6 7; do
        case "$index:${fields[$index]}" in
            3:start_time=*) value="${fields[$index]#start_time=}" ;;
            4:stop_time=*) value="${fields[$index]#stop_time=}" ;;
            6:code=*) value="${fields[$index]#code=}" ;;
            7:status=*) value="${fields[$index]#status=}" ;;
            *) return 1 ;;
        esac
        facelock_source_install_exec_status_value_is_bounded "$value" ||
            return 1
    done
    [[ "${fields[5]}" =~ ^pid=[0-9]{1,20}$ ]] || return 1
}

facelock_source_install_effective_unit_is_trusted() {
    local fragment_path="$1"
    local exec_start="$2"
    local drop_in_paths="$3"
    local boundary="$4"
    shift 4
    local asset executable selected=false
    # Leave headroom for optimized release builds while bounding file validation.
    local daemon_max_size=268435456

    [ -n "$fragment_path" ] && [ -z "$drop_in_paths" ] || return 1
    case "$exec_start" in
        '/usr/bin/facelock daemon') ;;
        *)
            facelock_source_install_parse_structured_exec_start \
                "$exec_start" || return 1
            [ "$FACELOCK_SOURCE_INSTALL_EXEC_PATH" = /usr/bin/facelock ] &&
                [ "$FACELOCK_SOURCE_INSTALL_EXEC_ARGV" = \
                    '/usr/bin/facelock daemon' ] || return 1
            ;;
    esac
    executable="${boundary%/}/usr/bin/facelock"
    facelock_source_install_regular_file_is_trusted \
        "$executable" "$boundary" "$daemon_max_size" true || return 1
    for asset in "$@"; do
        case "$asset" in
            */org.facelock.Daemon.service) continue ;;
        esac
        if [ "$fragment_path" = "$asset" ]; then
            selected=true
            break
        fi
    done
    [ "$selected" = true ] &&
        facelock_source_install_regular_file_is_trusted \
            "$fragment_path" "$boundary" 1048576
}

facelock_source_install_dbus_runtime_assets_are_trusted() {
    local id="$1"
    local names="$2"
    local exec_start="$3"
    local fragment_path="$4"
    local executable executable_path argv name
    local boundary="${FACELOCK_SOURCE_INSTALL_DBUS_LAYOUT_PREFIX:-/}"
    local prefix="$FACELOCK_SOURCE_INSTALL_DBUS_LAYOUT_PREFIX"
    local broker_name=false dbus_name=false
    local -a name_values

    case "$exec_start" in
        '{ '*' }')
            facelock_source_install_parse_structured_exec_start \
                "$exec_start" || return 1
            executable="$FACELOCK_SOURCE_INSTALL_EXEC_PATH"
            argv="$FACELOCK_SOURCE_INSTALL_EXEC_ARGV"
            ;;
        *)
            executable="${exec_start%% *}"
            argv="$exec_start"
            ;;
    esac
    read -r -a name_values <<<"$names"
    for name in "${name_values[@]}"; do
        case "$name" in
            dbus-broker.service)
                [ "$broker_name" = false ] || return 1
                broker_name=true
                ;;
            dbus.service)
                [ "$dbus_name" = false ] || return 1
                dbus_name=true
                ;;
            *) return 1 ;;
        esac
    done
    case "$executable" in
        /usr/bin/dbus-broker-launch)
            [ "$id" = dbus-broker.service ] &&
                [ "$broker_name" = true ] && [ "$dbus_name" = true ] &&
                [ "${#name_values[@]}" -eq 2 ] || return 1
            case "$argv" in
                '/usr/bin/dbus-broker-launch --scope system' | \
                    '/usr/bin/dbus-broker-launch --scope=system' | \
                    '/usr/bin/dbus-broker-launch --scope system --audit' | \
                    '/usr/bin/dbus-broker-launch --scope=system --audit') ;;
                *) return 1 ;;
            esac
            case "$fragment_path" in
                "$prefix/usr/lib/systemd/system/dbus-broker.service") ;;
                "$prefix/lib/systemd/system/dbus-broker.service")
                    facelock_source_install_standard_directory_alias_is_trusted \
                        "$prefix/lib" "$boundary" || return 1
                    ;;
                *) return 1 ;;
            esac
            ;;
        /usr/bin/dbus-daemon)
            [ "$id" = dbus.service ] && [ "$broker_name" = false ] &&
                [ "$dbus_name" = true ] &&
                [ "${#name_values[@]}" -eq 1 ] || return 1
            case "$exec_start" in
                '{ '*' }')
                    case "$argv" in
                        '/usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only' | \
                            'dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only' | \
                            '@dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only') ;;
                        *) return 1 ;;
                    esac
                    ;;
                *)
                    [ "$argv" = \
                        '/usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only' ] ||
                        return 1
                    ;;
            esac
            case "$fragment_path" in
                "$prefix/usr/lib/systemd/system/dbus.service") ;;
                "$prefix/lib/systemd/system/dbus.service")
                    facelock_source_install_standard_directory_alias_is_trusted \
                        "$prefix/lib" "$boundary" || return 1
                    ;;
                *) return 1 ;;
            esac
            ;;
        *) return 1 ;;
    esac
    executable_path="${prefix}${executable}"
    facelock_source_install_regular_file_is_trusted \
        "$executable_path" "$boundary" 16777216 &&
        facelock_source_install_regular_file_is_trusted \
            "$fragment_path" "$boundary" 1048576
}

facelock_source_install_dbus_uses_systemd_activation() {
    local snapshot line id="" names="" following="" load_state=""
    local active_state="" fragment_path="" drop_in_paths="" exec_start=""
    local id_count=0 names_count=0 following_count=0 load_state_count=0
    local active_state_count=0 fragment_path_count=0 drop_in_paths_count=0
    local exec_start_count=0

    if ! snapshot="$(systemctl show dbus.service \
        --property=Id \
        --property=Names \
        --property=Following \
        --property=LoadState \
        --property=ActiveState \
        --property=FragmentPath \
        --property=DropInPaths \
        --property=ExecStart \
        --no-pager)"; then
        return 1
    fi
    while IFS= read -r line; do
        case "$line" in
            Id=*)
                id_count=$((id_count + 1))
                id="${line#Id=}"
                ;;
            Names=*)
                names_count=$((names_count + 1))
                names="${line#Names=}"
                ;;
            Following=*)
                following_count=$((following_count + 1))
                following="${line#Following=}"
                ;;
            LoadState=*)
                load_state_count=$((load_state_count + 1))
                load_state="${line#LoadState=}"
                ;;
            ActiveState=*)
                active_state_count=$((active_state_count + 1))
                active_state="${line#ActiveState=}"
                ;;
            ExecStart=*)
                exec_start_count=$((exec_start_count + 1))
                exec_start="${line#ExecStart=}"
                ;;
            FragmentPath=*)
                fragment_path_count=$((fragment_path_count + 1))
                fragment_path="${line#FragmentPath=}"
                ;;
            DropInPaths=*)
                drop_in_paths_count=$((drop_in_paths_count + 1))
                drop_in_paths="${line#DropInPaths=}"
                ;;
            *) return 1 ;;
        esac
    done <<<"$snapshot"
    [ "$id_count" -eq 1 ] && [ "$names_count" -eq 1 ] &&
        [ "$following_count" -eq 1 ] && [ "$load_state_count" -eq 1 ] &&
        [ "$active_state_count" -eq 1 ] &&
        [ "$fragment_path_count" -eq 1 ] &&
        [ "$drop_in_paths_count" -eq 1 ] &&
        [ "$exec_start_count" -eq 1 ] ||
        return 1
    [ "$load_state" = loaded ] && [ "$active_state" = active ] &&
        [ -z "$following" ] && [ -z "$drop_in_paths" ] || return 1
    facelock_source_install_dbus_runtime_assets_are_trusted \
        "$id" "$names" "$exec_start" "$fragment_path"
}

facelock_source_install_dbus_config_fragment_is_policy_only() {
    local path="$1"
    local boundary="$2"
    local line

    facelock_source_install_existing_parents_are_trusted \
        "$path" "$boundary" || return 1
    if [ -L "$path" ] || { [ -e "$path" ] && [ ! -f "$path" ]; }; then
        return 1
    fi
    [ -e "$path" ] || return 0
    facelock_source_install_regular_file_is_trusted \
        "$path" "$boundary" 1048576 || return 1
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            *'<servicedir'* | *'<standard_system_servicedirs'* | \
                *'<include'*) return 1 ;;
        esac
    done <"$path"
}

facelock_source_install_dbus_config_dir_is_policy_only() {
    local directory="$1"
    local boundary="$2"
    local fragment

    facelock_source_install_existing_parents_are_trusted \
        "$directory" "$boundary" || return 1
    if [ -L "$directory" ] || {
        [ -e "$directory" ] && [ ! -d "$directory" ];
    }; then
        return 1
    fi
    [ -d "$directory" ] || return 0
    facelock_source_install_directory_is_trusted "$directory" || return 1
    for fragment in "$directory"/*.conf; do
        if [ ! -e "$fragment" ] && [ ! -L "$fragment" ]; then
            continue
        fi
        facelock_source_install_dbus_config_fragment_is_policy_only \
            "$fragment" "$boundary" || return 1
    done
}

facelock_source_install_dbus_config_is_standard() {
    local layout_prefix="$1"
    local main_config="$layout_prefix/usr/share/dbus-1/system.conf"
    local boundary="${layout_prefix:-/}"
    local line trimmed standard_dirs=0
    local fragment directory
    local -a fragments=(
        "$layout_prefix/etc/dbus-1/system.conf"
        "$layout_prefix/etc/dbus-1/system-local.conf"
        "$layout_prefix/usr/share/dbus-1/contexts/dbus_contexts"
    )
    local -a directories=(
        "$layout_prefix/usr/share/dbus-1/system.d"
        "$layout_prefix/etc/dbus-1/system.d"
    )

    facelock_source_install_regular_file_is_trusted \
        "$main_config" "$boundary" 1048576 || return 1
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%$'\r'}"
        trimmed="${line#"${line%%[![:space:]]*}"}"
        trimmed="${trimmed%"${trimmed##*[![:space:]]}"}"
        case "$trimmed" in
            '<standard_system_servicedirs/>' | \
                '<standard_system_servicedirs />')
                standard_dirs=$((standard_dirs + 1))
                ;;
            '<include ignore_missing="yes">/etc/dbus-1/system.conf</include>' | \
                '<includedir>system.d</includedir>' | \
                '<includedir>/etc/dbus-1/system.d</includedir>' | \
                '<include ignore_missing="yes">/etc/dbus-1/system-local.conf</include>' | \
                '<include if_selinux_enabled="yes" selinux_root_relative="yes">contexts/dbus_contexts</include>')
                ;;
            *'<servicedir'* | *'<standard_system_servicedirs'* | \
                *'<include'*) return 1 ;;
        esac
    done <"$main_config"
    [ "$standard_dirs" -eq 1 ] || return 1

    for fragment in "${fragments[@]}"; do
        facelock_source_install_dbus_config_fragment_is_policy_only \
            "$fragment" "$boundary" || return 1
    done
    for directory in "${directories[@]}"; do
        facelock_source_install_dbus_config_dir_is_policy_only \
            "$directory" "$boundary" || return 1
    done
}

facelock_source_install_dbus_line_is_ascii() {
    local remaining="$1"
    local byte
    local LC_ALL=C

    while [ -n "$remaining" ]; do
        byte="${remaining:0:1}"
        case "$byte" in
            $'\t' | [[:print:]]) ;;
            *) return 1 ;;
        esac
        remaining="${remaining:1}"
    done
}

facelock_source_install_parse_dbus_definition() {
    local path="$1"
    local trusted_path="$path"
    local boundary="${FACELOCK_SOURCE_INSTALL_DBUS_LAYOUT_PREFIX:-/}"
    local definition_fd definition_size line key value
    local bytes_read=0 final_line=false in_service=false
    local repository_path=false status=0
    local LC_ALL=C

    FACELOCK_SOURCE_INSTALL_DBUS_SERVICE_SECTIONS=0
    FACELOCK_SOURCE_INSTALL_DBUS_DEFINITION_VALID=true
    FACELOCK_SOURCE_INSTALL_DBUS_NAMES=0
    FACELOCK_SOURCE_INSTALL_DBUS_NAME=
    FACELOCK_SOURCE_INSTALL_DBUS_TARGET_NAME_SEEN=false
    FACELOCK_SOURCE_INSTALL_DBUS_EXECS=0
    FACELOCK_SOURCE_INSTALL_DBUS_EXEC=
    FACELOCK_SOURCE_INSTALL_DBUS_USERS=0
    FACELOCK_SOURCE_INSTALL_DBUS_USER=
    FACELOCK_SOURCE_INSTALL_DBUS_SYSTEMD_SERVICES=0
    FACELOCK_SOURCE_INSTALL_DBUS_SYSTEMD_SERVICE=
    case "$path" in
        /*)
            facelock_source_install_regular_file_is_trusted \
                "$path" "$boundary" 65536 || return 1
            ;;
        *)
            repository_path=true
            trusted_path="$FACELOCK_SOURCE_INSTALL_REPOSITORY_ROOT/$path"
            facelock_source_install_repository_file_is_trusted \
                "$trusted_path" 65536 || return 1
            ;;
    esac
    exec {definition_fd}<"$trusted_path" || return 1
    if [ ! "$trusted_path" -ef "/proc/$$/fd/$definition_fd" ]; then
        exec {definition_fd}>&-
        return 1
    fi
    if ! definition_size="$(
        stat -Lc '%s' -- "/proc/$$/fd/$definition_fd"
    )"; then
        exec {definition_fd}>&-
        return 1
    fi
    while true; do
        line=
        final_line=false
        if IFS= read -r -u "$definition_fd" line; then
            bytes_read=$((bytes_read + ${#line} + 1))
        else
            bytes_read=$((bytes_read + ${#line}))
            [ -n "$line" ] || break
            final_line=true
        fi
        if [ "$final_line" = false ]; then
            line="${line%$'\r'}"
        fi
        if ! facelock_source_install_dbus_line_is_ascii "$line"; then
            FACELOCK_SOURCE_INSTALL_DBUS_DEFINITION_VALID=false
            [ "$final_line" = false ] || break
            continue
        fi
        if [[ "$line" =~ ^[[:blank:]]*$ ]]; then
            [ "$final_line" = false ] || break
            continue
        fi
        case "$line" in
            \#*) ;;
            '[D-BUS Service]')
                FACELOCK_SOURCE_INSTALL_DBUS_SERVICE_SECTIONS=$((
                    FACELOCK_SOURCE_INSTALL_DBUS_SERVICE_SECTIONS + 1
                ))
                in_service=true
                ;;
            \[*\])
                FACELOCK_SOURCE_INSTALL_DBUS_DEFINITION_VALID=false
                in_service=false
                ;;
            *=*)
                if [ "$in_service" = true ]; then
                    key="${line%%=*}"
                    value="${line#*=}"
                    key="${key%"${key##*[! ]}"}"
                    value="${value#"${value%%[! ]*}"}"
                    case "$key" in
                        Name)
                            FACELOCK_SOURCE_INSTALL_DBUS_NAMES=$((
                                FACELOCK_SOURCE_INSTALL_DBUS_NAMES + 1
                            ))
                            FACELOCK_SOURCE_INSTALL_DBUS_NAME="$value"
                            [ "$value" = org.facelock.Daemon ] &&
                                FACELOCK_SOURCE_INSTALL_DBUS_TARGET_NAME_SEEN=true
                            ;;
                        Exec)
                            FACELOCK_SOURCE_INSTALL_DBUS_EXECS=$((
                                FACELOCK_SOURCE_INSTALL_DBUS_EXECS + 1
                            ))
                            FACELOCK_SOURCE_INSTALL_DBUS_EXEC="$value"
                            ;;
                        User)
                            FACELOCK_SOURCE_INSTALL_DBUS_USERS=$((
                                FACELOCK_SOURCE_INSTALL_DBUS_USERS + 1
                            ))
                            FACELOCK_SOURCE_INSTALL_DBUS_USER="$value"
                            ;;
                        SystemdService)
                            FACELOCK_SOURCE_INSTALL_DBUS_SYSTEMD_SERVICES=$((
                                FACELOCK_SOURCE_INSTALL_DBUS_SYSTEMD_SERVICES + 1
                            ))
                            FACELOCK_SOURCE_INSTALL_DBUS_SYSTEMD_SERVICE="$value"
                            ;;
                        *)
                            FACELOCK_SOURCE_INSTALL_DBUS_DEFINITION_VALID=false
                            ;;
                    esac
                else
                    FACELOCK_SOURCE_INSTALL_DBUS_DEFINITION_VALID=false
                fi
                ;;
            *)
                FACELOCK_SOURCE_INSTALL_DBUS_DEFINITION_VALID=false
                ;;
        esac
        [ "$final_line" = false ] || break
    done
    [ "$bytes_read" -eq "$definition_size" ] || status=1
    if [ "$repository_path" = true ]; then
        facelock_source_install_repository_file_is_trusted \
            "$trusted_path" 65536 || status=1
    else
        facelock_source_install_regular_file_is_trusted \
            "$trusted_path" "$boundary" 65536 || status=1
    fi
    [ "$trusted_path" -ef "/proc/$$/fd/$definition_fd" ] || status=1
    exec {definition_fd}>&-
    return "$status"
}

facelock_source_install_dbus_definition_delegates() {
    local path="$1"

    facelock_source_install_parse_dbus_definition "$path" &&
        [ "$FACELOCK_SOURCE_INSTALL_DBUS_DEFINITION_VALID" = true ] &&
        [ "$FACELOCK_SOURCE_INSTALL_DBUS_SERVICE_SECTIONS" -eq 1 ] &&
        [ "$FACELOCK_SOURCE_INSTALL_DBUS_NAMES" -eq 1 ] &&
        [ "$FACELOCK_SOURCE_INSTALL_DBUS_NAME" = org.facelock.Daemon ] &&
        [ "$FACELOCK_SOURCE_INSTALL_DBUS_EXECS" -eq 1 ] &&
        [ "$FACELOCK_SOURCE_INSTALL_DBUS_EXEC" = \
            '/usr/bin/facelock daemon' ] &&
        [ "$FACELOCK_SOURCE_INSTALL_DBUS_USERS" -eq 1 ] &&
        [ "$FACELOCK_SOURCE_INSTALL_DBUS_USER" = root ] &&
        [ "$FACELOCK_SOURCE_INSTALL_DBUS_SYSTEMD_SERVICES" -eq 1 ] &&
        [ "$FACELOCK_SOURCE_INSTALL_DBUS_SYSTEMD_SERVICE" = \
            facelock-daemon.service ]
}

facelock_source_install_dbus_definition_is_safe() {
    local asset directory previous_directory="" definition matched=0

    for asset in "${FACELOCK_SOURCE_INSTALL_DBUS_ASSETS[@]}"; do
        directory="${asset%/*}"
        [ "$directory" = "$previous_directory" ] && continue
        previous_directory="$directory"
        facelock_source_install_existing_parents_are_trusted \
            "$directory" \
            "${FACELOCK_SOURCE_INSTALL_DBUS_LAYOUT_PREFIX:-/}" || return 1
        if [ -e "$directory" ] || [ -L "$directory" ]; then
            facelock_source_install_directory_is_trusted "$directory" || return 1
        fi
        matched=0
        for definition in "$directory"/*.service; do
            if [ ! -e "$definition" ] && [ ! -L "$definition" ]; then
                continue
            fi
            if ! facelock_source_install_parse_dbus_definition "$definition"; then
                return 1
            fi
            if [ "$FACELOCK_SOURCE_INSTALL_DBUS_TARGET_NAME_SEEN" = true ]; then
                facelock_source_install_dbus_definition_delegates "$definition" ||
                    return 1
                matched=$((matched + 1))
            fi
        done
        if [ "$matched" -gt 0 ]; then
            [ "$matched" -eq 1 ]
            return
        fi
    done
    return 1
}

facelock_source_install_dbus_definition_is_absent() {
    local asset directory previous_directory="" definition

    for asset in "${FACELOCK_SOURCE_INSTALL_DBUS_ASSETS[@]}"; do
        directory="${asset%/*}"
        [ "$directory" = "$previous_directory" ] && continue
        previous_directory="$directory"
        facelock_source_install_existing_parents_are_trusted \
            "$directory" \
            "${FACELOCK_SOURCE_INSTALL_DBUS_LAYOUT_PREFIX:-/}" || return 1
        if [ -e "$directory" ] || [ -L "$directory" ]; then
            facelock_source_install_directory_is_trusted "$directory" || return 1
        fi
        for definition in "$directory"/*.service; do
            if [ ! -e "$definition" ] && [ ! -L "$definition" ]; then
                continue
            fi
            facelock_source_install_parse_dbus_definition "$definition" ||
                return 1
            [ "$FACELOCK_SOURCE_INSTALL_DBUS_TARGET_NAME_SEEN" = false ] ||
                return 1
        done
    done
    return 0
}

facelock_source_install_reload_dbus_activation() {
    busctl --system call \
        org.freedesktop.DBus \
        /org/freedesktop/DBus \
        org.freedesktop.DBus \
        ReloadConfig >/dev/null
}

facelock_source_install_dbus_owner_matches_snapshot() {
    local expected_owner=false

    [ "$FACELOCK_SOURCE_INSTALL_DAEMON_WAS_ACTIVE" = true ] &&
        expected_owner=true
    facelock_source_install_dbus_owner_is "$expected_owner"
}

facelock_source_install_dbus_owner_is() {
    local expected_owner="$1"
    local owner

    if ! owner="$(busctl --system call \
        org.freedesktop.DBus \
        /org/freedesktop/DBus \
        org.freedesktop.DBus \
        NameHasOwner \
        s org.facelock.Daemon)"; then
        return 1
    fi
    [ "$owner" = "b $expected_owner" ]
}

facelock_source_install_legacy_hash_is_known() {
    local wanted_id="$1"
    local wanted_hash="$2"
    local manifest="$FACELOCK_SOURCE_INSTALL_REPOSITORY_ROOT/dist/legacy-system-assets.sha256"

    [ -f "$manifest" ] && [ ! -L "$manifest" ] || return 1
    awk -v wanted_id="$wanted_id" -v wanted_hash="$wanted_hash" '
        /^[[:space:]]*(#|$)/ { next }
        {
            if (NF != 2 || length($2) != 64 || $2 !~ /^[0-9a-f]+$/) exit 2
            if ($1 != "systemd-unit" && $1 != "dbus-policy" &&
                $1 != "dbus-activation") exit 2
            key=$1 ":" $2
            if (seen[key]++) exit 2
            if ($1 == wanted_id && $2 == wanted_hash) found=1
        }
        END { if (!found) exit 1 }
    ' "$manifest"
}

facelock_source_install_legacy_identity() {
    local path="$1"
    local boundary="${FACELOCK_SOURCE_INSTALL_DBUS_LAYOUT_PREFIX:-/}"
    local metadata digest_output digest uid gid mode links kind

    facelock_source_install_parents_are_trusted "$path" "$boundary" || return 1
    [ -f "$path" ] && [ ! -L "$path" ] || return 1
    metadata="$(facelock_source_install_stat -Lc '%d:%i:%u:%g:%a:%h:%s:%F' -- "$path")" ||
        return 1
    IFS=: read -r _ _ uid gid mode links _ kind <<<"$metadata"
    [ "$uid" = "$FACELOCK_SOURCE_INSTALL_TRUST_UID" ] &&
        [ "$gid" = "$FACELOCK_SOURCE_INSTALL_TRUST_GID" ] &&
        [ "$mode" = 644 ] && [ "$links" -eq 1 ] &&
        [[ "$kind" = regular\ *file ]] || return 1
    digest_output="$(sha256sum -- "$path")" || return 1
    digest="${digest_output%% *}"
    [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || return 1
    FACELOCK_SOURCE_INSTALL_IDENTITY_RESULT="$metadata;$digest"
}

facelock_source_install_admin_mask_identity() {
    local path="$1"
    local boundary="${FACELOCK_SOURCE_INSTALL_DBUS_LAYOUT_PREFIX:-/}"
    local metadata target uid gid mode links size kind

    facelock_source_install_parents_are_trusted "$path" "$boundary" || return 1
    metadata="$(facelock_source_install_stat -c '%d:%i:%u:%g:%a:%h:%s:%F' -- "$path")" ||
        return 1
    IFS=: read -r _ _ uid gid mode links size kind <<<"$metadata"
    [ "$uid" = "$FACELOCK_SOURCE_INSTALL_TRUST_UID" ] &&
        [ "$gid" = "$FACELOCK_SOURCE_INSTALL_TRUST_GID" ] &&
        [ "$links" -eq 1 ] || return 1
    if [ -L "$path" ]; then
        [ "$kind" = symbolic\ link ] || return 1
        IFS= read -r -d '' target < <(readlink -z -- "$path") || return 1
        [ "$target" = /dev/null ] || return 1
        FACELOCK_SOURCE_INSTALL_IDENTITY_RESULT="symlink;$metadata;/dev/null"
        return
    fi
    [ -f "$path" ] && [[ "$kind" = regular\ *file ]] &&
        [ "$size" -eq 0 ] && [ "$((8#$mode & 8#022))" -eq 0 ] || return 1
    FACELOCK_SOURCE_INSTALL_IDENTITY_RESULT="regular;$metadata"
}

facelock_source_install_plan_legacy_assets() {
    local prefix="$FACELOCK_SOURCE_INSTALL_DBUS_LAYOUT_PREFIX"
    local record id public_relative quarantine_name public quarantine
    local public_identity quarantine_identity public_digest quarantine_digest
    local public_state quarantine_state
    local -a assets=(
        'systemd-unit|etc/systemd/system/facelock-daemon.service|.facelock-migrate-systemd-unit'
        'dbus-policy|etc/dbus-1/system.d/org.facelock.Daemon.conf|.facelock-migrate-dbus-policy'
        'dbus-activation|etc/dbus-1/system-services/org.facelock.Daemon.service|.facelock-migrate-dbus-activation'
    )

    FACELOCK_SOURCE_INSTALL_LEGACY_PLAN=()
    FACELOCK_SOURCE_INSTALL_LEGACY_MIGRATION_RECORDED=false
    FACELOCK_SOURCE_INSTALL_LEGACY_MIGRATION_COMMITTED=false
    FACELOCK_SOURCE_INSTALL_LEGACY_RECONCILIATION_FAILED=false
    FACELOCK_SOURCE_INSTALL_PERSISTENT_UNIT_PLANNED_RETIRE=false
    for record in "${assets[@]}"; do
        IFS='|' read -r id public_relative quarantine_name <<<"$record"
        public="${prefix}/${public_relative}"
        [ -n "$prefix" ] || public="/$public_relative"
        quarantine="${public%/*}/$quarantine_name"
        facelock_source_install_existing_parents_are_trusted \
            "$public" "${prefix:-/}" || return 1
        public_state=absent
        quarantine_state=absent
        public_identity=
        quarantine_identity=
        if [ -e "$public" ] || [ -L "$public" ]; then
            if [ "$id" = systemd-unit ] &&
                facelock_source_install_admin_mask_identity "$public"; then
                public_state=admin-mask
                public_identity="$FACELOCK_SOURCE_INSTALL_IDENTITY_RESULT"
            else
                facelock_source_install_legacy_identity "$public" || return 1
                public_identity="$FACELOCK_SOURCE_INSTALL_IDENTITY_RESULT"
                public_digest="${public_identity##*;}"
                if facelock_source_install_legacy_hash_is_known "$id" "$public_digest"; then
                    public_state=exact
                else
                    public_state=admin-file
                fi
            fi
        fi
        if [ -e "$quarantine" ] || [ -L "$quarantine" ]; then
            facelock_source_install_legacy_identity "$quarantine" || return 1
            quarantine_identity="$FACELOCK_SOURCE_INSTALL_IDENTITY_RESULT"
            quarantine_digest="${quarantine_identity##*;}"
            facelock_source_install_legacy_hash_is_known "$id" "$quarantine_digest" ||
                return 1
            quarantine_state=exact
        fi
        case "$public_state:$quarantine_state" in
            absent:absent)
                FACELOCK_SOURCE_INSTALL_LEGACY_PLAN+=(
                    "$id|$public|$quarantine|absent||"
                )
                ;;
            exact:absent)
                FACELOCK_SOURCE_INSTALL_LEGACY_PLAN+=(
                    "$id|$public|$quarantine|candidate|$public_identity|"
                )
                if [ "$id" = systemd-unit ]; then
                    FACELOCK_SOURCE_INSTALL_PERSISTENT_UNIT_PLANNED_RETIRE=true
                fi
                ;;
            absent:exact)
                FACELOCK_SOURCE_INSTALL_LEGACY_PLAN+=(
                    "$id|$public|$quarantine|interrupted||$quarantine_identity"
                )
                ;;
            admin-mask:absent)
                FACELOCK_SOURCE_INSTALL_LEGACY_PLAN+=(
                    "$id|$public|$quarantine|admin-mask|$public_identity|"
                )
                ;;
            admin-file:absent)
                FACELOCK_SOURCE_INSTALL_LEGACY_PLAN+=(
                    "$id|$public|$quarantine|admin-file|$public_identity|"
                )
                ;;
            *) return 1 ;;
        esac
    done
}

facelock_source_install_legacy_plan_is_current() {
    local record id public quarantine state public_identity quarantine_identity
    local current

    for record in "${FACELOCK_SOURCE_INSTALL_LEGACY_PLAN[@]}"; do
        IFS='|' read -r id public quarantine state public_identity quarantine_identity <<<"$record"
        case "$state" in
            absent)
                [ ! -e "$public" ] && [ ! -L "$public" ] &&
                    [ ! -e "$quarantine" ] && [ ! -L "$quarantine" ] || return 1
                ;;
            candidate)
                facelock_source_install_legacy_identity "$public" || return 1
                current="$FACELOCK_SOURCE_INSTALL_IDENTITY_RESULT"
                [ "$current" = "$public_identity" ] &&
                    [ ! -e "$quarantine" ] && [ ! -L "$quarantine" ] || return 1
                ;;
            interrupted)
                [ ! -e "$public" ] && [ ! -L "$public" ] || return 1
                facelock_source_install_legacy_identity "$quarantine" || return 1
                current="$FACELOCK_SOURCE_INSTALL_IDENTITY_RESULT"
                [ "$current" = "$quarantine_identity" ] || return 1
                ;;
            admin-mask)
                facelock_source_install_admin_mask_identity "$public" || return 1
                current="$FACELOCK_SOURCE_INSTALL_IDENTITY_RESULT"
                [ "$current" = "$public_identity" ] &&
                    [ ! -e "$quarantine" ] && [ ! -L "$quarantine" ] || return 1
                ;;
            admin-file)
                facelock_source_install_legacy_identity "$public" || return 1
                current="$FACELOCK_SOURCE_INSTALL_IDENTITY_RESULT"
                [ "$current" = "$public_identity" ] &&
                    [ ! -e "$quarantine" ] && [ ! -L "$quarantine" ] || return 1
                ;;
            *) return 1 ;;
        esac
    done
}

facelock_source_install_record_legacy_migration() {
    local record id public quarantine state _public_identity _quarantine_identity
    local expected_identity

    [ "${#FACELOCK_SOURCE_INSTALL_LEGACY_PLAN[@]}" -eq 3 ] || return 1
    for record in "${FACELOCK_SOURCE_INSTALL_LEGACY_PLAN[@]}"; do
        IFS='|' read -r id public quarantine state _public_identity _quarantine_identity <<<"$record"
        case "$state" in
            admin-mask)
                facelock_source_install_admin_mask_identity "$public" &&
                    [ "$FACELOCK_SOURCE_INSTALL_IDENTITY_RESULT" = "$_public_identity" ] &&
                    [ ! -e "$quarantine" ] && [ ! -L "$quarantine" ] || return 1
                ;;
            admin-file)
                facelock_source_install_legacy_identity "$public" &&
                    [ "$FACELOCK_SOURCE_INSTALL_IDENTITY_RESULT" = "$_public_identity" ] &&
                    [ ! -e "$quarantine" ] && [ ! -L "$quarantine" ] || return 1
                ;;
            candidate | interrupted)
                [ ! -e "$public" ] && [ ! -L "$public" ] &&
                    facelock_source_install_legacy_identity "$quarantine" || return 1
                expected_identity="$_public_identity"
                [ "$state" = candidate ] || expected_identity="$_quarantine_identity"
                [ "$FACELOCK_SOURCE_INSTALL_IDENTITY_RESULT" = "$expected_identity" ] ||
                    return 1
                ;;
            absent)
                [ ! -e "$public" ] && [ ! -L "$public" ] &&
                    [ ! -e "$quarantine" ] && [ ! -L "$quarantine" ] || return 1
                ;;
            *) return 1 ;;
        esac
    done
    FACELOCK_SOURCE_INSTALL_LEGACY_MIGRATION_RECORDED=true
}

facelock_source_install_invoke_legacy_stage() {
    local layout_root="$1"

    "$FACELOCK_SOURCE_INSTALL_REPOSITORY_ROOT/scripts/migrate-legacy-system-assets.sh" \
        --source-protected --stage "$layout_root"
}

facelock_source_install_stage_and_record_legacy_migration() {
    local layout_root="${1:-/}"
    local expected_root="${FACELOCK_SOURCE_INSTALL_DBUS_LAYOUT_PREFIX:-/}"
    local stage_status=0

    [ "$layout_root" = "$expected_root" ] || return 1
    [ "${#FACELOCK_SOURCE_INSTALL_LEGACY_PLAN[@]}" -eq 3 ] || return 1
    [ "$FACELOCK_SOURCE_INSTALL_LEGACY_MIGRATION_RECORDED" = false ] || return 1
    [ "$FACELOCK_SOURCE_INSTALL_LEGACY_MIGRATION_COMMITTED" = false ] || return 1

    # Bash normally defers a trapped signal while waiting for a foreground
    # child, but the critical flag must already be set when that wait starts.
    # Keep it set through the exact parent-side identity record so there is no
    # successful-child/unrecorded-parent signal window.
    FACELOCK_SOURCE_INSTALL_CRITICAL=true
    if facelock_source_install_invoke_legacy_stage "$layout_root"; then
        if [ "$FACELOCK_SOURCE_INSTALL_DEFERRED_SIGNAL" -ne 0 ]; then
            stage_status="$FACELOCK_SOURCE_INSTALL_DEFERRED_SIGNAL"
        elif facelock_source_install_record_legacy_migration; then
            stage_status=0
        else
            stage_status=$?
        fi
    else
        stage_status=$?
    fi
    FACELOCK_SOURCE_INSTALL_CRITICAL=false

    if [ "$FACELOCK_SOURCE_INSTALL_DEFERRED_SIGNAL" -ne 0 ]; then
        return "$FACELOCK_SOURCE_INSTALL_DEFERRED_SIGNAL"
    fi
    return "$stage_status"
}

facelock_source_install_move_noreplace() {
    local source="$1"
    local destination="$2"

    [ ! -e "$destination" ] && [ ! -L "$destination" ] || return 1
    mv -Tn -- "$source" "$destination" || return 1
    [ ! -e "$source" ] && [ ! -L "$source" ] &&
        { [ -e "$destination" ] || [ -L "$destination" ]; }
}

facelock_source_install_rollback_legacy_migration() {
    local index record id public quarantine state public_identity quarantine_identity
    local expected_identity current rollback_failed=0

    [ "${#FACELOCK_SOURCE_INSTALL_LEGACY_PLAN[@]}" -eq 3 ] || return 0
    [ "$FACELOCK_SOURCE_INSTALL_LEGACY_MIGRATION_COMMITTED" = false ] || return 1
    for ((index=${#FACELOCK_SOURCE_INSTALL_LEGACY_PLAN[@]} - 1; index >= 0; index--)); do
        record="${FACELOCK_SOURCE_INSTALL_LEGACY_PLAN[$index]}"
        IFS='|' read -r id public quarantine state public_identity quarantine_identity <<<"$record"
        case "$state" in
            candidate)
                expected_identity="$public_identity"
                if [ -e "$public" ] || [ -L "$public" ]; then
                    if [ -e "$quarantine" ] || [ -L "$quarantine" ] ||
                        ! facelock_source_install_legacy_identity "$public" ||
                        [ "$FACELOCK_SOURCE_INSTALL_IDENTITY_RESULT" != "$expected_identity" ]; then
                        echo "Error: source-install rollback preserved an ambiguous legacy pair: $public and $quarantine" >&2
                        rollback_failed=1
                    fi
                elif ! facelock_source_install_legacy_identity "$quarantine" ||
                    [ "$FACELOCK_SOURCE_INSTALL_IDENTITY_RESULT" != "$expected_identity" ] ||
                    ! facelock_source_install_move_noreplace "$quarantine" "$public" ||
                    ! facelock_source_install_legacy_identity "$public" ||
                    [ "$FACELOCK_SOURCE_INSTALL_IDENTITY_RESULT" != "$expected_identity" ]; then
                    echo "Error: source-install rollback preserved an ambiguous legacy pair: $public and $quarantine" >&2
                    rollback_failed=1
                fi
                ;;
            interrupted)
                expected_identity="$quarantine_identity"
                if [ -e "$quarantine" ] || [ -L "$quarantine" ]; then
                    if [ -e "$public" ] || [ -L "$public" ] ||
                        ! facelock_source_install_legacy_identity "$quarantine" ||
                        [ "$FACELOCK_SOURCE_INSTALL_IDENTITY_RESULT" != "$expected_identity" ]; then
                        echo "Error: source-install rollback preserved a changed interrupted quarantine: $quarantine" >&2
                        rollback_failed=1
                    fi
                elif ! facelock_source_install_legacy_identity "$public" ||
                    [ "$FACELOCK_SOURCE_INSTALL_IDENTITY_RESULT" != "$expected_identity" ] ||
                    ! facelock_source_install_move_noreplace "$public" "$quarantine" ||
                    ! facelock_source_install_legacy_identity "$quarantine" ||
                    [ "$FACELOCK_SOURCE_INSTALL_IDENTITY_RESULT" != "$expected_identity" ]; then
                    echo "Error: source-install rollback preserved a changed interrupted quarantine: $quarantine" >&2
                    rollback_failed=1
                fi
                ;;
            absent)
                [ ! -e "$public" ] && [ ! -L "$public" ] &&
                    [ ! -e "$quarantine" ] && [ ! -L "$quarantine" ] ||
                    rollback_failed=1
                ;;
            admin-mask)
                if ! facelock_source_install_admin_mask_identity "$public" ||
                    [ "$FACELOCK_SOURCE_INSTALL_IDENTITY_RESULT" != "$public_identity" ] ||
                    [ -e "$quarantine" ] || [ -L "$quarantine" ]; then
                    rollback_failed=1
                fi
                ;;
            admin-file)
                if ! facelock_source_install_legacy_identity "$public" ||
                    [ "$FACELOCK_SOURCE_INSTALL_IDENTITY_RESULT" != "$public_identity" ] ||
                    [ -e "$quarantine" ] || [ -L "$quarantine" ]; then
                    rollback_failed=1
                fi
                ;;
            *) rollback_failed=1 ;;
        esac
    done
    if [ "$rollback_failed" -ne 0 ]; then
        return 1
    fi
    FACELOCK_SOURCE_INSTALL_LEGACY_MIGRATION_RECORDED=false
    facelock_source_install_legacy_plan_is_current
}

facelock_source_install_commit_legacy_migration() {
    local record id public quarantine state public_identity quarantine_identity
    local expected_identity

    [ "$FACELOCK_SOURCE_INSTALL_LEGACY_MIGRATION_RECORDED" = true ] || return 0
    [ "$FACELOCK_SOURCE_INSTALL_LEGACY_MIGRATION_COMMITTED" = false ] || return 0
    facelock_source_install_legacy_state_is_expected || return 1
    for record in "${FACELOCK_SOURCE_INSTALL_LEGACY_PLAN[@]}"; do
        IFS='|' read -r id public quarantine state public_identity quarantine_identity <<<"$record"
        case "$state" in
            candidate | interrupted)
                expected_identity="$public_identity"
                [ "$state" = candidate ] || expected_identity="$quarantine_identity"
                facelock_source_install_legacy_identity "$quarantine" &&
                    [ "$FACELOCK_SOURCE_INSTALL_IDENTITY_RESULT" = "$expected_identity" ] ||
                    return 1
                rm -- "$quarantine" || return 1
                [ ! -e "$quarantine" ] && [ ! -L "$quarantine" ] || return 1
                echo "Removed exact known legacy system asset $public"
                ;;
        esac
    done
    FACELOCK_SOURCE_INSTALL_LEGACY_MIGRATION_COMMITTED=true
    facelock_source_install_legacy_state_is_expected
}

facelock_source_install_legacy_state_is_expected() {
    local record id public quarantine state _public_identity _quarantine_identity

    if [ "$FACELOCK_SOURCE_INSTALL_LEGACY_MIGRATION_RECORDED" = false ]; then
        facelock_source_install_legacy_plan_is_current
        return
    fi
    for record in "${FACELOCK_SOURCE_INSTALL_LEGACY_PLAN[@]}"; do
        IFS='|' read -r id public quarantine state _public_identity _quarantine_identity <<<"$record"
        case "$state" in
            admin-mask)
                facelock_source_install_admin_mask_identity "$public" &&
                    [ "$FACELOCK_SOURCE_INSTALL_IDENTITY_RESULT" = "$_public_identity" ] &&
                    [ ! -e "$quarantine" ] && [ ! -L "$quarantine" ] || return 1
                ;;
            admin-file)
                facelock_source_install_legacy_identity "$public" &&
                    [ "$FACELOCK_SOURCE_INSTALL_IDENTITY_RESULT" = "$_public_identity" ] &&
                    [ ! -e "$quarantine" ] && [ ! -L "$quarantine" ] || return 1
                ;;
            candidate | interrupted)
                [ ! -e "$public" ] && [ ! -L "$public" ] || return 1
                if [ "$FACELOCK_SOURCE_INSTALL_LEGACY_MIGRATION_COMMITTED" = true ]; then
                    [ ! -e "$quarantine" ] && [ ! -L "$quarantine" ] || return 1
                else
                    facelock_source_install_legacy_identity "$quarantine" || return 1
                    if [ "$state" = candidate ]; then
                        [ "$FACELOCK_SOURCE_INSTALL_IDENTITY_RESULT" = "$_public_identity" ] ||
                            return 1
                    else
                        [ "$FACELOCK_SOURCE_INSTALL_IDENTITY_RESULT" = "$_quarantine_identity" ] ||
                            return 1
                    fi
                fi
                ;;
            absent)
                [ ! -e "$public" ] && [ ! -L "$public" ] &&
                    [ ! -e "$quarantine" ] && [ ! -L "$quarantine" ] || return 1
                ;;
            *) return 1 ;;
        esac
    done
}

facelock_source_install_retired_persistent_unit_is_current() {
    local snapshot="$FACELOCK_SOURCE_INSTALL_PERSISTENT_MASK_SNAPSHOT"
    local fd="$FACELOCK_SOURCE_INSTALL_PERSISTENT_MASK_FD"
    local expected_metadata current_metadata expected_digest digest_output current_digest
    local expected_dev expected_ino expected_uid expected_gid expected_mode _expected_links
    local expected_size expected_kind current_dev current_ino current_uid current_gid
    local current_mode current_links current_size current_kind
    local quarantine="${FACELOCK_SOURCE_INSTALL_PERSISTENT_MASK_PATH%/*}/.facelock-migrate-systemd-unit"

    [ "$FACELOCK_SOURCE_INSTALL_PERSISTENT_UNIT_PLANNED_RETIRE" = true ] &&
        [ "$FACELOCK_SOURCE_INSTALL_LEGACY_MIGRATION_RECORDED" = true ] &&
        [[ "$snapshot" = ordinary:* ]] && [ -n "$fd" ] &&
        [ ! -e "$FACELOCK_SOURCE_INSTALL_PERSISTENT_MASK_PATH" ] &&
        [ ! -L "$FACELOCK_SOURCE_INSTALL_PERSISTENT_MASK_PATH" ] || return 1
    if [ "$FACELOCK_SOURCE_INSTALL_LEGACY_MIGRATION_COMMITTED" = true ]; then
        [ ! -e "$quarantine" ] && [ ! -L "$quarantine" ] || return 1
    else
        [ -e "$quarantine" ] && [ ! -L "$quarantine" ] || return 1
    fi
    expected_metadata="${snapshot#*:}"
    expected_metadata="${expected_metadata%:*}"
    expected_digest="${snapshot##*:}"
    current_metadata="$(facelock_source_install_stat -Lc '%d:%i:%u:%g:%a:%h:%s:%F' -- \
        "/proc/$$/fd/$fd")" || return 1
    IFS=: read -r expected_dev expected_ino expected_uid expected_gid expected_mode \
        _expected_links expected_size expected_kind <<<"$expected_metadata"
    IFS=: read -r current_dev current_ino current_uid current_gid current_mode \
        current_links current_size current_kind <<<"$current_metadata"
    [ "$current_dev:$current_ino:$current_uid:$current_gid:$current_mode:$current_size:$current_kind" = \
        "$expected_dev:$expected_ino:$expected_uid:$expected_gid:$expected_mode:$expected_size:$expected_kind" ] ||
        return 1
    if [ "$FACELOCK_SOURCE_INSTALL_LEGACY_MIGRATION_COMMITTED" = true ]; then
        [ "$current_links" -eq 0 ] || return 1
    else
        [ "$current_links" -eq 1 ] && [ "$quarantine" -ef "/proc/$$/fd/$fd" ] || return 1
    fi
    digest_output="$(sha256sum -- "/proc/$$/fd/$fd")" || return 1
    current_digest="${digest_output%% *}"
    [ "$current_digest" = "$expected_digest" ]
}

facelock_source_install_snapshot_physical_mask() {
    local path="$1"
    local snapshot_variable="$2"
    local fd_variable="$3"
    local boundary="${FACELOCK_SOURCE_INSTALL_DBUS_LAYOUT_PREFIX:-/}"
    local first_metadata second_metadata target digest_output digest
    local mask_fd=''
    local uid gid mode links size kind

    printf -v "$fd_variable" '%s' ''
    facelock_source_install_existing_parents_are_trusted \
        "$path" "$boundary" || return 1
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then
        printf -v "$snapshot_variable" '%s' absent
        return 0
    fi
    facelock_source_install_parents_are_trusted "$path" "$boundary" || return 1
    first_metadata="$(facelock_source_install_stat -c '%d:%i:%u:%g:%a:%h:%s:%F' -- "$path")" ||
        return 1
    IFS=: read -r _ _ uid gid mode links size kind <<<"$first_metadata"
    [ "$uid" = "$FACELOCK_SOURCE_INSTALL_TRUST_UID" ] &&
        [ "$gid" = "$FACELOCK_SOURCE_INSTALL_TRUST_GID" ] &&
        [ "$links" -eq 1 ] || return 1
    if [ -L "$path" ]; then
        [ "$kind" = symbolic\ link ] || return 1
        IFS= read -r -d '' target < <(readlink -z -- "$path") || return 1
        [ "$target" = /dev/null ] || return 1
        second_metadata="$(facelock_source_install_stat -c '%d:%i:%u:%g:%a:%h:%s:%F' -- "$path")" ||
            return 1
        [ "$first_metadata" = "$second_metadata" ] || return 1
        printf -v "$snapshot_variable" 'mask-symlink:%s:/dev/null' \
            "$first_metadata"
        return 0
    fi
    [ -f "$path" ] && [[ "$kind" = regular\ *file ]] &&
        [ "$size" -le 1048576 ] &&
        [ "$((8#$mode & 8#022))" -eq 0 ] || return 1
    exec {mask_fd}<"$path" || return 1
    if [ ! "$path" -ef "/proc/$$/fd/$mask_fd" ] ||
        [ "$(facelock_source_install_stat -Lc '%d:%i:%u:%g:%a:%h:%s:%F' -- \
            "/proc/$$/fd/$mask_fd")" != "$first_metadata" ]; then
        exec {mask_fd}>&-
        return 1
    fi
    if [ "$size" -eq 0 ]; then
        printf -v "$snapshot_variable" 'mask-regular:%s:' "$first_metadata"
    else
        digest_output="$(sha256sum -- "/proc/$$/fd/$mask_fd")" || {
            exec {mask_fd}>&-
            return 1
        }
        digest="${digest_output%% *}"
        [[ "$digest" =~ ^[0-9a-f]{64}$ ]] &&
            [ "$(facelock_source_install_stat -Lc '%d:%i:%u:%g:%a:%h:%s:%F' -- \
                "/proc/$$/fd/$mask_fd")" = "$first_metadata" ] &&
            [ "$path" -ef "/proc/$$/fd/$mask_fd" ] || {
            exec {mask_fd}>&-
            return 1
        }
        printf -v "$snapshot_variable" 'ordinary:%s:%s' \
            "$first_metadata" "$digest"
    fi
    printf -v "$fd_variable" '%s' "$mask_fd"
}

facelock_source_install_physical_mask_is_current() {
    local path="$1"
    local snapshot="$2"
    local mask_fd="$3"
    local expected_metadata expected_digest target current_metadata
    local second_metadata digest_output current_digest

    if [ "$snapshot" = absent ]; then
        [ ! -e "$path" ] && [ ! -L "$path" ]
        return
    fi
    expected_metadata="${snapshot#*:}"
    expected_metadata="${expected_metadata%:*}"
    case "$snapshot" in
        mask-symlink:*)
            [ -L "$path" ] || return 1
            current_metadata="$(facelock_source_install_stat -c '%d:%i:%u:%g:%a:%h:%s:%F' -- \
                "$path")" || return 1
            [ "$current_metadata" = "$expected_metadata" ] || return 1
            IFS= read -r -d '' target < <(readlink -z -- "$path") || return 1
            [ "$target" = /dev/null ] || return 1
            second_metadata="$(facelock_source_install_stat -c '%d:%i:%u:%g:%a:%h:%s:%F' -- \
                "$path")" || return 1
            [ "$second_metadata" = "$expected_metadata" ]
            ;;
        mask-regular:* | ordinary:*)
            [ -n "$mask_fd" ] && [ -f "$path" ] && [ ! -L "$path" ] &&
                [ "$path" -ef "/proc/$$/fd/$mask_fd" ] || return 1
            current_metadata="$(facelock_source_install_stat -Lc '%d:%i:%u:%g:%a:%h:%s:%F' -- \
                "$path")" || return 1
            [ "$current_metadata" = "$expected_metadata" ] &&
                [ "$(facelock_source_install_stat -Lc '%d:%i:%u:%g:%a:%h:%s:%F' -- \
                    "/proc/$$/fd/$mask_fd")" = "$expected_metadata" ] ||
                return 1
            if [[ "$snapshot" = ordinary:* ]]; then
                expected_digest="${snapshot##*:}"
                digest_output="$(sha256sum -- "/proc/$$/fd/$mask_fd")" ||
                    return 1
                current_digest="${digest_output%% *}"
                [ "$current_digest" = "$expected_digest" ] &&
                    [ "$(facelock_source_install_stat -Lc '%d:%i:%u:%g:%a:%h:%s:%F' -- \
                        "/proc/$$/fd/$mask_fd")" = "$expected_metadata" ] &&
                    [ "$path" -ef "/proc/$$/fd/$mask_fd" ]
            fi
            ;;
        *) return 1 ;;
    esac
}

facelock_source_install_physical_masks_are_current() {
    facelock_source_install_legacy_state_is_expected &&
        { facelock_source_install_physical_mask_is_current \
            "$FACELOCK_SOURCE_INSTALL_PERSISTENT_MASK_PATH" \
            "$FACELOCK_SOURCE_INSTALL_PERSISTENT_MASK_SNAPSHOT" \
            "$FACELOCK_SOURCE_INSTALL_PERSISTENT_MASK_FD" ||
            facelock_source_install_retired_persistent_unit_is_current; } &&
        facelock_source_install_physical_mask_is_current \
            "$FACELOCK_SOURCE_INSTALL_RUNTIME_MASK_PATH" \
            "$FACELOCK_SOURCE_INSTALL_RUNTIME_MASK_SNAPSHOT" \
            "$FACELOCK_SOURCE_INSTALL_RUNTIME_MASK_FD"
}

facelock_source_install_release_physical_mask_fds() {
    if [ -n "$FACELOCK_SOURCE_INSTALL_PERSISTENT_MASK_FD" ]; then
        exec {FACELOCK_SOURCE_INSTALL_PERSISTENT_MASK_FD}>&-
        FACELOCK_SOURCE_INSTALL_PERSISTENT_MASK_FD=
    fi
    if [ -n "$FACELOCK_SOURCE_INSTALL_RUNTIME_MASK_FD" ]; then
        exec {FACELOCK_SOURCE_INSTALL_RUNTIME_MASK_FD}>&-
        FACELOCK_SOURCE_INSTALL_RUNTIME_MASK_FD=
    fi
}

facelock_source_install_release_barrier_fds() {
    if [ -n "$FACELOCK_SOURCE_INSTALL_BARRIER_FD" ]; then
        exec {FACELOCK_SOURCE_INSTALL_BARRIER_FD}>&-
        FACELOCK_SOURCE_INSTALL_BARRIER_FD=
    fi
    if [ -n "$FACELOCK_SOURCE_INSTALL_BARRIER_DIR_FD" ]; then
        exec {FACELOCK_SOURCE_INSTALL_BARRIER_DIR_FD}>&-
        FACELOCK_SOURCE_INSTALL_BARRIER_DIR_FD=
    fi
}

facelock_source_install_unit_is_owned_barrier() {
    local expected_active_state="$1"
    local snapshot line load_state="" active_state="" fragment_path=""
    local load_count=0 active_count=0 fragment_count=0

    snapshot="$(systemctl show facelock-daemon.service \
        --property=LoadState \
        --property=ActiveState \
        --property=FragmentPath \
        --no-pager)" || return 1
    while IFS= read -r line; do
        case "$line" in
            LoadState=*)
                load_count=$((load_count + 1))
                load_state="${line#LoadState=}"
                ;;
            ActiveState=*)
                active_count=$((active_count + 1))
                active_state="${line#ActiveState=}"
                ;;
            FragmentPath=*)
                fragment_count=$((fragment_count + 1))
                fragment_path="${line#FragmentPath=}"
                ;;
            *) return 1 ;;
        esac
    done <<<"$snapshot"
    [ "$load_count" -eq 1 ] && [ "$active_count" -eq 1 ] &&
        [ "$fragment_count" -eq 1 ] &&
        [ "$load_state" = masked ] &&
        [ "$active_state" = "$expected_active_state" ] &&
        [ "$fragment_path" = "$FACELOCK_SOURCE_INSTALL_BARRIER_PATH" ]
}

facelock_source_install_control_topology_is_current() {
    [ -n "$FACELOCK_SOURCE_INSTALL_PERSISTENT_CONTROL_PATH" ] &&
        [ ! -e "$FACELOCK_SOURCE_INSTALL_PERSISTENT_CONTROL_PATH" ] &&
        [ ! -L "$FACELOCK_SOURCE_INSTALL_PERSISTENT_CONTROL_PATH" ] || return 1

    if [ "$FACELOCK_SOURCE_INSTALL_BARRIER_CREATED" = true ]; then
        if [ "$FACELOCK_SOURCE_INSTALL_BARRIER_QUARANTINED" = true ]; then
            [ ! -e "$FACELOCK_SOURCE_INSTALL_BARRIER_PATH" ] &&
                [ ! -L "$FACELOCK_SOURCE_INSTALL_BARRIER_PATH" ] &&
                facelock_source_install_quarantined_barrier_is_current
        else
            facelock_source_install_owned_barrier_is_current
        fi
    else
        [ "$FACELOCK_SOURCE_INSTALL_BARRIER_QUARANTINED" = false ] &&
            [ -z "$FACELOCK_SOURCE_INSTALL_BARRIER_QUARANTINE_PATH" ] &&
            [ ! -e "$FACELOCK_SOURCE_INSTALL_BARRIER_PATH" ] &&
            [ ! -L "$FACELOCK_SOURCE_INSTALL_BARRIER_PATH" ]
    fi
}

facelock_source_install_expected_dbus_definition_is_current() {
    if [ "$FACELOCK_SOURCE_INSTALL_INITIAL_DBUS_DEFINITION_ABSENT" = true ]; then
        facelock_source_install_dbus_definition_is_absent ||
            facelock_source_install_dbus_definition_is_safe
    else
        facelock_source_install_dbus_definition_is_safe
    fi
}

facelock_source_install_post_removal_state_is_safe() {
    local expected_active_state="$1"
    local expected_owner="$2"
    local snapshot line load_state="" active_state="" unit_file_state=""
    local fragment_path="" daemon_exec_start="" drop_in_paths=""
    local load_count=0 active_count=0 unit_file_count=0 fragment_count=0
    local exec_count=0 drop_in_count=0 expected_unit_file_state

    snapshot="$(systemctl show facelock-daemon.service \
        --property=LoadState \
        --property=ActiveState \
        --property=UnitFileState \
        --property=FragmentPath \
        --property=ExecStart \
        --property=DropInPaths \
        --no-pager)" || return 1
    while IFS= read -r line; do
        case "$line" in
            LoadState=*)
                load_count=$((load_count + 1))
                load_state="${line#LoadState=}"
                ;;
            ActiveState=*)
                active_count=$((active_count + 1))
                active_state="${line#ActiveState=}"
                ;;
            UnitFileState=*)
                unit_file_count=$((unit_file_count + 1))
                unit_file_state="${line#UnitFileState=}"
                ;;
            FragmentPath=*)
                fragment_count=$((fragment_count + 1))
                fragment_path="${line#FragmentPath=}"
                ;;
            ExecStart=*)
                exec_count=$((exec_count + 1))
                daemon_exec_start="${line#ExecStart=}"
                ;;
            DropInPaths=*)
                drop_in_count=$((drop_in_count + 1))
                drop_in_paths="${line#DropInPaths=}"
                ;;
            *) return 1 ;;
        esac
    done <<<"$snapshot"
    [ "$load_count" -eq 1 ] && [ "$active_count" -eq 1 ] &&
        [ "$unit_file_count" -eq 1 ] && [ "$fragment_count" -eq 1 ] &&
        [ "$drop_in_count" -eq 1 ] &&
        [ "$active_state" = "$expected_active_state" ] || return 1

    if [ "$FACELOCK_SOURCE_INSTALL_INITIAL_UNIT_NOT_FOUND" = true ] &&
        [ "$load_state" = not-found ]; then
        [ "$expected_active_state" = inactive ] &&
            [ "$load_state" = not-found ] && [ -z "$unit_file_state" ] &&
            [ -z "$fragment_path" ] && [ "$exec_count" -eq 0 ] &&
            [ -z "$drop_in_paths" ] || return 1
    elif [ "$FACELOCK_SOURCE_INSTALL_HAS_PHYSICAL_MASK" = true ]; then
        [ "$expected_active_state" = inactive ] && [ "$load_state" = masked ] &&
            [ "$exec_count" -eq 0 ] && [ -z "$drop_in_paths" ] &&
            [ "$fragment_path" = \
                "$FACELOCK_SOURCE_INSTALL_PHYSICAL_MASK_WINNER" ] || return 1
        if [ "$FACELOCK_SOURCE_INSTALL_PHYSICAL_MASK_WINNER" = \
            "$FACELOCK_SOURCE_INSTALL_PERSISTENT_MASK_PATH" ]; then
            expected_unit_file_state=masked
        else
            expected_unit_file_state=masked-runtime
        fi
        [ "$unit_file_state" = "$expected_unit_file_state" ] || return 1
    else
        [ "$load_state" = loaded ] && [ "$exec_count" -eq 1 ] &&
            [ -n "$daemon_exec_start" ] || return 1
        case "$unit_file_state" in
            enabled | enabled-runtime | linked | linked-runtime | alias | static | \
                indirect | disabled | generated | transient) ;;
            *) return 1 ;;
        esac
        facelock_source_install_effective_unit_is_trusted \
            "$fragment_path" "$daemon_exec_start" "$drop_in_paths" \
            "${FACELOCK_SOURCE_INSTALL_DBUS_LAYOUT_PREFIX:-/}" \
            "${FACELOCK_SOURCE_INSTALL_INSTALLED_ASSETS[@]}" || return 1
    fi

    facelock_source_install_control_topology_is_current &&
        facelock_source_install_physical_masks_are_current &&
        facelock_source_install_dbus_config_is_standard \
            "$FACELOCK_SOURCE_INSTALL_DBUS_LAYOUT_PREFIX" &&
        facelock_source_install_expected_dbus_definition_is_current &&
        facelock_source_install_dbus_owner_is "$expected_owner"
}

facelock_source_install_restart_active_daemon() {
    local attempt

    for attempt in 1 2 3; do
        facelock_source_install_post_removal_state_is_safe \
            inactive false || return 1
        if systemctl start facelock-daemon.service; then
            facelock_source_install_post_removal_state_is_safe \
                active true || return 1
            return 0
        fi
    done
    return 1
}

facelock_source_install_recover_owned_barrier() {
    if [ "$FACELOCK_SOURCE_INSTALL_BARRIER_QUARANTINED" = true ]; then
        facelock_source_install_restore_quarantined_barrier || return 1
    else
        facelock_source_install_owned_barrier_is_current || return 1
    fi
    facelock_source_install_retry systemctl daemon-reload || return 1
    facelock_source_install_control_topology_is_current &&
        facelock_source_install_physical_masks_are_current &&
        facelock_source_install_dbus_config_is_standard \
            "$FACELOCK_SOURCE_INSTALL_DBUS_LAYOUT_PREFIX" &&
        facelock_source_install_expected_dbus_definition_is_current || return 1
    systemctl stop facelock-daemon.service || return 1
    facelock_source_install_unit_is_owned_barrier inactive &&
        facelock_source_install_dbus_owner_is false
}

facelock_source_install_prepare_offline_image() {
    local image_root="${1:-/}"
    local -a installed_assets
    local asset executable target pid1_comm image_prefix build_root marker
    local source_path visible_pid indicator surface address_name

    case "$image_root" in
        /*) ;;
        *)
            echo "Error: offline image root must be absolute; no files were changed." >&2
            return 1
            ;;
    esac
    image_prefix="${image_root%/}"
    build_root="$image_prefix/build"
    marker="$build_root/test/source-install-offline-image.marker"
    if [ "${FACELOCK_SOURCE_INSTALL_OFFLINE_MARKER:-}" != "$marker" ] ||
        [ "$(pwd -P)" != "$build_root" ] ||
        ! source_path="$(readlink -f -- "${BASH_SOURCE[0]}")" ||
        [ "$source_path" != \
            "$build_root/scripts/source-install-daemon-lifecycle.sh" ]; then
        echo "Error: offline image mode is not the repository Containerfile invocation; no files were changed." >&2
        return 1
    fi
    if ! IFS=: read -r FACELOCK_SOURCE_INSTALL_TRUST_UID \
        FACELOCK_SOURCE_INSTALL_TRUST_GID < <(
        stat -Lc '%u:%g' -- "$image_root"
    ); then
        echo "Error: offline image mode could not establish its image trust root; no files were changed." >&2
        return 1
    fi
    for asset in \
        "$build_root/scripts/source-install-daemon-lifecycle.sh" \
        "$build_root/scripts/migrate-legacy-system-assets.sh" \
        "$build_root/dist/legacy-system-assets.sha256" \
        "$build_root/justfile" \
        "$build_root/test/Containerfile" \
        "$marker" \
        "$build_root/dbus/org.facelock.Daemon.conf" \
        "$build_root/dbus/org.facelock.Daemon.service" \
        "$build_root/systemd/facelock-daemon.service"; do
        if ! facelock_source_install_regular_file_is_trusted \
            "$asset" "$image_root" 1048576; then
            echo "Error: offline image mode found untrusted repository build input; no files were changed." >&2
            return 1
        fi
    done
    if [ "$(cat -- "$marker")" != \
        facelock-repository-test-container-source-install-v1 ]; then
        echo "Error: offline image mode found an invalid repository build marker; no files were changed." >&2
        return 1
    fi
    if ! facelock_source_install_ensure_lock_directory \
        "$image_prefix/run/facelock" "$image_root" ||
        ! facelock_source_install_acquire_lock \
            "$image_prefix/run/facelock/lifecycle.lock" "$image_root"; then
        echo "Error: offline image mode could not acquire the source-install lifecycle lock; no files were changed." >&2
        return 1
    fi
    FACELOCK_SOURCE_INSTALL_DBUS_LAYOUT_PREFIX="$image_prefix"
    if ! facelock_source_install_plan_legacy_assets; then
        echo "Error: offline image mode found an unsafe legacy system-asset state; no files were changed." >&2
        return 1
    fi
    if [ ! -e "$image_root/.dockerenv" ] &&
        [ ! -e "$image_root/run/.containerenv" ]; then
        echo "Error: offline image mode requires a container-build marker; no files were changed." >&2
        return 1
    fi
    for surface in \
        /run/systemd/system \
        /run/systemd/private \
        /run/systemd/notify \
        /run/systemd/journal/socket \
        /run/openrc \
        /run/runit \
        /run/s6 \
        /run/dinitctl \
        /run/initctl \
        /dev/initctl; do
        if [ -e "$image_prefix$surface" ] || [ -L "$image_prefix$surface" ]; then
            echo "Error: offline image mode found a live service-manager surface; no files were changed." >&2
            return 1
        fi
    done
    for address_name in DBUS_SYSTEM_BUS_ADDRESS DBUS_STARTER_ADDRESS \
        DBUS_SESSION_BUS_ADDRESS; do
        if [ -n "${!address_name+x}" ]; then
            echo "Error: offline image mode found a D-Bus address override; no files were changed." >&2
            return 1
        fi
    done
    if [ -e "$image_root/run/dbus/system_bus_socket" ] ||
        [ -L "$image_root/run/dbus/system_bus_socket" ] ||
        [ -e "$image_root/run/dbus/pid" ] ||
        [ -L "$image_root/run/dbus/pid" ]; then
        echo "Error: offline image mode found a system-bus activation surface; no files were changed." >&2
        return 1
    fi
    if ! IFS= read -r pid1_comm <"$image_root/proc/1/comm"; then
        echo "Error: offline image mode could not verify the container process namespace; no files were changed." >&2
        return 1
    fi
    if [ "$pid1_comm" = systemd ]; then
        echo "Error: offline image mode found systemd as PID 1; no files were changed." >&2
        return 1
    fi

    mapfile -t installed_assets < <(facelock_source_install_default_assets)
    FACELOCK_SOURCE_INSTALL_DBUS_ASSETS=()
    for asset in "${installed_assets[@]}"; do
        case "$asset" in
            */org.facelock.Daemon.service)
                FACELOCK_SOURCE_INSTALL_DBUS_ASSETS+=("$image_prefix$asset")
                ;;
        esac
        if [ -e "$image_prefix$asset" ] || [ -L "$image_prefix$asset" ]; then
            echo "Error: offline image mode found an existing activation asset; no files were changed." >&2
            return 1
        fi
    done
    if ! facelock_source_install_dbus_definition_is_absent; then
        echo "Error: offline image mode found an existing or unreadable D-Bus activation definition; no files were changed." >&2
        return 1
    fi
    for indicator in \
        /usr/bin/facelock \
        /lib/security/pam_facelock.so \
        /usr/lib/security/pam_facelock.so \
        /etc/facelock \
        /var/lib/facelock \
        /var/log/facelock \
        /usr/share/facelock \
        /usr/share/dbus-1/system.d/org.facelock.Daemon.conf \
        /etc/dbus-1/system.d/org.facelock.Daemon.conf \
        /usr/lib/tmpfiles.d/facelock.conf; do
        if [ -e "$image_prefix$indicator" ] || [ -L "$image_prefix$indicator" ]; then
            echo "Error: offline image mode found an existing Facelock install indicator; no files were changed." >&2
            return 1
        fi
    done
    for visible_pid in "$image_root"/proc/[0-9]*; do
        [ -d "$visible_pid" ] || continue
        executable="$visible_pid/exe"
        if [ ! -L "$executable" ]; then
            echo "Error: offline image mode could not inspect a visible process; no files were changed." >&2
            return 1
        fi
        if ! target="$(readlink "$executable")"; then
            echo "Error: offline image mode could not inspect a running process; no files were changed." >&2
            return 1
        fi
        target="${target% (deleted)}"
        if [ "${target##*/}" = facelock ]; then
            echo "Error: offline image mode found a running facelock process; no files were changed." >&2
            return 1
        fi
    done

    FACELOCK_SOURCE_INSTALL_DAEMON_WAS_ACTIVE=false
    FACELOCK_SOURCE_INSTALL_BARRIER_CREATED=false
    FACELOCK_SOURCE_INSTALL_PREPARED=false
}

facelock_source_install_prepare_daemon() {
    local systemd_runtime_dir="${1:-/run/systemd/system}"
    local -a installed_assets
    local layout_prefix runtime_root barrier_dir persistent_control_path
    local persistent_mask_path runtime_mask_path
    local snapshot line load_state="" active_state="" unit_file_state=""
    local fragment_path="" daemon_exec_start="" drop_in_paths=""
    local load_state_count=0 active_state_count=0 unit_file_state_count=0
    local fragment_path_count=0 daemon_exec_start_count=0 drop_in_paths_count=0
    local loaded_unit=false asset barrier_status=0

    if [ "$#" -gt 1 ]; then
        installed_assets=("${@:2}")
    else
        mapfile -t installed_assets < <(facelock_source_install_default_assets)
    fi
    FACELOCK_SOURCE_INSTALL_INSTALLED_ASSETS=("${installed_assets[@]}")
    FACELOCK_SOURCE_INSTALL_DBUS_ASSETS=()
    for asset in "${installed_assets[@]}"; do
        case "$asset" in
            */org.facelock.Daemon.service)
                FACELOCK_SOURCE_INSTALL_DBUS_ASSETS+=("$asset")
                ;;
        esac
    done

    FACELOCK_SOURCE_INSTALL_DAEMON_WAS_ACTIVE=false
    FACELOCK_SOURCE_INSTALL_BARRIER_CREATED=false
    FACELOCK_SOURCE_INSTALL_PREPARED=false
    facelock_source_install_release_barrier_fds
    FACELOCK_SOURCE_INSTALL_BARRIER_PATH=
    FACELOCK_SOURCE_INSTALL_BARRIER_FD=
    FACELOCK_SOURCE_INSTALL_BARRIER_QUARANTINE_PATH=
    FACELOCK_SOURCE_INSTALL_BARRIER_QUARANTINED=false
    FACELOCK_SOURCE_INSTALL_BARRIER_DIR_PATH=
    FACELOCK_SOURCE_INSTALL_BARRIER_DIR_CREATED=false
    FACELOCK_SOURCE_INSTALL_BARRIER_DIR_FD=
    FACELOCK_SOURCE_INSTALL_STOP_SUCCEEDED=false
    FACELOCK_SOURCE_INSTALL_PERSISTENT_CONTROL_PATH=
    FACELOCK_SOURCE_INSTALL_INITIAL_UNIT_NOT_FOUND=false
    FACELOCK_SOURCE_INSTALL_INITIAL_DBUS_DEFINITION_ABSENT=false
    facelock_source_install_release_physical_mask_fds
    FACELOCK_SOURCE_INSTALL_PERSISTENT_MASK_SNAPSHOT=absent
    FACELOCK_SOURCE_INSTALL_RUNTIME_MASK_SNAPSHOT=absent
    FACELOCK_SOURCE_INSTALL_HAS_PHYSICAL_MASK=false
    FACELOCK_SOURCE_INSTALL_PHYSICAL_MASK_WINNER=
    if [ ! -d "$systemd_runtime_dir" ]; then
        echo "Error: systemd is unavailable, so no source-install activation barrier can be established; no files were changed." >&2
        return 1
    fi
    case "$systemd_runtime_dir" in
        /run/systemd/system) layout_prefix= ;;
        */run/systemd/system)
            layout_prefix="${systemd_runtime_dir%/run/systemd/system}"
            ;;
        *)
            echo "Error: the systemd runtime layout is unsupported; no files were changed." >&2
            return 1
            ;;
    esac
    FACELOCK_SOURCE_INSTALL_DBUS_LAYOUT_PREFIX="$layout_prefix"
    if ! IFS=: read -r FACELOCK_SOURCE_INSTALL_TRUST_UID \
        FACELOCK_SOURCE_INSTALL_TRUST_GID < <(
        stat -Lc '%u:%g' -- "${layout_prefix:-/}"
    ); then
        echo "Error: the system layout trust root is unavailable; no files were changed." >&2
        return 1
    fi
    runtime_root="$layout_prefix/run"
    barrier_dir="$runtime_root/systemd/system.control"
    persistent_control_path="$layout_prefix/etc/systemd/system.control/facelock-daemon.service"
    persistent_mask_path="$layout_prefix/etc/systemd/system/facelock-daemon.service"
    runtime_mask_path="$layout_prefix/run/systemd/system/facelock-daemon.service"
    FACELOCK_SOURCE_INSTALL_PERSISTENT_MASK_PATH="$persistent_mask_path"
    FACELOCK_SOURCE_INSTALL_RUNTIME_MASK_PATH="$runtime_mask_path"
    FACELOCK_SOURCE_INSTALL_PERSISTENT_CONTROL_PATH="$persistent_control_path"
    if ! facelock_source_install_ensure_lock_directory \
        "$runtime_root/facelock" "${layout_prefix:-/}" ||
        ! facelock_source_install_acquire_lock \
            "$runtime_root/facelock/lifecycle.lock" "${layout_prefix:-/}"; then
        echo "Error: another source install is already running or its lifecycle lock is unavailable; no files were changed." >&2
        return 1
    fi
    if ! facelock_source_install_plan_legacy_assets; then
        echo "Error: a historical system asset or migration quarantine is ambiguous or untrusted; no files were changed." >&2
        return 1
    fi
    if ! facelock_source_install_snapshot_physical_mask \
        "$persistent_mask_path" \
        FACELOCK_SOURCE_INSTALL_PERSISTENT_MASK_SNAPSHOT \
        FACELOCK_SOURCE_INSTALL_PERSISTENT_MASK_FD ||
        ! facelock_source_install_snapshot_physical_mask \
            "$runtime_mask_path" \
            FACELOCK_SOURCE_INSTALL_RUNTIME_MASK_SNAPSHOT \
            FACELOCK_SOURCE_INSTALL_RUNTIME_MASK_FD; then
        echo "Error: an ordinary administrative unit asset is untrusted or unsupported; no files were changed." >&2
        return 1
    fi
    case "$FACELOCK_SOURCE_INSTALL_PERSISTENT_MASK_SNAPSHOT" in
        mask-*)
            FACELOCK_SOURCE_INSTALL_HAS_PHYSICAL_MASK=true
            FACELOCK_SOURCE_INSTALL_PHYSICAL_MASK_WINNER="$persistent_mask_path"
            ;;
        ordinary:*) ;;
        absent)
            case "$FACELOCK_SOURCE_INSTALL_RUNTIME_MASK_SNAPSHOT" in
                mask-*)
                    FACELOCK_SOURCE_INSTALL_HAS_PHYSICAL_MASK=true
                    FACELOCK_SOURCE_INSTALL_PHYSICAL_MASK_WINNER="$runtime_mask_path"
                    ;;
            esac
            ;;
    esac
    if [ -e "$persistent_control_path" ] || [ -L "$persistent_control_path" ]; then
        echo "Error: a higher-priority systemd control unit prevents a reliable activation barrier; no files were changed." >&2
        return 1
    fi
    if [ -e "$barrier_dir/facelock-daemon.service" ] ||
        [ -L "$barrier_dir/facelock-daemon.service" ]; then
        echo "Error: an existing runtime systemd control unit prevents a reliable activation barrier; no files were changed." >&2
        return 1
    fi

    if ! snapshot="$(systemctl show facelock-daemon.service \
        --property=LoadState \
        --property=ActiveState \
        --property=UnitFileState \
        --property=FragmentPath \
        --property=ExecStart \
        --property=DropInPaths \
        --no-pager)"; then
        echo "Error: could not determine facelock-daemon.service state; no files were changed." >&2
        return 1
    fi

    while IFS= read -r line; do
        case "$line" in
            LoadState=*)
                load_state_count=$((load_state_count + 1))
                load_state="${line#LoadState=}"
                ;;
            ActiveState=*)
                active_state_count=$((active_state_count + 1))
                active_state="${line#ActiveState=}"
                ;;
            UnitFileState=*)
                unit_file_state_count=$((unit_file_state_count + 1))
                unit_file_state="${line#UnitFileState=}"
                ;;
            FragmentPath=*)
                fragment_path_count=$((fragment_path_count + 1))
                fragment_path="${line#FragmentPath=}"
                ;;
            ExecStart=*)
                daemon_exec_start_count=$((daemon_exec_start_count + 1))
                daemon_exec_start="${line#ExecStart=}"
                ;;
            DropInPaths=*)
                drop_in_paths_count=$((drop_in_paths_count + 1))
                drop_in_paths="${line#DropInPaths=}"
                ;;
            *)
                echo "Error: systemd returned an unexpected unit-state property; no files were changed." >&2
                return 1
                ;;
        esac
    done <<<"$snapshot"
    if [ "$load_state_count" -ne 1 ] ||
        [ "$active_state_count" -ne 1 ] ||
        [ "$unit_file_state_count" -ne 1 ] ||
        [ "$fragment_path_count" -ne 1 ] ||
        [ "$daemon_exec_start_count" -gt 1 ] ||
        [ "$drop_in_paths_count" -ne 1 ]; then
        echo "Error: systemd returned duplicate or missing unit-state properties; no files were changed." >&2
        return 1
    fi

    case "$load_state" in
        loaded)
            if [ "$daemon_exec_start_count" -ne 1 ] ||
                [ -z "$daemon_exec_start" ]; then
                echo "Error: systemd returned an incomplete loaded-unit state; no files were changed." >&2
                return 1
            fi
            ;;
        not-found)
            if [ "$daemon_exec_start_count" -ne 0 ] ||
                [ "$active_state" != inactive ] ||
                [ -n "$unit_file_state" ] ||
                [ -n "$fragment_path" ] ||
                [ -n "$drop_in_paths" ]; then
                echo "Error: systemd returned an inconsistent not-found unit state; no files were changed." >&2
                return 1
            fi
            ;;
        masked)
            if [ "$daemon_exec_start_count" -ne 0 ] ||
                [ "$active_state" != inactive ] ||
                [ -n "$drop_in_paths" ]; then
                echo "Error: systemd returned an inconsistent masked unit state; no files were changed." >&2
                return 1
            fi
            if [ "$FACELOCK_SOURCE_INSTALL_HAS_PHYSICAL_MASK" != true ]; then
                echo "Error: systemd reported a mask that does not match an ordinary administrative mask; no files were changed." >&2
                return 1
            fi
            if [ "$FACELOCK_SOURCE_INSTALL_PHYSICAL_MASK_WINNER" = \
                "$persistent_mask_path" ]; then
                [ "$unit_file_state:$fragment_path" = \
                    "masked:$persistent_mask_path" ] || {
                    echo "Error: systemd returned an inconsistent mask for facelock-daemon.service; no files were changed." >&2
                    return 1
                }
            else
                [ "$unit_file_state:$fragment_path" = \
                    "masked-runtime:$runtime_mask_path" ] || {
                    echo "Error: systemd returned an inconsistent mask for facelock-daemon.service; no files were changed." >&2
                    return 1
                }
            fi
            ;;
    esac

    case "$unit_file_state" in
        enabled | enabled-runtime | linked | linked-runtime | alias | masked | \
            masked-runtime | static | indirect | disabled | generated | transient) ;;
        "")
            if [ "$load_state" != not-found ]; then
                echo "Error: systemd returned an incomplete unit-file state; no files were changed." >&2
                return 1
            fi
            ;;
        *)
            echo "Error: refusing source install for unknown unit-file state $unit_file_state; no files were changed." >&2
            return 1
            ;;
    esac

    case "$load_state:$active_state" in
        loaded:active)
            if [ "$FACELOCK_SOURCE_INSTALL_HAS_PHYSICAL_MASK" = true ]; then
                echo "Error: an active facelock-daemon.service has an ordinary administrative mask and cannot be restored safely; no files were changed." >&2
                return 1
            fi
            if ! facelock_source_install_effective_unit_is_trusted \
                "$fragment_path" "$daemon_exec_start" "$drop_in_paths" \
                "${layout_prefix:-/}" "${installed_assets[@]}"; then
                echo "Error: the loaded facelock-daemon.service assets are inconsistent or untrusted; no files were changed." >&2
                return 1
            fi
            FACELOCK_SOURCE_INSTALL_DAEMON_WAS_ACTIVE=true
            loaded_unit=true
            ;;
        loaded:inactive)
            if ! facelock_source_install_effective_unit_is_trusted \
                "$fragment_path" "$daemon_exec_start" "$drop_in_paths" \
                "${layout_prefix:-/}" "${installed_assets[@]}"; then
                echo "Error: the loaded facelock-daemon.service assets are inconsistent or untrusted; no files were changed." >&2
                return 1
            fi
            loaded_unit=true
            ;;
        not-found:inactive)
            if [ "$FACELOCK_SOURCE_INSTALL_PERSISTENT_MASK_SNAPSHOT" != absent ] ||
                [ "$FACELOCK_SOURCE_INSTALL_RUNTIME_MASK_SNAPSHOT" != absent ]; then
                echo "Error: systemd did not report an ordinary administrative unit asset; no files were changed." >&2
                return 1
            fi
            for asset in "${installed_assets[@]}"; do
                if [ -e "$asset" ] || [ -L "$asset" ]; then
                    echo "Error: systemd did not load facelock-daemon.service although an install asset exists; no files were changed." >&2
                    return 1
                fi
            done
            if ! facelock_source_install_dbus_definition_is_absent; then
                echo "Error: systemd did not load facelock-daemon.service although a D-Bus activation definition exists or is unreadable; no files were changed." >&2
                return 1
            fi
            FACELOCK_SOURCE_INSTALL_INITIAL_UNIT_NOT_FOUND=true
            FACELOCK_SOURCE_INSTALL_INITIAL_DBUS_DEFINITION_ABSENT=true
            ;;
        masked:inactive)
            :
            ;;
        *)
            echo "Error: refusing source install while facelock-daemon.service is $load_state/$active_state ($unit_file_state); no files were changed." >&2
            return 1
            ;;
    esac

    if [ "$loaded_unit" = true ]; then
        case "$unit_file_state" in
            masked | masked-runtime)
                echo "Error: systemd returned a false loaded/masked unit schema; no files were changed." >&2
                return 1
                ;;
        esac
    fi
    if ! facelock_source_install_dbus_uses_systemd_activation; then
        echo "Error: D-Bus activation is unavailable or does not reliably delegate to systemd; no files were changed." >&2
        return 1
    fi
    if ! facelock_source_install_dbus_config_is_standard "$layout_prefix"; then
        echo "Error: the effective D-Bus activation configuration is custom or cannot be proven safe; no files were changed." >&2
        return 1
    fi
    if [ "${#FACELOCK_SOURCE_INSTALL_DBUS_ASSETS[@]}" -eq 0 ] ||
        ! facelock_source_install_dbus_definition_delegates \
            dbus/org.facelock.Daemon.service || {
        if [ "$loaded_unit" = true ] ||
            [ "$FACELOCK_SOURCE_INSTALL_HAS_PHYSICAL_MASK" = true ]; then
            ! facelock_source_install_dbus_definition_is_safe
        else
            ! facelock_source_install_dbus_definition_is_absent
        fi
    }; then
        echo "Error: the selected D-Bus activation definition does not delegate to facelock-daemon.service; no files were changed." >&2
        return 1
    fi
    if ! facelock_source_install_retry \
        facelock_source_install_reload_dbus_activation ||
        ! facelock_source_install_dbus_owner_matches_snapshot; then
        echo "Error: D-Bus activation state could not be synchronized with the daemon snapshot; no files were changed." >&2
        return 1
    fi
    if ! facelock_source_install_dbus_config_is_standard "$layout_prefix" || {
        if [ "$loaded_unit" = true ] ||
            [ "$FACELOCK_SOURCE_INSTALL_HAS_PHYSICAL_MASK" = true ]; then
            ! facelock_source_install_dbus_definition_is_safe
        else
            ! facelock_source_install_dbus_definition_is_absent
        fi
    }; then
        echo "Error: D-Bus activation configuration changed while its cache was synchronized; no files were changed." >&2
        return 1
    fi

    if ! facelock_source_install_physical_masks_are_current; then
        echo "Error: an ordinary administrative mask changed before the activation barrier was created; no files were changed." >&2
        return 1
    fi
    FACELOCK_SOURCE_INSTALL_CRITICAL=true
    if facelock_source_install_create_barrier "$barrier_dir"; then
        barrier_status=0
    else
        barrier_status=$?
    fi
    FACELOCK_SOURCE_INSTALL_CRITICAL=false

    if [ "$FACELOCK_SOURCE_INSTALL_DEFERRED_SIGNAL" -ne 0 ]; then
        return "$FACELOCK_SOURCE_INSTALL_DEFERRED_SIGNAL"
    fi
    if [ "$barrier_status" -ne 0 ]; then
        echo "Error: could not establish a runtime activation barrier; no files were changed." >&2
        return 1
    fi
    if ! facelock_source_install_retry systemctl daemon-reload; then
        echo "Error: could not load the temporary activation barrier after 3 attempts; no files were changed." >&2
        return 1
    fi
    if ! facelock_source_install_physical_masks_are_current ||
        ! facelock_source_install_owned_barrier_is_current ||
        ! facelock_source_install_unit_is_owned_barrier "$active_state"; then
        echo "Error: the temporary activation barrier was not the exact effective unit before stop; no files were changed." >&2
        return 1
    fi

    if ! systemctl stop facelock-daemon.service; then
        echo "Error: could not stop facelock-daemon.service; no files were changed." >&2
        return 1
    fi
    FACELOCK_SOURCE_INSTALL_STOP_SUCCEEDED=true
    if ! facelock_source_install_unit_is_owned_barrier inactive; then
        echo "Error: the activation barrier could not be reconciled before source-install writes; no files were changed." >&2
        return 1
    fi
    if ! facelock_source_install_physical_masks_are_current ||
        ! facelock_source_install_owned_barrier_is_current ||
        ! facelock_source_install_dbus_owner_is false ||
        ! facelock_source_install_dbus_config_is_standard "$layout_prefix" || {
        if [ "$loaded_unit" = true ] ||
            [ "$FACELOCK_SOURCE_INSTALL_HAS_PHYSICAL_MASK" = true ]; then
            ! facelock_source_install_dbus_definition_is_safe
        else
            ! facelock_source_install_dbus_definition_is_absent
        fi
    }; then
        echo "Error: the activation barrier could not be reconciled before source-install writes; no files were changed." >&2
        return 1
    fi
    FACELOCK_SOURCE_INSTALL_PREPARED=true
}

facelock_source_install_restore_daemon() {
    local systemd_runtime_dir="${1:-/run/systemd/system}"
    local publication_allowed="${2:-false}"
    local restore_status=0
    local dbus_activation_safe=true
    local expected_active_state=inactive
    local expected_owner=false
    local barrier_retired=false

    if [ "$FACELOCK_SOURCE_INSTALL_STOP_SUCCEEDED" != true ] &&
        [ "$FACELOCK_SOURCE_INSTALL_DAEMON_WAS_ACTIVE" = true ]; then
        expected_active_state=active
        expected_owner=true
    fi

    if [ -d "$systemd_runtime_dir" ] && {
        [ "$FACELOCK_SOURCE_INSTALL_PREPARED" = true ] ||
            [ "$FACELOCK_SOURCE_INSTALL_BARRIER_CREATED" = true ] ||
            [ "$FACELOCK_SOURCE_INSTALL_BARRIER_DIR_CREATED" = true ];
    }; then
        if ! facelock_source_install_retry systemctl daemon-reload; then
            echo "Error: could not reload systemd after 3 attempts." >&2
            dbus_activation_safe=false
            restore_status=1
        fi
        if [ "$FACELOCK_SOURCE_INSTALL_LEGACY_RECONCILIATION_FAILED" = true ]; then
            echo "Error: an ambiguous legacy migration prefix could not be reconciled; the activation barrier was retained." >&2
            dbus_activation_safe=false
            restore_status=1
        fi
        if ! facelock_source_install_physical_masks_are_current ||
            ! facelock_source_install_control_topology_is_current ||
            ! facelock_source_install_dbus_config_is_standard \
            "$FACELOCK_SOURCE_INSTALL_DBUS_LAYOUT_PREFIX" ||
            ! facelock_source_install_expected_dbus_definition_is_current ||
            ! facelock_source_install_retry \
                facelock_source_install_reload_dbus_activation ||
            ! facelock_source_install_dbus_config_is_standard \
                "$FACELOCK_SOURCE_INSTALL_DBUS_LAYOUT_PREFIX" ||
            ! facelock_source_install_expected_dbus_definition_is_current ||
            { [ "$FACELOCK_SOURCE_INSTALL_BARRIER_CREATED" = true ] &&
                ! facelock_source_install_unit_is_owned_barrier \
                    "$expected_active_state"; } ||
            ! facelock_source_install_dbus_owner_is "$expected_owner" ||
            { [ "$FACELOCK_SOURCE_INSTALL_BARRIER_CREATED" = true ] &&
                ! facelock_source_install_owned_barrier_is_current; }; then
            echo "Error: could not safely reconcile the masked D-Bus activation state." >&2
            dbus_activation_safe=false
            restore_status=1
        fi
        if [ "$dbus_activation_safe" = true ] &&
            [ "$FACELOCK_SOURCE_INSTALL_LEGACY_MIGRATION_RECORDED" = true ] &&
            [ "$FACELOCK_SOURCE_INSTALL_LEGACY_MIGRATION_COMMITTED" = false ]; then
            if [ "$publication_allowed" != true ]; then
                echo "Error: staged legacy system assets were not eligible for publication; the activation barrier was retained." >&2
                dbus_activation_safe=false
                restore_status=1
            elif [ "$FACELOCK_SOURCE_INSTALL_DEFERRED_SIGNAL" -ne 0 ]; then
                if ! facelock_source_install_rollback_legacy_migration; then
                    echo "Error: could not roll back staged legacy system assets after a deferred signal." >&2
                fi
                dbus_activation_safe=false
                restore_status=1
            elif ! facelock_source_install_commit_legacy_migration; then
                echo "Error: could not publish staged legacy-system-asset retirement while activation remained barred." >&2
                if facelock_source_install_rollback_legacy_migration; then
                    if ! facelock_source_install_retry systemctl daemon-reload ||
                        ! facelock_source_install_physical_masks_are_current ||
                        ! facelock_source_install_control_topology_is_current ||
                        ! facelock_source_install_retry \
                            facelock_source_install_reload_dbus_activation ||
                        ! facelock_source_install_dbus_config_is_standard \
                            "$FACELOCK_SOURCE_INSTALL_DBUS_LAYOUT_PREFIX" ||
                        ! facelock_source_install_expected_dbus_definition_is_current ||
                        { [ "$FACELOCK_SOURCE_INSTALL_BARRIER_CREATED" = true ] &&
                            ! facelock_source_install_unit_is_owned_barrier \
                                "$expected_active_state"; } ||
                        ! facelock_source_install_dbus_owner_is "$expected_owner" ||
                        { [ "$FACELOCK_SOURCE_INSTALL_BARRIER_CREATED" = true ] &&
                            ! facelock_source_install_owned_barrier_is_current; }; then
                        echo "Error: rolled-back legacy system assets could not be reloaded and proved while activation remained barred." >&2
                    fi
                else
                    echo "Error: migration publication failed and rollback was incomplete; the activation barrier was retained." >&2
                fi
                dbus_activation_safe=false
                restore_status=1
            elif ! facelock_source_install_physical_masks_are_current ||
                ! facelock_source_install_control_topology_is_current ||
                ! facelock_source_install_dbus_config_is_standard \
                    "$FACELOCK_SOURCE_INSTALL_DBUS_LAYOUT_PREFIX" ||
                ! facelock_source_install_expected_dbus_definition_is_current ||
                { [ "$FACELOCK_SOURCE_INSTALL_BARRIER_CREATED" = true ] &&
                    ! facelock_source_install_unit_is_owned_barrier \
                        "$expected_active_state"; } ||
                ! facelock_source_install_dbus_owner_is "$expected_owner"; then
                echo "Error: published legacy-system-asset retirement changed before barrier removal." >&2
                dbus_activation_safe=false
                restore_status=1
            fi
        fi
        if [ "$dbus_activation_safe" = true ] &&
            [ "$FACELOCK_SOURCE_INSTALL_BARRIER_CREATED" = true ]; then
            if ! facelock_source_install_physical_masks_are_current ||
                ! facelock_source_install_control_topology_is_current; then
                echo "Error: an ordinary administrative unit changed immediately before barrier removal." >&2
                dbus_activation_safe=false
                restore_status=1
            elif ! facelock_source_install_retry \
                facelock_source_install_quarantine_owned_barrier; then
                echo "Error: could not quarantine the temporary activation barrier after 3 attempts." >&2
                dbus_activation_safe=false
                restore_status=1
            elif ! facelock_source_install_physical_masks_are_current ||
                ! facelock_source_install_control_topology_is_current; then
                echo "Error: an ordinary administrative unit changed while the barrier was quarantined." >&2
                dbus_activation_safe=false
                restore_status=1
                if ! facelock_source_install_recover_owned_barrier; then
                    echo "Error: could not recover the manager-effective activation barrier." >&2
                fi
            elif ! facelock_source_install_retry systemctl daemon-reload; then
                echo "Error: could not reload systemd after quarantining the activation barrier." >&2
                dbus_activation_safe=false
                restore_status=1
                if ! facelock_source_install_recover_owned_barrier; then
                    echo "Error: could not recover the manager-effective activation barrier." >&2
                fi
            elif ! facelock_source_install_post_removal_state_is_safe \
                "$expected_active_state" "$expected_owner"; then
                echo "Error: the post-removal manager or D-Bus state was not exact." >&2
                dbus_activation_safe=false
                restore_status=1
                if ! facelock_source_install_recover_owned_barrier; then
                    echo "Error: could not recover the manager-effective activation barrier." >&2
                fi
            elif facelock_source_install_retry \
                facelock_source_install_remove_quarantined_barrier; then
                FACELOCK_SOURCE_INSTALL_BARRIER_CREATED=false
                barrier_retired=true
            else
                echo "Error: could not remove the quarantined activation barrier after 3 attempts." >&2
                dbus_activation_safe=false
                restore_status=1
                if ! facelock_source_install_recover_owned_barrier; then
                    echo "Error: could not recover the manager-effective activation barrier." >&2
                fi
            fi
        fi
        if [ "$FACELOCK_SOURCE_INSTALL_BARRIER_CREATED" = false ] &&
            [ "$FACELOCK_SOURCE_INSTALL_BARRIER_DIR_CREATED" = true ]; then
            if facelock_source_install_remove_owned_barrier_dir; then
                FACELOCK_SOURCE_INSTALL_BARRIER_DIR_CREATED=false
            else
                echo "Error: could not remove the temporary activation-barrier directory." >&2
                dbus_activation_safe=false
                restore_status=1
            fi
        fi
        if [ "$barrier_retired" = true ] &&
            [ "$dbus_activation_safe" = true ] &&
            ! facelock_source_install_post_removal_state_is_safe \
                "$expected_active_state" "$expected_owner"; then
            echo "Error: the final manager, D-Bus, or administrator state changed before restart." >&2
            dbus_activation_safe=false
            restore_status=1
        fi
        if [ "$FACELOCK_SOURCE_INSTALL_DAEMON_WAS_ACTIVE" = true ] &&
            [ "$FACELOCK_SOURCE_INSTALL_STOP_SUCCEEDED" = true ] &&
            [ "$barrier_retired" = true ] &&
            [ "$dbus_activation_safe" = true ] &&
            [ "$FACELOCK_SOURCE_INSTALL_BARRIER_CREATED" = false ] &&
            ! facelock_source_install_restart_active_daemon; then
            echo "Error: could not restore the initially active daemon after 3 attempts." >&2
            restore_status=1
        fi
    fi

    FACELOCK_SOURCE_INSTALL_PREPARED=false
    return "$restore_status"
}

facelock_source_install_finish_daemon() {
    local original_status="$1"
    local restore_status=0
    local migration_status=0
    local publication_allowed=false
    local final_status="$original_status"

    FACELOCK_SOURCE_INSTALL_RESTORING=true
    if [ "${#FACELOCK_SOURCE_INSTALL_LEGACY_PLAN[@]}" -eq 3 ] &&
        [ "$FACELOCK_SOURCE_INSTALL_LEGACY_MIGRATION_COMMITTED" = false ] && {
        [ "$original_status" -ne 0 ] ||
            [ "$FACELOCK_SOURCE_INSTALL_DEFERRED_SIGNAL" -ne 0 ];
    }; then
        if ! facelock_source_install_rollback_legacy_migration; then
            echo "Error: could not roll back staged legacy system assets before daemon restoration." >&2
            migration_status=1
            FACELOCK_SOURCE_INSTALL_LEGACY_RECONCILIATION_FAILED=true
        fi
    fi
    if [ "$original_status" -eq 0 ] &&
        [ "$FACELOCK_SOURCE_INSTALL_DEFERRED_SIGNAL" -eq 0 ] &&
        [ "$migration_status" -eq 0 ]; then
        publication_allowed=true
    fi
    if facelock_source_install_restore_daemon \
        "$FACELOCK_SOURCE_INSTALL_SYSTEMD_RUNTIME_DIR" \
        "$publication_allowed"; then
        restore_status=0
    else
        restore_status=$?
    fi
    if [ "$FACELOCK_SOURCE_INSTALL_LEGACY_MIGRATION_RECORDED" = true ] &&
        [ "$FACELOCK_SOURCE_INSTALL_LEGACY_MIGRATION_COMMITTED" = false ]; then
        if [ -z "$FACELOCK_SOURCE_INSTALL_SYSTEMD_RUNTIME_DIR" ] &&
            [ "$original_status" -eq 0 ] &&
            [ "$FACELOCK_SOURCE_INSTALL_DEFERRED_SIGNAL" -eq 0 ] &&
            [ "$restore_status" -eq 0 ] && [ "$migration_status" -eq 0 ]; then
            if ! facelock_source_install_commit_legacy_migration; then
                echo "Error: could not publish staged offline legacy-system-asset retirement." >&2
                migration_status=1
                facelock_source_install_rollback_legacy_migration || true
            fi
        elif ! facelock_source_install_rollback_legacy_migration; then
            echo "Error: could not roll back staged legacy system assets after daemon restoration failed." >&2
            migration_status=1
        fi
    fi
    facelock_source_install_release_lock
    facelock_source_install_release_physical_mask_fds
    facelock_source_install_release_barrier_fds

    trap - EXIT HUP INT TERM
    FACELOCK_SOURCE_INSTALL_RESTORING=false
    if [ "$FACELOCK_SOURCE_INSTALL_DEFERRED_SIGNAL" -ne 0 ]; then
        final_status="$FACELOCK_SOURCE_INSTALL_DEFERRED_SIGNAL"
    elif [ "$final_status" -eq 0 ] && [ "$restore_status" -ne 0 ]; then
        final_status="$restore_status"
    elif [ "$final_status" -eq 0 ] && [ "$migration_status" -ne 0 ]; then
        final_status="$migration_status"
    fi
    return "$final_status"
}

facelock_source_install_exit_handler() {
    local original_status="$?"
    local final_status

    set +e
    facelock_source_install_finish_daemon "$original_status"
    final_status=$?
    exit "$final_status"
}

facelock_source_install_begin_daemon() {
    local status

    FACELOCK_SOURCE_INSTALL_SYSTEMD_RUNTIME_DIR="${1:-/run/systemd/system}"
    FACELOCK_SOURCE_INSTALL_DEFERRED_SIGNAL=0
    facelock_source_install_arm_daemon_restore
    if facelock_source_install_prepare_daemon "$@"; then
        return 0
    else
        status=$?
    fi

    facelock_source_install_finish_daemon "$status"
}

facelock_source_install_begin() {
    case "${FACELOCK_SOURCE_INSTALL_OFFLINE_IMAGE:-}" in
        "") facelock_source_install_begin_daemon "$@" ;;
        container-build)
            local image_root="${1:-/}"
            local status

            FACELOCK_SOURCE_INSTALL_SYSTEMD_RUNTIME_DIR=
            FACELOCK_SOURCE_INSTALL_DEFERRED_SIGNAL=0
            facelock_source_install_arm_daemon_restore
            if facelock_source_install_prepare_offline_image "$image_root"; then
                return 0
            else
                status=$?
            fi
            facelock_source_install_finish_daemon "$status"
            ;;
        *)
            echo "Error: unknown offline image mode; no files were changed." >&2
            return 1
            ;;
    esac
}

facelock_source_install_complete_daemon() {
    if [ "$#" -gt 0 ]; then
        FACELOCK_SOURCE_INSTALL_SYSTEMD_RUNTIME_DIR="$1"
    fi
    facelock_source_install_finish_daemon 0
}

facelock_source_install_complete() {
    case "${FACELOCK_SOURCE_INSTALL_OFFLINE_IMAGE:-}" in
        "") facelock_source_install_complete_daemon "$@" ;;
        container-build) facelock_source_install_finish_daemon 0 ;;
        *)
            echo "Error: unknown offline image mode." >&2
            return 1
            ;;
    esac
}
