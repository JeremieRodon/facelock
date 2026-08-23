#!/usr/bin/bash -p
set -euo pipefail
export LC_ALL=C

if [ "${1:-/}" = / ]; then
    PATH=/usr/bin:/bin
    export PATH
fi

# Source uninstall owns only the canonical package/source paths. Historical
# /etc copies are administrator state and are intentionally never inspected or
# removed here; setup's reviewed migration is their only automatic retirement.

layout_root="${1:-/}"
case "$layout_root" in
    /*) ;;
    *)
        echo "Error: system-asset layout root must be absolute; no files were changed." >&2
        exit 1
        ;;
esac
[ -d "$layout_root" ] && [ ! -L "$layout_root" ] || {
    echo "Error: system-asset layout root is not a real directory; no files were changed." >&2
    exit 1
}
layout_root="$(cd -- "$layout_root" && pwd -P)"
layout_prefix="${layout_root%/}"

if [ "$layout_root" = / ]; then
    expected_uid=0
    expected_gid=0
else
    IFS=: read -r expected_uid expected_gid < <(stat -c '%u:%g' -- "$layout_root") || {
        echo "Error: could not establish the system-asset layout owner; no files were changed." >&2
        exit 1
    }
fi

canonical_assets=(
    usr/lib/systemd/system/facelock-daemon.service \
    usr/share/dbus-1/system.d/org.facelock.Daemon.conf \
    usr/share/dbus-1/system-services/org.facelock.Daemon.service
)

layout_root_is_trusted() {
    local uid gid mode kind

    IFS=: read -r uid gid mode kind < <(
        stat -c '%u:%g:%a:%F' -- "$layout_root"
    ) || return 1
    [ "$uid" = "$expected_uid" ] &&
        [ "$gid" = "$expected_gid" ] &&
        [ "$kind" = directory ] &&
        [ "$((8#$mode & 8#022))" -eq 0 ]
}

canonical_parents_are_trusted() {
    local relative="$1"
    local parent_relative component current uid gid mode kind
    local -a parent_components

    parent_relative="${relative%/*}"
    current="$layout_root"
    IFS='/' read -r -a parent_components <<<"$parent_relative"
    for component in "${parent_components[@]}"; do
        [ -n "$component" ] && [ "$component" != . ] && [ "$component" != .. ] ||
            return 1
        current="${current%/}/$component"
        if [ ! -e "$current" ] && [ ! -L "$current" ]; then
            return 0
        fi
        IFS=: read -r uid gid mode kind < <(
            stat -c '%u:%g:%a:%F' -- "$current"
        ) || return 1
        [ "$uid" = "$expected_uid" ] &&
            [ "$gid" = "$expected_gid" ] &&
            [ "$kind" = directory ] &&
            [ "$((8#$mode & 8#022))" -eq 0 ] || return 1
    done
}

canonical_is_trusted_or_absent() {
    local relative="$1"
    local path="$layout_prefix/$relative"
    local uid gid mode links kind

    canonical_parents_are_trusted "$relative" || return 1
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then
        return 0
    fi
    IFS=: read -r uid gid mode links kind < <(
        stat -c '%u:%g:%a:%h:%F' -- "$path"
    ) || return 1
    [ "$uid" = "$expected_uid" ] &&
        [ "$gid" = "$expected_gid" ] &&
        [ "$mode" = 644 ] &&
        [ "$links" -eq 1 ] &&
        [ "$kind" = 'regular file' ]
}

failures=()
removals=()
if ! layout_root_is_trusted; then
    failures+=("system-asset layout root is linked, untrusted, or writable: $layout_root")
fi
for canonical in "${canonical_assets[@]}"; do
    canonical_path="$layout_prefix/$canonical"
    if ! canonical_is_trusted_or_absent "$canonical"; then
        failures+=("canonical asset or parent is linked, untrusted, multiply linked, or has unexpected metadata and was preserved: $canonical_path")
    elif [ -e "$canonical_path" ] || [ -L "$canonical_path" ]; then
        removals+=("$canonical_path")
    fi
done

if [ "${#failures[@]}" -ne 0 ]; then
    echo "Error: canonical system-asset validation failed; no files were changed:" >&2
    printf '  - %s\n' "${failures[@]}" >&2
    exit 1
fi

for canonical_path in "${removals[@]}"; do
    rm -- "$canonical_path"
done
