#!/usr/bin/bash -p
set -euo pipefail
PATH=/usr/bin:/bin
export PATH

if [ "${1:-}" = -Dm755 ] && {
    [ "${2:-}" = target/release/facelock ] ||
        [ "${2:-}" = "/source-install-lifecycle/repository/target/release/facelock" ];
} &&
    [ "${3:-}" = /usr/bin/facelock ] &&
    [ -n "${FACELOCK_RECIPE_FIRST_WRITE_FAULT:-}" ] &&
    [ ! -e "${FACELOCK_RECIPE_FIRST_WRITE_MARKER:?}" ]; then
    : >"$FACELOCK_RECIPE_FIRST_WRITE_MARKER"
    case "$FACELOCK_RECIPE_FIRST_WRITE_FAULT" in
        failure) exit 1 ;;
        HUP)
            kill -HUP "$PPID"
            exit 129
            ;;
        *) exit 98 ;;
    esac
fi

exec "${FACELOCK_RECIPE_REAL_INSTALL:-/usr/bin/install}" "$@"
