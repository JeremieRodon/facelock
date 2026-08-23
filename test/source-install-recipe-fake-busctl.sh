#!/usr/bin/bash -p
set -euo pipefail
PATH=/usr/bin:/bin
export PATH

case "$*" in
    *' ReloadConfig') ;;
    *' NameHasOwner s org.facelock.Daemon')
        if [ "$(cat "${FACELOCK_RECIPE_FAKE_STATE_DIR:?}/active-state")" = active ]; then
            printf '%s\n' 'b true'
        else
            printf '%s\n' 'b false'
        fi
        ;;
    *) exit 2 ;;
esac
