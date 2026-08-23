#!/usr/bin/env bash
set -euo pipefail

barrier=/run/systemd/system.control/facelock-daemon.service
runtime_mask=/run/systemd/system/facelock-daemon.service

if [ "$*" = 'daemon-reload' ]; then
    if [ -e /run/facelock-source-install-fail-cleanup-reload ] &&
        [ -e "$barrier" ]; then
        exit 1
    fi
    if [ -e /run/facelock-source-install-fail-final-reload ] &&
        [ ! -e "$barrier" ] && [ ! -L "$barrier" ]; then
        exit 1
    fi
    if [ -e /run/facelock-source-install-cleanup-mask-race ] &&
        [ -e "$barrier" ]; then
        rm -f -- /run/facelock-source-install-cleanup-mask-race
        ln -s /dev/null "$runtime_mask"
    fi
    if [ -e /run/facelock-source-install-definition-race ] &&
        [ -e "$barrier" ]; then
        rm -f -- /run/facelock-source-install-definition-race
        printf '%s\n' \
            '[D-BUS Service]' \
            'Name=org.facelock.Daemon' \
            'Exec=/usr/bin/facelock daemon' \
            'User=root' \
            >/usr/share/dbus-1/system-services/org.facelock.Daemon.service
    fi
    if [ -e /run/facelock-source-install-fragment-race ] &&
        [ -e "$barrier" ]; then
        rm -f -- /run/facelock-source-install-fragment-race
        mkdir -p /etc/systemd/system.control
        install -m600 /dev/null \
            /etc/systemd/system.control/facelock-daemon.service
    fi
    if [ -e /run/facelock-source-install-owner-race ] &&
        [ -e "$barrier" ]; then
        rm -f -- /run/facelock-source-install-owner-race
        /usr/bin/facelock daemon \
            >/run/facelock-source-install-owner-race.log 2>&1 &
        for _ in $(seq 1 50); do
            if [ "$(busctl --system call org.freedesktop.DBus \
                /org/freedesktop/DBus org.freedesktop.DBus NameHasOwner \
                s org.facelock.Daemon)" = 'b true' ]; then
                break
            fi
            sleep 0.02
        done
    fi
fi

if [ "${1:-}" = show ] &&
    [ -e /run/facelock-source-install-pre-restart-mask-race ] &&
    [ ! -e "$barrier" ] && [ ! -L "$barrier" ] &&
    ! compgen -G "$barrier.facelock-remove.*" >/dev/null; then
    rm -f -- /run/facelock-source-install-pre-restart-mask-race
    ln -s /dev/null "$runtime_mask"
    /usr/bin/systemctl daemon-reload
fi

if [ "$*" = 'stop facelock-daemon.service' ]; then
    fragment="$(/usr/bin/systemctl show facelock-daemon.service \
        --property=FragmentPath --value --no-pager)"
    [ "$fragment" = "$barrier" ]
    touch /run/facelock-source-install-stop-proof
fi

exec /usr/bin/systemctl "$@"
