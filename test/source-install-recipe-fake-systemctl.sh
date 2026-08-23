#!/usr/bin/bash -p
set -euo pipefail
PATH=/usr/bin:/bin
export PATH

state_dir=${FACELOCK_RECIPE_FAKE_STATE_DIR:?}
state_file=$state_dir/active-state
barrier=/run/systemd/system.control/facelock-daemon.service

case "${1:-}" in
    show)
        case "${2:-}" in
            dbus.service)
                printf '%s\n' \
                    'Id=dbus-broker.service' \
                    'Names=dbus-broker.service dbus.service' \
                    'Following=' \
                    'LoadState=loaded' \
                    'ActiveState=active' \
                    'FragmentPath=/usr/lib/systemd/system/dbus-broker.service' \
                    'DropInPaths=' \
                    'ExecStart=/usr/bin/dbus-broker-launch --scope system'
                ;;
            facelock-daemon.service)
                active_state=$(cat "$state_file")
                if [ -e "$barrier" ]; then
                    printf 'LoadState=masked\nActiveState=%s\n' "$active_state"
                    case "$*" in
                        *--property=UnitFileState*)
                            printf '%s\n' \
                                'UnitFileState=masked-runtime' \
                                "FragmentPath=$barrier" \
                                'DropInPaths='
                            ;;
                        *) printf 'FragmentPath=%s\n' "$barrier" ;;
                    esac
                else
                    fragment=
                    for candidate in /etc/systemd/system/facelock-daemon.service \
                        /usr/lib/systemd/system/facelock-daemon.service; do
                        if [ -e "$candidate" ]; then
                            fragment=$candidate
                            break
                        fi
                    done
                    if [ -z "$fragment" ]; then
                        printf '%s\n' \
                            'LoadState=not-found' \
                            'ActiveState=inactive' \
                            'UnitFileState=' \
                            'FragmentPath=' \
                            'DropInPaths='
                    else
                        printf '%s\n' \
                            'LoadState=loaded' \
                            "ActiveState=$active_state" \
                            'UnitFileState=static' \
                            "FragmentPath=$fragment" \
                            'ExecStart=/usr/bin/facelock daemon' \
                            'DropInPaths='
                    fi
                fi
                ;;
            *) exit 2 ;;
        esac
        ;;
    daemon-reload) ;;
    stop) printf '%s\n' inactive >"$state_file" ;;
    start)
        [ ! -e "$barrier" ] || exit 1
        printf '%s\n' active >"$state_file"
        ;;
    *) exit 2 ;;
esac
