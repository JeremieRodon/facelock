#!/usr/bin/env bash
set -euo pipefail

case_name=${1:?usage: source-install-daemon-lifecycle-systemd.sh <case>}
root=/source-install-lifecycle
lifecycle=$root/scripts/source-install-daemon-lifecycle.sh
unit=/usr/lib/systemd/system/facelock-daemon.service
definition=/usr/share/dbus-1/system-services/org.facelock.Daemon.service
persistent_mask=/etc/systemd/system/facelock-daemon.service
runtime_mask=/run/systemd/system/facelock-daemon.service
persistent_control=/etc/systemd/system.control/facelock-daemon.service
runtime_control=/run/systemd/system.control/facelock-daemon.service
barrier=/run/systemd/system.control/facelock-daemon.service

fail() {
    echo "source-install real systemd ($case_name): $*" >&2
    systemctl show facelock-daemon.service --no-pager >&2 || true
    exit 1
}

owner_is() {
    local expected=$1
    [ "$(busctl --system call org.freedesktop.DBus /org/freedesktop/DBus \
        org.freedesktop.DBus NameHasOwner s org.facelock.Daemon)" = \
        "b $expected" ]
}

unit_state_is() {
    local expected_load=$1
    local expected_active=$2
    local expected_fragment=$3
    local snapshot
    snapshot="$(systemctl show facelock-daemon.service \
        --property=LoadState --property=ActiveState --property=FragmentPath \
        --no-pager)"
    [ "$snapshot" = "$(printf '%s\n' \
        "LoadState=$expected_load" \
        "ActiveState=$expected_active" \
        "FragmentPath=$expected_fragment")" ]
}

stat_mask() {
    local path=$1
    stat -c '%d:%i:%u:%g:%a:%h:%s:%F' -- "$path"
    if [ -L "$path" ]; then
        readlink -- "$path"
    fi
}

file_identity() {
    stat -c '%d:%i:%u:%g:%a:%h:%s:%F' -- "$1"
    sha256sum -- "$1" | awk '{print $1}'
}

install_test_assets() {
    install -m755 "$root/test/source-install-daemon-stub.sh" /usr/bin/facelock
    install -m644 "$root/test/source-install-daemon-test.service" "$unit"
    install -m644 "$root/dbus/org.facelock.Daemon.service" "$definition"
}

prepare_recipe_assets() {
    local repository=$root/repository

    /usr/bin/install -m755 "$root/test/source-install-daemon-stub.sh" \
        "$repository/target/release/facelock"
    /usr/bin/install -m644 /lib/security/pam_facelock.so \
        "$repository/target/release/libpam_facelock.so"
}

run_install_recipe() {
    (
        cd "$root/repository"
        /usr/bin/just --justfile "$root/repository/justfile" \
            install-files
    )
}

install_fixed_path_recipe_probes() {
    local fake_manager=${1:-false}

    if [ ! -e /usr/bin/install.facelock-real ]; then
        /usr/bin/mv /usr/bin/install /usr/bin/install.facelock-real
        /usr/bin/cp "$root/test/source-install-recipe-install-probe.sh" \
            /usr/bin/install
        /usr/bin/chmod 755 /usr/bin/install
    fi
    export FACELOCK_RECIPE_REAL_INSTALL=/usr/bin/install.facelock-real
    if [ "$fake_manager" = true ]; then
        /usr/bin/mv /usr/bin/systemctl /usr/bin/systemctl.facelock-real
        /usr/bin/mv /usr/bin/busctl /usr/bin/busctl.facelock-real
        /usr/bin/cp "$root/test/source-install-recipe-fake-systemctl.sh" \
            /usr/bin/systemctl
        /usr/bin/cp "$root/test/source-install-recipe-fake-busctl.sh" \
            /usr/bin/busctl
        /usr/bin/chmod 755 /usr/bin/systemctl /usr/bin/busctl
    fi
}

run_recipe_case() {
    local fault=${1:-}
    local first_write_marker=/run/facelock-source-install-recipe-first-write
    local binary_before expected_status status

    prepare_recipe_assets
    rm -f "$first_write_marker"
    case "$case_name" in
        recipe-known-legacy-retired)
            mkdir -p /etc/systemd/system /etc/dbus-1/system.d \
                /etc/dbus-1/system-services
            /usr/bin/install -m644 \
                "$root/repository/systemd/facelock-daemon.service" \
                "$persistent_mask"
            /usr/bin/install -m644 \
                "$root/repository/dbus/org.facelock.Daemon.conf" \
                /etc/dbus-1/system.d/org.facelock.Daemon.conf
            /usr/bin/install -m644 \
                "$root/repository/dbus/org.facelock.Daemon.service" \
                /etc/dbus-1/system-services/org.facelock.Daemon.service
            systemctl daemon-reload
            systemctl start facelock-daemon.service
            owner_is true || fail "known-legacy oracle did not own its D-Bus name"
            install_fixed_path_recipe_probes false
            run_install_recipe || fail "known-legacy actual install-files recipe failed"
            for path in \
                "$persistent_mask" \
                /etc/dbus-1/system.d/org.facelock.Daemon.conf \
                /etc/dbus-1/system-services/org.facelock.Daemon.service \
                /etc/systemd/system/.facelock-migrate-systemd-unit \
                /etc/dbus-1/system.d/.facelock-migrate-dbus-policy \
                /etc/dbus-1/system-services/.facelock-migrate-dbus-activation; do
                [ ! -e "$path" ] && [ ! -L "$path" ] ||
                    fail "known-legacy recipe retained $path"
            done
            systemctl is-active --quiet facelock-daemon.service ||
                fail "known-legacy recipe did not restore the active daemon"
            owner_is true || fail "known-legacy recipe did not restore the D-Bus owner"
            ;;
        recipe-admin-overrides-preserved | recipe-fake-manager-overrides-preserved)
            if [ "$case_name" = recipe-fake-manager-overrides-preserved ]; then
                export FACELOCK_RECIPE_FAKE_STATE_DIR=/run/facelock-recipe-fake-manager
                mkdir -p "$FACELOCK_RECIPE_FAKE_STATE_DIR"
                printf '%s\n' active >"$FACELOCK_RECIPE_FAKE_STATE_DIR/active-state"
            fi
            mkdir -p /etc/systemd/system /etc/dbus-1/system.d \
                /etc/dbus-1/system-services
            {
                cat "$root/test/source-install-daemon-test.service"
                printf '%s\n' '# historical administrator unit'
            } >"$persistent_mask"
            {
                cat "$root/dbus/org.facelock.Daemon.service"
                printf '%s\n' '# historical administrator activation definition'
            } >/etc/dbus-1/system-services/org.facelock.Daemon.service
            printf '%s\n' \
                '<busconfig>' \
                '  <policy user="root"><allow own="org.facelock.Daemon"/></policy>' \
                '  <policy context="default"><allow send_destination="org.facelock.Daemon"/></policy>' \
                '  <!-- historical administrator policy -->' \
                '</busconfig>' >/etc/dbus-1/system.d/org.facelock.Daemon.conf
            chmod 0644 "$persistent_mask" \
                /etc/dbus-1/system-services/org.facelock.Daemon.service \
                /etc/dbus-1/system.d/org.facelock.Daemon.conf
            unit_before="$(file_identity "$persistent_mask")"
            definition_before="$(file_identity \
                /etc/dbus-1/system-services/org.facelock.Daemon.service)"
            policy_before="$(file_identity \
                /etc/dbus-1/system.d/org.facelock.Daemon.conf)"
            if [ "$case_name" = recipe-admin-overrides-preserved ]; then
                systemctl daemon-reload
                systemctl start facelock-daemon.service
                install_fixed_path_recipe_probes false
            else
                install_fixed_path_recipe_probes true
            fi
            run_install_recipe || fail "actual install-files recipe failed"
            [ "$(file_identity "$persistent_mask")" = "$unit_before" ] ||
                fail "actual recipe changed the historical administrator unit"
            [ "$(file_identity /etc/dbus-1/system-services/org.facelock.Daemon.service)" = \
                "$definition_before" ] ||
                fail "actual recipe changed the historical D-Bus definition"
            [ "$(file_identity /etc/dbus-1/system.d/org.facelock.Daemon.conf)" = \
                "$policy_before" ] ||
                fail "actual recipe changed the historical D-Bus policy"
            cmp -s "$root/repository/systemd/facelock-daemon.service" "$unit" ||
                fail "actual recipe did not install the canonical /usr unit"
            cmp -s "$root/repository/dbus/org.facelock.Daemon.service" \
                "$definition" ||
                fail "actual recipe did not install the canonical /usr D-Bus definition"
            if [ "$case_name" = recipe-admin-overrides-preserved ]; then
                systemctl is-active --quiet facelock-daemon.service ||
                    fail "actual recipe did not restore the active daemon"
                owner_is true || fail "actual recipe did not restore the D-Bus owner"
            else
                [ "$(cat "$FACELOCK_RECIPE_FAKE_STATE_DIR/active-state")" = active ] ||
                    fail "fake-manager recipe did not restore the active state"
            fi
            ;;
        recipe-locale-failure-retry)
            # A translation msgfmt rejects fails the recipe mid-window, after
            # the first asset writes but before the activation assets. The
            # recipe must fail loudly, ship no catalog, lift the activation
            # barrier, and restore the initially active daemon — never leave
            # the unit masked.
            command -v msgfmt >/dev/null ||
                fail "locale-failure case needs msgfmt in the image"
            systemctl start facelock-daemon.service
            owner_is true || fail "locale-failure oracle did not own its D-Bus name"
            mkdir -p "$root/repository/po/zz"
            printf '%s\n' \
                'msgid ""' \
                'msgstr ""' \
                '"Content-Type: text/plain; charset=UTF-8\n"' \
                '' \
                '#, python-brace-format' \
                'msgid "Authenticating {user}"' \
                'msgstr "Authenticating {typoed_placeholder}"' \
                >"$root/repository/po/zz/facelock.po"
            unit_before="$(file_identity "$unit")"
            set +e
            recipe_output="$(run_install_recipe 2>&1)"
            status=$?
            set -e
            printf '%s\n' "$recipe_output" >&2
            [ "$status" -eq 1 ] ||
                fail "broken-translation recipe exited $status, expected 1"
            # The msgfmt failure in the output is what proves the recipe died
            # at the locale step inside the install window. A reinstalled
            # /usr/bin/facelock cannot prove it: install recreates the stub
            # with identical content, owner, mode and size, and the freed
            # inode number can be recycled, so its identity may not change.
            printf '%s\n' "$recipe_output" |
                grep -Fq 'msgfmt: found 1 fatal error' ||
                fail "broken-translation recipe did not fail at msgfmt"
            [ "$(file_identity "$unit")" = "$unit_before" ] ||
                fail "broken-translation recipe reached past the locale step"
            [ ! -e /usr/share/locale/zz ] ||
                fail "broken-translation recipe left a rejected catalog installed"
            [ ! -e "$barrier" ] && [ ! -L "$barrier" ] ||
                fail "broken-translation recipe left the barrier installed"
            unit_state_is loaded active "$unit" ||
                fail "broken-translation recipe left the unit masked or inactive"
            owner_is true ||
                fail "broken-translation recipe did not restore the D-Bus owner"
            rm -rf "$root/repository/po/zz"
            run_install_recipe || fail "retry after the broken translation failed"
            cmp -s "$root/repository/systemd/facelock-daemon.service" "$unit" ||
                fail "retry after the broken translation missed the /usr unit"
            systemctl is-active --quiet facelock-daemon.service ||
                fail "retry after the broken translation did not restore the active daemon"
            owner_is true ||
                fail "retry after the broken translation did not restore the D-Bus owner"
            ;;
        recipe-first-install-failure-retry | recipe-first-install-hup-retry)
            rm -f "$unit" "$definition" "$persistent_mask" \
                /etc/dbus-1/system-services/org.facelock.Daemon.service \
                /etc/dbus-1/system.d/org.facelock.Daemon.conf
            systemctl daemon-reload
            unit_state_is not-found inactive '' ||
                fail "first-install recipe oracle was not absent"
            binary_before="$(file_identity /usr/bin/facelock)"
            set +e
            export FACELOCK_RECIPE_FIRST_WRITE_FAULT="$fault"
            export FACELOCK_RECIPE_FIRST_WRITE_MARKER="$first_write_marker"
            install_fixed_path_recipe_probes false
            run_install_recipe
            status=$?
            set -e
            unset FACELOCK_RECIPE_FIRST_WRITE_FAULT \
                FACELOCK_RECIPE_FIRST_WRITE_MARKER
            case "$fault" in
                failure) expected_status=1 ;;
                HUP) expected_status=129 ;;
                *) fail "unknown first-write fault $fault" ;;
            esac
            [ "$status" -eq "$expected_status" ] ||
                fail "first-write $fault exited $status, expected $expected_status"
            [ -e "$first_write_marker" ] ||
                fail "first-write $fault did not reach the injected boundary"
            [ "$(file_identity /usr/bin/facelock)" = "$binary_before" ] ||
                fail "first-write $fault changed the first asset"
            [ ! -e "$unit" ] && [ ! -e "$definition" ] ||
                fail "first-write $fault reached a later activation asset"
            [ ! -e "$barrier" ] && [ ! -L "$barrier" ] ||
                fail "first-write $fault left the barrier installed"
            unit_state_is not-found inactive '' ||
                fail "first-write $fault did not restore the absent manager state"
            owner_is false || fail "first-write $fault acquired the D-Bus name"
            run_install_recipe || fail "retry after first-write $fault failed"
            cmp -s "$root/repository/systemd/facelock-daemon.service" "$unit" ||
                fail "retry after first-write $fault missed the /usr unit"
            cmp -s "$root/repository/dbus/org.facelock.Daemon.service" \
                "$definition" ||
                fail "retry after first-write $fault missed the D-Bus definition"
            ! systemctl is-active --quiet facelock-daemon.service ||
                fail "retry after first-write $fault activated an initially absent daemon"
            owner_is false ||
                fail "retry after first-write $fault acquired the D-Bus name"
            ;;
    esac
    [ ! -e "$barrier" ] && [ ! -L "$barrier" ] ||
        fail "actual recipe left its barrier installed"
    flock -n /run/facelock/lifecycle.lock true ||
        fail "actual recipe left the lifecycle lock held"
    [ "$(stat -c '%U:%G:%a:%F' /run/facelock)" = \
        'root:root:755:directory' ] ||
        fail "actual recipe left an unsafe canonical lifecycle lock directory"
    [ "$(stat -c '%U:%G:%a:%h:%s:%F' /run/facelock/lifecycle.lock)" = \
        'root:root:600:1:0:regular empty file' ] ||
        fail "actual recipe left an unsafe canonical lifecycle lock"
}

make_mask() {
    local path=$1
    local kind=$2
    mkdir -p "${path%/*}"
    case "$kind" in
        symlink) ln -s /dev/null "$path" ;;
        regular) install -m644 /dev/null "$path" ;;
        *) fail "unknown mask kind $kind" ;;
    esac
}

pin_inactive_loaded_unit() {
    local enabled_state
    printf '%s\n' \
        '[Unit]' \
        'Wants=facelock-daemon.service' \
        'After=facelock-daemon.service' \
        > /run/systemd/system/facelock-source-pin.target
    systemctl daemon-reload
    systemctl start facelock-source-pin.target
    systemctl stop facelock-daemon.service
    [ "$(systemctl show facelock-daemon.service \
        --property=LoadState --value --no-pager)" = loaded ] &&
        [ "$(systemctl show facelock-daemon.service \
            --property=ActiveState --value --no-pager)" = inactive ] &&
        [ "$(systemctl show facelock-daemon.service \
            --property=UnitFileState --value --no-pager)" = static ] &&
        [ "$(systemctl show facelock-daemon.service \
            --property=FragmentPath --value --no-pager)" = "$unit" ] ||
        fail "could not pin the loaded/inactive oracle"
    enabled_state="$(systemctl is-enabled facelock-daemon.service 2>/dev/null || true)"
    [ "$enabled_state" = static ] || fail "pinned oracle was not initially static"
}

assert_stale_mask_oracle() {
    local expected_enabled=$1
    local enabled_state
    [ "$(systemctl show facelock-daemon.service \
        --property=LoadState --value --no-pager)" = loaded ] &&
        [ "$(systemctl show facelock-daemon.service \
            --property=ActiveState --value --no-pager)" = inactive ] &&
        [ "$(systemctl show facelock-daemon.service \
            --property=UnitFileState --value --no-pager)" = static ] &&
        [ "$(systemctl show facelock-daemon.service \
            --property=FragmentPath --value --no-pager)" = "$unit" ] ||
        fail "mask unexpectedly changed the cached unit"
    enabled_state="$(systemctl is-enabled facelock-daemon.service 2>/dev/null || true)"
    [ "$enabled_state" = "$expected_enabled" ] ||
        fail "disk mask did not have expected enablement state $expected_enabled"
}

install_test_assets
rm -f "$persistent_mask" "$runtime_mask" "$persistent_control" \
    "$runtime_control" /run/facelock-source-install-stop-proof
systemctl daemon-reload
systemctl stop facelock-daemon.service
owner_is false || fail "daemon owned the bus before setup"

case "$case_name" in
    recipe-known-legacy-retired | recipe-admin-overrides-preserved | \
        recipe-fake-manager-overrides-preserved | recipe-locale-failure-retry)
        run_recipe_case
        echo "source-install real systemd ($case_name): OK"
        exit 0
        ;;
    recipe-first-install-failure-retry)
        run_recipe_case failure
        echo "source-install real systemd ($case_name): OK"
        exit 0
        ;;
    recipe-first-install-hup-retry)
        run_recipe_case HUP
        echo "source-install real systemd ($case_name): OK"
        exit 0
        ;;
esac

expected_success=true
expected_cleanup_success=true
initial_active=false
expected_final_fragment=$unit
cleanup_fault=
case "$case_name" in
    unmasked-active)
        systemctl start facelock-daemon.service
        initial_active=true
        ;;
    unmasked-inactive) ;;
    first-install)
        rm -f "$unit" "$definition"
        systemctl daemon-reload
        ;;
    persistent-symlink-mask)
        make_mask "$persistent_mask" symlink
        systemctl daemon-reload
        expected_final_fragment=$persistent_mask
        ;;
    persistent-regular-mask)
        make_mask "$persistent_mask" regular
        systemctl daemon-reload
        expected_final_fragment=$persistent_mask
        ;;
    runtime-symlink-mask)
        make_mask "$runtime_mask" symlink
        systemctl daemon-reload
        expected_final_fragment=$runtime_mask
        ;;
    runtime-regular-mask)
        make_mask "$runtime_mask" regular
        systemctl daemon-reload
        expected_final_fragment=$runtime_mask
        ;;
    both-masks)
        make_mask "$persistent_mask" symlink
        make_mask "$runtime_mask" regular
        systemctl daemon-reload
        expected_final_fragment=$persistent_mask
        ;;
    stale-persistent-mask)
        pin_inactive_loaded_unit
        make_mask "$persistent_mask" symlink
        assert_stale_mask_oracle masked
        expected_final_fragment=$persistent_mask
        ;;
    stale-runtime-mask)
        pin_inactive_loaded_unit
        make_mask "$runtime_mask" regular
        assert_stale_mask_oracle masked-runtime
        expected_final_fragment=$runtime_mask
        ;;
    persistent-override-runtime-mask)
        install -m644 "$root/test/source-install-daemon-test.service" \
            "$persistent_mask"
        make_mask "$runtime_mask" symlink
        systemctl daemon-reload
        expected_final_fragment=$persistent_mask
        ;;
    persistent-mask-runtime-override)
        make_mask "$persistent_mask" symlink
        install -m644 "$root/test/source-install-daemon-test.service" \
            "$runtime_mask"
        systemctl daemon-reload
        expected_final_fragment=$persistent_mask
        ;;
    active-stale-mask-refused)
        systemctl start facelock-daemon.service
        make_mask "$persistent_mask" symlink
        expected_success=false
        initial_active=true
        ;;
    active-effective-mask-refused)
        systemctl start facelock-daemon.service
        make_mask "$runtime_mask" symlink
        systemctl daemon-reload
        expected_success=false
        initial_active=true
        ;;
    manager-disk-mismatch-refused)
        pin_inactive_loaded_unit
        make_mask "$persistent_mask" symlink
        systemctl daemon-reload
        unit_state_is masked inactive "$persistent_mask" ||
            fail "manager did not load the persistent mismatch oracle"
        [ "$(systemctl show facelock-daemon.service \
            --property=UnitFileState --value --no-pager)" = masked ] ||
            fail "persistent mismatch oracle had the wrong unit-file state"
        rm -f "$persistent_mask"
        unit_state_is masked inactive "$persistent_mask" ||
            fail "manager discarded the mismatch oracle after unlink"
        [ "$(systemctl show facelock-daemon.service \
            --property=UnitFileState --value --no-pager)" = masked ] ||
            fail "unlinked mismatch oracle had the wrong unit-file state"
        expected_success=false
        ;;
    persistent-control-conflict)
        mkdir -p "${persistent_control%/*}"
        : >"$persistent_control"
        chmod 600 "$persistent_control"
        expected_success=false
        ;;
    runtime-control-conflict)
        mkdir -p "${runtime_control%/*}"
        : >"$runtime_control"
        chmod 600 "$runtime_control"
        expected_success=false
        ;;
    cleanup-initial-reload-failure)
        systemctl start facelock-daemon.service
        initial_active=true
        expected_cleanup_success=false
        cleanup_fault=fail-cleanup-reload
        ;;
    cleanup-final-reload-failure)
        systemctl start facelock-daemon.service
        initial_active=true
        expected_cleanup_success=false
        cleanup_fault=fail-final-reload
        ;;
    cleanup-mask-race)
        systemctl start facelock-daemon.service
        initial_active=true
        expected_cleanup_success=false
        cleanup_fault=cleanup-mask-race
        ;;
    cleanup-definition-race)
        systemctl start facelock-daemon.service
        initial_active=true
        expected_cleanup_success=false
        cleanup_fault='definition-race'
        ;;
    cleanup-fragment-race)
        systemctl start facelock-daemon.service
        initial_active=true
        expected_cleanup_success=false
        cleanup_fault='fragment-race'
        ;;
    cleanup-owner-race)
        systemctl start facelock-daemon.service
        initial_active=true
        expected_cleanup_success=false
        cleanup_fault='owner-race'
        ;;
    cleanup-pre-restart-mask-race)
        systemctl start facelock-daemon.service
        initial_active=true
        expected_cleanup_success=false
        cleanup_fault=pre-restart-mask-race
        ;;
    *) fail "unknown case" ;;
esac

persistent_before=absent
runtime_before=absent
persistent_control_before=absent
runtime_control_before=absent
[ ! -e "$persistent_mask" ] && [ ! -L "$persistent_mask" ] ||
    persistent_before="$(stat_mask "$persistent_mask")"
[ ! -e "$runtime_mask" ] && [ ! -L "$runtime_mask" ] ||
    runtime_before="$(stat_mask "$runtime_mask")"
[ ! -e "$persistent_control" ] && [ ! -L "$persistent_control" ] ||
    persistent_control_before="$(stat_mask "$persistent_control")"
[ ! -e "$runtime_control" ] && [ ! -L "$runtime_control" ] ||
    runtime_control_before="$(stat_mask "$runtime_control")"

# shellcheck source=scripts/source-install-daemon-lifecycle.sh
source "$lifecycle"
export PATH="$root/test/bin:$PATH"
if [ "$expected_success" = false ]; then
    set +e
    facelock_source_install_begin_daemon /run/systemd/system "$unit" \
        "$definition" "$persistent_mask" "$runtime_mask"
    status=$?
    set -e
    [ "$status" -ne 0 ] || fail "unsafe state was admitted"
    [ "$initial_active" != true ] || owner_is true ||
        fail "refusal stopped the initially active daemon"
    if [ "$runtime_control_before" = absent ]; then
        [ ! -e "$runtime_control" ] && [ ! -L "$runtime_control" ] ||
            fail "refusal left an owned barrier"
    else
        [ "$(stat_mask "$runtime_control")" = \
            "$runtime_control_before" ] ||
            fail "refusal changed the runtime control conflict"
    fi
    if [ "$persistent_control_before" = absent ]; then
        [ ! -e "$persistent_control" ] && [ ! -L "$persistent_control" ] ||
            fail "refusal created a persistent control unit"
    else
        [ "$(stat_mask "$persistent_control")" = \
            "$persistent_control_before" ] ||
            fail "refusal changed the persistent control conflict"
    fi
    exit 0
fi

facelock_source_install_begin_daemon /run/systemd/system "$unit" \
    "$definition" "$persistent_mask" "$runtime_mask"
unit_state_is masked inactive "$barrier" ||
    fail "owned barrier was not exact and inactive after stop"
owner_is false || fail "daemon retained its bus name before writes"
if [ "$initial_active" = true ]; then
    [ -e /run/facelock-source-install-stop-proof ] ||
        fail "stop probe did not observe the owned fragment"
fi
if systemctl start facelock-daemon.service; then
    fail "direct activation crossed the barrier"
fi
if busctl --system call org.freedesktop.DBus /org/freedesktop/DBus \
    org.freedesktop.DBus StartServiceByName su org.facelock.Daemon 0; then
    fail "D-Bus activation crossed the barrier"
fi
systemctl daemon-reload
unit_state_is masked inactive "$barrier" ||
    fail "extra reload displaced the owned barrier"
if systemctl start facelock-daemon.service; then
    fail "direct activation crossed the reloaded barrier"
fi
owner_is false || fail "D-Bus owner appeared while barrier was loaded"
if busctl --system call org.freedesktop.DBus /org/freedesktop/DBus \
    org.freedesktop.DBus StartServiceByName su org.facelock.Daemon 0; then
    fail "D-Bus activation crossed the reloaded barrier"
fi

if [ "$case_name" = first-install ]; then
    install -m644 "$root/test/source-install-daemon-test.service" "$unit"
    install -m644 "$root/dbus/org.facelock.Daemon.service" "$definition"
fi
if [ -n "$cleanup_fault" ]; then
    : >"/run/facelock-source-install-$cleanup_fault"
fi
if [ "$expected_cleanup_success" = true ]; then
    facelock_source_install_complete_daemon /run/systemd/system
else
    set +e
    facelock_source_install_complete_daemon /run/systemd/system
    status=$?
    set -e
    [ "$status" -ne 0 ] || fail "unsafe cleanup state was accepted"
    ! systemctl is-active --quiet facelock-daemon.service ||
        fail "cleanup failure restarted the initially active daemon"
    case "$case_name" in
        cleanup-initial-reload-failure | cleanup-final-reload-failure | \
            cleanup-mask-race | cleanup-definition-race | cleanup-owner-race)
            unit_state_is masked inactive "$barrier" ||
                fail "cleanup failure did not retain the owned manager barrier"
            ;;
        cleanup-fragment-race)
            [ -f "$persistent_control" ] && [ ! -s "$persistent_control" ] ||
                fail "cleanup changed the concurrent persistent control unit"
            unit_state_is masked inactive "$persistent_control" ||
                fail "cleanup fragment race did not retain the foreign winner"
            ;;
        cleanup-pre-restart-mask-race)
            [ ! -e "$barrier" ] && [ ! -L "$barrier" ] ||
                fail "last-window race recreated a retired barrier"
            [ -L "$runtime_mask" ] &&
                [ "$(readlink -- "$runtime_mask")" = /dev/null ] ||
                fail "cleanup changed the concurrent runtime mask"
            unit_state_is masked inactive "$runtime_mask" ||
                fail "last-window race did not retain the administrator mask"
            ;;
    esac
    if [ "$case_name" = cleanup-owner-race ]; then
        owner_is true || fail "owner-race fixture did not retain its direct owner"
    else
        owner_is false || fail "cleanup failure activated the daemon bus name"
    fi
    exit 0
fi

[ ! -e "$barrier" ] && [ ! -L "$barrier" ] ||
    fail "owned barrier remained after completion"
if [ "$persistent_before" != absent ]; then
    [ "$(stat_mask "$persistent_mask")" = "$persistent_before" ] ||
        fail "persistent mask identity changed"
fi
if [ "$runtime_before" != absent ]; then
    [ "$(stat_mask "$runtime_mask")" = "$runtime_before" ] ||
        fail "runtime mask identity changed"
fi
if [ "$initial_active" = true ]; then
    systemctl is-active --quiet facelock-daemon.service ||
        fail "initially active daemon was not restored"
    owner_is true || fail "restored daemon did not own its bus name"
else
    ! systemctl is-active --quiet facelock-daemon.service ||
        fail "initially inactive daemon was activated"
    owner_is false || fail "inactive daemon acquired its bus name"
fi
expected_final_load=loaded
if [ -L "$expected_final_fragment" ] || {
    [ -f "$expected_final_fragment" ] && [ ! -s "$expected_final_fragment" ];
}; then
    expected_final_load=masked
fi
unit_state_is "$expected_final_load" \
    "$([ "$initial_active" = true ] && printf active || printf inactive)" \
    "$expected_final_fragment" || fail "final manager winner/state was wrong"

echo "source-install real systemd ($case_name): OK"
