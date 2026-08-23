#!/usr/bin/bash -p
set -euo pipefail
export LC_ALL=C

# Protected source installation preserves trusted administrator variants after
# the lifecycle has proved their manager/D-Bus semantics. Standalone setup
# migration keeps the stricter all-or-nothing ambiguity refusal.
protected_source=false
if [ "${1:-}" = --source-protected ]; then
    protected_source=true
    shift
fi
stage_only=false
if [ "${1:-}" = --stage ]; then
    [ "$protected_source" = true ] || {
        echo "Error: --stage is reserved for the protected source-install lifecycle." >&2
        exit 1
    }
    stage_only=true
    shift
fi

# Production source installation is privileged. Never resolve migration tools
# through the invoking user's command path. Alternate-layout tests retain their
# injected PATH so failure and collision branches remain directly testable.
if [ "${1:-/}" = / ]; then
    PATH=/usr/bin:/bin
    export PATH
fi

# Remove only exact, reviewed Facelock copies from the three historical /etc
# paths.  Static /usr writes remain the responsibility of distro packaging and
# `just install-files`; this helper only validates those writes and retires
# historical copies that would override or duplicate them.

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
manifest="$repository_root/dist/legacy-system-assets.sha256"
layout_root="${1:-/}"

case "$layout_root" in
    /*) ;;
    *)
        echo "Error: system-asset layout root must be absolute; no legacy files were changed." >&2
        exit 1
        ;;
esac
[ -d "$layout_root" ] && [ ! -L "$layout_root" ] || {
    echo "Error: system-asset layout root is not a real directory; no legacy files were changed." >&2
    exit 1
}
layout_root="$(cd -- "$layout_root" && pwd -P)"
layout_prefix="${layout_root%/}"

[ -f "$manifest" ] && [ ! -L "$manifest" ] || {
    echo "Error: reviewed system-asset digest allowlist is missing or linked; no legacy files were changed." >&2
    exit 1
}

if [ "$layout_root" = / ]; then
    # Production is always the real system root. Tests may inject an isolated
    # layout whose owner is the root-equivalent identity for that fixture.
    expected_uid=0
    expected_gid=0
else
    IFS=: read -r expected_uid expected_gid < <(stat -c '%u:%g' -- "$layout_root") || {
        echo "Error: could not establish the system-asset layout owner; no legacy files were changed." >&2
        exit 1
    }
fi

assets=(
    'systemd-unit|systemd/facelock-daemon.service|usr/lib/systemd/system/facelock-daemon.service|etc/systemd/system/facelock-daemon.service'
    'dbus-policy|dbus/org.facelock.Daemon.conf|usr/share/dbus-1/system.d/org.facelock.Daemon.conf|etc/dbus-1/system.d/org.facelock.Daemon.conf'
    'dbus-activation|dbus/org.facelock.Daemon.service|usr/share/dbus-1/system-services/org.facelock.Daemon.service|etc/dbus-1/system-services/org.facelock.Daemon.service'
)

allowlist_contains() {
    local wanted_id="$1"
    local wanted_hash="$2"

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

parents_are_trusted() {
    local path="$1"
    local relative parent_relative component current uid gid mode kind
    local -a parent_components

    case "$layout_prefix" in
        '') relative="${path#/}" ;;
        *)
            case "$path" in
                "$layout_prefix"/*) relative="${path#"$layout_prefix"/}" ;;
                *) return 1 ;;
            esac
            ;;
    esac
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
        [ ! -L "$current" ] && [ -d "$current" ] || return 1
        IFS=: read -r uid gid mode kind < <(
            stat -c '%u:%g:%a:%F' -- "$current"
        ) || return 1
        [ "$uid" = "$expected_uid" ] &&
            [ "$gid" = "$expected_gid" ] &&
            [ "$kind" = directory ] &&
            [ "$((8#$mode & 8#022))" -eq 0 ] || return 1
    done
}

metadata_is_trusted_regular() {
    local path="$1"
    local uid gid mode links kind

    parents_are_trusted "$path" || return 1
    [ ! -L "$path" ] && [ -f "$path" ] || return 1
    IFS=: read -r uid gid mode links kind < <(
        stat -c '%u:%g:%a:%h:%F' -- "$path"
    ) || return 1
    [ "$uid" = "$expected_uid" ] &&
        [ "$gid" = "$expected_gid" ] &&
        [ "$mode" = 644 ] &&
        [ "$links" -eq 1 ] &&
        [ "$kind" = 'regular file' ]
}

metadata_is_administrator_mask() {
    local path="$1"
    local uid gid mode links size kind target

    parents_are_trusted "$path" || return 1
    IFS=: read -r uid gid mode links size kind < <(
        stat -c '%u:%g:%a:%h:%s:%F' -- "$path"
    ) || return 1
    [ "$uid" = "$expected_uid" ] && [ "$gid" = "$expected_gid" ] &&
        [ "$links" -eq 1 ] || return 1
    if [ -L "$path" ]; then
        [ "$kind" = 'symbolic link' ] || return 1
        IFS= read -r -d '' target < <(readlink -z -- "$path") || return 1
        [ "$target" = /dev/null ]
        return
    fi
    [ -f "$path" ] && [ "$kind" = 'regular empty file' ] &&
        [ "$size" -eq 0 ] && [ "$((8#$mode & 8#022))" -eq 0 ]
}

canonical_assets_are_valid() {
    local record id source_relative canonical_relative legacy_relative
    local source_path canonical_path current_hash

    layout_root_is_trusted || return 1
    for record in "${assets[@]}"; do
        IFS='|' read -r id source_relative canonical_relative legacy_relative <<<"$record"
        source_path="$repository_root/$source_relative"
        canonical_path="$layout_prefix/$canonical_relative"
        metadata_is_trusted_regular "$canonical_path" || return 1
        cmp -s -- "$source_path" "$canonical_path" || return 1
        current_hash="$(sha256sum -- "$source_path" | awk '{print $1}')"
        allowlist_contains "$id" "$current_hash" || return 1
    done
}

move_noreplace() {
    local source="$1"
    local destination="$2"

    if [ -e "$destination" ] || [ -L "$destination" ]; then
        return 1
    fi
    # GNU mv uses the kernel's no-replace operation where available. -T keeps
    # the destination an exact name; -n forbids replacement. The state check
    # catches both a concurrent collision and implementations that report a
    # no-clobber skip as success.
    mv -Tn -- "$source" "$destination" || return 1
    [ ! -e "$source" ] && [ ! -L "$source" ] &&
        { [ -e "$destination" ] || [ -L "$destination" ]; }
}

staged=()
initial_interrupted=()
stage_transaction_armed=false
stage_transaction_complete=false

rollback_staged() {
    local index record id legacy_path quarantine_path expected_hash current_hash
    local rollback_failed=0

    for ((index=${#staged[@]} - 1; index >= 0; index--)); do
        record="${staged[$index]}"
        IFS='|' read -r id legacy_path quarantine_path expected_hash <<<"$record"
        if [ -e "$legacy_path" ] || [ -L "$legacy_path" ]; then
            if [ -e "$quarantine_path" ] || [ -L "$quarantine_path" ] ||
                ! metadata_is_trusted_regular "$legacy_path"; then
                echo "Error: rollback collision preserved both names for administrator review: $legacy_path and $quarantine_path" >&2
                rollback_failed=1
                continue
            fi
            current_hash="$(sha256sum -- "$legacy_path" | awk '{print $1}')"
            if [ "$current_hash" != "$expected_hash" ] ||
                ! allowlist_contains "$id" "$current_hash"; then
                echo "Error: rollback preserved changed public bytes for administrator review: $legacy_path" >&2
                rollback_failed=1
            fi
            continue
        fi
        if ! metadata_is_trusted_regular "$quarantine_path"; then
            echo "Error: rollback preserved an untrusted quarantine for administrator review: $quarantine_path" >&2
            rollback_failed=1
            continue
        fi
        current_hash="$(sha256sum -- "$quarantine_path" | awk '{print $1}')"
        if [ "$current_hash" != "$expected_hash" ] ||
            ! allowlist_contains "$id" "$current_hash"; then
            echo "Error: rollback preserved a changed quarantine for administrator review: $quarantine_path" >&2
            rollback_failed=1
            continue
        fi
        if ! move_noreplace "$quarantine_path" "$legacy_path" ||
            ! metadata_is_trusted_regular "$legacy_path"; then
            echo "Error: rollback collision preserved both names for administrator review: $legacy_path and $quarantine_path" >&2
            rollback_failed=1
            continue
        fi
        current_hash="$(sha256sum -- "$legacy_path" | awk '{print $1}')"
        if [ "$current_hash" != "$expected_hash" ] ||
            [ -e "$quarantine_path" ] || [ -L "$quarantine_path" ]; then
            echo "Error: rollback could not prove the restored public identity: $legacy_path" >&2
            rollback_failed=1
        fi
    done
    return "$rollback_failed"
}

rollback_initial_interrupted() {
    local index record id legacy_path quarantine_path expected_hash current_hash
    local rollback_failed=0

    for ((index=${#initial_interrupted[@]} - 1; index >= 0; index--)); do
        record="${initial_interrupted[$index]}"
        IFS='|' read -r id legacy_path quarantine_path expected_hash <<<"$record"
        if [ -e "$quarantine_path" ] || [ -L "$quarantine_path" ]; then
            if [ -e "$legacy_path" ] || [ -L "$legacy_path" ] ||
                ! metadata_is_trusted_regular "$quarantine_path"; then
                echo "Error: rollback preserved an ambiguous interrupted pair: $legacy_path and $quarantine_path" >&2
                rollback_failed=1
                continue
            fi
            current_hash="$(sha256sum -- "$quarantine_path" | awk '{print $1}')"
            if [ "$current_hash" != "$expected_hash" ] ||
                ! allowlist_contains "$id" "$current_hash"; then
                echo "Error: rollback preserved a changed interrupted quarantine: $quarantine_path" >&2
                rollback_failed=1
            fi
            continue
        fi
        if ! metadata_is_trusted_regular "$legacy_path"; then
            echo "Error: rollback could not find the interrupted identity at either fixed name: $legacy_path and $quarantine_path" >&2
            rollback_failed=1
            continue
        fi
        current_hash="$(sha256sum -- "$legacy_path" | awk '{print $1}')"
        if [ "$current_hash" != "$expected_hash" ] ||
            ! allowlist_contains "$id" "$current_hash" ||
            ! move_noreplace "$legacy_path" "$quarantine_path" ||
            ! metadata_is_trusted_regular "$quarantine_path"; then
            echo "Error: rollback could not restore the interrupted quarantine: $quarantine_path" >&2
            rollback_failed=1
            continue
        fi
        current_hash="$(sha256sum -- "$quarantine_path" | awk '{print $1}')"
        if [ "$current_hash" != "$expected_hash" ] ||
            [ -e "$legacy_path" ] || [ -L "$legacy_path" ]; then
            echo "Error: rollback could not prove the interrupted quarantine identity: $quarantine_path" >&2
            rollback_failed=1
        fi
    done
    return "$rollback_failed"
}

rollback_stage_transaction() {
    local rollback_failed=0

    rollback_staged || rollback_failed=1
    rollback_initial_interrupted || rollback_failed=1
    return "$rollback_failed"
}

handle_stage_exit() {
    local status="$?"

    trap - EXIT HUP INT TERM
    if [ "$stage_transaction_complete" != true ] &&
        ! rollback_stage_transaction; then
        echo "Error: signal/exit rollback was incomplete; inspect the reported fixed paths before retrying." >&2
        status=1
    fi
    exit "$status"
}

handle_stage_signal() {
    local signal="$1"
    local status=1

    case "$signal" in
        HUP) status=129 ;;
        INT) status=130 ;;
        TERM) status=143 ;;
    esac
    exit "$status"
}

arm_stage_transaction() {
    [ "$stage_only" = true ] || return 0
    [ "$stage_transaction_armed" = false ] || return 0
    trap 'handle_stage_exit' EXIT
    trap 'handle_stage_signal HUP' HUP
    trap 'handle_stage_signal INT' INT
    trap 'handle_stage_signal TERM' TERM
    stage_transaction_armed=true
}

abort_staging() {
    local reason="$1"

    echo "Error: $reason" >&2
    if { [ "$stage_only" = true ] && ! rollback_stage_transaction; } ||
        { [ "$stage_only" = false ] && ! rollback_staged; }; then
        echo "Error: migration rollback was incomplete; inspect the reported fixed paths before retrying." >&2
    else
        stage_transaction_complete=true
    fi
    exit 1
}

recovery_completed=0
initial_inventory_recorded=false
while :; do
    failures=()
    candidates=()
    interrupted=()

    if ! layout_root_is_trusted; then
        failures+=("system-asset layout root is wrongly owned or writable by group/other: $layout_root")
    fi

    # Validate every immutable asset before authorizing any /etc mutation.
    for record in "${assets[@]}"; do
        IFS='|' read -r id source_relative canonical_relative legacy_relative <<<"$record"
        source_path="$repository_root/$source_relative"
        canonical_path="$layout_prefix/$canonical_relative"
        if ! metadata_is_trusted_regular "$canonical_path"; then
            failures+=("package/source-owned asset is missing, linked, multiply linked, wrongly owned, or not mode 0644: $canonical_path")
            continue
        fi
        if ! cmp -s -- "$source_path" "$canonical_path"; then
            failures+=("package/source-owned asset bytes do not match this checkout: $canonical_path")
            continue
        fi
        current_hash="$(sha256sum -- "$source_path" | awk '{print $1}')"
        if ! allowlist_contains "$id" "$current_hash"; then
            failures+=("current $source_relative bytes are absent from the reviewed allowlist")
        fi
    done

    # Inventory all three exact public/quarantine pairs before any recovery or
    # migration move. Only absent-public plus an exact known quarantine is a
    # recoverable interrupted transaction. Every dual or untrusted state is
    # preserved as ambiguous.
    for record in "${assets[@]}"; do
        IFS='|' read -r id source_relative canonical_relative legacy_relative <<<"$record"
        legacy_path="$layout_prefix/$legacy_relative"
        quarantine_path="${legacy_path%/*}/.facelock-migrate-$id"
        legacy_state=absent
        quarantine_state=absent
        if ! parents_are_trusted "$legacy_path"; then
            failures+=("legacy asset parent is linked, untrusted, or writable and was preserved: ${legacy_path%/*}")
            continue
        fi
        if [ -e "$legacy_path" ] || [ -L "$legacy_path" ]; then
            if [ "$id" = systemd-unit ] &&
                metadata_is_administrator_mask "$legacy_path"; then
                legacy_state=admin-mask
            elif metadata_is_trusted_regular "$legacy_path"; then
                legacy_hash="$(sha256sum -- "$legacy_path" | awk '{print $1}')"
                if allowlist_contains "$id" "$legacy_hash"; then
                    legacy_state=exact
                elif [ "$protected_source" = true ]; then
                    legacy_state=admin-file
                else
                    failures+=("legacy asset has modified or unknown bytes and was preserved: $legacy_path")
                    legacy_state=invalid
                fi
            else
                failures+=("legacy asset is linked, non-regular, multiply linked, wrongly owned, or not mode 0644 and was preserved: $legacy_path")
                legacy_state=invalid
            fi
        fi
        if [ -e "$quarantine_path" ] || [ -L "$quarantine_path" ]; then
            if metadata_is_trusted_regular "$quarantine_path"; then
                quarantine_hash="$(sha256sum -- "$quarantine_path" | awk '{print $1}')"
                if allowlist_contains "$id" "$quarantine_hash"; then
                    quarantine_state=exact
                else
                    failures+=("migration quarantine has modified or unknown bytes and was preserved: $quarantine_path")
                    quarantine_state=invalid
                fi
            else
                failures+=("migration quarantine is linked, non-regular, multiply linked, wrongly owned, or not mode 0644 and was preserved: $quarantine_path")
                quarantine_state=invalid
            fi
        fi
        case "$legacy_state:$quarantine_state" in
            absent:absent) ;;
            exact:absent) candidates+=("$id|$legacy_path|$quarantine_path|$legacy_hash") ;;
            absent:exact) interrupted+=("$id|$legacy_path|$quarantine_path|$quarantine_hash") ;;
            exact:exact)
                failures+=("both the legacy asset and its fixed migration quarantine exist and were preserved as ambiguous: $legacy_path and $quarantine_path")
                ;;
            admin-mask:absent) ;;
            admin-file:absent) ;;
            admin-mask:*)
                failures+=("administrator systemd mask has an ambiguous migration quarantine peer and was preserved: $legacy_path and $quarantine_path")
                ;;
            admin-file:*)
                failures+=("administrator system asset has an ambiguous migration quarantine peer and was preserved: $legacy_path and $quarantine_path")
                ;;
            invalid:* | *:invalid) ;;
        esac
    done

    if [ "${#failures[@]}" -ne 0 ]; then
        if [ "$recovery_completed" -ne 0 ]; then
            echo "Error: system asset validation failed after interrupted-staging names were restored; no fixed quarantine was deleted." >&2
            echo "Resolve the preserved paths and retry:" >&2
        else
            echo "Error: system asset validation failed; no legacy files were changed." >&2
            echo "Reinstall Facelock or rerun 'sudo just install-files', resolve preserved /etc overrides, and retry:" >&2
        fi
        printf '  - %s\n' "${failures[@]}" >&2
        exit 1
    fi
    if [ "$stage_only" = true ] && [ "$initial_inventory_recorded" = false ]; then
        initial_interrupted=("${interrupted[@]}")
        initial_inventory_recorded=true
        arm_stage_transaction
    fi
    if [ "${#interrupted[@]}" -eq 0 ]; then
        break
    fi
    if [ "$recovery_completed" -ne 0 ]; then
        echo "Error: fixed migration state changed immediately after interrupted-staging recovery; exact known names were preserved for administrator review." >&2
        exit 1
    fi

    for ((index=${#interrupted[@]} - 1; index >= 0; index--)); do
        IFS='|' read -r id legacy_path quarantine_path _ <<<"${interrupted[$index]}"
        if [ -e "$legacy_path" ] || [ -L "$legacy_path" ]; then
            echo "Error: interrupted-staging recovery found a new public collision and preserved both names: $legacy_path and $quarantine_path" >&2
            exit 1
        fi
        if ! metadata_is_trusted_regular "$quarantine_path"; then
            echo "Error: interrupted-staging recovery quarantine changed and was preserved: $quarantine_path" >&2
            exit 1
        fi
        quarantine_hash="$(sha256sum -- "$quarantine_path" | awk '{print $1}')"
        if ! allowlist_contains "$id" "$quarantine_hash"; then
            echo "Error: interrupted-staging recovery quarantine bytes changed and were preserved: $quarantine_path" >&2
            exit 1
        fi
        if ! move_noreplace "$quarantine_path" "$legacy_path"; then
            echo "Error: failed to restore interrupted migration quarantine without replacement; both names were preserved when present: $quarantine_path to $legacy_path" >&2
            exit 1
        fi
        if ! metadata_is_trusted_regular "$legacy_path" ||
            [ -e "$quarantine_path" ] || [ -L "$quarantine_path" ]; then
            echo "Error: interrupted-staging recovery reported success without restoring the exact fixed pair: $legacy_path and $quarantine_path" >&2
            exit 1
        fi
        legacy_hash="$(sha256sum -- "$legacy_path" | awk '{print $1}')"
        if ! allowlist_contains "$id" "$legacy_hash"; then
            echo "Error: interrupted-staging recovery restored changed bytes and preserved them: $legacy_path" >&2
            exit 1
        fi
    done
    recovery_completed=1
done

for candidate in "${candidates[@]}"; do
    IFS='|' read -r id legacy_path quarantine_path legacy_hash <<<"$candidate"
    staged+=("$id|$legacy_path|$quarantine_path|$legacy_hash")
    # Revalidate immediately before removal.  Another privileged writer is
    # outside this helper's trust boundary, but a stable-path change still
    # fails closed instead of deleting newly ambiguous bytes.
    if [ ! -e "$legacy_path" ] && [ ! -L "$legacy_path" ]; then
        abort_staging "legacy asset disappeared after preflight and earlier candidates were rolled back: $legacy_path"
    fi
    if ! metadata_is_trusted_regular "$legacy_path"; then
        abort_staging "legacy asset changed after preflight and earlier candidates were rolled back: $legacy_path"
    fi
    legacy_hash="$(sha256sum -- "$legacy_path" | awk '{print $1}')"
    if ! allowlist_contains "$id" "$legacy_hash"; then
        abort_staging "legacy asset changed after preflight and earlier candidates were rolled back: $legacy_path"
    fi
    if ! move_noreplace "$legacy_path" "$quarantine_path"; then
        abort_staging "could not quarantine exact legacy asset without replacement; earlier candidates were rolled back: $legacy_path"
    fi
    if ! metadata_is_trusted_regular "$quarantine_path"; then
        abort_staging "quarantined legacy asset failed metadata revalidation: $quarantine_path"
    fi
    quarantine_hash="$(sha256sum -- "$quarantine_path" | awk '{print $1}')"
    if ! allowlist_contains "$id" "$quarantine_hash"; then
        abort_staging "quarantined legacy asset failed digest revalidation: $quarantine_path"
    fi
done

# Every legacy name is absent, but rollback remains possible until the fixed
# quarantines are published by deletion. Revalidate the complete canonical set
# and root-equivalent trust identity before crossing that boundary.
if ! canonical_assets_are_valid; then
    abort_staging "canonical system assets or their trusted identity changed during migration; every staged legacy asset was rolled back"
fi

for candidate in "${staged[@]}"; do
    IFS='|' read -r id legacy_path quarantine_path _ <<<"$candidate"
    if ! metadata_is_trusted_regular "$quarantine_path"; then
        abort_staging "quarantine changed before publication: $quarantine_path"
    fi
    quarantine_hash="$(sha256sum -- "$quarantine_path" | awk '{print $1}')"
    if ! allowlist_contains "$id" "$quarantine_hash"; then
        abort_staging "quarantine bytes changed before publication: $quarantine_path"
    fi
done

if [ "$stage_only" = true ]; then
    for candidate in "${staged[@]}"; do
        IFS='|' read -r _ legacy_path _ _ <<<"$candidate"
        echo "Staged exact known legacy system asset $legacy_path"
    done
    stage_transaction_complete=true
    trap - EXIT HUP INT TERM
    exit 0
fi

for candidate in "${staged[@]}"; do
    IFS='|' read -r id legacy_path quarantine_path _ <<<"$candidate"
    rm -- "$quarantine_path"
    echo "Removed exact known legacy system asset $legacy_path"
done

# A second privileged writer is outside the transaction's authority, but the
# completed operation never reports healthy without a final canonical and
# root-equivalent identity check.
if ! canonical_assets_are_valid; then
    echo "Error: canonical system assets or their trusted identity changed after migration." >&2
    exit 1
fi
