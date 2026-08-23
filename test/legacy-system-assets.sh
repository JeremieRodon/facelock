#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
helper="$repo_root/scripts/migrate-legacy-system-assets.sh"
uninstall_helper="$repo_root/scripts/uninstall-system-assets.sh"
manifest="$repo_root/dist/legacy-system-assets.sha256"
justfile="$repo_root/justfile"
postinst="$repo_root/debian/postinst"
containerfile="$repo_root/test/Containerfile"

fail() {
    echo "legacy system assets: $*" >&2
    exit 1
}

[ -f "$helper" ] || fail "missing source-install migration helper"
[ -f "$uninstall_helper" ] || fail "missing source-uninstall system-asset helper"
[ -f "$manifest" ] || fail "missing reviewed digest allowlist"
grep -Fq 'COPY scripts/migrate-legacy-system-assets.sh /build/scripts/migrate-legacy-system-assets.sh' \
    "$containerfile" ||
    fail "source-install container omits the migration helper"

helper_call_line="$(grep -n -m1 -F 'facelock_source_install_stage_and_record_legacy_migration /' "$justfile" |
    cut -d: -f1 || true)"
[ -n "$helper_call_line" ] || fail "install-files does not invoke exact legacy migration"
for install_needle in \
    'install -Dm644 systemd/facelock-daemon.service /usr/lib/systemd/system/facelock-daemon.service' \
    'install -Dm644 dbus/org.facelock.Daemon.conf /usr/share/dbus-1/system.d/org.facelock.Daemon.conf' \
    'install -Dm644 dbus/org.facelock.Daemon.service /usr/share/dbus-1/system-services/org.facelock.Daemon.service'; do
    install_line="$(grep -n -m1 -F "$install_needle" "$justfile" | cut -d: -f1 || true)"
    [ -n "$install_line" ] && [ "$install_line" -lt "$helper_call_line" ] ||
        fail "install-files must write every canonical asset before migration"
done
if rg -n "grep -q '(ExecStart=/usr/bin/facelock daemon|org.facelock.Daemon)'" \
    "$justfile" "$postinst" "$repo_root/dist/facelock.install" \
    "$repo_root/dist/facelock.spec" >/dev/null; then
    fail "marker-based legacy asset overwrite remains in source/package install logic"
fi
if grep -Eq 'install[[:space:]].*/etc/(systemd/system|dbus-1/)' "$postinst"; then
    fail "Debian postinst still writes legacy /etc service assets"
fi
grep -Fq 'scripts/uninstall-system-assets.sh /' "$justfile" ||
    fail "uninstall-files does not use the fixed system-asset helper"
uninstall_recipe="$(sed -n '/^uninstall-files:/,/^[[:alnum:]_-][[:alnum:]_-]*:/p' "$justfile")"
for historical in \
    /etc/systemd/system/facelock-daemon.service \
    /etc/dbus-1/system.d/org.facelock.Daemon.conf \
    /etc/dbus-1/system-services/org.facelock.Daemon.service; do
    if grep -Fq "$historical" <<<"$uninstall_recipe"; then
        fail "uninstall-files still targets historical system asset $historical"
    fi
done

tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/facelock-legacy-system-assets.XXXXXX")"
trap 'rm -rf -- "$tmp_root"' EXIT

seed_canonical() {
    local root="$1"
    install -Dm644 "$repo_root/systemd/facelock-daemon.service" \
        "$root/usr/lib/systemd/system/facelock-daemon.service"
    install -Dm644 "$repo_root/dbus/org.facelock.Daemon.conf" \
        "$root/usr/share/dbus-1/system.d/org.facelock.Daemon.conf"
    install -Dm644 "$repo_root/dbus/org.facelock.Daemon.service" \
        "$root/usr/share/dbus-1/system-services/org.facelock.Daemon.service"
}

seed_legacy_current() {
    local root="$1"

    install -Dm644 "$repo_root/systemd/facelock-daemon.service" \
        "$root/etc/systemd/system/facelock-daemon.service"
    install -Dm644 "$repo_root/dbus/org.facelock.Daemon.conf" \
        "$root/etc/dbus-1/system.d/org.facelock.Daemon.conf"
    install -Dm644 "$repo_root/dbus/org.facelock.Daemon.service" \
        "$root/etc/dbus-1/system-services/org.facelock.Daemon.service"
}

snapshot_canonical() {
    local root="$1"
    for path in \
        usr/lib/systemd/system/facelock-daemon.service \
        usr/share/dbus-1/system.d/org.facelock.Daemon.conf \
        usr/share/dbus-1/system-services/org.facelock.Daemon.service; do
        stat -c '%u:%g:%a:%h' "$root/$path"
        sha256sum "$root/$path"
    done
}

case_root="$tmp_root/exact"
mkdir -p "$case_root"
seed_canonical "$case_root"
before="$(snapshot_canonical "$case_root")"
install -Dm644 "$repo_root/dbus/org.facelock.Daemon.conf" \
    "$case_root/etc/dbus-1/system.d/org.facelock.Daemon.conf"
install -Dm644 "$repo_root/dbus/org.facelock.Daemon.service" \
    "$case_root/etc/dbus-1/system-services/org.facelock.Daemon.service"
mkdir -p "$case_root/etc/systemd/system"
cat >"$case_root/etc/systemd/system/facelock-daemon.service" <<'UNIT'
[Unit]
Description=Facelock Face Authentication Daemon
After=local-fs.target

[Service]
Type=dbus
BusName=org.facelock.Daemon
ExecStart=/usr/bin/facelock daemon
StandardOutput=journal
StandardError=journal
Restart=on-failure
RestartSec=3
LimitNOFILE=1024

# Phase 1: Filesystem isolation
ProtectSystem=strict
# ProtectHome=yes also hides /run/user/, breaking desktop notifications
# (daemon sends notify-send via runuser to /run/user/<uid>/bus).
# Use InaccessiblePaths instead to protect /home and /root without
# affecting /run/user/.
InaccessiblePaths=/home /root
ReadWritePaths=/var/lib/facelock /var/log/facelock
PrivateTmp=yes
NoNewPrivileges=yes

# Phase 2: Kernel hardening
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes

# Phase 2.5: Device access
# DevicePolicy=closed/auto both use cgroup device ACLs which hide /dev/video*
# from stat(), breaking camera auto-detection. Omitted — the daemon only needs
# /dev/video* and /dev/tpmrm0, both protected by standard Unix permissions.
# ProtectSystem=strict already prevents writing to /dev/.

# Deferred: MemoryDenyWriteExecute=yes breaks ONNX Runtime JIT.
# Phase 3 (seccomp, capabilities, network) deferred to future work.

[Install]
WantedBy=multi-user.target
UNIT
"$helper" "$case_root"
[ ! -e "$case_root/etc/systemd/system/facelock-daemon.service" ] ||
    fail "stale exact unit was not migrated"
[ ! -e "$case_root/etc/dbus-1/system.d/org.facelock.Daemon.conf" ] ||
    fail "current exact policy was not migrated"
[ ! -e "$case_root/etc/dbus-1/system-services/org.facelock.Daemon.service" ] ||
    fail "current exact activation definition was not migrated"
[ "$(snapshot_canonical "$case_root")" = "$before" ] ||
    fail "migration changed canonical bytes or metadata"
"$helper" "$case_root"

case_root="$tmp_root/ambiguous"
mkdir -p "$case_root"
seed_canonical "$case_root"
install -Dm644 "$repo_root/systemd/facelock-daemon.service" \
    "$case_root/etc/systemd/system/facelock-daemon.service"
install -Dm644 /dev/null \
    "$case_root/etc/dbus-1/system.d/org.facelock.Daemon.conf"
printf '%s\n' 'administrator policy' \
    >"$case_root/etc/dbus-1/system.d/org.facelock.Daemon.conf"
if "$helper" "$case_root" >/dev/null 2>&1; then
    fail "modified legacy policy was accepted"
fi
[ -f "$case_root/etc/systemd/system/facelock-daemon.service" ] ||
    fail "whole-set preflight removed an exact peer before rejecting ambiguity"
grep -Fq 'administrator policy' \
    "$case_root/etc/dbus-1/system.d/org.facelock.Daemon.conf" ||
    fail "modified policy was not preserved"

for linked in symlink hardlink; do
    case_root="$tmp_root/$linked"
    mkdir -p "$case_root"
    seed_canonical "$case_root"
    legacy="$case_root/etc/systemd/system/facelock-daemon.service"
    outside="$case_root/outside-unit"
    mkdir -p "${legacy%/*}"
    cp "$repo_root/systemd/facelock-daemon.service" "$outside"
    if [ "$linked" = symlink ]; then
        ln -s "$outside" "$legacy"
    else
        ln "$outside" "$legacy"
    fi
    if "$helper" "$case_root" >/dev/null 2>&1; then
        fail "$linked legacy unit was accepted"
    fi
    [ -e "$legacy" ] || [ -L "$legacy" ] || fail "$linked legacy unit was removed"
    cmp -s "$outside" "$repo_root/systemd/facelock-daemon.service" ||
        fail "$linked outside target changed"
done

case_root="$tmp_root/parent-symlink"
mkdir -p "$case_root"
seed_canonical "$case_root"
outside_dir="$case_root/outside-policy-dir"
mkdir -p "$outside_dir" "$case_root/etc/dbus-1"
cp "$repo_root/dbus/org.facelock.Daemon.conf" \
    "$outside_dir/org.facelock.Daemon.conf"
ln -s "$outside_dir" "$case_root/etc/dbus-1/system.d"
if "$helper" "$case_root" >/dev/null 2>&1; then
    fail "symlinked legacy parent was accepted"
fi
cmp -s "$outside_dir/org.facelock.Daemon.conf" \
    "$repo_root/dbus/org.facelock.Daemon.conf" ||
    fail "symlinked legacy parent target changed"

case_root="$tmp_root/canonical-mode"
mkdir -p "$case_root"
seed_canonical "$case_root"
chmod 0600 "$case_root/usr/lib/systemd/system/facelock-daemon.service"
install -Dm644 "$repo_root/dbus/org.facelock.Daemon.conf" \
    "$case_root/etc/dbus-1/system.d/org.facelock.Daemon.conf"
if "$helper" "$case_root" >/dev/null 2>&1; then
    fail "wrong canonical mode was accepted"
fi
[ -f "$case_root/etc/dbus-1/system.d/org.facelock.Daemon.conf" ] ||
    fail "canonical preflight failure removed an exact legacy file"

case_root="$tmp_root/late-stage-rollback"
mkdir -p "$case_root"
seed_canonical "$case_root"
seed_legacy_current "$case_root"
real_mv="$(command -v mv)"
shim_bin="$tmp_root/late-stage-bin"
mkdir -p "$shim_bin"
cat >"$shim_bin/mv" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
count=0
if [ -f "$FACELOCK_MV_COUNT" ]; then
    read -r count <"$FACELOCK_MV_COUNT"
fi
count=$((count + 1))
printf '%s\n' "$count" >"$FACELOCK_MV_COUNT"
if [ "$count" -eq 2 ]; then
    exit 73
fi
exec "$FACELOCK_REAL_MV" "$@"
EOF
chmod 0755 "$shim_bin/mv"
if PATH="$shim_bin:$PATH" \
    FACELOCK_REAL_MV="$real_mv" \
    FACELOCK_MV_COUNT="$tmp_root/late-stage-mv-count" \
    "$helper" "$case_root" >/dev/null 2>&1; then
    fail "late migration-stage failure unexpectedly succeeded"
fi
for asset in \
    etc/systemd/system/facelock-daemon.service \
    etc/dbus-1/system.d/org.facelock.Daemon.conf \
    etc/dbus-1/system-services/org.facelock.Daemon.service; do
    [ -f "$case_root/$asset" ] ||
        fail "late stage failure did not roll back $asset"
done
if find "$case_root/etc" -name '.facelock-migrate-*' -print -quit | grep -q .; then
    fail "late stage rollback left a migration quarantine behind"
fi

case_root="$tmp_root/stage-process-group-interrupt"
mkdir -p "$case_root"
seed_canonical "$case_root"
seed_legacy_current "$case_root"
real_mv="$(command -v mv)"
shim_bin="$tmp_root/stage-process-group-interrupt-bin"
mkdir -p "$shim_bin"
cat >"$shim_bin/mv" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

count=0
[ ! -f "$FACELOCK_MV_COUNT" ] || read -r count <"$FACELOCK_MV_COUNT"
count=$((count + 1))
printf '%s\n' "$count" >"$FACELOCK_MV_COUNT"
"$FACELOCK_REAL_MV" "$@"
if [ "$count" -eq 1 ]; then
    kill -INT 0
fi
EOF
chmod 0755 "$shim_bin/mv"
set +e
setsid env PATH="$shim_bin:$PATH" \
    FACELOCK_REAL_MV="$real_mv" \
    FACELOCK_MV_COUNT="$tmp_root/stage-process-group-interrupt-count" \
    "$helper" --source-protected --stage "$case_root" >/dev/null 2>&1
status=$?
set -e
[ "$status" -eq 130 ] ||
    fail "process-group interrupt exited $status instead of 130"
for asset in \
    etc/systemd/system/facelock-daemon.service \
    etc/dbus-1/system.d/org.facelock.Daemon.conf \
    etc/dbus-1/system-services/org.facelock.Daemon.service; do
    [ -f "$case_root/$asset" ] ||
        fail "process-group interrupt did not restore $asset"
done
if find "$case_root/etc" -name '.facelock-migrate-*' -print -quit | grep -q .; then
    fail "process-group interrupt left a migration quarantine behind"
fi

case_root="$tmp_root/rollback-collision"
mkdir -p "$case_root"
seed_canonical "$case_root"
seed_legacy_current "$case_root"
shim_bin="$tmp_root/rollback-collision-bin"
mkdir -p "$shim_bin"
cat >"$shim_bin/mv" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
count=0
if [ -f "$FACELOCK_MV_COUNT" ]; then
    read -r count <"$FACELOCK_MV_COUNT"
fi
count=$((count + 1))
printf '%s\n' "$count" >"$FACELOCK_MV_COUNT"
if [ "$count" -eq 2 ]; then
    printf '%s\n' 'administrator replacement' >"$FACELOCK_FIRST_LEGACY"
    exit 73
fi
exec "$FACELOCK_REAL_MV" "$@"
EOF
chmod 0755 "$shim_bin/mv"
first_legacy="$case_root/etc/systemd/system/facelock-daemon.service"
first_quarantine="$case_root/etc/systemd/system/.facelock-migrate-systemd-unit"
rollback_log="$tmp_root/rollback-collision.log"
if PATH="$shim_bin:$PATH" \
    FACELOCK_REAL_MV="$real_mv" \
    FACELOCK_MV_COUNT="$tmp_root/rollback-collision-mv-count" \
    FACELOCK_FIRST_LEGACY="$first_legacy" \
    "$helper" "$case_root" >"$rollback_log" 2>&1; then
    fail "rollback collision unexpectedly succeeded"
fi
grep -Fqx 'administrator replacement' "$first_legacy" ||
    fail "rollback overwrote an administrator replacement"
cmp -s "$repo_root/systemd/facelock-daemon.service" "$first_quarantine" ||
    fail "rollback collision did not preserve the exact quarantine"
grep -Fq 'rollback collision preserved both names' "$rollback_log" ||
    fail "rollback collision was not reported"
grep -Fq 'migration rollback was incomplete' "$rollback_log" ||
    fail "incomplete rollback was not reported"

case_root="$tmp_root/quarantine-collision"
mkdir -p "$case_root"
seed_canonical "$case_root"
seed_legacy_current "$case_root"
collision="$case_root/etc/dbus-1/system.d/.facelock-migrate-dbus-policy"
printf '%s\n' 'administrator collision sentinel' >"$collision"
if "$helper" "$case_root" >/dev/null 2>&1; then
    fail "migration accepted a quarantine-name collision"
fi
grep -Fqx 'administrator collision sentinel' "$collision" ||
    fail "migration changed a quarantine collision"
for asset in \
    etc/systemd/system/facelock-daemon.service \
    etc/dbus-1/system.d/org.facelock.Daemon.conf \
    etc/dbus-1/system-services/org.facelock.Daemon.service; do
    [ -f "$case_root/$asset" ] ||
        fail "quarantine collision did not preserve $asset"
done

case_root="$tmp_root/interrupted-staging-recovery"
mkdir -p "$case_root"
seed_canonical "$case_root"
seed_legacy_current "$case_root"
mv -- \
    "$case_root/etc/systemd/system/facelock-daemon.service" \
    "$case_root/etc/systemd/system/.facelock-migrate-systemd-unit"
mv -- \
    "$case_root/etc/dbus-1/system.d/org.facelock.Daemon.conf" \
    "$case_root/etc/dbus-1/system.d/.facelock-migrate-dbus-policy"
"$helper" "$case_root"
for asset in \
    etc/systemd/system/facelock-daemon.service \
    etc/dbus-1/system.d/org.facelock.Daemon.conf \
    etc/dbus-1/system-services/org.facelock.Daemon.service; do
    [ ! -e "$case_root/$asset" ] && [ ! -L "$case_root/$asset" ] ||
        fail "interrupted staging recovery retained legacy asset $asset"
done
if find "$case_root/etc" -name '.facelock-migrate-*' -print -quit | grep -q .; then
    fail "interrupted staging recovery retained a fixed quarantine"
fi

case_root="$tmp_root/interrupted-staging-ambiguous-peer"
mkdir -p "$case_root"
seed_canonical "$case_root"
seed_legacy_current "$case_root"
interrupted_legacy="$case_root/etc/systemd/system/facelock-daemon.service"
interrupted_quarantine="$case_root/etc/systemd/system/.facelock-migrate-systemd-unit"
mv -- "$interrupted_legacy" "$interrupted_quarantine"
ambiguous_peer="$case_root/etc/dbus-1/system.d/org.facelock.Daemon.conf"
printf '%s\n' 'administrator policy' >"$ambiguous_peer"
if "$helper" "$case_root" >/dev/null 2>&1; then
    fail "interrupted staging recovery accepted an ambiguous peer"
fi
[ ! -e "$interrupted_legacy" ] && [ ! -L "$interrupted_legacy" ] ||
    fail "whole-set recovery preflight restored before finding an ambiguous peer"
cmp -s "$repo_root/systemd/facelock-daemon.service" "$interrupted_quarantine" ||
    fail "whole-set recovery preflight changed the interrupted quarantine"
grep -Fqx 'administrator policy' "$ambiguous_peer" ||
    fail "whole-set recovery preflight changed the ambiguous peer"

case_root="$tmp_root/interrupted-staging-dual-name"
mkdir -p "$case_root"
seed_canonical "$case_root"
seed_legacy_current "$case_root"
dual_legacy="$case_root/etc/systemd/system/facelock-daemon.service"
dual_quarantine="$case_root/etc/systemd/system/.facelock-migrate-systemd-unit"
cp -- "$dual_legacy" "$dual_quarantine"
if "$helper" "$case_root" >/dev/null 2>&1; then
    fail "interrupted staging recovery accepted a dual-name state"
fi
cmp -s "$repo_root/systemd/facelock-daemon.service" "$dual_legacy" ||
    fail "dual-name recovery changed the public legacy asset"
cmp -s "$repo_root/systemd/facelock-daemon.service" "$dual_quarantine" ||
    fail "dual-name recovery changed the quarantine"

case_root="$tmp_root/interrupted-staging-unknown-quarantine"
mkdir -p "$case_root"
seed_canonical "$case_root"
seed_legacy_current "$case_root"
unknown_legacy="$case_root/etc/systemd/system/facelock-daemon.service"
unknown_quarantine="$case_root/etc/systemd/system/.facelock-migrate-systemd-unit"
mv -- "$unknown_legacy" "$unknown_quarantine"
printf '%s\n' 'unknown quarantine' >"$unknown_quarantine"
if "$helper" "$case_root" >/dev/null 2>&1; then
    fail "interrupted staging recovery accepted an unknown quarantine"
fi
[ ! -e "$unknown_legacy" ] && [ ! -L "$unknown_legacy" ] ||
    fail "unknown-quarantine preflight recreated a public name"
grep -Fqx 'unknown quarantine' "$unknown_quarantine" ||
    fail "unknown-quarantine preflight changed the quarantine"

case_root="$tmp_root/interrupted-staging-recovery-collision"
mkdir -p "$case_root"
seed_canonical "$case_root"
seed_legacy_current "$case_root"
interrupted_legacy="$case_root/etc/systemd/system/facelock-daemon.service"
interrupted_quarantine="$case_root/etc/systemd/system/.facelock-migrate-systemd-unit"
mv -- "$interrupted_legacy" "$interrupted_quarantine"
shim_bin="$tmp_root/recovery-collision-bin"
mkdir -p "$shim_bin"
cat >"$shim_bin/mv" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [ "$1" = -Tn ] && [ "$4" = "$FACELOCK_RECOVERY_LEGACY" ]; then
    printf '%s\n' 'administrator replacement' >"$FACELOCK_RECOVERY_LEGACY"
fi
exec "$FACELOCK_REAL_MV" "$@"
EOF
chmod 0755 "$shim_bin/mv"
recovery_log="$tmp_root/recovery-collision.log"
if PATH="$shim_bin:$PATH" \
    FACELOCK_REAL_MV="$real_mv" \
    FACELOCK_RECOVERY_LEGACY="$interrupted_legacy" \
    "$helper" "$case_root" >"$recovery_log" 2>&1; then
    fail "interrupted staging recovery overwrote a concurrent collision"
fi
grep -Fqx 'administrator replacement' "$interrupted_legacy" ||
    fail "interrupted staging recovery changed a concurrent public replacement"
cmp -s "$repo_root/systemd/facelock-daemon.service" "$interrupted_quarantine" ||
    fail "interrupted staging recovery changed its quarantine after collision"
grep -Fq 'without replacement' "$recovery_log" ||
    fail "interrupted staging recovery collision was not reported"

case_root="$tmp_root/untrusted-layout-root"
mkdir -p "$case_root"
seed_canonical "$case_root"
seed_legacy_current "$case_root"
chmod 0777 "$case_root"
if "$helper" "$case_root" >/dev/null 2>&1; then
    chmod 0700 "$case_root"
    fail "migration trusted a group/world-writable layout root"
fi
chmod 0700 "$case_root"
[ -f "$case_root/etc/systemd/system/facelock-daemon.service" ] ||
    fail "untrusted layout root did not preserve the legacy unit"

seed_uninstall_case() {
    local root="$1"

    seed_canonical "$root"
    install -Dm755 /dev/null "$root/usr/bin/facelock"
}

assert_canonical_assets_removed() {
    local root="$1"

    for asset in \
        usr/lib/systemd/system/facelock-daemon.service \
        usr/share/dbus-1/system.d/org.facelock.Daemon.conf \
        usr/share/dbus-1/system-services/org.facelock.Daemon.service; do
        [ ! -e "$root/$asset" ] && [ ! -L "$root/$asset" ] ||
            fail "source uninstall retained canonical asset $asset"
    done
}

assert_canonical_assets_present() {
    local root="$1"

    for asset in \
        usr/lib/systemd/system/facelock-daemon.service \
        usr/share/dbus-1/system.d/org.facelock.Daemon.conf \
        usr/share/dbus-1/system-services/org.facelock.Daemon.service; do
        [ -e "$root/$asset" ] || [ -L "$root/$asset" ] ||
            fail "source uninstall changed canonical peer $asset after failed preflight"
    done
}

case_root="$tmp_root/uninstall-exact"
mkdir -p "$case_root"
seed_uninstall_case "$case_root"
seed_legacy_current "$case_root"
"$uninstall_helper" "$case_root"
assert_canonical_assets_removed "$case_root"
for asset in \
    systemd-unit:systemd/facelock-daemon.service:etc/systemd/system/facelock-daemon.service \
    dbus-policy:dbus/org.facelock.Daemon.conf:etc/dbus-1/system.d/org.facelock.Daemon.conf \
    dbus-activation:dbus/org.facelock.Daemon.service:etc/dbus-1/system-services/org.facelock.Daemon.service; do
    IFS=: read -r id source legacy <<<"$asset"
    cmp -s "$repo_root/$source" "$case_root/$legacy" ||
        fail "source uninstall changed exact regular legacy asset $id"
done

case_root="$tmp_root/uninstall-canonical-direct-symlink"
mkdir -p "$case_root"
seed_uninstall_case "$case_root"
canonical="$case_root/usr/share/dbus-1/system.d/org.facelock.Daemon.conf"
outside="$case_root/outside-canonical-policy"
cp "$repo_root/dbus/org.facelock.Daemon.conf" "$outside"
rm -- "$canonical"
ln -s "$outside" "$canonical"
if "$uninstall_helper" "$case_root" >/dev/null 2>&1; then
    fail "source uninstall accepted a linked canonical target"
fi
assert_canonical_assets_present "$case_root"
[ -L "$canonical" ] || fail "source uninstall removed a linked canonical target"
cmp -s "$repo_root/dbus/org.facelock.Daemon.conf" "$outside" ||
    fail "source uninstall changed the direct-link outside sentinel"

case_root="$tmp_root/uninstall-canonical-parent-symlink"
mkdir -p "$case_root"
seed_uninstall_case "$case_root"
canonical_parent="$case_root/usr/lib/systemd/system"
outside_dir="$case_root/outside-canonical-systemd"
outside="$outside_dir/facelock-daemon.service"
mkdir -p "$outside_dir"
cp "$repo_root/systemd/facelock-daemon.service" "$outside"
rm -- "$canonical_parent/facelock-daemon.service"
rmdir -- "$canonical_parent"
ln -s "$outside_dir" "$canonical_parent"
if "$uninstall_helper" "$case_root" >/dev/null 2>&1; then
    fail "source uninstall accepted a linked canonical parent"
fi
assert_canonical_assets_present "$case_root"
[ -L "$canonical_parent" ] || fail "source uninstall changed a linked canonical parent"
cmp -s "$repo_root/systemd/facelock-daemon.service" "$outside" ||
    fail "source uninstall removed the canonical parent-link outside sentinel"

case_root="$tmp_root/uninstall-symlink"
mkdir -p "$case_root"
seed_uninstall_case "$case_root"
legacy="$case_root/etc/systemd/system/facelock-daemon.service"
outside="$case_root/outside-unit"
mkdir -p "${legacy%/*}"
cp "$repo_root/systemd/facelock-daemon.service" "$outside"
ln -s "$outside" "$legacy"
"$uninstall_helper" "$case_root"
assert_canonical_assets_removed "$case_root"
[ -L "$legacy" ] || fail "source uninstall removed a direct legacy symlink"
cmp -s "$repo_root/systemd/facelock-daemon.service" "$outside" ||
    fail "source uninstall changed a direct-symlink target"

case_root="$tmp_root/uninstall-hardlink"
mkdir -p "$case_root"
seed_uninstall_case "$case_root"
legacy="$case_root/etc/systemd/system/facelock-daemon.service"
outside="$case_root/outside-unit"
mkdir -p "${legacy%/*}"
cp "$repo_root/systemd/facelock-daemon.service" "$outside"
ln "$outside" "$legacy"
before_links="$(stat -c %h "$outside")"
"$uninstall_helper" "$case_root"
assert_canonical_assets_removed "$case_root"
[ -f "$legacy" ] || fail "source uninstall removed a legacy hardlink"
[ "$(stat -c %h "$outside")" = "$before_links" ] ||
    fail "source uninstall changed the legacy hardlink count"

case_root="$tmp_root/uninstall-parent-symlink"
mkdir -p "$case_root"
seed_uninstall_case "$case_root"
outside_dir="$case_root/outside-systemd"
outside="$outside_dir/facelock-daemon.service"
mkdir -p "$outside_dir" "$case_root/etc/systemd"
cp "$repo_root/systemd/facelock-daemon.service" "$outside"
ln -s "$outside_dir" "$case_root/etc/systemd/system"
"$uninstall_helper" "$case_root"
assert_canonical_assets_removed "$case_root"
[ -L "$case_root/etc/systemd/system" ] ||
    fail "source uninstall removed a symlinked legacy parent"
cmp -s "$repo_root/systemd/facelock-daemon.service" "$outside" ||
    fail "source uninstall changed the outside parent-symlink sentinel"

echo "legacy system assets: ok"
