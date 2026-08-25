#!/usr/bin/env bash
# Booted Fedora proof that Facelock edits only explicitly selected leaf PAM
# services and never rewrites authselect's shared policy.
set -euo pipefail

local_service=facelock-rpm-leaf
vendor_service=facelock-rpm-vendor-leaf
symlink_service=facelock-rpm-symlink
local_path="/etc/pam.d/$local_service"
vendor_path="/usr/lib/pam.d/$vendor_service"
vendor_override="/etc/pam.d/$vendor_service"
symlink_path="/etc/pam.d/$symlink_service"
snapshot_dir="$(mktemp -d /tmp/facelock-rpm-pam.XXXXXX)"
pam_log="$snapshot_dir/pamtester.log"
outside_path="$snapshot_dir/outside-pam"
pass_count=0

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

pass() {
    printf 'TEST: %s ... PASS\n' "$1"
    pass_count=$((pass_count + 1))
}

snapshot_authselect() {
    local entry
    /usr/bin/authselect current -r
    for entry in \
        /etc/authselect/authselect.conf \
        /etc/authselect/system-auth \
        /etc/authselect/password-auth \
        /etc/authselect/postlogin; do
        stat -c '%n|%F|%u|%g|%a|%h|%s' -- "$entry"
        sha256sum -- "$entry"
    done
}

snapshot_pam_root() {
    local path basename
    while IFS= read -r -d '' path; do
        basename="${path##*/}"
        case "$basename" in
            "$local_service"|"$vendor_service"|"$symlink_service") continue ;;
        esac
        stat -c '%n|%F|%u|%g|%a|%h|%s' -- "$path"
        if [ -L "$path" ]; then
            readlink -- "$path"
        elif [ -f "$path" ]; then
            sha256sum -- "$path"
        fi
    done < <(find /etc/pam.d -mindepth 1 -maxdepth 1 -print0 | sort -z)
}

snapshot_file() {
    local path="$1"
    stat -c '%F|%u|%g|%a|%h|%s' -- "$path"
    sha256sum -- "$path" | awk '{print $1}'
}

# pamtester's own output used to go to /dev/null, so an unexpected result was a
# one-line FAIL with nothing behind it. That is where the Fedora lifecycle lane
# stopped the first time CI ran it (#229): a rejection two seconds in, with no
# way to tell a refused password from a module that never reached the daemon.
# Keep the output, and dump the state the module depends on, whenever a case
# does not go the way it should.
authenticate() {
    printf '%s\n' "$1" |
        timeout --foreground 30 pamtester "$local_service" testuser authenticate \
            >"$pam_log" 2>&1
}

authenticate_diagnostics() {
    # This runs as the command after a final `||`, where bash keeps errexit
    # ACTIVE inside the compound -- a probe that exits nonzero (getent on a
    # missing entry, the deliberately failing replays below) would otherwise
    # kill the dump mid-flight and steal the script's exit code. Scope the
    # opt-out to this function.
    local -
    set +e
    {
        echo "--- pamtester output ---"
        cat -- "$pam_log" 2>/dev/null || echo "(nothing captured)"
        echo "--- $local_path ---"
        cat -- "$local_path" 2>/dev/null || echo "(absent)"
        echo "--- facelock-daemon.service ---"
        systemctl --no-pager --full status facelock-daemon.service 2>&1 || true
        echo "--- facelock-daemon.service journal ---"
        journalctl --no-pager --full -u facelock-daemon.service -n 60 2>&1 || true
        echo "--- failed units ---"
        systemctl --no-pager --full --failed 2>&1 || true
        echo "--- org.facelock.Daemon bus name ---"
        busctl --system status org.facelock.Daemon 2>&1 || true
        echo "--- /var/lib/facelock/models ---"
        ls -l /var/lib/facelock/models 2>&1 || true
        # pam_unix's side of the stack. AUTHINFO_UNAVAIL with the correct
        # password means pam_unix could not retrieve the shadow entry, not
        # that a password was refused -- reproduced exactly by deleting
        # testuser's shadow row. Show whether the entry is reachable (never
        # the hash), what storage the file sits on, and what pam_unix logged.
        echo "--- pam_unix credential sources ---"
        ls -ln /etc/passwd /etc/shadow 2>&1 || true
        stat -f -c 'fstype=%T' /etc/shadow 2>&1 || true
        cat /proc/self/uid_map 2>&1 || true
        getent shadow testuser >/dev/null 2>&1; echo "getent shadow testuser: rc=$?"
        grep -E '^Cap(Inh|Prm|Eff|Bnd)' /proc/self/status 2>&1 || true
        dd if=/etc/shadow of=/dev/null bs=1 count=1 2>&1 | tail -1 || true
        printf 'testuser shadow rows: '; grep -c '^testuser:' /etc/shadow 2>&1 || true
        # Probe: does loosening the 0000 mode make the entry readable? Only
        # reached on the way to fail(), so the mutation dies with the
        # container; restore anyway.
        chmod 0400 /etc/shadow 2>/dev/null || true
        getent shadow testuser >/dev/null 2>&1; echo "getent after chmod 0400: rc=$?"
        chmod 0000 /etc/shadow 2>/dev/null || true
        echo "--- pamtester journal (pam_unix) ---"
        journalctl --no-pager --full -n 40 -t pamtester 2>&1 || true
        # The module logs under its own ident, not the application's, and
        # pam_unix 1.7+ verifies every shadowed password through an exec of
        # unix_chkpwd — whose pre-exec failures exit AUTHINFO_UNAVAIL without
        # logging. Cover both witnesses, then take the stack apart: the
        # helper alone, pam_unix alone, and the full leaf under strace so a
        # failing execve names its errno.
        echo "--- module and helper journal ---"
        journalctl --no-pager --full -n 40 -t pam_facelock -t unix_chkpwd 2>&1 || true
        echo "--- process security state ---"
        grep -E 'NoNewPrivs|Seccomp' /proc/self/status 2>&1 || true
        echo "--- unix_chkpwd direct ---"
        # The helper reads a NUL-terminated password from stdin.
        printf 'test\0' | /usr/sbin/unix_chkpwd testuser nonull
        echo "unix_chkpwd direct: rc=$?"
        echo "--- pam_unix-only control ---"
        printf '%s\n' \
            '#%PAM-1.0' \
            'auth      required pam_unix.so' \
            'account   required pam_permit.so' \
            >/etc/pam.d/facelock-rpm-control
        printf 'test\n' | pamtester facelock-rpm-control testuser authenticate
        echo "pam_unix-only control: rc=$?"
        rm -f /etc/pam.d/facelock-rpm-control
        echo "--- leaf replay under strace ---"
        if command -v strace >/dev/null 2>&1; then
            printf 'test\n' | strace -f -qq -e trace=%file,exit_group \
                -o /tmp/facelock-pam-diag.strace \
                pamtester "$local_service" testuser authenticate
            echo "strace replay: rc=$?"
            grep -E 'shadow|passwd|chkpwd|exit_group' /tmp/facelock-pam-diag.strace 2>&1 | head -40
            rm -f /tmp/facelock-pam-diag.strace
        else
            echo "(strace not installed)"
        fi
    } >&2
}

authselect_is_unchanged() {
    snapshot_authselect /dev/stdout | cmp -s - "$snapshot_dir/authselect.before"
}

cleanup() {
    /usr/bin/facelock pam remove --service "$local_service" --if-present --no-confirm \
        >/dev/null 2>&1 || true
    /usr/bin/facelock pam remove --service "$vendor_service" --if-present --no-confirm \
        >/dev/null 2>&1 || true
    rm -f -- "$local_path" "$vendor_override" "$vendor_path" "$symlink_path" "$outside_path"
    rm -rf -- "$snapshot_dir"
}
trap cleanup EXIT

for required in /usr/bin/facelock /usr/bin/authselect /usr/bin/pamtester; do
    [ -x "$required" ] || fail "missing required executable: $required"
done
[ ! -e "$local_path" ] && [ ! -L "$local_path" ] || fail "$local_path already exists"
[ ! -e "$vendor_path" ] && [ ! -L "$vendor_path" ] || fail "$vendor_path already exists"
[ ! -e "$vendor_override" ] && [ ! -L "$vendor_override" ] || \
    fail "$vendor_override already exists"
[ ! -e "$symlink_path" ] && [ ! -L "$symlink_path" ] || fail "$symlink_path already exists"

snapshot_authselect >"$snapshot_dir/authselect.before"
snapshot_pam_root >"$snapshot_dir/pam-root.before"

printf '%s\n' \
    '#%PAM-1.0' \
    'auth      required pam_unix.so' \
    'account   required pam_permit.so' \
    >"$local_path"
chmod 0644 "$local_path"
snapshot_file "$local_path" >"$snapshot_dir/local.before"

/usr/bin/facelock pam add --service "$local_service" --no-confirm >/dev/null
grep -qxF 'auth      sufficient pam_facelock.so' "$local_path" || \
    fail "local leaf is missing the Facelock rule"
grep -qxF 'auth      required pam_unix.so' "$local_path" || \
    fail "local leaf lost its password fallback"
pass "service-scoped PAM setup succeeds on an RPM install"

authselect_is_unchanged || fail "service-scoped setup changed authselect state"
pass "service-scoped PAM setup leaves authselect selection unchanged"
pass "service-scoped PAM setup leaves shared authselect PAM files unchanged"
snapshot_pam_root | cmp -s - "$snapshot_dir/pam-root.before" || \
    fail "service-scoped setup changed an unrelated PAM service"
pass "service-scoped PAM setup edits only the requested leaf service"

# The PAM module asks the system daemon first. Give that daemon the same
# container-only camera path used by the general package validator so D-Bus
# activation does not fail early on the deliberately camera-less fixture.
if ! grep -q '^path\s*=' /etc/facelock/config.toml; then
    sed -i '/^\[device\]/a path = "/dev/video0"' /etc/facelock/config.toml
fi

authenticate test || {
    authenticate_diagnostics
    fail "correct password did not fall through after Facelock rejection"
}
if authenticate wrong-password; then
    authenticate_diagnostics
    fail "wrong password authenticated through the configured leaf"
fi
pass "correct password falls through after Facelock rejection"

# Leave the following package validator an independent daemon-start boundary.
systemctl stop facelock-daemon.service >/dev/null 2>&1 || true
systemctl reset-failed facelock-daemon.service >/dev/null 2>&1 || true

/usr/bin/facelock pam remove --service "$local_service" --no-confirm >/dev/null
snapshot_file "$local_path" | cmp -s - "$snapshot_dir/local.before" || \
    fail "local leaf was not restored byte-for-byte with its metadata"
authselect_is_unchanged || fail "local leaf removal changed authselect state"
pass "service-scoped PAM removal restores the requested leaf"
authenticate test || {
    authenticate_diagnostics
    fail "correct password failed after service-scoped PAM removal"
}
if authenticate wrong-password; then
    authenticate_diagnostics
    fail "wrong password authenticated after service-scoped PAM removal"
fi
pass "service-scoped PAM removal preserves password success and rejection"

install -d -m0755 /usr/lib/pam.d
printf '%s\n' \
    '#%PAM-1.0' \
    'auth      required pam_unix.so' \
    'account   required pam_permit.so' \
    >"$vendor_path"
chmod 0644 "$vendor_path"
snapshot_file "$vendor_path" >"$snapshot_dir/vendor.before"

/usr/bin/facelock pam add --service "$vendor_service" --no-confirm >/dev/null
[ -f "$vendor_override" ] && [ ! -L "$vendor_override" ] || \
    fail "vendor-only setup did not create a regular local override"
grep -qxF 'auth      sufficient pam_facelock.so' "$vendor_override" || \
    fail "vendor-only local override is missing the Facelock rule"
snapshot_file "$vendor_path" | cmp -s - "$snapshot_dir/vendor.before" || \
    fail "vendor-only setup changed the vendor service"
authselect_is_unchanged || fail "vendor-only setup changed authselect state"
pass "vendor-only leaf setup leaves the vendor service unchanged"

/usr/bin/facelock pam remove --service "$vendor_service" --no-confirm >/dev/null
[ ! -e "$vendor_override" ] && [ ! -L "$vendor_override" ] || \
    fail "vendor-only removal retained the unchanged Facelock-created override"
snapshot_file "$vendor_path" | cmp -s - "$snapshot_dir/vendor.before" || \
    fail "vendor-only removal changed the vendor service"
authselect_is_unchanged || fail "vendor-only removal changed authselect state"
pass "vendor-only leaf removal retires the unchanged Facelock override"

printf '%s\n' '# administrator-owned PAM sentinel' >"$outside_path"
outside_hash="$(sha256sum "$outside_path" | awk '{print $1}')"
ln -s "$outside_path" "$symlink_path"
if /usr/bin/facelock pam add --service "$symlink_service" --no-confirm \
    >/dev/null 2>&1; then
    fail "outbound PAM service symlink was accepted"
fi
[ "$(sha256sum "$outside_path" | awk '{print $1}')" = "$outside_hash" ] || \
    fail "outbound symlink target was changed"
authselect_is_unchanged || fail "symlink refusal changed authselect state"
pass "outbound PAM service symlink is refused"

printf '\n=== RPM service-scoped PAM results: %d passed, 0 failed ===\n' "$pass_count"
