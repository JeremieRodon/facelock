#!/usr/bin/env bash
# Booted Debian/Ubuntu proof for the exact candidate .deb. The package is
# mounted read-only at runtime; it is never installed while the image is built.
set -euo pipefail

PACKAGE=/facelock-test-package.deb
STATE_ROOT=/run/facelock-deb-lifecycle
PAM_SERVICE=facelock-deb-lifecycle
PAM_PATH="/etc/pam.d/$PAM_SERVICE"
PAM_RETAINED=/var/lib/facelock/pam-backups/lifecycle-retained-provenance
EXTERNAL_SENTINEL=/srv/facelock-lifecycle-external
COMMON_AUTH=/etc/pam.d/common-auth
APT_LOG=/tmp/facelock-deb-lifecycle-apt.log
DB_HOLDER_PID=

phase="${1:-}"
case "$phase" in
    install|install-remove-reinstall|versioned-upgrade-inactive|versioned-upgrade-active|purge) ;;
    *)
        echo "usage: $0 {install|install-remove-reinstall|versioned-upgrade-inactive|versioned-upgrade-active|purge}" >&2
        exit 2
        ;;
esac

fail() {
    echo "FAIL [Debian $phase lifecycle]: $*" >&2
    exit 1
}

pass() {
    printf 'TEST: Debian %s ... PASS\n' "$1"
}

assert_eq() {
    local expected="$1" actual="$2" label="$3"
    [ "$actual" = "$expected" ] ||
        fail "$label: expected '$expected', got '$actual'"
}

assert_regular() {
    local path="$1"
    [ -f "$path" ] && [ ! -L "$path" ] || fail "not a regular file: $path"
}

record_failure() {
    echo "FAIL [Debian $phase lifecycle]: $*" >&2
    failed=1
}

assert_trusted_inert_anchor() {
    local root="$1" expected_mode="$2"
    local mount_target

    if [ ! -d "$root" ] || [ -L "$root" ]; then
        record_failure "fixed root is not an inert directory anchor: $root"
        return
    fi
    if [ "$(stat -c '%a:%u:%g' -- "$root")" != "$expected_mode:0:0" ]; then
        record_failure \
            "fixed root has unsafe metadata: $root ($(stat -c '%a:%u:%g' -- "$root"))"
    fi
    if [ "$(stat -c %d -- "$root")" != "$(stat -c %d -- "$(dirname "$root")")" ]; then
        record_failure "fixed root crosses its parent device: $root"
    fi
    mount_target="$(findmnt -n -o TARGET --target "$root")"
    if [ "$mount_target" = "$root" ]; then
        record_failure "fixed root is a mount point: $root"
    fi
}

assert_absent_or_trusted_inert_anchor() {
    local root="$1" expected_mode="$2"

    if [ ! -e "$root" ] && [ ! -L "$root" ]; then
        return
    fi
    assert_trusted_inert_anchor "$root" "$expected_mode"
}

assert_no_purge_eligible_children() {
    local root="$1" path allowed candidate
    shift

    if [ ! -e "$root" ] && [ ! -L "$root" ]; then
        return
    fi

    while IFS= read -r -d '' path; do
        allowed=0
        for candidate in "$@"; do
            if [ "$path" = "$candidate" ]; then
                allowed=1
                break
            fi
        done
        if [ "$allowed" -eq 0 ]; then
            record_failure "purge-eligible child survived below $root: $path"
        fi
    done < <(find "$root" -xdev -mindepth 1 -print0)
}

artifact_hash() {
    sha256sum -- "$PACKAGE" | cut -d' ' -f1
}

assert_exact_artifact_mount() {
    local mount_target mount_options
    assert_regular "$PACKAGE"
    mount_target="$(findmnt -n -o TARGET --target "$PACKAGE")"
    assert_eq "$PACKAGE" "$mount_target" "candidate mount target"
    mount_options="$(findmnt -n -o OPTIONS --target "$PACKAGE")"
    case ",$mount_options," in
        *,ro,*) ;;
        *) fail "candidate package mount is writable: $mount_options" ;;
    esac
    [ "$(stat -c %a "$PACKAGE")" = 444 ] ||
        fail "candidate package must be emitted mode 0444"
    assert_eq facelock "$(dpkg-deb --field "$PACKAGE" Package)" \
        "candidate package name"
}

assert_dpkg_healthy() {
    local audit
    audit="$(dpkg --audit)"
    [ -z "$audit" ] || fail "dpkg reports an incomplete transaction: $audit"
}

assert_no_repair_masking() {
    if grep -Eqi \
        'correcting dependencies|fix-broken|unmet dependencies|dependency problems - leaving unconfigured' \
        "$APT_LOG"; then
        cat "$APT_LOG" >&2
        fail "APT repaired or masked an incomplete package transaction"
    fi
}

apt_transaction() {
    : >"$APT_LOG"
    DEBIAN_FRONTEND=noninteractive apt-get update >>"$APT_LOG" 2>&1
    if ! DEBIAN_FRONTEND=noninteractive apt-get "$@" >>"$APT_LOG" 2>&1; then
        cat "$APT_LOG" >&2
        fail "APT transaction failed: apt-get $*"
    fi
    assert_no_repair_masking
    assert_dpkg_healthy
}

assert_not_installed() {
    if dpkg-query -W -f='${db:Status-Status}\n' facelock 2>/dev/null |
        grep -qx installed; then
        fail "facelock was installed before the runtime transaction"
    fi
}

assert_installed_candidate() {
    local expected_version actual_version
    expected_version="$(dpkg-deb --field "$PACKAGE" Version)"
    actual_version="$(dpkg-query -W -f='${Version}' facelock)"
    assert_eq "$expected_version" "$actual_version" "installed candidate version"
    assert_eq installed \
        "$(dpkg-query -W -f='${db:Status-Status}' facelock)" \
        "installed candidate status"
}

assert_installed_payload_metadata() {
    local data_tar
    data_tar="$(mktemp "${TMPDIR:-/tmp}/facelock-installed-data.XXXXXX.tar")"
    dpkg-deb --fsys-tarfile "$PACKAGE" >"$data_tar"
    if ! python3 - "$data_tar" <<'PY'
import hashlib
import os
import stat
import subprocess
import sys
import tarfile


def normalized_path(raw):
    name = raw
    while name.startswith("./"):
        name = name[2:]
    if not name or name == ".":
        return None
    parts = name.split("/")
    if name.startswith("/") or any(part in ("", ".", "..") for part in parts):
        raise SystemExit(f"unsafe package data path: {raw}")
    return "/" + name


def dpkg_attributes_path(search_output, package, path):
    for owner_line in search_output.splitlines():
        owner_list, separator, owned_path = owner_line.rpartition(": ")
        if not separator or owned_path != path:
            continue
        for package_spec in owner_list.split(", "):
            if package_spec.split(":", 1)[0] == package:
                return True
    return False


if not dpkg_attributes_path(
    "base-files, libc6:amd64, facelock: /etc", "facelock", "/etc"
):
    raise SystemExit("shared parent directory ownership parser regression")
if dpkg_attributes_path(
    "base-files, libc6:amd64: /etc", "facelock", "/etc"
):
    raise SystemExit("shared parent directory ownership false positive")


listed = subprocess.run(
    ["dpkg-query", "-L", "facelock"],
    check=True,
    text=True,
    stdout=subprocess.PIPE,
).stdout.splitlines()
listed_paths = {path.rstrip("/") or "/" for path in listed if path not in ("", "/.")}
checked = 0
archive_paths = set()
with tarfile.open(sys.argv[1], mode="r:") as archive:
    members = archive.getmembers()
    for member in members:
        path = normalized_path(member.name)
        if path is None:
            continue
        archive_paths.add(path.rstrip("/") or "/")
        ownership = subprocess.run(
            ["dpkg-query", "--search", "--", path],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if ownership.returncode != 0 or not dpkg_attributes_path(
            ownership.stdout, "facelock", path
        ):
            raise SystemExit(f"dpkg does not attribute package payload to facelock: {path}")
        package_private_directories = (
            "/etc/facelock",
            "/usr/lib/facelock",
            "/usr/share/doc/facelock",
            "/usr/share/facelock",
        )
        if member.isdir() and not any(
            path == root or path.startswith(root + "/")
            for root in package_private_directories
        ):
            # dpkg data archives repeat shared ancestor directories. Native
            # usrmerge may resolve one of those through a system-owned symlink,
            # so its live metadata is not exclusively controlled by Facelock.
            continue
        info = os.lstat(path)
        actual_mode = stat.S_IMODE(info.st_mode)
        expected_mode = member.mode & 0o7777
        if (info.st_uid, info.st_gid) != (member.uid, member.gid):
            raise SystemExit(
                f"installed owner differs from package archive: {path}: "
                f"{info.st_uid}:{info.st_gid} != {member.uid}:{member.gid}"
            )
        if (member.uid, member.gid) != (0, 0):
            raise SystemExit(f"package data is not root-owned: {path}")
        if actual_mode != expected_mode:
            raise SystemExit(
                f"installed mode differs from package archive: {path}: "
                f"{actual_mode:o} != {expected_mode:o}"
            )
        if not member.issym() and actual_mode & 0o022:
            raise SystemExit(f"package data is group/world writable: {path}")
        if member.isdir():
            if not stat.S_ISDIR(info.st_mode):
                raise SystemExit(f"installed package directory changed type: {path}")
        elif member.isfile():
            if not stat.S_ISREG(info.st_mode):
                raise SystemExit(f"installed package file changed type: {path}")
            archived = archive.extractfile(member)
            if archived is None:
                raise SystemExit(f"package archive file cannot be read: {path}")
            archived_hash = hashlib.sha256(archived.read()).hexdigest()
            descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                live_info = os.fstat(descriptor)
                if (live_info.st_dev, live_info.st_ino) != (info.st_dev, info.st_ino):
                    raise SystemExit(f"installed package file changed during proof: {path}")
                live_hash = hashlib.sha256()
                while chunk := os.read(descriptor, 1024 * 1024):
                    live_hash.update(chunk)
            finally:
                os.close(descriptor)
            if live_hash.hexdigest() != archived_hash:
                raise SystemExit(f"installed package file bytes differ from archive: {path}")
        elif member.issym():
            if not stat.S_ISLNK(info.st_mode) or os.readlink(path) != member.linkname:
                raise SystemExit(f"installed package symlink differs: {path}")
        elif member.islnk():
            target = normalized_path(member.linkname)
            if target is None or not stat.S_ISREG(info.st_mode) or not os.path.samefile(path, target):
                raise SystemExit(f"installed package hard link differs: {path}")
        else:
            raise SystemExit(f"unsupported package data type: {path}")
        checked += 1
if archive_paths != listed_paths:
    missing = sorted(archive_paths - listed_paths)
    extra = sorted(listed_paths - archive_paths)
    raise SystemExit(
        "dpkg package list differs from data archive: "
        f"missing={missing!r}, extra={extra!r}"
    )
if checked == 0:
    raise SystemExit("package data archive is empty")
print(f"verified {checked} installed package paths and dpkg ownership against archive metadata and bytes")
PY
    then
        rm -f -- "$data_tar"
        fail "installed package ownership/mode/type metadata is unsafe or differs from the candidate"
    fi
    rm -f -- "$data_tar"
}

snapshot_file() {
    local path="$1"
    assert_regular "$path"
    stat -c '%n|%F|%a|%u|%g|%s' -- "$path"
    sha256sum -- "$path"
}

snapshot_enrollment_database_state() {
    python3 - <<'PY'
import hashlib
import sqlite3


connection = sqlite3.connect(
    "file:/var/lib/facelock/facelock.db?mode=ro", uri=True
)
model_count = connection.execute(
    "SELECT COUNT(*) FROM face_models"
).fetchone()[0]
embedding_count = connection.execute(
    "SELECT COUNT(*) FROM face_embeddings"
).fetchone()[0]
rows = connection.execute(
    "SELECT fm.user, fm.label, fm.created_at, fm.embedder_model, "
    "fm.device_id, fe.embedding, fe.sealed "
    "FROM face_models AS fm "
    "JOIN face_embeddings AS fe ON fe.model_id = fm.id "
    "WHERE fm.user = ? ORDER BY fm.id, fe.id",
    ("testuser",),
).fetchall()
connection.close()

if (model_count, embedding_count) != (1, 1):
    raise SystemExit(
        "expected exactly one model and one embedding row, got "
        f"models={model_count}, embeddings={embedding_count}"
    )
if len(rows) != 1:
    raise SystemExit(
        f"expected exactly one authoritative testuser enrollment row, got {len(rows)}"
    )
user, label, created_at, embedder_model, device_id, embedding, sealed = rows[0]
expected = ("testuser", "lifecycle-retained", 1700000000, "", None, 0)
actual = (user, label, created_at, embedder_model, device_id, sealed)
if actual != expected:
    raise SystemExit(f"unexpected authoritative enrollment metadata: {actual!r}")
if len(embedding) != 512 * 4:
    raise SystemExit(f"unexpected enrollment embedding size: {len(embedding)}")
embedding_digest = hashlib.sha256(embedding).hexdigest()
expected_embedding_digest = (
    "82a0081de4c338fc91c362ed4d2ab615bca1dd45152aaa713322b5482078ddee"
)
if embedding_digest != expected_embedding_digest:
    raise SystemExit(
        f"unexpected enrollment embedding digest: {embedding_digest}"
    )
print(
    "enrollment-row|"
    f"user={user}|label={label}|created_at={created_at}|"
    f"embedder_model={embedder_model}|device_id=null|sealed={sealed}|"
    f"embedding_sha256={embedding_digest}"
)
PY
}

snapshot_enrollment_marker() {
    local path="$1" expected_uid expected_gid
    assert_regular "$path"
    expected_uid="$(id -u testuser)"
    expected_gid="$(id -g testuser)"
    assert_eq "600:$expected_uid:$expected_gid" \
        "$(stat -c '%a:%u:%g' -- "$path")" \
        "enrollment marker metadata for $path"
    python3 - "$path" "$expected_uid" "$expected_gid" <<'PY'
import datetime
import json
import os
import stat
import sys


path = sys.argv[1]
expected_uid = int(sys.argv[2])
expected_gid = int(sys.argv[3])
descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
try:
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise SystemExit(f"enrollment marker is not a single-link regular file: {path}")
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise SystemExit(f"enrollment marker has wrong mode: {path}")
    if (info.st_uid, info.st_gid) != (expected_uid, expected_gid):
        raise SystemExit(f"enrollment marker has wrong owner: {path}")
    with os.fdopen(descriptor, encoding="utf-8") as handle:
        descriptor = -1
        marker = json.load(handle)
finally:
    if descriptor >= 0:
        os.close(descriptor)

if set(marker) != {"models", "updated"}:
    raise SystemExit(f"enrollment marker has unexpected fields: {sorted(marker)!r}")
if type(marker["models"]) is not int or marker["models"] != 1:
    raise SystemExit(f"enrollment marker has wrong model count: {marker['models']!r}")
updated = marker["updated"]
if not isinstance(updated, str) or not updated:
    raise SystemExit("enrollment marker timestamp is empty or not a string")
try:
    parsed = datetime.datetime.fromisoformat(updated.replace("Z", "+00:00"))
except ValueError as error:
    raise SystemExit(f"enrollment marker timestamp is invalid: {updated!r}") from error
if parsed.tzinfo is None:
    raise SystemExit(f"enrollment marker timestamp has no timezone: {updated!r}")

print(
    f"{path}|regular file|600|{expected_uid}|{expected_gid}|"
    "models=1|updated=valid"
)
PY
}

snapshot_retained_state() {
    local path
    for path in \
        /etc/facelock/config.toml \
        /etc/facelock/encryption.key \
        /etc/facelock/encryption.key.sealed \
        /var/lib/facelock/facelock.db \
        /var/lib/facelock/facelock.db-wal \
        /var/lib/facelock/facelock.db-shm \
        /var/lib/facelock/models/lifecycle-model.onnx \
        /var/lib/facelock/enrolled/testuser \
        /var/lib/facelock/setup.complete \
        "$PAM_RETAINED" \
        /var/log/facelock/audit.jsonl \
        /var/log/facelock/snapshots/lifecycle.jpg; do
        snapshot_file "$path"
    done
}

snapshot_versioned_upgrade_state() {
    local path

    for path in \
        /etc/facelock/config.toml \
        /etc/facelock/encryption.key \
        /etc/facelock/encryption.key.sealed \
        /var/lib/facelock/facelock.db \
        /var/lib/facelock/setup.complete \
        "$PAM_RETAINED" \
        /var/log/facelock/audit.jsonl \
        /var/log/facelock/snapshots/lifecycle.jpg; do
        snapshot_file "$path"
    done
    snapshot_enrollment_database_state
    snapshot_enrollment_marker /var/lib/facelock/enrolled/testuser
    while IFS= read -r path; do
        snapshot_file "$path"
    done < <(
        find /etc/facelock /var/lib/facelock /var/log/facelock \
            -xdev -maxdepth 1 -type f \
            -name 'lifecycle-versioned-upgrade-*' -print |
            LC_ALL=C sort
    )
}

make_lower_package() {
    local label="$1" label_token candidate_version lower_root

    label_token="${label//-/}"
    candidate_version="$(dpkg-deb --field "$PACKAGE" Version)"
    lower_version="${candidate_version}~facelock.${label_token}"
    dpkg --compare-versions "$lower_version" lt "$candidate_version" ||
        fail "controlled upgrade seed is not older: $lower_version >= $candidate_version"
    lower_root="$STATE_ROOT/lower-$label"
    lower_package="$STATE_ROOT/facelock-$label-lower.deb"
    [ ! -e "$lower_root" ] && [ ! -e "$lower_package" ] ||
        fail "controlled lower-version fixture already exists: $label"
    dpkg-deb --raw-extract "$PACKAGE" "$lower_root"
    sed -i -E "s/^Version:.*/Version: $lower_version/" "$lower_root/DEBIAN/control"
    [ "$(sed -n 's/^Version: //p' "$lower_root/DEBIAN/control")" = "$lower_version" ] ||
        fail "could not set controlled lower package version"
    dpkg-deb --build --root-owner-group "$lower_root" "$lower_package" >/dev/null
    [ "$(dpkg-deb --field "$lower_package" Version)" = "$lower_version" ] ||
        fail "rebuilt upgrade seed has the wrong version"
}

create_versioned_upgrade_state() {
    local label="$1" path

    install -d -m0755 /etc/facelock
    install -d -m0711 /var/lib/facelock
    install -d -m0700 /var/lib/facelock/pam-backups /var/log/facelock
    if [ ! -e "$PAM_RETAINED" ] && [ ! -L "$PAM_RETAINED" ]; then
        printf '%s\n' retained-provenance >"$PAM_RETAINED"
        chmod 0600 "$PAM_RETAINED"
    fi
    for path in \
        "/etc/facelock/lifecycle-versioned-upgrade-$label" \
        "/var/lib/facelock/lifecycle-versioned-upgrade-$label" \
        "/var/log/facelock/lifecycle-versioned-upgrade-$label"; do
        printf '%s\n' "$label retained state" >"$path"
        chmod 0600 "$path"
    done
}

exercise_one_versioned_upgrade() {
    local activity="$1" enablement="$2" label before_hash candidate_version
    local before_start="" after_start="" actual_enablement

    label="$activity-$enablement"
    assert_installed_candidate
    before_hash="$(artifact_hash)"
    candidate_version="$(dpkg-deb --field "$PACKAGE" Version)"

    apt_transaction remove -y facelock
    assert_not_installed
    make_lower_package "$label"
    apt_transaction install -y --no-install-recommends "$lower_package"
    assert_eq "$lower_version" "$(dpkg-query -W -f='${Version}' facelock)" \
        "controlled lower package version"

    case "$enablement" in
        enabled) systemctl enable facelock-daemon.service >/dev/null ;;
        disabled) systemctl disable facelock-daemon.service >/dev/null 2>&1 || true ;;
        *) fail "invalid versioned-upgrade enablement fixture: $enablement" ;;
    esac
    case "$activity" in
        active)
            if ! grep -Eq '^[[:space:]]*path[[:space:]]*=' /etc/facelock/config.toml; then
                sed -i '/^\[device\]/a path = "/dev/video0"' /etc/facelock/config.toml
            fi
            systemctl start facelock-daemon.service
            systemctl is-active --quiet facelock-daemon.service ||
                fail "controlled lower-version daemon did not start"
            before_start="$(systemctl show -p ExecMainStartTimestampMonotonic --value \
                facelock-daemon.service)"
            ;;
        inactive)
            systemctl stop facelock-daemon.service >/dev/null 2>&1 || true
            ! systemctl is-active --quiet facelock-daemon.service ||
                fail "controlled lower-version daemon remained active"
            ;;
        *) fail "invalid versioned-upgrade activity fixture: $activity" ;;
    esac
    actual_enablement="$(systemctl is-enabled facelock-daemon.service 2>/dev/null || true)"
    assert_eq "$enablement" "$actual_enablement" \
        "controlled lower-version service enablement"

    create_versioned_upgrade_state "$label"
    snapshot_versioned_upgrade_state >"$STATE_ROOT/upgrade-$label.before"
    apt_transaction install -y --no-install-recommends "$PACKAGE"
    grep -Fq "Unpacking facelock ($candidate_version) over ($lower_version)" "$APT_LOG" || {
        cat "$APT_LOG" >&2
        fail "APT did not report a genuine lower-to-candidate versioned upgrade"
    }
    assert_installed_candidate
    snapshot_versioned_upgrade_state >"$STATE_ROOT/upgrade-$label.after"
    cmp -s "$STATE_ROOT/upgrade-$label.before" "$STATE_ROOT/upgrade-$label.after" || {
        diff -u "$STATE_ROOT/upgrade-$label.before" \
            "$STATE_ROOT/upgrade-$label.after" >&2 || true
        fail "versioned upgrade changed retained state: $label"
    }
    assert_eq "$before_hash" "$(artifact_hash)" \
        "candidate artifact digest after versioned upgrade"
    actual_enablement="$(systemctl is-enabled facelock-daemon.service 2>/dev/null || true)"
    assert_eq "$enablement" "$actual_enablement" \
        "candidate service enablement after versioned upgrade"
    if [ "$activity" = active ]; then
        systemctl is-active --quiet facelock-daemon.service ||
            fail "active daemon stopped across versioned upgrade"
        after_start="$(systemctl show -p ExecMainStartTimestampMonotonic --value \
            facelock-daemon.service)"
        [ -n "$before_start" ] && [ -n "$after_start" ] &&
            [ "$before_start" != "$after_start" ] ||
            fail "active daemon was not restarted by the versioned upgrade"
    else
        ! systemctl is-active --quiet facelock-daemon.service ||
            fail "inactive daemon started across versioned upgrade"
    fi
    pass "genuine $activity/$enablement lower-to-candidate upgrade"
}

restore_validator_service_baseline() {
    systemctl stop facelock-daemon.service >/dev/null 2>&1 || true
    systemctl disable facelock-daemon.service >/dev/null 2>&1 || true
    ! systemctl is-active --quiet facelock-daemon.service ||
        fail "daemon remained active after the versioned-upgrade matrix"
    assert_eq disabled \
        "$(systemctl is-enabled facelock-daemon.service 2>/dev/null || true)" \
        "service enablement after the versioned-upgrade matrix"
}

exercise_versioned_upgrade_matrix() {
    local activity="$1" enablement

    for enablement in disabled enabled; do
        exercise_one_versioned_upgrade "$activity" "$enablement"
    done
    # The inactive and active phases together prove that a genuine, ordered
    # versioned upgrade preserves active/inactive and enabled/disabled state.
    # Leave the exact candidate in the fresh-install state expected by the
    # shared package validator; the matrix assertions above have already
    # captured and compared every requested service state across the upgrade.
    restore_validator_service_baseline
}

assert_tmpfiles_layout() {
    local expected path
    while read -r expected path; do
        [ -d "$path" ] && [ ! -L "$path" ] || fail "tmpfiles directory missing: $path"
        assert_eq "$expected" "$(stat -c '%a:%u:%g' "$path")" \
            "tmpfiles metadata for $path"
    done <<'EOF'
755:0:0 /run/facelock
711:0:0 /var/lib/facelock
755:0:0 /var/lib/facelock/models
711:0:0 /var/lib/facelock/enrolled
700:0:0 /var/lib/facelock/pam-backups
700:0:0 /var/log/facelock
700:0:0 /var/log/facelock/snapshots
EOF
}

assert_static_payload_absent() {
    local path
    for path in \
        /usr/bin/facelock \
        /lib/security/pam_facelock.so \
        /usr/lib/security/pam_facelock.so \
        /usr/lib/systemd/system/facelock-daemon.service \
        /usr/share/dbus-1/system.d/org.facelock.Daemon.conf \
        /usr/share/dbus-1/system-services/org.facelock.Daemon.service \
        /usr/lib/tmpfiles.d/facelock.conf \
        /usr/share/pam-configs/facelock \
        /usr/lib/facelock/libonnxruntime.so; do
        [ ! -e "$path" ] && [ ! -L "$path" ] ||
            fail "package-owned static payload survived removal: $path"
    done
}

assert_password_fallback() {
    printf '%s\n' test |
        timeout --foreground 30 pamtester "$PAM_SERVICE" testuser authenticate \
            >/dev/null 2>&1 ||
        fail "correct password did not succeed after biometric failure"
    if printf '%s\n' wrong-password |
        timeout --foreground 30 pamtester "$PAM_SERVICE" testuser authenticate \
            >/dev/null 2>&1; then
        fail "wrong password authenticated through $PAM_SERVICE"
    fi
}

fresh_install() {
    local common_hash common_metadata before_hash
    assert_exact_artifact_mount
    assert_not_installed
    before_hash="$(artifact_hash)"
    common_hash="$(sha256sum "$COMMON_AUTH" | cut -d' ' -f1)"
    common_metadata="$(stat -c '%a:%u:%g' "$COMMON_AUTH")"

    apt_transaction install -y --no-install-recommends "$PACKAGE"

    assert_installed_candidate
    assert_installed_payload_metadata
    assert_eq "$before_hash" "$(artifact_hash)" "candidate artifact digest after install"
    assert_eq "$common_hash" "$(sha256sum "$COMMON_AUTH" | cut -d' ' -f1)" \
        "common-auth bytes after fresh install"
    assert_eq "$common_metadata" "$(stat -c '%a:%u:%g' "$COMMON_AUTH")" \
        "common-auth metadata after fresh install"
    ! grep -q pam_facelock.so "$COMMON_AUTH" ||
        fail "fresh install activated Facelock in common-auth"
    assert_tmpfiles_layout
    if [ -d /run/systemd/system ]; then
        [ "$(systemctl is-enabled facelock-daemon.service 2>/dev/null || true)" = disabled ] ||
            fail "fresh install enabled facelock-daemon"
        ! systemctl is-active --quiet facelock-daemon.service ||
            fail "fresh install started facelock-daemon"
    fi
    touch /facelock-common-auth-install-invariant
    pass "exact artifact installs at runtime without PAM or service activation"
}

create_retained_state() {
    local auth_status=0

    printf '\n# facelock lifecycle administrator marker\n' >>/etc/facelock/config.toml
    if ! grep -Eq '^[[:space:]]*path[[:space:]]*=' /etc/facelock/config.toml; then
        sed -i '/^\[device\]/a path = "/dev/video0"' /etc/facelock/config.toml
    fi
    facelock auth --user testuser >/dev/null 2>&1 || auth_status=$?
    assert_eq 2 "$auth_status" \
        "one-shot fixture initialization for an unenrolled user"
    if [ ! -s /etc/facelock/encryption.key ]; then
        dd if=/dev/urandom of=/etc/facelock/encryption.key bs=32 count=1 status=none
    fi
    chmod 0600 /etc/facelock/encryption.key
    printf '%s\n' sealed-key > /etc/facelock/encryption.key.sealed
    chmod 0600 /etc/facelock/encryption.key.sealed
    python3 - "$STATE_ROOT/database.ready" "$STATE_ROOT/database.stop" <<'PY' &
import pathlib
import sqlite3
import struct
import sys
import time

ready = pathlib.Path(sys.argv[1])
stop = pathlib.Path(sys.argv[2])
connection = sqlite3.connect("/var/lib/facelock/facelock.db")
connection.execute("PRAGMA journal_mode=WAL")
connection.execute(
    "CREATE TABLE IF NOT EXISTS lifecycle_retained "
    "(value TEXT NOT NULL)"
)
connection.execute(
    "INSERT INTO lifecycle_retained (value) VALUES (?)",
    ("ordinary-remove-preservation",),
)
connection.execute(
    "INSERT INTO face_models "
    "(user, label, created_at, embedder_model, device_id) "
    "VALUES (?, ?, ?, ?, ?)",
    ("testuser", "lifecycle-retained", 1700000000, "", None),
)
model_id = connection.execute(
    "SELECT id FROM face_models WHERE user = ? AND label = ?",
    ("testuser", "lifecycle-retained"),
).fetchone()[0]
embedding = struct.pack("<512f", *((index + 1) / 512 for index in range(512)))
connection.execute(
    "INSERT INTO face_embeddings (model_id, embedding, sealed) VALUES (?, ?, ?)",
    (model_id, embedding, 0),
)
connection.commit()
ready.touch()
while not stop.exists():
    time.sleep(0.1)
connection.close()
PY
    DB_HOLDER_PID=$!
    for _ in $(seq 1 100); do
        if [ -f "$STATE_ROOT/database.ready" ] &&
           [ -s /var/lib/facelock/facelock.db-wal ] &&
           [ -s /var/lib/facelock/facelock.db-shm ]; then
            break
        fi
        sleep 0.1
    done
    [ -f "$STATE_ROOT/database.ready" ] || fail "SQLite fixture did not become ready"
    [ -s /var/lib/facelock/facelock.db-wal ] || fail "SQLite WAL fixture is empty"
    [ -s /var/lib/facelock/facelock.db-shm ] || fail "SQLite SHM fixture is empty"
    chmod 0600 /var/lib/facelock/facelock.db*
    printf '%s\n' model > /var/lib/facelock/models/lifecycle-model.onnx
    chmod 0644 /var/lib/facelock/models/lifecycle-model.onnx
    printf '%s\n' \
        '{"models":1,"updated":"2026-01-01T00:00:00Z"}' \
        > /var/lib/facelock/enrolled/testuser
    chown testuser:testuser /var/lib/facelock/enrolled/testuser
    chmod 0600 /var/lib/facelock/enrolled/testuser
    printf '%s\n' complete > /var/lib/facelock/setup.complete
    chmod 0600 /var/lib/facelock/setup.complete
    printf '%s\n' retained-provenance >"$PAM_RETAINED"
    chmod 0600 "$PAM_RETAINED"
    printf '%s\n' audit > /var/log/facelock/audit.jsonl
    printf '%s\n' snapshot > /var/log/facelock/snapshots/lifecycle.jpg
    chmod 0600 /var/log/facelock/audit.jsonl \
        /var/log/facelock/snapshots/lifecycle.jpg
}

exercise_remove_reinstall() {
    local before_hash backup common_hash common_metadata leaf_hash leaf_metadata
    install -Dm0644 /dev/stdin "$PAM_PATH" <<'EOF'
#%PAM-1.0
auth      required pam_unix.so
account   required pam_permit.so
EOF
    leaf_hash="$(sha256sum "$PAM_PATH" | cut -d' ' -f1)"
    leaf_metadata="$(stat -c '%a:%u:%g' "$PAM_PATH")"
    common_hash="$(sha256sum "$COMMON_AUTH" | cut -d' ' -f1)"
    common_metadata="$(stat -c '%a:%u:%g' "$COMMON_AUTH")"
    facelock pam add --service "$PAM_SERVICE" --no-confirm >/dev/null
    grep -q pam_facelock.so "$PAM_PATH" || fail "direct PAM setup did not edit $PAM_PATH"
    assert_password_fallback
    backup="$(find /var/lib/facelock/pam-backups -maxdepth 1 -type f \
        -name "$PAM_SERVICE.*" ! -name '*.json' -print -quit)"
    [ -n "$backup" ] && [ -f "$backup.json" ] ||
        fail "direct PAM setup did not create backup and provenance"

    # pamtester may D-Bus activate the daemon while proving password fallback.
    # Stop it before materializing byte-exact database sidecars: an open SQLite
    # connection is otherwise allowed to checkpoint and remove an idle WAL.
    if [ -d /run/systemd/system ]; then
        systemctl stop facelock-daemon.service
    fi
    install -d -m0700 "$STATE_ROOT"
    create_retained_state
    snapshot_retained_state >"$STATE_ROOT/retained.before"
    before_hash="$(artifact_hash)"
    if [ -d /run/systemd/system ]; then
        systemctl enable facelock-daemon.service >/dev/null
    fi

    apt_transaction remove -y facelock

    assert_not_installed
    assert_static_payload_absent
    snapshot_retained_state >"$STATE_ROOT/retained.after-remove"
    cmp -s "$STATE_ROOT/retained.before" "$STATE_ROOT/retained.after-remove" || {
        diff -u "$STATE_ROOT/retained.before" "$STATE_ROOT/retained.after-remove" >&2 || true
        fail "ordinary removal changed retained biometric, configuration, or PAM state"
    }
    assert_eq "$leaf_hash" "$(sha256sum "$PAM_PATH" | cut -d' ' -f1)" \
        "direct PAM leaf bytes after removal"
    assert_eq "$leaf_metadata" "$(stat -c '%a:%u:%g' "$PAM_PATH")" \
        "direct PAM leaf metadata after removal"
    ! grep -q pam_facelock.so "$PAM_PATH" || fail "ordinary removal retained a direct PAM rule"
    [ ! -e "$backup" ] && [ ! -e "$backup.json" ] ||
        fail "successful direct PAM cleanup retained obsolete provenance"
    assert_eq "$common_hash" "$(sha256sum "$COMMON_AUTH" | cut -d' ' -f1)" \
        "common-auth bytes after ordinary removal"
    assert_eq "$common_metadata" "$(stat -c '%a:%u:%g' "$COMMON_AUTH")" \
        "common-auth metadata after ordinary removal"
    pass "ordinary remove deletes static payload and preserves all retained state"

    apt_transaction install -y --no-install-recommends "$PACKAGE"

    assert_installed_candidate
    assert_eq "$before_hash" "$(artifact_hash)" "candidate artifact digest after reinstall"
    snapshot_retained_state >"$STATE_ROOT/retained.after-reinstall"
    cmp -s "$STATE_ROOT/retained.before" "$STATE_ROOT/retained.after-reinstall" || {
        diff -u "$STATE_ROOT/retained.before" "$STATE_ROOT/retained.after-reinstall" >&2 || true
        fail "reinstall changed retained biometric, configuration, or PAM state"
    }
    touch "$STATE_ROOT/database.stop"
    wait "$DB_HOLDER_PID"
    python3 - <<'PY'
import sqlite3

connection = sqlite3.connect("/var/lib/facelock/facelock.db")
assert connection.execute("PRAGMA quick_check").fetchone() == ("ok",)
connection.close()
PY
    # This arbitrary payload proved model-file preservation, but it is not an
    # inference fixture. Remove it before the shared validator stages and loads
    # the checkout's reviewed ONNX models.
    rm -f /var/lib/facelock/models/lifecycle-model.onnx
    if [ -d /run/systemd/system ]; then
        systemctl is-enabled --quiet facelock-daemon.service ||
            fail "reinstall did not preserve administrator enablement"
        systemctl disable facelock-daemon.service >/dev/null
    fi
    assert_password_fallback
    pass "reinstall reuses retained state and the exact immutable artifact"
}

exercise_purge() {
    local before_hash failed=0 safe_child
    assert_exact_artifact_mount
    assert_not_installed
    before_hash="$(artifact_hash)"

    # The preceding package validator ends with ordinary remove. Add safe state
    # to every fixed root so purge cannot pass by inspecting empty directories.
    install -d -m0700 "$STATE_ROOT"
    install -d -m0755 /etc/facelock/lifecycle-purge-directory
    printf '%s\n' purge-etc > /etc/facelock/lifecycle-purge-directory/state
    chmod 0600 /etc/facelock/lifecycle-purge-directory/state
    install -d -m0700 /var/lib/facelock/pam-backups
    printf '%s\n' purge-pam >"$PAM_RETAINED"
    chmod 0600 "$PAM_RETAINED"
    install -d -m0755 /var/lib/facelock/lifecycle-purge-directory
    printf '%s\n' purge-db > /var/lib/facelock/lifecycle-purge-directory/state
    chmod 0600 /var/lib/facelock/lifecycle-purge-directory/state
    install -d -m0700 /var/log/facelock/snapshots
    printf '%s\n' purge-log > /var/log/facelock/snapshots/lifecycle-purge-state
    chmod 0600 /var/log/facelock/snapshots/lifecycle-purge-state
    printf '%s\n' external-sentinel >"$EXTERNAL_SENTINEL"
    chmod 0600 "$EXTERNAL_SENTINEL"
    snapshot_file "$PAM_RETAINED" >"$STATE_ROOT/pam-purge.before"
    snapshot_file "$EXTERNAL_SENTINEL" >"$STATE_ROOT/external-purge.before"

    apt_transaction purge -y facelock

    if dpkg-query -W facelock >/dev/null 2>&1; then
        echo "FAIL [Debian purge lifecycle]: dpkg retained a facelock package record" >&2
        failed=1
    fi
    for safe_child in \
        /etc/facelock/lifecycle-purge-directory/state \
        /etc/facelock/lifecycle-purge-directory \
        /var/lib/facelock/lifecycle-purge-directory/state \
        /var/lib/facelock/lifecycle-purge-directory \
        /var/log/facelock/snapshots/lifecycle-purge-state; do
        if [ -e "$safe_child" ] || [ -L "$safe_child" ]; then
            record_failure "known purge-eligible child survived: $safe_child"
        fi
    done
    # The helper never removes a compiled root. After it returns, dpkg may
    # remove the now-empty conffile parent that it owns at /etc/facelock.
    assert_absent_or_trusted_inert_anchor /etc/facelock 755
    assert_trusted_inert_anchor /var/lib/facelock 711
    assert_trusted_inert_anchor /var/log/facelock 700
    assert_trusted_inert_anchor /var/lib/facelock/pam-backups 700
    assert_no_purge_eligible_children /etc/facelock
    assert_no_purge_eligible_children /var/lib/facelock \
        /var/lib/facelock/pam-backups "$PAM_RETAINED"
    assert_no_purge_eligible_children /var/log/facelock
    if [ "$(stat -c %h -- "$PAM_RETAINED")" != 1 ]; then
        record_failure "opaque PAM rollback remnant is hard-linked"
    fi
    snapshot_file "$PAM_RETAINED" >"$STATE_ROOT/pam-purge.after"
    if ! cmp -s "$STATE_ROOT/pam-purge.before" "$STATE_ROOT/pam-purge.after"; then
        diff -u "$STATE_ROOT/pam-purge.before" "$STATE_ROOT/pam-purge.after" >&2 || true
        record_failure "purge changed opaque non-empty PAM rollback state"
    fi
    snapshot_file "$EXTERNAL_SENTINEL" >"$STATE_ROOT/external-purge.after"
    if ! cmp -s "$STATE_ROOT/external-purge.before" "$STATE_ROOT/external-purge.after"; then
        diff -u "$STATE_ROOT/external-purge.before" "$STATE_ROOT/external-purge.after" >&2 || true
        record_failure "purge changed state outside the compiled fixed roots"
    fi
    assert_eq "$before_hash" "$(artifact_hash)" "candidate artifact digest after purge"
    if [ -d /run/systemd/system ] &&
       systemctl is-enabled --quiet facelock-daemon.service 2>/dev/null; then
        echo "FAIL [Debian purge lifecycle]: purge retained daemon enablement" >&2
        failed=1
    fi
    [ "$failed" -eq 0 ] || exit 1
    pass "purge clears eligible contents and preserves trusted opaque remnants"
}

case "$phase" in
    install)
        fresh_install
        ;;
    install-remove-reinstall)
        fresh_install
        exercise_remove_reinstall
        ;;
    versioned-upgrade-inactive)
        exercise_versioned_upgrade_matrix inactive
        ;;
    versioned-upgrade-active)
        exercise_versioned_upgrade_matrix active
        ;;
    purge)
        exercise_purge
        ;;
esac
