# facelock build automation
# Usage: just <recipe>

# Build in debug mode (development)
build:
    cargo build --workspace

# Build in release mode (for install)
build-release:
    cargo build --release --workspace
    cargo build --release -p facelock-cli --features tpm

# Run all unit tests
test:
    cargo test --workspace

# Run all tests including hardware-dependent (ignored) tests
test-all:
    cargo test --workspace -- --include-ignored

# Run clippy with warnings as errors
lint:
    cargo clippy --workspace -- -D warnings

# Format check
fmt-check:
    cargo fmt --all -- --check

# Format code
fmt:
    cargo fmt --all

# Scan the dependency tree for RustSec advisories (mirrors the CI cargo-audit job).
# Ignore policy lives in .cargo/audit.toml; deny policy is set here so CI matches.
# Requires cargo-audit: cargo install cargo-audit --locked
audit:
    cargo audit --deny unmaintained --deny unsound

# Run all checks (test + lint + format + audit)
check: test lint fmt-check audit

# Build the PAM test container image (uses host-built release binaries).
# Keep in sync with .github/workflows/ci.yml, which builds this same image
# directly rather than going through this recipe.
_build-test-container: build-release
    podman build -t facelock-pam-test -f test/Containerfile .

# Automated PAM smoke tests (Arch container)
test-arch-pam: _build-test-container
    podman run --rm facelock-pam-test

# Automated state-layout test (Arch container, camera-free).
# Asserts the exact modes and ownership of everything under /var/lib/facelock
# and /var/log/facelock, including that enrolled/ is traversable but not
# listable for a facelock group member. This is the only test that exercises
# the packaging wiring (install-files modes + the built-in defaults) end to
# end — unit tests cannot.
test-arch-layout: _build-test-container
    podman run --rm facelock-pam-test /run-layout-tests.sh

# Guard for the camera tiers: the Containerfile bakes models/ into the image
# with a tolerant `|| true`, so building from a checkout without the ONNX
# models (fresh clone/worktree — they are downloaded, not tracked) produces an
# image whose daemon cannot load the face engine and whose enroll bails before
# opening the camera. Fail loudly here instead of debugging opaque test FAILs.
# Check the two non-optional models by name: a checkout holding only the
# optional ones (det_10g.onnx, glintr100.onnx) satisfies a bare *.onnx glob but
# still leaves the default detector/embedder missing at runtime.
_require-models:
    #!/usr/bin/env bash
    set -euo pipefail
    missing=()
    for m in models/scrfd_2.5g_bnkps.onnx models/w600k_r50.onnx; do
        [ -f "$m" ] || missing+=("$m")
    done
    if [ ${#missing[@]} -gt 0 ]; then
        echo "error: missing required ONNX models — the camera test tiers need them baked into the image:" >&2
        for m in "${missing[@]}"; do echo "         $m" >&2; done
        echo "       They are downloaded, not tracked. Copy them from the install tree" >&2
        echo "       ('sudo facelock setup' downloads them to /var/lib/facelock/models):" >&2
        echo "         sudo cp /var/lib/facelock/models/*.onnx models/" >&2
        echo "       (models/*.onnx is gitignored, so this cannot be committed by accident.)" >&2
        exit 1
    fi

# Automated daemon integration tests (Arch, requires camera)
test-arch-integration: _require-models _build-test-container
    #!/usr/bin/env bash
    set -euo pipefail
    devices=""
    for d in /dev/video*; do
        [ -e "$d" ] && devices="$devices --device $d"
    done
    podman run --rm $devices facelock-pam-test /run-integration-tests.sh

# Automated oneshot (daemonless) integration tests (Arch, requires camera)
test-arch-oneshot: _require-models _build-test-container
    #!/usr/bin/env bash
    set -euo pipefail
    devices=""
    for d in /dev/video*; do
        [ -e "$d" ] && devices="$devices --device $d"
    done
    podman run --rm $devices facelock-pam-test /run-oneshot-tests.sh

# Dev shell — interactive Arch container with host models for fast iteration (requires camera)
test-arch-dev-shell: _build-test-container
    #!/usr/bin/env bash
    set -euo pipefail
    devices=""
    for d in /dev/video*; do
        [ -e "$d" ] && devices="$devices --device $d"
    done
    mounts=""
    for f in /var/lib/facelock/models/*.onnx /var/lib/facelock/models/*.toml; do
        [ -f "$f" ] && mounts="$mounts -v $f:/tmp/host-models/$(basename $f):ro"
    done
    echo "Starting dev shell (Arch, binary install, host models). Try:"
    echo "  facelock daemon &"
    echo "  sleep 2"
    echo "  facelock enroll --user testuser --label myface"
    echo "  facelock test --user testuser"
    echo "  pamtester facelock-test testuser authenticate"
    podman run --rm -it $devices $mounts facelock-pam-test \
        bash -c "cp /tmp/host-models/* /var/lib/facelock/models/ 2>/dev/null; exec bash"

# Release shell — clean-room Arch container, real user experience (requires camera)
test-arch-release-shell: _build-test-container
    #!/usr/bin/env bash
    set -euo pipefail
    devices=""
    for d in /dev/video*; do
        [ -e "$d" ] && devices="$devices --device $d"
    done
    echo "Starting release shell (Arch, binary install, clean room). Try:"
    echo "  facelock setup"
    echo "  facelock enroll --user testuser --label myface"
    echo "  facelock test --user testuser"
    echo "  pamtester facelock-test testuser authenticate"
    podman run --rm -it $devices facelock-pam-test /bin/bash

# Build release and install to system
# Run as: just install (builds as you, installs as root)
install: build-release
    sudo env PATH="$PATH" just install-files

# Install pre-built binaries to system (requires root, no build)
install-files:
    #!/usr/bin/env bash
    set -euo pipefail

    # Verify binaries exist
    for f in target/release/facelock target/release/libpam_facelock.so; do
        [ -f "$f" ] || { echo "Error: $f not found. Run 'just build-release' first."; exit 1; }
    done

    # Create facelock system group and add the installing user
    getent group facelock >/dev/null || groupadd -r facelock
    REAL_USER="${SUDO_USER:-${DOAS_USER:-}}"
    if [ -n "$REAL_USER" ] && ! id -nG "$REAL_USER" 2>/dev/null | grep -qw facelock; then
        usermod -aG facelock "$REAL_USER"
        echo "Added $REAL_USER to facelock group (log out and back in to take effect)."
    fi

    # Binaries
    install -Dm755 target/release/facelock /usr/bin/facelock
    install -Dm755 target/release/libpam_facelock.so /lib/security/pam_facelock.so

    # Config (don't overwrite existing)
    install -Dm644 config/facelock.toml /etc/facelock/config.toml.default
    [ -f /etc/facelock/config.toml ] || cp /etc/facelock/config.toml.default /etc/facelock/config.toml

    # Hardware quirks database
    install -dm755 /usr/share/facelock/quirks.d
    install -Dm644 config/quirks.d/*.toml /usr/share/facelock/quirks.d/

    # systemd unit
    install -Dm644 systemd/facelock-daemon.service /usr/lib/systemd/system/facelock-daemon.service
    if [ -f /etc/systemd/system/facelock-daemon.service ] && \
       grep -q 'ExecStart=/usr/bin/facelock daemon' /etc/systemd/system/facelock-daemon.service; then
        install -Dm644 systemd/facelock-daemon.service /etc/systemd/system/facelock-daemon.service
    fi

    # D-Bus policy and activation
    install -Dm644 dbus/org.facelock.Daemon.conf /usr/share/dbus-1/system.d/org.facelock.Daemon.conf
    install -Dm644 dbus/org.facelock.Daemon.service /usr/share/dbus-1/system-services/org.facelock.Daemon.service
    if [ -f /etc/dbus-1/system.d/org.facelock.Daemon.conf ] && \
       grep -q 'org.facelock.Daemon' /etc/dbus-1/system.d/org.facelock.Daemon.conf; then
        install -Dm644 dbus/org.facelock.Daemon.conf /etc/dbus-1/system.d/org.facelock.Daemon.conf
    fi
    if [ -f /etc/dbus-1/system-services/org.facelock.Daemon.service ] && \
       grep -q 'org.facelock.Daemon' /etc/dbus-1/system-services/org.facelock.Daemon.service; then
        install -Dm644 dbus/org.facelock.Daemon.service /etc/dbus-1/system-services/org.facelock.Daemon.service
    fi

    # Polkit action (interactive authorization for preview frame bytes)
    install -Dm644 dbus/org.facelock.policy /usr/share/polkit-1/actions/org.facelock.policy

    # Polkit agent binary (optional, do NOT install autostart — agent is not production-ready
    # and will steal polkit auth from the DE's agent, causing all privilege prompts to hang)
    [ -f target/release/facelock-polkit-agent ] && install -Dm755 target/release/facelock-polkit-agent /usr/bin/facelock-polkit-agent || true

    # Directories. Must match dist/facelock.tmpfiles.
    # State dir 0710 root:facelock: traverse-only for the group, nothing for
    # anyone else. Models are public, SHA256-verified downloads — the 0710
    # parent is the gate. enrolled/ 0710 root:facelock: a group member can
    # open its own 0600 marker by name but cannot list who else is enrolled.
    # Audit log and snapshots are root-only (per-user auth history and raw
    # face images).
    install -dm710 -o root -g facelock /var/lib/facelock
    install -dm755 -o root -g root /var/lib/facelock/models
    install -dm710 -o root -g facelock /var/lib/facelock/enrolled
    install -dm700 -o root -g root /var/log/facelock
    install -dm700 -o root -g root /var/log/facelock/snapshots

    # Enable D-Bus activation (if systemd present)
    if [ -d /run/systemd/system ]; then
        systemctl stop facelock-daemon.service 2>/dev/null || true
        systemctl daemon-reload
        systemctl reset-failed facelock-daemon.service 2>/dev/null || true
        systemctl enable facelock-daemon.service 2>/dev/null || true
        echo "D-Bus activation enabled."
    fi

    # Fix permissions on existing data
    [ -d /etc/facelock ] && chown root:root /etc/facelock && chmod 755 /etc/facelock || true
    [ -f /etc/facelock/config.toml ] && chown root:root /etc/facelock/config.toml && chmod 644 /etc/facelock/config.toml || true
    [ -f /etc/facelock/config.toml.default ] && chown root:root /etc/facelock/config.toml.default && chmod 644 /etc/facelock/config.toml.default || true
    [ -d /var/lib/facelock ] && chown root:facelock /var/lib/facelock && chmod 710 /var/lib/facelock || true
    [ -d /var/lib/facelock/models ] && chown root:root /var/lib/facelock/models && chmod 755 /var/lib/facelock/models || true
    [ -d /var/lib/facelock/enrolled ] && chown root:facelock /var/lib/facelock/enrolled && chmod 710 /var/lib/facelock/enrolled || true
    [ -d /var/log/facelock ] && chown root:root /var/log/facelock && chmod 700 /var/log/facelock || true
    [ -d /var/log/facelock/snapshots ] && chown root:root /var/log/facelock/snapshots && chmod 700 /var/log/facelock/snapshots || true
    [ -f /var/log/facelock/audit.jsonl ] && chown root:root /var/log/facelock/audit.jsonl && chmod 600 /var/log/facelock/audit.jsonl || true
    [ -d /var/lib/facelock/models ] && chmod 644 /var/lib/facelock/models/*.onnx 2>/dev/null || true
    # The database and sidecars are root-only: encrypted biometric templates,
    # read by the daemon. Tighten if present, never create.
    [ -f /var/lib/facelock/facelock.db ] && chown root:root /var/lib/facelock/facelock.db && chmod 600 /var/lib/facelock/facelock.db || true
    [ -f /var/lib/facelock/facelock.db-wal ] && chown root:root /var/lib/facelock/facelock.db-wal && chmod 600 /var/lib/facelock/facelock.db-wal || true
    [ -f /var/lib/facelock/facelock.db-shm ] && chown root:root /var/lib/facelock/facelock.db-shm && chmod 600 /var/lib/facelock/facelock.db-shm || true

    echo ""
    echo ""

    # Check what's still needed
    NEEDS_SETUP=false
    NEEDS_ORT=false

    # Models present?
    if ! ls /var/lib/facelock/models/*.onnx >/dev/null 2>&1; then
        NEEDS_SETUP=true
    fi

    # Config present?
    if [ ! -f /etc/facelock/config.toml ]; then
        NEEDS_SETUP=true
    fi

    # PAM configured?
    if ! grep -qs pam_facelock /etc/pam.d/sudo 2>/dev/null; then
        NEEDS_SETUP=true
    fi

    # ORT installed? Check file paths directly.
    if [ ! -f /usr/lib/libonnxruntime.so ] && \
       [ ! -f /usr/lib64/libonnxruntime.so ] && \
       [ ! -f /usr/lib/facelock/libonnxruntime.so ]; then
        NEEDS_ORT=true
    fi

    if $NEEDS_SETUP || $NEEDS_ORT; then
        echo "Installed."
        if $NEEDS_ORT; then
            echo ""
            echo "Requires: onnxruntime (pacman -S onnxruntime-cpu)"
            echo "Optional: onnxruntime-opt-cuda (NVIDIA) or onnxruntime-opt-rocm (AMD)"
        fi
        if $NEEDS_SETUP; then
            echo ""
            echo "Run 'sudo facelock setup' to complete configuration."
            echo "  (downloads models, configures PAM services, enrolls your face)"
        fi
    else
        echo "Installed and up to date."
    fi

# Uninstall from system
# Run as: just uninstall (elevates to root, preserving PATH)
uninstall:
    sudo env PATH="$PATH" just uninstall-files

# Uninstall files from system (requires root, called by uninstall)
uninstall-files:
    #!/usr/bin/env bash
    set -euo pipefail
    # Stop and disable daemon
    systemctl stop facelock-daemon.service 2>/dev/null || true
    systemctl disable facelock-daemon.service 2>/dev/null || true

    # Remove PAM lines from all known services (match on module name, not exact spacing)
    for PAM_FILE in /etc/pam.d/sudo /etc/pam.d/polkit-1 /etc/pam.d/hyprlock; do
        if [ -f "$PAM_FILE" ] && grep -q 'pam_facelock\.so' "$PAM_FILE"; then
            sed -i '/pam_facelock\.so/d' "$PAM_FILE"
            echo "Removed face auth from $PAM_FILE"
        fi
    done

    # Remove PAM safety backups created by `facelock setup`
    for backup in /etc/pam.d/sudo.facelock-backup /etc/pam.d/polkit-1.facelock-backup /etc/pam.d/hyprlock.facelock-backup; do
        [ -f "$backup" ] && rm -f "$backup" && echo "Removed $backup"
    done

    # Kill facelock polkit agent if running (so the DE's agent can take over)
    pkill -f facelock-polkit-agent 2>/dev/null || true

    # Remove binaries and units
    rm -f /usr/bin/facelock /lib/security/pam_facelock.so
    # Decide whether the /etc/systemd/system/ override matches the installed unit
    # (we want to clean up our own override, but never clobber an admin customization).
    # We must compare BEFORE removing /usr/lib/systemd/system/facelock-daemon.service.
    SYSTEM_OVERRIDE="/etc/systemd/system/facelock-daemon.service"
    INSTALLED_UNIT="/usr/lib/systemd/system/facelock-daemon.service"
    REMOVE_OVERRIDE=false
    if [ -f "$SYSTEM_OVERRIDE" ] && [ -f "$INSTALLED_UNIT" ] && cmp -s "$INSTALLED_UNIT" "$SYSTEM_OVERRIDE"; then
        REMOVE_OVERRIDE=true
    fi
    rm -f "$INSTALLED_UNIT"
    if [ "$REMOVE_OVERRIDE" = true ]; then
        rm -f "$SYSTEM_OVERRIDE"
        echo "Removed $SYSTEM_OVERRIDE (matched installed unit)"
    elif [ -f "$SYSTEM_OVERRIDE" ]; then
        echo "Kept $SYSTEM_OVERRIDE (admin-modified or installed unit not present for comparison)"
    fi
    rm -f /usr/share/dbus-1/system.d/org.facelock.Daemon.conf
    rm -f /usr/share/dbus-1/system-services/org.facelock.Daemon.service
    rm -f /usr/share/polkit-1/actions/org.facelock.policy
    rm -f /usr/bin/facelock-polkit-agent
    rm -f /etc/xdg/autostart/org.facelock.AuthAgent.desktop

    # Remove quirks database and source-install config artifacts
    # (these would otherwise collide with a subsequent package install)
    rm -rf /usr/share/facelock
    rm -f /etc/facelock/config.toml.default

    systemctl daemon-reload 2>/dev/null || true

    echo ""
    echo "==> facelock uninstalled. User data preserved at:"
    echo "==>   /etc/facelock/      (config.toml, encryption.key.sealed, setup markers)"
    echo "==>   /var/lib/facelock/  (face database, ONNX models ~100MB)"
    echo "==>   /var/log/facelock/  (audit logs and snapshots)"
    echo "==>"
    echo "==> To remove all face data, config, models, and logs:"
    echo "==>   sudo rm -rf /etc/facelock /var/lib/facelock /var/log/facelock"
    echo "==>"
    echo "==> To remove the facelock group (after removing all members):"
    echo "==>   sudo gpasswd -d <username> facelock"
    echo "==>   sudo groupdel facelock"

# Bump version and prepare a release commit + tag
# Usage: just release 0.2.0
release version:
    #!/usr/bin/env bash
    set -euo pipefail
    VERSION="{{version}}"

    # Validate version format
    if ! echo "$VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
        echo "Error: Version must be semver (e.g. 0.2.0), got '$VERSION'"
        exit 1
    fi

    # Check for clean working tree
    if [ -n "$(git status --porcelain)" ]; then
        echo "Error: Working tree is not clean. Commit or stash changes first."
        exit 1
    fi

    OLD_VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')
    echo "Bumping version: $OLD_VERSION → $VERSION"

    # 1. Cargo.toml (workspace version)
    sed -i "s/^version = \"$OLD_VERSION\"/version = \"$VERSION\"/" Cargo.toml
    echo "  ✓ Cargo.toml"

    # 2. dist/PKGBUILD
    if [ -f dist/PKGBUILD ]; then
        sed -i "s/^pkgver=.*/pkgver=$VERSION/" dist/PKGBUILD
        echo "  ✓ dist/PKGBUILD"
    fi

    # 2b. dist/PKGBUILD-bin (per-binary sha256sums are filled in by CI)
    if [ -f dist/PKGBUILD-bin ]; then
        sed -i "s/^pkgver=.*/pkgver=$VERSION/" dist/PKGBUILD-bin
        echo "  ✓ dist/PKGBUILD-bin"
    fi

    # 2c. dist/PKGBUILD-git: the runtime pkgver() function computes the real
    # version from `git describe`, but generate_srcinfo in publish-aur.sh runs
    # without a git checkout, so AUR's web display falls back to this static
    # pkgver. Keep it in sync with the release so the AUR page doesn't drift.
    if [ -f dist/PKGBUILD-git ]; then
        sed -i "s/^pkgver=.*/pkgver=$VERSION/" dist/PKGBUILD-git
        echo "  ✓ dist/PKGBUILD-git"
    fi

    # 3. dist/facelock.spec
    if [ -f dist/facelock.spec ]; then
        sed -i "s/^Version:.*/Version:        $VERSION/" dist/facelock.spec
        echo "  ✓ dist/facelock.spec"
    fi

    # 4. dist/debian/changelog (prepend new entry)
    if [ -f dist/debian/changelog ]; then
        DATE=$(date -R)
        sed -i "1i facelock ($VERSION-1) unstable; urgency=medium\n\n  * Release v$VERSION.\n\n -- Facelock Contributors <facelock@m.tysmith.me>  $DATE\n" dist/debian/changelog
        echo "  ✓ dist/debian/changelog"
    fi

    # 5. Verify it compiles
    echo ""
    echo "Running cargo check..."
    cargo check --workspace
    echo "  ✓ cargo check passed"

    # 6. Remind to update CHANGELOG.md
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Update CHANGELOG.md with the changes for v$VERSION"
    echo "  then run:"
    echo ""
    echo "    git add -A && git commit -m 'chore: release v$VERSION'"
    echo "    git tag v$VERSION"
    echo "    git push origin main --tags"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Show current version
version:
    @grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/'

# Clean build artifacts
clean:
    cargo clean

# Show installed file locations
show-paths:
    @echo "Binary:   /usr/bin/facelock"
    @echo "PAM:      /lib/security/pam_facelock.so"
    @echo "Config:   /etc/facelock/config.toml"
    @echo "Models:   /var/lib/facelock/models/"
    @echo "Database: /var/lib/facelock/facelock.db"
    @echo "D-Bus:    /usr/share/dbus-1/system.d/org.facelock.Daemon.conf"
    @echo "Polkit:   /usr/share/polkit-1/actions/org.facelock.policy"
    @echo "Service:  /usr/lib/systemd/system/facelock-daemon.service"
    @echo "Logs:     /var/log/facelock/"

# Detect host ONNX Runtime version for container builds.
# Local binaries are built against the host ORT, so bundled ORT must match.
# CI uses 1.20.1 (set in release.yml); local builds use whatever is installed.
_ort-version := `for ort in /usr/lib/libonnxruntime.so /usr/lib64/libonnxruntime.so; do if [ -e "$ort" ]; then readlink -f "$ort" | grep -oP '\d+\.\d+\.\d+$'; exit; fi; done; echo "1.20.1"`

# Test RPM packaging in Fedora container
test-rpm: build-release
    #!/usr/bin/env bash
    set -euo pipefail
    podman build -t facelock-rpm-test -f test/Containerfile.fedora .
    podman run --rm facelock-rpm-test

# Test .deb packaging in Ubuntu container
test-deb: build-release
    #!/usr/bin/env bash
    set -euo pipefail
    podman build -t facelock-deb-test -f test/Containerfile.ubuntu .
    podman run --rm facelock-deb-test

# Package test — build real .deb, install via dpkg, validate under booted systemd
test-deb-pkg: build-release
    #!/usr/bin/env bash
    set -euo pipefail
    podman build --build-arg ORT_VERSION={{_ort-version}} -t facelock-deb-pkg -f test/Containerfile.deb-e2e .
    test/run-pkg-validate-systemd.sh facelock-deb-pkg

# Package test — build real TPM .deb (trixie), install via dpkg, run automated validation
test-deb-tpm-pkg: build-release
    #!/usr/bin/env bash
    set -euo pipefail
    podman build --build-arg ORT_VERSION={{_ort-version}} -t facelock-deb-tpm-pkg -f test/Containerfile.deb-tpm-e2e .
    podman run --rm facelock-deb-tpm-pkg

# Package test — build real .rpm, install via dnf, validate under booted systemd
test-rpm-pkg: build-release
    #!/usr/bin/env bash
    set -euo pipefail
    podman build --build-arg ORT_VERSION={{_ort-version}} -t facelock-rpm-pkg -f test/Containerfile.rpm-e2e .
    test/run-pkg-validate-systemd.sh facelock-rpm-pkg

# COPR-equivalent build — Packit SRPM + mock from-source rebuild on a Fedora chroot (slow, opt-in)
test-copr:
    #!/usr/bin/env bash
    set -euo pipefail
    podman build -t facelock-copr-test -f test/Containerfile.copr .
    podman run --privileged --rm -v "$PWD:/repo:ro" facelock-copr-test

# Dev shell — interactive .deb container with host models for fast iteration (requires camera)
test-deb-dev-shell: build-release
    #!/usr/bin/env bash
    set -euo pipefail
    podman build --build-arg ORT_VERSION={{_ort-version}} -t facelock-deb-pkg -f test/Containerfile.deb-e2e .
    devices=""
    for d in /dev/video*; do
        [ -e "$d" ] && devices="$devices --device $d"
    done
    mounts=""
    for f in /var/lib/facelock/models/*.onnx /var/lib/facelock/models/*.toml; do
        [ -f "$f" ] && mounts="$mounts -v $f:/tmp/host-models/$(basename $f):ro"
    done
    mounts="$mounts -v $(pwd)/test/container-config.toml:/tmp/container-config.toml:ro"
    echo "Starting dev shell (Ubuntu 24.04, .deb installed, host models). Try:"
    echo "  facelock enroll --user root --label myface"
    echo "  facelock test --user root"
    podman run --rm -it $devices $mounts facelock-deb-pkg \
        bash -c "cp /tmp/container-config.toml /etc/facelock/config.toml; cp /tmp/host-models/* /var/lib/facelock/models/ 2>/dev/null; exec bash"

# Dev shell — interactive .rpm container with host models for fast iteration (requires camera)
test-rpm-dev-shell: build-release
    #!/usr/bin/env bash
    set -euo pipefail
    podman build --build-arg ORT_VERSION={{_ort-version}} -t facelock-rpm-pkg -f test/Containerfile.rpm-e2e .
    devices=""
    for d in /dev/video*; do
        [ -e "$d" ] && devices="$devices --device $d"
    done
    mounts=""
    for f in /var/lib/facelock/models/*.onnx /var/lib/facelock/models/*.toml; do
        [ -f "$f" ] && mounts="$mounts -v $f:/tmp/host-models/$(basename $f):ro"
    done
    mounts="$mounts -v $(pwd)/test/container-config.toml:/tmp/container-config.toml:ro"
    echo "Starting dev shell (Fedora, .rpm installed, host models). Try:"
    echo "  facelock enroll --user root --label myface"
    echo "  facelock test --user root"
    podman run --rm -it $devices $mounts facelock-rpm-pkg \
        bash -c "cp /tmp/container-config.toml /etc/facelock/config.toml; cp /tmp/host-models/* /var/lib/facelock/models/ 2>/dev/null; exec bash"

# Release shell — clean-room .deb container, real user experience (requires camera)
test-deb-release-shell: build-release
    #!/usr/bin/env bash
    set -euo pipefail
    podman build --build-arg ORT_VERSION={{_ort-version}} -t facelock-deb-pkg -f test/Containerfile.deb-e2e .
    devices=""
    for d in /dev/video*; do
        [ -e "$d" ] && devices="$devices --device $d"
    done
    mounts="-v $(pwd)/test/container-config.toml:/tmp/container-config.toml:ro"
    echo "Starting release shell (Ubuntu 24.04, .deb installed, clean room). Try:"
    echo "  facelock setup"
    echo "  facelock enroll --user root --label myface"
    echo "  facelock test --user root"
    podman run --rm -it $devices $mounts facelock-deb-pkg \
        bash -c "cp /tmp/container-config.toml /etc/facelock/config.toml; exec bash"

# Release shell — clean-room .rpm container, real user experience (requires camera)
test-rpm-release-shell: build-release
    #!/usr/bin/env bash
    set -euo pipefail
    podman build --build-arg ORT_VERSION={{_ort-version}} -t facelock-rpm-pkg -f test/Containerfile.rpm-e2e .
    devices=""
    for d in /dev/video*; do
        [ -e "$d" ] && devices="$devices --device $d"
    done
    mounts="-v $(pwd)/test/container-config.toml:/tmp/container-config.toml:ro"
    echo "Starting release shell (Fedora, .rpm installed, clean room). Try:"
    echo "  facelock setup"
    echo "  facelock enroll --user root --label myface"
    echo "  facelock test --user root"
    podman run --rm -it $devices $mounts facelock-rpm-pkg \
        bash -c "cp /tmp/container-config.toml /etc/facelock/config.toml; exec bash"

# Test APT repo generation locally (requires reprepro + gpg)
test-apt-repo:
    #!/usr/bin/env bash
    set -euo pipefail

    # Check tools
    for cmd in reprepro dpkg-deb; do
        command -v "$cmd" >/dev/null || { echo "Error: '$cmd' not found. Install it first."; exit 1; }
    done

    # Verify config exists
    if [ ! -f dist/apt/conf/distributions ]; then
        echo "Error: dist/apt/conf/distributions not found"
        exit 1
    fi

    TMPDIR=$(mktemp -d)
    trap 'rm -rf "$TMPDIR"' EXIT

    REPO_DIR="${TMPDIR}/repo"
    mkdir -p "${REPO_DIR}/conf"
    cp dist/apt/conf/distributions "${REPO_DIR}/conf/distributions"

    # For local testing without GPG, strip SignWith lines
    sed -i '/^SignWith:/d' "${REPO_DIR}/conf/distributions"

    # Find any .deb files (from just test-deb or CI artifacts)
    DEB_FILES=$({ find . -maxdepth 1 -name 'facelock_*.deb'; find ./target -maxdepth 1 -name 'facelock_*.deb' 2>/dev/null; } | head -2)
    if [ -z "$DEB_FILES" ]; then
        echo "No .deb files found. Building a test .deb is not required."
        echo "Validating reprepro config only..."
        reprepro -b "${REPO_DIR}" check
        echo ""
        echo "APT repo config: OK"
        echo "To test with real .deb files, build them first with CI or 'just test-deb'."
        exit 0
    fi

    # Add first .deb to main, second to legacy (or same to both)
    FIRST_DEB=$(echo "$DEB_FILES" | head -1)
    SECOND_DEB=$(echo "$DEB_FILES" | tail -1)

    reprepro -b "${REPO_DIR}" includedeb main "$FIRST_DEB"
    reprepro -b "${REPO_DIR}" includedeb legacy "$SECOND_DEB"

    echo ""
    echo "=== APT repo structure ==="
    find "${REPO_DIR}" -type f -not -path '*/db/*' -not -path '*/conf/*' | sort

    # Validate expected structure
    for SUITE in main legacy; do
        [ -f "${REPO_DIR}/dists/${SUITE}/Release" ] && echo "OK: dists/${SUITE}/Release"
        [ -d "${REPO_DIR}/dists/${SUITE}/facelock/binary-amd64" ] && echo "OK: dists/${SUITE}/facelock/binary-amd64/"
    done
    [ -d "${REPO_DIR}/pool/facelock" ] && echo "OK: pool/facelock/"

    echo ""
    echo "APT repo generation: OK"

# Quick preflight before tagging a release
# Usage:
#   just release-preflight                 # assume stable release
#   just release-preflight v0.2.0-rc1      # prerelease (secrets optional)
release-preflight tag='':
    #!/usr/bin/env bash
    set -euo pipefail

    failed=0
    TAG="{{tag}}"
    prerelease=0
    if [ -n "$TAG" ] && echo "$TAG" | grep -Eq '(alpha|beta|rc)'; then
        prerelease=1
    fi

    check_cmd() {
        local cmd="$1"
        if command -v "$cmd" >/dev/null 2>&1; then
            echo "OK: found '$cmd'"
        else
            echo "MISSING: '$cmd' not found in PATH"
            failed=1
        fi
    }

    echo "== Local tool checks =="
    check_cmd git
    check_cmd cargo
    check_cmd just
    check_cmd podman

    echo ""
    echo "== Packaging file checks =="
    for f in \
        dist/PKGBUILD \
        dist/PKGBUILD-git \
        dist/facelock.spec \
        dist/debian/control \
        dist/debian/rules \
        dist/apt/conf/distributions \
        .packit.yaml \
        .github/workflows/release.yml; do
        if [ -f "$f" ]; then
            echo "OK: $f"
        else
            echo "MISSING: $f"
            failed=1
        fi
    done

    echo ""
    echo "== GitHub release secret checks =="
    if [ "$prerelease" -eq 1 ]; then
        echo "Mode: prerelease ($TAG) — AUR secrets are optional"
    else
        echo "Mode: stable release — AUR secrets are required"
    fi
    echo "Note: COPR builds are handled by Packit (.packit.yaml) — no secret required."

    if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
        if gh secret list | grep -q '^AUR_SSH_KEY\b'; then
            echo "OK: AUR_SSH_KEY configured"
        else
            echo "MISSING: AUR_SSH_KEY"
            if [ "$prerelease" -eq 0 ]; then
                failed=1
            fi
        fi

        if gh secret list | grep -q '^APT_GPG_PRIVATE_KEY\b'; then
            echo "OK: APT_GPG_PRIVATE_KEY configured"
        else
            echo "MISSING: APT_GPG_PRIVATE_KEY"
            if [ "$prerelease" -eq 0 ]; then
                failed=1
            fi
        fi

        if gh secret list | grep -q '^APT_GPG_PASSPHRASE\b'; then
            echo "OK: APT_GPG_PASSPHRASE configured"
        else
            echo "MISSING: APT_GPG_PASSPHRASE"
            if [ "$prerelease" -eq 0 ]; then
                failed=1
            fi
        fi
    else
        echo "SKIP: gh not installed or not authenticated; cannot verify repo secrets"
        if [ "$prerelease" -eq 0 ]; then
            failed=1
        fi
    fi

    echo ""
    if [ "$failed" -ne 0 ]; then
        echo "Release preflight: FAILED"
        exit 1
    fi

    echo "Release preflight: OK"
    echo "Next: run 'just check', 'just test-pam', 'just test-rpm', and 'just test-deb' before tagging."
