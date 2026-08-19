#!/usr/bin/env bash
set -euo pipefail

PKG_VERSION_RAW="${1:?Usage: build-rpm.sh <VERSION_RAW> <PRERELEASE_COUNTER>}"
PRERELEASE_COUNTER="${2:?Usage: build-rpm.sh <VERSION_RAW> <PRERELEASE_COUNTER>}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../../scripts/release-versions.sh
source "$SCRIPT_DIR/../../../scripts/release-versions.sh"
PKG_VERSION="$(release_rpm_version "$PKG_VERSION_RAW")"
PKG_RELEASE="$(release_rpm_release "$PKG_VERSION_RAW" "$PRERELEASE_COUNTER")%{?dist}"

echo "=== Building RPM package ==="
echo "Raw version: ${PKG_VERSION_RAW}"

echo "RPM Version: ${PKG_VERSION}"
echo "RPM Release: ${PKG_RELEASE}"

mkdir -p ~/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

# Copy spec file and set version/release
cp dist/facelock.spec ~/rpmbuild/SPECS/facelock.spec
sed -i "s|^Version:.*|Version:        ${PKG_VERSION}|" ~/rpmbuild/SPECS/facelock.spec
sed -i "s|^Release:.*|Release:        ${PKG_RELEASE}|" ~/rpmbuild/SPECS/facelock.spec

# Build source tarball expected by Source0 so rpmbuild can run the
# full %prep/%build/%install pipeline.
tar --exclude=.git --exclude=target \
    --transform "s|^|facelock-${PKG_VERSION}/|" \
    -czf "${HOME}/rpmbuild/SOURCES/facelock-${PKG_VERSION}.tar.gz" .

# Build RPM using spec-defined build/install steps.
rpmbuild --define "_topdir $HOME/rpmbuild" \
         -bb ~/rpmbuild/SPECS/facelock.spec

echo "=== RPM package built ==="
