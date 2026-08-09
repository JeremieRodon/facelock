#!/bin/sh
# Build and install pamtester 0.1.2 from upstream source.
#
# Shared by every test Containerfile (Arch, deb-e2e, deb-tpm-e2e, rpm-e2e) —
# pamtester is not packaged by Arch, Debian/Ubuntu, or Fedora. The caller is
# responsible for providing curl, tar, and a C toolchain (and for removing them
# again if the image cares about size).
#
# sh-compatible on purpose: the deb/rpm images run this before any bash-specific
# SHELL directive takes effect.
set -eu

VERSION=0.1.2
# downloads.sourceforge.net redirects straight to a mirror; the /projects/...
# /download landing URL goes through an extra interstitial hop for the same
# bytes (identical sha256), so prefer the shorter chain.
URL="https://downloads.sourceforge.net/project/pamtester/pamtester/${VERSION}/pamtester-${VERSION}.tar.gz"
SHA256=83633d0e8a4f35810456d9d52261c8ae0beb9148276847cae8963505240fb2d5

TARBALL=/tmp/pamtester-${VERSION}.tar.gz
SRCDIR=/tmp/pamtester-${VERSION}

# -f turns an HTTP error page into a failure instead of feeding it to tar; the
# retries cover transient mirror failures, and the checksum catches a truncated
# body that still returned 200.
if ! curl -fsSL --retry 5 --retry-delay 2 --retry-all-errors -o "$TARBALL" "$URL"; then
    # Podman's default rootless build network advertises an IPv6 path that
    # completes the TCP connect but fails the TLS handshake (curl exit 35).
    # Happy Eyeballs only races the connect, so curl never falls back on its
    # own — pin to IPv4 and retry.
    echo "pamtester: download failed, retrying over IPv4 only" >&2
    curl -4 -fsSL --retry 5 --retry-delay 2 --retry-all-errors -o "$TARBALL" "$URL"
fi
echo "${SHA256}  ${TARBALL}" | sha256sum -c

tar xzf "$TARBALL" -C /tmp
cd "$SRCDIR"
# pamtester 0.1.2 predates C99 implicit-declaration errors being fatal (GCC 14+).
./configure --prefix=/usr CFLAGS="-Wno-implicit-function-declaration"
make
make install

cd /
rm -rf "$SRCDIR" "$TARBALL"
