#!/usr/bin/env bash
# Build dist/PKGBUILD end to end inside the Arch package container, then
# install the result with pacman.
#
# ## How the recipe's source= is exercised without downloading
#
# dist/PKGBUILD fetches a GitHub archive tarball for the released tag. Letting
# it download would test the last release instead of the candidate, and would
# make every run depend on the network. Stubbing source= out would test a
# recipe nobody ships.
#
# So the candidate tree is mounted at /staged-source and repacked here under
# exactly the file name the recipe's own source= array declares, in the
# directory shape a GitHub archive unpacks to. makepkg then finds it in SRCDEST
# and does everything else for real: it parses source=, checks sha256sums,
# extracts, and runs prepare(), build(), check() and package(). If the recipe's
# rename target and the directory its functions cd into ever disagree, the
# build fails here.
#
# Source retrieval runs under the same fail-closed network sandbox the Debian
# lane uses, so "it did not download" is enforced rather than asserted.
#
# ## Integrity
#
# dist/PKGBUILD declares a fail-closed placeholder that publish-aur.sh replaces
# with the release tarball's digest at publish time (#283). A tarball repacked
# from the working tree can never match a published sum, so this lane applies
# the same transformation to the staged tarball: it computes the staged file's
# digest, writes it into the build copy of the recipe, and lets makepkg verify
# it for real. Before that it proves the check can fail at all, by offering a
# wrong digest and requiring rejection, and it refuses a recipe that declares
# SKIP, which is the hole #283 closed.
#
# ## What this does NOT verify
#
# The declared source URL is never fetched, so a wrong or dead URL passes here.
# The digest of the published release tarball is computed and substituted by CI
# at publish time, not asserted here.
set -euo pipefail

STAGED=${FACELOCK_STAGED_SOURCE:-/staged-source}
RECIPE=${FACELOCK_RECIPE_DIR:-/recipe}
BUILD=/tmp/facelock-arch-build
BUILDER=builder

fail() {
    echo "arch package build: $*" >&2
    exit 1
}

[ -d "$STAGED" ] || fail "candidate source tree is not mounted at $STAGED"
[ -f "$STAGED/Cargo.toml" ] && [ -f "$STAGED/dist/PKGBUILD" ] ||
    fail "$STAGED does not look like a facelock checkout"
[ -f "$RECIPE/PKGBUILD" ] || fail "missing recipe: $RECIPE/PKGBUILD"

# The recipe that gets built is the one in the candidate tree. Copying it out
# of $STAGED rather than out of the image keeps a single source of truth even
# though the image also carries a copy for the dependency contract.
install -d -m 0755 -o "$BUILDER" -g "$BUILDER" "$BUILD"
install -m 0644 -o "$BUILDER" -g "$BUILDER" "$STAGED/dist/PKGBUILD" "$BUILD/PKGBUILD"
install -m 0644 -o "$BUILDER" -g "$BUILDER" "$STAGED/dist/facelock.install" \
    "$BUILD/facelock.install"

srcinfo="$(runuser -u "$BUILDER" -- bash -c "cd '$BUILD' && makepkg --printsrcinfo")" ||
    fail "dist/PKGBUILD does not parse"

mapfile -t sources < <(printf '%s\n' "$srcinfo" | sed -n -E 's/^[[:space:]]*source = //p')
[ "${#sources[@]}" -eq 1 ] ||
    fail "expected dist/PKGBUILD to declare exactly one source, got ${#sources[@]}"
entry="${sources[0]}"
case "$entry" in
    *::*) ;;
    *) fail "source entry does not rename the fetched tarball: $entry" ;;
esac
tarball="${entry%%::*}"
url="${entry#*::}"
case "$tarball" in
    */*|"") fail "source rename target is not a plain file name: $tarball" ;;
    *.tar.gz) ;;
    *) fail "source rename target is not a .tar.gz: $tarball" ;;
esac
case "$url" in
    https://*) ;;
    *) fail "source is not fetched over https: $url" ;;
esac

# The recipe must pin its one source: SKIP is the fail-open state #283 removed.
# The __SRC_SHA256__ placeholder and a real digest are both acceptable here,
# because either one is replaced with the staged tarball's digest below.
mapfile -t declared_sums < <(printf '%s\n' "$srcinfo" | sed -n -E 's/^[[:space:]]*sha256sums = //p')
[ "${#declared_sums[@]}" -eq 1 ] ||
    fail "expected dist/PKGBUILD to declare exactly one sha256sum, got ${#declared_sums[@]}"
[ "${declared_sums[0]}" != "SKIP" ] ||
    fail "dist/PKGBUILD declares sha256sums=('SKIP'); a fixed release tarball must be pinned (#283)"

# A GitHub archive of v<tag> unpacks to <pkgname>-<tag>/, which is what every
# recipe function cds into. Deriving it from the rename target rather than
# restating _tag keeps this honest if the recipe's naming changes.
topdir="${tarball%.tar.gz}"

echo "==> staging the candidate tree as $tarball"
echo "    recipe declares: $url"
cp -a -- "$STAGED" "$BUILD/$topdir"
chown -R "$BUILDER:$BUILDER" "$BUILD/$topdir"
runuser -u "$BUILDER" -- tar -C "$BUILD" -czf "$BUILD/$tarball" "$topdir"
rm -rf -- "$BUILD/${topdir:?}"

staged_sum="$(sha256sum "$BUILD/$tarball" | cut -d' ' -f1)"

# Prove the integrity gate bites before relying on it: a digest that cannot
# match the staged tarball must make --verifysource fail. Flipping the first
# nibble keeps the value well-formed while guaranteeing a mismatch.
case "$staged_sum" in
    0*) wrong_sum="f${staged_sum:1}" ;;
    *) wrong_sum="0${staged_sum:1}" ;;
esac
echo "==> verifying a wrong digest is rejected"
sed -i "s/^sha256sums=.*/sha256sums=('${wrong_sum}')/" "$BUILD/PKGBUILD"
chown "$BUILDER:$BUILDER" "$BUILD/PKGBUILD"
if runuser -u "$BUILDER" -- /run-networkless.sh \
    bash -c "cd '$BUILD' && makepkg --verifysource --nodeps --noconfirm" >/dev/null 2>&1; then
    fail "makepkg accepted a tarball whose digest does not match sha256sums"
fi

# Finalize the staged digest exactly as publish-aur.sh finalizes the shipped
# recipe, so the verification below checks the sum for real.
sed -i "s/^sha256sums=.*/sha256sums=('${staged_sum}')/" "$BUILD/PKGBUILD"
chown "$BUILDER:$BUILDER" "$BUILD/PKGBUILD"

# Refresh the sync database once as root. makepkg --syncdeps below resolves the
# recipe's own depends and makedepends through pacman against this snapshot.
pacman -Sy --noconfirm >/dev/null

echo "==> verifying sources with networking denied"
runuser -u "$BUILDER" -- /run-networkless.sh \
    bash -c "cd '$BUILD' && makepkg --verifysource --nodeps --noconfirm" ||
    fail "source verification reached for the network or rejected the staged tarball"

# prepare() runs `cargo fetch --locked`, so this half is deliberately online;
# build() and check() are --frozen and therefore offline regardless.
echo "==> makepkg: syncdeps, prepare, build, check, package"
runuser -u "$BUILDER" -- \
    bash -c "cd '$BUILD' && makepkg --syncdeps --noconfirm" ||
    fail "makepkg failed"

package="$(find "$BUILD" -maxdepth 1 -type f -name 'facelock-*.pkg.tar.zst' -print -quit)"
[ -n "$package" ] || fail "makepkg produced no package"

echo "==> pacman -U $(basename -- "$package")"
cp -- "$package" /facelock-test-package.pkg.tar.zst
pacman -U --noconfirm -- "$package"
rm -rf -- "$BUILD"
