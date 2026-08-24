#!/usr/bin/env bash
# Compile this tree's translations into a locale root.
#
# Every install path calls this — deb, rpm, the three PKGBUILDs, Nix, and the
# source install (`just install-files`, which is also how OpenRC/runit/s6
# systems install). Before this existed only `just install-files` shipped a
# catalog, and only when the operator had run `just mo` first.
#
# po/ holds nothing but .pot templates today, so this is a no-op everywhere.
# That is the point: the moment the first po/<lang>/<domain>.po lands it must
# reach every package, and wiring seven install paths after translations exist
# means shipping untranslated packages in between.
#
# Usage: install-locale-catalogs.sh <destdir>
#
#   <destdir>  locale root to populate — /usr/share/locale, or a staging root
#              such as debian/facelock/usr/share/locale. Created only when
#              there is something to put in it, so no packaging path ends up
#              owning an empty /usr/share/locale.
#
# The two gettext domains stay separate by construction: this compiles whatever
# po/<lang>/ names, and `facelock` (CLI) and `pam_facelock` (PAM module, which
# has its own dependency ceiling) never merge.
#
# FACELOCK_PO_DIR overrides the source directory. Test-only.
set -euo pipefail

[ "$#" -eq 1 ] || {
    echo "usage: install-locale-catalogs.sh <destdir>" >&2
    exit 2
}
destdir="$1"
[ -n "$destdir" ] || {
    echo "install-locale-catalogs: destination must not be empty" >&2
    exit 2
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
po_dir="${FACELOCK_PO_DIR:-$repo_root/po}"

shopt -s nullglob
catalogs=("$po_dir"/*/*.po)
shopt -u nullglob

if [ "${#catalogs[@]}" -eq 0 ]; then
    echo "install-locale-catalogs: no po/<lang>/*.po in $po_dir — nothing to install"
    exit 0
fi

command -v msgfmt >/dev/null || {
    echo "install-locale-catalogs: msgfmt not found, but $po_dir holds ${#catalogs[@]} translation(s)." >&2
    echo "                         Install gettext. Refusing to build a package that" >&2
    echo "                         silently drops translations it was asked to ship." >&2
    exit 1
}

# Compile into a private staging tree first: msgfmt (gettext 1.0) writes its
# output file even when --check finds a fatal error, so compiling straight
# into <destdir> would install the very catalog it just rejected — on a source
# install that is the live /usr/share/locale. Nothing reaches <destdir> until
# every catalog has passed.
staging="$(mktemp -d)"
trap 'rm -rf -- "$staging"' EXIT

for po in "${catalogs[@]}"; do
    lang="$(basename "$(dirname "$po")")"
    domain="$(basename "$po" .po)"
    mkdir -p "$staging/$lang"
    # --check is what enforces the `{placeholder}` contract (see `just pot`).
    # Keeping it here means a package build rejects a broken translation too,
    # not only a translator running `just mo`.
    msgfmt --check -o "$staging/$lang/$domain.mo" "$po"
done

for po in "${catalogs[@]}"; do
    lang="$(basename "$(dirname "$po")")"
    domain="$(basename "$po" .po)"
    out="$destdir/$lang/LC_MESSAGES/$domain.mo"
    install -Dm644 "$staging/$lang/$domain.mo" "$out"
    echo "  $po -> $out"
done
