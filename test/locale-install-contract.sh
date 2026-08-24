#!/usr/bin/env bash
# Every install path must ship compiled gettext catalogs.
#
# po/ holds only .pot templates, so nothing in the tree exercises this on its
# own: seven install paths can all be wired wrong and every other gate stays
# green. This builds a throwaway pseudo-locale from the real templates, runs
# the shared installer against it, and asserts both domains land at
# <root>/<lang>/LC_MESSAGES/<domain>.mo — then checks statically that each
# packaging path actually calls that installer and declares gettext.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
installer=scripts/install-locale-catalogs.sh

fail() {
    echo "locale install contract: $*" >&2
    exit 1
}

# --- static: every install path calls the installer -------------------------

[ -x "$installer" ] || fail "$installer must exist and be executable"

grep -Fq 'scripts/install-locale-catalogs.sh debian/facelock/usr/share/locale' debian/rules ||
    fail "debian/rules must install compiled catalogs into the binary package"
grep -Fq 'scripts/install-locale-catalogs.sh %{buildroot}%{_datadir}/locale' dist/facelock.spec ||
    fail "dist/facelock.spec must install compiled catalogs into the buildroot"
# shellcheck disable=SC2016  # the literal $pkgdir/$out are what must appear
for pkgbuild in dist/PKGBUILD dist/PKGBUILD-bin dist/PKGBUILD-git; do
    grep -Fq 'scripts/install-locale-catalogs.sh "$pkgdir/usr/share/locale"' "$pkgbuild" ||
        fail "$pkgbuild must install compiled catalogs into \$pkgdir"
done
# shellcheck disable=SC2016
grep -Fq 'scripts/install-locale-catalogs.sh $out/share/locale' dist/nix/default.nix ||
    fail "dist/nix/default.nix must install compiled catalogs into \$out"
# The source install is how OpenRC, runit and s6 systems get facelock; there is
# no separate packaging path for them.
grep -Fq 'scripts/install-locale-catalogs.sh /usr/share/locale' justfile ||
    fail "justfile install-files must install compiled catalogs"

# %files is exhaustive, so a hand-listed locale path would break the RPM build
# the moment a new language appears. Only %find_lang generates that list, and
# it has to run for both domains.
grep -Fq '%find_lang %{name}' dist/facelock.spec ||
    fail "dist/facelock.spec must collect the facelock catalog with %find_lang"
grep -Fq '%find_lang pam_facelock' dist/facelock.spec ||
    fail "dist/facelock.spec must collect the pam_facelock catalog with %find_lang"
grep -Fq '%files -f %{name}.lang' dist/facelock.spec ||
    fail "dist/facelock.spec %files must consume the generated language list"
# That list is empty until a translation lands, and rpm 4.20 fails the build on
# an empty -f manifest. Without this the RPM is unbuildable in the exact state
# the tree is in today.
grep -Fq '%global _empty_manifest_terminate_build 0' dist/facelock.spec ||
    fail "dist/facelock.spec must tolerate an empty %find_lang manifest"

# msgfmt has to be present wherever a package is built, or the first
# translation to land turns into a failed build instead of a shipped catalog.
grep -Fq 'BuildRequires:  gettext' dist/facelock.spec ||
    fail "dist/facelock.spec must BuildRequire gettext"
grep -Eq '^[[:space:]]*gettext,[[:space:]]*$' debian/control ||
    fail "debian/control Build-Depends must include gettext"
for pkgbuild in dist/PKGBUILD dist/PKGBUILD-bin dist/PKGBUILD-git; do
    grep -Eq "^makedepends=\(.*'gettext'" "$pkgbuild" ||
        fail "$pkgbuild must declare gettext in makedepends"
done
grep -Fq 'gettext' dist/nix/default.nix ||
    fail "dist/nix/default.nix must take gettext as a native build input"

# --- functional: a real catalog reaches a real locale root ------------------

if ! command -v msgfmt >/dev/null || ! command -v msgen >/dev/null; then
    echo "locale install contract: static checks passed; gettext absent, skipping the compile check"
    exit 0
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/facelock-locale-contract.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT

# Nothing to install must stay a no-op that creates no empty locale root: an
# unowned, empty /usr/share/locale in a package is a packaging bug of its own.
FACELOCK_PO_DIR="$work/empty-po" "$installer" "$work/empty-dest" >/dev/null
[ ! -e "$work/empty-dest" ] ||
    fail "installer created a locale root with no translations to put in it"

# A throwaway pseudo-locale, built the way a translator would start one, from
# the committed templates. Never committed: po/ holding only templates is the
# intended state.
lang=zz_ZZ
mkdir -p "$work/po/$lang"
for domain in facelock pam_facelock; do
    msgen "po/$domain.pot" |
        sed -e '/^#, fuzzy$/d' \
            -e 's/charset=CHARSET/charset=UTF-8/' \
            -e "s/^\"Language: .*/\"Language: $lang\\\\n\"/" \
            -e 's/^"PO-Revision-Date: .*/"PO-Revision-Date: 2026-01-01 00:00+0000\\n"/' \
            -e 's/^"Last-Translator: .*/"Last-Translator: contract fixture <fixture@invalid>\\n"/' \
            -e 's/^"Language-Team: .*/"Language-Team: contract fixture <fixture@invalid>\\n"/' \
            > "$work/po/$lang/$domain.po"
done

FACELOCK_PO_DIR="$work/po" "$installer" "$work/dest" >/dev/null

for domain in facelock pam_facelock; do
    mo="$work/dest/$lang/LC_MESSAGES/$domain.mo"
    [ -f "$mo" ] || fail "installer did not place $domain.mo under $lang/LC_MESSAGES/"
    [ "$(stat -c '%a' "$mo")" = 644 ] || fail "$domain.mo must be world-readable 0644"
    msgunfmt "$mo" >/dev/null || fail "$domain.mo is not a valid compiled catalog"
done

# The two domains are separate catalogs with separate dependency ceilings.
# Merging them would show up here as one file carrying the other's msgids.
pam_messages="$(msgunfmt "$work/dest/$lang/LC_MESSAGES/pam_facelock.mo")"
printf '%s\n' "$pam_messages" | grep -Fq 'Identifying face...' ||
    fail "pam_facelock.mo lost its own messages"
if printf '%s\n' "$pam_messages" | grep -Fq 'Root required. Re-run with sudo?'; then
    fail "pam_facelock.mo absorbed CLI messages; the two domains must stay split"
fi

# --check must stay live: a translation that invents a {placeholder} is what it
# exists to catch, and a package build must reject it too. Only the msgstr is
# mangled — a matching pair on both sides is legitimate.
broken="$work/broken-po/$lang"
mkdir -p "$broken"
awk '
    /^msgstr "/ && /\{[a-z_][a-z0-9_]*\}/ && !done {
        gsub(/\{[a-z_][a-z0-9_]*\}/, "{typoed_placeholder}")
        done = 1
    }
    { print }
' "$work/po/$lang/facelock.po" > "$broken/facelock.po"
if FACELOCK_PO_DIR="$work/broken-po" "$installer" "$work/broken-dest" >/dev/null 2>&1; then
    fail "installer accepted a translation with an invented placeholder"
fi
# msgfmt writes its output file even on a fatal --check error, so a rejected
# translation must never reach the destination — on a source install that
# destination is the live /usr/share/locale.
[ ! -e "$work/broken-dest" ] ||
    fail "installer left output behind for a rejected translation"

echo "locale install contract: ok"
