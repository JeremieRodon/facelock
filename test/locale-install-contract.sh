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

# --- every install path calls the installer, on a live line -----------------

[ -x "$installer" ] || fail "$installer must exist and be executable"

# Each entry: <file>|<regex anchoring the call to a non-comment line>|<label>.
#
# The anchor carries more weight than it looks. A plain `grep -F` for the call
# matches a commented-out copy just as happily, so the gate stays green while
# that path installs nothing — the exact silent skip this contract exists to
# catch. `^[[:space:]]*` cannot match a `#`, in make recipes, shell, spec
# scriptlets and Nix indented strings alike.
call_sites=(
    "debian/rules|^[[:space:]]*scripts/install-locale-catalogs\.sh debian/facelock/usr/share/locale\$|debian/rules must install compiled catalogs into the binary package"
    "dist/facelock.spec|^[[:space:]]*scripts/install-locale-catalogs\.sh %\{buildroot\}%\{_datadir\}/locale\$|dist/facelock.spec must install compiled catalogs into the buildroot"
    "dist/PKGBUILD|^[[:space:]]*scripts/install-locale-catalogs\.sh \"\\\$pkgdir/usr/share/locale\"\$|dist/PKGBUILD must install compiled catalogs into \$pkgdir"
    "dist/PKGBUILD-bin|^[[:space:]]*scripts/install-locale-catalogs\.sh \"\\\$pkgdir/usr/share/locale\"\$|dist/PKGBUILD-bin must install compiled catalogs into \$pkgdir"
    "dist/PKGBUILD-git|^[[:space:]]*scripts/install-locale-catalogs\.sh \"\\\$pkgdir/usr/share/locale\"\$|dist/PKGBUILD-git must install compiled catalogs into \$pkgdir"
    "dist/nix/default.nix|^[[:space:]]*bash scripts/install-locale-catalogs\.sh \\\$out/share/locale\$|dist/nix/default.nix must install compiled catalogs into \$out"
    # The source install is how OpenRC, runit and s6 systems get facelock; there
    # is no separate packaging path for them. `bash -p` because install-files'
    # own -p does not reach a child started from its shebang.
    "justfile|^[[:space:]]*bash -p scripts/install-locale-catalogs\.sh /usr/share/locale\$|justfile install-files must install compiled catalogs"
)

matched_lines=()
for entry in "${call_sites[@]}"; do
    file="${entry%%|*}"
    rest="${entry#*|}"
    pattern="${rest%%|*}"
    label="${rest#*|}"
    line="$(grep -E -m1 "$pattern" "$file" || true)"
    [ -n "$line" ] || fail "$label (no live, uncommented call site found)"
    matched_lines+=("$file|$line")
done

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

# --- functional: each packaging path's own command line reaches the installer

# The anchors above prove a live call site exists; they cannot prove it works.
# Run the exact line each file carries, with only its destination argument
# redirected, so a typo'd script path, a dropped `bash` prefix or a wrong flag
# fails here rather than in a release build.
for matched in "${matched_lines[@]}"; do
    file="${matched%%|*}"
    line="${matched#*|}"
    probe="$work/probe/${file//\//_}"
    mkdir -p "$probe"
    # The destination is always the final argument; keep everything before it
    # (`bash`, `bash -p`, the script path) exactly as the file spells it.
    command_prefix="${line% *}"
    if ! (
        cd "$repo_root"
        FACELOCK_PO_DIR="$work/po" eval "$command_prefix \"\$probe\""
    ) >/dev/null 2>&1; then
        fail "$file: its own install command failed to run"
    fi
    for domain in facelock pam_facelock; do
        [ -f "$probe/$lang/LC_MESSAGES/$domain.mo" ] ||
            fail "$file: its own install command placed no $domain.mo"
    done
done

echo "locale install contract: ok"
