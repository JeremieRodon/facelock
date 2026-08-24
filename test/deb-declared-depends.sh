#!/usr/bin/env bash
# Shared reading of the exact candidate's declared runtime dependencies.
#
# Two Debian gates reason about the same Depends field from opposite ends:
# deb-dependency-closure.sh proves it resolves on a pristine suite base, and
# deb-package-lifecycle.sh proves the booted harness image is not quietly
# satisfying it in advance. One parser keeps them from disagreeing about what
# the package actually declares.
#
# Sourced, never executed. The caller defines fail().

# Emit one line per Depends element. Alternatives stay together on their line,
# space separated, because any one of them satisfies the element. Version
# constraints, build profiles, and multiarch qualifiers are stripped.
declared_dependency_groups() {
    local package="$1" element
    dpkg-deb --field "$package" Depends |
        tr ',' '\n' |
        sed -e 's/([^)]*)//g' -e 's/\[[^]]*\]//g' -e 's/<[^>]*>//g' |
        while IFS= read -r element; do
            printf '%s\n' "$element" |
                tr '|' '\n' |
                sed -e 's/[[:space:]]//g' -e 's/:.*$//' -e '/^$/d' |
                paste -sd' ' -
        done |
        sed '/^$/d'
}

dependency_installed() {
    dpkg-query -W -f='${db:Status-Status}\n' "$1" 2>/dev/null |
        grep -qx installed
}

dependency_group_satisfied() {
    local name
    for name in $1; do
        if dependency_installed "$name"; then
            return 0
        fi
    done
    return 1
}

# Fail unless every dependency element read from stdin has an installed
# alternative. Counting "at least one dependency arrived" cannot tell a full
# closure from a near-empty one, so each element is checked by name.
assert_dependency_groups_satisfied() {
    local label="$1" group resolved=0
    while IFS= read -r group; do
        [ -n "$group" ] || continue
        dependency_group_satisfied "$group" ||
            fail "$label: declared dependency is unsatisfied: $group"
        resolved=$((resolved + 1))
    done
    [ "$resolved" -gt 0 ] || fail "$label: no declared dependency was checked"
}
