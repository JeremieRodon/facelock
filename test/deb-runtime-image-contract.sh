#!/usr/bin/env bash
# Structural contract for the Debian harness image, read from the Containerfile.
#
# The booted lifecycle gate sorts each declared dependency into "the suite base
# ships it", "the harness is allowed to pre-satisfy it", or "the runtime
# transaction resolves it", using a package manifest recorded while the
# dependency-closure stage was built. deb-dependency-closure.sh compares that
# record against its own live dpkg database at run time, which catches anything
# installed after the record was taken.
#
# Nothing at run time can catch an install placed before it. The record would be
# poisoned at birth, the comparison would confirm the poisoned copy, and the
# lifecycle gate would file a harness-installed package under "the suite base
# ships it" — the exact masking these gates exist to remove. Only reading the
# Containerfile settles it, so that is what this does.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
containerfile="${1:-$script_dir/Containerfile.deb-runtime}"
RECORD=/facelock-suite-base-packages
STAGE=dependency-closure

fail() {
    echo "deb runtime image contract: $*" >&2
    exit 1
}

[ -f "$containerfile" ] && [ ! -L "$containerfile" ] ||
    fail "Containerfile is not a regular file: $containerfile"

# One record per instruction: "<stage>\t<KEYWORD>\t<instruction, continuations
# joined>". Comments and blank lines are dropped, and a comment never continues
# an instruction.
instructions="$(awk '
    {
        line = $0
        if (continuing) {
            continuing = (line ~ /\\[[:space:]]*$/)
            sub(/\\[[:space:]]*$/, " ", line)
            text = text line
            if (!continuing) { print stage "\t" keyword "\t" text }
            next
        }
        sub(/^[[:space:]]+/, "", line)
        if (line == "" || line ~ /^#/) next
        keyword = toupper(substr(line, 1, index(line " ", " ") - 1))
        if (keyword == "FROM") {
            stage = ""
            if (match(line, /[[:space:]][Aa][Ss][[:space:]]+[^[:space:]]+[[:space:]]*$/)) {
                stage = substr(line, RSTART, RLENGTH)
                sub(/^[[:space:]]+[Aa][Ss][[:space:]]+/, "", stage)
                sub(/[[:space:]]+$/, "", stage)
            }
        }
        text = line
        continuing = (line ~ /\\[[:space:]]*$/)
        sub(/\\[[:space:]]*$/, " ", text)
        if (!continuing) { print stage "\t" keyword "\t" text }
    }
' "$containerfile")"

stage_count="$(printf '%s\n' "$instructions" |
    awk -F'\t' -v stage="$STAGE" '$2 == "FROM" && $1 == stage' | wc -l)"
[ "$stage_count" -eq 1 ] ||
    fail "expected exactly one $STAGE stage, found $stage_count"

# Only RUN, COPY, and ADD can change a stage's package set. ENV, ARG, and the
# other inert instructions may precede the record.
first_mutation="$(printf '%s\n' "$instructions" |
    awk -F'\t' -v stage="$STAGE" '
        $1 == stage && ($2 == "RUN" || $2 == "COPY" || $2 == "ADD") { print; exit }
    ')"
[ -n "$first_mutation" ] ||
    fail "$STAGE stage records no suite package set"
IFS=$'\t' read -r _ first_keyword first_text <<<"$first_mutation"
[ "$first_keyword" = RUN ] ||
    fail "the $STAGE stage must record $RECORD before its first $first_keyword: $first_text"
case "$first_text" in
    *"$RECORD"*) ;;
    *) fail "the first RUN in the $STAGE stage must record $RECORD, not: $first_text" ;;
esac

# The record is only worth taking if the harness image actually carries it.
printf '%s\n' "$instructions" |
    awk -F'\t' -v stage="$STAGE" -v record="$RECORD" '
        $2 == "COPY" && $1 != stage &&
            index($3, "--from=" stage) && index($3, record) { found = 1 }
        END { exit found ? 0 : 1 }
    ' ||
    fail "no later stage copies $RECORD out of the $STAGE stage"

echo "deb runtime image contract: ok"
