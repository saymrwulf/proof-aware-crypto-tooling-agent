#!/usr/bin/env bash
# check-paper.sh — the paper's form gate.
#
# Ports the book's check-book.sh lesson to the paper: the 2026-08-16
# socratic round found a ghost page (a fossil \clearpage) and a solid-set
# claim matrix whose badness-10000 warnings had printed in EVERY build,
# unread. This gate makes both classes of defect fail the build instead
# of shipping silently. It cannot replace the render-and-look eye pass —
# it renders the pages so the eye pass has no excuse.
#
# Usage:  ./check-paper.sh            build + all gates + render pages
#         ./check-paper.sh --selftest exercise the gate parsers on
#                                     known-bad and known-good log lines
set -euo pipefail
cd "$(dirname "$0")"

OVERFULL_LIMIT_PT=10
MIN_PAGE_CHARS=300     # calibrated 2026-08-16: real minimum was 922 (claim-matrix page)
PAGES_DIR=rendered-pages

fail() { echo "FAIL: $*" >&2; exit 1; }

# --- gate parsers (pure text -> verdict; selftestable) -------------------
overfull_violations() {  # stdin: build log -> lines exceeding the limit
  grep -i 'Overfull \\hbox' | grep -oP '\(\K[0-9.]+(?=pt too wide)' \
    | awk -v lim="$OVERFULL_LIMIT_PT" '$1 > lim' || true
}
badness_violations() {   # stdin: build log -> badness-10000 underfull lines
  grep -i 'Underfull \\hbox (badness 10000)' || true
}

if [[ "${1:-}" == "--selftest" ]]; then
  n=0
  t() { n=$((n+1)); [[ "$2" == "$3" ]] && echo "selftest $n ok: $1" || fail "selftest $n: $1 (got '$3', want '$2')"; }
  t "80pt overfull trips" "80.05" \
    "$(echo 'warning: x.tex:1: Overfull \hbox (80.05pt too wide) in paragraph' | overfull_violations)"
  t "3.4pt overfull passes" "" \
    "$(echo 'warning: x.tex:1: Overfull \hbox (3.374pt too wide) in paragraph' | overfull_violations)"
  t "badness 10000 trips" "1" \
    "$(echo 'warning: x.tex:1: Underfull \hbox (badness 10000) in paragraph' | badness_violations | wc -l)"
  t "badness 2913 passes" "0" \
    "$(echo 'warning: x.tex:1: Underfull \hbox (badness 2913) in paragraph' | badness_violations | wc -l)"
  echo "selftest: $n/$n ok"; exit 0
fi

# --- 1. build ------------------------------------------------------------
LOG=$(mktemp); trap 'rm -f "$LOG"' EXIT
tectonic ltl.tex 2>&1 | tee "$LOG" >/dev/null
grep -qi '^error' "$LOG" && fail "TeX errors in build log"

# --- 2. overfull gate ----------------------------------------------------
OV=$(overfull_violations <"$LOG")
[[ -z "$OV" ]] || fail "overfull hbox beyond ${OVERFULL_LIMIT_PT}pt: $OV"

# --- 3. loose-typesetting gate (the ignored-warnings class) --------------
BAD=$(badness_violations <"$LOG" | wc -l)
[[ "$BAD" -eq 0 ]] || fail "$BAD underfull badness-10000 lines (gappy table/paragraph)"

# --- 4. ghost-page gate (the fossil-clearpage class) ---------------------
NPAGES=$(pdfinfo ltl.pdf | awk '/^Pages:/{print $2}')
for p in $(seq 1 $((NPAGES-1))); do
  chars=$(pdftotext -f "$p" -l "$p" ltl.pdf - 2>/dev/null | tr -d '[:space:]' | wc -c)
  [[ "$chars" -ge "$MIN_PAGE_CHARS" ]] || fail "page $p is mostly blank ($chars chars) — ghost page"
done

# --- 5. content probes ---------------------------------------------------
VERSION=$(grep -oP '\\date\{[^}]*---\s*\Kv[0-9.]+' ltl.tex || true)
[[ -n "$VERSION" ]] || fail "cannot extract version from \\date{...} in ltl.tex"
pdftotext -f 1 -l 1 ltl.pdf - | grep -q "$VERSION" || fail "title page does not carry $VERSION"
! pdftotext ltl.pdf - | grep -q '??' || fail "unresolved ?? reference in PDF"

# --- 6. render for the mandatory eye pass --------------------------------
rm -rf "$PAGES_DIR"; mkdir -p "$PAGES_DIR"
pdftoppm -png -r 110 ltl.pdf "$PAGES_DIR/p"
echo "OK: $VERSION, $NPAGES pages, no overfull>${OVERFULL_LIMIT_PT}pt, no badness-10000, no ghost pages, no ?? refs."
echo "NOW LOOK: the render-and-look law is not automated. Flip every page in $PAGES_DIR/."
