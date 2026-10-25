#!/usr/bin/env bash
# Lists every non-standard-library package in the build, kanonarion's and its
# dependencies', on every release target, and fails when the packages that
# import os/exec, plugin, syscall or unsafe differ from
# scripts/restricted-imports.allow in either direction. Where processes are
# started is checked separately, by TestEveryChildProcessIsHardened in
# test/architecture_test.go. make lint and CI's "Restricted Imports Check"
# both run this file; --print writes the pairs instead of comparing them.
set -euo pipefail

# Must match ci.yml's "Cross-compile the release matrix" step and the target
# loops in release.yml.
TARGETS="darwin/amd64 darwin/arm64 windows/amd64 windows/arm64 linux/amd64 linux/arm64 linux/arm"
RESTRICTED="os/exec|plugin|syscall|unsafe"
ALLOW="$(dirname "$0")/restricted-imports.allow"

export LC_ALL=C

# One "<package> <import>" line per restricted import, over every target.
FOUND=""
for t in $TARGETS; do
  # go list runs as a plain assignment so a load failure stops the script
  # instead of reading as "no imports".
  listed=$(GOOS=${t%/*} GOARCH=${t#*/} go list -deps \
    -f '{{if not .Standard}}{{.ImportPath}} {{join .Imports " "}}{{end}}' ./...)
  FOUND+=$(awk -v re="^($RESTRICTED)\$" '{ for (i = 2; i <= NF; i++) if ($i ~ re) print $1, $i }' <<<"$listed")$'\n'
done
FOUND=$(grep -v '^$' <<<"$FOUND" | sort -u)

# --print writes the pairs the build holds, for regenerating the list.
if [ "${1:-}" = "--print" ]; then
  echo "$FOUND"
  exit 0
fi

LISTED=$(grep -Ev '^[[:space:]]*(#|$)' "$ALLOW" || true)

if [ "$LISTED" != "$(sort -u <<<"$LISTED")" ]; then
  echo "::error::$ALLOW must be sorted (LC_ALL=C sort -u) with no duplicate lines."
  exit 1
fi

MISSING=$(comm -23 <(printf '%s\n' "$FOUND") <(printf '%s\n' "$LISTED") | grep -v '^$' || true)
STALE=$(comm -13 <(printf '%s\n' "$FOUND") <(printf '%s\n' "$LISTED") | grep -v '^$' || true)

status=0
if [ -n "$MISSING" ]; then
  echo "::error::Restricted imports not in $ALLOW (add them after review, or remove the import):"
  echo "$MISSING"
  status=1
fi
if [ -n "$STALE" ]; then
  echo "::error::$ALLOW lists pairs no target's build contains (remove them: the list cannot outlive the code it describes):"
  echo "$STALE"
  status=1
fi
if [ "$status" -ne 0 ]; then
  exit 1
fi

TARGET_COUNT=$(wc -w <<<"$TARGETS")
echo "Restricted imports match $ALLOW: $(grep -c . <<<"$FOUND") pairs across $TARGET_COUNT release targets."
