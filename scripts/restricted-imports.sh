#!/usr/bin/env bash
# Fails when an extraction package imports os/exec, plugin, syscall or unsafe
# directly. make lint and CI's "Restricted Imports Check" both run this file.
set -euo pipefail

RESTRICTED="os/exec|plugin|syscall|unsafe"
PACKAGES="./internal/license/... ./internal/iface/... ./internal/callgraph/... ./internal/example/..."

# go list runs on its own so a load failure fails the check instead of
# reading as "no imports".
# shellcheck disable=SC2086 # PACKAGES is a word list on purpose
LISTED=$(go list -f '{{.ImportPath}} {{join .Imports " "}}' $PACKAGES)
FOUND=$(grep -E " ($RESTRICTED)" <<<"$LISTED" || true)
if [ -n "$FOUND" ]; then
  echo "::error::Restricted imports found in extraction packages:"
  echo "$FOUND"
  exit 1
fi
echo "No restricted imports found."
