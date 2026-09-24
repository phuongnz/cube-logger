#!/usr/bin/env bash
# The phase checkpoint runs this. It has to be honest about a repository that is
# still growing: nothing to test yet is a pass, a failing test is a failure.
# Extend it as the project grows (web UI tests, vet, lint).
set -euo pipefail

if [ -f go.mod ]; then
  go vet ./...
  go test ./...
else
  echo "no Go module yet — nothing to test"
fi
