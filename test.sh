#!/usr/bin/env bash
# The phase checkpoint runs this. It has to be honest about a repository that is
# still growing: nothing to test yet is a pass, a failing test is a failure.
# Extend it as the project grows (web UI tests, vet, lint).
set -euo pipefail

fail=0

# This repository is public and the raw captures are production CUBE output. A tracked
# capture would be a data leak that no later commit can undo, so check on every run.
echo "== checking that no raw capture is tracked by git =="
leaked=$(git ls-files -- 'captures/*' '*.log' '*.pcap' '*.pcapng' || true)
if [ -n "$leaked" ]; then
  echo "FAIL: raw capture files are tracked by git:" >&2
  echo "$leaked" >&2
  fail=1
else
  echo "ok: captures/, *.log, *.pcap and *.pcapng are untracked"
fi

if [ -f go.mod ]; then
  echo "== go vet =="
  go vet ./...
  echo "== go test =="
  go test ./...
else
  echo "no Go module yet — nothing to test"
fi

exit "$fail"
