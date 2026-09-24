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
  # Each step reports rather than aborting, so one run tells you everything that
  # is wrong instead of only the first thing.
  echo "== gofmt =="
  unformatted=$(gofmt -l . || true)
  if [ -n "$unformatted" ]; then
    echo "FAIL: not gofmt-clean (run: gofmt -w .):" >&2
    echo "$unformatted" >&2
    fail=1
  else
    echo "ok: gofmt-clean"
  fi

  echo "== go build =="
  go build ./... || fail=1

  echo "== go vet =="
  go vet ./... || fail=1

  # The test suite carries its own safety net: TestFixturesAreSafeToPublish in
  # internal/sanitize walks testdata/ and rejects any address or domain that is
  # not from a reserved range. Fixtures are committed to a public repository.
  echo "== go test =="
  go test ./... || fail=1
else
  echo "no Go module yet — nothing to test"
fi

exit "$fail"
