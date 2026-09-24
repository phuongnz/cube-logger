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

  # The tool is meant to stay a single binary that go:embed can ship and that
  # needs no toolchain to build. Every dependency past the standard library is a
  # decision worth making on purpose, so an accidental one has to fail here.
  echo "== no external dependencies =="
  deps=$(go list -deps -f '{{if and .Module (not .Standard)}}{{.Module.Path}}{{end}}' ./... \
    | grep -v '^github.com/phuongnz/cube-logger$' | sort -u || true)
  if [ -n "$deps" ]; then
    echo "FAIL: the module depends on something outside the standard library:" >&2
    echo "$deps" >&2
    fail=1
  else
    echo "ok: standard library only"
  fi

  # The test suite carries its own safety net: TestFixturesAreSafeToPublish in
  # internal/sanitize walks testdata/ and rejects any address or domain that is
  # not from a reserved range. Fixtures are committed to a public repository.
  echo "== go test =="
  go test ./... || fail=1

  # The live path is several goroutines around one reassembler, one ring buffer
  # and one hijacked socket. A data race there shows up as a record that is
  # occasionally wrong, which is the hardest kind of bug to be told about, so
  # the concurrent packages are run under the race detector on every checkpoint.
  echo "== go test -race (concurrent packages) =="
  go test -race -count=1 \
    ./internal/live/... ./internal/store/... ./internal/ws/... \
    ./internal/listen/... ./internal/calls/... ./internal/web/... ./cmd/... || fail=1
else
  echo "no Go module yet — nothing to test"
fi

# The UI has no build step and no test runner, which is the point: one binary,
# no toolchain. The cost is that a syntax error in app.js is invisible until a
# browser silently renders nothing, so it is checked here when a JavaScript
# engine happens to be installed. Nothing is installed to make this run, and a
# machine without one is not a failure.
if command -v node >/dev/null 2>&1; then
  echo "== ui syntax =="
  if node --check internal/web/ui/app.js; then
    echo "ok: app.js parses"
  else
    fail=1
  fi
else
  echo "== ui syntax == (skipped: no node on this machine)"
fi

exit "$fail"
