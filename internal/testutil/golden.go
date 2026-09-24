// Package testutil holds the golden-file helper the parser, correlator and
// sanitizer tests share.
//
// A golden test states the expected answer as a file rather than as assertions,
// which is what makes a parser test readable: the fixture is CUBE output and
// the golden file is exactly what the tool made of it. Regenerate with
// "go test ./... -update", then read the diff before committing it — an
// unreviewed -update turns a bug into the expected answer.
package testutil

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// Update is set by "go test -update" and rewrites every golden file.
var Update = flag.Bool("update", false, "rewrite the golden files from the current output")

// Golden compares got against the contents of path, or rewrites path when
// -update is set.
func Golden(t *testing.T, path string, got []byte) {
	t.Helper()
	if *Update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run: go test ./... -update, then read the diff)", err)
	}
	if string(got) == string(want) {
		return
	}
	t.Errorf("%s does not match.\n--- want ---\n%s\n--- got ---\n%s", path, firstDiff(want, got), firstDiff(got, want))
}

// firstDiff trims a mismatch down to the lines around the first difference, so
// a failure names the change instead of printing two whole files.
func firstDiff(a, b []byte) string {
	const context = 120
	i := 0
	for i < len(a) && i < len(b) && a[i] == b[i] {
		i++
	}
	start := i - context
	if start < 0 {
		start = 0
	}
	end := i + context
	if end > len(a) {
		end = len(a)
	}
	return string(a[start:end])
}
