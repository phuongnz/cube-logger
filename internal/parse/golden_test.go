package parse_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phuongnz/cube-logger/internal/parse"
	"github.com/phuongnz/cube-logger/internal/testutil"
)

// fixtureYear is the year the fixtures are set in. IOS logs no year, so every
// test has to supply one; pinning it keeps the golden files stable.
const fixtureYear = 2026

// Fixtures returns every capture fixture. They live in one directory at the
// repository root because the parser and the correlator are tested against the
// same files.
func Fixtures(t *testing.T) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("..", "..", "testdata", "*.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no fixtures found under testdata/")
	}
	return paths
}

// Parse reads one fixture. The source name is the file name rather than the
// path, so a golden file does not depend on where the repository sits.
func Parse(t *testing.T, path string) *parse.Result {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	res, err := parse.Reader(f, filepath.Base(path), fixtureYear)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestGoldenRecords(t *testing.T) {
	for _, path := range Fixtures(t) {
		t.Run(filepath.Base(path), func(t *testing.T) {
			got, err := json.MarshalIndent(Parse(t, path), "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			golden := strings.TrimSuffix(path, ".txt") + ".records.json"
			testutil.Golden(t, golden, append(got, '\n'))
		})
	}
}

// TestEveryLineIsAccountedFor is the invariant behind the whole reassembler:
// a record's first line carries the frame and every bare line after it belongs
// to that record, so no line may be silently dropped.
func TestEveryLineIsAccountedFor(t *testing.T) {
	for _, path := range Fixtures(t) {
		t.Run(filepath.Base(path), func(t *testing.T) {
			res := Parse(t, path)
			n := len(res.Orphans)
			for _, r := range res.Records {
				n += len(r.Raw)
			}
			// A fixture's final newline produces no line.
			if n != res.Lines {
				t.Errorf("accounted for %d lines of %d", n, res.Lines)
			}
		})
	}
}

// TestContentLengthMatches checks the integrity test docs/log-format.md
// established on the real capture: on the terminal path every SIP body matches
// its Content-Length exactly. The one fixture that breaks it does so on purpose.
func TestContentLengthMatches(t *testing.T) {
	for _, path := range Fixtures(t) {
		name := filepath.Base(path)
		if name == "wrapped_buffer.txt" {
			continue // carries a deliberately short body
		}
		t.Run(name, func(t *testing.T) {
			for _, r := range Parse(t, path).Records {
				if r.SIP == nil || !r.SIP.HasContentLength {
					continue
				}
				if r.SIP.BodyBytes != r.SIP.ContentLength {
					t.Errorf("line %d: body is %d bytes, Content-Length is %d",
						r.Line, r.SIP.BodyBytes, r.SIP.ContentLength)
				}
			}
		})
	}
}
