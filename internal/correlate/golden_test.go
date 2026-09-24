package correlate_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phuongnz/cube-logger/internal/correlate"
	"github.com/phuongnz/cube-logger/internal/parse"
	"github.com/phuongnz/cube-logger/internal/testutil"
)

const fixtureYear = 2026

func fixtures(t *testing.T) []string {
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

func correlateFile(t *testing.T, path string) (*correlate.Correlator, *correlate.Result) {
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
	c := correlate.New()
	for _, r := range res.Records {
		c.Add(r)
	}
	return c, c.Result()
}

func TestGoldenCalls(t *testing.T) {
	for _, path := range fixtures(t) {
		t.Run(filepath.Base(path), func(t *testing.T) {
			_, grouped := correlateFile(t, path)
			got, err := json.MarshalIndent(grouped, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			golden := strings.TrimSuffix(path, ".txt") + ".calls.json"
			testutil.Golden(t, golden, append(got, '\n'))
		})
	}
}

// TestEveryRecordIsPlaced checks that correlation loses nothing: every record
// is either on a leg or explicitly unattached, and never on two legs.
func TestEveryRecordIsPlaced(t *testing.T) {
	for _, path := range fixtures(t) {
		t.Run(filepath.Base(path), func(t *testing.T) {
			c, grouped := correlateFile(t, path)
			seen := make([]int, len(c.Records()))
			for _, call := range grouped.Calls {
				for _, leg := range call.Legs {
					for _, i := range leg.Records {
						seen[i]++
					}
				}
			}
			for _, i := range grouped.Unattached {
				seen[i]++
			}
			for i, n := range seen {
				if n != 1 {
					t.Errorf("record %d appears on %d legs, want exactly 1", i, n)
				}
			}
		})
	}
}

// TestGUIDReuseSplitsCalls is the correlator's central rule. The debug GUID is
// only 12 hex characters and CUBE reuses it: in the study capture about 30
// GUIDs covered 13 to 17 unrelated legs over a couple of hours. Grouping by
// GUID alone would fuse them into one impossible call, so the GUID is scoped by
// time and a reappearance after the previous legs ended starts a new call.
func TestGUIDReuseSplitsCalls(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "guid_reuse.txt")
	_, grouped := correlateFile(t, path)
	if len(grouped.Calls) != 2 {
		t.Fatalf("got %d calls, want 2 — the reused GUID was not split", len(grouped.Calls))
	}
	for _, c := range grouped.Calls {
		if c.GUID != "5F816200001A" {
			t.Errorf("%s has GUID %q, want the shared one", c.ID, c.GUID)
		}
		if len(c.Legs) != 1 {
			t.Errorf("%s has %d legs, want 1", c.ID, len(c.Legs))
		}
	}
	if got, want := grouped.Calls[0].Result, "486 Busy Here"; got != want {
		t.Errorf("first call result = %q, want %q", got, want)
	}
	if got, want := grouped.Calls[1].Result, "200 OK"; got != want {
		t.Errorf("second call result = %q, want %q", got, want)
	}
}

// TestLegAdoptsCallEntryID covers the case docs/log-format.md calls a design
// constraint rather than an edge case: an inbound call's first INVITE is logged
// with call entry ID -1, before CUBE has a leg for it. The leg has to be
// created from the SIP Call-ID and adopt the call entry ID afterwards, or the
// INVITE that started the call is missing from it.
func TestLegAdoptsCallEntryID(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "basic_call.txt")
	c, grouped := correlateFile(t, path)
	if len(grouped.Calls) != 1 {
		t.Fatalf("got %d calls, want 1", len(grouped.Calls))
	}
	inbound := grouped.Calls[0].Legs[0]
	if inbound.CallEntryID != 2540661 {
		t.Errorf("inbound leg call entry ID = %d, want 2540661", inbound.CallEntryID)
	}
	if len(inbound.Records) == 0 || inbound.Records[0] != 0 {
		t.Fatalf("inbound leg records = %v, want it to start with the first record", inbound.Records)
	}
	first := c.Records()[inbound.Records[0]]
	if first.Debug == nil || first.Debug.CallID != parse.NoCallID {
		t.Errorf("the adopted record should be the one logged with call entry ID -1")
	}
	if first.SIP == nil || first.SIP.Method != "INVITE" {
		t.Errorf("the adopted record should be the inbound INVITE")
	}
}
