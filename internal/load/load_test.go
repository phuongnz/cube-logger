package load_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phuongnz/cube-logger/internal/ingest"
	"github.com/phuongnz/cube-logger/internal/live"
	"github.com/phuongnz/cube-logger/internal/load"
)

// fixtureYear is the year the fixtures are set in; IOS logs none.
const fixtureYear = 2026

func read(t *testing.T, name string, opt load.Options) *load.Result {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "..", "testdata", "files", name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	opt.Year = fixtureYear
	res, err := load.File(f, opt)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func sources(res *load.Result) []string {
	var out []string
	for _, s := range res.Sources {
		out = append(out, s.Source)
	}
	return out
}

// find returns the first record whose text contains needle.
func find(t *testing.T, res *load.Result, needle string) *live.Record {
	t.Helper()
	for _, r := range res.Records {
		if strings.Contains(r.Text, needle) {
			return r
		}
		for _, c := range r.RawLines {
			if strings.Contains(c, needle) {
				return r
			}
		}
	}
	t.Fatalf("no record containing %q; the file gave %d", needle, len(res.Records))
	return nil
}

func TestShowLogging(t *testing.T) {
	res := read(t, "show_logging.txt", load.Options{Source: "show_logging.txt"})
	if res.Format != ingest.IOS {
		t.Errorf("format = %q, want %q", res.Format, ingest.IOS)
	}
	// The preamble is not log content and must not become records or orphans.
	if len(res.Banner) < 20 {
		t.Errorf("%d banner line(s); the whole preamble should have been recognised", len(res.Banner))
	}
	if n := len(res.Orphans); n != 0 {
		t.Errorf("%d orphan line(s), want none: %q", n, res.Orphans)
	}
	if n := len(res.Records); n != 5 {
		t.Fatalf("%d record(s), want 5", n)
	}
	// The prompt names the device, which is the only place a terminal capture
	// says which router it came from.
	if got := sources(res); len(got) != 1 || got[0] != "cube-a" {
		t.Errorf("sources = %v, want [cube-a]", got)
	}
	inv := find(t, res, "INVITE sip:15550100")
	if inv.SIP == nil {
		t.Fatal("the INVITE was not recognised as a SIP message")
	}
	if inv.SIP.CallID != "11223344-5566@192.0.2.10" {
		t.Errorf("Call-ID = %q", inv.SIP.CallID)
	}
	if inv.Severity != 7 {
		t.Errorf("a debug record came out at severity %d, want 7", inv.Severity)
	}
	if !strings.Contains(strings.Join(inv.RawLines, "\n"), "v=0") {
		t.Error("the SDP body was not kept with its message")
	}
	log := find(t, res, "DIALPEER_STATUS")
	if log.Severity != 5 {
		t.Errorf("severity = %d, want 5 from the %%SIP-5- tag", log.Severity)
	}
	// A file has no arrival time of its own, so the device's clock stands in
	// rather than "now".
	if !log.Received.Equal(log.Time) {
		t.Errorf("received = %v, want the device's own clock %v", log.Received, log.Time)
	}
}

func TestTwoCubesInOneFile(t *testing.T) {
	res := read(t, "syslog_bsd_two_cubes.txt", load.Options{Source: "unused"})
	if res.Format != ingest.BSD {
		t.Errorf("format = %q, want %q", res.Format, ingest.BSD)
	}
	if got := sources(res); len(got) != 2 || got[0] != "cube-a" || got[1] != "cube-b" {
		t.Fatalf("sources = %v, want [cube-a cube-b]", got)
	}
	// Each device's records carry its own name, and nothing is mixed.
	for _, r := range res.Records {
		if r.Source != "cube-a" && r.Source != "cube-b" {
			t.Fatalf("record from %q: %s", r.Source, r.Text)
		}
	}
	inv := find(t, res, "INVITE sip:15550100")
	if inv.Source != "cube-a" {
		t.Errorf("the INVITE came from %q, want cube-a", inv.Source)
	}
	if inv.SIP == nil || inv.SIP.CallID != "22334455-6677@192.0.2.10" {
		t.Fatalf("the INVITE was not reassembled across its prefixed lines: %+v", inv.SIP)
	}
	// cube-b's numbering is eight million ahead of cube-a's. Differencing the
	// two would invent a loss of that size; keeping a parser per device does
	// not.
	for _, s := range res.Sources {
		if s.LostRecords != 0 {
			t.Errorf("%s: %d record(s) reported lost, want 0", s.Source, s.LostRecords)
		}
	}
	// The receiving server's clock is what a file in this format carries.
	if inv.Received.IsZero() {
		t.Error("the syslog server's timestamp was dropped")
	}
	if !hasNote(res, "device") {
		t.Errorf("no note about there being two devices: %q", res.Notes)
	}
}

func TestISO(t *testing.T) {
	res := read(t, "syslog_iso.txt", load.Options{})
	if res.Format != ingest.ISO {
		t.Errorf("format = %q, want %q", res.Format, ingest.ISO)
	}
	if got := sources(res); len(got) != 1 || got[0] != "cube-c" {
		t.Fatalf("sources = %v, want [cube-c]", got)
	}
	opt := find(t, res, "OPTIONS sip:192.0.2.20")
	if opt.SIP == nil || opt.SIP.Method != "OPTIONS" {
		t.Fatalf("the OPTIONS message was not reassembled: %+v", opt.SIP)
	}
	if _, off := opt.Received.Zone(); off != 2*3600 {
		t.Errorf("the server's timezone offset was lost: %v", opt.Received)
	}
}

func TestPriorityDump(t *testing.T) {
	res := read(t, "datagrams_pri.txt", load.Options{Source: "datagrams_pri.txt"})
	if res.Format != ingest.PRI {
		t.Errorf("format = %q, want %q", res.Format, ingest.PRI)
	}
	// Nothing in this format names the device, so the caller's name is used.
	if got := sources(res); len(got) != 1 || got[0] != "datagrams_pri.txt" {
		t.Fatalf("sources = %v", got)
	}
	msg := find(t, res, "OPTIONS sip:192.0.2.30")
	if msg.Severity != 7 || msg.Facility != 23 {
		t.Errorf("severity/facility = %d/%d, want 7/23 from <191>", msg.Severity, msg.Facility)
	}
	log := find(t, res, "DIALPEER_STATUS")
	if log.Severity != 5 {
		t.Errorf("severity = %d, want 5 from <189>", log.Severity)
	}
}

func TestKiwiTabSeparated(t *testing.T) {
	res := read(t, "kiwi_tsv.txt", load.Options{})
	if res.Format != ingest.TSV {
		t.Errorf("format = %q, want %q", res.Format, ingest.TSV)
	}
	if got := sources(res); len(got) != 1 || got[0] != "198.51.100.30" {
		t.Fatalf("sources = %v", got)
	}
	if n := len(res.Records); n != 2 {
		t.Fatalf("%d record(s), want 2", n)
	}
	if res.Records[1].Severity != 5 {
		t.Errorf("severity = %d, want 5 from the Local7.Notice column",
			res.Records[1].Severity)
	}
}

func TestDeviceWithoutTimestamps(t *testing.T) {
	res := read(t, "no_timestamps.txt", load.Options{})
	if n := len(res.Records); n != 2 {
		t.Fatalf("%d record(s), want 2", n)
	}
	msg := find(t, res, "OPTIONS sip:192.0.2.50")
	if msg.SIP == nil {
		t.Fatal("the SIP message was broken up: a continuation line was given a frame of its own")
	}
	if !hasNote(res, "service timestamps") {
		t.Errorf("no note that the times are the server's: %q", res.Notes)
	}
}

func TestRename(t *testing.T) {
	res := read(t, "kiwi_tsv.txt", load.Options{
		Rename: func(s string) string {
			if s == "198.51.100.30" {
				return "branch-gw"
			}
			return s
		},
	})
	if got := sources(res); len(got) != 1 || got[0] != "branch-gw" {
		t.Fatalf("sources = %v, want [branch-gw]", got)
	}
	if res.Records[0].Source != "branch-gw" {
		t.Errorf("record source = %q", res.Records[0].Source)
	}
}

func TestEmptyFile(t *testing.T) {
	res, err := load.File(strings.NewReader(""), load.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 0 || len(res.Sources) != 0 {
		t.Errorf("an empty file produced %d record(s) and %d source(s)",
			len(res.Records), len(res.Sources))
	}
	if len(res.Notes) != 0 {
		t.Errorf("an empty file is not worth a note: %q", res.Notes)
	}
}

func hasNote(res *load.Result, needle string) bool {
	for _, n := range res.Notes {
		if strings.Contains(n, needle) {
			return true
		}
	}
	return false
}
