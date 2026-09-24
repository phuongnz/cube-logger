package session_test

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phuongnz/cube-logger/internal/live"
	"github.com/phuongnz/cube-logger/internal/load"
	"github.com/phuongnz/cube-logger/internal/parse"
	"github.com/phuongnz/cube-logger/internal/session"
)

const fixtureYear = 2026

func fixture(t *testing.T, name string) []*live.Record {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "..", "testdata", "files", name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	res, err := load.File(f, load.Options{Year: fixtureYear, Source: name})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) == 0 {
		t.Fatalf("%s produced no records", name)
	}
	return res.Records
}

func write(t *testing.T, recs []*live.Record, opt session.Options) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := session.NewWriter(&buf, session.Header{Title: "a session", Year: fixtureYear}, opt)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Records(recs...); err != nil {
		t.Fatal(err)
	}
	if err := w.Close([]live.SourceStat{{Source: "cube-a", Records: uint64(len(recs))}}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestRoundTrip(t *testing.T) {
	want := fixture(t, "show_logging.txt")
	got, err := session.Read(bytes.NewReader(write(t, want, session.Options{})), 0)
	if err != nil {
		t.Fatal(err)
	}
	if got.Truncated {
		t.Error("a file that was closed properly was reported as cut off")
	}
	if got.Header.Title != "a session" || got.Header.Version != session.Version {
		t.Errorf("header = %+v", got.Header)
	}
	if len(got.Records) != len(want) {
		t.Fatalf("%d record(s) back, wrote %d", len(got.Records), len(want))
	}
	for i := range want {
		a, b := want[i], got.Records[i]
		if strings.Join(a.RawLines, "\n") != strings.Join(b.RawLines, "\n") {
			t.Fatalf("record %d: raw lines differ\n got %q\nwant %q", i, b.RawLines, a.RawLines)
		}
		if a.Source != b.Source || a.Severity != b.Severity || !a.Received.Equal(b.Received) {
			t.Errorf("record %d: source/severity/received = %q/%d/%v, want %q/%d/%v",
				i, b.Source, b.Severity, b.Received, a.Source, a.Severity, a.Received)
		}
		if !a.Time.Equal(b.Time) {
			t.Errorf("record %d: the device's clock came back as %v, want %v", i, b.Time, a.Time)
		}
		if (a.SIP == nil) != (b.SIP == nil) {
			t.Fatalf("record %d: SIP message present = %v, want %v", i, b.SIP != nil, a.SIP != nil)
		}
		if a.SIP != nil && a.SIP.CallID != b.SIP.CallID {
			t.Errorf("record %d: Call-ID = %q, want %q", i, b.SIP.CallID, a.SIP.CallID)
		}
		if a.Call != b.Call {
			t.Errorf("record %d: leg = %q, want %q", i, b.Call, a.Call)
		}
	}
}

func TestTheFileHoldsRawLinesAndNotParsedRecords(t *testing.T) {
	// The promise of the format: what is on disk is what the router said, so a
	// later parser re-reads it rather than inheriting today's mistakes.
	recs := fixture(t, "show_logging.txt")
	b := write(t, recs, session.Options{})
	if bytes.Contains(b, []byte(`"sip":`)) || bytes.Contains(b, []byte(`"kind":`)) {
		t.Error("the file carries parsed structure; it should carry only raw lines")
	}
	if !bytes.Contains(b, []byte("INVITE sip:15550100")) {
		t.Error("the file does not carry the raw SIP line")
	}
}

func TestGzip(t *testing.T) {
	recs := fixture(t, "show_logging.txt")
	b := write(t, recs, session.Options{Gzip: true})
	if b[0] != 0x1f || b[1] != 0x8b {
		t.Fatal("the file is not gzipped")
	}
	got, err := session.Read(bytes.NewReader(b), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Records) != len(recs) {
		t.Errorf("%d record(s) back, wrote %d", len(got.Records), len(recs))
	}
	// And it is found by sniffing, whatever the file is called.
	rd, ok, err := session.Sniff(bytes.NewReader(b))
	if err != nil || !ok {
		t.Fatalf("Sniff = %v, %v; want true, nil", ok, err)
	}
	all, err := io.ReadAll(rd)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(all, []byte("INVITE sip:15550100")) {
		t.Error("sniffing consumed part of the stream")
	}
}

func TestACutOffFileStillReads(t *testing.T) {
	recs := fixture(t, "show_logging.txt")
	b := write(t, recs, session.Options{})
	// Cut the footer and half of the last record off, the way a laptop losing
	// power would.
	cut := bytes.LastIndexByte(b[:len(b)-1], '\n')
	cut = bytes.LastIndexByte(b[:cut], '\n')
	truncated := append(append([]byte{}, b[:cut+1]...), []byte(`{"type":"record","raw":["unfinis`)...)

	got, err := session.Read(bytes.NewReader(truncated), 0)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Truncated {
		t.Error("a file with no end marker was not reported as cut off")
	}
	if len(got.Records) != len(recs)-1 {
		t.Errorf("%d record(s) back, want %d", len(got.Records), len(recs)-1)
	}
	if got.Skipped != 1 {
		t.Errorf("Skipped = %d, want 1 for the half-written line", got.Skipped)
	}
	// With no footer the sources are counted from what was read.
	if len(got.Sources) != 1 || got.Sources[0].Source != "cube-a" {
		t.Errorf("sources = %+v", got.Sources)
	}
}

func TestSeveralDevicesKeepSeparateParsers(t *testing.T) {
	recs := fixture(t, "syslog_bsd_two_cubes.txt")
	got, err := session.Read(bytes.NewReader(write(t, recs, session.Options{})), 0)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, r := range got.Records {
		seen[r.Source] = true
		for _, w := range r.Warnings {
			if strings.Contains(w, "lost") {
				t.Errorf("%s: %q — the two devices' numbering was differenced", r.Source, w)
			}
		}
	}
	if !seen["cube-a"] || !seen["cube-b"] {
		t.Errorf("devices read back: %v", seen)
	}
}

func TestAFutureVersionIsRefused(t *testing.T) {
	b := []byte(`{"type":"session","tool":"cube-logger","version":99}` + "\n")
	if _, err := session.Read(bytes.NewReader(b), 0); err == nil {
		t.Fatal("a version this build does not know was read anyway")
	}
}

func TestSniffTellsALogFileFromASession(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "..", "testdata", "files", "show_logging.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rd, ok, err := session.Sniff(f)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("a log file was taken for a session file")
	}
	b, err := io.ReadAll(rd)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(b), "cube-a#terminal length 0") {
		t.Error("sniffing consumed part of the file")
	}
}

func TestTheYearSurvives(t *testing.T) {
	// IOS prints no year. A session reopened in a later year has to be read in
	// the year it was recorded, or every timestamp moves.
	recs := fixture(t, "show_logging.txt")
	got, err := session.Read(bytes.NewReader(write(t, recs, session.Options{})), 0)
	if err != nil {
		t.Fatal(err)
	}
	if y := got.Records[0].Time.Year(); y != fixtureYear {
		t.Errorf("year = %d, want %d", y, fixtureYear)
	}
	// An explicit year overrides the header, for a file recorded without one.
	got, err = session.Read(bytes.NewReader(write(t, recs, session.Options{})), 2031)
	if err != nil {
		t.Fatal(err)
	}
	if y := got.Records[0].Time.Year(); y != 2031 {
		t.Errorf("year = %d, want 2031", y)
	}
}

func TestEmptyAndHeaderOnly(t *testing.T) {
	if _, err := session.Read(bytes.NewReader(nil), 0); err == nil {
		t.Error("an empty file was read as a session")
	}
	var buf bytes.Buffer
	w, err := session.NewWriter(&buf, session.Header{Created: time.Now()}, session.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(nil); err != nil {
		t.Fatal(err)
	}
	got, err := session.Read(bytes.NewReader(buf.Bytes()), fixtureYear)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Records) != 0 || got.Truncated {
		t.Errorf("a session with no records: %d record(s), truncated = %v",
			len(got.Records), got.Truncated)
	}
}

func TestARecordWithNoIOSFrameIsStillHandedBack(t *testing.T) {
	// Not everything in the ring came through the parser cleanly: a wrapped
	// buffer starts mid-record, and a device without timestamps emits lines
	// that cannot be framed. A session file that loses those on reload would
	// be worse than one that hands them back as text.
	rec := &live.Record{
		Record:   &parse.Record{Source: "cube-a", Text: "no frame here", Raw: []string{"no frame here"}},
		Severity: 6,
		Received: time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC),
		RawLines: []string{"no frame here"},
	}
	var buf bytes.Buffer
	w, err := session.NewWriter(&buf, session.Header{Year: fixtureYear}, session.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Records(rec); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(nil); err != nil {
		t.Fatal(err)
	}
	got, err := session.Read(bytes.NewReader(buf.Bytes()), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Records) != 1 {
		t.Fatalf("%d record(s) back, want 1", len(got.Records))
	}
	if got.Records[0].Text != "no frame here" {
		t.Errorf("text = %q", got.Records[0].Text)
	}
	if !got.Records[0].Received.Equal(rec.Received) {
		t.Errorf("received = %v, want %v", got.Records[0].Received, rec.Received)
	}
	if len(got.Records[0].Warnings) == 0 {
		t.Error("nothing said that this record could not be framed")
	}
}
