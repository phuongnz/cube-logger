package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phuongnz/cube-logger/internal/calls"
	"github.com/phuongnz/cube-logger/internal/live"
	"github.com/phuongnz/cube-logger/internal/load"
	"github.com/phuongnz/cube-logger/internal/session"
	"github.com/phuongnz/cube-logger/internal/store"
	"github.com/phuongnz/cube-logger/internal/web"
)

// file names a fixture in the format directory: the files other things wrote.
func file(name string) string {
	return filepath.Join("..", "..", "testdata", "files", name)
}

func readSession(t *testing.T, path string) *session.Result {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rd, isSession, err := session.Sniff(f)
	if err != nil {
		t.Fatal(err)
	}
	if !isSession {
		t.Fatalf("%s is not a session file", path)
	}
	res, err := session.Read(rd, 0)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestOpenConvertsAFileToASession(t *testing.T) {
	out := filepath.Join(t.TempDir(), "converted"+session.Ext)
	if err := openCmd([]string{"-year", "2026", "-o", out, file("show_logging.txt")}); err != nil {
		t.Fatal(err)
	}
	res := readSession(t, out)
	if len(res.Records) != 5 {
		t.Fatalf("%d record(s) in the session, want 5", len(res.Records))
	}
	if res.Records[0].Source != "cube-a" {
		t.Errorf("device = %q, want cube-a", res.Records[0].Source)
	}
	if res.Header.Year != 2026 {
		t.Errorf("the year was not recorded: %+v", res.Header)
	}
	// The whole point of the format: the SIP message is there as the router
	// wrote it, and a second pass over the file finds it again.
	found := false
	for _, r := range res.Records {
		if r.SIP != nil && strings.HasPrefix(r.SIP.StartLine, "INVITE") {
			found = true
		}
	}
	if !found {
		t.Error("the INVITE did not survive the round trip")
	}
}

func TestOpenGzipsWhenAsked(t *testing.T) {
	out := filepath.Join(t.TempDir(), "converted.cubelog.gz")
	if err := openCmd([]string{"-year", "2026", "-o", out, file("show_logging.txt")}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if b[0] != 0x1f || b[1] != 0x8b {
		t.Fatal("a name ending .gz did not produce a compressed file")
	}
	if n := len(readSession(t, out).Records); n != 5 {
		t.Errorf("%d record(s) back, want 5", n)
	}
}

func TestOpenMergesSeveralFilesInClockOrder(t *testing.T) {
	out := filepath.Join(t.TempDir(), "merged"+session.Ext)
	// The ISO file is an hour later than the BSD one but is named first: the
	// merge has to order by the devices' clocks, not by the command line.
	if err := openCmd([]string{"-year", "2026", "-o", out,
		file("syslog_iso.txt"), file("syslog_bsd_two_cubes.txt")}); err != nil {
		t.Fatal(err)
	}
	res := readSession(t, out)
	var order []string
	last := res.Records[0].Time
	for _, r := range res.Records {
		if r.Time.Before(last) {
			t.Fatalf("out of order: %v after %v", r.Time, last)
		}
		last = r.Time
		order = append(order, r.Source)
	}
	seen := map[string]bool{}
	for _, s := range order {
		seen[s] = true
	}
	for _, want := range []string{"cube-a", "cube-b", "cube-c"} {
		if !seen[want] {
			t.Errorf("%s is missing from the merge: %v", want, order)
		}
	}
}

func TestOpenRejectsAFileItCannotRead(t *testing.T) {
	junk := filepath.Join(t.TempDir(), "notes.txt")
	if err := os.WriteFile(junk, []byte("the trunk was down again\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := openCmd([]string{"-o", "-", junk}); err == nil {
		t.Fatal("a file with no records was accepted")
	}
	if err := openCmd([]string{"-o", "-"}); err == nil {
		t.Fatal("open with no file was accepted")
	}
}

// TestOpenServesTheSameViewsAsLive builds what openCmd builds and asks the
// server the questions the browser asks. The command itself blocks until it is
// signalled, which is not a thing a test can do portably.
func TestOpenServesTheSameViewsAsLive(t *testing.T) {
	o, err := openFile(file("syslog_bsd_two_cubes.txt"), load.Options{Year: 2026})
	if err != nil {
		t.Fatal(err)
	}
	st := store.New(1000)
	ix := calls.New(0)
	add := &feeder{st: st, ix: ix}
	add.records(o.records...)
	srv := &web.Server{Store: st, Calls: ix, Sources: o.sources, Title: "a file", Add: add.records}
	if err := web.Open("127.0.0.1:0", srv); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	t.Cleanup(func() { cancel(); <-done })

	var stats struct {
		Sources []live.SourceStat `json:"sources"`
		Store   struct {
			Records int `json:"records"`
		} `json:"store"`
	}
	getJSON(t, srv.URL()+"/api/stats", &stats)
	if len(stats.Sources) != 2 {
		t.Errorf("%d device(s) in the status, want 2: %+v", len(stats.Sources), stats.Sources)
	}
	if stats.Store.Records != len(o.records) {
		t.Errorf("%d record(s) held, want %d", stats.Store.Records, len(o.records))
	}

	var list struct {
		Calls []struct {
			ID string `json:"id"`
		} `json:"calls"`
	}
	getJSON(t, srv.URL()+"/api/calls", &list)
	if len(list.Calls) == 0 {
		t.Fatal("a file produced no calls; the call list is the same view as the live one")
	}
}

func getJSON(t *testing.T, url string, v any) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d", url, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
}

// TestLiveSavesASessionThatReadsBack is the other half of the phase: a stream
// that arrives over a socket is written to a file as it goes, and that file
// opens again as the same records.
func TestLiveSavesASessionThatReadsBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "live"+session.Ext)
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	sw, err := session.NewWriter(f, session.Header{Title: "live", Year: 2026}, session.Options{})
	if err != nil {
		t.Fatal(err)
	}
	r := startReceiverSaving(t, sw)
	replay(t, "-to", r.ln.Addr(), "-rate", "0", "-frame", fixture("basic_call.txt"))
	waitFor(t, "records", func() bool { return r.st.Stats().Records > 5 })
	settle(t, r)
	if err := sw.Close(r.re.Stats()); err != nil {
		t.Fatal(err)
	}
	f.Close()

	res := readSession(t, path)
	if res.Truncated {
		t.Error("the session written by the live path has no end marker")
	}
	if len(res.Records) == 0 || uint64(len(res.Records)) != sw.Count() {
		t.Fatalf("%d record(s) read back, %d written", len(res.Records), sw.Count())
	}
	// It is the wire's facts that a file cannot reproduce, and they survive:
	// the per-line counter, the severity and the device.
	var withSeq int
	for _, rec := range res.Records {
		if rec.HasLineSeq {
			withSeq++
		}
		if rec.Source == "" {
			t.Error("a record came back with no device")
		}
	}
	if withSeq == 0 {
		t.Error("no record kept the outer, per-line counter it arrived with")
	}
	if len(res.Sources) == 0 {
		t.Error("the footer recorded no devices")
	}
}

// settle waits until the store stops growing. The reassembler releases the
// last record of a burst on an idle timeout rather than when the socket goes
// quiet, so "the replay returned" is not "everything has arrived".
func settle(t *testing.T, r *receiver) {
	t.Helper()
	last, stable := -1, 0
	for i := 0; i < 400; i++ {
		n := r.st.Stats().Records
		if n == last && n > 0 {
			stable++
		} else {
			stable = 0
		}
		last = n
		if stable > 30 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the stream never went quiet")
}
