package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phuongnz/cube-logger/internal/calls"
	"github.com/phuongnz/cube-logger/internal/listen"
	"github.com/phuongnz/cube-logger/internal/live"
	"github.com/phuongnz/cube-logger/internal/session"
	"github.com/phuongnz/cube-logger/internal/store"
	"github.com/phuongnz/cube-logger/internal/web"
)

func TestSeverityOfAMessageTag(t *testing.T) {
	cases := []struct {
		line string
		want int
	}{
		{"%SIP-5-DIALPEER_STATUS: VoIP dial-Peer <2000> is Up", 5},
		{"%VOICE_IEC-3-GW: SIP: Internal Error", 3},
		{"%SYS-6-LOGGINGHOST_STARTSTOP: Logging to host started", 6},
		// Debug output carries no tag, and is severity 7. Getting this wrong is
		// not cosmetic: 7 is exactly what "logging trap informational" drops.
		{"//2540681/ABCDEF000001/SIP/Msg/ccsipDisplayMsg:", 7},
		{"Received:", 7},
		{"", 7},
		// A percent sign in the middle of prose is not a message tag.
		{"utilisation 95% of the configured limit", 7},
		{"%NOT-A-TAG", 7},
	}
	for _, c := range cases {
		if got := severityOf(c.line); got != c.want {
			t.Errorf("severityOf(%q) = %d, want %d", c.line, got, c.want)
		}
	}
}

func TestWrapAddsTheWireFraming(t *testing.T) {
	got := wrap(23, 7, 4001, "Received:")
	if got != "<191>4001: Received:" {
		t.Errorf("wrap = %q", got)
	}
	// An empty line still becomes a datagram, because an empty datagram is what
	// separates a SIP message's headers from its body.
	if got := wrap(23, 7, 4002, ""); got != "<191>4002: " {
		t.Errorf("wrap of an empty line = %q", got)
	}
	// A line that already carries framing is a saved datagram dump: pass it on
	// verbatim rather than framing it twice.
	already := "<189>4003: 5967001: Sep 24 10:14:20.640: something"
	if got := wrap(23, 7, 9, already); got != already {
		t.Errorf("wrap re-framed an already framed line: %q", got)
	}
}

func TestIsWireShaped(t *testing.T) {
	yes := []string{"<0>x", "<191>1: x", "<189>abc"}
	no := []string{"", "x", "<>x", "<abc>x", "<123456>x", "<191 x"}
	for _, s := range yes {
		if !isWireShaped(s) {
			t.Errorf("isWireShaped(%q) = false, want true", s)
		}
	}
	for _, s := range no {
		if isWireShaped(s) {
			t.Errorf("isWireShaped(%q) = true, want false", s)
		}
	}
}

func TestReadLinesKeepsEmptyLinesAndDropsTheTrailingNewline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f.txt")
	if err := os.WriteFile(path, []byte("a\n\nb\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readLines(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a", "", "b"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("readLines = %q, want %q", got, want)
	}
}

func TestReadLinesOnAFileWithNoFinalNewline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f.txt")
	if err := os.WriteFile(path, []byte("a\nb"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, _ := readLines(path)
	if fmt.Sprint(got) != fmt.Sprint([]string{"a", "b"}) {
		t.Errorf("readLines = %q", got)
	}
}

// receiver is the live path in one process: a real UDP socket, the real
// reassembler, the real store and the real web server.
type receiver struct {
	ln    *listen.Listener
	re    *live.Reassembler
	st    *store.Store
	ix    *calls.Index
	srv   *web.Server
	stop  context.CancelFunc
	waits sync.WaitGroup
}

func startReceiver(t *testing.T) *receiver { return startReceiverSaving(t, nil) }

// startReceiverSaving is the same, writing every record to a session file as
// it arrives when sw is not nil.
func startReceiverSaving(t *testing.T, sw *session.Writer) *receiver {
	t.Helper()
	ln, err := listen.Open("127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	re := live.New()
	re.Year = 2026
	st := store.New(1000)
	ix := calls.New(0)
	add := &feeder{st: st, ix: ix, sw: sw}
	srv := &web.Server{Store: st, Live: re, Listener: ln, Calls: ix, Title: "test"}
	if err := web.Open("127.0.0.1:0", srv); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &receiver{ln: ln, re: re, st: st, ix: ix, srv: srv, stop: cancel}

	// The same feeder the command uses, so the test exercises the ordering the
	// correlator depends on rather than a simpler path that happens to work.
	r.waits.Add(3)
	go func() {
		defer r.waits.Done()
		_ = ln.Run(ctx, func(d live.Datagram) { add.records(re.Datagram(d)...) })
	}()
	go func() {
		defer r.waits.Done()
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-tick.C:
				add.records(re.Tick(now)...)
			}
		}
	}()
	go func() { defer r.waits.Done(); _ = srv.Serve(ctx) }()

	t.Cleanup(func() {
		cancel()
		ln.Close()
		r.waits.Wait()
	})
	return r
}

// waitFor polls until cond holds. The live path is asynchronous by nature — a
// datagram crosses a socket and a record waits for its idle timeout — so a
// test that asserts immediately asserts on nothing.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// fixture names a file in the repository's shared testdata directory. The
// fixtures live at the root because the parser tests use them too, and they are
// all invented values, never anything from a real capture.
func fixture(name string) string {
	return filepath.Join("..", "..", "testdata", name)
}

func replay(t *testing.T, args ...string) {
	t.Helper()
	if err := replayCmd(args); err != nil {
		t.Fatalf("replay %v: %v", args, err)
	}
}

// The end-to-end check the phase is for: a fixture replayed one datagram per
// line comes out of the other end as records, over a real socket.
func TestReplayIntoTheLivePath(t *testing.T) {
	r := startReceiver(t)
	replay(t, "-to", r.ln.Addr(), "-rate", "0", fixture("basic_call.txt"))

	waitFor(t, "records", func() bool { return r.st.Stats().Records > 0 })

	recs := r.st.Recent(1000)
	if len(recs) < 3 {
		t.Fatalf("only %d record(s) from a fixture with several", len(recs))
	}
	// One datagram per line is the point: far more lines than records, because
	// a SIP message is one record spread over many datagrams.
	if r.ln.Stats().Datagrams <= uint64(len(recs)) {
		t.Errorf("%d datagram(s) for %d record(s): replay is not sending line-per-datagram",
			r.ln.Stats().Datagrams, len(recs))
	}
	// The SIP body has to survive the empty datagram that separates it from the
	// headers. If empty datagrams were dropped, every INVITE would arrive bodiless.
	var sawSDP bool
	for _, e := range recs {
		for _, line := range e.RawLines {
			if strings.HasPrefix(line, "v=0") {
				sawSDP = true
			}
		}
		if e.Incomplete {
			t.Errorf("record %d is incomplete after a lossless replay: %v", e.ID, e.Warnings)
		}
	}
	if !sawSDP {
		t.Error("no SDP body survived the replay; the empty separating datagram was probably dropped")
	}

	// And the source is the datagram's address, because the frame has no hostname.
	for _, e := range recs {
		if !strings.HasPrefix(e.Source, "127.0.0.1") {
			t.Errorf("source = %q, want the sender's address", e.Source)
			break
		}
	}
}

// The whole reason replay exists as a load test: -drop must show up as loss the
// reassembler reports, not as records that quietly look whole.
func TestReplayWithDropIsReportedAsLoss(t *testing.T) {
	r := startReceiver(t)
	replay(t, "-to", r.ln.Addr(), "-rate", "0", "-drop", "0.3", fixture("basic_call.txt"))

	waitFor(t, "loss to be noticed", func() bool {
		for _, s := range r.re.Stats() {
			if s.LostLines > 0 {
				return true
			}
		}
		return false
	})
	var incomplete int
	for _, e := range r.st.Recent(1000) {
		if e.Incomplete {
			incomplete++
		}
	}
	if incomplete == 0 {
		t.Error("lines were dropped but no record is marked incomplete: loss is being hidden")
	}
}

// Reordering is what the reorder buffer is for; a replay that reorders must
// come out in order and without phantom loss.
func TestReplayWithShuffleIsPutBackInOrder(t *testing.T) {
	r := startReceiver(t)
	replay(t, "-to", r.ln.Addr(), "-rate", "0", "-shuffle", "3", fixture("basic_call.txt"))

	waitFor(t, "records", func() bool { return r.st.Stats().Records > 3 })
	// Give the reorder window and the idle timeout room to finish.
	time.Sleep(time.Second)

	for _, e := range r.st.Recent(1000) {
		if e.Incomplete {
			t.Errorf("record %d incomplete after a reordered but lossless replay: %v",
				e.ID, e.Warnings)
		}
	}
	for _, s := range r.re.Stats() {
		if s.LostLines > 0 {
			t.Errorf("%s: %d line(s) reported lost after a lossless replay: reordering is being counted as loss",
				s.Source, s.LostLines)
		}
		if s.Reordered == 0 {
			t.Errorf("%s: nothing counted as reordered, so the test proved nothing", s.Source)
		}
	}
}

func TestReplayRejectsBadArguments(t *testing.T) {
	if err := replayCmd([]string{"-to", "127.0.0.1:1", "-drop", "1.5", fixture("basic_call.txt")}); err == nil {
		t.Error("-drop 1.5 was accepted")
	}
	if err := replayCmd([]string{"-to", "127.0.0.1:1", filepath.Join(t.TempDir(), "nope.txt")}); err == nil {
		t.Error("a missing file was accepted")
	}
	empty := filepath.Join(t.TempDir(), "empty.txt")
	_ = os.WriteFile(empty, nil, 0o600)
	if err := replayCmd([]string{"-to", "127.0.0.1:1", empty}); err == nil {
		t.Error("an empty file was accepted")
	}
}

// The UI is served on the same process as the listener, so an engineer gets one
// command and one URL.
func TestLiveSessionServesTheUI(t *testing.T) {
	r := startReceiver(t)
	replay(t, "-to", r.ln.Addr(), "-rate", "0", fixture("basic_call.txt"))
	waitFor(t, "records", func() bool { return r.st.Stats().Records > 0 })

	resp, err := http.Get(r.srv.URL() + "/api/records?limit=1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestRouterConfigNamesThePortActuallyBound(t *testing.T) {
	lines := routerConfig("0.0.0.0:15514")
	if !strings.Contains(lines[0], "port 15514") {
		t.Errorf("config line does not name the bound port: %q", lines[0])
	}
	// Without sequence numbers there is no outer counter, and without that
	// there is no reordering and no gap detection. It is not optional advice.
	if !strings.Contains(strings.Join(lines, "\n"), "service sequence-numbers") {
		t.Errorf("config does not tell the engineer to turn on sequence numbers: %q", lines)
	}
}

// The call list is the phase's end-to-end claim: a fixture replayed over a
// real socket comes out the other end as a call an engineer can select, with a
// ladder and a set of records the table can be narrowed to.
func TestReplayProducesACallWithALadder(t *testing.T) {
	r := startReceiver(t)
	replay(t, "-to", r.ln.Addr(), "-rate", "0", fixture("basic_call.txt"))
	waitFor(t, "a call", func() bool { return len(r.ix.List(0, false)) > 0 })

	list := r.ix.List(0, false)
	if len(list) != 1 {
		t.Fatalf("calls = %d, want the one call in the fixture", len(list))
	}
	c := list[0]
	if c.Calling == "" || c.Called == "" {
		t.Errorf("call has no from/to: %+v", c)
	}
	if c.Legs != 2 {
		t.Errorf("legs = %d, want the two legs of a back-to-back call", c.Legs)
	}

	d, ok := r.ix.Get(c.ID, r.srv.Lookup)
	if !ok {
		t.Fatalf("call %s vanished between the list and the detail", c.ID)
	}
	if len(d.Records) == 0 {
		t.Fatal("the call carries no records")
	}
	if d.Ladder == nil || len(d.Ladder.Arrows) == 0 {
		t.Fatal("no ladder was built from a call that is entirely SIP")
	}
	// Every record of the call is still in the ring, so nothing should be
	// reported missing. A ladder that quietly loses messages is worse than one
	// that admits to it.
	if d.Ladder.Missing != 0 {
		t.Errorf("ladder is missing %d record(s) that the ring still holds", d.Ladder.Missing)
	}
	// And the records really are the call's: the store has each of them.
	for _, ref := range d.Records {
		if _, ok := r.st.Get(ref); !ok {
			t.Errorf("record %d is not in the store", ref)
		}
	}
}
