package live

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/phuongnz/cube-logger/internal/parse"
)

// Every address, number, Call-ID, GUID, sequence number and timestamp below is
// invented. docs/log-format.md § The UDP path gives the shapes; the real
// capture is never quoted.

var t0 = time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)

// at returns a time n milliseconds after the start of the test.
func at(ms int) time.Time { return t0.Add(time.Duration(ms) * time.Millisecond) }

// sender builds the datagrams of one SIP message the way a CUBE sends them:
// one line per datagram, a counter on every one, an empty datagram between the
// headers and the body, and a bare CR at the end of each.
type sender struct {
	source   string
	lineSeq  uint64
	recSeq   uint64
	severity int
}

func newSender(source string) *sender {
	return &sender{source: source, lineSeq: 400000, recSeq: 7200000, severity: 191}
}

// head builds a record's first datagram: the outer counter, then the IOS frame
// with its own per-record counter, then the payload.
func (s *sender) head(clock, payload string) string {
	s.lineSeq++
	s.recSeq++
	return fmt.Sprintf("<%d>%d: %d: Sep 24 %s UTC: %s\r",
		s.severity, s.lineSeq, s.recSeq, clock, payload)
}

// cont builds a continuation datagram: outer counter, then the bare line.
func (s *sender) cont(line string) string {
	s.lineSeq++
	return fmt.Sprintf("<%d>%d: %s\r", s.severity, s.lineSeq, line)
}

// invite is the 19-ish datagrams of one SIP INVITE, the shape that makes the
// reassembler necessary in the first place.
func (s *sender) invite(clock, callID string, body string) []string {
	out := []string{
		s.head(clock, "//-1/A1B2C3D4E5F6/SIP/Msg/ccsipDisplayMsg:"),
		s.cont("Received:"),
		s.cont("INVITE sip:+449876543210@192.0.2.10:5060 SIP/2.0"),
		s.cont("Via: SIP/2.0/TLS 192.0.2.20:5061;branch=z9hG4bK1234abcd"),
		s.cont("From: <sip:+441234567890@192.0.2.20>;tag=11223344"),
		s.cont("To: <sip:+449876543210@192.0.2.10>"),
		s.cont("Call-ID: " + callID),
		s.cont("CSeq: 101 INVITE"),
		s.cont("Content-Type: application/sdp"),
		s.cont(fmt.Sprintf("Content-Length: %d", crlfLen(body))),
		// The empty datagram. It is what separates headers from body, and
		// discarding empty payloads would destroy every message body there is.
		s.cont(""),
	}
	for _, l := range strings.Split(body, "\n") {
		out = append(out, s.cont(l))
	}
	return out
}

// crlfLen is Content-Length as the parser counts it: CRLF-terminated bytes.
func crlfLen(body string) int {
	n := 0
	for _, l := range strings.Split(body, "\n") {
		n += len(l) + 2
	}
	return n
}

const sdp = "v=0\no=- 1 1 IN IP4 192.0.2.20\ns=-\nc=IN IP4 192.0.2.20\nt=0 0\nm=audio 16384 RTP/AVP 0\na=rtpmap:0 PCMU/8000"

// feed sends payloads to one source, one millisecond apart, and returns
// everything that completed.
func feed(r *Reassembler, source string, ms int, payloads ...string) []*Record {
	var out []*Record
	for i, p := range payloads {
		out = append(out, r.Datagram(Datagram{Source: source, Payload: p, Time: at(ms + i)})...)
	}
	return out
}

func only(t *testing.T, recs []*Record) *Record {
	t.Helper()
	if len(recs) != 1 {
		t.Fatalf("want exactly 1 record, got %d: %s", len(recs), summarize(recs))
	}
	return recs[0]
}

func summarize(recs []*Record) string {
	var b strings.Builder
	for _, r := range recs {
		fmt.Fprintf(&b, "\n  %s kind=%s lines=%d missing=%d incomplete=%v %q",
			r.Time.Format("15:04:05.000"), r.Kind, r.Lines, r.MissingLines, r.Incomplete, r.Text)
	}
	return b.String()
}

// TestOneMessageIsManyDatagrams is the fact the whole package exists for: 19
// datagrams in, one SIP message out, not 19 fragments.
func TestOneMessageIsManyDatagrams(t *testing.T) {
	r := New()
	s := newSender("192.0.2.1")
	dgs := s.invite("12:00:00.123", "aaaa-0001@192.0.2.20", sdp)
	if len(dgs) < 15 {
		t.Fatalf("the fixture should look like a real message: %d datagrams", len(dgs))
	}

	// Not one of them completes anything: a record ends only when the next begins.
	if got := feed(r, "192.0.2.1", 0, dgs...); len(got) != 0 {
		t.Fatalf("no record should be complete yet, got %d", len(got))
	}

	rec := only(t, r.Flush())
	if rec.Kind != parse.KindDebug || rec.SIP == nil {
		t.Fatalf("want a debug record with a SIP message, got kind=%s sip=%v", rec.Kind, rec.SIP)
	}
	if rec.SIP.Method != "INVITE" {
		t.Errorf("Method = %q, want INVITE", rec.SIP.Method)
	}
	if rec.SIP.CallID != "aaaa-0001@192.0.2.20" {
		t.Errorf("Call-ID = %q", rec.SIP.CallID)
	}
	if rec.SIP.Truncated {
		t.Error("body should match Content-Length exactly")
	}
	if rec.Incomplete {
		t.Error("a complete message must not be marked incomplete")
	}
	if rec.Lines != len(dgs) {
		t.Errorf("Lines = %d, want %d", rec.Lines, len(dgs))
	}
	if rec.Severity != 7 || rec.SeverityName != "debug" {
		t.Errorf("severity = %d/%q, want 7/debug", rec.Severity, rec.SeverityName)
	}
	// The record's time is the head line's. A continuation has no clock.
	if got := rec.Time.Format("15:04:05.000"); got != "12:00:00.123" {
		t.Errorf("Time = %s, want the head line's 12:00:00.123", got)
	}
	// The body survived the empty datagram in the middle.
	if !strings.Contains(rec.SIP.Body, "m=audio 16384 RTP/AVP 0") {
		t.Errorf("body lost its media line:\n%s", rec.SIP.Body)
	}
}

// TestEmptyDatagramIsContent states the rule on its own, because an
// optimisation that drops empty payloads would pass every other test here.
func TestEmptyDatagramIsContent(t *testing.T) {
	r := New()
	s := newSender("192.0.2.1")
	dgs := s.invite("12:00:00.123", "aaaa-0002@192.0.2.20", "v=0\nc=IN IP4 192.0.2.20")
	feed(r, "192.0.2.1", 0, dgs...)
	rec := only(t, r.Flush())
	if rec.SIP.Body == "" {
		t.Fatal("no body: the blank line between headers and body was dropped")
	}
	if rec.SIP.BodyBytes != rec.SIP.ContentLength {
		t.Errorf("BodyBytes = %d, Content-Length = %d", rec.SIP.BodyBytes, rec.SIP.ContentLength)
	}
}

// TestReorderedLinesArePutBack: UDP may reorder even though the capture did
// not, and sorting by the counter rather than by arrival is what covers it.
func TestReorderedLinesArePutBack(t *testing.T) {
	r := New()
	s := newSender("192.0.2.1")
	dgs := s.invite("12:00:00.123", "aaaa-0003@192.0.2.20", sdp)

	// Swap two header lines on the wire.
	dgs[4], dgs[5] = dgs[5], dgs[4]
	feed(r, "192.0.2.1", 0, dgs...)
	rec := only(t, r.Flush())

	if rec.Incomplete {
		t.Error("reordering is not loss; the record should be whole")
	}
	if rec.SIP.From == nil || rec.SIP.From.User != "+441234567890" {
		t.Errorf("From did not survive reordering: %+v", rec.SIP.From)
	}
	st := r.Stats()[0]
	if st.Reordered == 0 {
		t.Error("the reordering should be counted")
	}
	if st.LostLines != 0 {
		t.Errorf("LostLines = %d, want 0", st.LostLines)
	}
}

// TestBadlyDisplacedLineIsStillPutBack: reordering that moves a datagram
// several positions, which is as bad as a real network gets.
func TestBadlyDisplacedLineIsStillPutBack(t *testing.T) {
	r := New()
	s := newSender("192.0.2.1")
	dgs := s.invite("12:00:00.123", "aaaa-0004@192.0.2.20", sdp)

	// Move the Call-ID header six places later on the wire.
	callID := dgs[6]
	dgs = append(dgs[:6], dgs[7:]...)
	dgs = append(dgs[:12], append([]string{callID}, dgs[12:]...)...)

	feed(r, "192.0.2.1", 0, dgs...)
	rec := only(t, r.Flush())
	if rec.Incomplete {
		t.Error("reordering is not loss; the record should be whole")
	}
	if rec.SIP.CallID != "aaaa-0004@192.0.2.20" {
		t.Errorf("Call-ID = %q, header was not put back in place", rec.SIP.CallID)
	}
	if rec.SIP.Truncated {
		t.Error("the body should still match Content-Length")
	}
}

// TestLineBelowTheStreamStartIsCountedNotSilentlyDropped states the one
// limitation of committing to the first number seen: a line numbered below it
// cannot be shown, because output after it has already gone to the user. It
// must at least be counted, so a rising Late figure explains the gap.
func TestLineBelowTheStreamStartIsCountedNotSilentlyDropped(t *testing.T) {
	r := New()
	s := newSender("192.0.2.1")
	early := s.cont("Content-Length: 0") // numbered 400001
	head := s.head("12:00:00.100", "%SYS-6-A: the stream starts here")

	feed(r, "192.0.2.1", 0, head, early) // head arrives first
	r.Flush()

	st := r.Stats()[0]
	if st.Late != 1 {
		t.Errorf("Late = %d, want 1", st.Late)
	}
	if st.LostLines != 0 {
		t.Errorf("LostLines = %d, want 0: nothing before the stream started was lost", st.LostLines)
	}
}

// TestLostLineMakesAnIncompleteRecord: the guarantee that matters most. A
// record with a line missing is shown as incomplete, never silently as whole.
func TestLostLineMakesAnIncompleteRecord(t *testing.T) {
	r := New()
	s := newSender("192.0.2.1")
	dgs := s.invite("12:00:00.123", "aaaa-0005@192.0.2.20", sdp)

	// Drop one body line in the middle.
	dropped := len(dgs) - 3
	kept := append(append([]string{}, dgs[:dropped]...), dgs[dropped+1:]...)
	feed(r, "192.0.2.1", 0, kept...)

	// The hole is given up on once the reorder window has elapsed, and the
	// record that follows is idle by then, so Tick releases it.
	got := r.Tick(at(1000))
	got = append(got, r.Flush()...)
	rec := only(t, got)

	if !rec.Incomplete {
		t.Fatal("a record missing a line must be marked incomplete")
	}
	if rec.MissingLines != 1 {
		t.Errorf("MissingLines = %d, want 1", rec.MissingLines)
	}
	if !rec.SIP.Truncated {
		t.Error("Content-Length should also catch the short body")
	}
	// "lost or rate-limited", never "lost": open question 2.
	var warned bool
	for _, w := range rec.Warnings {
		if strings.Contains(w, "lost or rate-limited") {
			warned = true
		}
		if strings.Contains(w, "lost") && !strings.Contains(w, "lost or rate-limited") {
			t.Errorf("warning claims loss without the rate-limit caveat: %q", w)
		}
	}
	if !warned {
		t.Errorf("no loss warning on the record: %v", rec.Warnings)
	}
	if st := r.Stats()[0]; st.LostLines != 1 {
		t.Errorf("LostLines = %d, want 1", st.LostLines)
	}
}

// TestLossIsNotCountedAsReordering: every line behind a hole is parked before
// anyone knows whether the hole is reordering or loss. Once it is given up on
// as loss, those lines were in the order the device sent them all along.
// Counting them would tell the engineer the network is shuffling datagrams
// when it is only dropping them — and under real loss that is most of the
// stream, so the number is not a rounding error.
func TestLossIsNotCountedAsReordering(t *testing.T) {
	r := New()
	s := newSender("192.0.2.1")
	dgs := s.invite("12:00:00.123", "aaaa-0009@192.0.2.20", sdp)

	// Drop a line early, so most of the message queues up behind the hole.
	const dropped = 3
	kept := append(append([]string{}, dgs[:dropped]...), dgs[dropped+1:]...)
	behind := len(kept) - dropped
	feed(r, "192.0.2.1", 0, kept...)
	r.Tick(at(1000))
	r.Flush()

	st := r.Stats()[0]
	if st.LostLines != 1 {
		t.Fatalf("LostLines = %d, want 1", st.LostLines)
	}
	if st.Reordered != 0 {
		t.Errorf("Reordered = %d, want 0: %d line(s) queued behind the lost one, "+
			"none of them out of order", st.Reordered, behind)
	}
}

// TestLostRecordCountsOnTheInnerCounter: the two counters count different
// things, and a gap in the inner one means whole records are gone.
func TestLostRecordCountsOnTheInnerCounter(t *testing.T) {
	r := New()
	s := newSender("192.0.2.1")
	first := s.head("12:00:00.100", "%SYS-6-LOGGINGHOST_STARTSTOP: Logging to host started")
	// Skip three record numbers without skipping any line numbers: the router
	// dropped whole records before transmitting them.
	s.recSeq += 3
	second := s.head("12:00:01.100", "%SYS-6-CLOCKUPDATE: System clock has been updated")

	feed(r, "192.0.2.1", 0, first, second)
	r.Flush()

	st := r.Stats()[0]
	if st.LostRecords != 3 {
		t.Errorf("LostRecords = %d, want 3", st.LostRecords)
	}
	if st.LostLines != 0 {
		t.Errorf("LostLines = %d, want 0: no line number was skipped", st.LostLines)
	}
}

// TestBothCountersAreIndependent drives one gap in each and checks neither is
// reported as the other.
func TestBothCountersAreIndependent(t *testing.T) {
	r := New()
	s := newSender("192.0.2.1")
	a := s.head("12:00:00.100", "%SYS-6-A: one")
	s.lineSeq += 2 // two lines lost
	s.recSeq += 5  // five records lost
	b := s.head("12:00:01.100", "%SYS-6-B: two")

	feed(r, "192.0.2.1", 0, a, b)
	r.Tick(at(1000))
	r.Flush()

	st := r.Stats()[0]
	if st.LostLines != 2 {
		t.Errorf("LostLines = %d, want 2", st.LostLines)
	}
	if st.LostRecords != 5 {
		t.Errorf("LostRecords = %d, want 5", st.LostRecords)
	}
}

// TestSourcesAreTrackedSeparately is the 974-million-phantom-losses lesson:
// sequence numbers are per device and differencing across devices is
// meaningless.
func TestSourcesAreTrackedSeparately(t *testing.T) {
	r := New()
	a, b := newSender("192.0.2.1"), newSender("192.0.2.2")
	// Two devices in wildly different numbering spaces, interleaved.
	b.lineSeq, b.recSeq = 900000000, 43300000

	feed(r, "192.0.2.1", 0, a.head("12:00:00.100", "%SYS-6-A: from device one"))
	feed(r, "192.0.2.2", 1, b.head("12:00:00.200", "%SYS-6-B: from device two"))
	feed(r, "192.0.2.1", 2, a.head("12:00:00.300", "%SYS-6-C: from device one again"))
	feed(r, "192.0.2.2", 3, b.head("12:00:00.400", "%SYS-6-D: from device two again"))
	r.Tick(at(2000))
	r.Flush()

	stats := r.Stats()
	if len(stats) != 2 {
		t.Fatalf("want 2 sources, got %d", len(stats))
	}
	for _, st := range stats {
		if st.LostLines != 0 || st.LostRecords != 0 || st.Restarts != 0 {
			t.Errorf("%s: invented loss across devices: %+v", st.Source, st)
		}
		if st.Records != 2 {
			t.Errorf("%s: Records = %d, want 2", st.Source, st.Records)
		}
	}
}

// TestHugeJumpRestartsRatherThanReportingMillionsLost: a reload, or something
// else sending from the same address. Reporting 974M lost lines is a lie.
func TestHugeJumpRestartsRatherThanReportingMillionsLost(t *testing.T) {
	r := New()
	s := newSender("192.0.2.1")
	a := s.head("12:00:00.100", "%SYS-6-A: before the reload")
	s.lineSeq = 1
	s.recSeq = 1
	b := s.head("12:00:30.000", "%SYS-5-RESTART: System restarted")

	got := feed(r, "192.0.2.1", 0, a, b)
	got = append(got, r.Flush()...)
	if len(got) != 2 {
		t.Fatalf("want both records, got %d: %s", len(got), summarize(got))
	}
	st := r.Stats()[0]
	if st.Restarts != 1 {
		t.Errorf("Restarts = %d, want 1", st.Restarts)
	}
	if st.LostLines != 0 {
		t.Errorf("LostLines = %d, want 0: a new numbering space is not loss", st.LostLines)
	}
}

// TestIdleTimeoutReleasesTheLastRecord: on a quiet CUBE the newest record
// would otherwise never be shown, because a record ends when the next begins.
func TestIdleTimeoutReleasesTheLastRecord(t *testing.T) {
	r := &Reassembler{IdleTimeout: 100 * time.Millisecond}
	s := newSender("192.0.2.1")

	if got := feed(r, "192.0.2.1", 0, s.head("12:00:00.100", "%SYS-6-A: alone")); len(got) != 0 {
		t.Fatal("a record is not complete the moment it arrives")
	}
	if got := r.Tick(at(50)); len(got) != 0 {
		t.Fatal("released before the idle timeout elapsed")
	}
	rec := only(t, r.Tick(at(200)))
	if rec.Log == nil || rec.Log.Mnemonic != "A" {
		t.Errorf("wrong record released: %+v", rec.Log)
	}
	// And it is released once, not on every tick.
	if got := r.Tick(at(400)); len(got) != 0 {
		t.Errorf("released twice: %s", summarize(got))
	}
}

// TestIdleTimeoutWaitsForHeldLines: a record with lines still in the reorder
// buffer is not idle, it is waiting.
func TestIdleTimeoutWaitsForHeldLines(t *testing.T) {
	r := &Reassembler{IdleTimeout: 50 * time.Millisecond, ReorderWindow: time.Second}
	s := newSender("192.0.2.1")
	head := s.head("12:00:00.100", "//-1/A1B2C3D4E5F6/SIP/Msg/ccsipDisplayMsg:")
	lost := s.cont("Received:")
	later := s.cont("OPTIONS sip:192.0.2.10 SIP/2.0")
	_ = lost

	feed(r, "192.0.2.1", 0, head, later) // the middle line is held back
	if got := r.Tick(at(100)); len(got) != 0 {
		t.Errorf("released while a line was still held: %s", summarize(got))
	}
	// Once the reorder window passes, the hole is loss and the record follows.
	recs := r.Tick(at(2000))
	recs = append(recs, r.Flush()...)
	rec := only(t, recs)
	if !rec.Incomplete || rec.MissingLines != 1 {
		t.Errorf("want incomplete with 1 missing line, got incomplete=%v missing=%d",
			rec.Incomplete, rec.MissingLines)
	}
}

// TestReorderDepthGivesUpOnADeepHole: nineteen lines is a SIP message, so a
// hole with far more than that stacked behind it is loss, not reordering, and
// waiting the full window would stall the display.
func TestReorderDepthGivesUpOnADeepHole(t *testing.T) {
	r := &Reassembler{ReorderDepth: 4, ReorderWindow: time.Hour}
	s := newSender("192.0.2.1")
	feed(r, "192.0.2.1", 0, s.head("12:00:00.100", "%SYS-6-A: first"))

	s.lineSeq++ // the line that never arrives
	var dgs []string
	for i := 0; i < 6; i++ {
		dgs = append(dgs, s.head(fmt.Sprintf("12:00:0%d.000", i+1), fmt.Sprintf("%%SYS-6-N%d: later", i)))
	}
	got := feed(r, "192.0.2.1", 10, dgs...)
	if len(got) == 0 {
		t.Fatal("depth limit should have released the backlog without waiting an hour")
	}
	if st := r.Stats()[0]; st.LostLines != 1 {
		t.Errorf("LostLines = %d, want 1", st.LostLines)
	}
}

// TestLateLineIsDroppedNotMisplaced: a line that turns up after its hole was
// given up on would be inserted after lines it belongs before. Losing it is
// better than showing a scrambled message as whole.
func TestLateLineIsDroppedNotMisplaced(t *testing.T) {
	r := &Reassembler{ReorderWindow: 10 * time.Millisecond}
	s := newSender("192.0.2.1")
	feed(r, "192.0.2.1", 0, s.head("12:00:00.100", "//-1/A1B2C3D4E5F6/SIP/Msg/ccsipDisplayMsg:"))
	missing := s.cont("Received:")
	feed(r, "192.0.2.1", 1, s.cont("OPTIONS sip:192.0.2.10 SIP/2.0"))
	r.Tick(at(500)) // give up on the hole

	feed(r, "192.0.2.1", 600, missing) // arrives far too late
	r.Flush()

	st := r.Stats()[0]
	if st.Late != 1 {
		t.Errorf("Late = %d, want 1", st.Late)
	}
}

// TestDuplicateLineIsDropped: a retransmitting or double-configured device.
func TestDuplicateLineIsDropped(t *testing.T) {
	r := New()
	s := newSender("192.0.2.1")
	head := s.head("12:00:00.100", "//-1/A1B2C3D4E5F6/SIP/Msg/ccsipDisplayMsg:")
	c1 := s.cont("Received:")
	c2 := s.cont("OPTIONS sip:192.0.2.10 SIP/2.0")

	feed(r, "192.0.2.1", 0, head, c2, c2, c1) // c2 held twice, then the hole fills
	rec := only(t, r.Flush())
	if rec.Incomplete {
		t.Error("a duplicate is not loss")
	}
	if st := r.Stats()[0]; st.Duplicate != 1 {
		t.Errorf("Duplicate = %d, want 1", st.Duplicate)
	}
}

// TestNoSequenceNumbersStillWorks: without "service sequence-numbers" there is
// no counter to order by and no loss detection, but the lines must still reach
// the user.
func TestNoSequenceNumbersStillWorks(t *testing.T) {
	r := New()
	feed(r, "192.0.2.1", 0,
		"<191>Sep 24 12:00:00.123 UTC: //-1/A1B2C3D4E5F6/SIP/Msg/ccsipDisplayMsg:\r",
		"<191>Received:\r",
		"<191>OPTIONS sip:192.0.2.10 SIP/2.0\r",
	)
	rec := only(t, r.Flush())
	if rec.SIP == nil || rec.SIP.Method != "OPTIONS" {
		t.Fatalf("message lost without a counter: %+v", rec.SIP)
	}
	if rec.HasLineSeq {
		t.Error("HasLineSeq should be false when the device sends no counter")
	}
	if st := r.Stats()[0]; st.NoSeq != 3 {
		t.Errorf("NoSeq = %d, want 3", st.NoSeq)
	}
}

// TestSeverityComesFromTheHeadLine: a continuation inherits the record's
// severity, so a stray value on a continuation must not win.
func TestSeverityComesFromTheHeadLine(t *testing.T) {
	r := New()
	s := newSender("192.0.2.1")
	s.severity = 187 // error
	head := s.head("12:00:00.100", "%VOICE_IEC-3-GW: Internal Error: Software error")
	s.severity = 191
	cont := s.cont("     IEC=1.1.130.7")

	feed(r, "192.0.2.1", 0, head, cont)
	rec := only(t, r.Flush())
	if rec.Severity != 3 || rec.SeverityName != "error" {
		t.Errorf("severity = %d/%q, want 3/error", rec.Severity, rec.SeverityName)
	}
	if rec.Facility != 23 {
		t.Errorf("Facility = %d, want 23 (local7)", rec.Facility)
	}
}

// TestOrphanLinesAreCountedNotAttached: starting the listener in the middle of
// a message gives lines with no record to belong to.
func TestOrphanLinesAreCountedNotAttached(t *testing.T) {
	r := New()
	s := newSender("192.0.2.1")
	feed(r, "192.0.2.1", 0,
		s.cont("Content-Length: 0"),
		s.cont(""),
		s.head("12:00:00.500", "%SYS-6-A: the first whole record"))
	rec := only(t, r.Flush())
	if rec.Log == nil || rec.Log.Mnemonic != "A" {
		t.Fatalf("wrong record: %+v", rec.Log)
	}
	if rec.Lines != 1 {
		t.Errorf("Lines = %d, want 1: the orphans must not be attached", rec.Lines)
	}
	if st := r.Stats()[0]; st.Orphans != 2 {
		t.Errorf("Orphans = %d, want 2", st.Orphans)
	}
}

// TestRecordBoundaryIsTheNextHeadLine: two records back to back, no blank line
// between them.
func TestRecordBoundaryIsTheNextHeadLine(t *testing.T) {
	r := New()
	s := newSender("192.0.2.1")
	got := feed(r, "192.0.2.1", 0,
		s.head("12:00:00.100", "//12/A1B2C3D4E5F6/SIP/Msg/ccsipDisplayMsg:"),
		s.cont("Sent:"),
		s.cont("SIP/2.0 180 Ringing"),
		s.head("12:00:00.200", "//12/A1B2C3D4E5F6/SIP/Msg/ccsipDisplayMsg:"),
		s.cont("Sent:"),
		s.cont("SIP/2.0 200 OK"),
	)
	if len(got) != 1 {
		t.Fatalf("the second head should have completed the first record, got %d", len(got))
	}
	if got[0].SIP == nil || got[0].SIP.Status != 180 {
		t.Errorf("first record = %+v, want 180 Ringing", got[0].SIP)
	}
	rec := only(t, r.Flush())
	if rec.SIP == nil || rec.SIP.Status != 200 {
		t.Errorf("second record = %+v, want 200 OK", rec.SIP)
	}
}

// TestStatsCountEveryLine is a cheap invariant that has caught miscounting
// before: every datagram is one line, whatever became of it.
func TestStatsCountEveryLine(t *testing.T) {
	r := New()
	s := newSender("192.0.2.1")
	dgs := s.invite("12:00:00.123", "aaaa-0006@192.0.2.20", sdp)
	feed(r, "192.0.2.1", 0, dgs...)
	r.Flush()
	if st := r.Stats()[0]; st.Lines != uint64(len(dgs)) {
		t.Errorf("Lines = %d, want %d", st.Lines, len(dgs))
	}
}

func TestFlushIsIdempotent(t *testing.T) {
	r := New()
	s := newSender("192.0.2.1")
	feed(r, "192.0.2.1", 0, s.head("12:00:00.100", "%SYS-6-A: one"))
	if len(r.Flush()) != 1 {
		t.Fatal("first flush should release the record")
	}
	if got := r.Flush(); len(got) != 0 {
		t.Errorf("second flush released %d record(s) again", len(got))
	}
}

func TestConcurrentSourcesAreSafe(t *testing.T) {
	r := New()
	done := make(chan struct{})
	for i := 0; i < 4; i++ {
		src := fmt.Sprintf("192.0.2.%d", i+1)
		go func() {
			defer func() { done <- struct{}{} }()
			s := newSender(src)
			for n := 0; n < 200; n++ {
				r.Datagram(Datagram{Source: src,
					Payload: s.head("12:00:00.100", "%SYS-6-A: concurrent"), Time: at(n)})
			}
		}()
	}
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				r.Tick(time.Now())
				r.Stats()
			}
		}
	}()
	for i := 0; i < 4; i++ {
		<-done
	}
	close(stop)
	r.Flush()
	if n := len(r.Stats()); n != 4 {
		t.Errorf("want 4 sources, got %d", n)
	}
}

// TestCallColumnIdentifiesTheLeg: the table's call column, which is a leg
// identity and not a call. The fallbacks matter because an inbound call's
// first INVITE arrives with call entry ID -1, before a leg exists.
func TestCallColumnIdentifiesTheLeg(t *testing.T) {
	r := New()
	s := newSender("192.0.2.1")

	// A debug line that names its leg outright.
	feed(r, "192.0.2.1", 0, s.head("12:00:00.100", "//42/A1B2C3D4E5F6/SIP/Msg/ccsipDisplayMsg:"))
	feed(r, "192.0.2.1", 1, s.cont("Sent:"), s.cont("SIP/2.0 180 Ringing"))

	// One with no call entry ID: the Call-ID has to carry it.
	feed(r, "192.0.2.1", 10, s.invite("12:00:01.000", "aaaa-0007@192.0.2.20", "v=0")...)
	got := r.Flush()

	all := r.Stats()[0]
	_ = all
	if len(got) < 1 {
		t.Fatal("no records")
	}
	last := got[len(got)-1]
	if last.Call != "aaaa-0007@192.0.2.20" {
		t.Errorf("Call = %q, want the SIP Call-ID when the entry ID is -1", last.Call)
	}
}

func TestCallColumnPrefersTheCallEntryID(t *testing.T) {
	r := New()
	s := newSender("192.0.2.1")
	feed(r, "192.0.2.1", 0,
		s.head("12:00:00.100", "//42/A1B2C3D4E5F6/SIP/Msg/ccsipDisplayMsg:"),
		s.cont("Sent:"),
		s.cont("SIP/2.0 180 Ringing"),
		s.cont("Call-ID: aaaa-0008@192.0.2.20"),
		s.cont("Content-Length: 0"),
		s.cont(""))
	rec := only(t, r.Flush())
	if rec.Call != "42" {
		t.Errorf("Call = %q, want the call entry ID 42", rec.Call)
	}
}
