package correlate_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phuongnz/cube-logger/internal/correlate"
	"github.com/phuongnz/cube-logger/internal/parse"
)

// ladderOf correlates a fixture and lays out its first non-keepalive call.
func ladderOf(t *testing.T, name string) (*correlate.Call, *correlate.Ladder) {
	t.Helper()
	c, grouped := correlateFile(t, filepath.Join("..", "..", "testdata", name))
	recs := c.Records()
	lookup := func(ref uint64) *parse.Record {
		if ref >= uint64(len(recs)) {
			return nil
		}
		return recs[ref]
	}
	for _, call := range grouped.Calls {
		if !call.Keepalive {
			return call, correlate.BuildLadder(call, lookup)
		}
	}
	t.Fatalf("%s: no call to draw", name)
	return nil, nil
}

func TestLadderPutsCUBEBetweenTheTwoPeers(t *testing.T) {
	_, l := ladderOf(t, "basic_call.txt")

	if len(l.Columns) != 3 {
		t.Fatalf("columns = %d (%+v), want the caller, CUBE and the called peer", len(l.Columns), l.Columns)
	}
	if l.Columns[0].Kind != correlate.ColPeer || l.Columns[1].Kind != correlate.ColCUBE ||
		l.Columns[2].Kind != correlate.ColPeer {
		t.Fatalf("column kinds = %v, want peer, cube, peer", kinds(l))
	}
	// The addresses are the fixture's, which is invented data from a
	// documentation range. The inbound leg's peer sent the first INVITE.
	if l.Columns[0].Label != "10.0.0.5" {
		t.Errorf("inbound peer = %q, want the address the INVITE came from", l.Columns[0].Label)
	}
	if l.Columns[1].Label != "10.0.0.1" {
		t.Errorf("CUBE column = %q, want the address CUBE used", l.Columns[1].Label)
	}
	if l.Columns[2].Label != "192.0.2.10" {
		t.Errorf("outbound peer = %q, want the address CUBE sent the INVITE to", l.Columns[2].Label)
	}
	if len(l.Columns[1].Legs) != 2 {
		t.Errorf("CUBE column legs = %v, want both legs of the call", l.Columns[1].Legs)
	}
}

func TestLadderArrowsAreInTimeOrderAndPointTheRightWay(t *testing.T) {
	_, l := ladderOf(t, "basic_call.txt")

	if len(l.Arrows) != 14 {
		t.Fatalf("arrows = %d, want one per SIP message in the fixture", len(l.Arrows))
	}
	for i := 1; i < len(l.Arrows); i++ {
		if l.Arrows[i].Time.Before(l.Arrows[i-1].Time) {
			t.Fatalf("arrow %d is before the one above it: the ladder is not in time order", i)
		}
	}

	first := l.Arrows[0]
	if first.Method != "INVITE" || first.From != 0 || first.To != 1 {
		t.Errorf("first arrow = %+v, want the inbound INVITE from the left peer into CUBE", first)
	}
	if !first.Body {
		t.Error("the first INVITE carried SDP; the arrow should say so")
	}

	// The outbound INVITE leaves CUBE for the right-hand peer.
	var out *correlate.Arrow
	for i := range l.Arrows {
		if l.Arrows[i].Method == "INVITE" && l.Arrows[i].Leg != first.Leg {
			out = &l.Arrows[i]
			break
		}
	}
	if out == nil {
		t.Fatal("no INVITE on the second leg")
	}
	if out.From != 1 || out.To != 2 {
		t.Errorf("outbound INVITE goes %d -> %d, want CUBE (1) -> peer (2)", out.From, out.To)
	}

	classes := map[string]int{}
	for _, a := range l.Arrows {
		classes[a.Class]++
	}
	if classes[correlate.ClassProvisional] == 0 || classes[correlate.ClassSuccess] == 0 ||
		classes[correlate.ClassRequest] == 0 {
		t.Errorf("classes = %v, want requests, provisionals and successes", classes)
	}
}

func TestLadderOfAFailedCallCarriesTheFailureAndTheIEC(t *testing.T) {
	call, l := ladderOf(t, "failed_call.txt")

	var failure *correlate.Arrow
	for i := range l.Arrows {
		if l.Arrows[i].Class == correlate.ClassFailure {
			failure = &l.Arrows[i]
			break
		}
	}
	if failure == nil {
		t.Fatalf("no failure arrow in %s, call result %q", call.ID, call.Result)
	}
	if failure.Status < 400 {
		t.Errorf("failure arrow status = %d, want a 4xx or worse", failure.Status)
	}
	if call.IEC != "" && len(l.Notes) == 0 {
		t.Errorf("call carries IEC %s but the ladder has no note saying so", call.IEC)
	}
	for _, n := range l.Notes {
		if !strings.HasPrefix(n.Text, "%") {
			t.Errorf("note %q does not look like a %% log line", n.Text)
		}
	}
}

// A record that has aged out of the ring is counted, not quietly skipped: a
// ladder with holes in it must say that it has holes.
func TestLadderCountsRecordsItCannotLookUp(t *testing.T) {
	c, grouped := correlateFile(t, filepath.Join("..", "..", "testdata", "basic_call.txt"))
	recs := c.Records()
	gone := func(ref uint64) *parse.Record {
		if ref < 4 { // pretend the first four aged out
			return nil
		}
		return recs[ref]
	}
	call := grouped.Calls[0]
	l := correlate.BuildLadder(call, gone)
	if l.Missing != 4 {
		t.Errorf("Missing = %d, want 4", l.Missing)
	}
	if len(l.Arrows) == 0 {
		t.Error("the records that are still there should still be drawn")
	}
}

func TestLadderOfNothing(t *testing.T) {
	l := correlate.BuildLadder(nil, func(uint64) *parse.Record { return nil })
	if len(l.Columns) != 0 || len(l.Arrows) != 0 {
		t.Errorf("a nil call drew %+v", l)
	}
}

// A leg whose peer never appeared in a request still gets a column, because a
// ladder with a missing side is not a ladder.
func TestLadderLabelsAnUnknownPeer(t *testing.T) {
	_, l := ladderOf(t, "voice_trace.txt")
	for i, c := range l.Columns {
		if c.Label == "" {
			t.Errorf("column %d has no label: %+v", i, c)
		}
	}
	cubes := 0
	for _, c := range l.Columns {
		if c.Kind == correlate.ColCUBE {
			cubes++
		}
	}
	if cubes != 1 {
		t.Errorf("cube columns = %d, want exactly one", cubes)
	}
}

func kinds(l *correlate.Ladder) []string {
	out := make([]string, len(l.Columns))
	for i, c := range l.Columns {
		out[i] = c.Kind
	}
	return out
}

// hostOf is not exported, so it is exercised through the labels a ladder
// produces. This test pins the shapes that matter: a URI with a user and a
// port, and an IPv6 literal in brackets.
func TestLadderHandlesIPv6AndURIParameters(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "v6.txt")
	// Invented values: RFC 3849 documentation prefix, RFC 5737 address.
	const fixture = `100001: Sep 24 10:00:00.000: //-1/AABBCCDDEEFF/SIP/Msg/ccsipDisplayMsg:
Received:
INVITE sip:+15550100@[2001:db8::1]:5060;transport=tcp SIP/2.0
Via: SIP/2.0/TCP [2001:db8::2]:5060;branch=z9hG4bKaaa
From: <sip:+15550199@[2001:db8::2]>;tag=aaa
To: <sip:+15550100@[2001:db8::1]>
Call-ID: v6-call-1@example.invalid
CSeq: 1 INVITE
Content-Length: 0

`
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	c, grouped := correlateFile(t, path)
	recs := c.Records()
	l := correlate.BuildLadder(grouped.Calls[0], func(ref uint64) *parse.Record { return recs[ref] })
	if len(l.Columns) != 2 {
		t.Fatalf("columns = %+v, want a peer and CUBE", l.Columns)
	}
	if l.Columns[0].Label != "2001:db8::2" {
		t.Errorf("peer = %q, want the bracketed Via address unwrapped", l.Columns[0].Label)
	}
	if l.Columns[1].Label != "2001:db8::1" {
		t.Errorf("CUBE = %q, want the Request-URI host without its port or parameters",
			l.Columns[1].Label)
	}
}
