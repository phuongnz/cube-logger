package correlate

// The live path's requirements on the correlator, which are different from the
// file path's: a stream does not end, so nothing may grow without a bound and
// nothing may be pinned in memory that the store has already forgotten.

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/phuongnz/cube-logger/internal/parse"
)

func load(t *testing.T, name string) []*parse.Record {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "..", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	res, err := parse.Reader(f, name, 2026)
	if err != nil {
		t.Fatal(err)
	}
	return res.Records
}

func TestAddRefKeepsTheCallerHandlesAndNotTheRecords(t *testing.T) {
	recs := load(t, "basic_call.txt")
	c := New()
	// Store IDs start at 1 and are nothing like slice indexes, on purpose: a
	// correlator that quietly assumed one would pass with 0-based refs.
	for i, r := range recs {
		c.AddRef(uint64(i)+1000, r)
	}
	if got := len(c.Records()); got != 0 {
		t.Errorf("AddRef kept %d records; it must keep none", got)
	}
	calls := c.Calls()
	if len(calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(calls))
	}
	for _, l := range calls[0].Legs {
		for _, ref := range l.Records {
			if ref < 1000 {
				t.Fatalf("leg %s references %d, not the ID the caller gave", l.ID, ref)
			}
		}
	}
	if n := len(calls[0].Legs); n != 2 {
		t.Errorf("legs = %d, want the two legs of a back-to-back call", n)
	}
}

func TestMaxCallsDropsTheOldestFinishedCalls(t *testing.T) {
	recs := load(t, "basic_call.txt")
	c := New()
	c.MaxCalls = 3

	// Ten copies of the same call, each an hour apart and with its own call
	// entry IDs and GUID, so they are ten different calls rather than one.
	var ref uint64
	for round := 0; round < 10; round++ {
		for _, r := range recs {
			ref++
			c.AddRef(ref, shift(r, round))
		}
	}

	if got := len(c.Calls()); got > c.MaxCalls {
		t.Errorf("calls held = %d, want at most %d", got, c.MaxCalls)
	}
	if c.Evicted() != 7 {
		t.Errorf("Evicted() = %d, want the seven calls that were dropped", c.Evicted())
	}
	// The indexes have to shrink with the calls. If they do not, the leak has
	// only moved somewhere harder to see.
	if len(c.byEntry) > 2*c.MaxCalls || len(c.byCallID) > 2*c.MaxCalls ||
		len(c.openGUID) > c.MaxCalls || len(c.byID) > c.MaxCalls {
		t.Errorf("indexes did not shrink with the calls: byEntry=%d byCallID=%d openGUID=%d byID=%d",
			len(c.byEntry), len(c.byCallID), len(c.openGUID), len(c.byID))
	}
	// The newest call is the one an engineer is looking at, so it is the one
	// that must survive.
	held := c.Calls()
	if last := held[len(held)-1]; last.State != StateEnded || last.Result == "" {
		t.Errorf("the newest call did not survive intact: %+v", last)
	}
}

// Evicting a leg must really forget it. If a stale index entry survived, the
// next call to reuse that call entry ID would be silently glued onto a call
// that ended hours ago.
func TestAnEvictedCallEntryIDIsNotResurrected(t *testing.T) {
	recs := load(t, "basic_call.txt")
	c := New()
	c.MaxCalls = 1

	var ref uint64
	for _, r := range recs {
		ref++
		c.AddRef(ref, r)
	}
	// A second call an hour later that CUBE gave the *same* call entry IDs —
	// which a router does, since the IDs wrap. The first call is evicted as
	// the second one starts, so nothing must be left pointing at its legs.
	for _, r := range recs {
		ref++
		c.AddRef(ref, reuseEntryIDs(r))
	}
	calls := c.Calls()
	if len(calls) != 1 {
		t.Fatalf("calls = %d, want 1 held", len(calls))
	}
	if n := len(calls[0].Legs); n != 2 {
		t.Errorf("the surviving call has %d legs, want 2 — a stale index entry "+
			"would have attached the second round to the evicted call", n)
	}
}

func TestCallFollowsAMergeSoAnOldIDStillResolves(t *testing.T) {
	recs := load(t, "basic_call.txt")
	c := New()
	for i, r := range recs {
		c.AddRef(uint64(i), r)
	}
	calls := c.Calls()
	if len(calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(calls))
	}
	// Every ID the correlator ever minted resolves to a call that exists.
	for id := 1; id <= c.nCalls; id++ {
		if c.Call("call-"+itoa(id)) == nil {
			t.Errorf("call-%d resolves to nothing; a browser holding it would land nowhere", id)
		}
	}
	if c.Call("call-nope") != nil {
		t.Error("an ID that was never minted resolved to something")
	}
}

func TestUnattachedIsNotCollectedOnTheLivePath(t *testing.T) {
	recs := load(t, "keepalive_and_logs.txt")
	live, file := New(), New()
	for i, r := range recs {
		live.AddRef(uint64(i), r)
		file.Add(r)
	}
	if len(live.Result().Unattached) != 0 {
		t.Error("AddRef collected unattached records; on a live stream that list never stops growing")
	}
	if len(file.Result().Unattached) == 0 {
		t.Error("the fixture is meant to contain records that belong to no call")
	}
}

// reuseEntryIDs is a later call that happens to land on the same call entry
// IDs: a new time, a new GUID and a new SIP Call-ID, but the router's own
// per-leg counter back where it was.
func reuseEntryIDs(r *parse.Record) *parse.Record {
	c := shift(r, 1)
	if r.Debug != nil {
		d := *c.Debug
		d.CallID = r.Debug.CallID
		c.Debug = &d
	}
	return c
}

// shift makes a record look like a different call, an hour later per round, so
// one fixture can stand in for a long session.
func shift(r *parse.Record, round int) *parse.Record {
	if round == 0 {
		return r
	}
	c := *r
	c.Time = r.Time.Add(time.Duration(round) * time.Hour)
	if r.Debug != nil {
		d := *r.Debug
		if d.CallID != parse.NoCallID {
			d.CallID += int64(round) * 1000
		}
		if d.GUID != "" {
			d.GUID = d.GUID[:len(d.GUID)-1] + string("0123456789ABCDEF"[round%16])
		}
		c.Debug = &d
	}
	if r.SIP != nil {
		s := *r.SIP
		s.CallID = itoa(round) + "-" + s.CallID
		c.SIP = &s
	}
	return &c
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
