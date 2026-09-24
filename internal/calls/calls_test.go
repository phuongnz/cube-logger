package calls_test

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phuongnz/cube-logger/internal/calls"
	"github.com/phuongnz/cube-logger/internal/parse"
)

// fixture parses one of the committed fixtures. They are hand-written with
// invented numbers and addresses; nothing here comes from a real capture.
func fixture(t *testing.T, name string) []*parse.Record {
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

// feed loads a fixture into an index with store-like IDs, which start at 1.
func feed(t *testing.T, ix *calls.Index, name string) []*parse.Record {
	t.Helper()
	recs := fixture(t, name)
	for i, r := range recs {
		ix.Add(uint64(i)+1, r)
	}
	return recs
}

func lookupOf(recs []*parse.Record) calls.Lookup {
	return func(ref uint64) *parse.Record {
		if ref == 0 || ref > uint64(len(recs)) {
			return nil
		}
		return recs[ref-1]
	}
}

func TestListSummarisesACall(t *testing.T) {
	ix := calls.New(0)
	feed(t, ix, "basic_call.txt")

	list := ix.List(0, false)
	if len(list) != 1 {
		t.Fatalf("calls = %d, want 1", len(list))
	}
	c := list[0]
	if c.Calling == "" || c.Called == "" {
		t.Errorf("call has no numbers: %+v", c)
	}
	if c.State != "ended" {
		t.Errorf("state = %q, want ended", c.State)
	}
	if c.Result == "" {
		t.Errorf("result is empty; the call list's whole point is saying what happened")
	}
	if c.Failed {
		t.Errorf("a call that was answered and hung up is not a failure: %+v", c)
	}
	if c.DurationMs <= 0 {
		t.Errorf("durationMs = %d, want the time from the first record to the last", c.DurationMs)
	}
	if c.Legs != 2 {
		t.Errorf("legs = %d, want 2", c.Legs)
	}
	if c.Records == 0 {
		t.Error("the call claims no records")
	}
}

func TestAFailedCallIsMarkedFailed(t *testing.T) {
	ix := calls.New(0)
	feed(t, ix, "failed_call.txt")
	list := ix.List(0, false)
	if len(list) == 0 {
		t.Fatal("no calls")
	}
	if !list[0].Failed {
		t.Errorf("call not marked failed: %+v", list[0])
	}
}

func TestKeepalivesAreHiddenUnlessAskedFor(t *testing.T) {
	ix := calls.New(0)
	feed(t, ix, "keepalive_and_logs.txt")
	if n := len(ix.List(0, false)); n != 0 {
		t.Errorf("calls = %d, want the OPTIONS probes hidden", n)
	}
	if n := len(ix.List(0, true)); n == 0 {
		t.Error("the fixture has keepalive legs; -keepalives should show them")
	}
}

func TestListIsNewestFirstAndBounded(t *testing.T) {
	ix := calls.New(0)
	feed(t, ix, "guid_reuse.txt")
	list := ix.List(0, false)
	if len(list) < 2 {
		t.Fatalf("calls = %d, want the two calls the reused GUID must not merge", len(list))
	}
	if list[0].Start.Before(list[1].Start) {
		t.Errorf("list is oldest first; the call an engineer wants is the newest")
	}
	if n := len(ix.List(1, false)); n != 1 {
		t.Errorf("List(1) returned %d", n)
	}
}

func TestSinceSendsOnlyWhatChanged(t *testing.T) {
	ix := calls.New(0)
	recs := fixture(t, "basic_call.txt")

	for i, r := range recs[:4] {
		ix.Add(uint64(i)+1, r)
	}
	first := ix.Since(0)
	if len(first.Calls) == 0 {
		t.Fatal("nothing reported after the first records")
	}
	if ix.Since(first.Rev).Calls != nil {
		t.Errorf("a second poll with no new records reported changes: %+v", ix.Since(first.Rev))
	}

	for i, r := range recs[4:] {
		ix.Add(uint64(i)+5, r)
	}
	u := ix.Since(first.Rev)
	if len(u.Calls) == 0 {
		t.Fatal("the call changed and the update did not say so")
	}
	if u.Rev <= first.Rev {
		t.Errorf("rev did not advance: %d then %d", first.Rev, u.Rev)
	}
	if u.Calls[0].State != "ended" {
		t.Errorf("the update carries a stale summary: %+v", u.Calls[0])
	}
}

// A call that turns out to be part of another one has to come off the list, or
// the browser shows a phantom half-call for ever.
func TestAMergedCallIsRemovedButStillResolves(t *testing.T) {
	ix := calls.New(0)
	recs := feed(t, ix, "basic_call.txt")
	u := ix.Since(0)

	var merged string
	for _, id := range u.Removed {
		merged = id
	}
	if merged == "" {
		t.Skip("this fixture produced no merge")
	}
	for _, c := range u.Calls {
		if c.ID == merged {
			t.Fatalf("%s is both listed and removed", merged)
		}
	}
	// A browser that selected the ID before the merge still lands on the call.
	d, ok := ix.Get(merged, lookupOf(recs))
	if !ok {
		t.Fatalf("%s no longer resolves; a browser holding it would land nowhere", merged)
	}
	if d.ID == merged {
		t.Errorf("Get(%q) returned the merged shell rather than the call it became", merged)
	}
}

func TestGetBuildsTheLadderAndTheRecordList(t *testing.T) {
	ix := calls.New(0)
	recs := feed(t, ix, "basic_call.txt")
	list := ix.List(0, false)

	d, ok := ix.Get(list[0].ID, lookupOf(recs))
	if !ok {
		t.Fatal("the call in the list does not open")
	}
	if len(d.Records) != len(recs) {
		t.Errorf("records = %d, want all %d of the fixture's", len(d.Records), len(recs))
	}
	for i := 1; i < len(d.Records); i++ {
		if d.Records[i] < d.Records[i-1] {
			t.Fatalf("record refs are not in order: %v", d.Records)
		}
	}
	if d.Ladder == nil || len(d.Ladder.Columns) != 3 {
		t.Fatalf("ladder = %+v, want three columns", d.Ladder)
	}
	if len(d.Legs) != 2 {
		t.Errorf("legDetail = %d legs, want 2", len(d.Legs))
	}

	if _, ok := ix.Get("call-does-not-exist", lookupOf(recs)); ok {
		t.Error("an unknown call ID opened something")
	}
}

func TestRefsAreWhatTheTableFiltersOn(t *testing.T) {
	ix := calls.New(0)
	recs := feed(t, ix, "basic_call.txt")
	list := ix.List(0, false)
	refs, ok := ix.Refs(list[0].ID)
	if !ok {
		t.Fatal("no refs for the call")
	}
	if len(refs) != len(recs) {
		t.Errorf("refs = %d, want %d", len(refs), len(recs))
	}
	if refs[0] != 1 {
		t.Errorf("refs start at %d; the store's IDs start at 1", refs[0])
	}
}

func TestTextIsACompleteTranscript(t *testing.T) {
	ix := calls.New(0)
	recs := feed(t, ix, "basic_call.txt")
	list := ix.List(0, false)
	d, _ := ix.Get(list[0].ID, lookupOf(recs))

	raw := func(ref uint64) []string {
		r := lookupOf(recs)(ref)
		if r == nil {
			return nil
		}
		return r.Raw
	}
	text := calls.Text(d, raw)

	for _, want := range []string{"call:", "from:", "duration:", "leg:", "INVITE", "BYE"} {
		if !strings.Contains(text, want) {
			t.Errorf("the transcript has no %q in it", want)
		}
	}
	if n := strings.Count(text, "ccsipDisplayMsg"); n != len(recs) {
		t.Errorf("transcript holds %d records, want %d", n, len(recs))
	}
}

// A transcript pasted into a ticket must not look complete when it is not.
func TestTextSaysWhichRecordsAreGone(t *testing.T) {
	ix := calls.New(0)
	recs := feed(t, ix, "basic_call.txt")
	list := ix.List(0, false)
	aged := func(ref uint64) *parse.Record {
		if ref <= 3 {
			return nil // overwritten by the ring
		}
		return lookupOf(recs)(ref)
	}
	d, _ := ix.Get(list[0].ID, aged)
	text := calls.Text(d, func(ref uint64) []string {
		if r := aged(ref); r != nil {
			return r.Raw
		}
		return nil
	})
	if !strings.Contains(text, "3 record(s) no longer held") {
		t.Errorf("the transcript does not admit to its holes:\n%s", text[:min(400, len(text))])
	}
}

func TestEvictionIsReportedAndBounded(t *testing.T) {
	ix := calls.New(2)
	recs := fixture(t, "guid_reuse.txt")
	var ref uint64
	for round := 0; round < 4; round++ {
		for _, r := range recs {
			ref++
			ix.Add(ref, offset(r, round))
		}
	}
	st := ix.Stats()
	if st.Calls > 2 {
		t.Errorf("calls held = %d, want at most 2", st.Calls)
	}
	if st.Evicted == 0 {
		t.Error("calls were dropped and Stats does not say so")
	}
	if st.Max != 2 {
		t.Errorf("Max = %d, want 2", st.Max)
	}
	u := ix.Since(0)
	if len(u.Removed) == 0 && !u.Reset {
		t.Error("evicted calls were neither reported as removed nor as a reset")
	}
}

// The index is written on the socket's goroutine and read by the web server on
// another. This is the test that says so.
func TestConcurrentAddAndRead(t *testing.T) {
	ix := calls.New(64)
	recs := fixture(t, "basic_call.txt")

	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		var ref uint64
		for round := 0; round < 40; round++ {
			for _, r := range recs {
				ref++
				ix.Add(ref, offset(r, round))
			}
		}
		close(stop)
	}()
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				for _, c := range ix.List(10, true) {
					ix.Get(c.ID, lookupOf(recs))
					ix.Refs(c.ID)
				}
				ix.Since(0)
				ix.Stats()
			}
		}()
	}
	wg.Wait()
}

// offset makes a record look like a later, different call.
func offset(r *parse.Record, round int) *parse.Record {
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
		s.CallID = strings.Repeat("x", round) + s.CallID
		c.SIP = &s
	}
	return &c
}
