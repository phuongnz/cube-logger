package store

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/phuongnz/cube-logger/internal/live"
	"github.com/phuongnz/cube-logger/internal/parse"
)

// rec builds a minimal stored record. Every value is invented.
func rec(source, text string, sev int) *live.Record {
	return &live.Record{
		Record: &parse.Record{
			Source: source,
			Kind:   parse.KindLog,
			Text:   text,
			Time:   time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC),
			Raw:    []string{text},
		},
		Severity: sev,
		Lines:    1,
	}
}

func ids(es []Entry) []uint64 {
	out := make([]uint64, len(es))
	for i, e := range es {
		out[i] = e.ID
	}
	return out
}

func eq(t *testing.T, got, want []uint64) {
	t.Helper()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("ids = %v, want %v", got, want)
	}
}

func TestAddAssignsAscendingIDs(t *testing.T) {
	s := New(10)
	got := s.Add(rec("192.0.2.1", "one", 6), rec("192.0.2.1", "two", 6))
	eq(t, ids(got), []uint64{1, 2})
	eq(t, ids(s.Recent(0)), []uint64{1, 2})
	if st := s.Stats(); st.Total != 2 || st.Records != 2 || st.Lines != 2 {
		t.Errorf("Stats = %+v", st)
	}
}

func TestRingEvictsOldest(t *testing.T) {
	s := New(3)
	for i := 0; i < 5; i++ {
		s.Add(rec("192.0.2.1", fmt.Sprintf("line %d", i), 6))
	}
	eq(t, ids(s.Recent(0)), []uint64{3, 4, 5})

	st := s.Stats()
	if st.Records != 3 || st.Cap != 3 {
		t.Errorf("Records = %d, Cap = %d, want 3 and 3", st.Records, st.Cap)
	}
	if st.Evicted != 2 {
		t.Errorf("Evicted = %d, want 2", st.Evicted)
	}
	if st.Total != 5 {
		t.Errorf("Total = %d, want 5", st.Total)
	}
	if st.Oldest != 3 || st.Newest != 5 {
		t.Errorf("Oldest/Newest = %d/%d, want 3/5", st.Oldest, st.Newest)
	}
}

func TestRecentTakesTheNewest(t *testing.T) {
	s := New(10)
	for i := 0; i < 6; i++ {
		s.Add(rec("192.0.2.1", fmt.Sprintf("line %d", i), 6))
	}
	eq(t, ids(s.Recent(2)), []uint64{5, 6})
	eq(t, ids(s.Recent(100)), []uint64{1, 2, 3, 4, 5, 6})
	if got := s.Recent(0); len(got) != 6 {
		t.Errorf("Recent(0) returned %d, want everything", len(got))
	}
}

func TestSinceResumesFromAnID(t *testing.T) {
	s := New(10)
	for i := 0; i < 5; i++ {
		s.Add(rec("192.0.2.1", fmt.Sprintf("line %d", i), 6))
	}
	got, missed := s.Since(2, 0)
	eq(t, ids(got), []uint64{3, 4, 5})
	if missed != 0 {
		t.Errorf("missed = %d, want 0", missed)
	}
	// Caught up already.
	got, missed = s.Since(5, 0)
	if len(got) != 0 || missed != 0 {
		t.Errorf("Since(5) = %v, missed %d, want nothing", ids(got), missed)
	}
	// A watcher from the future asks for nothing and is told nothing is missing.
	got, missed = s.Since(99, 0)
	if len(got) != 0 || missed != 0 {
		t.Errorf("Since(99) = %v, missed %d", ids(got), missed)
	}
}

// A watcher away long enough for the ring to lap it is told how much it lost.
// That is eviction, not loss on the wire, and the two must not be confused.
func TestSinceReportsWhatTheRingOverwrote(t *testing.T) {
	s := New(3)
	for i := 0; i < 6; i++ {
		s.Add(rec("192.0.2.1", fmt.Sprintf("line %d", i), 6))
	}
	got, missed := s.Since(1, 0)
	eq(t, ids(got), []uint64{4, 5, 6})
	if missed != 2 { // 2 and 3 were overwritten
		t.Errorf("missed = %d, want 2", missed)
	}
}

func TestSinceCapsAtMaxAndKeepsTheLiveEdge(t *testing.T) {
	s := New(10)
	for i := 0; i < 8; i++ {
		s.Add(rec("192.0.2.1", fmt.Sprintf("line %d", i), 6))
	}
	got, missed := s.Since(0, 3)
	eq(t, ids(got), []uint64{6, 7, 8})
	if missed != 5 {
		t.Errorf("missed = %d, want 5", missed)
	}
}

func TestSinceOnAnEmptyStore(t *testing.T) {
	s := New(10)
	got, missed := s.Since(0, 0)
	if len(got) != 0 || missed != 0 {
		t.Errorf("Since on an empty store = %v, %d", ids(got), missed)
	}
	if st := s.Stats(); st.Oldest != 0 || st.Newest != 0 {
		t.Errorf("Stats on an empty store = %+v", st)
	}
}

func TestSubscribeReceivesNewRecords(t *testing.T) {
	s := New(10)
	sub := s.Subscribe(4)
	defer sub.Close()

	s.Add(rec("192.0.2.1", "one", 6))
	s.Add(rec("192.0.2.1", "two", 6), rec("192.0.2.1", "three", 6))

	eq(t, ids(<-sub.C), []uint64{1})
	eq(t, ids(<-sub.C), []uint64{2, 3})
	if st := s.Stats(); st.Watchers != 1 {
		t.Errorf("Watchers = %d, want 1", st.Watchers)
	}
}

// A browser that cannot keep up loses its place, not the socket's datagrams.
func TestSlowWatcherIsMarkedBehindNotBlocked(t *testing.T) {
	s := New(100)
	sub := s.Subscribe(2)
	defer sub.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 20; i++ {
			s.Add(rec("192.0.2.1", fmt.Sprintf("line %d", i), 6))
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Add blocked on a watcher that was not reading")
	}

	if !sub.Behind() {
		t.Error("the watcher should be marked behind")
	}
	if sub.Behind() {
		t.Error("Behind should clear the flag once read")
	}
	// Everything is still in the ring, so the watcher can resynchronise.
	got, missed := s.Since(0, 0)
	if len(got) != 20 || missed != 0 {
		t.Errorf("ring lost records: %d entries, %d missed", len(got), missed)
	}
}

func TestCloseIsIdempotentAndUnsubscribes(t *testing.T) {
	s := New(10)
	sub := s.Subscribe(1)
	sub.Close()
	sub.Close()
	if st := s.Stats(); st.Watchers != 0 {
		t.Errorf("Watchers = %d, want 0", st.Watchers)
	}
	// Delivering to a closed subscription must not panic on a closed channel.
	s.Add(rec("192.0.2.1", "after close", 6))
	if _, ok := <-sub.C; ok {
		t.Error("C should be closed and drained")
	}
}

func TestClearEmptiesTheRingButKeepsIDsAscending(t *testing.T) {
	s := New(10)
	s.Add(rec("192.0.2.1", "one", 6))
	s.Clear()
	if st := s.Stats(); st.Records != 0 {
		t.Errorf("Records = %d after Clear, want 0", st.Records)
	}
	got := s.Add(rec("192.0.2.1", "two", 6))
	if got[0].ID != 2 {
		t.Errorf("ID = %d after Clear, want 2: a clear is not a restart", got[0].ID)
	}
}

func TestAddIgnoresNil(t *testing.T) {
	s := New(10)
	got := s.Add(nil, rec("192.0.2.1", "one", 6), nil)
	if len(got) != 1 {
		t.Fatalf("Add stored %d entries, want 1", len(got))
	}
}

func TestMatchZeroValueAcceptsEverything(t *testing.T) {
	s := New(10)
	s.Add(rec("192.0.2.1", "%SYS-6-A: anything", 6))
	if got := s.Search(nil, 0); len(got) != 1 {
		t.Errorf("a nil filter should match everything, got %d", len(got))
	}
	if got := s.Search(&Match{MinSeverity: -1}, 0); len(got) != 1 {
		t.Errorf("an empty filter should match everything, got %d", len(got))
	}
}

func TestSearchByText(t *testing.T) {
	s := New(10)
	s.Add(
		rec("192.0.2.1", "%SYS-6-A: nothing here", 6),
		rec("192.0.2.1", "INVITE sip:+449876543210@192.0.2.10 SIP/2.0", 7),
		rec("192.0.2.2", "%SYS-6-B: nothing here either", 6),
	)
	got := s.Search(&Match{Text: "449876543210", MinSeverity: -1}, 0)
	if len(got) != 1 || got[0].ID != 2 {
		t.Errorf("text search found %v, want just id 2", ids(got))
	}
	// Case-insensitive, and the source counts as searchable text.
	if got := s.Search(&Match{Text: "invite", MinSeverity: -1}, 0); len(got) != 1 {
		t.Errorf("search should be case-insensitive, got %d", len(got))
	}
	if got := s.Search(&Match{Text: "192.0.2.2", MinSeverity: -1}, 0); len(got) != 1 {
		t.Errorf("the source should be searchable, got %v", ids(got))
	}
}

func TestSearchBySeverityKeepsTheMoreUrgent(t *testing.T) {
	s := New(10)
	s.Add(
		rec("192.0.2.1", "debug line", 7),
		rec("192.0.2.1", "informational line", 6),
		rec("192.0.2.1", "error line", 3),
	)
	got := s.Search(&Match{MinSeverity: 6}, 0)
	eq(t, ids(got), []uint64{2, 3})
	got = s.Search(&Match{MinSeverity: 3}, 0)
	eq(t, ids(got), []uint64{3})
}

// A datagram with no <PRI> has severity -1. A severity filter has nothing to
// compare it against and must not silently hide it.
func TestSeverityFilterKeepsRecordsWithNoSeverity(t *testing.T) {
	s := New(10)
	s.Add(rec("192.0.2.1", "no priority on the wire", -1))
	if got := s.Search(&Match{MinSeverity: 0}, 0); len(got) != 1 {
		t.Errorf("a record with no severity was hidden by a severity filter")
	}
}

func TestSearchBySourceAndCall(t *testing.T) {
	s := New(10)
	a := rec("192.0.2.1", "leg 42", 7)
	a.Call = "42"
	b := rec("192.0.2.2", "leg 43", 7)
	b.Call = "43"
	s.Add(a, b)

	if got := s.Search(&Match{Source: "192.0.2.2", MinSeverity: -1}, 0); len(got) != 1 || got[0].ID != 2 {
		t.Errorf("source filter found %v", ids(got))
	}
	if got := s.Search(&Match{Call: "42", MinSeverity: -1}, 0); len(got) != 1 || got[0].ID != 1 {
		t.Errorf("call filter found %v", ids(got))
	}
}

func TestSearchIncompleteOnly(t *testing.T) {
	s := New(10)
	whole := rec("192.0.2.1", "whole", 7)
	broken := rec("192.0.2.1", "broken", 7)
	broken.Incomplete = true
	broken.MissingLines = 3
	s.Add(whole, broken)

	got := s.Search(&Match{IncompleteOnly: true, MinSeverity: -1}, 0)
	if len(got) != 1 || got[0].ID != 2 {
		t.Errorf("incomplete filter found %v, want just id 2", ids(got))
	}
}

// Search returns the newest matches but hands them back in reading order.
func TestSearchCapsAtTheNewestAndReturnsInOrder(t *testing.T) {
	s := New(100)
	for i := 0; i < 10; i++ {
		s.Add(rec("192.0.2.1", "match me", 7))
	}
	got := s.Search(&Match{Text: "match", MinSeverity: -1}, 3)
	eq(t, ids(got), []uint64{8, 9, 10})
}

func TestConcurrentAddAndRead(t *testing.T) {
	s := New(1000)
	sub := s.Subscribe(64)
	defer sub.Close()

	// The reader is drained until the writers are done and the subscription is
	// closed, which is what closes C. Waiting on it before that would deadlock.
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for range sub.C {
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			s.Add(rec("192.0.2.1", "concurrent", 7))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			s.Recent(10)
			s.Stats()
			s.Since(uint64(i), 10)
			s.Search(&Match{Text: "concurrent", MinSeverity: -1}, 5)
		}
	}()
	wg.Wait()
	sub.Close()
	<-drained
	if st := s.Stats(); st.Total != 500 {
		t.Errorf("Total = %d, want 500", st.Total)
	}
}
