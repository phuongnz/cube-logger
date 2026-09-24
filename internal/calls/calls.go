// Package calls is the live call index: the call-centric view of a stream that
// never ends.
//
// The correlator already knows how to turn records into calls. What it does not
// know is that a browser is watching. This package adds the three things a live
// view needs and a batch run does not:
//
//   - Safety. Records arrive on the socket's goroutine while the web server
//     reads calls on another. Everything here is behind one mutex.
//   - A bound. correlate.MaxCalls keeps the index from growing for as long as
//     the session lasts.
//   - A version. Every call carries a revision that goes up when the call
//     changes, so a browser can be sent the four calls that moved instead of
//     the five thousand that did not. A call list that re-sent itself every
//     second would spend the whole budget on calls nobody is looking at.
//
// It holds no records. A leg references records by store ID, and anything that
// needs the records themselves — the ladder, the text export — takes a lookup
// and asks the store. That is what lets the ring evict a record without the
// call index having to care.
package calls

import (
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/phuongnz/cube-logger/internal/correlate"
	"github.com/phuongnz/cube-logger/internal/parse"
)

// DefaultMax is how many calls the index keeps.
//
// It is sized against the store's own ring: a hundred thousand records is a few
// thousand calls of SIP debug, so an index that held many more would be listing
// calls whose records had all been overwritten.
const DefaultMax = 5000

// Lookup resolves a record reference. It returns nil for a record the store has
// already overwritten, which is not an error: it is a call older than the ring.
//
// It must not call back into the Index. The Index holds its lock while it runs.
type Lookup func(ref uint64) *parse.Record

// Summary is one row of the call list.
type Summary struct {
	ID   string `json:"id"`
	Rev  uint64 `json:"rev"`
	GUID string `json:"guid,omitempty"`

	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
	// DurationMs is how long the call lasted. It is milliseconds rather than a
	// Go duration because the browser has to format it either way.
	DurationMs int64 `json:"durationMs"`

	Calling string `json:"calling,omitempty"`
	Called  string `json:"called,omitempty"`
	State   string `json:"state"`
	Result  string `json:"result,omitempty"`
	Cause   string `json:"cause,omitempty"`
	IEC     string `json:"iec,omitempty"`

	// Failed is the call list's colour: a final response of 4xx or worse, or an
	// internal error code. A call the caller hung up on is not a failure.
	Failed    bool     `json:"failed,omitempty"`
	Keepalive bool     `json:"keepalive,omitempty"`
	Legs      int      `json:"legs"`
	Records   int      `json:"records"`
	Sources   []string `json:"sources,omitempty"`
	Warnings  []string `json:"warnings,omitempty"`
}

// Detail is one call opened: its legs, every record in it, and the ladder.
type Detail struct {
	Summary
	Legs []*correlate.Leg `json:"legDetail"`
	// Records is every record of the call, in reference order, which is the
	// order they were stored and therefore the order they arrived.
	Records []uint64          `json:"recordRefs"`
	Ladder  *correlate.Ladder `json:"ladder"`
}

// Update is what changed since a revision.
type Update struct {
	Calls []Summary `json:"calls"`
	// Removed are calls that are no longer rows of their own: evicted, or
	// merged into another call once their second leg turned up.
	Removed []string `json:"removed,omitempty"`
	Rev     uint64   `json:"rev"`
	// Reset tells a browser to start its list again: the index has forgotten
	// more than it can describe, so a delta would leave stale rows on screen.
	Reset bool `json:"reset,omitempty"`
}

// Stats describe the index.
type Stats struct {
	Calls   int    `json:"calls"`
	Active  int    `json:"active"`
	Total   uint64 `json:"total"`
	Evicted uint64 `json:"evicted"`
	Max     int    `json:"max"`
	Rev     uint64 `json:"rev"`
}

// maxRemembered bounds how many forgotten call IDs are kept so that a browser
// can be told about them. Past it, a browser that has been away that long is
// told to start again instead.
const maxRemembered = 4096

// Index is the live set of calls. It is safe for concurrent use.
type Index struct {
	mu   sync.Mutex
	c    *correlate.Correlator
	rev  uint64
	revs map[string]uint64
	// gone maps a forgotten call ID to the revision it went at, so a browser
	// can be told to take the row off its list.
	gone     map[string]uint64
	goneFrom uint64 // the oldest revision `gone` can still account for
	total    uint64
}

// New returns an empty index holding at most max calls. Zero means DefaultMax.
func New(max int) *Index {
	if max <= 0 {
		max = DefaultMax
	}
	ix := &Index{
		c:    correlate.New(),
		revs: map[string]uint64{},
		gone: map[string]uint64{},
	}
	ix.c.MaxCalls = max
	ix.c.Forget = ix.forgetLocked
	return ix
}

// Add takes the next record. ref is the store ID the record was given, and it
// is what the call's Records will contain.
//
// Records must arrive in the order they were stored: the correlator's GUID
// window is a statement about time, and feeding it shuffled records makes it
// split calls that belong together.
func (ix *Index) Add(ref uint64, r *parse.Record) {
	if r == nil {
		return
	}
	ix.mu.Lock()
	defer ix.mu.Unlock()
	call := ix.c.AddRef(ref, r)
	if call == nil {
		return
	}
	ix.rev++
	if _, seen := ix.revs[call.ID]; !seen {
		ix.total++
	}
	ix.revs[call.ID] = ix.rev
	// A call that was merged away and is now being touched again is a row
	// again; the browser was told to drop it, and must be told it is back.
	delete(ix.gone, call.ID)
}

// forgetLocked runs inside the correlator, which runs inside Add, which holds
// the lock. It must not take it again.
func (ix *Index) forgetLocked(id string) {
	ix.rev++
	delete(ix.revs, id)
	ix.gone[id] = ix.rev
	if len(ix.gone) > maxRemembered {
		ix.pruneGone()
	}
}

// pruneGone drops the oldest half of the forgotten IDs and records how far back
// the remainder can still account for. A browser asking from before that point
// is told to start again rather than quietly left with rows that no longer
// exist.
func (ix *Index) pruneGone() {
	type g struct {
		id  string
		rev uint64
	}
	all := make([]g, 0, len(ix.gone))
	for id, rev := range ix.gone {
		all = append(all, g{id, rev})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].rev < all[j].rev })
	cut := len(all) / 2
	for _, e := range all[:cut] {
		delete(ix.gone, e.id)
	}
	if cut > 0 {
		ix.goneFrom = all[cut-1].rev
	}
}

// List returns the calls, newest first, at most max of them. Keepalives — legs
// that only ever carried OPTIONS — are left out unless keepalives is set: on a
// box with a dozen dial-peers they are most of the rows and none of the calls.
func (ix *Index) List(max int, keepalives bool) []Summary {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	all := ix.c.Calls()
	out := make([]Summary, 0, len(all))
	for i := len(all) - 1; i >= 0; i-- {
		if all[i].Keepalive && !keepalives {
			continue
		}
		out = append(out, ix.summarize(all[i]))
		if max > 0 && len(out) >= max {
			break
		}
	}
	return out
}

// Since returns the calls that changed after rev, oldest change first, and the
// ones that stopped being calls.
func (ix *Index) Since(rev uint64) Update {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	u := Update{Rev: ix.rev}
	if rev < ix.goneFrom {
		// More has been forgotten than can be described. Saying so is the only
		// honest answer; sending a delta would leave rows on screen for calls
		// that no longer exist.
		u.Reset = true
		rev = 0
	}
	for _, call := range ix.c.Calls() {
		if ix.revs[call.ID] > rev {
			u.Calls = append(u.Calls, ix.summarize(call))
		}
	}
	sort.Slice(u.Calls, func(i, j int) bool { return u.Calls[i].Rev < u.Calls[j].Rev })
	if !u.Reset {
		for id, at := range ix.gone {
			if at > rev {
				u.Removed = append(u.Removed, id)
			}
		}
		sort.Strings(u.Removed)
	}
	return u
}

// Get opens one call. It follows a merge, so an ID a browser selected before
// the call's second leg arrived still lands on the call.
func (ix *Index) Get(id string, lookup Lookup) (*Detail, bool) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	call := ix.c.Call(id)
	if call == nil {
		return nil, false
	}
	d := &Detail{Summary: ix.summarize(call), Legs: call.Legs}
	d.Records = refsOf(call)
	if lookup != nil {
		d.Ladder = correlate.BuildLadder(call, func(ref uint64) *parse.Record { return lookup(ref) })
	}
	return d, true
}

// Refs returns every record reference of one call, in order. It is what the
// log table filters on: show me only this call.
func (ix *Index) Refs(id string) ([]uint64, bool) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	call := ix.c.Call(id)
	if call == nil {
		return nil, false
	}
	return refsOf(call), true
}

func (ix *Index) Stats() Stats {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	all := ix.c.Calls()
	active := 0
	for _, call := range all {
		if call.State != correlate.StateEnded && !call.Keepalive {
			active++
		}
	}
	return Stats{
		Calls: len(all), Active: active, Total: ix.total,
		Evicted: ix.c.Evicted(), Max: ix.c.MaxCalls, Rev: ix.rev,
	}
}

// refsOf collects a call's record references in ascending order. Legs
// interleave, so concatenating them would hand the browser the outbound leg's
// records after the inbound leg's rather than in the order they happened.
func refsOf(call *correlate.Call) []uint64 {
	n := 0
	for _, l := range call.Legs {
		n += len(l.Records)
	}
	refs := make([]uint64, 0, n)
	for _, l := range call.Legs {
		refs = append(refs, l.Records...)
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i] < refs[j] })
	return refs
}

func (ix *Index) summarize(call *correlate.Call) Summary {
	s := Summary{
		ID: call.ID, Rev: ix.revs[call.ID], GUID: call.GUID,
		Start: call.Start, End: call.End,
		DurationMs: call.Duration().Milliseconds(),
		Calling:    call.Calling, Called: call.Called,
		State: call.State, Result: call.Result, Cause: call.Cause, IEC: call.IEC,
		Keepalive: call.Keepalive, Legs: len(call.Legs),
		Warnings: call.Warnings,
	}
	seen := map[string]bool{}
	for _, l := range call.Legs {
		s.Records += len(l.Records)
		if l.FinalStatus >= 400 {
			s.Failed = true
		}
		if l.Source != "" && !seen[l.Source] {
			seen[l.Source] = true
			s.Sources = append(s.Sources, l.Source)
		}
	}
	if call.IEC != "" {
		s.Failed = true
	}
	sort.Strings(s.Sources)
	return s
}

// Text renders one call as plain text: a header an engineer can read, then
// every record of the call verbatim, in order.
//
// raw returns a record's lines as the router printed them, or nil for a record
// the store no longer has. Those are not skipped silently — a transcript with
// holes in it says where the holes are, because somebody will paste this into a
// ticket and draw conclusions from it.
func Text(d *Detail, raw func(ref uint64) []string) string {
	var b strings.Builder
	if d == nil {
		return ""
	}
	w := func(s string) { b.WriteString(s); b.WriteByte('\n') }

	w("call:      " + d.ID)
	if d.GUID != "" {
		w("guid:      " + d.GUID)
	}
	w("from:      " + dash(d.Calling))
	w("to:        " + dash(d.Called))
	w("start:     " + d.Start.Format("2006-01-02 15:04:05.000"))
	w("duration:  " + (time.Duration(d.DurationMs) * time.Millisecond).String())
	w("state:     " + d.State)
	if d.Result != "" {
		w("result:    " + strings.TrimSpace(d.Result+" "+d.Cause))
	}
	if d.IEC != "" {
		w("IEC:       " + d.IEC)
	}
	for _, l := range d.Legs {
		w("leg:       " + l.ID + "  call entry " + legEntry(l) + "  " +
			dash(l.Direction) + "  " + l.State + "  " + dash(strings.Join(l.SIPCallIDs, ", ")))
	}
	for _, warn := range d.Warnings {
		w("warning:   " + warn)
	}
	if d.Ladder != nil && d.Ladder.Missing > 0 {
		w("note:      " + strconv.Itoa(d.Ladder.Missing) +
			" record(s) of this call are no longer held; the buffer overwrote them")
	}
	w("")

	missing := 0
	for _, ref := range d.Records {
		lines := raw(ref)
		if len(lines) == 0 {
			missing++
			continue
		}
		if missing > 0 {
			w("--- " + strconv.Itoa(missing) + " record(s) no longer held ---")
			missing = 0
		}
		for _, l := range lines {
			w(l)
		}
		w("")
	}
	if missing > 0 {
		w("--- " + strconv.Itoa(missing) + " record(s) no longer held ---")
	}
	return b.String()
}

func legEntry(l *correlate.Leg) string {
	if l.CallEntryID == parse.NoCallID {
		return "unknown"
	}
	return strconv.FormatInt(l.CallEntryID, 10)
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
