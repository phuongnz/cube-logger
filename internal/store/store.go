// Package store holds the records of one session in memory and fans them out
// to whoever is watching.
//
// It is a ring: the newest N records, and the oldest quietly overwritten. This
// is a troubleshooting tool, not a SIEM — an engineer reproduces a call, looks
// at it, and moves on — so nothing is written to disk and nothing is searched
// across days. The plan's open decision 3 keeps SQLite in reserve for the day
// a session outgrows this, and until then a ring is the whole design.
//
// Every record gets a monotonic ID. That is what makes the browser's life
// simple: it remembers the last ID it drew, and after a hiccup it asks for
// everything since, instead of trying to reconcile two streams.
//
// IDs start at 1 in every store, and a restart is a new store, so an ID alone
// does not say which store it came from. Each store has a random epoch for
// that: an ID means something only next to the epoch it was given under.
package store

import (
	"crypto/rand"
	"strings"
	"sync"

	"github.com/phuongnz/cube-logger/internal/live"
)

// DefaultCap is how many records a session keeps.
//
// The plan sizes the ring in lines — the last million or so. Records are the
// unit here, and a SIP message is about nineteen lines, so a hundred thousand
// records is that order of magnitude for debug-heavy traffic and far more for
// plain log lines. It is also small enough that the process stays in a few
// hundred megabytes, which matters on the laptop this runs on.
const DefaultCap = 100000

// Entry is a stored record with the ID the store gave it.
//
// The embedded pointer is flattened by encoding/json, so the browser sees one
// object with an id on it and not a wrapper.
type Entry struct {
	ID uint64 `json:"id"`
	*live.Record
}

// Stats describe the ring itself, not the log in it.
type Stats struct {
	// Records is how many are held now, Total how many have ever been stored.
	Records int    `json:"records"`
	Total   uint64 `json:"total"`
	Cap     int    `json:"cap"`
	// Lines is how many datagram lines went into the records held now.
	Lines uint64 `json:"lines"`
	// Evicted is how many records the ring has overwritten. A non-zero value
	// is normal and means the session is older than the ring is deep; it is
	// not loss on the wire and must never be shown as if it were.
	Evicted uint64 `json:"evicted"`
	// Oldest and Newest bound the IDs currently held.
	Oldest uint64 `json:"oldest"`
	Newest uint64 `json:"newest"`
	// Watchers is how many browsers are subscribed.
	Watchers int `json:"watchers"`
	// Epoch names this store. It changes when the process restarts and not
	// when the ring is cleared.
	Epoch string `json:"epoch"`
}

// Store is the session's records. It is safe for concurrent use.
type Store struct {
	mu   sync.RWMutex
	cap  int
	buf  []Entry
	head int // index of the oldest entry
	n    int
	next uint64 // ID of the next record stored

	epoch string

	total, evicted, lines uint64

	subs   map[uint64]*Sub
	nextID uint64
}

// New returns a store holding at most capacity records. Zero means DefaultCap.
func New(capacity int) *Store {
	if capacity <= 0 {
		capacity = DefaultCap
	}
	return &Store{
		cap:   capacity,
		buf:   make([]Entry, capacity),
		next:  1,
		epoch: rand.Text(),
		subs:  map[uint64]*Sub{},
	}
}

// Add stores records and delivers them to every watcher. It returns the
// entries it created, in order.
//
// It never blocks on a watcher. A browser that cannot keep up loses its place
// in the stream and resynchronises from the ring by ID; it does not get to
// slow down the socket that is reading from the router.
func (s *Store) Add(recs ...*live.Record) []Entry {
	if len(recs) == 0 {
		return nil
	}
	s.mu.Lock()
	added := make([]Entry, 0, len(recs))
	for _, r := range recs {
		if r == nil {
			continue
		}
		e := Entry{ID: s.next, Record: r}
		s.next++
		s.total++
		s.lines += uint64(r.Lines)
		if s.n == s.cap {
			s.buf[s.head] = Entry{}
			s.head = (s.head + 1) % s.cap
			s.n--
			s.evicted++
		}
		s.buf[(s.head+s.n)%s.cap] = e
		s.n++
		added = append(added, e)
	}
	subs := make([]*Sub, 0, len(s.subs))
	for _, sub := range s.subs {
		subs = append(subs, sub)
	}
	s.mu.Unlock()

	for _, sub := range subs {
		sub.deliver(added)
	}
	return added
}

// Stats describes the ring.
func (s *Store) Stats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st := Stats{
		Records:  s.n,
		Total:    s.total,
		Cap:      s.cap,
		Lines:    s.lines,
		Evicted:  s.evicted,
		Watchers: len(s.subs),
		Epoch:    s.epoch,
	}
	if s.n > 0 {
		st.Oldest = s.buf[s.head].ID
		st.Newest = s.buf[(s.head+s.n-1)%s.cap].ID
	}
	return st
}

// Recent returns the newest n entries, oldest first. n <= 0 means everything
// held.
func (s *Store) Recent(n int) []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if n <= 0 || n > s.n {
		n = s.n
	}
	out := make([]Entry, n)
	for i := 0; i < n; i++ {
		out[i] = s.buf[(s.head+s.n-n+i)%s.cap]
	}
	return out
}

// Since returns up to max entries with an ID greater than after, oldest first,
// together with how many were missed because the ring had already overwritten
// them.
//
// A watcher that fell behind calls this with the last ID it drew. A non-zero
// missed count is the honest answer to "what happened while I was away": those
// records existed and are gone, which is a different thing from a gap on the
// wire and is reported differently.
func (s *Store) Since(after uint64, max int) (entries []Entry, missed uint64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.n == 0 {
		return nil, 0
	}
	oldest := s.buf[s.head].ID
	if after+1 < oldest {
		missed = oldest - after - 1
	}
	// IDs are dense and ascending, so the offset is arithmetic, not a search.
	start := 0
	if after >= oldest {
		start = int(after - oldest + 1)
	}
	if start >= s.n {
		return nil, missed
	}
	count := s.n - start
	if max > 0 && count > max {
		// Keep the newest: a watcher catching up wants the live edge, and the
		// records it skips it can still ask for.
		missed += uint64(count - max)
		start += count - max
		count = max
	}
	out := make([]Entry, count)
	for i := 0; i < count; i++ {
		out[i] = s.buf[(s.head+start+i)%s.cap]
	}
	return out, missed
}

// Clear empties the ring. IDs keep ascending and the epoch stays, so a
// watcher can tell a clear from a restart.
func (s *Store) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buf = make([]Entry, s.cap)
	s.head, s.n = 0, 0
	s.lines = 0
}

// Sub is one watcher's queue.
type Sub struct {
	// C carries batches of entries, oldest first. It is closed when the
	// subscription ends.
	C chan []Entry

	store *Store
	id    uint64

	mu     sync.Mutex
	closed bool
	// behind is set when a batch could not be queued. The reader clears it by
	// resynchronising from the ring, which is cheaper and more honest than
	// blocking the writer.
	behind bool
}

// Subscribe returns a queue of new entries. queue is how many batches may
// wait; zero picks a sensible default.
func (s *Store) Subscribe(queue int) *Sub {
	if queue <= 0 {
		queue = 256
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	sub := &Sub{C: make(chan []Entry, queue), store: s, id: s.nextID}
	s.subs[sub.id] = sub
	return sub
}

// Close ends the subscription and closes C.
func (sub *Sub) Close() {
	sub.store.mu.Lock()
	delete(sub.store.subs, sub.id)
	sub.store.mu.Unlock()

	sub.mu.Lock()
	defer sub.mu.Unlock()
	if !sub.closed {
		sub.closed = true
		close(sub.C)
	}
}

// Behind reports and clears the flag saying a batch was dropped, so the reader
// knows to resynchronise by ID.
func (sub *Sub) Behind() bool {
	sub.mu.Lock()
	defer sub.mu.Unlock()
	b := sub.behind
	sub.behind = false
	return b
}

func (sub *Sub) deliver(batch []Entry) {
	sub.mu.Lock()
	defer sub.mu.Unlock()
	if sub.closed {
		return
	}
	select {
	case sub.C <- batch:
	default:
		sub.behind = true
	}
}

// Match is a filter over stored records: the text and severity filters the log
// table offers. The zero Match accepts everything.
//
// It lives here rather than in the browser because the browser is handed a
// bounded backfill, and filtering a hundred thousand records to find the
// twenty that mention a number is work the server should do once.
type Match struct {
	// Text is matched case-insensitively against the record's whole text,
	// its source and its call. Empty matches everything.
	Text string
	// MinSeverity keeps records at this severity or more urgent (a *lower*
	// syslog number). -1 means no severity filter.
	MinSeverity int
	// Kinds, when non-empty, keeps only these record kinds.
	Kinds []string
	// Source, when non-empty, keeps only this device.
	Source string
	// Call, when non-empty, keeps only this leg.
	Call string
	// IncompleteOnly keeps only records that are missing lines.
	IncompleteOnly bool
}

// Accepts reports whether an entry passes the filter.
func (m *Match) Accepts(e Entry) bool {
	if m == nil || e.Record == nil {
		return true
	}
	if m.Source != "" && e.Record.Record.Source != m.Source {
		return false
	}
	if m.Call != "" && e.Call != m.Call {
		return false
	}
	if m.IncompleteOnly && !e.Incomplete {
		return false
	}
	// Severity -1 means the datagram carried no <PRI>. Such a record has no
	// severity to compare, so a severity filter must not silently hide it.
	if m.MinSeverity >= 0 && e.Severity >= 0 && e.Severity > m.MinSeverity {
		return false
	}
	if len(m.Kinds) > 0 {
		ok := false
		for _, k := range m.Kinds {
			if string(e.Kind) == k {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if m.Text != "" && !containsFold(e, m.Text) {
		return false
	}
	return true
}

// containsFold searches the whole record, not just its first line: an engineer
// looking for a phone number will find it in an SDP body or a To header, not
// in the debug header.
func containsFold(e Entry, needle string) bool {
	if strings.Contains(strings.ToLower(e.Record.Record.Source), strings.ToLower(needle)) ||
		strings.Contains(strings.ToLower(e.Call), strings.ToLower(needle)) {
		return true
	}
	for _, l := range e.Raw {
		if strings.Contains(strings.ToLower(l), strings.ToLower(needle)) {
			return true
		}
	}
	return false
}

// Search walks the ring newest-first and returns up to max matches, oldest
// first.
func (s *Store) Search(m *Match, max int) []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if max <= 0 {
		max = s.n
	}
	out := make([]Entry, 0, min(max, s.n))
	for i := s.n - 1; i >= 0 && len(out) < max; i-- {
		e := s.buf[(s.head+i)%s.cap]
		if m.Accepts(e) {
			out = append(out, e)
		}
	}
	// Collected newest-first; hand it back in reading order.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// Get returns one entry by ID. The second result is false for a record the
// ring has already overwritten, or one that was never stored.
//
// IDs are dense and ascending, so this is arithmetic rather than a search:
// looking up the twenty records of a call is twenty index calculations, not
// twenty walks of a hundred thousand entries.
func (s *Store) Get(id uint64) (Entry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.n == 0 {
		return Entry{}, false
	}
	oldest := s.buf[s.head].ID
	if id < oldest || id >= oldest+uint64(s.n) {
		return Entry{}, false
	}
	return s.buf[(s.head+int(id-oldest))%s.cap], true
}
