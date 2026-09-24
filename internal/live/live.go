// Package live reassembles UDP syslog datagrams into records.
//
// It does no I/O. Datagrams in — each one a source address, a payload and an
// arrival time — records out. The listener supplies real datagrams and a test
// supplies invented ones, and neither can tell the difference.
//
// # Why this package exists
//
// On the UDP path one datagram is one *line*, never a message: the capture
// behind docs/log-format.md § The UDP path carried 66 records in 1,288
// datagrams, about nineteen per SIP message, and not one datagram contained a
// newline. A receiver that treats a datagram as a record shows nineteen
// meaningless fragments per message. Rejoining them is the whole job.
//
// # What it guarantees
//
//   - Lines are ordered by the outer counter, not by arrival. UDP may reorder
//     even though the capture did not. The one exception is a line numbered
//     below the first one this process ever saw from that source: it is
//     counted as Late, because putting it back would mean inserting it before
//     output the user has already read.
//   - A record runs from one head line to the next, so lines are attributed by
//     the head that precedes them *in sequence order*. Records were emitted
//     atomically in the capture, but that was one call at low load (open
//     question 1), and this rule is correct either way.
//   - An empty datagram is content, not noise: it is the blank line between a
//     SIP message's headers and its body.
//   - A record that is missing lines is marked Incomplete and says how many.
//     It is never shown silently as whole.
//
// # Two counters
//
// The counter after <PRI> advances per line; the one inside the IOS frame
// advances per record. A gap in the first counts lost lines, a gap in the
// second counts lost records. Both are tracked per source address, because
// sequence numbers are per device and differencing across devices is
// meaningless — on the terminal capture it produced 974 million phantom losses.
package live

import (
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/phuongnz/cube-logger/internal/parse"
	"github.com/phuongnz/cube-logger/internal/wire"
)

// Defaults. They are fields on Reassembler so a test can make time explicit.
const (
	// DefaultReorderWindow is how long a line waits for a lower-numbered line
	// that has not arrived. It buys tolerance of reordering at the cost of
	// latency on a real loss, and on a LAN path reordering is measured in
	// milliseconds.
	DefaultReorderWindow = 250 * time.Millisecond

	// DefaultReorderDepth caps how many out-of-order lines are held while
	// waiting. A SIP message is about nineteen lines, so a hole that already
	// has this many lines stacked behind it is loss, not reordering.
	DefaultReorderDepth = 64

	// DefaultIdleTimeout is how long the last record of a burst waits for a
	// successor before it is shown. A record is only known to be complete when
	// the next one starts, so without this the newest record on an idle device
	// would never appear — which on a quiet CUBE is most of them.
	DefaultIdleTimeout = 750 * time.Millisecond

	// maxPlausibleGap is where "lines were lost" stops being the best
	// explanation and "this is a different numbering space" takes over: the
	// device reloaded, or something else is sending to this port from the same
	// address. Above it the stream is restarted rather than reporting a loss of
	// millions.
	maxPlausibleGap = 100000
)

// Datagram is one received UDP datagram.
type Datagram struct {
	// Source is the datagram's source address, and it is the only device
	// identity there is: the frame carries no hostname.
	Source  string
	Payload string
	// Time is when it arrived. A continuation line has no clock of its own, so
	// for those this is the only time there is.
	Time time.Time
}

// Record is a reassembled record together with what only the wire knew.
//
// The embedded *parse.Record is the same type the file path produces, so every
// view downstream — the table, the correlator, the ladder — is written once.
type Record struct {
	*parse.Record

	// Severity and Facility come from the head line's <PRI>. Severity is -1
	// when the datagram carried none. A continuation line inherits the
	// severity of the record it belongs to, so only the head's is kept.
	Severity int `json:"severity"`
	Facility int `json:"facility,omitempty"`
	// SeverityName is the word for Severity, so the browser does not have to
	// carry the table.
	SeverityName string `json:"severityName,omitempty"`

	// Received is when the record's head line arrived. It is wall-clock time on
	// this machine, unlike Time, which is the device's own clock.
	Received time.Time `json:"received"`

	// FirstLineSeq and LastLineSeq bound the record in the outer, per-line
	// counter. Lines is how many datagrams were actually joined into it.
	FirstLineSeq uint64 `json:"firstLineSeq,omitempty"`
	LastLineSeq  uint64 `json:"lastLineSeq,omitempty"`
	HasLineSeq   bool   `json:"hasLineSeq,omitempty"`
	Lines        int    `json:"lines"`

	// MissingLines is how many lines of this record never arrived.
	MissingLines uint64 `json:"missingLines,omitempty"`
	// Incomplete is set when lines are missing or the body is shorter than its
	// Content-Length. A record is shown as incomplete or as whole, never
	// silently as whole when it is not.
	Incomplete bool `json:"incomplete,omitempty"`

	// RawLines is every line of the record verbatim. parse.Record.Raw is kept
	// out of JSON because the golden files would double in size, but the
	// browser has nothing else to show in a detail pane: the whole point of
	// the tool is reading what the router actually said. Same backing slice,
	// not a copy.
	RawLines []string `json:"raw,omitempty"`

	// Call is this record's own leg identity, for the table's call column and
	// its filter: the IOS call entry ID when the record carries one, else the
	// debug GUID, else the SIP Call-ID.
	//
	// It identifies a *leg*, not a call. CUBE is a back-to-back user agent, so
	// a call is normally two legs, and joining them needs the correlator and a
	// GUID time window. That is the call-centric view, and it is a later phase.
	Call string `json:"call,omitempty"`
}

// SourceStat is one device's running totals, for the UI's status panel.
type SourceStat struct {
	Source  string    `json:"source"`
	First   time.Time `json:"first"`
	Last    time.Time `json:"last"`
	Lines   uint64    `json:"lines"`
	Records uint64    `json:"records"`
	// LostLines and LostRecords are counted on the two different counters and
	// mean different things: lines lost inside messages, and whole messages
	// lost. Both are "lost or rate-limited" until open question 2 is settled.
	LostLines   uint64 `json:"lostLines"`
	LostRecords uint64 `json:"lostRecords"`
	// Reordered is how many lines arrived before the line in front of them and
	// were put back once it turned up. Lines released because that line never
	// turned up are loss, not reordering, and are not counted here.
	Reordered uint64 `json:"reordered"`
	// Late is lines that arrived after their hole had already been given up on,
	// and Duplicate is lines whose number had already been used. Both are
	// dropped; a rising count means ReorderWindow is too short.
	Late      uint64 `json:"late"`
	Duplicate uint64 `json:"duplicate"`
	// Orphans are bare continuation lines with no record to attach to: the
	// first datagrams after the listener starts, mid-message.
	Orphans uint64 `json:"orphans"`
	// Restarts is how many times the counter jumped so far that the stream was
	// treated as a new numbering space — normally a device reload.
	Restarts uint64 `json:"restarts"`
	// Held is how many lines are waiting for a hole to fill right now.
	Held int `json:"held"`
	// NoSeq counts datagrams with no outer counter at all, which means the
	// device has no "service sequence-numbers" and loss cannot be detected.
	NoSeq uint64 `json:"noSeq"`
}

// Reassembler turns datagrams from any number of devices into records.
// It is safe for concurrent use: the listener calls Datagram while a ticker
// calls Tick.
type Reassembler struct {
	// ReorderWindow, ReorderDepth and IdleTimeout default to the constants
	// above when zero. Year is the calendar year the first record belongs to,
	// since IOS logs no year; 0 means the current year.
	ReorderWindow time.Duration
	ReorderDepth  int
	IdleTimeout   time.Duration
	Year          int

	mu      sync.Mutex
	streams map[string]*stream
}

// New returns a Reassembler with the default timings.
func New() *Reassembler { return &Reassembler{} }

func (r *Reassembler) reorderWindow() time.Duration {
	if r.ReorderWindow <= 0 {
		return DefaultReorderWindow
	}
	return r.ReorderWindow
}

func (r *Reassembler) reorderDepth() int {
	if r.ReorderDepth <= 0 {
		return DefaultReorderDepth
	}
	return r.ReorderDepth
}

func (r *Reassembler) idleTimeout() time.Duration {
	if r.IdleTimeout <= 0 {
		return DefaultIdleTimeout
	}
	return r.IdleTimeout
}

// Datagram feeds one datagram and returns whatever records it completed.
// Most datagrams complete nothing: a SIP message takes about nineteen.
func (r *Reassembler) Datagram(d Datagram) []*Record {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stream(d.Source).datagram(d.Payload, d.Time)
}

// Tick advances every source's clock: it gives up on holes that have waited
// past the reorder window, and releases a record that has been idle long
// enough to be the last of its burst. Call it a few times a second.
func (r *Reassembler) Tick(now time.Time) []*Record {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*Record
	for _, s := range r.sortedStreams() {
		out = append(out, s.expire(now, true)...)
		out = append(out, s.idle(now)...)
	}
	return out
}

// Flush releases everything still held, at end of input. The records it
// returns may be incomplete, and say so.
func (r *Reassembler) Flush() []*Record {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*Record
	for _, s := range r.sortedStreams() {
		out = append(out, s.flush()...)
	}
	return out
}

// Stats returns one entry per source, ordered by address.
func (r *Reassembler) Stats() []SourceStat {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]SourceStat, 0, len(r.streams))
	for _, s := range r.sortedStreams() {
		st := s.stat
		st.Held = len(s.pending)
		out = append(out, st)
	}
	return out
}

func (r *Reassembler) sortedStreams() []*stream {
	names := make([]string, 0, len(r.streams))
	for k := range r.streams {
		names = append(names, k)
	}
	sort.Strings(names)
	out := make([]*stream, len(names))
	for i, n := range names {
		out[i] = r.streams[n]
	}
	return out
}

func (r *Reassembler) stream(source string) *stream {
	if r.streams == nil {
		r.streams = map[string]*stream{}
	}
	s := r.streams[source]
	if s == nil {
		s = newStream(source, r)
		r.streams[source] = s
	}
	return s
}

// held is one line waiting for a lower-numbered line to arrive.
type held struct {
	frame wire.Frame
	at    time.Time
}

// accum is the record currently being assembled: what the parser is holding
// plus the wire facts the parser never sees.
type accum struct {
	open         bool
	severity     int
	facility     int
	first, last  uint64
	hasSeq       bool
	lines        int
	missing      uint64
	received     time.Time
	lastArrival  time.Time
	sawIdleFlush bool
}

// stream is one source address's reassembly state. Everything in it is
// per-device on purpose: § Two devices in one file.
type stream struct {
	r      *Reassembler
	parser *parse.Parser

	next    uint64
	have    bool
	pending map[uint64]held
	// oldest is when the earliest line now held began waiting, which is what
	// the reorder window is measured against.
	oldest time.Time

	cur  accum
	stat SourceStat
}

func newStream(source string, r *Reassembler) *stream {
	// The outer counter needs no SeqTracker: a gap in it is handled here and
	// then, because holding lines for a window that might still fill it is a
	// decision a tracker cannot make. The parser keeps the inner one.
	return &stream{
		r:       r,
		parser:  parse.NewParser(source, r.Year),
		pending: map[uint64]held{},
		stat:    SourceStat{Source: source},
	}
}

func (s *stream) datagram(payload string, now time.Time) []*Record {
	f := wire.Decode(payload)
	s.stat.Lines++
	if s.stat.First.IsZero() {
		s.stat.First = now
	}
	s.stat.Last = now

	// No "service sequence-numbers" on the device: there is no counter to order
	// by and no way to detect loss, so take the wire's word for the order.
	if !f.HasSeq {
		s.stat.NoSeq++
		return s.feed(f, now)
	}

	// The first line seen sets where this source's numbering starts. Lines
	// numbered below it are counted as Late and dropped: they would have to be
	// inserted before output the user has already been shown. The alternative —
	// holding every stream's opening line for a reorder window before showing
	// anything — costs latency on every source to rescue a case UDP does not
	// produce, since reordering displaces a datagram by a few positions and
	// never reverses a burst.
	if !s.have {
		s.next, s.have = f.Seq, true
	}

	switch {
	case f.Seq == s.next:
		out := s.feed(f, now)
		s.next++
		return append(out, s.drain(now, true)...)

	case f.Seq > s.next:
		if f.Seq-s.next > maxPlausibleGap {
			// Too far to be loss. A reload restarts the counter, and something
			// else sending from this address restarts it somewhere else
			// entirely; either way, reporting millions of lost lines would be a
			// lie. Start a new numbering space instead.
			return s.restart(f, now)
		}
		return s.hold(f, now)

	default: // f.Seq < s.next
		if s.next-f.Seq > maxPlausibleGap {
			return s.restart(f, now)
		}
		// Either a line we already have, or one that arrived after its hole was
		// given up on. Both are dropped: feeding it now would put it after
		// lines it belongs before, which is worse than losing it.
		s.stat.Late++
		return nil
	}
}

// hold parks an out-of-order line until the hole in front of it fills, the
// reorder window elapses, or too many lines stack up behind it.
func (s *stream) hold(f wire.Frame, now time.Time) []*Record {
	if _, dup := s.pending[f.Seq]; dup {
		s.stat.Duplicate++
		return nil
	}
	if len(s.pending) == 0 {
		s.oldest = now
	}
	s.pending[f.Seq] = held{frame: f, at: now}
	// Not counted as reordered yet. A line parked behind a hole is only known
	// to have arrived early once the hole fills; if it never does, the hole was
	// loss and this line was in order all along. drain counts it on release.
	// Holding too many lines behind one hole means the hole is loss, not
	// reordering, and waiting out the window would stall the display.
	return s.expire(now, false)
}

// lowestPending is the smallest sequence number now held. It is only called
// with a non-empty buffer.
func (s *stream) lowestPending() uint64 {
	first := true
	var lo uint64
	for k := range s.pending {
		if first || k < lo {
			lo, first = k, false
		}
	}
	return lo
}

// restart abandons the current numbering space. The record under construction
// is released first, because whatever follows belongs to a different stream of
// numbers and must not be joined to it.
func (s *stream) restart(f wire.Frame, now time.Time) []*Record {
	out := s.flush()
	s.stat.Restarts++
	s.pending = map[uint64]held{}
	s.next, s.have = f.Seq, true
	out = append(out, s.feed(f, now)...)
	s.next++
	return out
}

// drain feeds every held line that is now contiguous. holeFilled says why they
// are being released: true when the line in front of them arrived, which makes
// them genuinely early, and false when that line was given up on as loss, which
// leaves them in the order the device sent them.
func (s *stream) drain(now time.Time, holeFilled bool) []*Record {
	var out []*Record
	for {
		h, ok := s.pending[s.next]
		if !ok {
			break
		}
		delete(s.pending, s.next)
		if holeFilled {
			s.stat.Reordered++
		}
		out = append(out, s.feed(h.frame, h.at)...)
		s.next++
	}
	if len(s.pending) == 0 {
		s.oldest = time.Time{}
	}
	return out
}

// expire gives up on a hole whose lines are never coming. byTime is false on
// the arrival path, where only the depth limit applies, and true from Tick,
// where the reorder window has had a chance to elapse.
func (s *stream) expire(now time.Time, byTime bool) []*Record {
	var out []*Record
	for len(s.pending) > 0 {
		overDepth := len(s.pending) >= s.r.reorderDepth()
		overTime := byTime && !s.oldest.IsZero() && now.Sub(s.oldest) >= s.r.reorderWindow()
		if !overDepth && !overTime {
			break
		}
		lo := s.lowestPending()
		if lo <= s.next {
			// Defensive: drain should have taken it already.
			out = append(out, s.drain(now, true)...)
			continue
		}
		missing := lo - s.next
		s.stat.LostLines += missing
		s.cur.missing += missing
		s.next = lo
		out = append(out, s.drain(now, false)...)
		s.oldest = now
	}
	if len(s.pending) == 0 {
		s.oldest = time.Time{}
	}
	return out
}

// idle releases a record whose successor has not arrived in time. A record is
// only known to be complete when the next one starts, so on a quiet device the
// newest record would otherwise never be shown.
func (s *stream) idle(now time.Time) []*Record {
	if !s.cur.open || len(s.pending) > 0 {
		return nil
	}
	if now.Sub(s.cur.lastArrival) < s.r.idleTimeout() {
		return nil
	}
	return s.flushParser()
}

func (s *stream) flush() []*Record {
	if !s.have && len(s.pending) > 0 {
		s.next, s.have = s.lowestPending(), true
	}
	out := s.drain(time.Time{}, false)
	// Anything still held after a drain sits behind a hole that will never
	// fill. Release it in order rather than losing it.
	for len(s.pending) > 0 {
		lo := s.lowestPending()
		if lo > s.next {
			missing := lo - s.next
			s.stat.LostLines += missing
			s.cur.missing += missing
		}
		s.next = lo
		out = append(out, s.drain(time.Time{}, false)...)
	}
	return append(out, s.flushParser()...)
}

func (s *stream) flushParser() []*Record {
	rec := s.parser.Flush()
	if rec == nil {
		s.cur = accum{}
		return nil
	}
	return []*Record{s.finish(rec)}
}

// feed hands one line to the parser and folds the wire facts into the record
// being assembled.
func (s *stream) feed(f wire.Frame, at time.Time) []*Record {
	rec := s.parser.Line(f.Line)
	if o := s.parser.TakeOrphans(); len(o) > 0 {
		// A bare line with no record to attach to: the listener started in the
		// middle of a message, or a continuation arrived after an idle flush.
		s.stat.Orphans += uint64(len(o))
		return nil
	}
	var out []*Record
	if rec != nil {
		out = append(out, s.finish(rec))
	}
	s.accumulate(f, at)
	return out
}

// accumulate folds one line into the record under construction.
func (s *stream) accumulate(f wire.Frame, at time.Time) {
	if !s.cur.open {
		// The head line's severity is the record's: a continuation line repeats
		// it, and taking the head's is what makes the two agree.
		s.cur = accum{
			open:     true,
			severity: f.Severity,
			facility: f.Facility,
			received: at,
		}
		if f.HasSeq {
			s.cur.first, s.cur.hasSeq = f.Seq, true
		}
	}
	if f.HasSeq {
		s.cur.last = f.Seq
		if !s.cur.hasSeq {
			s.cur.first, s.cur.hasSeq = f.Seq, true
		}
	}
	s.cur.lines++
	s.cur.lastArrival = at
}

// finish turns a parsed record and the accumulated wire facts into a Record.
func (s *stream) finish(pr *parse.Record) *Record {
	a := s.cur
	s.cur = accum{}
	s.stat.Records++

	// The parser's own tracker watches the counter inside the IOS frame, which
	// counts records. Drain it so a long-running stream does not accumulate,
	// and total the losses it saw; the warning text is already on the record.
	for _, g := range s.parser.TakeGaps() {
		if g.Kind == parse.GapLoss {
			s.stat.LostRecords += g.Missing
		}
	}

	r := &Record{
		Record:       pr,
		Severity:     a.severity,
		Facility:     a.facility,
		SeverityName: wire.SeverityName(a.severity),
		Received:     a.received,
		FirstLineSeq: a.first,
		LastLineSeq:  a.last,
		HasLineSeq:   a.hasSeq,
		Lines:        a.lines,
		MissingLines: a.missing,
		RawLines:     pr.Raw,
	}
	if a.received.IsZero() {
		r.Received = a.lastArrival
	}
	if a.missing > 0 {
		r.Incomplete = true
		pr.Warnings = append(pr.Warnings, "record incomplete: "+
			strconv.FormatUint(a.missing, 10)+" line(s) lost or rate-limited")
	}
	// A body shorter than its Content-Length is the other way a record can be
	// missing lines, and it is the check that catches loss in the middle of a
	// message even when the counters look clean.
	if pr.SIP != nil && pr.SIP.Truncated {
		r.Incomplete = true
	}
	r.Call = legKey(pr)
	return r
}

// legKey picks the identifier that ties a record to a leg, most specific
// first. An inbound call's first INVITE has call entry ID -1, which is why the
// SIP Call-ID has to be a fallback and not an afterthought.
func legKey(r *parse.Record) string {
	if r.Cover != nil && r.Cover.CallID > 0 {
		return strconv.FormatInt(r.Cover.CallID, 10)
	}
	if r.Debug != nil && r.Debug.CallID != parse.NoCallID {
		return strconv.FormatInt(r.Debug.CallID, 10)
	}
	if r.Log != nil && r.Log.CallID != parse.NoCallID && r.Log.CallID != 0 {
		return strconv.FormatInt(r.Log.CallID, 10)
	}
	if r.SIP != nil && r.SIP.CallID != "" {
		return r.SIP.CallID
	}
	if r.Debug != nil && r.Debug.GUID != "" {
		return r.Debug.GUID
	}
	return ""
}
