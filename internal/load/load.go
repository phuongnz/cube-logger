// Package load reads a saved log file into the same records the live path
// produces.
//
// It is the file half of the tool: internal/ingest says what wrote the file,
// internal/parse turns the IOS lines into records, and this package holds the
// two together and adds the little the wire knew that a file does not say
// outright — a severity, a device, and which lines belonged to which record.
//
// One file can hold more than one device. A syslog server writes every router
// that points at it into the same file, so a source here is a device, not a
// file: each gets its own parser, because sequence numbers are per device and
// differencing across two of them invents losses that never happened.
package load

import (
	"bufio"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/phuongnz/cube-logger/internal/ingest"
	"github.com/phuongnz/cube-logger/internal/live"
	"github.com/phuongnz/cube-logger/internal/parse"
	"github.com/phuongnz/cube-logger/internal/wire"
)

// maxLine is the longest line accepted. SIP lines are short, but a file can
// hold anything and a scanner that stops at 64k would truncate a capture in
// silence.
const maxLine = 4 * 1024 * 1024

// Options are the things a file cannot say for itself.
type Options struct {
	// Year is the calendar year the first record belongs to; 0 means this
	// year. IOS prints no year.
	Year int
	// Source names the device when the file does not: a terminal capture
	// carries no hostname. The file's own name is the usual answer.
	Source string
	// Rename replaces the device name the file gave, for a file full of bare
	// addresses. It may be nil.
	Rename func(string) string
}

// Result is one pass over one file.
type Result struct {
	// Records are in the order the file completed them.
	Records []*live.Record
	// Sources is one entry per device found, sorted by name.
	Sources []live.SourceStat
	// Format is what the file turned out to be.
	Format ingest.Format `json:"format"`
	// Lines is every line read, banner and all.
	Lines int
	// Banner is the "show logging" preamble, kept because it says what the
	// device was configured to log — which is the first thing to check when
	// the debug output an engineer expected is not in the file.
	Banner []string
	// Orphans are lines that belonged to no record: what a wrapped buffer
	// starts with.
	Orphans []string
	// Notes are things worth telling the engineer about the file itself.
	Notes []string
}

// File reads rd to the end.
func File(rd io.Reader, opt Options) (*Result, error) {
	in := ingest.New()
	in.Year = opt.Year
	l := &loader{opt: opt, in: in, srcs: map[string]*device{}}

	sc := bufio.NewScanner(rd)
	sc.Buffer(make([]byte, 0, 64*1024), maxLine)
	for sc.Scan() {
		l.line(sc.Text())
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return l.finish(), nil
}

type loader struct {
	opt     Options
	in      *ingest.Reader
	srcs    map[string]*device
	order   []*device
	records []*live.Record
	lines   int
	synth   int
}

func (l *loader) line(s string) {
	l.lines++
	il := l.in.Line(s)
	if il.Banner {
		return
	}
	if il.Synthesized {
		l.synth++
	}
	d := l.device(il.Host)
	if r := d.line(il); r != nil {
		l.records = append(l.records, r)
	}
}

// device returns the per-device state, naming a device the file did not name.
func (l *loader) device(host string) *device {
	name := host
	if name == "" {
		name = l.in.Host() // a hostname the prompt gave up later in the file
	}
	if name == "" {
		name = l.opt.Source
	}
	if name == "" {
		name = "file"
	}
	if l.opt.Rename != nil {
		name = l.opt.Rename(name)
	}
	if d, ok := l.srcs[name]; ok {
		return d
	}
	d := newDevice(name, l.opt.Year)
	l.srcs[name] = d
	l.order = append(l.order, d)
	return d
}

func (l *loader) finish() *Result {
	res := &Result{
		Format: l.in.Format(),
		Lines:  l.lines,
		Banner: l.in.Banner(),
	}
	// A device the file named only by its prompt was called something else
	// until the prompt appeared. Nothing to undo: the prompt comes first in
	// "show logging" output.
	for _, d := range l.order {
		if r := d.flush(); r != nil {
			l.records = append(l.records, r)
		}
		res.Orphans = append(res.Orphans, d.p.Orphans()...)
		res.Sources = append(res.Sources, d.stat)
	}
	sort.Slice(res.Sources, func(i, j int) bool { return res.Sources[i].Source < res.Sources[j].Source })
	res.Records = l.records

	if len(res.Records) == 0 && res.Lines > 0 {
		res.Notes = append(res.Notes, "no records: nothing in this file carries an IOS timestamp. "+
			"The device needs \"service timestamps log datetime msec\" before its output can be framed.")
	}
	if l.synth > 0 {
		res.Notes = append(res.Notes, plural(l.synth, "line")+
			" had no IOS timestamp, so the receiving server's clock was used instead. "+
			"Set \"service timestamps log datetime msec\" on the device for its own clock.")
	}
	if n := countLogsWithoutDebug(res.Records); n {
		res.Notes = append(res.Notes, "log lines but no debug lines — the device probably has "+
			"\"logging trap informational\" set. Debug output is severity 7 and never leaves the box.")
	}
	if len(res.Sources) > 1 {
		res.Notes = append(res.Notes, plural(len(res.Sources), "device")+" in one file; "+
			"each is counted separately, since sequence numbers are per device.")
	}
	return res
}

func plural(n int, unit string) string {
	s := ""
	if n != 1 {
		s = "s"
	}
	return itoa(n) + " " + unit + s
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func countLogsWithoutDebug(recs []*live.Record) bool {
	logs, debugs := 0, 0
	for _, r := range recs {
		switch r.Kind {
		case parse.KindLog:
			logs++
		case parse.KindDebug:
			debugs++
		}
	}
	return logs > 0 && debugs == 0
}

// device is one CUBE's state: its parser, the wire facts of the record being
// built, and its running totals.
type device struct {
	p    *parse.Parser
	stat live.SourceStat
	cur  accum
}

// accum is what the framing knew about the record still being built.
type accum struct {
	severity int
	facility int
	received time.Time
	hasRecv  bool
	first    uint64
	last     uint64
	hasSeq   bool
	lines    int
	started  bool
}

func newDevice(name string, year int) *device {
	return &device{
		p:    parse.NewParser(name, year),
		stat: live.SourceStat{Source: name},
		cur:  accum{severity: -1},
	}
}

// line feeds one peeled line and returns the record it completed, if any.
func (d *device) line(l ingest.Line) *live.Record {
	_, _, head := parse.SplitFrame(l.Text)
	done := d.p.Line(l.Text)
	var out *live.Record
	if done != nil {
		out = d.finish(done)
	}
	if head || d.cur.started {
		d.accumulate(l, head)
	}
	d.stat.Lines++
	if l.HasTime {
		if d.stat.First.IsZero() {
			d.stat.First = l.Time
		}
		d.stat.Last = l.Time
	}
	return out
}

func (d *device) accumulate(l ingest.Line, head bool) {
	if head && !d.cur.started {
		d.cur.started = true
		d.cur.severity, d.cur.facility = l.Severity, l.Facility
		if l.HasTime {
			d.cur.received, d.cur.hasRecv = l.Time, true
		}
	}
	// A file's lines carry no outer, per-line counter — that only exists on
	// the wire — so the sequence number here is the record's own, and first
	// and last are the same number.
	if m := frameSeq(l.Text); m > 0 {
		if !d.cur.hasSeq {
			d.cur.first, d.cur.hasSeq = m, true
		}
		d.cur.last = m
	}
	d.cur.lines++
}

// frameSeq reads the sequence number out of an IOS frame, or 0 if there is
// none. It is only ever called on a line the parser also framed.
func frameSeq(s string) uint64 {
	f, _, ok := parse.SplitFrame(s)
	if !ok {
		return 0
	}
	i := strings.IndexByte(f, ':')
	if i <= 0 {
		return 0
	}
	var n uint64
	for _, c := range f[:i] {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + uint64(c-'0')
	}
	return n
}

func (d *device) finish(pr *parse.Record) *live.Record {
	a := d.cur
	d.cur = accum{severity: -1}
	d.stat.Records++

	for _, g := range d.p.TakeGaps() {
		if g.Kind == parse.GapLoss {
			d.stat.LostRecords += g.Missing
		}
	}

	sev := a.severity
	if sev < 0 {
		// A file rarely carries a priority. The severity of a log line is in
		// its own tag; everything else is debug output, which is severity 7 —
		// and saying so matters, because severity 7 is exactly what "logging
		// trap informational" keeps off the wire.
		sev = 7
		if pr.Log != nil {
			sev = pr.Log.Severity
		}
	}
	r := &live.Record{
		Record:       pr,
		Severity:     sev,
		Facility:     a.facility,
		SeverityName: wire.SeverityName(sev),
		Received:     a.received,
		FirstLineSeq: a.first,
		LastLineSeq:  a.last,
		HasLineSeq:   a.hasSeq,
		Lines:        max(a.lines, 1),
		RawLines:     pr.Raw,
	}
	if !a.hasRecv {
		// Nothing received this: it came off a disk. The device's own clock is
		// the only time there is, and it is the honest one to show.
		r.Received = pr.Time
	}
	if pr.SIP != nil && pr.SIP.Truncated {
		r.Incomplete = true
	}
	r.Call = live.LegKey(pr)
	return r
}

func (d *device) flush() *live.Record {
	if pr := d.p.Flush(); pr != nil {
		return d.finish(pr)
	}
	return nil
}
