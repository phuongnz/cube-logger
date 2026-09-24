// Package session writes and reads a saved session.
//
// A session file holds the *raw lines*, not the parsed records. That is the
// whole design decision: the parser will get better — every phase so far has
// found something in the format nobody knew about — and a session saved today
// has to be re-readable by that better parser, not frozen at today's
// understanding. So the file keeps what the router said, plus the few things
// only the wire knew and the text does not repeat: which device sent it, when
// it arrived here, and what syslog priority it came with.
//
// The format is JSON Lines, one object per line:
//
//	{"type":"session",...}   exactly one, first
//	{"type":"record",...}    one per record, in order
//	{"type":"end",...}       exactly one, last — absent if the file was cut off
//
// JSON Lines because a session is appended to as it grows and may be cut off
// by a laptop losing power: every line that was written is still readable, and
// a missing footer is a fact the reader reports rather than an error it dies
// of. Gzip is understood on reading, whatever the file is called.
package session

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/phuongnz/cube-logger/internal/live"
	"github.com/phuongnz/cube-logger/internal/parse"
	"github.com/phuongnz/cube-logger/internal/wire"
)

// Version is the format version. A reader refuses a version it does not know,
// rather than guessing at a file a later cube-logger wrote.
const Version = 1

// Ext is the conventional extension. Nothing depends on it: the reader sniffs.
const Ext = ".cubelog"

// maxLine bounds one JSON object. A record is a handful of short lines, so
// this is generous by a wide margin.
const maxLine = 8 * 1024 * 1024

// Header is the first line of a session file.
type Header struct {
	Type    string    `json:"type"`
	Tool    string    `json:"tool"`
	Version int       `json:"version"`
	Created time.Time `json:"created"`
	Title   string    `json:"title,omitempty"`
	// Year is the calendar year the records belong to. IOS prints no year, so
	// without this a session reopened in January would be read as this year's.
	Year int `json:"year,omitempty"`
	// Listen and Source describe where the records came from, for a human
	// opening a file a month later.
	Listen string `json:"listen,omitempty"`
	Source string `json:"source,omitempty"`
}

// Footer is the last line, and its absence means the file was cut off.
type Footer struct {
	Type    string            `json:"type"`
	Records uint64            `json:"records"`
	Sources []live.SourceStat `json:"sources,omitempty"`
	Closed  time.Time         `json:"closed"`
}

// entry is one record: the raw lines, and what the text does not repeat.
type entry struct {
	Type         string    `json:"type"`
	Source       string    `json:"source,omitempty"`
	Received     time.Time `json:"received,omitempty"`
	Severity     int       `json:"severity"`
	Facility     int       `json:"facility,omitempty"`
	FirstLineSeq uint64    `json:"firstLineSeq,omitempty"`
	LastLineSeq  uint64    `json:"lastLineSeq,omitempty"`
	HasLineSeq   bool      `json:"hasLineSeq,omitempty"`
	MissingLines uint64    `json:"missingLines,omitempty"`
	Lines        int       `json:"lines,omitempty"`
	Raw          []string  `json:"raw"`
}

// Writer writes a session file.
type Writer struct {
	w     *bufio.Writer
	gz    *gzip.Writer
	enc   *json.Encoder
	n     uint64
	year  int
	err   error
	ended bool
}

// Options are the writer's knobs.
type Options struct {
	// Gzip compresses the file. A long session is mostly SIP headers, which
	// compress to about a tenth.
	Gzip bool
}

// NewWriter starts a session file. Header.Type, Tool and Version are filled in
// here; Created is filled in if it is zero.
func NewWriter(w io.Writer, h Header, opt Options) (*Writer, error) {
	out := &Writer{}
	if opt.Gzip {
		out.gz = gzip.NewWriter(w)
		w = out.gz
	}
	out.w = bufio.NewWriter(w)
	out.enc = json.NewEncoder(out.w)
	h.Type, h.Tool, h.Version = "session", "cube-logger", Version
	if h.Created.IsZero() {
		h.Created = time.Now()
	}
	out.year = h.Year
	if err := out.enc.Encode(h); err != nil {
		return nil, err
	}
	return out, nil
}

// Record appends one record. A record with no raw lines is skipped: there
// would be nothing for a later parser to re-read.
func (w *Writer) Record(r *live.Record) error {
	if w.err != nil {
		return w.err
	}
	if r == nil || len(r.RawLines) == 0 {
		return nil
	}
	e := entry{
		Type:         "record",
		Severity:     r.Severity,
		Facility:     r.Facility,
		Received:     r.Received,
		FirstLineSeq: r.FirstLineSeq,
		LastLineSeq:  r.LastLineSeq,
		HasLineSeq:   r.HasLineSeq,
		MissingLines: r.MissingLines,
		Lines:        r.Lines,
		Raw:          r.RawLines,
	}
	if r.Record != nil {
		e.Source = r.Source
		if w.year == 0 && !r.Time.IsZero() {
			w.year = r.Time.Year()
		}
	}
	w.n++
	w.err = w.enc.Encode(e)
	return w.err
}

// Records appends many.
func (w *Writer) Records(recs ...*live.Record) error {
	for _, r := range recs {
		if err := w.Record(r); err != nil {
			return err
		}
	}
	return nil
}

// Count is how many records have been written.
func (w *Writer) Count() uint64 { return w.n }

// Close writes the footer and flushes. A file without a footer is still
// readable; the reader says it was cut off.
func (w *Writer) Close(sources []live.SourceStat) error {
	if w.ended {
		return w.err
	}
	w.ended = true
	if w.err == nil {
		w.err = w.enc.Encode(Footer{
			Type: "end", Records: w.n, Sources: sources, Closed: time.Now(),
		})
	}
	if err := w.w.Flush(); err != nil && w.err == nil {
		w.err = err
	}
	if w.gz != nil {
		if err := w.gz.Close(); err != nil && w.err == nil {
			w.err = err
		}
	}
	return w.err
}

// Result is a session file read back.
type Result struct {
	Header  Header
	Records []*live.Record
	Sources []live.SourceStat
	// Truncated is set when the file has no footer: it was cut off while it
	// was being written, and what is here is what survived.
	Truncated bool
	// Skipped counts lines that could not be read back as records.
	Skipped int
	Notes   []string
}

// Read reads a whole session file. year overrides the year in the header, and
// 0 means "use the header's".
func Read(rd io.Reader, year int) (*Result, error) {
	rd, _, err := decompress(rd)
	if err != nil {
		return nil, err
	}

	sc := bufio.NewScanner(rd)
	sc.Buffer(make([]byte, 0, 64*1024), maxLine)
	if !sc.Scan() {
		if err := sc.Err(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("session: the file is empty")
	}
	res := &Result{}
	if err := json.Unmarshal(sc.Bytes(), &res.Header); err != nil {
		return nil, fmt.Errorf("session: the first line is not a session header: %w", err)
	}
	if res.Header.Type != "session" {
		return nil, fmt.Errorf("session: the first line is %q, not a session header", res.Header.Type)
	}
	if res.Header.Version > Version {
		return nil, fmt.Errorf("session: this file is version %d and this cube-logger reads %d: "+
			"use the version that wrote it", res.Header.Version, Version)
	}
	if year == 0 {
		year = res.Header.Year
	}

	r := &reader{year: year, srcs: map[string]*parse.Parser{}}
	res.Truncated = true
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var probe struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(line, &probe); err != nil {
			res.Skipped++
			continue
		}
		switch probe.Type {
		case "record":
			var e entry
			if err := json.Unmarshal(line, &e); err != nil {
				res.Skipped++
				continue
			}
			if rec := r.record(e); rec != nil {
				res.Records = append(res.Records, rec)
			} else {
				res.Skipped++
			}
		case "end":
			var f Footer
			if err := json.Unmarshal(line, &f); err == nil {
				res.Sources, res.Truncated = f.Sources, false
			}
		default:
			// A line this version does not know is not an error: a later
			// cube-logger may write more kinds, and the records are still
			// readable.
			res.Skipped++
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if res.Sources == nil {
		res.Sources = r.stats()
	}
	if res.Truncated {
		res.Notes = append(res.Notes, "this session file has no end marker: "+
			"it was cut off while it was being written, and what is here is what survived.")
	}
	if res.Skipped > 0 {
		res.Notes = append(res.Notes, fmt.Sprintf("%d line(s) in the file could not be read back.",
			res.Skipped))
	}
	return res, nil
}

// reader turns entries back into records by re-parsing their raw lines.
type reader struct {
	year int
	srcs map[string]*parse.Parser
	seen []string
	n    map[string]uint64
}

func (r *reader) parser(source string) *parse.Parser {
	p, ok := r.srcs[source]
	if !ok {
		p = parse.NewParser(source, r.year)
		r.srcs[source] = p
		r.seen = append(r.seen, source)
	}
	return p
}

// record re-parses one entry. Each entry is exactly one record, so the parser
// is flushed after it: there is no next line to close it off.
func (r *reader) record(e entry) *live.Record {
	if len(e.Raw) == 0 {
		return nil
	}
	p := r.parser(e.Source)
	for _, l := range e.Raw {
		// A completed record here would mean the entry held more than one,
		// which a file this package wrote never does. Flush catches it either
		// way, and dropping it silently is better than returning two records
		// from a call that promises one.
		_ = p.Line(l)
	}
	pr := p.Flush()
	if pr == nil {
		return nil
	}
	if r.n == nil {
		r.n = map[string]uint64{}
	}
	r.n[e.Source]++

	rec := &live.Record{
		Record:       pr,
		Severity:     e.Severity,
		Facility:     e.Facility,
		SeverityName: wire.SeverityName(e.Severity),
		Received:     e.Received,
		FirstLineSeq: e.FirstLineSeq,
		LastLineSeq:  e.LastLineSeq,
		HasLineSeq:   e.HasLineSeq,
		MissingLines: e.MissingLines,
		Lines:        e.Lines,
		RawLines:     pr.Raw,
	}
	if rec.Lines == 0 {
		rec.Lines = len(e.Raw)
	}
	if rec.Received.IsZero() {
		rec.Received = pr.Time
	}
	if e.MissingLines > 0 || (pr.SIP != nil && pr.SIP.Truncated) {
		rec.Incomplete = true
	}
	rec.Call = live.LegKey(pr)
	return rec
}

// stats stands in for a footer that is not there.
func (r *reader) stats() []live.SourceStat {
	out := make([]live.SourceStat, 0, len(r.seen))
	for _, s := range r.seen {
		out = append(out, live.SourceStat{Source: s, Records: r.n[s]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Source < out[j].Source })
	return out
}

// decompress peeks at the first bytes and wraps rd in a gzip reader if it is
// compressed. A session file is often shared by e-mail, and whether someone
// gzipped it on the way is not worth an engineer's attention.
func decompress(rd io.Reader) (io.Reader, bool, error) {
	br := bufio.NewReaderSize(rd, 64*1024)
	b, err := br.Peek(2)
	if err != nil && err != io.EOF {
		return nil, false, err
	}
	if len(b) == 2 && b[0] == 0x1f && b[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return nil, false, err
		}
		return gz, true, nil
	}
	return br, false, nil
}

// Sniff reports whether what is behind rd is a session file rather than a log,
// and returns a reader that still has everything rd had — decompressed, so the
// caller reads the same stream either way.
func Sniff(rd io.Reader) (io.Reader, bool, error) {
	plain, _, err := decompress(rd)
	if err != nil {
		return nil, false, err
	}
	br, ok := plain.(*bufio.Reader)
	if !ok {
		br = bufio.NewReaderSize(plain, 64*1024)
	}
	// A session file starts with a JSON object; a log file never does.
	b, err := br.Peek(512)
	if err != nil && err != io.EOF {
		return br, false, err
	}
	line := b
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		line = b[:i]
	}
	line = bytes.TrimSpace(line)
	if len(line) == 0 || line[0] != '{' {
		return br, false, nil
	}
	var probe struct {
		Type string `json:"type"`
	}
	// A header longer than the peek window is truncated JSON, which will not
	// unmarshal; the type is at the front, so look for it directly too.
	if err := json.Unmarshal(line, &probe); err != nil {
		return br, bytes.Contains(line, []byte(`"type":"session"`)), nil
	}
	return br, probe.Type == "session", nil
}
