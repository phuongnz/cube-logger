// Package parse turns CUBE log and debug text into records.
//
// It does no I/O: text in, records out. Live UDP syslog and a saved file
// therefore go through exactly the same code, and both can be tested with
// plain-text fixtures.
//
// The shapes implemented here are described in docs/log-format.md.
package parse

import (
	"bufio"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Kind is what a record's payload turned out to be.
type Kind string

const (
	// KindDebug is a debug line: the payload starts "//".
	KindDebug Kind = "debug"
	// KindLog is an IOS log line: the payload starts "%FACILITY-SEVERITY-MNEMONIC:".
	KindLog Kind = "log"
	// KindOther is a framed line whose payload is neither of those.
	KindOther Kind = "other"
)

// Record is one framed log or debug record, together with every bare
// continuation line that followed it.
//
// Time is the device's own clock reading. IOS prints no year and, unless
// "service timestamps ... show-timezone" is configured, no zone either, so
// Time carries the year the parser supplied and a UTC location standing in for
// "the device's local time". Zone holds the zone token when the device did
// print one; TimeTrusted is false when IOS flagged the clock as unsynchronised
// with a leading "*".
type Record struct {
	Source      string    `json:"source,omitempty"`
	Line        int       `json:"line"`
	Seq         uint64    `json:"seq,omitempty"`
	HasSeq      bool      `json:"hasSeq,omitempty"`
	Time        time.Time `json:"time"`
	Zone        string    `json:"zone,omitempty"`
	TimeTrusted bool      `json:"timeTrusted"`

	Kind Kind   `json:"kind"`
	Text string `json:"text"`

	Debug *DebugHeader `json:"debug,omitempty"`
	Log   *LogLine     `json:"log,omitempty"`
	SIP   *SIPMessage  `json:"sip,omitempty"`
	Cover *CoverBuffer `json:"cover,omitempty"`

	// Cont holds continuation lines that no structured field claimed.
	Cont     []string `json:"cont,omitempty"`
	Warnings []string `json:"warnings,omitempty"`

	// Raw is every line of the record verbatim, first line included. It is the
	// text the UI shows, and is deliberately kept out of the golden JSON.
	Raw []string `json:"-"`
}

// DebugHeader is the "//<call entry id>/<guid>/<component...>" prefix of a debug line.
type DebugHeader struct {
	// CallID is the IOS call entry ID, or NoCallID when the line carries "-1".
	CallID int64 `json:"callId"`
	// GUID is the 12 hex character debug GUID, empty when "xxxxxxxxxxxx".
	GUID      string   `json:"guid,omitempty"`
	Component []string `json:"component,omitempty"`
	Detail    string   `json:"detail,omitempty"`
}

// NoCallID is the call entry ID of a debug line that is not yet attached to a leg.
const NoCallID int64 = -1

// Function returns the last component segment, which by convention names the
// function that emitted the line. It is empty when the component path is empty.
func (d *DebugHeader) Function() string {
	if len(d.Component) == 0 {
		return ""
	}
	return d.Component[len(d.Component)-1]
}

// LogLine is a "%FACILITY-SEVERITY-MNEMONIC: text" line.
type LogLine struct {
	Facility string `json:"facility"`
	Severity int    `json:"severity"`
	Mnemonic string `json:"mnemonic"`
	Text     string `json:"text"`
	// CallID is the leg named by "on callID <n>", or NoCallID. %VOICE_IEC-3-GW
	// carries it, which is what makes a failure attachable to a call.
	CallID int64 `json:"callId,omitempty"`
	// IEC is the Cisco Internal Error Code, when the line carries one.
	IEC string `json:"iec,omitempty"`
}

// Tag is the "%FACILITY-SEVERITY-MNEMONIC" identifier without its text.
func (l *LogLine) Tag() string {
	return "%" + l.Facility + "-" + strconv.Itoa(l.Severity) + "-" + l.Mnemonic
}

// frameRe matches the frame IOS writes from "service sequence-numbers" and
// "service timestamps". Everything optional here is optional in IOS too: the
// sequence number (no "service sequence-numbers"), the "*" that marks an
// unsynchronised clock, the year ("service timestamps ... year"), the
// milliseconds (without "msec") and the zone token (without "show-timezone").
//
// It is anchored and complete on purpose. A loose "^\d+:" also matches SIP body
// text, and a loose "^\d{6}:" misses the 7-digit sequence numbers real boxes use.
var frameRe = regexp.MustCompile(
	`^(?:(\d+): )?(\*)?([A-Z][a-z]{2}) {1,2}(\d{1,2}) (?:(\d{4}) )?(\d{1,2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?(?: ([A-Za-z]{2,6}|[+-]\d{2}:?\d{2}))?:`)

var months = map[string]time.Month{
	"Jan": time.January, "Feb": time.February, "Mar": time.March,
	"Apr": time.April, "May": time.May, "Jun": time.June,
	"Jul": time.July, "Aug": time.August, "Sep": time.September,
	"Oct": time.October, "Nov": time.November, "Dec": time.December,
}

// Parser reassembles a line stream into records. Feed it lines with Line and
// finish with Flush; a record is only complete once the line after it arrives,
// because continuation lines are what extend it.
//
// A Parser handles one source. Sequence numbers are per device (see
// docs/log-format.md), so a second CUBE needs a second Parser.
type Parser struct {
	source string
	year   int

	lastMonth time.Month
	cur       *Record
	lineNo    int

	// orphans are bare lines seen before the first framed line. A "show logging"
	// buffer that has wrapped starts in the middle of a record, so these belong
	// to a record that no longer exists.
	orphans []string
	seq     SeqTracker
}

// NewParser returns a Parser for one source. year is the calendar year the
// first record belongs to; 0 means the current year. IOS does not print a year,
// so the caller has to supply one, and the parser rolls it forward when the
// month goes backwards.
func NewParser(source string, year int) *Parser {
	if year == 0 {
		year = time.Now().Year()
	}
	return &Parser{source: source, year: year}
}

// Line feeds one line, without its line ending. It returns the record that the
// line completed, or nil when the line extended the record still being built.
func (p *Parser) Line(s string) *Record {
	p.lineNo++
	s = strings.TrimSuffix(s, "\r")

	m := frameRe.FindStringSubmatch(s)
	if m == nil || !payloadStarts(s, len(m[0])) {
		if p.cur == nil {
			p.orphans = append(p.orphans, s)
			return nil
		}
		p.cur.Raw = append(p.cur.Raw, s)
		p.cur.Cont = append(p.cur.Cont, s)
		return nil
	}

	done := p.finish()
	p.cur = p.newRecord(s, m)
	return done
}

// payloadStarts reports whether what follows the frame at offset n is a payload
// rather than more of the same line. IOS writes ": " after the timestamp; a
// record with an empty payload ends right there.
func payloadStarts(s string, n int) bool {
	return n == len(s) || s[n] == ' '
}

func (p *Parser) newRecord(s string, m []string) *Record {
	r := &Record{
		Source:      p.source,
		Line:        p.lineNo,
		TimeTrusted: m[2] != "*",
		Zone:        m[10],
		Raw:         []string{s},
	}
	if m[1] != "" {
		r.Seq, _ = strconv.ParseUint(m[1], 10, 64)
		r.HasSeq = true
		if g, ok := p.seq.Observe(r.Seq); ok {
			r.Warnings = append(r.Warnings, g.Reason())
		}
	}
	r.Time = p.stamp(m)
	r.Text = strings.TrimPrefix(s[len(m[0]):], " ")
	return r
}

// stamp builds the timestamp, supplying the year IOS does not print and rolling
// it forward across a year boundary in a long capture.
func (p *Parser) stamp(m []string) time.Time {
	mon := months[m[3]]
	if p.lastMonth == time.December && mon == time.January {
		p.year++
	}
	if mon != 0 {
		p.lastMonth = mon
	}
	year := p.year
	if m[5] != "" {
		year, _ = strconv.Atoi(m[5])
	}
	day, _ := strconv.Atoi(m[4])
	hh, _ := strconv.Atoi(m[6])
	mm, _ := strconv.Atoi(m[7])
	ss, _ := strconv.Atoi(m[8])
	// IOS prints milliseconds, so "5" means 500ms, not 5ms.
	ms := 0
	if m[9] != "" {
		ms, _ = strconv.Atoi(m[9] + strings.Repeat("0", 3-len(m[9])))
	}
	return time.Date(year, mon, day, hh, mm, ss, ms*int(time.Millisecond), time.UTC)
}

// finish structures the record under construction and returns it.
func (p *Parser) finish() *Record {
	r := p.cur
	p.cur = nil
	if r == nil {
		return nil
	}
	switch {
	case strings.HasPrefix(r.Text, "//"):
		r.Kind = KindDebug
		r.Debug = parseDebugHeader(r.Text)
		if r.Debug == nil {
			r.Kind = KindOther
			r.Warnings = append(r.Warnings, "debug header did not parse")
		}
	case strings.HasPrefix(r.Text, "%"):
		r.Kind = KindLog
		r.Log = parseLogLine(r.Text)
		if r.Log == nil {
			r.Kind = KindOther
		}
	default:
		r.Kind = KindOther
	}
	structureBody(r)
	return r
}

// Flush returns the record still being built, if any. Call it at end of input.
// On a live stream a record is only known to be complete when the next one
// starts, so a listener should also flush on an idle timeout.
func (p *Parser) Flush() *Record { return p.finish() }

// Orphans returns the bare lines seen before the first framed line. A wrapped
// "show logging" buffer opens with the tail of an overwritten record, and those
// lines belong to no record.
func (p *Parser) Orphans() []string { return p.orphans }

// Gaps returns the sequence-number discontinuities seen so far.
func (p *Parser) Gaps() []Gap { return p.seq.Gaps }

var debugCallIDRe = regexp.MustCompile(`^-?\d+$`)

// parseDebugHeader reads "//<call entry id>/<guid>/<component...>[: detail]".
//
// The component path is variable length — "SIP/Msg/ccsipDisplayMsg" is three
// segments, "CUBE_VT/SIP/FSM/SPI-State-Change" is four, and a voice-trace
// Cover Buffer header has none at all — so the field count is never assumed.
func parseDebugHeader(text string) *DebugHeader {
	head, detail, _ := strings.Cut(strings.TrimPrefix(text, "//"), ":")
	fields := strings.Split(head, "/")
	if len(fields) < 2 || !debugCallIDRe.MatchString(fields[0]) {
		return nil
	}
	d := &DebugHeader{Detail: strings.TrimSpace(detail)}
	d.CallID, _ = strconv.ParseInt(fields[0], 10, 64)
	if g := fields[1]; g != "xxxxxxxxxxxx" {
		d.GUID = g
	}
	for _, c := range fields[2:] {
		if c != "" {
			d.Component = append(d.Component, c)
		}
	}
	return d
}

var (
	logRe     = regexp.MustCompile(`^%([A-Za-z0-9_]+)-(\d)-([A-Za-z0-9_]+): ?(.*)$`)
	onCallRe  = regexp.MustCompile(`\bon callID (\d+)\b`)
	iecRe     = regexp.MustCompile(`\bIEC=([0-9]+(?:\.[0-9]+)+)`)
	logSlotRe = regexp.MustCompile(`^%[A-Za-z0-9_]+-\d+-[A-Za-z0-9_]+:`)
)

// parseLogLine reads "%FACILITY-SEVERITY-MNEMONIC: text", and pulls out the two
// fields that tie a log line to a call: the "on callID <n>" that %VOICE_IEC-3-GW
// carries, and the Internal Error Code beside it.
func parseLogLine(text string) *LogLine {
	m := logRe.FindStringSubmatch(text)
	if m == nil {
		return nil
	}
	l := &LogLine{Facility: m[1], Mnemonic: m[3], Text: m[4], CallID: NoCallID}
	l.Severity, _ = strconv.Atoi(m[2])
	if c := onCallRe.FindStringSubmatch(l.Text); c != nil {
		l.CallID, _ = strconv.ParseInt(c[1], 10, 64)
	}
	if e := iecRe.FindStringSubmatch(l.Text); e != nil {
		l.IEC = e[1]
	}
	return l
}

// structureBody turns a record's continuation lines into a SIP message or a
// Cover Buffer block when they are one, and leaves them in Cont when they are not.
func structureBody(r *Record) {
	if len(r.Cont) == 0 {
		return
	}
	if c := parseCoverBuffer(r.Cont); c != nil {
		r.Cover = c
		r.Cont = nil
		return
	}
	if msg, warns := parseSIPMessage(r.Cont); msg != nil {
		r.SIP = msg
		r.Cont = nil
		r.Warnings = append(r.Warnings, warns...)
	}
}

// Result is everything one pass over a file produced.
type Result struct {
	Source  string    `json:"source,omitempty"`
	Records []*Record `json:"records"`
	Orphans []string  `json:"orphans,omitempty"`
	Gaps    []Gap     `json:"gaps,omitempty"`
	Lines   int       `json:"lines"`
}

// Reader parses a whole stream. year is the calendar year the first record
// belongs to; 0 means the current year.
func Reader(rd io.Reader, source string, year int) (*Result, error) {
	p := NewParser(source, year)
	res := &Result{Source: source}
	sc := bufio.NewScanner(rd)
	// SIP lines are short — the longest line in the study capture was 453 bytes —
	// but a saved file can hold anything, so allow a generous line.
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		if r := p.Line(sc.Text()); r != nil {
			res.Records = append(res.Records, r)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if r := p.Flush(); r != nil {
		res.Records = append(res.Records, r)
	}
	res.Orphans = p.Orphans()
	res.Gaps = p.Gaps()
	res.Lines = p.lineNo
	return res, nil
}

// SplitFrame splits a line into the IOS frame ("<seq>: <Mon DD HH:MM:SS.mmm>: ")
// and the payload after it. ok is false for a bare continuation line, which has
// no frame and is all payload.
//
// The frame holds a sequence number and a clock reading and nothing else, so a
// tool that rewrites sensitive values can leave it alone — and must, since the
// sequence number is the loss detector.
func SplitFrame(line string) (frame, payload string, ok bool) {
	m := frameRe.FindStringIndex(strings.TrimSuffix(line, "\r"))
	if m == nil || !payloadStarts(line, m[1]) {
		return "", line, false
	}
	n := m[1]
	if n < len(line) && line[n] == ' ' {
		n++
	}
	return line[:n], line[n:], true
}

// TakeOrphans returns the orphan lines seen since the last call and forgets
// them, for the same reason as SeqTracker.TakeGaps: on a live stream the
// parser is flushed on an idle timeout, so a continuation arriving after a
// flush becomes an orphan, and a process running for days must not accumulate
// them forever.
func (p *Parser) TakeOrphans() []string {
	o := p.orphans
	p.orphans = nil
	return o
}

// TakeGaps returns the sequence-number gaps seen since the last call and
// forgets them.
func (p *Parser) TakeGaps() []Gap { return p.seq.TakeGaps() }
