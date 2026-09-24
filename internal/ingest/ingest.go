// Package ingest peels whatever wrote a saved file off each of its lines.
//
// A CUBE line reaches a file by one of several routes, and each route adds its
// own framing in front of the line the device actually emitted:
//
//	400020: Sep 24 10:00:01.123: %SIP-5-...        a terminal capture of "show logging"
//	<191>400020: Sep 24 10:00:01.123: %SIP-5-...   a saved datagram dump
//	Sep 24 10:00:01 cube-a 400020: Sep 24 ...      a syslog server writing RFC 3164
//	2026-09-24T10:00:01+02:00 cube-a 400020: ...   rsyslog's file format, syslog-ng's ISO
//	<191>1 2026-09-24T10:00:01Z cube-a - - - ...   RFC 5424
//	2026-09-24\t10:00:01\tLocal7.Debug\tcube-a\t.. Kiwi's tab-separated file
//
// Underneath all of them is the same IOS line, and internal/parse already knows
// how to read that. So this package does one job: it hands back the IOS line,
// plus the two things the outer framing knows and the IOS line does not — which
// device this came from, and what severity the device gave it.
//
// It does not do I/O and it holds no file: feed it lines, in order.
//
// # Why it locks onto one format
//
// The framings are told apart by shape, and a SIP body can contain almost any
// shape. So a peel is only ever attempted when the line does *not* already
// start with an IOS frame, a foreign format is only recognised when what is
// left after peeling looks like IOS output, and once a file has shown which
// format it is, only that format is tried. A capture of a terminal session is
// therefore never "corrected" by stripping something off a SIP header that
// happened to look like a timestamp.
package ingest

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/phuongnz/cube-logger/internal/parse"
)

// Format is what wrote the file.
type Format string

const (
	// Unknown is a file that has not shown its hand yet.
	Unknown Format = ""
	// IOS is the device's own framing with nothing in front of it: a terminal
	// capture, "show logging" output, or a syslog server writing the message
	// and nothing else.
	IOS Format = "ios"
	// PRI is an IOS line behind a bare syslog priority, which is what a saved
	// datagram dump looks like.
	PRI Format = "pri"
	// BSD is RFC 3164, the default of most syslog servers.
	BSD Format = "syslog-bsd"
	// ISO is a timestamp in ISO 8601 and a hostname: rsyslog's file format and
	// syslog-ng's ISO template.
	ISO Format = "syslog-iso"
	// RFC5424 is the newer syslog format, structured data and all.
	RFC5424 Format = "syslog-5424"
	// TSV is a tab-separated file of the kind Kiwi Syslog Server writes.
	TSV Format = "syslog-tsv"
)

// Describe names the format in words, for a summary line a human reads.
func (f Format) Describe() string {
	switch f {
	case IOS:
		return "IOS output with no syslog framing (a terminal capture or \"show logging\")"
	case PRI:
		return "IOS output behind a syslog priority (a saved datagram dump)"
	case BSD:
		return "a syslog server writing RFC 3164"
	case ISO:
		return "a syslog server writing an ISO 8601 timestamp and a hostname"
	case RFC5424:
		return "a syslog server writing RFC 5424"
	case TSV:
		return "a tab-separated syslog file"
	}
	return "an unrecognised format"
}

// Line is one input line with the outer framing removed.
type Line struct {
	// Text is the line internal/parse should be given. For a format that
	// carries no framing of its own it is the input unchanged.
	Text string
	// Host is the device this line came from, as the file names it: a
	// hostname or an address. It is empty when the file said nothing, which
	// is the normal case for a terminal capture.
	Host string
	// Time is the receiving server's clock, which is not the device's clock.
	// It is only set for the formats that carry one.
	Time    time.Time
	HasTime bool
	// Severity and Facility come from a syslog priority, and are -1 and 0
	// when the file carried none.
	Severity int
	Facility int
	// Format is what this line was recognised as.
	Format Format
	// Banner is set for a line that is not log content at all: the preamble
	// "show logging" prints before the buffer, or the prompt around it.
	Banner bool
	// Synthesized is set when the device was configured without
	// "service timestamps log datetime msec" and the IOS frame was rebuilt
	// from the receiving server's clock so that the line can be a record at
	// all. The times in it are the server's, not the router's.
	Synthesized bool
}

// Reader recognises one file. Feed it lines with Line, in order.
//
// The zero value is not usable; call New.
type Reader struct {
	// Year is the calendar year a format without one belongs to. 0 means the
	// current year.
	Year int

	format   Format
	counts   map[Format]int
	lines    int
	preamble bool
	host     string
	banner   []string
	lastMon  time.Month
}

// New returns a Reader that has not yet decided what it is reading.
func New() *Reader {
	return &Reader{counts: map[Format]int{}, preamble: true}
}

// Format is what the file turned out to be, or Unknown if nothing was
// recognised.
func (r *Reader) Format() Format { return r.format }

// Host is the hostname the file named, if any. For a terminal capture that is
// whatever stood in front of the "#" in the prompt.
func (r *Reader) Host() string { return r.host }

// Banner returns the preamble lines that were recognised and skipped.
func (r *Reader) Banner() []string { return r.banner }

// Line peels one line. It never returns an error: a line it does not
// recognise is passed through unchanged, which is exactly what a continuation
// line of a multi-line SIP message needs.
func (r *Reader) Line(s string) Line {
	r.lines++
	s = strings.TrimSuffix(s, "\r")
	out := Line{Text: s, Severity: -1, Host: r.host}

	// An IOS frame at the start of the line settles it: nothing was put in
	// front, so nothing is taken off.
	if _, _, ok := parse.SplitFrame(s); ok {
		r.preamble = false
		r.see(IOS)
		out.Format = IOS
		return out
	}

	if r.preamble || r.isOwnPrompt(s) {
		if name, ok := banner(s); ok {
			if name != "" && r.host == "" {
				r.host = name
			}
			r.preamble = true
			r.banner = append(r.banner, s)
			out.Host, out.Banner, out.Format = r.host, true, r.format
			return out
		}
	}

	// A syslog priority announces itself: an IOS line never starts with "<".
	// These two are therefore safe to peel whatever the rest of the file looks
	// like, which is what a mixed datagram dump needs.
	if strings.HasPrefix(s, "<") {
		for _, c := range []Format{RFC5424, PRI} {
			rest, p, ok := peel(c, s, r.year())
			if ok && (looksLikeIOS(rest) || r.counts[c] > 0) {
				r.see(c)
				return r.peeled(rest, p, c)
			}
		}
		return out
	}

	// A format already settled on is the only one tried, so that a SIP body
	// line is never mistaken for someone else's framing.
	if r.format != Unknown {
		if r.format == IOS {
			return out
		}
		if rest, p, ok := peel(r.format, s, r.year()); ok {
			return r.peeled(rest, p, r.format)
		}
		return out
	}

	// Nothing settled yet. A foreign format is only accepted when what is left
	// after peeling looks like something a router said.
	for _, c := range candidates {
		rest, p, ok := peel(c, s, r.year())
		if !ok || !looksLikeIOS(rest) {
			continue
		}
		r.see(c)
		return r.peeled(rest, p, c)
	}
	return out
}

func (r *Reader) year() int {
	if r.Year != 0 {
		return r.Year
	}
	return time.Now().Year()
}

// peeled builds the result for a line a foreign framing was taken off.
func (r *Reader) peeled(rest string, p prefix, f Format) Line {
	r.preamble = false
	if p.host != "" {
		r.host = p.host
	}
	out := Line{
		Text:     rest,
		Host:     p.host,
		Time:     p.t,
		HasTime:  p.hasTime,
		Severity: p.sev,
		Facility: p.fac,
		Format:   f,
	}
	if out.Host == "" {
		out.Host = r.host
	}
	// A device without "service timestamps" emits a line the parser cannot
	// frame. The receiving server timestamped it, so the frame can be rebuilt
	// — but only for a line that starts a record. A continuation line must
	// stay bare, or a SIP message would become nineteen records.
	if _, _, ok := parse.SplitFrame(rest); !ok && p.hasTime && startsRecord(rest) {
		out.Text = synthFrame(rest, p.t)
		out.Synthesized = true
	}
	return out
}

func (r *Reader) see(f Format) {
	r.counts[f]++
	if r.format == Unknown {
		r.format = f
	}
}

// Counts is how many lines were recognised as each format, for a summary that
// can say "this file is mostly one thing with a few lines of another".
func (r *Reader) Counts() map[Format]int {
	out := make(map[Format]int, len(r.counts))
	for k, v := range r.counts {
		out[k] = v
	}
	return out
}

// candidates are the framings that do not announce themselves, tried most
// specific first: TSV's first field could pass for ISO's.
var candidates = []Format{TSV, ISO, BSD}

// prefix is what a foreign framing knew.
type prefix struct {
	host    string
	t       time.Time
	hasTime bool
	sev     int
	fac     int
}

func newPrefix() prefix { return prefix{sev: -1} }

func peel(f Format, s string, year int) (string, prefix, bool) {
	switch f {
	case BSD:
		return peelBSD(s, year)
	case ISO:
		return peelISO(s)
	case RFC5424:
		return peel5424(s)
	case TSV:
		return peelTSV(s)
	case PRI:
		return peelPRI(s)
	}
	return s, newPrefix(), false
}

// looksLikeIOS reports whether what is left after peeling is plausibly a line
// a router wrote: a framed record, a log line, or a debug header. It is the
// guard that keeps a coincidence in a SIP body from being read as framing.
func looksLikeIOS(s string) bool {
	if _, _, ok := parse.SplitFrame(s); ok {
		return true
	}
	return startsRecord(s)
}

var logTagRe = regexp.MustCompile(`^%[A-Z][A-Z0-9_]*-[0-7]-[A-Z0-9_]+:`)

// startsRecord reports whether an unframed line is one that would start a
// record rather than continue one: a "%FACILITY-severity-MNEMONIC" log line or
// a "//call/guid/..." debug header, either of which may still be behind the
// sequence number "service sequence-numbers" adds.
func startsRecord(s string) bool {
	if m := seqPrefixRe.FindStringSubmatch(s); m != nil {
		s = s[len(m[0]):]
	}
	return logTagRe.MatchString(s) || strings.HasPrefix(s, "//")
}

var seqPrefixRe = regexp.MustCompile(`^(\d+): `)

// synthFrame puts an IOS timestamp in front of a line that has none, keeping a
// sequence number if the device was at least numbering its messages.
func synthFrame(s string, t time.Time) string {
	seq := ""
	if m := seqPrefixRe.FindStringSubmatch(s); m != nil {
		seq, s = m[1]+": ", s[len(m[0]):]
	}
	return seq + t.Format("Jan _2 15:04:05.000") + ": " + s
}

// --- the framings -----------------------------------------------------------

var bsdRe = regexp.MustCompile(
	`^([A-Z][a-z]{2}) {1,2}(\d{1,2}) (\d{2}):(\d{2}):(\d{2})(?:[.,](\d{1,6}))? (\S+) `)

var months = map[string]time.Month{
	"Jan": time.January, "Feb": time.February, "Mar": time.March,
	"Apr": time.April, "May": time.May, "Jun": time.June,
	"Jul": time.July, "Aug": time.August, "Sep": time.September,
	"Oct": time.October, "Nov": time.November, "Dec": time.December,
}

func peelBSD(s string, year int) (string, prefix, bool) {
	m := bsdRe.FindStringSubmatch(s)
	if m == nil {
		return s, newPrefix(), false
	}
	mon, ok := months[m[1]]
	if !ok {
		return s, newPrefix(), false
	}
	day, _ := strconv.Atoi(m[2])
	h, _ := strconv.Atoi(m[3])
	min, _ := strconv.Atoi(m[4])
	sec, _ := strconv.Atoi(m[5])
	p := newPrefix()
	p.host = strings.TrimSuffix(m[7], ":")
	p.t = time.Date(year, mon, day, h, min, sec, frac(m[6]), time.Local)
	p.hasTime = true
	return s[len(m[0]):], p, true
}

// frac turns a fractional-second field of any length into nanoseconds.
func frac(s string) int {
	if s == "" {
		return 0
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	for i := len(s); i < 9; i++ {
		n *= 10
	}
	return n
}

var isoRe = regexp.MustCompile(
	`^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?) (\S+) `)

func peelISO(s string) (string, prefix, bool) {
	m := isoRe.FindStringSubmatch(s)
	if m == nil {
		return s, newPrefix(), false
	}
	t, ok := parseISO(m[1])
	if !ok {
		return s, newPrefix(), false
	}
	p := newPrefix()
	p.host = strings.TrimSuffix(m[2], ":")
	p.t, p.hasTime = t, true
	return s[len(m[0]):], p, true
}

var isoLayouts = []string{
	time.RFC3339Nano, time.RFC3339,
	"2006-01-02T15:04:05.999999999",
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05.999999999-07:00",
	"2006-01-02 15:04:05-07:00",
	"2006-01-02 15:04:05.999999999",
	"2006-01-02 15:04:05",
}

func parseISO(s string) (time.Time, bool) {
	// A comma is a legal decimal separator in ISO 8601 and some servers write
	// one; Go's layouts only know the dot.
	s = strings.Replace(s, ",", ".", 1)
	for _, l := range isoLayouts {
		if t, err := time.Parse(l, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

var rfc5424Re = regexp.MustCompile(`^<(\d{1,3})>1 (\S+) (\S+) (\S+) (\S+) (\S+) `)

func peel5424(s string) (string, prefix, bool) {
	m := rfc5424Re.FindStringSubmatch(s)
	if m == nil {
		return s, newPrefix(), false
	}
	rest := s[len(m[0]):]
	// A file that left MSGID out — some servers do — puts the structured data
	// where MSGID should be. Give it back.
	if strings.HasPrefix(m[6], "[") {
		rest = s[strings.LastIndex(s[:len(m[0])], m[6]):]
	}
	// Structured data: "-" for none, else one or more "[...]" elements in
	// which a "]" can be escaped.
	switch {
	case strings.HasPrefix(rest, "- "):
		rest = rest[2:]
	case rest == "-":
		rest = ""
	case strings.HasPrefix(rest, "["):
		var ok bool
		if rest, ok = skipStructured(rest); !ok {
			return s, newPrefix(), false
		}
	}
	rest = strings.TrimPrefix(rest, "\ufeff")
	p := newPrefix()
	p.sev, p.fac = priority(m[1])
	if m[3] != "-" {
		p.host = m[3]
	}
	if t, ok := parseISO(m[2]); ok {
		p.t, p.hasTime = t, true
	}
	return rest, p, true
}

func skipStructured(s string) (string, bool) {
	for strings.HasPrefix(s, "[") {
		i, esc := 1, false
		for ; i < len(s); i++ {
			switch {
			case esc:
				esc = false
			case s[i] == '\\':
				esc = true
			case s[i] == ']':
				goto closed
			}
		}
		return s, false
	closed:
		s = s[i+1:]
	}
	return strings.TrimPrefix(s, " "), true
}

var priRe = regexp.MustCompile(`^<(\d{1,3})>`)

func peelPRI(s string) (string, prefix, bool) {
	m := priRe.FindStringSubmatch(s)
	if m == nil {
		return s, newPrefix(), false
	}
	p := newPrefix()
	p.sev, p.fac = priority(m[1])
	if p.sev < 0 {
		return s, newPrefix(), false
	}
	return s[len(m[0]):], p, true
}

func priority(s string) (sev, fac int) {
	n, err := strconv.Atoi(s)
	if err != nil || n > 191 {
		return -1, 0
	}
	return n % 8, n / 8
}

func peelTSV(s string) (string, prefix, bool) {
	f := strings.Split(s, "\t")
	if len(f) < 5 {
		return s, newPrefix(), false
	}
	t, ok := parseISO(f[0] + "T" + f[1])
	if !ok {
		return s, newPrefix(), false
	}
	p := newPrefix()
	p.t, p.hasTime = t, true
	p.host = f[3]
	p.sev, p.fac = facilitySeverity(f[2])
	return strings.Join(f[4:], "\t"), p, true
}

// facilitySeverity reads Kiwi's "Local7.Debug" priority column. The facility
// name is not worth a table: what an engineer filters on is the severity.
func facilitySeverity(s string) (sev, fac int) {
	name, sevName, ok := strings.Cut(s, ".")
	if !ok {
		return -1, 0
	}
	sev = severityByName(sevName)
	if n, err := strconv.Atoi(strings.TrimPrefix(strings.ToLower(name), "local")); err == nil && n >= 0 && n <= 7 {
		fac = 16 + n
	}
	return sev, fac
}

var severityNames = []string{
	"emergency", "alert", "critical", "error",
	"warning", "notice", "informational", "debug",
}

// severityByName accepts what a syslog server writes in a text column, which
// is not always the RFC's word: "err", "crit", "info", "emerg", "panic".
func severityByName(s string) int {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "panic":
		return 0
	case "warn":
		return 4
	}
	found := -1
	for i, n := range severityNames {
		if len(s) >= 3 && strings.HasPrefix(n, s) {
			if found >= 0 {
				return -1
			}
			found = i
		}
	}
	return found
}

// --- the "show logging" preamble --------------------------------------------

// bannerPrefixes are the lines "show logging" prints before the buffer itself.
// They are only ever recognised in the preamble — before the first record, or
// straight after this device's own prompt — so a SIP body that happens to
// start with one of these words is safe.
var bannerPrefixes = []string{
	"Syslog logging:",
	"Console logging:",
	"Monitor logging:",
	"Buffer logging:",
	"Exception Logging:",
	"Count and timestamp logging messages:",
	"Persistent logging:",
	"File logging:",
	"Trap logging:",
	"Logging to ",
	"Logging Source-Interface:",
	"Log Buffer (",
	"No Active Message Discriminator.",
	"No Inactive Message Discriminator.",
	"Active Message Discriminator:",
	"Inactive Message Discriminator:",
	"Filter modules:",
	"ESM:",
	"TLS Profiles:",
	"VRF Name:",
	"Logging Exception size",
	"terminal length",
	"terminal width",
}

// promptRe is "hostname#" or "hostname>", alone or with the command that was
// typed after it. The command is held to lower-case words so that a line of
// SIP does not pass for one.
var promptRe = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9_.-]*)[#>] ?([a-z][a-z0-9 |_-]{0,60})?$`)

// banner reports whether a line is preamble rather than log content, and names
// the device if the line was a prompt.
func banner(s string) (host string, ok bool) {
	t := strings.TrimSpace(s)
	if t == "" {
		return "", true
	}
	if m := promptRe.FindStringSubmatch(t); m != nil {
		return m[1], true
	}
	for _, p := range bannerPrefixes {
		if strings.HasPrefix(t, p) {
			return "", true
		}
	}
	return "", false
}

// isOwnPrompt reports whether a line is this device's prompt appearing again
// after the buffer has been printed — the end of "show logging", and the start
// of another preamble. Only the hostname already learned is accepted, because
// outside the preamble the prompt pattern alone is not evidence enough.
func (r *Reader) isOwnPrompt(s string) bool {
	if r.host == "" {
		return false
	}
	t := strings.TrimSpace(s)
	if !strings.HasPrefix(t, r.host) {
		return false
	}
	rest := t[len(r.host):]
	return strings.HasPrefix(rest, "#") || strings.HasPrefix(rest, ">")
}
