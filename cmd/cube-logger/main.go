// Command cube-logger is a live syslog and debug viewer for Cisco CUBE.
//
// "live" listens for syslog datagrams, reassembles them into records and serves
// a table of them to a browser on this machine. "open" does the same for saved
// files — a "show logging" capture, a file some other syslog server wrote, or a
// session this tool saved — so that a file and a stream get the same views.
// "replay" sends a saved log to the listener one datagram per line, or one TLS
// message per line, which is how the live path is exercised without a router. "parse" reads a saved log
// offline, and "sanitize" rewrites a capture into something safe to commit.
// "cert" makes the certificates syslog over TLS needs and prints the router
// configuration that trusts them.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/phuongnz/cube-logger/internal/correlate"
	"github.com/phuongnz/cube-logger/internal/live"
	"github.com/phuongnz/cube-logger/internal/load"
	"github.com/phuongnz/cube-logger/internal/parse"
	"github.com/phuongnz/cube-logger/internal/sanitize"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "parse":
		err = parseCmd(os.Args[2:])
	case "sanitize":
		err = sanitizeCmd(os.Args[2:])
	case "live":
		err = liveCmd(os.Args[2:])
	case "open":
		err = openCmd(os.Args[2:])
	case "replay":
		err = replayCmd(os.Args[2:])
	case "cert":
		err = certCmd(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "cube-logger:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `cube-logger — a live syslog and debug viewer for Cisco CUBE

usage:
  cube-logger live [flags]              listen for syslog and open a live view in a browser
  cube-logger open [flags] <file>...    open saved logs or a saved session in the same views
  cube-logger replay [flags] <file>     send a saved log to a listener, one datagram (or TLS message) per line
  cube-logger cert [flags]              make the TLS certificates and print the router config for them
  cube-logger parse [flags] <file>      parse a saved log and print records and calls
  cube-logger sanitize [flags] <file>   rewrite a capture so it is safe to commit

"-" reads standard input. Run a subcommand with -h for its flags.
`)
}

// open returns the named file, or standard input for "-".
func open(name string) (io.ReadCloser, error) {
	if name == "-" {
		return io.NopCloser(os.Stdin), nil
	}
	return os.Open(name)
}

func parseCmd(args []string) error {
	fs := flag.NewFlagSet("parse", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "print records and calls as JSON")
	records := fs.Bool("records", false, "print only the records")
	calls := fs.Bool("calls", false, "print only the calls")
	keepalives := fs.Bool("keepalives", false, "include OPTIONS keepalives in the call list")
	year := fs.Int("year", 0, "calendar year of the first record (IOS does not log one; 0 means this year)")
	source := fs.String("source", "", "name for the device this file came from (default: the file name)")
	var names labelList
	fs.Var(&names, "name", "rename a device, as address=name (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("parse needs exactly one file (or \"-\")")
	}
	name := fs.Arg(0)

	// One reader for every kind of file: a terminal capture, whatever a syslog
	// server wrote, and a session this tool saved. An engineer should not have
	// to know which one they were handed.
	o, err := openFile(name, load.Options{Year: *year, Source: *source, Rename: names.rename})
	if err != nil {
		return err
	}
	recs := make([]*parse.Record, 0, len(o.records))
	for _, r := range o.records {
		recs = append(recs, r.Record)
	}
	c := correlate.New()
	for _, r := range recs {
		c.Add(r)
	}
	grouped := c.Result()

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(output{
			Source: name, Format: o.format, Lines: o.lines, Records: recs,
			Orphans: o.orphans, Sources: o.sources, Notes: o.notes,
			Calls: grouped.Calls, Unattached: grouped.Unattached,
		})
	}

	showRecords, showCalls := !*calls, !*records
	printSummary(name, o, recs, grouped)
	if showRecords {
		printRecords(recs)
	}
	if showCalls {
		printCalls(grouped, recs, *keepalives)
	}
	return nil
}

// output is the -json shape: what the file was, what came out of it, and the
// correlator's answer folded in.
type output struct {
	Source     string            `json:"source,omitempty"`
	Format     string            `json:"format,omitempty"`
	Lines      int               `json:"lines"`
	Records    []*parse.Record   `json:"records"`
	Orphans    []string          `json:"orphans,omitempty"`
	Sources    []live.SourceStat `json:"sources,omitempty"`
	Notes      []string          `json:"notes,omitempty"`
	Calls      []*correlate.Call `json:"calls"`
	Unattached []uint64          `json:"unattached,omitempty"`
}

func printSummary(name string, o *opened, records []*parse.Record, grouped *correlate.Result) {
	fmt.Printf("%s: %s\n", name, o.format)
	fmt.Printf("  %d line(s), %d record(s), %d call(s)\n",
		o.lines, len(records), len(grouped.Calls))

	debugs, logs := 0, 0
	for _, r := range records {
		switch r.Kind {
		case parse.KindDebug:
			debugs++
		case parse.KindLog:
			logs++
		}
	}
	fmt.Printf("  %d debug, %d log, %d other\n", debugs, logs, len(records)-debugs-logs)

	// One line per device, because a file can hold more than one and their
	// sequence numbers are not comparable.
	for _, s := range o.sources {
		lost := ""
		if s.LostRecords > 0 {
			lost = fmt.Sprintf(", %d record(s) lost or rate-limited", s.LostRecords)
		}
		fmt.Printf("  %s: %d record(s)%s\n", s.Source, s.Records, lost)
	}
	for _, n := range o.notes {
		fmt.Println("  note: " + n)
	}
	if n := len(o.orphans); n > 0 {
		fmt.Printf("  %d line(s) before the first record, discarded "+
			"(a \"show logging\" buffer that has wrapped starts mid-record)\n", n)
	}
	fmt.Println()
}

func printRecords(records []*parse.Record) {
	fmt.Println("records:")
	for _, r := range records {
		seq := "-"
		if r.HasSeq {
			seq = fmt.Sprint(r.Seq)
		}
		fmt.Printf("  %10s  %s  %-5s  %s\n",
			seq, r.Time.Format("15:04:05.000"), r.Kind, recordSummary(r))
		for _, w := range r.Warnings {
			fmt.Printf("  %10s  %12s  %-5s  ! %s\n", "", "", "", w)
		}
	}
	fmt.Println()
}

// recordSummary is the one-line description the record list shows: the leg
// identifiers a debug line carries, then what the record actually says.
func recordSummary(r *parse.Record) string {
	prefix := ""
	if r.Debug != nil {
		id := "-1"
		if r.Debug.CallID != parse.NoCallID {
			id = fmt.Sprint(r.Debug.CallID)
		}
		guid := r.Debug.GUID
		if guid == "" {
			guid = "-"
		}
		prefix = id + "/" + guid + " "
	}

	var desc string
	switch {
	case r.SIP != nil:
		dir := "-->"
		if r.SIP.Direction == parse.DirReceived {
			dir = "<--"
		}
		desc = dir + " " + r.SIP.StartLine
	case r.Cover != nil:
		desc = fmt.Sprintf("Cover Buffer: %s -> %s (call %d, GUID %s)",
			r.Cover.Calling, r.Cover.Called, r.Cover.CallID, r.Cover.GUID)
	case r.Log != nil:
		desc = r.Log.Tag() + ": " + r.Log.Text
	case r.Debug != nil:
		desc = strings.TrimSpace(strings.Join(r.Debug.Component, "/") + " " + r.Debug.Detail)
	default:
		desc = r.Text
	}
	if desc == "" && len(r.Cont) > 0 {
		desc = strings.TrimSpace(r.Cont[0])
	}
	return strings.TrimSpace(prefix + desc)
}

func printCalls(grouped *correlate.Result, records []*parse.Record, keepalives bool) {
	fmt.Println("calls:")
	shown := 0
	for _, call := range grouped.Calls {
		if call.Keepalive && !keepalives {
			continue
		}
		shown++
		guid := call.GUID
		if guid == "" {
			guid = "(no GUID)"
		}
		fmt.Printf("  %-8s %-14s %s -> %s\n", call.ID, guid,
			dash(call.Calling), dash(call.Called))
		fmt.Println(strings.TrimRight(fmt.Sprintf("           %s  %-8s  %-10s %s",
			call.Start.Format("15:04:05.000"), round(call.Duration()),
			call.State, strings.TrimSpace(call.Result+" "+call.Cause)), " "))
		if call.IEC != "" {
			fmt.Printf("           IEC=%s\n", call.IEC)
		}
		for _, l := range call.Legs {
			fmt.Printf("    %-8s call entry %-8s %-9s %-10s %d record(s)\n",
				l.ID, legID(l), dash(l.Direction), l.State, len(l.Records))
		}
		for _, w := range call.Warnings {
			fmt.Printf("    ! %s\n", w)
		}
	}
	if shown == 0 {
		fmt.Println("  (none)")
	}
	if hidden := len(grouped.Calls) - shown; hidden > 0 {
		fmt.Printf("  %d OPTIONS keepalive(s) hidden; -keepalives shows them\n", hidden)
	}
	if n := len(grouped.Unattached); n > 0 {
		fmt.Printf("\n%d record(s) belong to no call:\n", n)
		for _, i := range grouped.Unattached {
			fmt.Printf("  %s  %s\n", records[i].Time.Format("15:04:05.000"), recordSummary(records[i]))
		}
	}
}

func legID(l *correlate.Leg) string {
	if l.CallEntryID == parse.NoCallID {
		return "unknown"
	}
	return fmt.Sprint(l.CallEntryID)
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func round(d time.Duration) string {
	if d < time.Minute {
		return d.Round(time.Millisecond).String()
	}
	return d.Round(time.Second).String()
}

func sanitizeCmd(args []string) error {
	fs := flag.NewFlagSet("sanitize", flag.ExitOnError)
	out := fs.String("o", "-", "write to this file instead of standard output")
	var literals stringList
	fs.Var(&literals, "literal", "replace this exact string wherever it appears (repeatable: hostnames, customer names)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("sanitize needs exactly one file (or \"-\")")
	}

	f, err := open(fs.Arg(0))
	if err != nil {
		return err
	}
	defer f.Close()

	w := io.WriteCloser(nopWriteCloser{os.Stdout})
	if *out != "-" {
		if w, err = os.Create(*out); err != nil {
			return err
		}
		defer w.Close()
	}

	s := sanitize.New()
	for _, l := range literals {
		s.AddLiteral(l)
	}
	if err := s.Reader(f, w); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "sanitized: %s\n", s.Stats())
	fmt.Fprintln(os.Stderr, "read the output before you commit it: the rules are patterns, not understanding.")
	return nil
}

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }
