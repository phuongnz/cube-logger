package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/phuongnz/cube-logger/internal/calls"
	"github.com/phuongnz/cube-logger/internal/ingest"
	"github.com/phuongnz/cube-logger/internal/live"
	"github.com/phuongnz/cube-logger/internal/load"
	"github.com/phuongnz/cube-logger/internal/session"
	"github.com/phuongnz/cube-logger/internal/store"
	"github.com/phuongnz/cube-logger/internal/web"
)

// openCmd loads saved files and serves the same views the live path serves.
// There is no second UI for files: a saved log and a live stream are the same
// records, so they get the same table, the same call list and the same ladder.
func openCmd(args []string) error {
	fs := flag.NewFlagSet("open", flag.ExitOnError)
	httpAddr := fs.String("http", "127.0.0.1:8514",
		"address for the web UI (loopback only; the UI refuses a non-local client)")
	capacity := fs.Int("buffer", store.DefaultCap, "how many records to keep in memory")
	maxCalls := fs.Int("calls", calls.DefaultMax, "how many calls to keep in the call list")
	title := fs.String("title", "", "name for this session, shown in the browser tab")
	year := fs.Int("year", 0, "calendar year of the first record (IOS does not log one; 0 means this year)")
	source := fs.String("source", "", "name for the device, when the file does not name one (default: the file name)")
	out := fs.String("o", "", "write the records to this session file and exit, instead of serving")
	gz := fs.Bool("gzip", false, "compress the session file written by -o")
	var names labelList
	fs.Var(&names, "name", "rename a device, as address=name (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return fmt.Errorf("open needs at least one file (or \"-\")")
	}

	opt := load.Options{Year: *year, Source: *source, Rename: names.rename}
	var recs []*live.Record
	var sources []live.SourceStat
	multi := fs.NArg() > 1
	for _, name := range fs.Args() {
		r, err := openFile(name, opt)
		if err != nil {
			return err
		}
		recs = append(recs, r.records...)
		sources = append(sources, r.sources...)
		r.report(name)
	}
	if multi {
		// Several files are normally several devices over the same period, and
		// reading them one after the other would show the second device's
		// whole day below the first's. The device's own clock is the only
		// order that makes sense across files; within one file the order the
		// file had is kept, which is what a stable sort does.
		sort.SliceStable(recs, func(i, j int) bool { return recs[i].Time.Before(recs[j].Time) })
		sources = mergeStats(sources)
		fmt.Fprintf(os.Stderr, "%d file(s) merged in clock order\n", fs.NArg())
	}
	if len(recs) == 0 {
		return fmt.Errorf("nothing in %s could be read as CUBE output — "+
			"is it a log file? (\"cube-logger parse\" says what it made of it)",
			strings.Join(fs.Args(), ", "))
	}

	if *out != "" {
		return writeSession(*out, *gz, session.Header{
			Title:  titleOr(*title, fs.Args()),
			Year:   recs[0].Time.Year(),
			Source: strings.Join(fs.Args(), ", "),
		}, recs, sources)
	}

	st := store.New(*capacity)
	ix := calls.New(*maxCalls)
	for _, e := range st.Add(recs...) {
		if e.Record != nil && e.Record.Record != nil {
			ix.Add(e.ID, e.Record.Record)
		}
	}
	srv := &web.Server{
		Store:   st,
		Calls:   ix,
		Sources: sources,
		Title:   titleOr(*title, fs.Args()),
	}
	if err := web.Open(*httpAddr, srv); err != nil {
		return fmt.Errorf("web: %w (is another cube-logger already running?)", err)
	}
	ss, cs := st.Stats(), ix.Stats()
	fmt.Printf("%d record(s), %d call(s) from %s\n", ss.Total, cs.Total, plural(len(sources), "device"))
	if ss.Evicted > 0 {
		fmt.Printf("  %d record(s) dropped to stay within -buffer=%d (the oldest go first)\n",
			ss.Evicted, ss.Cap)
	}
	fmt.Printf("open %s\n\nCtrl-C to stop.\n", srv.URL())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return srv.Serve(ctx)
}

// opened is one file, whichever of the two kinds it turned out to be.
type opened struct {
	records []*live.Record
	sources []live.SourceStat
	orphans []string
	lines   int
	format  string
	notes   []string
}

func (o *opened) report(name string) {
	fmt.Fprintf(os.Stderr, "%s: %s, %d record(s) from %s\n",
		name, o.format, len(o.records), plural(len(o.sources), "device"))
	for _, n := range o.notes {
		fmt.Fprintln(os.Stderr, "  note: "+n)
	}
}

// openFile reads one file, which is either a session this tool wrote or a log
// something else wrote. Which one is decided by looking, not by the name: a
// session file that was renamed is still a session file.
func openFile(name string, opt load.Options) (*opened, error) {
	f, err := open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	rd, isSession, err := session.Sniff(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if isSession {
		res, err := session.Read(rd, opt.Year)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		o := &opened{
			records: res.Records,
			sources: res.Sources,
			lines:   res.Skipped + len(res.Records),
			format:  "a saved session",
			notes:   res.Notes,
		}
		if res.Header.Title != "" {
			o.format += " (" + res.Header.Title + ")"
		}
		return o, nil
	}

	if opt.Source == "" {
		opt.Source = filepath.Base(name)
	}
	res, err := load.File(rd, opt)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return &opened{
		records: res.Records,
		sources: res.Sources,
		orphans: res.Orphans,
		lines:   res.Lines,
		format:  describe(res.Format, res.Lines),
		notes:   res.Notes,
	}, nil
}

func describe(f ingest.Format, lines int) string {
	return fmt.Sprintf("%d line(s) of %s", lines, f.Describe())
}

// writeSession is the converter: a big "show logging" capture becomes a
// session file that opens in a second and can be handed to someone else.
func writeSession(name string, gz bool, h session.Header, recs []*live.Record, sources []live.SourceStat) error {
	var w io.WriteCloser = nopWriteCloser{os.Stdout}
	if name != "-" {
		f, err := os.Create(name)
		if err != nil {
			return err
		}
		w = f
	}
	defer w.Close()

	sw, err := session.NewWriter(w, h, session.Options{Gzip: gz || strings.HasSuffix(name, ".gz")})
	if err != nil {
		return err
	}
	if err := sw.Records(recs...); err != nil {
		return err
	}
	if err := sw.Close(sources); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %d record(s) to %s\n", sw.Count(), name)
	return nil
}

// titleOr names the browser tab after the files when nothing better was given.
func titleOr(title string, files []string) string {
	if title != "" {
		return title
	}
	names := make([]string, 0, len(files))
	for _, f := range files {
		names = append(names, filepath.Base(f))
	}
	return strings.Join(names, ", ")
}

// mergeStats adds up the per-device totals of several files, since one device
// can appear in more than one of them.
func mergeStats(in []live.SourceStat) []live.SourceStat {
	by := map[string]*live.SourceStat{}
	var order []string
	for _, s := range in {
		if cur, ok := by[s.Source]; ok {
			cur.Lines += s.Lines
			cur.Records += s.Records
			cur.LostRecords += s.LostRecords
			cur.Orphans += s.Orphans
			if !s.First.IsZero() && (cur.First.IsZero() || s.First.Before(cur.First)) {
				cur.First = s.First
			}
			if s.Last.After(cur.Last) {
				cur.Last = s.Last
			}
			continue
		}
		c := s
		by[s.Source] = &c
		order = append(order, s.Source)
	}
	sort.Strings(order)
	out := make([]live.SourceStat, 0, len(order))
	for _, n := range order {
		out = append(out, *by[n])
	}
	return out
}

// labelList is the -name flag: a device is an address on the wire and a name
// on a network diagram, and the person reading the table thinks in names.
type labelList struct {
	pairs []string
	to    map[string]string
}

func (l *labelList) String() string { return strings.Join(l.pairs, ",") }

func (l *labelList) Set(v string) error {
	from, to, ok := strings.Cut(v, "=")
	if !ok || from == "" || to == "" {
		return fmt.Errorf("a name is address=name, for example 198.51.100.9=cube-a")
	}
	if l.to == nil {
		l.to = map[string]string{}
	}
	l.to[from] = to
	l.pairs = append(l.pairs, v)
	return nil
}

func (l *labelList) rename(s string) string {
	if n, ok := l.to[s]; ok {
		return n
	}
	return s
}

func (l *labelList) empty() bool { return len(l.to) == 0 }

func plural(n int, unit string) string {
	s := ""
	if n != 1 {
		s = "s"
	}
	return fmt.Sprintf("%d %s%s", n, unit, s)
}
