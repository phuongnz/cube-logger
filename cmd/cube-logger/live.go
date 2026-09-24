package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/phuongnz/cube-logger/internal/calls"
	"github.com/phuongnz/cube-logger/internal/listen"
	"github.com/phuongnz/cube-logger/internal/live"
	"github.com/phuongnz/cube-logger/internal/session"
	"github.com/phuongnz/cube-logger/internal/store"
	"github.com/phuongnz/cube-logger/internal/web"
)

// tickInterval drives the reassembler's clock. The reassembler releases a
// record when the next head line arrives, which on a quiet router may be
// minutes away; the tick is what makes the last record of a burst appear
// within the idle timeout instead of whenever the router next says something.
const tickInterval = 100 * time.Millisecond

func liveCmd(args []string) error {
	fs := flag.NewFlagSet("live", flag.ExitOnError)
	addr := fs.String("listen", fmt.Sprintf(":%d", listen.DefaultPort),
		"UDP address to receive syslog on")
	httpAddr := fs.String("http", "127.0.0.1:8514",
		"address for the web UI (loopback only; the UI refuses a non-local client)")
	allowSpec := fs.String("allow", "",
		"comma-separated IPs or CIDRs allowed to send (default: anything that reaches the socket)")
	capacity := fs.Int("buffer", store.DefaultCap, "how many records to keep in memory")
	maxCalls := fs.Int("calls", calls.DefaultMax, "how many calls to keep in the call list")
	title := fs.String("title", "", "name for this session, shown in the browser tab")
	year := fs.Int("year", 0, "calendar year (IOS does not log one; 0 means this year)")
	quiet := fs.Bool("quiet", false, "do not print a line per source as it first appears")
	save := fs.String("save", "", "also write every record to this session file as it arrives")
	gz := fs.Bool("gzip", false, "compress the session file written by -save")
	var names labelList
	fs.Var(&names, "name", "rename a device, as address=name (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("live takes no arguments, only flags")
	}

	allow, err := listen.ParseAllowlist(*allowSpec)
	if err != nil {
		return err
	}
	ln, err := listen.Open(*addr, allow)
	if err != nil {
		return err
	}
	defer ln.Close()

	re := live.New()
	re.Year = *year
	st := store.New(*capacity)
	ix := calls.New(*maxCalls)
	add := &feeder{st: st, ix: ix}
	if *save != "" {
		f, err := os.Create(*save)
		if err != nil {
			return err
		}
		defer f.Close()
		sw, err := session.NewWriter(f, session.Header{
			Title:  *title,
			Year:   *year,
			Listen: ln.Addr(),
		}, session.Options{Gzip: *gz || strings.HasSuffix(*save, ".gz")})
		if err != nil {
			return err
		}
		add.sw = sw
		fmt.Printf("saving every record to %s\n", *save)
	}
	srv := &web.Server{Store: st, Live: re, Listener: ln, Calls: ix, Title: *title, Year: *year}
	srv.Add = add.records
	if err := web.Open(*httpAddr, srv); err != nil {
		return fmt.Errorf("web: %w (is another cube-logger already running?)", err)
	}

	printBanner(ln, srv)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Three goroutines and a wait: the socket, the reassembler's clock, and the
	// web server. Records only ever enter the store through the feeder, so
	// ordering by ID stays the order they were reassembled in and the call
	// index sees the stream in that same order.
	errs := make(chan error, 3)
	seen := map[string]bool{}
	go func() {
		errs <- ln.Run(ctx, func(d live.Datagram) {
			if !names.empty() {
				d.Source = names.rename(d.Source)
			}
			if !*quiet && !seen[d.Source] {
				// Safe from the outside: only this goroutine touches `seen`.
				seen[d.Source] = true
				fmt.Fprintf(os.Stderr, "receiving from %s\n", d.Source)
			}
			add.records(re.Datagram(d)...)
		})
	}()
	go func() {
		t := time.NewTicker(tickInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				errs <- nil
				return
			case now := <-t.C:
				add.records(re.Tick(now)...)
			}
		}
	}()
	go func() { errs <- srv.Serve(ctx) }()

	// The first error wins, and cancelling brings the other two down.
	err = <-errs
	stop()
	<-errs
	<-errs

	// Whatever was half-assembled is still worth showing; it is written to the
	// store rather than dropped, so a -buffer dump after Ctrl-C is complete.
	add.records(re.Flush()...)
	printLiveSummary(ln, st, re, ix)
	if add.sw != nil {
		if cerr := add.sw.Close(re.Stats()); cerr != nil && err == nil {
			err = cerr
		}
		fmt.Fprintf(os.Stderr, "  %d record(s) written to %s\n", add.sw.Count(), *save)
	}
	return err
}

// feeder is the one door into the store, and the only thing that feeds the
// call index.
//
// Two goroutines add records — the socket and the reassembler's clock — and
// the store delivers to subscribers after it has released its own lock, so
// subscription order is not ID order. The correlator behind the index reads a
// stream and has to be given records in the order they happened, so it is fed
// here, inside one lock, rather than from a subscription.
type feeder struct {
	mu sync.Mutex
	st *store.Store
	ix *calls.Index
	// sw is the session file, when one was asked for. It is written inside the
	// same lock as the store, so the file is in the order the ring is in — and
	// a session saved from a crash is still a session.
	sw *session.Writer
}

func (f *feeder) records(recs ...*live.Record) {
	if len(recs) == 0 {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range f.st.Add(recs...) {
		if e.Record != nil && e.Record.Record != nil {
			f.ix.Add(e.ID, e.Record.Record)
		}
		if f.sw != nil {
			// A failing disk must not stop the live view: the error surfaces
			// when the file is closed.
			_ = f.sw.Record(e.Record)
		}
	}
}

func printBanner(ln *listen.Listener, srv *web.Server) {
	fmt.Printf("listening for syslog on %s/udp\n", ln.Addr())
	if a := ln.Allowlist(); !a.Empty() {
		fmt.Printf("  accepting only %s\n", a)
	}
	fmt.Printf("open %s\n", srv.URL())
	fmt.Println()
	fmt.Println("on the CUBE:")
	for _, line := range routerConfig(ln.Addr()) {
		fmt.Println("  " + line)
	}
	fmt.Println()
	fmt.Println("Ctrl-C to stop.")
}

// routerConfig is the three lines a CUBE needs before anything arrives here.
// "service sequence-numbers" is not optional for this tool: without the outer
// counter there is no way to put reordered datagrams back or to see loss.
func routerConfig(addr string) []string {
	port := fmt.Sprint(listen.DefaultPort)
	if _, p, err := net.SplitHostPort(addr); err == nil && p != "" {
		port = p
	}
	return []string{
		"logging host <this machine's IP> transport udp port " + port,
		"logging trap debugging",
		"service sequence-numbers",
	}
}

func printLiveSummary(ln *listen.Listener, st *store.Store, re *live.Reassembler, ix *calls.Index) {
	ls := ln.Stats()
	ss := st.Stats()
	cs := ix.Stats()
	fmt.Fprintf(os.Stderr, "\n%d datagram(s), %d byte(s), %d record(s), %d call(s)\n",
		ls.Datagrams, ls.Bytes, ss.Total, cs.Total)
	if cs.Evicted > 0 {
		fmt.Fprintf(os.Stderr, "  %d call(s) dropped to stay within -calls=%d\n", cs.Evicted, cs.Max)
	}
	if ls.Blocked > 0 {
		fmt.Fprintf(os.Stderr, "  %d datagram(s) blocked by the allowlist\n", ls.Blocked)
	}
	for _, s := range re.Stats() {
		parts := []string{fmt.Sprintf("%d line(s), %d record(s)", s.Lines, s.Records)}
		if s.LostLines > 0 {
			parts = append(parts, fmt.Sprintf("%d line(s) lost or rate-limited", s.LostLines))
		}
		if s.LostRecords > 0 {
			parts = append(parts, fmt.Sprintf("%d record(s) lost or rate-limited", s.LostRecords))
		}
		if s.Reordered > 0 {
			parts = append(parts, fmt.Sprintf("%d reordered", s.Reordered))
		}
		if s.Late > 0 {
			parts = append(parts, fmt.Sprintf("%d too late", s.Late))
		}
		if s.Duplicate > 0 {
			parts = append(parts, fmt.Sprintf("%d duplicate", s.Duplicate))
		}
		fmt.Fprintf(os.Stderr, "  %s: %s\n", s.Source, strings.Join(parts, ", "))
	}
}
