package main

import (
	"context"
	"flag"
	"fmt"
	"io"
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
		`UDP address to receive syslog on, or "off"`)
	tlsAddr := fs.String("tls", "",
		fmt.Sprintf("also receive syslog over TLS on this address, such as :%d (\"cube-logger cert\" prints the router side)", listen.DefaultTLSPort))
	tlsDir := fs.String("tls-dir", "", "directory for the certificates cube-logger makes (default: the user configuration directory)")
	var tlsNames stringList
	fs.Var(&tlsNames, "tls-name", "an address or host name the router uses to reach this machine, such as a\n"+
		"port-forwarded public address; the certificate names it (repeatable)")
	tlsCert := fs.String("tls-cert", "", "serve this PEM certificate, or chain, instead of the one cube-logger makes")
	tlsKey := fs.String("tls-key", "", "the PEM private key of -tls-cert")
	clientCA := fs.String("tls-client-ca", "",
		"accept TLS only from routers presenting a certificate issued by this PEM CA")
	httpAddr := fs.String("http", "127.0.0.1:8514",
		"address for the web UI (loopback only; the UI refuses a non-local client)")
	allowSpec := fs.String("allow", "",
		"comma-separated IPs or CIDRs allowed to send (default: anything that reaches the socket)")
	capacity := fs.Int("buffer", store.DefaultCap, "how many records to keep in memory")
	maxCalls := fs.Int("calls", calls.DefaultMax, "how many calls to keep in the call list")
	title := fs.String("title", "", "name for this session, shown in the browser tab")
	year := fs.Int("year", 0, "calendar year (IOS does not log one; 0 means this year)")
	quiet := fs.Bool("quiet", false, "do not print a line per source as it first appears, nor TLS connects and disconnects")
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
	udpOn := *addr != "off"
	tlsOn := *tlsAddr != ""
	switch {
	case !udpOn && !tlsOn:
		return fmt.Errorf(`nothing to listen on: -listen is "off" and there is no -tls`)
	case !tlsOn && (*tlsDir != "" || len(tlsNames) > 0 || *tlsCert != "" || *tlsKey != "" || *clientCA != ""):
		return fmt.Errorf("the -tls-… flags need -tls, the address to receive TLS on")
	case (*tlsCert == "") != (*tlsKey == ""):
		return fmt.Errorf("-tls-cert and -tls-key go together")
	case *tlsCert != "" && (*tlsDir != "" || len(tlsNames) > 0):
		return fmt.Errorf("-tls-dir and -tls-name are for the certificate cube-logger makes, not for -tls-cert")
	}

	allow, err := listen.ParseAllowlist(*allowSpec)
	if err != nil {
		return err
	}
	var ln *listen.Listener
	if udpOn {
		if ln, err = listen.Open(*addr, allow); err != nil {
			return err
		}
		defer ln.Close()
	}
	var tl *listen.TLSListener
	var ts *tlsSetup
	if tlsOn {
		ts, err = setupTLS(*tlsDir, tlsNames, *tlsCert, *tlsKey, *clientCA, time.Now())
		if err != nil {
			return err
		}
		if tl, err = listen.OpenTLS(*tlsAddr, allow, ts.config); err != nil {
			return err
		}
		defer tl.Close()
		el := &eventLog{w: os.Stderr, quiet: *quiet, now: time.Now}
		if !names.empty() {
			el.rename = names.rename
		}
		tl.Events = el.print
	}

	re := live.New()
	re.Year = *year
	st := store.New(*capacity)
	ix := calls.New(*maxCalls)
	add := &feeder{st: st, ix: ix}
	srv := &web.Server{Store: st, Live: re, Listener: ln, TLS: tl, Calls: ix, Title: *title, Year: *year}
	if *save != "" {
		f, err := os.Create(*save)
		if err != nil {
			return err
		}
		defer f.Close()
		sw, err := session.NewWriter(f, session.Header{
			Title:  *title,
			Year:   *year,
			Listen: srv.ListenAddr(),
		}, session.Options{Gzip: *gz || strings.HasSuffix(*save, ".gz")})
		if err != nil {
			return err
		}
		add.sw = sw
		fmt.Printf("saving every record to %s\n", *save)
	}
	srv.Add = add.records
	if err := web.Open(*httpAddr, srv); err != nil {
		return fmt.Errorf("web: %w (is another cube-logger already running?)", err)
	}
	in := &intake{re: re, add: add}
	if !names.empty() {
		in.rename = names.rename
	}
	if !*quiet {
		in.announce = os.Stderr
	}

	printBanner(ln, tl, ts, allow, srv)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// A goroutine per input, one for the reassembler's clock and one for the
	// web server. Records only ever enter the store through the feeder, so
	// ordering by ID stays the order they were reassembled in and the call
	// index sees the stream in that same order.
	errs := make(chan error, 4)
	running := 0
	run := func(f func() error) {
		running++
		go func() { errs <- f() }()
	}
	if ln != nil {
		run(func() error { return ln.Run(ctx, in.datagram) })
	}
	if tl != nil {
		run(func() error { return tl.Run(ctx, in.datagram) })
	}
	run(func() error {
		t := time.NewTicker(tickInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return nil
			case now := <-t.C:
				add.records(re.Tick(now)...)
			}
		}
	})
	run(func() error { return srv.Serve(ctx) })

	// The first error wins, and cancelling brings the others down.
	err = <-errs
	stop()
	for range running - 1 {
		<-errs
	}

	// Whatever was half-assembled is still worth showing; it is written to the
	// store rather than dropped, so a -buffer dump after Ctrl-C is complete.
	add.records(re.Flush()...)
	printLiveSummary(ln, tl, st, re, ix)
	if add.sw != nil {
		if cerr := add.sw.Close(re.Stats()); cerr != nil && err == nil {
			err = cerr
		}
		fmt.Fprintf(os.Stderr, "  %d record(s) written to %s\n", add.sw.Count(), *save)
	}
	return err
}

// intake is where every input hands its datagrams: the UDP socket, and the
// TLS connections, which the TLS listener already hands over one at a time.
type intake struct {
	re  *live.Reassembler
	add *feeder
	// rename is -name, when it was given.
	rename func(string) string
	// announce is where a device is reported the first time it is heard from;
	// nil with -quiet.
	announce io.Writer

	// mu makes UDP and TLS take turns. That keeps seen safe, and it hands
	// what the reassembler returns to the feeder in the order it came out,
	// which two inputs racing between the two calls would not.
	mu   sync.Mutex
	seen map[string]bool
}

func (in *intake) datagram(d live.Datagram) {
	if in.rename != nil {
		d.Source = in.rename(d.Source)
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.announce != nil && !in.seen[d.Source] {
		if in.seen == nil {
			in.seen = map[string]bool{}
		}
		in.seen[d.Source] = true
		fmt.Fprintf(in.announce, "receiving from %s\n", d.Source)
	}
	in.add.records(in.re.Datagram(d)...)
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

func printBanner(ln *listen.Listener, tl *listen.TLSListener, ts *tlsSetup, allow *listen.Allowlist, srv *web.Server) {
	if ln != nil {
		fmt.Printf("listening for syslog on %s/udp\n", ln.Addr())
	}
	if tl != nil {
		fmt.Printf("listening for syslog on %s/tls\n", tl.Addr())
		for _, line := range ts.about {
			fmt.Println("  " + line)
		}
	}
	if !allow.Empty() {
		fmt.Printf("  accepting only %s\n", allow)
	}
	fmt.Printf("open %s\n", srv.URL())
	if ln != nil {
		fmt.Println()
		if tl != nil {
			fmt.Println("on the CUBE, over UDP:")
		} else {
			fmt.Println("on the CUBE:")
		}
		for _, line := range routerConfig(ln.Addr()) {
			fmt.Println("  " + line)
		}
	}
	if tl != nil {
		fmt.Println()
		fmt.Printf("on the CUBE, over TLS, once it trusts %s:\n", ts.trust)
		for _, line := range tlsRouterConfig(tl.Addr(), ts.host, listen.SuiteKeyword(ts.config), ts.clientCA) {
			fmt.Println("  " + line)
		}
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

func printLiveSummary(ln *listen.Listener, tl *listen.TLSListener, st *store.Store, re *live.Reassembler, ix *calls.Index) {
	ss := st.Stats()
	cs := ix.Stats()
	var got []string
	var ls listen.Stats
	if ln != nil {
		ls = ln.Stats()
		got = append(got, fmt.Sprintf("%d datagram(s), %d byte(s)", ls.Datagrams, ls.Bytes))
	}
	var ts listen.TLSStats
	if tl != nil {
		ts = tl.Stats()
		got = append(got, fmt.Sprintf("%d TLS message(s), %d byte(s) in %d connection(s)", ts.Messages, ts.Bytes, ts.Connections))
	}
	fmt.Fprintf(os.Stderr, "\n%s, %d record(s), %d call(s)\n", strings.Join(got, "; "), ss.Total, cs.Total)
	if cs.Evicted > 0 {
		fmt.Fprintf(os.Stderr, "  %d call(s) dropped to stay within -calls=%d\n", cs.Evicted, cs.Max)
	}
	if ls.Blocked > 0 {
		fmt.Fprintf(os.Stderr, "  %d datagram(s) blocked by the allowlist\n", ls.Blocked)
	}
	if ts.Blocked > 0 {
		fmt.Fprintf(os.Stderr, "  %d TLS connection(s) blocked by the allowlist\n", ts.Blocked)
	}
	if ts.HandshakeFailures > 0 {
		fmt.Fprintf(os.Stderr, "  %d TLS handshake(s) failed\n", ts.HandshakeFailures)
	}
	if ts.Refused > 0 {
		fmt.Fprintf(os.Stderr, "  %d TLS connection(s) refused because too many were open\n", ts.Refused)
	}
	if ts.Errors > 0 {
		fmt.Fprintf(os.Stderr, "  %d TLS error(s): failed accepts, or streams that stopped being syslog\n", ts.Errors)
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
