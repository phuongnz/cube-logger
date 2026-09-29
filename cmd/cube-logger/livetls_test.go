package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phuongnz/cube-logger/internal/calls"
	"github.com/phuongnz/cube-logger/internal/listen"
	"github.com/phuongnz/cube-logger/internal/live"
	"github.com/phuongnz/cube-logger/internal/store"
	"github.com/phuongnz/cube-logger/internal/tlscert"
	"github.com/phuongnz/cube-logger/internal/web"
)

// Every one of these is refused before anything is bound, so a mistake costs
// a message rather than a port.
func TestLiveRejectsFlagsThatCannotWork(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"-listen", "off"}, "nothing to listen on"},
		{[]string{"-tls-name", "203.0.113.5"}, "need -tls"},
		{[]string{"-tls-client-ca", "ca.pem"}, "need -tls"},
		{[]string{"-tls", ":0", "-tls-cert", "a.pem"}, "go together"},
		{[]string{"-tls", ":0", "-tls-key", "a-key.pem"}, "go together"},
		{[]string{"-tls", ":0", "-tls-cert", "a.pem", "-tls-key", "a-key.pem", "-tls-name", "203.0.113.5"}, "not for -tls-cert"},
		{[]string{"extra"}, "no arguments"},
	}
	for _, tt := range tests {
		err := liveCmd(tt.args)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("live %v: error %v, want one containing %q", tt.args, err, tt.want)
		}
	}
}

func TestSetupTLSWithTheCertificatesItMakes(t *testing.T) {
	dir := t.TempDir()
	ts, err := setupTLS(dir, []string{"203.0.113.5"}, "", "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if ts.host != "203.0.113.5" {
		t.Errorf("host %q, want the first -tls-name", ts.host)
	}
	about := strings.Join(ts.about, "\n")
	if !strings.Contains(about, filepath.Join(dir, tlscert.CAFile)) || !strings.Contains(about, "no router trusts it yet") {
		t.Errorf("banner does not say a new authority needs importing:\n%s", about)
	}
	if !strings.Contains(ts.trust, "cube-logger cert") {
		t.Errorf("trust %q does not say where the steps are", ts.trust)
	}
	if ts.config.ClientAuth != tls.NoClientCert || ts.clientCA {
		t.Error("asked a router for a certificate without -tls-client-ca")
	}
	if got := ts.config.Certificates[0].Leaf.Subject.CommonName; got != "203.0.113.5" {
		t.Errorf("serving a certificate for %q", got)
	}

	// Next session, nothing to say.
	ts, err = setupTLS(dir, []string{"203.0.113.5"}, "", "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(ts.about) != 1 {
		t.Errorf("a second session still has news: %q", ts.about)
	}

	// Without a name, the engineer picks the address.
	ts, err = setupTLS(dir, nil, "", "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if ts.host != "<this machine's IP>" {
		t.Errorf("host %q, want a placeholder", ts.host)
	}
}

func TestSetupTLSWithACertificateGiven(t *testing.T) {
	dir := t.TempDir()
	if _, err := tlscert.Ensure(dir, []string{"logger.example"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	cert, key, ca := filepath.Join(dir, "server.pem"), filepath.Join(dir, "server-key.pem"), filepath.Join(dir, tlscert.CAFile)

	ts, err := setupTLS("", nil, cert, key, ca, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	about := strings.Join(ts.about, "\n")
	if !strings.Contains(about, `certificate "logger.example" issued by "cube-logger CA`) {
		t.Errorf("banner does not describe the certificate:\n%s", about)
	}
	if !strings.Contains(ts.trust, cert) {
		t.Errorf("trust %q does not name the certificate", ts.trust)
	}
	if ts.config.ClientAuth != tls.RequireAndVerifyClientCert || !ts.clientCA || !strings.Contains(about, ca) {
		t.Error("-tls-client-ca did not make a router certificate required")
	}

	for name, args := range map[string][]string{
		"expired":            {cert, key, "", "2099"},
		"key does not fit":   {cert, ca, "", ""},
		"missing":            {filepath.Join(dir, "none.pem"), key, "", ""},
		"client CA missing":  {cert, key, filepath.Join(dir, "none.pem"), ""},
		"client CA is a key": {cert, key, key, ""},
	} {
		now := time.Now()
		if args[3] != "" {
			now = time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
		}
		if _, err := setupTLS("", nil, args[0], args[1], args[2], now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestTLSRouterConfig(t *testing.T) {
	got := strings.Join(tlsRouterConfig("[::]:7514", "203.0.113.5", "ecdhe-ecdsa-aes-gcm-sha2", true), "\n")
	want := `logging tls-profile CUBE-LOGGER
 tls-version TLSv1.2
 ciphersuite ecdhe-ecdsa-aes-gcm-sha2
 client-id-trustpoint <the trustpoint holding this router's own certificate>
logging host 203.0.113.5 transport tls port 7514 profile CUBE-LOGGER
logging trap debugging
service sequence-numbers`
	if got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
}

func TestEventLogSaysEachThingOnceInAWhile(t *testing.T) {
	var out bytes.Buffer
	now := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	l := &eventLog{w: &out, now: func() time.Time { return now },
		rename: func(s string) string { return strings.ReplaceAll(s, "192.0.2.1", "cube-a") }}
	fail := listen.Event{Kind: listen.HandshakeFailed, Source: "192.0.2.1", Detail: "no cipher suite in common",
		Hint: `on the router: "ciphersuite ecdhe-rsa-aes-gcm-sha2" in the logging tls-profile`}

	l.print(fail)
	now = now.Add(time.Second)
	l.print(fail) // the router retrying
	l.print(listen.Event{Kind: listen.HandshakeFailed, Source: "192.0.2.2", Detail: "no cipher suite in common"})
	now = now.Add(repeatWindow)
	l.print(fail)

	got := out.String()
	if n := strings.Count(got, "cube-a: TLS handshake failed"); n != 2 {
		t.Errorf("the repeated failure was printed %d time(s), want 2 (once, and once after the window):\n%s", n, got)
	}
	if !strings.Contains(got, "192.0.2.2: TLS handshake failed") {
		t.Errorf("a failure from another router was held back:\n%s", got)
	}
	if strings.Contains(got, "192.0.2.1") {
		t.Errorf("-name was not applied:\n%s", got)
	}
	if !strings.Contains(got, `"ciphersuite ecdhe-rsa-aes-gcm-sha2"`) {
		t.Errorf("the hint was lost:\n%s", got)
	}
}

func TestEventLogQuietKeepsFailures(t *testing.T) {
	var out bytes.Buffer
	l := &eventLog{w: &out, quiet: true, now: time.Now}
	l.print(listen.Event{Kind: listen.Connected, Source: "192.0.2.1", Detail: "TLS 1.3"})
	l.print(listen.Event{Kind: listen.Disconnected, Source: "192.0.2.1", Detail: "closed by the router"})
	l.print(listen.Event{Kind: listen.HandshakeFailed, Source: "192.0.2.1", Detail: "no handshake within 10s"})
	l.print(listen.Event{Kind: listen.Format, Source: "192.0.2.1", Detail: "RFC 5424"})
	got := out.String()
	if strings.Contains(got, "connected") {
		t.Errorf("-quiet printed a connect or disconnect:\n%s", got)
	}
	if !strings.Contains(got, "handshake failed") || !strings.Contains(got, "RFC 5424") {
		t.Errorf("-quiet hid a problem:\n%s", got)
	}
}

// A scan from many addresses must not grow the log's memory without bound.
func TestEventLogForgetsOldEvents(t *testing.T) {
	now := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	l := &eventLog{w: &bytes.Buffer{}, now: func() time.Time { return now }}
	for i := range 3 * maxRemembered {
		now = now.Add(time.Second)
		l.print(listen.Event{Kind: listen.HandshakeFailed, Source: strings.Repeat("x", i%50) + string(rune('a'+i%26)), Detail: time.Duration(i).String()})
		if len(l.last) > maxRemembered {
			t.Fatalf("%d events remembered, limit %d", len(l.last), maxRemembered)
		}
	}
}

// UDP and TLS deliver on different goroutines. Each device is announced once
// and reassembled whole, whichever input it arrived on.
func TestIntakeTakesUDPAndTLSAtOnce(t *testing.T) {
	lines, err := readLines(fixture("basic_call.txt"))
	if err != nil {
		t.Fatal(err)
	}
	feed := func(in *intake, source string) {
		for i, line := range lines {
			in.datagram(live.Datagram{Source: source, Payload: wrap(23, 7, uint64(i+1), line), Time: time.Now()})
		}
	}
	newIntake := func(announce io.Writer) (*intake, *live.Reassembler) {
		re := live.New()
		re.Year = 2026
		return &intake{re: re, add: &feeder{st: store.New(10000), ix: calls.New(0)}, announce: announce,
			rename: func(s string) string {
				if s == "192.0.2.1" {
					return "cube-a"
				}
				return s
			}}, re
	}

	alone, re := newIntake(nil)
	feed(alone, "192.0.2.9")
	alone.add.records(re.Flush()...)
	want := re.Stats()[0].Records
	if want == 0 {
		t.Fatal("the fixture made no records")
	}

	var announced bytes.Buffer
	in, re := newIntake(&announced)
	var wg sync.WaitGroup
	for _, src := range []string{"192.0.2.1", "192.0.2.2"} {
		wg.Add(1)
		go func() { defer wg.Done(); feed(in, src) }()
	}
	wg.Wait()
	in.add.records(re.Flush()...)

	if n := len(re.Stats()); n != 2 {
		t.Fatalf("%d source(s), want 2", n)
	}
	for _, s := range re.Stats() {
		if s.Records != want || s.LostLines != 0 {
			t.Errorf("%s: %d record(s), %d line(s) lost; alone it is %d record(s)", s.Source, s.Records, s.LostLines, want)
		}
	}
	if got := announced.String(); got != "receiving from cube-a\nreceiving from 192.0.2.2\n" &&
		got != "receiving from 192.0.2.2\nreceiving from cube-a\n" {
		t.Errorf("announced:\n%s", got)
	}
}

// The browser is told about both inputs, and about TLS connections as they
// come and go.
func TestStatusShowsBothInputs(t *testing.T) {
	dir := t.TempDir()
	certs, err := tlscert.Ensure(dir, []string{"127.0.0.1"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	allow, _ := listen.ParseAllowlist("127.0.0.1")
	ln, err := listen.Open("127.0.0.1:0", allow)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	tl, err := listen.OpenTLS("127.0.0.1:0", allow, listen.ServerConfig(certs.Server, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer tl.Close()
	srv := &web.Server{Store: store.New(10), Listener: ln, TLS: tl}
	if err := web.Open("127.0.0.1:0", srv); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)
	go tl.Run(ctx, func(live.Datagram) {})

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certs.CAPEM)
	c, err := tls.Dial("tcp", tl.Addr(), &tls.Config{RootCAs: roots, ServerName: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	waitFor(t, "the connection to count", func() bool { return tl.Stats().Active == 1 })

	var st struct {
		Listen    string           `json:"listen"`
		UDPListen string           `json:"udpListen"`
		TLSListen string           `json:"tlsListen"`
		Allow     string           `json:"allow"`
		TLS       *listen.TLSStats `json:"tls"`
	}
	getJSON(t, srv.URL()+"/api/stats", &st)
	if st.Listen != ln.Addr()+"/udp, "+tl.Addr()+"/tls" {
		t.Errorf("listen = %q", st.Listen)
	}
	if st.UDPListen != ln.Addr() || st.TLSListen != tl.Addr() {
		t.Errorf("udpListen = %q, tlsListen = %q", st.UDPListen, st.TLSListen)
	}
	if st.Allow != "127.0.0.1/32" && st.Allow != "127.0.0.1" {
		t.Errorf("allow = %q", st.Allow)
	}
	if st.TLS == nil || st.TLS.Active != 1 || st.TLS.Connections != 1 {
		t.Errorf("tls = %+v, want one connection open", st.TLS)
	}
}

func TestLiveSummaryWithTLSOnly(t *testing.T) {
	// The summary must not assume a UDP socket: -listen off is a real setup.
	certs, err := tlscert.Ensure(t.TempDir(), []string{"127.0.0.1"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	tl, err := listen.OpenTLS("127.0.0.1:0", nil, listen.ServerConfig(certs.Server, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer tl.Close()
	out := capture(t, &os.Stderr, func() { printLiveSummary(nil, tl, store.New(10), live.New(), calls.New(0)) })
	if !strings.Contains(out, "0 TLS message(s), 0 byte(s) in 0 connection(s), 0 record(s)") {
		t.Errorf("summary:\n%s", out)
	}
}

// capture returns what f writes to the file *std points at.
func capture(t *testing.T, std **os.File, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := *std
	*std = w
	done := make(chan string)
	go func() {
		var b bytes.Buffer
		b.ReadFrom(r)
		done <- b.String()
	}()
	f()
	*std = saved
	w.Close()
	return <-done
}

func TestBannerForTLSOnly(t *testing.T) {
	ts, err := setupTLS(t.TempDir(), []string{"203.0.113.5"}, "", "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	tl, err := listen.OpenTLS("127.0.0.1:0", nil, ts.config)
	if err != nil {
		t.Fatal(err)
	}
	defer tl.Close()
	allow, _ := listen.ParseAllowlist("203.0.113.0/24")
	srv := &web.Server{Store: store.New(10), TLS: tl}
	out := capture(t, &os.Stdout, func() { printBanner(nil, tl, ts, allow, srv) })
	_, port, _ := strings.Cut(tl.Addr(), "127.0.0.1:")
	for _, want := range []string{
		"listening for syslog on " + tl.Addr() + "/tls\n",
		"no router trusts it yet",
		"accepting only 203.0.113.0/24",
		`once it trusts cube-logger's certificate authority ("cube-logger cert" prints how):`,
		" ciphersuite ecdhe-rsa-aes-gcm-sha2\n",
		"logging host 203.0.113.5 transport tls port " + port + " profile CUBE-LOGGER",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("banner lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "/udp") || strings.Contains(out, "transport udp") {
		t.Errorf("banner talks about UDP with -listen off:\n%s", out)
	}
}
