package listen

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phuongnz/cube-logger/internal/live"
)

// testPKI is made once per test binary. The server key is RSA, like the one
// the tool makes, so the cipher-suite hints are judged as they will be for
// real. The client keys are ECDSA because they are quicker to make.
type testPKI struct {
	server tls.Certificate
	roots  *x509.CertPool // trusts server
	router tls.Certificate
	// routers trusts router, the way -tls-client-ca will.
	routers  *x509.CertPool
	stranger tls.Certificate // a client certificate nobody trusts
}

var (
	pkiOnce sync.Once
	pki     testPKI
)

func certs(t *testing.T) *testPKI {
	t.Helper()
	pkiOnce.Do(func() {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		var leaf *x509.Certificate
		pki.server, leaf = selfSigned("cube-logger test", rsaKey, x509.ExtKeyUsageServerAuth)
		pki.roots = x509.NewCertPool()
		pki.roots.AddCert(leaf)

		pki.router, leaf = selfSigned("router", ecKey(), x509.ExtKeyUsageClientAuth)
		pki.routers = x509.NewCertPool()
		pki.routers.AddCert(leaf)
		pki.stranger, _ = selfSigned("stranger", ecKey(), x509.ExtKeyUsageClientAuth)
	})
	return &pki
}

func ecKey() crypto.Signer {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}

// selfSigned makes a CA:TRUE certificate for the loopback, which is the shape
// Cisco's own examples import into a trustpoint.
func selfSigned(cn string, key crypto.Signer, eku x509.ExtKeyUsage) (tls.Certificate, *x509.Certificate) {
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{eku},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		panic(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: c}, c
}

// tlsCollector runs a TLS listener on an ephemeral loopback port and gathers
// what it receives and what it reports.
type tlsCollector struct {
	l      *TLSListener
	mu     sync.Mutex
	got    []live.Datagram
	events []Event
	cancel context.CancelFunc
	done   chan error
}

func startTLS(t *testing.T, allow *Allowlist, cfg *tls.Config, tweak func(*TLSListener)) *tlsCollector {
	t.Helper()
	l, err := OpenTLS("127.0.0.1:0", allow, cfg)
	if err != nil {
		t.Fatal(err)
	}
	c := &tlsCollector{l: l, done: make(chan error, 1)}
	l.Events = func(e Event) {
		c.mu.Lock()
		c.events = append(c.events, e)
		c.mu.Unlock()
	}
	if tweak != nil {
		tweak(l)
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	t.Cleanup(func() {
		cancel()
		select {
		case <-c.done:
		case <-time.After(5 * time.Second):
			t.Error("Run did not return after cancel")
		}
	})
	go func() {
		c.done <- l.Run(ctx, func(d live.Datagram) {
			c.mu.Lock()
			c.got = append(c.got, d)
			c.mu.Unlock()
		})
	}()
	return c
}

// client is what a router with a trustpoint holding the server certificate
// would offer: TLS 1.2 or later, Go's defaults otherwise.
func client(t *testing.T) *tls.Config {
	return &tls.Config{RootCAs: certs(t).roots, ServerName: "127.0.0.1"}
}

func (c *tlsCollector) dial(t *testing.T, cfg *tls.Config) (*tls.Conn, error) {
	t.Helper()
	d := &net.Dialer{Timeout: 2 * time.Second}
	return tls.DialWithDialer(d, "tcp", c.l.Addr(), cfg)
}

func (c *tlsCollector) send(t *testing.T, cfg *tls.Config, msgs ...string) {
	t.Helper()
	conn, err := c.dial(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for _, m := range msgs {
		if _, err := conn.Write([]byte(octet(m))); err != nil {
			t.Fatal(err)
		}
	}
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("waited for %s", what)
}

func (c *tlsCollector) messages(t *testing.T, n int) []live.Datagram {
	t.Helper()
	waitUntil(t, "messages", func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return len(c.got) >= n
	})
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]live.Datagram(nil), c.got...)
}

// event waits for the first event of kind.
func (c *tlsCollector) event(t *testing.T, kind EventKind) Event {
	t.Helper()
	var found Event
	waitUntil(t, "an event", func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		for _, e := range c.events {
			if e.Kind == kind {
				found = e
				return true
			}
		}
		return false
	})
	return found
}

func (c *tlsCollector) allEvents() []Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Event(nil), c.events...)
}

func TestTLSReceivesMessages(t *testing.T) {
	c := startTLS(t, nil, ServerConfig(certs(t).server, nil), nil)
	msgs := []string{
		"<191>400001: 400002: Sep 24 10:00:00.001 UTC: //1/ABC/SIP/Msg/ccsipDisplayMsg:\r",
		"<191>400002: Sent: \r",
		"<189>400003: 400004: Sep 24 10:00:01.000 UTC: %SYS-5-CONFIG_I: Configured from console\r",
	}
	c.send(t, client(t), msgs...)

	got := c.messages(t, len(msgs))
	for i, d := range got {
		if d.Payload != msgs[i] {
			t.Errorf("message %d = %q, want %q (the same shape as a UDP payload)", i, d.Payload, msgs[i])
		}
		if d.Source != "127.0.0.1" {
			t.Errorf("source %q, want the peer address without a port", d.Source)
		}
		if d.Time.IsZero() {
			t.Error("arrival time not set")
		}
	}
	e := c.event(t, Connected)
	if e.Source != "127.0.0.1" || !strings.Contains(e.Detail, "TLS 1.3") {
		t.Errorf("connected event %+v", e)
	}
	waitUntil(t, "the stats", func() bool { return c.l.Stats().Messages == 3 })
	st := c.l.Stats()
	if st.Connections != 1 || st.Bytes == 0 || st.Blocked != 0 || st.HandshakeFailures != 0 {
		t.Errorf("stats %+v", st)
	}
}

func TestTLSKeepsOneConnectionsOrder(t *testing.T) {
	c := startTLS(t, nil, ServerConfig(certs(t).server, nil), nil)
	var msgs []string
	for i := 0; i < 500; i++ {
		msgs = append(msgs, "<191>"+strconv.Itoa(i)+": line\r")
	}
	c.send(t, client(t), msgs...)
	got := c.messages(t, len(msgs))
	for i := range msgs {
		if got[i].Payload != msgs[i] {
			t.Fatalf("message %d = %q, want %q", i, got[i].Payload, msgs[i])
		}
	}
}

// A router that reconnects is the same device: its lines must land on the same
// stream, so the reassembler's sequence counter carries on across the gap.
func TestTLSReconnectIsTheSameSource(t *testing.T) {
	c := startTLS(t, nil, ServerConfig(certs(t).server, nil), nil)
	c.send(t, client(t), "<191>1: before\r")
	c.messages(t, 1)
	c.event(t, Disconnected)
	c.send(t, client(t), "<191>2: after\r")
	got := c.messages(t, 2)
	if got[0].Source != got[1].Source {
		t.Errorf("sources %q and %q, want one device", got[0].Source, got[1].Source)
	}
	if e := c.event(t, Disconnected); e.Detail != "closed by the router" {
		t.Errorf("disconnected detail %q", e.Detail)
	}
	if st := c.l.Stats(); st.Connections != 2 {
		t.Errorf("%d connections, want 2", st.Connections)
	}
}

func TestTLSAllowlistRefusesBeforeHandshake(t *testing.T) {
	allow, _ := ParseAllowlist("192.0.2.10")
	c := startTLS(t, allow, ServerConfig(certs(t).server, nil), nil)
	if conn, err := c.dial(t, client(t)); err == nil {
		conn.Close()
		t.Fatal("a sender outside the allowlist completed a handshake")
	}
	waitUntil(t, "the blocked count", func() bool { return c.l.Stats().Blocked == 1 })
	if st := c.l.Stats(); st.HandshakeFailures != 0 {
		t.Errorf("a blocked sender should not get as far as a handshake: %+v", st)
	}
	if ev := c.allEvents(); len(ev) != 0 {
		t.Errorf("a blocked sender should not be reported one connection at a time: %v", ev)
	}
}

// Most IOS-XE ciphersuite keywords are RSA key exchange or DHE, which this
// server refuses. The failure has to say what to change on the router.
func TestTLSNoCommonCipherSuiteSaysWhatToConfigure(t *testing.T) {
	c := startTLS(t, nil, ServerConfig(certs(t).server, nil), nil)
	cfg := client(t)
	cfg.MaxVersion = tls.VersionTLS12
	cfg.CipherSuites = []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.TLS_RSA_WITH_AES_256_CBC_SHA}
	if conn, err := c.dial(t, cfg); err == nil {
		conn.Close()
		t.Fatal("handshake succeeded with RSA key exchange only")
	}
	e := c.event(t, HandshakeFailed)
	if !strings.Contains(e.Offered, "TLS_RSA_WITH_AES_128_CBC_SHA") || !strings.Contains(e.Offered, "TLS 1.2") {
		t.Errorf("offered %q should name what the router proposed", e.Offered)
	}
	if !strings.Contains(e.Hint, "ciphersuite ecdhe-rsa-aes-gcm-sha2") {
		t.Errorf("hint %q should name the IOS-XE keyword that works", e.Hint)
	}
}

func TestTLSGCMWithECDHEIsAccepted(t *testing.T) {
	c := startTLS(t, nil, ServerConfig(certs(t).server, nil), nil)
	cfg := client(t)
	cfg.MaxVersion = tls.VersionTLS12
	cfg.CipherSuites = []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}
	c.send(t, cfg, "<191>1: x\r")
	c.messages(t, 1)
	if e := c.event(t, Connected); !strings.Contains(e.Detail, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256") {
		t.Errorf("connected detail %q", e.Detail)
	}
}

func TestTLSOldVersionSaysWhatToConfigure(t *testing.T) {
	c := startTLS(t, nil, ServerConfig(certs(t).server, nil), nil)
	cfg := client(t)
	cfg.MinVersion = tls.VersionTLS11
	cfg.MaxVersion = tls.VersionTLS11
	if conn, err := c.dial(t, cfg); err == nil {
		conn.Close()
		t.Fatal("handshake succeeded with TLS 1.1")
	}
	if e := c.event(t, HandshakeFailed); !strings.Contains(e.Hint, "tls-version TLSv1.2") {
		t.Errorf("hint %q", e.Hint)
	}
}

// "transport tcp" instead of "transport tls" sends plain syslog to the TLS
// port — an easy slip, and a baffling one without a hint.
func TestTLSPlainSyslogSaysSo(t *testing.T) {
	c := startTLS(t, nil, ServerConfig(certs(t).server, nil), nil)
	conn, err := net.Dial("tcp", c.l.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write([]byte(octet("<191>1: plain\r")))
	e := c.event(t, HandshakeFailed)
	if e.Detail != "what arrived is not TLS" || !strings.Contains(e.Hint, "transport tls") {
		t.Errorf("event %+v", e)
	}
}

func TestTLSClientCertificate(t *testing.T) {
	p := certs(t)
	c := startTLS(t, nil, ServerConfig(p.server, p.routers), nil)

	// A router that presents the trusted certificate gets through.
	cfg := client(t)
	cfg.Certificates = []tls.Certificate{p.router}
	c.send(t, cfg, "<191>1: from the router\r")
	c.messages(t, 1)
	if e := c.event(t, Connected); !strings.Contains(e.Detail, "CN=router") {
		t.Errorf("connected detail %q should name the router's certificate", e.Detail)
	}

	// With TLS 1.3 the client finishes before the server has judged its
	// certificate, so the refusal shows on the server side, not in Dial.
	for _, cert := range [][]tls.Certificate{nil, {p.stranger}} {
		cfg := client(t)
		cfg.Certificates = cert
		if conn, err := c.dial(t, cfg); err == nil {
			conn.Write([]byte(octet("<191>2: should not arrive\r")))
			conn.Close()
		}
	}
	waitUntil(t, "two refusals", func() bool { return c.l.Stats().HandshakeFailures == 2 })
	for _, e := range c.allEvents() {
		if e.Kind == HandshakeFailed && !strings.Contains(e.Hint, "client-id-trustpoint") {
			t.Errorf("hint %q should say how the router presents a certificate", e.Hint)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if got := c.messages(t, 1); len(got) != 1 {
		t.Errorf("%d message(s): an untrusted client got a line through", len(got))
	}
}

func TestTLSGarbageAfterHandshakeClosesTheConnection(t *testing.T) {
	c := startTLS(t, nil, ServerConfig(certs(t).server, nil), nil)
	conn, err := c.dial(t, client(t))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write([]byte(octet("<191>1: good\r") + "hello\n"))
	c.messages(t, 1)
	if e := c.event(t, Disconnected); !strings.Contains(e.Detail, "not syslog framing") {
		t.Errorf("disconnected detail %q", e.Detail)
	}
	if st := c.l.Stats(); st.Errors != 1 {
		t.Errorf("stats %+v, want one error", st)
	}
}

func TestTLSHandshakeTimeout(t *testing.T) {
	c := startTLS(t, nil, ServerConfig(certs(t).server, nil), func(l *TLSListener) {
		l.handshake = 50 * time.Millisecond
	})
	conn, err := net.Dial("tcp", c.l.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if e := c.event(t, HandshakeFailed); !strings.HasPrefix(e.Detail, "no handshake within") {
		t.Errorf("detail %q", e.Detail)
	}
}

func TestTLSConnectionLimit(t *testing.T) {
	c := startTLS(t, nil, ServerConfig(certs(t).server, nil), func(l *TLSListener) { l.limit = 2 })
	var held []net.Conn
	defer func() {
		for _, h := range held {
			h.Close()
		}
	}()
	for i := 0; i < 3; i++ {
		conn, err := net.Dial("tcp", c.l.Addr())
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, conn)
	}
	waitUntil(t, "a refusal", func() bool { return c.l.Stats().Refused == 1 })
	if st := c.l.Stats(); st.Active != 2 {
		t.Errorf("%d active, want 2", st.Active)
	}
}

func TestTLSRFC5424IsReported(t *testing.T) {
	c := startTLS(t, nil, ServerConfig(certs(t).server, nil), nil)
	c.send(t, client(t), "<189>1 2026-09-24T10:00:00.000Z - - - - - %SYS-5-CONFIG_I: x")
	c.messages(t, 1)
	if e := c.event(t, Format); !strings.Contains(e.Hint, "syslog-format rfc5424") {
		t.Errorf("hint %q", e.Hint)
	}
}

func TestIsRFC5424(t *testing.T) {
	for msg, want := range map[string]bool{
		"<189>1 2026-09-24T10:00:00.000Z - - - - - x": true,
		"<7>1 -":                     true,
		"<191>1: 000001: Sep 24 ...": false,
		"<191>400001: x":             false,
		"1 no pri":                   false,
		"":                           false,
		"<>1 x":                      false,
	} {
		if got := isRFC5424(msg); got != want {
			t.Errorf("isRFC5424(%q) = %v, want %v", msg, got, want)
		}
	}
}

// Cancelling must bring down connections that are open and idle, or Run never
// returns and Ctrl-C hangs while a router is connected.
func TestTLSCancelClosesOpenConnections(t *testing.T) {
	c := startTLS(t, nil, ServerConfig(certs(t).server, nil), nil)
	conn, err := c.dial(t, client(t))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	c.event(t, Connected)
	c.cancel()
	select {
	case err := <-c.done:
		if err != nil {
			t.Errorf("Run: %v", err)
		}
		c.done <- err // for the cleanup
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return with a connection open")
	}
	for _, e := range c.allEvents() {
		if e.Kind == Disconnected {
			t.Errorf("shutting down is not the router disconnecting: %v", e)
		}
	}
}

func TestOpenTLSNeedsACertificate(t *testing.T) {
	if _, err := OpenTLS("127.0.0.1:0", nil, &tls.Config{}); err == nil {
		t.Error("OpenTLS without a certificate should fail")
	}
}

func TestServerConfigOffersOnlyForwardSecrecy(t *testing.T) {
	cfg := ServerConfig(certs(t).server, nil)
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion %x", cfg.MinVersion)
	}
	for _, s := range cfg.CipherSuites {
		if !strings.HasPrefix(tls.CipherSuiteName(s), "TLS_ECDHE_") {
			t.Errorf("%s has no forward secrecy", tls.CipherSuiteName(s))
		}
	}
	if cfg.ClientAuth != tls.NoClientCert {
		t.Error("no client CAs should mean no client certificate asked for")
	}
}
