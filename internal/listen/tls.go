package listen

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/phuongnz/cube-logger/internal/live"
)

// DefaultTLSPort is the port RFC 5425 assigns to syslog over TLS, and the one
// IOS-XE uses when "logging host … transport tls" names none.
const DefaultTLSPort = 6514

const (
	// handshakeTimeout bounds the only part of a connection that happens
	// before the peer has proved anything. A router completes a handshake in
	// milliseconds; something that holds one open is not a router.
	handshakeTimeout = 10 * time.Second

	// maxConns bounds the connections held open at once. A CUBE keeps one open
	// for as long as it logs, so this is several routers' worth — and a cap on
	// what anything else reaching the port can cost.
	maxConns = 32

	// acceptRetry is the pause after a failed Accept, such as running out of
	// file descriptors. The listener waits it out rather than ending a
	// session an engineer is in the middle of.
	acceptRetry = 100 * time.Millisecond
)

// acceptedSuites are the TLS 1.2 cipher suites offered: ECDHE only, so a
// recorded stream cannot be decrypted later with the server's key. Go does not
// implement DHE and no longer offers RSA key exchange by default, which rules
// out most of IOS-XE's "ciphersuite" keywords; "ecdhe-rsa-aes-gcm-sha2" is the
// one that works with the RSA certificate this tool makes. TLS 1.3 suites are
// not configurable in Go, and all three are fine.
var acceptedSuites = []uint16{
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
}

// ServerConfig is the TLS configuration for receiving syslog with cert. When
// clientCAs is not nil, a peer must present a certificate that chains to it —
// which is how a router proves who it is, the allowlist being only an address.
func ServerConfig(cert tls.Certificate, clientCAs *x509.CertPool) *tls.Config {
	c := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: slices.Clone(acceptedSuites),
	}
	if clientCAs != nil {
		c.ClientCAs = clientCAs
		c.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return c
}

// EventKind says what happened to a connection.
type EventKind int

const (
	// Connected is a completed handshake.
	Connected EventKind = iota
	// Disconnected is a connection that ended after its handshake.
	Disconnected
	// HandshakeFailed is a connection that never got as far as a message.
	HandshakeFailed
	// Format is a sender whose messages this tool will not read well.
	Format
)

// Event is something about a connection that an engineer watching the
// terminal wants to know: a router connected, went away, or could not complete
// the handshake — and, for that last one, what it offered and what to change.
type Event struct {
	Kind   EventKind
	Source string
	// Detail is the protocol and suite for Connected, and the error otherwise.
	Detail string
	// Offered is what the peer's ClientHello proposed, for a failed handshake.
	Offered string
	// Hint is the change that fixes it, when that is known.
	Hint string
}

func (e Event) String() string {
	var s string
	switch e.Kind {
	case Connected:
		s = fmt.Sprintf("%s connected over TLS (%s)", e.Source, e.Detail)
	case Disconnected:
		s = fmt.Sprintf("%s disconnected: %s", e.Source, e.Detail)
	case HandshakeFailed:
		s = fmt.Sprintf("%s: TLS handshake failed: %s", e.Source, e.Detail)
	case Format:
		s = fmt.Sprintf("%s: %s", e.Source, e.Detail)
	}
	if e.Offered != "" {
		s += "\n  it offered " + e.Offered
	}
	if e.Hint != "" {
		s += "\n  " + e.Hint
	}
	return s
}

// TLSStats are the TLS listener's own counters.
type TLSStats struct {
	// Connections counts handshakes that completed; Active is how many of
	// those are open now.
	Connections uint64 `json:"connections"`
	Active      int    `json:"active"`
	Messages    uint64 `json:"messages"`
	Bytes       uint64 `json:"bytes"`
	// Blocked connections came from an address the allowlist refuses, and were
	// closed before any TLS was spoken.
	Blocked uint64 `json:"blocked"`
	// Refused connections arrived while maxConns were already open.
	Refused           uint64 `json:"refused"`
	HandshakeFailures uint64 `json:"handshakeFailures"`
	// Errors are failed accepts and streams that stopped being syslog.
	Errors uint64 `json:"errors"`
}

// TLSListener receives syslog over TLS, RFC 5425. Each message becomes one
// live.Datagram, exactly as if it had arrived over UDP, so everything after
// the socket is shared.
type TLSListener struct {
	ln     net.Listener
	config *tls.Config
	allow  *Allowlist
	// usable are the offered suites that the certificate's key can sign for,
	// which is what a handshake failure is judged against.
	usable []uint16

	// Events, when set before Run, is told about connections as they come and
	// go. It and the handle given to Run are never called at the same time.
	Events func(Event)

	// handshake and limit are handshakeTimeout and maxConns, as fields so a
	// test need not wait ten seconds or open thirty-three sockets.
	handshake time.Duration
	limit     int

	cb    sync.Mutex // serialises handle and Events across connections
	mu    sync.Mutex
	conns map[net.Conn]struct{}

	connections, messages, bytes, blocked, refused, handshakeFails, errs atomic.Uint64
}

// OpenTLS binds addr for TCP. An addr of "" means every interface on
// DefaultTLSPort; ":0" is useful in a test, which reads the port back from
// Addr.
func OpenTLS(addr string, allow *Allowlist, config *tls.Config) (*TLSListener, error) {
	if config == nil || (len(config.Certificates) == 0 && config.GetCertificate == nil) {
		return nil, errors.New("TLS listener needs a server certificate")
	}
	if addr == "" {
		addr = fmt.Sprintf(":%d", DefaultTLSPort)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &TLSListener{
		ln:        ln,
		config:    config,
		allow:     allow,
		usable:    usableSuites(config),
		handshake: handshakeTimeout,
		limit:     maxConns,
		conns:     map[net.Conn]struct{}{},
	}, nil
}

// Addr is the address actually bound, with the real port filled in.
func (l *TLSListener) Addr() string { return l.ln.Addr().String() }

// Allowlist is the list this listener was opened with.
func (l *TLSListener) Allowlist() *Allowlist { return l.allow }

// Stats returns the listener counters.
func (l *TLSListener) Stats() TLSStats {
	l.mu.Lock()
	active := len(l.conns)
	l.mu.Unlock()
	return TLSStats{
		Connections:       l.connections.Load(),
		Active:            active,
		Messages:          l.messages.Load(),
		Bytes:             l.bytes.Load(),
		Blocked:           l.blocked.Load(),
		Refused:           l.refused.Load(),
		HandshakeFailures: l.handshakeFails.Load(),
		Errors:            l.errs.Load(),
	}
}

// Close stops accepting and closes every open connection. A Run in progress
// returns nil.
func (l *TLSListener) Close() error {
	err := l.ln.Close()
	l.mu.Lock()
	for c := range l.conns {
		c.Close()
	}
	l.mu.Unlock()
	return err
}

// Run accepts connections until ctx is cancelled or the listener is closed,
// calling handle for every message on every connection. It returns once all
// of them are closed, and does not return an error for a cancelled context.
//
// handle is never called concurrently by one listener, so the order of one
// connection's messages is the order they are handed on. It must not block for
// long: a slow handle holds up every connection, not just one.
func (l *TLSListener) Run(ctx context.Context, handle func(live.Datagram)) error {
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			l.Close()
		case <-stop:
		}
	}()

	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		c, err := l.ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				l.Close()
				return nil
			}
			l.errs.Add(1)
			select {
			case <-ctx.Done():
			case <-time.After(acceptRetry):
			}
			continue
		}

		// The allowlist is applied before the handshake: a refused address
		// costs a closed socket, not a key exchange.
		ip := remoteIP(c)
		if !l.allow.Allows(ip) {
			l.blocked.Add(1)
			c.Close()
			continue
		}
		if !l.track(c) {
			l.refused.Add(1)
			c.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer l.untrack(c)
			l.serve(ctx, c, ip.String(), handle)
		}()
	}
}

func (l *TLSListener) track(c net.Conn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.conns) >= l.limit {
		return false
	}
	l.conns[c] = struct{}{}
	return true
}

func (l *TLSListener) untrack(c net.Conn) {
	l.mu.Lock()
	delete(l.conns, c)
	l.mu.Unlock()
	c.Close()
}

func (l *TLSListener) event(e Event) {
	if l.Events == nil {
		return
	}
	l.cb.Lock()
	defer l.cb.Unlock()
	l.Events(e)
}

// serve runs one connection: the handshake, then one message at a time until
// the peer goes away or the stream stops being syslog.
func (l *TLSListener) serve(ctx context.Context, c net.Conn, source string, handle func(live.Datagram)) {
	// What the peer offered is kept for the one case it matters: a handshake
	// that fails because the two sides have nothing in common. The callback
	// runs on this goroutine, inside the handshake.
	var offered *hello
	cfg := l.config.Clone()
	cfg.GetConfigForClient = func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		offered = &hello{versions: slices.Clone(h.SupportedVersions), suites: slices.Clone(h.CipherSuites)}
		return nil, nil
	}
	tc := tls.Server(c, cfg)
	hctx, cancel := context.WithTimeout(ctx, l.handshake)
	err := tc.HandshakeContext(hctx)
	cancel()
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		l.handshakeFails.Add(1)
		l.event(l.handshakeFailure(source, err, offered))
		return
	}

	l.connections.Add(1)
	st := tc.ConnectionState()
	detail := tls.VersionName(st.Version) + ", " + tls.CipherSuiteName(st.CipherSuite)
	if len(st.PeerCertificates) > 0 {
		detail += ", certificate " + st.PeerCertificates[0].Subject.String()
	}
	l.event(Event{Kind: Connected, Source: source, Detail: detail})

	fr := newFrameReader(tc, maxFrame)
	first := true
	for {
		msg, err := fr.next()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			why := "closed by the router"
			if !errors.Is(err, io.EOF) {
				l.errs.Add(1)
				why = err.Error()
			}
			l.event(Event{Kind: Disconnected, Source: source, Detail: why})
			return
		}
		if first && isRFC5424(msg) {
			l.event(Event{Kind: Format, Source: source,
				Detail: "sends RFC 5424, which puts the IOS timestamp and sequence number where this tool does not look for them",
				Hint:   `on the router, drop "syslog-format rfc5424" from "logging trap"`})
		}
		first = false
		l.messages.Add(1)
		l.bytes.Add(uint64(len(msg)))
		d := live.Datagram{Source: source, Payload: msg, Time: time.Now()}
		l.cb.Lock()
		handle(d)
		l.cb.Unlock()
	}
}

// hello is the part of a ClientHello worth reporting.
type hello struct {
	versions []uint16
	suites   []uint16
}

func (h *hello) String() string {
	vs := make([]string, 0, len(h.versions))
	for _, v := range h.versions {
		vs = append(vs, tls.VersionName(v))
	}
	ss := make([]string, 0, len(h.suites))
	for _, s := range h.suites {
		ss = append(ss, tls.CipherSuiteName(s))
	}
	return strings.Join(vs, ", ") + "; " + strings.Join(ss, ", ")
}

// handshakeFailure explains a failed handshake in the router's terms. The
// three failures worth a hint are the ones a first setup runs into: plain
// TCP sent to the TLS port, a tls-profile with no suite in common, and a
// certificate one side does not trust.
func (l *TLSListener) handshakeFailure(source string, err error, h *hello) Event {
	e := Event{Kind: HandshakeFailed, Source: source, Detail: err.Error()}
	var rh tls.RecordHeaderError
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		e.Detail = fmt.Sprintf("no handshake within %s", l.handshake)
		return e
	case errors.As(err, &rh):
		e.Detail = "what arrived is not TLS"
		e.Hint = `the router is sending plain syslog: use "transport tls" in "logging host"`
		return e
	case h == nil:
		return e
	}
	e.Offered = h.String()
	switch {
	case !slices.Contains(h.versions, tls.VersionTLS13) && !slices.Contains(h.versions, tls.VersionTLS12):
		e.Hint = `on the router: "tls-version TLSv1.2" in the logging tls-profile`
	case !slices.Contains(h.versions, tls.VersionTLS13) && !l.anyUsable(h.suites):
		e.Hint = fmt.Sprintf(`on the router: "ciphersuite %s" in the logging tls-profile`, suiteKeyword(l.usable))
	case l.config.ClientAuth == tls.RequireAndVerifyClientCert && isClientCertError(err):
		e.Hint = `the router must present a certificate that -tls-client-ca trusts: "client-id-trustpoint" in the logging tls-profile`
	case strings.Contains(err.Error(), "remote error") && strings.Contains(err.Error(), "certificate"):
		e.Hint = `the router does not trust this certificate: import it with "crypto pki authenticate" (cube-logger cert prints it)`
	}
	return e
}

func (l *TLSListener) anyUsable(offered []uint16) bool {
	for _, s := range offered {
		if slices.Contains(l.usable, s) {
			return true
		}
	}
	return false
}

// SuiteKeyword is the IOS-XE "ciphersuite" keyword that works with the
// certificate in c, for the router configuration to name.
func SuiteKeyword(c *tls.Config) string { return suiteKeyword(usableSuites(c)) }

func suiteKeyword(usable []uint16) string {
	for _, s := range usable {
		if strings.Contains(tls.CipherSuiteName(s), "_ECDSA_") {
			return "ecdhe-ecdsa-aes-gcm-sha2"
		}
	}
	return "ecdhe-rsa-aes-gcm-sha2"
}

// usableSuites narrows the configured suites to the ones the certificate can
// be used with: an RSA key cannot sign an ECDHE_ECDSA handshake, or the other
// way round.
func usableSuites(c *tls.Config) []uint16 {
	suites := c.CipherSuites
	if suites == nil {
		suites = acceptedSuites
	}
	want := ""
	if len(c.Certificates) > 0 {
		switch c.Certificates[0].PrivateKey.(type) {
		case *rsa.PrivateKey:
			want = "_RSA_"
		case *ecdsa.PrivateKey:
			want = "_ECDSA_"
		}
	}
	var out []uint16
	for _, s := range suites {
		if want == "" || strings.Contains(tls.CipherSuiteName(s), want) {
			out = append(out, s)
		}
	}
	return out
}

// isClientCertError is Go's server side of a peer that sent no certificate,
// or one that does not chain to ClientCAs.
func isClientCertError(err error) bool {
	var ue x509.UnknownAuthorityError
	var ce x509.CertificateInvalidError
	return errors.As(err, &ue) || errors.As(err, &ce) ||
		strings.Contains(err.Error(), "didn't provide a certificate")
}

// isRFC5424 spots "<PRI>1 " — the RFC 5424 version field — where IOS's own
// frame has "<PRI>seq: ".
func isRFC5424(msg string) bool {
	i := strings.IndexByte(msg, '>')
	return msg != "" && msg[0] == '<' && i > 1 && i <= 4 && strings.HasPrefix(msg[i+1:], "1 ")
}

// remoteIP is the peer's address without its port, and IPv4 unmapped so that
// an allowlist naming the IPv4 address matches on a dual-stack socket.
func remoteIP(c net.Conn) netip.Addr {
	if ta, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		return ta.AddrPort().Addr().Unmap()
	}
	return netip.Addr{}
}
