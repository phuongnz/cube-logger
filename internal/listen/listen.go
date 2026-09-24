// Package listen receives CUBE syslog over UDP.
//
// It is the thin I/O shell around internal/live: it owns a socket, decides
// which senders to accept, and hands every datagram on unchanged. All of the
// judgement — ordering, reassembly, loss — lives in packages that do no I/O
// and can be tested from a string.
//
// UDP is fire-and-forget, so there is nothing to accept and no connection to
// lose: the listener is receive-only and never sends a byte back. It binds
// whatever address it is given, and the default is every interface, because a
// router on the far side of a network has to be able to reach it. The web UI
// is the part that binds 127.0.0.1.
package listen

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/phuongnz/cube-logger/internal/live"
)

// DefaultPort is the port the tool listens on. It is not 514: that one needs
// root on every Unix, and a troubleshooting tool a user runs on their laptop
// should never ask for that.
const DefaultPort = 5514

// readBuffer is generous on purpose. The largest datagram measured was 214
// bytes and the longest line ever seen was 453, so nothing observed comes near
// this — but a short buffer truncates a datagram silently, and a corrupted
// line that looks plausible is worse than any amount of unused memory.
const readBuffer = 65536

// Allowlist decides which senders are accepted. An empty Allowlist accepts
// everything, which is the right default for a tool on an engineer's laptop on
// a lab network.
//
// It exists because this port is unauthenticated: anything that can route to
// the machine can inject lines that look exactly like the router's. On a
// shared network, naming the CUBE is worth the two minutes it takes.
type Allowlist struct {
	addrs    []netip.Addr
	prefixes []netip.Prefix
}

// ParseAllowlist reads a comma-separated list of addresses and CIDR prefixes.
func ParseAllowlist(spec string) (*Allowlist, error) {
	a := &Allowlist{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "/") {
			p, err := netip.ParsePrefix(part)
			if err != nil {
				return nil, fmt.Errorf("allowlist entry %q: %w", part, err)
			}
			a.prefixes = append(a.prefixes, p.Masked())
			continue
		}
		ip, err := netip.ParseAddr(part)
		if err != nil {
			return nil, fmt.Errorf("allowlist entry %q: not an address or CIDR prefix", part)
		}
		a.addrs = append(a.addrs, ip.Unmap())
	}
	return a, nil
}

// Empty reports whether the allowlist accepts everything.
func (a *Allowlist) Empty() bool {
	return a == nil || (len(a.addrs) == 0 && len(a.prefixes) == 0)
}

// Allows reports whether a sender is accepted.
func (a *Allowlist) Allows(ip netip.Addr) bool {
	if a.Empty() {
		return true
	}
	ip = ip.Unmap()
	for _, x := range a.addrs {
		if x == ip {
			return true
		}
	}
	for _, p := range a.prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// String renders the allowlist for a status line.
func (a *Allowlist) String() string {
	if a.Empty() {
		return "any"
	}
	parts := make([]string, 0, len(a.addrs)+len(a.prefixes))
	for _, x := range a.addrs {
		parts = append(parts, x.String())
	}
	for _, p := range a.prefixes {
		parts = append(parts, p.String())
	}
	return strings.Join(parts, ",")
}

// Stats are the listener's own counters, which are about the socket and not
// about the log: what arrived, what was refused, what failed to read.
type Stats struct {
	Datagrams uint64 `json:"datagrams"`
	Bytes     uint64 `json:"bytes"`
	Blocked   uint64 `json:"blocked"`
	Errors    uint64 `json:"errors"`
}

// Listener is a bound UDP socket.
type Listener struct {
	conn  *net.UDPConn
	allow *Allowlist

	datagrams, bytes, blocked, errs atomic.Uint64
}

// Open binds addr. An addr of "" or ":0" is allowed and useful in a test,
// which then reads the real port back from Addr.
func Open(addr string, allow *Allowlist) (*Listener, error) {
	if addr == "" {
		addr = fmt.Sprintf(":%d", DefaultPort)
	}
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen address %q: %w", addr, err)
	}
	conn, err := net.ListenUDP("udp", ua)
	if err != nil {
		// The one mistake worth explaining rather than reporting: port 514 is
		// privileged, and the fix is to use the default port, not to use sudo.
		if ua.Port > 0 && ua.Port < 1024 && errors.Is(err, os.ErrPermission) {
			return nil, fmt.Errorf("cannot bind %s: ports below 1024 need root. "+
				"Use port %d instead and point the router's \"logging host\" at it", addr, DefaultPort)
		}
		return nil, err
	}
	return &Listener{conn: conn, allow: allow}, nil
}

// Addr is the address actually bound, with the real port filled in.
func (l *Listener) Addr() string { return l.conn.LocalAddr().String() }

// Allowlist is the list this listener was opened with.
func (l *Listener) Allowlist() *Allowlist { return l.allow }

// Stats returns the socket counters.
func (l *Listener) Stats() Stats {
	return Stats{
		Datagrams: l.datagrams.Load(),
		Bytes:     l.bytes.Load(),
		Blocked:   l.blocked.Load(),
		Errors:    l.errs.Load(),
	}
}

// Close stops the listener. A Run in progress returns nil.
func (l *Listener) Close() error { return l.conn.Close() }

// Run reads datagrams until ctx is cancelled or the socket is closed, calling
// handle for each accepted one. It does not return an error for a cancelled
// context: that is the normal way to stop.
//
// handle is called on this goroutine, so it must not block for long. The
// server hands straight to the reassembler and a non-blocking fan-out, which
// is what keeps a slow browser from costing the socket a datagram.
func (l *Listener) Run(ctx context.Context, handle func(live.Datagram)) error {
	// Close on cancellation: that is the only way to interrupt a blocking read.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			l.conn.Close()
		case <-stop:
		}
	}()

	buf := make([]byte, readBuffer)
	for {
		n, from, err := l.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			// A transient read error must not end the session: an engineer
			// watching a call wants the next datagram, not a stack trace.
			l.errs.Add(1)
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return err
		}
		now := time.Now()
		ip := from.Addr().Unmap()
		if !l.allow.Allows(ip) {
			l.blocked.Add(1)
			continue
		}
		l.datagrams.Add(1)
		l.bytes.Add(uint64(n))

		// The source address is the device identity, and the port is not part
		// of it: IOS picks an ephemeral source port and may change it.
		handle(live.Datagram{
			Source:  ip.String(),
			Payload: string(buf[:n]),
			Time:    now,
		})
	}
}
