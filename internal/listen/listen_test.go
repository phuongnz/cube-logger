package listen

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/phuongnz/cube-logger/internal/live"
)

// Every address below is from a reserved documentation range, and the test
// sockets are on the loopback.

func TestParseAllowlist(t *testing.T) {
	a, err := ParseAllowlist(" 192.0.2.10 , 198.51.100.0/24 ,, 2001:db8::1 ")
	if err != nil {
		t.Fatal(err)
	}
	allowed := []string{"192.0.2.10", "198.51.100.1", "198.51.100.255", "2001:db8::1"}
	for _, s := range allowed {
		if !a.Allows(netip.MustParseAddr(s)) {
			t.Errorf("%s should be allowed", s)
		}
	}
	denied := []string{"192.0.2.11", "198.51.100.0/25.0", "203.0.113.1", "2001:db8::2"}
	for _, s := range denied {
		ip, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		if a.Allows(ip) {
			t.Errorf("%s should be denied", s)
		}
	}
	if a.Empty() {
		t.Error("a populated allowlist is not empty")
	}
}

func TestEmptyAllowlistAllowsEverything(t *testing.T) {
	for _, spec := range []string{"", "  ", ",,"} {
		a, err := ParseAllowlist(spec)
		if err != nil {
			t.Fatalf("ParseAllowlist(%q): %v", spec, err)
		}
		if !a.Empty() {
			t.Errorf("ParseAllowlist(%q) should be empty", spec)
		}
		if !a.Allows(netip.MustParseAddr("203.0.113.9")) {
			t.Errorf("an empty allowlist should allow everything")
		}
		if a.String() != "any" {
			t.Errorf("String() = %q, want any", a.String())
		}
	}
	// A nil allowlist is the same as an empty one: the zero value must work.
	var nilList *Allowlist
	if !nilList.Empty() || !nilList.Allows(netip.MustParseAddr("203.0.113.9")) {
		t.Error("a nil allowlist should allow everything")
	}
}

// An IPv4 sender arriving on a dual-stack socket appears as ::ffff:192.0.2.10.
// If that is not unmapped, an allowlist naming the v4 address never matches.
func TestAllowlistUnmapsIPv4InIPv6(t *testing.T) {
	a, err := ParseAllowlist("192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	if !a.Allows(netip.MustParseAddr("::ffff:192.0.2.10")) {
		t.Error("an IPv4-mapped IPv6 address should match its IPv4 allowlist entry")
	}
}

func TestParseAllowlistRejectsNonsense(t *testing.T) {
	for _, spec := range []string{"not-an-address", "192.0.2.0/33", "192.0.2"} {
		if _, err := ParseAllowlist(spec); err == nil {
			t.Errorf("ParseAllowlist(%q) should have failed", spec)
		}
	}
}

// collector runs a listener on an ephemeral loopback port and gathers what it
// receives.
type collector struct {
	l    *Listener
	mu   sync.Mutex
	got  []live.Datagram
	done chan struct{}
}

func start(t *testing.T, allow *Allowlist) *collector {
	t.Helper()
	l, err := Open("127.0.0.1:0", allow)
	if err != nil {
		t.Fatal(err)
	}
	c := &collector{l: l, done: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); <-c.done; l.Close() })
	go func() {
		defer close(c.done)
		if err := l.Run(ctx, func(d live.Datagram) {
			c.mu.Lock()
			c.got = append(c.got, d)
			c.mu.Unlock()
		}); err != nil {
			t.Errorf("Run: %v", err)
		}
	}()
	return c
}

func (c *collector) send(t *testing.T, payloads ...string) {
	t.Helper()
	conn, err := net.Dial("udp", c.l.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for _, p := range payloads {
		if _, err := conn.Write([]byte(p)); err != nil {
			t.Fatal(err)
		}
	}
}

// waitFor polls until n datagrams have been collected. UDP on the loopback
// does not drop, but it is still asynchronous.
func (c *collector) waitFor(t *testing.T, n int) []live.Datagram {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		got := append([]live.Datagram(nil), c.got...)
		c.mu.Unlock()
		if len(got) >= n {
			return got
		}
		time.Sleep(time.Millisecond)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	t.Fatalf("waited for %d datagram(s), got %d", n, len(c.got))
	return nil
}

func TestReceivesDatagrams(t *testing.T) {
	c := start(t, nil)
	c.send(t,
		"<191>400001: 7200001: Sep 24 12:00:00.123 UTC: //-1/A1B2C3D4E5F6/SIP/Msg/ccsipDisplayMsg:\r",
		"<191>400002: Received:\r",
		"<191>400003:", // the empty datagram between headers and body
	)
	got := c.waitFor(t, 3)

	if got[1].Payload != "<191>400002: Received:\r" {
		t.Errorf("payload = %q, altered in transit", got[1].Payload)
	}
	// The empty datagram is what separates a SIP message's headers from its
	// body. A listener that skipped zero-length reads would lose every body.
	if got[2].Payload != "<191>400003:" {
		t.Errorf("third payload = %q", got[2].Payload)
	}
	for i, d := range got {
		if d.Source != "127.0.0.1" {
			t.Errorf("datagram %d: Source = %q, want the sender's address", i, d.Source)
		}
		if d.Time.IsZero() {
			t.Errorf("datagram %d: no arrival time", i)
		}
	}
	if st := c.l.Stats(); st.Datagrams != 3 || st.Blocked != 0 {
		t.Errorf("Stats = %+v, want 3 datagrams and nothing blocked", st)
	}
}

// A truly empty datagram is legal UDP and must not be mistaken for the socket
// closing.
func TestZeroLengthDatagram(t *testing.T) {
	c := start(t, nil)
	c.send(t, "", "<191>400001: 7200001: Sep 24 12:00:00.123 UTC: %SYS-6-A: after the empty one")
	got := c.waitFor(t, 2)
	if got[0].Payload != "" {
		t.Errorf("first payload = %q, want empty", got[0].Payload)
	}
}

func TestAllowlistBlocksOtherSenders(t *testing.T) {
	// Loopback traffic comes from 127.0.0.1, so an allowlist naming a
	// documentation address blocks everything this test can send.
	allow, err := ParseAllowlist("192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	c := start(t, allow)
	c.send(t, "<191>400001: 7200001: Sep 24 12:00:00.123 UTC: %SYS-6-A: from an unexpected sender")

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if c.l.Stats().Blocked > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	st := c.l.Stats()
	if st.Blocked != 1 {
		t.Errorf("Blocked = %d, want 1", st.Blocked)
	}
	if st.Datagrams != 0 {
		t.Errorf("Datagrams = %d, want 0", st.Datagrams)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.got) != 0 {
		t.Errorf("a blocked datagram reached the handler: %q", c.got[0].Payload)
	}
}

func TestAllowlistPassesANamedSender(t *testing.T) {
	allow, err := ParseAllowlist("127.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	c := start(t, allow)
	c.send(t, "<191>400001: 7200001: Sep 24 12:00:00.123 UTC: %SYS-6-A: from the router")
	c.waitFor(t, 1)
	if st := c.l.Stats(); st.Blocked != 0 {
		t.Errorf("Blocked = %d, want 0", st.Blocked)
	}
}

func TestCancelStopsRunWithoutAnError(t *testing.T) {
	l, err := Open("127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- l.Run(ctx, func(live.Datagram) {}) }()
	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Errorf("cancelling should not be an error, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after the context was cancelled")
	}
}

func TestCloseStopsRunWithoutAnError(t *testing.T) {
	l, err := Open("127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	go func() { errc <- l.Run(context.Background(), func(live.Datagram) {}) }()
	time.Sleep(10 * time.Millisecond)
	l.Close()
	select {
	case err := <-errc:
		if err != nil {
			t.Errorf("closing should not be an error, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after the socket was closed")
	}
}

func TestOpenRejectsANonsenseAddress(t *testing.T) {
	if _, err := Open("not:an:address", nil); err == nil {
		t.Error("Open should have failed")
	}
}
