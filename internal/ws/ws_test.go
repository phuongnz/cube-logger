package ws

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// client is a WebSocket client written the long way, so the tests exercise the
// wire format rather than this package talking to itself. It masks its frames
// the way a browser does, which is the rule the server enforces.
type client struct {
	conn net.Conn
	br   *bufio.Reader
}

func dial(t *testing.T, srv *httptest.Server, headers map[string]string) (*client, *http.Response) {
	t.Helper()
	u := strings.TrimPrefix(srv.URL, "http://")
	conn, err := net.Dial("tcp", u)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })

	var key [16]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	k := base64.StdEncoding.EncodeToString(key[:])

	h := map[string]string{
		"Host":                  u,
		"Upgrade":               "websocket",
		"Connection":            "Upgrade",
		"Sec-WebSocket-Key":     k,
		"Sec-WebSocket-Version": "13",
	}
	for name, v := range headers {
		if v == "" {
			delete(h, name)
			continue
		}
		h[name] = v
	}
	var b strings.Builder
	b.WriteString("GET /ws HTTP/1.1\r\n")
	for name, v := range h {
		b.WriteString(name + ": " + v + "\r\n")
	}
	b.WriteString("\r\n")
	if _, err := conn.Write([]byte(b.String())); err != nil {
		t.Fatal(err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := &client{conn: conn, br: br}
	if resp.StatusCode == http.StatusSwitchingProtocols {
		if got := resp.Header.Get("Sec-WebSocket-Accept"); got != acceptKey(k) {
			t.Errorf("Sec-WebSocket-Accept = %q, want %q", got, acceptKey(k))
		}
	}
	return c, resp
}

// send writes one masked client frame.
func (c *client) send(t *testing.T, op byte, payload []byte) {
	t.Helper()
	var hdr []byte
	hdr = append(hdr, 0x80|op)
	n := len(payload)
	switch {
	case n < 126:
		hdr = append(hdr, byte(n)|0x80)
	case n <= 0xFFFF:
		hdr = append(hdr, 126|0x80)
		hdr = binary.BigEndian.AppendUint16(hdr, uint16(n))
	default:
		hdr = append(hdr, 127|0x80)
		hdr = binary.BigEndian.AppendUint64(hdr, uint64(n))
	}
	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		t.Fatal(err)
	}
	hdr = append(hdr, mask[:]...)
	masked := make([]byte, n)
	for i := range payload {
		masked[i] = payload[i] ^ mask[i%4]
	}
	if _, err := c.conn.Write(append(hdr, masked...)); err != nil {
		t.Fatal(err)
	}
}

// sendRaw writes bytes verbatim, for the frames a correct client cannot make.
func (c *client) sendRaw(t *testing.T, b []byte) {
	t.Helper()
	if _, err := c.conn.Write(b); err != nil {
		t.Fatal(err)
	}
}

// recv reads one server frame. A server frame is never masked.
func (c *client) recv(t *testing.T) (op byte, payload []byte) {
	t.Helper()
	c.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var hdr [2]byte
	if _, err := io.ReadFull(c.br, hdr[:]); err != nil {
		t.Fatalf("reading frame header: %v", err)
	}
	if hdr[1]&0x80 != 0 {
		t.Fatal("a server frame must not be masked")
	}
	if hdr[0]&0x80 == 0 {
		t.Fatal("this server never fragments what it sends, so FIN should be set")
	}
	op = hdr[0] & 0x0F
	n := uint64(hdr[1] & 0x7F)
	switch n {
	case 126:
		var ext [2]byte
		io.ReadFull(c.br, ext[:])
		n = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		io.ReadFull(c.br, ext[:])
		n = binary.BigEndian.Uint64(ext[:])
	}
	payload = make([]byte, n)
	if _, err := io.ReadFull(c.br, payload); err != nil {
		t.Fatalf("reading %d byte payload: %v", n, err)
	}
	return op, payload
}

// serve runs an httptest server whose handler gets the accepted connection.
func serve(t *testing.T, handle func(*Conn)) *httptest.Server {
	t.Helper()
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := Accept(w, r)
		if err != nil {
			return
		}
		defer close(done)
		handle(c)
	}))
	t.Cleanup(func() {
		select {
		case <-done:
		case <-time.After(time.Second):
		}
		srv.Close()
	})
	return srv
}

func TestHandshakeAndTextFrame(t *testing.T) {
	srv := serve(t, func(c *Conn) {
		if err := c.WriteText([]byte(`{"type":"hello"}`)); err != nil {
			t.Errorf("WriteText: %v", err)
		}
		c.Close(CloseNormal, "")
	})
	c, resp := dial(t, srv, nil)
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	op, payload := c.recv(t)
	if op != opText {
		t.Errorf("opcode = %d, want text", op)
	}
	if string(payload) != `{"type":"hello"}` {
		t.Errorf("payload = %q", payload)
	}
	if op, _ := c.recv(t); op != opClose {
		t.Errorf("expected a close frame, got opcode %d", op)
	}
}

// Payload lengths straddling the 7-bit, 16-bit and 64-bit length encodings.
// Getting a boundary wrong here corrupts every frame after it.
func TestFrameLengthEncodings(t *testing.T) {
	sizes := []int{0, 1, 125, 126, 127, 65535, 65536, 70000}
	srv := serve(t, func(c *Conn) {
		for _, n := range sizes {
			if err := c.WriteText(make([]byte, n)); err != nil {
				t.Errorf("WriteText(%d): %v", n, err)
				return
			}
		}
		c.Close(CloseNormal, "")
	})
	c, _ := dial(t, srv, nil)
	for _, n := range sizes {
		op, payload := c.recv(t)
		if op != opText {
			t.Fatalf("size %d: opcode = %d", n, op)
		}
		if len(payload) != n {
			t.Errorf("size %d: got %d bytes", n, len(payload))
		}
	}
}

func TestServerAnswersAPing(t *testing.T) {
	srv := serve(t, func(c *Conn) {
		if _, err := c.ReadMessage(); !IsClose(err) {
			t.Errorf("ReadMessage: %v", err)
		}
	})
	c, _ := dial(t, srv, nil)
	c.send(t, opPing, []byte("are you there"))
	op, payload := c.recv(t)
	if op != opPong {
		t.Fatalf("opcode = %d, want pong", op)
	}
	if string(payload) != "are you there" {
		t.Errorf("pong payload = %q, want the ping's", payload)
	}
	c.send(t, opClose, []byte{0x03, 0xE8})
}

func TestServerPing(t *testing.T) {
	srv := serve(t, func(c *Conn) {
		if err := c.Ping(); err != nil {
			t.Errorf("Ping: %v", err)
		}
		c.ReadMessage()
	})
	c, _ := dial(t, srv, nil)
	if op, _ := c.recv(t); op != opPing {
		t.Errorf("expected a ping")
	}
	c.send(t, opPong, nil)
	c.send(t, opClose, nil)
}

func TestReadMessage(t *testing.T) {
	got := make(chan string, 1)
	srv := serve(t, func(c *Conn) {
		m, err := c.ReadMessage()
		if err != nil {
			t.Errorf("ReadMessage: %v", err)
			return
		}
		got <- string(m.Data)
		c.Close(CloseNormal, "")
	})
	c, _ := dial(t, srv, nil)
	c.send(t, opText, []byte(`{"type":"filter","text":"INVITE"}`))
	select {
	case s := <-got:
		if s != `{"type":"filter","text":"INVITE"}` {
			t.Errorf("read %q", s)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReadMessage never returned")
	}
}

// A browser may split a message across frames, and joining them is the
// receiver's job.
func TestFragmentedMessageIsJoined(t *testing.T) {
	got := make(chan string, 1)
	srv := serve(t, func(c *Conn) {
		m, err := c.ReadMessage()
		if err != nil {
			t.Errorf("ReadMessage: %v", err)
			return
		}
		got <- string(m.Data)
		c.Close(CloseNormal, "")
	})
	c, _ := dial(t, srv, nil)
	// FIN clear on the first, continuation after.
	sendFrag := func(op byte, fin bool, payload []byte) {
		var hdr []byte
		b := op
		if fin {
			b |= 0x80
		}
		hdr = append(hdr, b, byte(len(payload))|0x80)
		var mask [4]byte
		rand.Read(mask[:])
		hdr = append(hdr, mask[:]...)
		m := make([]byte, len(payload))
		for i := range payload {
			m[i] = payload[i] ^ mask[i%4]
		}
		c.sendRaw(t, append(hdr, m...))
	}
	sendFrag(opText, false, []byte(`{"type":`))
	sendFrag(opContinuation, false, []byte(`"filter",`))
	sendFrag(opContinuation, true, []byte(`"text":"BYE"}`))

	select {
	case s := <-got:
		if s != `{"type":"filter","text":"BYE"}` {
			t.Errorf("joined message = %q", s)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReadMessage never returned")
	}
}

func TestCleanCloseFromTheClient(t *testing.T) {
	errc := make(chan error, 1)
	srv := serve(t, func(c *Conn) {
		_, err := c.ReadMessage()
		errc <- err
	})
	c, _ := dial(t, srv, nil)
	payload := append(binary.BigEndian.AppendUint16(nil, CloseGoingAway), "tab closed"...)
	c.send(t, opClose, payload)

	err := <-errc
	var ce *CloseError
	if !errors.As(err, &ce) {
		t.Fatalf("err = %v, want a CloseError", err)
	}
	if ce.Code != CloseGoingAway || ce.Reason != "tab closed" {
		t.Errorf("close = %d %q", ce.Code, ce.Reason)
	}
	if !IsClose(err) {
		t.Error("IsClose should recognise a clean close")
	}
}

// An unmasked client frame is how a cache-poisoning proxy attack starts, and
// the RFC requires the server to reject it.
func TestUnmaskedClientFrameIsRejected(t *testing.T) {
	errc := make(chan error, 1)
	srv := serve(t, func(c *Conn) {
		_, err := c.ReadMessage()
		errc <- err
	})
	c, _ := dial(t, srv, nil)
	c.sendRaw(t, []byte{0x81, 0x02, 'h', 'i'}) // FIN|text, length 2, no mask bit

	select {
	case err := <-errc:
		if err == nil || !strings.Contains(err.Error(), "not masked") {
			t.Errorf("err = %v, want a masking complaint", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the server accepted an unmasked frame")
	}
}

func TestOversizedFrameIsRefused(t *testing.T) {
	errc := make(chan error, 1)
	srv := serve(t, func(c *Conn) {
		_, err := c.ReadMessage()
		errc <- err
	})
	c, _ := dial(t, srv, nil)
	// A 64-bit length far beyond the cap, and no payload to follow: the server
	// must refuse on the header rather than try to allocate it.
	hdr := []byte{0x81, 127 | 0x80}
	hdr = binary.BigEndian.AppendUint64(hdr, 1<<40)
	hdr = append(hdr, 0, 0, 0, 0)
	c.sendRaw(t, hdr)

	select {
	case err := <-errc:
		if err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Errorf("err = %v, want a size complaint", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the server tried to read an absurd frame")
	}
}

func TestFragmentedControlFrameIsRejected(t *testing.T) {
	errc := make(chan error, 1)
	srv := serve(t, func(c *Conn) {
		_, err := c.ReadMessage()
		errc <- err
	})
	c, _ := dial(t, srv, nil)
	c.sendRaw(t, []byte{opPing, 0x80, 0, 0, 0, 0}) // FIN clear on a ping

	select {
	case err := <-errc:
		if err == nil || !strings.Contains(err.Error(), "control frame") {
			t.Errorf("err = %v, want a control-frame complaint", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the server accepted a fragmented control frame")
	}
}

func TestInvalidUTF8TextIsRejected(t *testing.T) {
	errc := make(chan error, 1)
	srv := serve(t, func(c *Conn) {
		_, err := c.ReadMessage()
		errc <- err
	})
	c, _ := dial(t, srv, nil)
	c.send(t, opText, []byte{0xFF, 0xFE})

	select {
	case err := <-errc:
		if err == nil || !strings.Contains(err.Error(), "UTF-8") {
			t.Errorf("err = %v, want a UTF-8 complaint", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the server accepted invalid UTF-8 as text")
	}
}

// A browser pointed at the wrong URL should get an error it can show.
func TestNonUpgradeRequestGetsAnHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := Accept(w, r); err == nil {
			t.Error("Accept should have refused a plain GET")
		}
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/ws")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUpgradeRequired {
		t.Errorf("status = %d, want 426", resp.StatusCode)
	}
}

func TestBadHandshakes(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string]string
		status  int
	}{
		{"wrong version", map[string]string{"Sec-WebSocket-Version": "8"}, http.StatusUpgradeRequired},
		{"no key", map[string]string{"Sec-WebSocket-Key": ""}, http.StatusBadRequest},
		{"no upgrade header", map[string]string{"Upgrade": ""}, http.StatusUpgradeRequired},
		{"wrong upgrade", map[string]string{"Upgrade": "h2c"}, http.StatusUpgradeRequired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if _, err := Accept(w, r); err == nil {
					t.Error("Accept should have refused this handshake")
				}
			}))
			defer srv.Close()
			_, resp := dial(t, srv, tc.headers)
			if resp.StatusCode != tc.status {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.status)
			}
		})
	}
}

// "Connection: keep-alive, Upgrade" is legal, and a plain string compare
// misses it. Some proxies send exactly that.
func TestConnectionHeaderWithSeveralTokens(t *testing.T) {
	srv := serve(t, func(c *Conn) {
		c.WriteText([]byte("ok"))
		c.Close(CloseNormal, "")
	})
	c, resp := dial(t, srv, map[string]string{"Connection": "keep-alive, Upgrade"})
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	if _, p := c.recv(t); string(p) != "ok" {
		t.Errorf("payload = %q", p)
	}
}

func TestWriteAfterCloseIsAnError(t *testing.T) {
	done := make(chan struct{})
	srv := serve(t, func(c *Conn) {
		defer close(done)
		c.Close(CloseNormal, "")
		if err := c.WriteText([]byte("too late")); !errors.Is(err, ErrClosed) {
			t.Errorf("WriteText after Close = %v, want ErrClosed", err)
		}
		// Closing twice is safe.
		if err := c.Close(CloseNormal, ""); err != nil {
			t.Errorf("second Close = %v", err)
		}
	})
	dial(t, srv, nil)
	<-done
}

func TestConcurrentWritesAreSerialised(t *testing.T) {
	const n = 50
	srv := serve(t, func(c *Conn) {
		done := make(chan struct{})
		for i := 0; i < 4; i++ {
			go func() {
				defer func() { done <- struct{}{} }()
				for j := 0; j < n; j++ {
					if err := c.WriteText([]byte("0123456789")); err != nil {
						return
					}
				}
			}()
		}
		for i := 0; i < 4; i++ {
			<-done
		}
		c.Close(CloseNormal, "")
	})
	c, _ := dial(t, srv, nil)
	// Every frame must arrive intact: interleaved writes would corrupt them.
	for i := 0; i < 4*n; i++ {
		op, p := c.recv(t)
		if op != opText || string(p) != "0123456789" {
			t.Fatalf("frame %d = op %d, %q: writes were interleaved", i, op, p)
		}
	}
}
