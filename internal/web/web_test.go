package web

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/phuongnz/cube-logger/internal/live"
	"github.com/phuongnz/cube-logger/internal/parse"
	"github.com/phuongnz/cube-logger/internal/store"
)

// rec builds a record shaped the way the reassembler emits one. The values are
// invented; nothing here comes from a capture.
func rec(text, source, call string, sev int) *live.Record {
	return &live.Record{
		Record: &parse.Record{
			Kind:   parse.KindLog,
			Time:   time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
			Source: source,
			Text:   text,
			Raw:    []string{text},
		},
		Severity:     sev,
		SeverityName: "informational",
		Received:     time.Now(),
		Lines:        1,
		Call:         call,
		RawLines:     []string{text},
	}
}

// serve starts the real handler on a real loopback socket. httptest.Server is
// the right tool here rather than httptest.NewRecorder, because the WebSocket
// path hijacks the connection and a recorder cannot be hijacked.
func serve(t *testing.T, s *Server) *httptest.Server {
	t.Helper()
	if s.Store == nil {
		s.Store = store.New(100)
	}
	srv := httptest.NewServer(s.handler())
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, url string) map[string]any {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d", url, resp.StatusCode)
	}
	var v map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		t.Fatalf("GET %s: decode: %v", url, err)
	}
	return v
}

func TestIndexIsServedFromTheBinary(t *testing.T) {
	srv := serve(t, &Server{})
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "app.js") {
		t.Errorf("index.html does not load app.js:\n%s", body)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store: a stale UI against a new binary is a bug report that cannot be reproduced",
			resp.Header.Get("Cache-Control"))
	}
}

// The UI must not reach for anything off this machine. The tool is local-only,
// and a CDN reference would be an outbound call at runtime.
func TestUIFetchesNothingFromTheNetwork(t *testing.T) {
	srv := serve(t, &Server{})
	for _, name := range []string{"/index.html", "/app.js", "/style.css"} {
		resp, err := http.Get(srv.URL + name)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status %d", name, resp.StatusCode)
		}
		for _, bad := range []string{"http://", "https://", "//cdn", "fonts.googleapis"} {
			if strings.Contains(string(body), bad) {
				t.Errorf("%s references %q — the UI must load nothing from the network", name, bad)
			}
		}
	}
}

func TestStatsReportsTheStore(t *testing.T) {
	s := &Server{Store: store.New(10), Live: live.New(), Title: "lab-cube"}
	srv := serve(t, s)
	s.Store.Add(rec("one", "192.0.2.1", "", 6))

	v := get(t, srv.URL+"/api/stats")
	if v["title"] != "lab-cube" {
		t.Errorf("title = %v", v["title"])
	}
	st, _ := v["store"].(map[string]any)
	if st == nil || st["records"] != float64(1) {
		t.Errorf("store stats = %v", v["store"])
	}
	if _, ok := v["sources"]; !ok {
		t.Error("no sources field; the status bar needs one per device")
	}
}

// A nil Live and a nil Listener are the saved-file case, and must not panic.
func TestStatsWithoutAListener(t *testing.T) {
	srv := serve(t, &Server{Store: store.New(10)})
	v := get(t, srv.URL+"/api/stats")
	if _, ok := v["listener"]; ok {
		t.Errorf("listener reported with no listener: %v", v["listener"])
	}
}

func recordTexts(t *testing.T, v map[string]any) []string {
	t.Helper()
	list, ok := v["records"].([]any)
	if !ok {
		t.Fatalf("no records array in %v", v)
	}
	var out []string
	for _, e := range list {
		m := e.(map[string]any)
		out = append(out, fmt.Sprint(m["text"]))
	}
	return out
}

func TestRecordsFilters(t *testing.T) {
	s := &Server{Store: store.New(100)}
	srv := serve(t, s)
	s.Store.Add(
		rec("call setup ok", "192.0.2.1", "leg-1", 6),
		rec("gateway down", "192.0.2.2", "leg-2", 3),
		rec("call teardown", "192.0.2.1", "leg-1", 6),
	)

	cases := []struct {
		query string
		want  []string
	}{
		{"", []string{"call setup ok", "gateway down", "call teardown"}},
		{"?text=call", []string{"call setup ok", "call teardown"}},
		{"?source=192.0.2.2", []string{"gateway down"}},
		{"?call=leg-1", []string{"call setup ok", "call teardown"}},
		{"?severity=3", []string{"gateway down"}},
		{"?limit=1", []string{"call teardown"}},
		{"?text=nothing-matches-this", nil},
	}
	for _, c := range cases {
		got := recordTexts(t, get(t, srv.URL+"/api/records"+c.query))
		if fmt.Sprint(got) != fmt.Sprint(c.want) {
			t.Errorf("/api/records%s = %v, want %v", c.query, got, c.want)
		}
	}
}

// An empty result has to serialize as [] and not null, or the browser has to
// guard every iteration.
func TestEmptyRecordsIsAnArray(t *testing.T) {
	srv := serve(t, &Server{Store: store.New(10)})
	resp, err := http.Get(srv.URL + "/api/records")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"records":[]`) {
		t.Errorf("empty result = %s, want an empty array", body)
	}
}

func TestRecordsSinceResumesAndReportsEviction(t *testing.T) {
	s := &Server{Store: store.New(4)}
	srv := serve(t, s)
	s.Store.Add(rec("a", "192.0.2.1", "", 6), rec("b", "192.0.2.1", "", 6))

	v := get(t, srv.URL+"/api/records?since=1")
	if got := recordTexts(t, v); fmt.Sprint(got) != "[b]" {
		t.Errorf("since=1 = %v, want [b]", got)
	}
	if v["missed"] != float64(0) {
		t.Errorf("missed = %v, want 0", v["missed"])
	}

	// Overflow the ring so ID 1 is gone, then ask for it again.
	for i := 0; i < 6; i++ {
		s.Store.Add(rec("fill", "192.0.2.1", "", 6))
	}
	v = get(t, srv.URL+"/api/records?since=1")
	if v["missed"] == float64(0) {
		t.Error("eviction not reported: the browser would silently show a hole as continuity")
	}
}

// The raw lines are what an engineer actually reads. parse.Record keeps them
// out of JSON; live.Record has to put them back, or the detail pane is empty.
func TestRecordsCarryTheRawLines(t *testing.T) {
	s := &Server{Store: store.New(10)}
	srv := serve(t, s)
	s.Store.Add(rec("SIP/2.0 200 OK", "192.0.2.1", "", 6))

	body := get(t, srv.URL+"/api/records")
	list := body["records"].([]any)
	raw, ok := list[0].(map[string]any)["raw"].([]any)
	if !ok || len(raw) != 1 || raw[0] != "SIP/2.0 200 OK" {
		t.Errorf("raw = %v, want the record's lines", list[0].(map[string]any)["raw"])
	}
}

// localOnly is defence in depth: the socket binds 127.0.0.1, and the handler
// refuses anything that is not loopback anyway, so a future bind-elsewhere flag
// has to remove this deliberately rather than by accident.
func TestNonLoopbackIsRefused(t *testing.T) {
	h := (&Server{Store: store.New(10)}).handler()
	for _, addr := range []string{"203.0.113.9:1234", "[2001:db8::1]:1234"} {
		req := httptest.NewRequest("GET", "/api/stats", nil)
		req.RemoteAddr = addr
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("remote %s: status %d, want 403", addr, w.Code)
		}
	}
	for _, addr := range []string{"127.0.0.1:1234", "[::1]:1234"} {
		req := httptest.NewRequest("GET", "/api/stats", nil)
		req.RemoteAddr = addr
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("remote %s: status %d, want 200", addr, w.Code)
		}
	}
}

// --- a WebSocket client, only as much of RFC 6455 as these tests need ---

type client struct {
	t  *testing.T
	c  net.Conn
	br *bufio.Reader
}

func dial(t *testing.T, srv *httptest.Server, path string) *client {
	t.Helper()
	host := strings.TrimPrefix(srv.URL, "http://")
	c, err := net.Dial("tcp", host)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))

	key := make([]byte, 16)
	_, _ = rand.Read(key)
	fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\n"+
		"Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		path, host, base64.StdEncoding.EncodeToString(key))

	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("handshake: status %d, want 101", resp.StatusCode)
	}
	return &client{t: t, c: c, br: br}
}

// read returns the next data message as a decoded JSON object, answering pings
// on the way so the server does not time the connection out.
func (c *client) read() map[string]any {
	c.t.Helper()
	for {
		op, payload := c.frame()
		switch op {
		case 0x1, 0x2:
			var v map[string]any
			if err := json.Unmarshal(payload, &v); err != nil {
				c.t.Fatalf("bad JSON frame %q: %v", payload, err)
			}
			return v
		case 0x9:
			c.send(0xA, payload)
		case 0x8:
			c.t.Fatalf("server closed: %q", payload)
		}
	}
}

// readType skips messages until one of the wanted type arrives. Stats and
// record frames interleave on a live socket, so a test that wants one must not
// depend on the other not being there.
func (c *client) readType(want string) map[string]any {
	c.t.Helper()
	for i := 0; i < 50; i++ {
		v := c.read()
		if v["type"] == want {
			return v
		}
	}
	c.t.Fatalf("no %q message in 50 frames", want)
	return nil
}

func (c *client) frame() (byte, []byte) {
	c.t.Helper()
	var h [2]byte
	if _, err := io.ReadFull(c.br, h[:]); err != nil {
		c.t.Fatalf("read frame header: %v", err)
	}
	op := h[0] & 0x0f
	if h[1]&0x80 != 0 {
		c.t.Fatal("server frame is masked; a server must never mask")
	}
	n := uint64(h[1] & 0x7f)
	switch n {
	case 126:
		var b [2]byte
		_, _ = io.ReadFull(c.br, b[:])
		n = uint64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		_, _ = io.ReadFull(c.br, b[:])
		n = binary.BigEndian.Uint64(b[:])
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(c.br, p); err != nil {
		c.t.Fatalf("read frame payload: %v", err)
	}
	return op, p
}

func (c *client) send(op byte, payload []byte) {
	c.t.Helper()
	var mask [4]byte
	_, _ = rand.Read(mask[:])
	hdr := []byte{0x80 | op}
	n := len(payload)
	switch {
	case n < 126:
		hdr = append(hdr, 0x80|byte(n))
	case n < 1<<16:
		hdr = append(hdr, 0x80|126, byte(n>>8), byte(n))
	default:
		c.t.Fatal("test client does not send frames this large")
	}
	hdr = append(hdr, mask[:]...)
	masked := make([]byte, n)
	for i := range payload {
		masked[i] = payload[i] ^ mask[i%4]
	}
	if _, err := c.c.Write(append(hdr, masked...)); err != nil {
		c.t.Fatalf("write frame: %v", err)
	}
}

func entryIDs(t *testing.T, v map[string]any) []uint64 {
	t.Helper()
	list, ok := v["records"].([]any)
	if !ok {
		t.Fatalf("no records in %v", v)
	}
	var out []uint64
	for _, e := range list {
		out = append(out, uint64(e.(map[string]any)["id"].(float64)))
	}
	return out
}

func TestWebSocketGreetsThenBackfillsThenStreams(t *testing.T) {
	s := &Server{Store: store.New(100), Title: "lab-cube"}
	srv := serve(t, s)
	s.Store.Add(rec("before", "192.0.2.1", "", 6))

	c := dial(t, srv, "/ws")
	hello := c.read()
	if hello["type"] != "hello" {
		t.Fatalf("first message is %v, want hello", hello["type"])
	}
	if st, _ := hello["status"].(map[string]any); st == nil || st["title"] != "lab-cube" {
		t.Errorf("hello carries no status: %v", hello)
	}

	first := c.readType("records")
	if got := recordTexts(t, first); fmt.Sprint(got) != "[before]" {
		t.Errorf("backfill = %v, want [before]", got)
	}

	// Anything added now must arrive without another request.
	s.Store.Add(rec("after", "192.0.2.1", "", 6))
	live := c.readType("records")
	if got := recordTexts(t, live); fmt.Sprint(got) != "[after]" {
		t.Errorf("streamed = %v, want [after]", got)
	}
}

func TestWebSocketSinceSkipsWhatTheBrowserHas(t *testing.T) {
	s := &Server{Store: store.New(100)}
	srv := serve(t, s)
	s.Store.Add(rec("a", "192.0.2.1", "", 6), rec("b", "192.0.2.1", "", 6), rec("c", "192.0.2.1", "", 6))

	c := dial(t, srv, "/ws?since=2")
	if v := c.read(); v["type"] != "hello" {
		t.Fatalf("first message is %v", v["type"])
	}
	got := entryIDs(t, c.readType("records"))
	if fmt.Sprint(got) != "[3]" {
		t.Errorf("resume from 2 gave %v, want only id 3", got)
	}
}

// A restarted server numbers its records from 1 again. A browser that was
// open across the restart asks for what came after its last ID, and without
// the epoch the new server would take that ID as its own and send nothing
// until it caught up with a number from another process.
func TestWebSocketStartsOverForAnIDFromAnotherStore(t *testing.T) {
	s := &Server{Store: store.New(100)}
	srv := serve(t, s)
	s.Store.Add(rec("a", "192.0.2.1", "", 6), rec("b", "192.0.2.1", "", 6), rec("c", "192.0.2.1", "", 6))
	epoch := s.Store.Stats().Epoch

	c := dial(t, srv, "/ws?since=2&epoch="+epoch)
	c.read() // hello
	if got := entryIDs(t, c.readType("records")); fmt.Sprint(got) != "[3]" {
		t.Errorf("resume from 2 in this store gave %v, want only id 3", got)
	}

	c = dial(t, srv, "/ws?since=2&epoch=another-store")
	hello := c.read()
	if hello["type"] != "hello" {
		t.Fatalf("first message is %v", hello["type"])
	}
	st, _ := hello["status"].(map[string]any)
	if sto, _ := st["store"].(map[string]any); sto["epoch"] != epoch {
		t.Errorf("hello says epoch %v, want %q so the browser can tell it restarted", sto["epoch"], epoch)
	}
	if got := entryIDs(t, c.readType("records")); fmt.Sprint(got) != "[1 2 3]" {
		t.Errorf("an ID from another store gave %v, want everything, as for a new browser", got)
	}
}

func TestWebSocketReportsEvictionAsResyncNotAsLoss(t *testing.T) {
	s := &Server{Store: store.New(4)}
	srv := serve(t, s)
	for i := 0; i < 10; i++ {
		s.Store.Add(rec("fill", "192.0.2.1", "", 6))
	}
	c := dial(t, srv, "/ws?since=1")
	if v := c.read(); v["type"] != "hello" {
		t.Fatalf("first message is %v", v["type"])
	}
	v := c.readType("resync")
	if v["missed"] == float64(0) {
		t.Errorf("resync reports no misses: %v", v)
	}
}

func TestWebSocketPushesStats(t *testing.T) {
	s := &Server{Store: store.New(10), Live: live.New()}
	srv := serve(t, s)
	c := dial(t, srv, "/ws")
	c.read() // hello
	v := c.readType("stats")
	if _, ok := v["status"].(map[string]any); !ok {
		t.Errorf("stats message carries no status: %v", v)
	}
}

// A browser that closes cleanly must not leave a subscriber behind: on a
// days-long session a leak per reload is a leak per reload.
func TestClosingTheSocketDropsTheSubscriber(t *testing.T) {
	s := &Server{Store: store.New(10)}
	srv := serve(t, s)
	c := dial(t, srv, "/ws")
	c.read()
	if got := s.Store.Stats().Watchers; got != 1 {
		t.Fatalf("watchers = %d, want 1", got)
	}
	c.send(0x8, []byte{0x03, 0xe8}) // close, 1000
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if s.Store.Stats().Watchers == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("watchers = %d after close, want 0", s.Store.Stats().Watchers)
}

func TestWebSocketNeedsAnUpgradeRequest(t *testing.T) {
	srv := serve(t, &Server{Store: store.New(10)})
	resp, err := http.Get(srv.URL + "/ws")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusSwitchingProtocols {
		t.Error("a plain GET was upgraded")
	}
}
