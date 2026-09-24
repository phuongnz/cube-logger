// Package web serves the live view: a static UI and a WebSocket that pushes
// records to it.
//
// It binds the loopback interface. That is not a default to be overridden
// lightly — the UI has no authentication of any kind, and what it displays is
// every phone number, address and SIP header the router logs. Binding anything
// else publishes a customer's call detail to the network.
//
// The UI is plain JavaScript and CSS under ui/, embedded with go:embed. There
// is no build step: "go build" produces the whole product, and a user who
// downloads one file gets one file that works.
package web

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/phuongnz/cube-logger/internal/listen"
	"github.com/phuongnz/cube-logger/internal/live"
	"github.com/phuongnz/cube-logger/internal/store"
	"github.com/phuongnz/cube-logger/internal/ws"
)

//go:embed ui
var uiFS embed.FS

// Tuning for the push loop.
const (
	// backfill is how many records a newly connected browser is given before
	// the live stream starts. Enough to see the call that just happened,
	// bounded so that opening a tab on a long session is not a stall.
	backfill = 5000

	// resyncLimit bounds a catch-up after a browser fell behind.
	resyncLimit = 20000

	// flushInterval batches records into one frame. A busy CUBE produces
	// records faster than a browser can usefully repaint, and one frame per
	// record would spend the whole budget on framing.
	flushInterval = 100 * time.Millisecond

	// statsInterval is how often the status bar is refreshed.
	statsInterval = time.Second

	// pingInterval and pongWait notice a browser that went away without
	// closing — a laptop that slept, a tab killed by the OS.
	pingInterval = 30 * time.Second
	pongWait     = 90 * time.Second
)

// Server is the local web server.
type Server struct {
	Store *store.Store
	// Live is consulted for per-source reassembly statistics. It may be nil
	// when a saved file was loaded rather than a listener started.
	Live *live.Reassembler
	// Listener is consulted for socket statistics, and may be nil for the
	// same reason.
	Listener *listen.Listener

	// Title is shown in the browser tab and the header, so an engineer with
	// two sessions open can tell them apart.
	Title string

	mux  *http.Server
	ln   net.Listener
	addr string
}

// Open binds addr and prepares to serve. It does not start serving; call
// Serve. Binding first means the caller can print the real URL, including the
// port the kernel picked for ":0", before anything can connect.
func Open(addr string, s *Server) error {
	if addr == "" {
		addr = "127.0.0.1:8514"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.ln = ln
	s.addr = ln.Addr().String()
	s.mux = &http.Server{
		Handler: s.handler(),
		// A slow or stuck client must not hold a connection open forever.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		// No WriteTimeout: it would cut the WebSocket off mid-session, since a
		// hijacked connection is long-lived by design. ws.Conn sets its own
		// per-write deadline instead.
	}
	return nil
}

// Addr is the address actually bound, with the real port filled in.
func (s *Server) Addr() string { return s.addr }

// URL is the address to open in a browser.
func (s *Server) URL() string {
	addr := s.addr
	// A bare ":8514" or "0.0.0.0:8514" is not something a browser can open.
	if h, p, err := net.SplitHostPort(addr); err == nil && (h == "" || h == "0.0.0.0" || h == "::") {
		addr = net.JoinHostPort("127.0.0.1", p)
	}
	return "http://" + addr
}

// Serve runs until ctx is cancelled.
func (s *Server) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.mux.Shutdown(shutdown)
	}()
	err := s.mux.Serve(s.ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()
	sub, err := fs.Sub(uiFS, "ui")
	if err != nil {
		panic("web: embedded ui missing: " + err.Error())
	}
	files := http.FileServer(http.FS(sub))
	mux.Handle("/", noStore(files))
	mux.HandleFunc("/ws", s.serveWS)
	mux.HandleFunc("/api/stats", s.serveStats)
	mux.HandleFunc("/api/records", s.serveRecords)
	return localOnly(mux)
}

// noStore keeps a browser from caching the UI across versions of the binary.
// A stale app.js against a new server is a bug report nobody can reproduce.
func noStore(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		h.ServeHTTP(w, r)
	})
}

// localOnly refuses anything that did not come from this machine.
//
// The server binds the loopback, so this should be unreachable. It is here
// because the cost of being wrong is a customer's call detail on the network,
// and because a future flag that binds elsewhere should have to remove this
// line deliberately rather than inherit an open door.
func localOnly(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			http.Error(w, "cube-logger serves the local machine only", http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// status is the payload of a stats message and of /api/stats.
type status struct {
	Title    string            `json:"title,omitempty"`
	Store    store.Stats       `json:"store"`
	Sources  []live.SourceStat `json:"sources"`
	Listener *listen.Stats     `json:"listener,omitempty"`
	Listen   string            `json:"listen,omitempty"`
	Allow    string            `json:"allow,omitempty"`
}

func (s *Server) status() status {
	st := status{Title: s.Title, Store: s.Store.Stats()}
	if s.Live != nil {
		st.Sources = s.Live.Stats()
	}
	if st.Sources == nil {
		st.Sources = []live.SourceStat{}
	}
	if s.Listener != nil {
		ls := s.Listener.Stats()
		st.Listener = &ls
		st.Listen = s.Listener.Addr()
		st.Allow = s.Listener.Allowlist().String()
	}
	return st
}

func (s *Server) serveStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.status())
}

// serveRecords is the non-streaming way in: a filtered slice of the ring.
// The UI uses the WebSocket, but this makes the session scriptable with curl,
// which is how a developer debugs the thing that debugs the router.
func (s *Server) serveRecords(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := atoiDefault(q.Get("limit"), 1000)
	m := &store.Match{
		Text:           q.Get("text"),
		Source:         q.Get("source"),
		Call:           q.Get("call"),
		MinSeverity:    -1,
		IncompleteOnly: q.Get("incomplete") == "1",
	}
	if v := q.Get("severity"); v != "" {
		m.MinSeverity = atoiDefault(v, -1)
	}
	if v := q.Get("kind"); v != "" {
		m.Kinds = strings.Split(v, ",")
	}
	if v := q.Get("since"); v != "" {
		after, _ := strconv.ParseUint(v, 10, 64)
		entries, missed := s.Store.Since(after, limit)
		var kept []store.Entry
		for _, e := range entries {
			if m.Accepts(e) {
				kept = append(kept, e)
			}
		}
		writeJSON(w, map[string]any{"records": orEmpty(kept), "missed": missed})
		return
	}
	writeJSON(w, map[string]any{"records": orEmpty(s.Store.Search(m, limit))})
}

func orEmpty(e []store.Entry) []store.Entry {
	if e == nil {
		return []store.Entry{}
	}
	return e
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	_ = enc.Encode(v)
}

// The message types pushed to the browser. Each is a JSON object with a
// "type", which is the only thing the client dispatches on.
type (
	helloMsg struct {
		Type   string `json:"type"`
		Status status `json:"status"`
	}
	recordsMsg struct {
		Type    string        `json:"type"`
		Records []store.Entry `json:"records"`
	}
	statsMsg struct {
		Type   string `json:"type"`
		Status status `json:"status"`
	}
	// resyncMsg tells the browser that records existed which it will never
	// see. It is deliberately a different message from a sequence gap: one is
	// this tool running out of room, the other is the router or the network
	// losing output, and conflating them would send an engineer hunting a
	// network fault that does not exist.
	resyncMsg struct {
		Type   string `json:"type"`
		Missed uint64 `json:"missed"`
		From   uint64 `json:"from"`
	}
)

func (s *Server) serveWS(w http.ResponseWriter, r *http.Request) {
	conn, err := ws.Accept(w, r)
	if err != nil {
		return
	}
	defer conn.Close(ws.CloseGoingAway, "")

	// Subscribe before reading the backfill, so a record arriving between the
	// two is queued rather than lost.
	sub := s.Store.Subscribe(0)
	defer sub.Close()

	if err := send(conn, helloMsg{Type: "hello", Status: s.status()}); err != nil {
		return
	}

	// A browser reconnecting after a dropped socket says where it got to.
	var last uint64
	var initial []store.Entry
	if v := r.URL.Query().Get("since"); v != "" {
		after, _ := strconv.ParseUint(v, 10, 64)
		var missed uint64
		initial, missed = s.Store.Since(after, resyncLimit)
		if missed > 0 {
			if err := send(conn, resyncMsg{Type: "resync", Missed: missed, From: after}); err != nil {
				return
			}
		}
	} else {
		initial = s.Store.Recent(backfill)
	}
	if len(initial) > 0 {
		last = initial[len(initial)-1].ID
		if err := sendRecords(conn, initial); err != nil {
			return
		}
	}

	// The reader exists to answer pings and to notice the tab closing. It owns
	// the read side; the write side is this goroutine plus its mutex.
	gone := make(chan struct{})
	go func() {
		defer close(gone)
		_ = conn.SetReadDeadline(time.Now().Add(pongWait))
		for {
			if _, err := conn.ReadMessage(); err != nil {
				return
			}
			_ = conn.SetReadDeadline(time.Now().Add(pongWait))
		}
	}()

	flush := time.NewTicker(flushInterval)
	defer flush.Stop()
	stats := time.NewTicker(statsInterval)
	defer stats.Stop()
	ping := time.NewTicker(pingInterval)
	defer ping.Stop()

	var batch []store.Entry
	for {
		select {
		case <-gone:
			return

		case entries, ok := <-sub.C:
			if !ok {
				return
			}
			batch = append(batch, entries...)

		case <-flush.C:
			// A dropped batch is not a hole in the record: the ring still has
			// everything, so fetch what was missed rather than showing a gap
			// that is not there.
			if sub.Behind() {
				caught, missed := s.Store.Since(last, resyncLimit)
				if missed > 0 {
					if err := send(conn, resyncMsg{Type: "resync", Missed: missed, From: last}); err != nil {
						return
					}
				}
				batch = caught
			}
			if len(batch) == 0 {
				continue
			}
			// Records may repeat after a resync; the browser keys by ID, but
			// trimming here keeps the frame small.
			batch = after(batch, last)
			if len(batch) == 0 {
				continue
			}
			last = batch[len(batch)-1].ID
			if err := sendRecords(conn, batch); err != nil {
				return
			}
			batch = nil

		case <-stats.C:
			if err := send(conn, statsMsg{Type: "stats", Status: s.status()}); err != nil {
				return
			}

		case <-ping.C:
			if err := conn.Ping(); err != nil {
				return
			}
		}
	}
}

// after drops entries the browser already has.
func after(batch []store.Entry, last uint64) []store.Entry {
	for i, e := range batch {
		if e.ID > last {
			return batch[i:]
		}
	}
	return nil
}

// sendRecords splits a large batch so one frame never grows without bound: a
// replay at full speed can hand over tens of thousands of records at once.
func sendRecords(c *ws.Conn, entries []store.Entry) error {
	const chunk = 2000
	for len(entries) > 0 {
		n := min(chunk, len(entries))
		if err := send(c, recordsMsg{Type: "records", Records: entries[:n]}); err != nil {
			return err
		}
		entries = entries[n:]
	}
	return nil
}

func send(c *ws.Conn, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return c.WriteText(b)
}
