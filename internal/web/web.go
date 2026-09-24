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
	"sync"
	"time"

	"github.com/phuongnz/cube-logger/internal/calls"
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
	// Calls is the live call index. It may be nil, in which case the call
	// list is simply absent: parsing records is useful on its own.
	Calls *calls.Index
	// Sources is the per-device summary to show when there is no reassembler
	// to ask: a file that was opened rather than a stream that is arriving.
	// It is guarded by mu, because a file opened from the browser adds to it.
	Sources []live.SourceStat

	// Add is the one door into the store, so that records a browser opens from
	// a file reach the call index in the same order they reach the ring. It
	// may be nil, and then the browser cannot open a file into this session.
	Add func(...*live.Record)

	// Year is the calendar year a file opened from the browser belongs to; 0
	// means this year. IOS prints no year.
	Year int

	// Title is shown in the browser tab and the header, so an engineer with
	// two sessions open can tell them apart.
	Title string

	mu   sync.Mutex
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
	mux.HandleFunc("/api/calls", s.serveCalls)
	mux.HandleFunc("/api/calls/{id}", s.serveCall)
	mux.HandleFunc("/api/calls/{id}/text", s.serveCallText)
	mux.HandleFunc("/api/session", s.serveSession)
	mux.HandleFunc("/api/load", s.serveLoad)
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
	Calls    *calls.Stats      `json:"calls,omitempty"`
	Listen   string            `json:"listen,omitempty"`
	Allow    string            `json:"allow,omitempty"`
}

func (s *Server) status() status {
	st := status{Title: s.Title, Store: s.Store.Stats()}
	if s.Live != nil {
		st.Sources = s.Live.Stats()
	} else {
		s.mu.Lock()
		st.Sources = append([]live.SourceStat(nil), s.Sources...)
		s.mu.Unlock()
	}
	if st.Sources == nil {
		st.Sources = []live.SourceStat{}
	}
	if s.Calls != nil {
		cs := s.Calls.Stats()
		st.Calls = &cs
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
	// callsMsg carries the call list as a delta: only the calls whose
	// revision moved, plus the IDs that stopped being calls of their own.
	callsMsg struct {
		Type string `json:"type"`
		calls.Update
	}
	// callMsg is the one call the browser says it is looking at, with its
	// record references and its ladder. It is re-sent whenever that call
	// changes, which is what keeps a ladder growing while the call is up.
	callMsg struct {
		Type string        `json:"type"`
		Call *calls.Detail `json:"call"`
		// Gone is set when the selected call no longer exists: evicted, or
		// the session was cleared. The browser drops its filter rather than
		// showing an empty table it cannot explain.
		Gone string `json:"gone,omitempty"`
	}
)

// clientMsg is the only thing a browser sends us. The rest of the socket is
// one-way.
type clientMsg struct {
	Type string `json:"type"`
	// Call is the call the browser is showing, for a "select" message. Empty
	// means it closed the call and wants nothing pushed.
	Call string `json:"call"`
}

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

	// The reader answers pings, notices the tab closing, and carries the one
	// thing a browser tells us: which call it is looking at. It owns the read
	// side; the write side is this goroutine plus its mutex.
	//
	// selected is buffered and dropped-on-full on purpose: a browser clicking
	// down a call list faster than the push loop turns over should end up on
	// the call it stopped at, not queue every call it passed through.
	gone := make(chan struct{})
	selected := make(chan string, 1)
	go func() {
		defer close(gone)
		_ = conn.SetReadDeadline(time.Now().Add(pongWait))
		for {
			m, err := conn.ReadMessage()
			if err != nil {
				return
			}
			_ = conn.SetReadDeadline(time.Now().Add(pongWait))
			var cm clientMsg
			if m.Binary || json.Unmarshal(m.Data, &cm) != nil || cm.Type != "select" {
				continue
			}
			select {
			case selected <- cm.Call:
			default:
				<-selected
				selected <- cm.Call
			}
		}
	}()

	flush := time.NewTicker(flushInterval)
	defer flush.Stop()
	stats := time.NewTicker(statsInterval)
	defer stats.Stop()
	ping := time.NewTicker(pingInterval)
	defer ping.Stop()

	// callsRev is how far the browser's call list has been brought; watching
	// is the call it has open, if any.
	var callsRev uint64
	var watching string
	if s.Calls != nil {
		u, err := s.pushCalls(conn, 0)
		if err != nil {
			return
		}
		callsRev = u.Rev
	}

	var batch []store.Entry
	for {
		select {
		case <-gone:
			return

		case id := <-selected:
			watching = id
			if watching != "" {
				var err error
				if watching, err = s.pushCall(conn, watching); err != nil {
					return
				}
			}

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
			if s.Calls == nil {
				continue
			}
			u, err := s.pushCalls(conn, callsRev)
			if err != nil {
				return
			}
			callsRev = u.Rev
			// The open call is re-sent only when it actually changed, so a
			// ladder for a call that ended an hour ago is not rebuilt every
			// second for as long as somebody leaves the tab open.
			if watching != "" && changed(u, watching) {
				if watching, err = s.pushCall(conn, watching); err != nil {
					return
				}
			}

		case <-ping.C:
			if err := conn.Ping(); err != nil {
				return
			}
		}
	}
}

// pushCalls sends what changed in the call list since rev and returns the new
// revision. It stays quiet when nothing changed: the call list is beside the
// log table, and a frame a second that redraws it for no reason is a frame a
// second the browser spends not drawing records.
func (s *Server) pushCalls(c *ws.Conn, rev uint64) (calls.Update, error) {
	u := s.Calls.Since(rev)
	if rev != 0 && len(u.Calls) == 0 && len(u.Removed) == 0 && !u.Reset {
		return u, nil
	}
	if rev == 0 {
		// A fresh list, not a delta: say so, so a browser reconnecting after a
		// dropped socket replaces its rows instead of merging into stale ones.
		u.Reset = true
	}
	return u, send(c, callsMsg{Type: "calls", Update: u})
}

// pushCall sends the call the browser has open and returns the ID it should
// now be watching — which is not always the ID it asked for, since two legs
// that turn out to be one call are merged under one of the two IDs.
func (s *Server) pushCall(c *ws.Conn, id string) (string, error) {
	d, ok := s.Calls.Get(id, s.Lookup)
	if !ok {
		return "", send(c, callMsg{Type: "call", Gone: id})
	}
	return d.ID, send(c, callMsg{Type: "call", Call: d})
}

// changed reports whether one call moved in this update, so that an idle call
// costs a scan of what changed rather than a rebuilt ladder every second.
func changed(u calls.Update, id string) bool {
	if u.Reset {
		return true
	}
	for _, c := range u.Calls {
		if c.ID == id {
			return true
		}
	}
	for _, gone := range u.Removed {
		if gone == id {
			return true
		}
	}
	return false
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

// parseUint is strconv.ParseUint with the error dropped: a malformed query
// parameter means "from the beginning", which is the safe answer.
func parseUint(s string) (uint64, bool) {
	n, err := strconv.ParseUint(s, 10, 64)
	return n, err == nil
}
