package web

// The call API, over HTTP and over the socket. The fixtures under testdata/
// are invented; nothing in this file comes from a capture.

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phuongnz/cube-logger/internal/calls"
	"github.com/phuongnz/cube-logger/internal/live"
	"github.com/phuongnz/cube-logger/internal/parse"
	"github.com/phuongnz/cube-logger/internal/store"
)

// withCalls builds a server whose store and index both hold one fixture,
// loaded the way the live path loads it: store first, then the index, in ID
// order.
func withCalls(t *testing.T, fixture string) *Server {
	t.Helper()
	s := &Server{Store: store.New(1000), Calls: calls.New(0)}
	feed(t, s, fixture)
	return s
}

func feed(t *testing.T, s *Server, fixture string) {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "..", "testdata", fixture))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	res, err := parse.Reader(f, "192.0.2.1", 2026)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res.Records {
		lr := &live.Record{Record: r, Severity: 7, Received: time.Now(), Lines: 1}
		for _, e := range s.Store.Add(lr) {
			s.Calls.Add(e.ID, e.Record.Record)
		}
	}
}

func TestCallListIsServed(t *testing.T) {
	s := withCalls(t, "basic_call.txt")
	srv := serve(t, s)

	v := get(t, srv.URL+"/api/calls")
	list, _ := v["calls"].([]any)
	if len(list) != 1 {
		t.Fatalf("calls = %v, want one call", v["calls"])
	}
	row := list[0].(map[string]any)
	for _, field := range []string{"id", "start", "durationMs", "state"} {
		if _, ok := row[field]; !ok {
			t.Errorf("a call row has no %q: %v", field, row)
		}
	}
	// The list is the whole point of the pane: time, from, to, duration,
	// result. A row missing the numbers is a row an engineer cannot scan.
	if row["calling"] == "" || row["called"] == "" {
		t.Errorf("call row has no from/to: %v", row)
	}
	st, _ := v["stats"].(map[string]any)
	if st == nil || st["total"].(float64) < 1 {
		t.Errorf("no index stats alongside the list: %v", v["stats"])
	}
}

func TestOneCallCarriesItsRecordsAndItsLadder(t *testing.T) {
	s := withCalls(t, "basic_call.txt")
	srv := serve(t, s)

	id := firstCallID(t, srv.URL)
	v := get(t, srv.URL+"/api/calls/"+id)
	refs, _ := v["recordRefs"].([]any)
	if len(refs) == 0 {
		t.Fatal("the call carries no record references; the table has nothing to filter on")
	}
	// Every reference has to resolve in the ring, or the table filter shows
	// fewer rows than the call has records.
	for _, ref := range refs {
		if _, ok := s.Store.Get(uint64(ref.(float64))); !ok {
			t.Errorf("reference %v is not in the store", ref)
		}
	}
	ladder, _ := v["ladder"].(map[string]any)
	if ladder == nil {
		t.Fatal("no ladder")
	}
	cols, _ := ladder["columns"].([]any)
	arrows, _ := ladder["arrows"].([]any)
	if len(cols) < 3 {
		t.Errorf("columns = %d, want the CUBE and a peer on each side", len(cols))
	}
	if len(arrows) == 0 {
		t.Error("the ladder has no arrows")
	}
}

func TestOneCallAsText(t *testing.T) {
	s := withCalls(t, "basic_call.txt")
	srv := serve(t, s)
	id := firstCallID(t, srv.URL)

	resp, err := http.Get(srv.URL + "/api/calls/" + id + "/text")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	text := string(body)

	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, id+".txt") {
		t.Errorf("Content-Disposition = %q, want a file named after the call", cd)
	}
	if !strings.Contains(text, "call:      "+id) {
		t.Errorf("the export has no header:\n%s", first(text, 400))
	}
	// The export is what gets pasted into a ticket, so it has to carry the
	// messages themselves and not just a summary of them.
	if !strings.Contains(text, "INVITE") || !strings.Contains(text, "SIP/2.0 200 OK") {
		t.Errorf("the export is missing the SIP messages:\n%s", first(text, 800))
	}
}

func TestTextExportNamesTheRecordsTheRingNoLongerHas(t *testing.T) {
	// A ring of two: by the end of the fixture almost every record of the call
	// has been overwritten. The export must say so rather than present what is
	// left as the whole call.
	s := &Server{Store: store.New(2), Calls: calls.New(0)}
	feed(t, s, "basic_call.txt")
	srv := serve(t, s)
	id := firstCallID(t, srv.URL)

	resp, err := http.Get(srv.URL + "/api/calls/" + id + "/text")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "no longer held") {
		t.Errorf("the export hides the records the buffer overwrote:\n%s", first(string(body), 800))
	}
}

func TestUnknownCallIsNotFound(t *testing.T) {
	srv := serve(t, withCalls(t, "basic_call.txt"))
	for _, path := range []string{"/api/calls/call-999", "/api/calls/call-999/text"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s: status %d, want 404", path, resp.StatusCode)
		}
	}
}

func TestCallAPIWithoutAnIndex(t *testing.T) {
	srv := serve(t, &Server{})
	resp, err := http.Get(srv.URL + "/api/calls")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status %d, want 404 when the session has no call index", resp.StatusCode)
	}
	// And the rest of the session still works: a call index is an extra, not
	// a requirement.
	if v := get(t, srv.URL+"/api/stats"); v["calls"] != nil {
		t.Errorf("stats claim a call index that does not exist: %v", v["calls"])
	}
}

func TestSocketPushesTheCallListAsItGrows(t *testing.T) {
	s := &Server{Store: store.New(1000), Calls: calls.New(0)}
	srv := serve(t, s)

	c := dial(t, srv, "/ws")
	c.readType("hello")
	// An empty session still gets a list, so the browser knows it is current
	// rather than still waiting.
	first := c.readType("calls")
	if first["reset"] != true {
		t.Errorf("the first call message is not a reset: %v", first)
	}

	feed(t, s, "basic_call.txt")
	upd := c.readType("calls")
	list, _ := upd["calls"].([]any)
	if len(list) == 0 {
		t.Fatalf("no calls pushed: %v", upd)
	}
	if _, ok := upd["rev"].(float64); !ok {
		t.Errorf("no revision in %v", upd)
	}
}

func TestSocketPushesTheSelectedCall(t *testing.T) {
	s := withCalls(t, "basic_call.txt")
	srv := serve(t, s)

	c := dial(t, srv, "/ws")
	c.readType("hello")
	id := idOf(t, c.readType("calls"))

	c.send(0x1, mustJSON(t, map[string]any{"type": "select", "call": id}))
	v := c.readType("call")
	call, _ := v["call"].(map[string]any)
	if call == nil {
		t.Fatalf("no call in %v", v)
	}
	if call["id"] != id {
		t.Errorf("selected %s, got %v", id, call["id"])
	}
	if refs, _ := call["recordRefs"].([]any); len(refs) == 0 {
		t.Error("the selected call carries no record references, so the table cannot be filtered")
	}
	if call["ladder"] == nil {
		t.Error("the selected call carries no ladder")
	}
}

func TestSelectingACallThatIsNotThereSaysSo(t *testing.T) {
	s := withCalls(t, "basic_call.txt")
	srv := serve(t, s)

	c := dial(t, srv, "/ws")
	c.readType("hello")
	c.send(0x1, mustJSON(t, map[string]any{"type": "select", "call": "call-does-not-exist"}))
	v := c.readType("call")
	if v["gone"] != "call-does-not-exist" {
		t.Errorf("selecting a missing call gave %v; the browser needs to be told to drop its filter", v)
	}
}

// A message the server does not understand must not end the session: an older
// or newer browser talking to this binary should degrade, not disconnect.
func TestUnknownClientMessagesAreIgnored(t *testing.T) {
	s := withCalls(t, "basic_call.txt")
	srv := serve(t, s)

	c := dial(t, srv, "/ws")
	c.readType("hello")
	c.send(0x1, []byte(`{"type":"nonsense"}`))
	c.send(0x1, []byte(`not json at all`))
	c.readType("stats")
}

func TestQuietSessionDoesNotRepeatTheCallList(t *testing.T) {
	s := withCalls(t, "basic_call.txt")
	srv := serve(t, s)

	c := dial(t, srv, "/ws")
	c.readType("hello")
	c.readType("calls")
	// Two stats ticks with nothing happening in between: the call list must
	// stay off the wire, or the pane redraws once a second for no reason.
	deadline := time.Now().Add(3 * statsInterval)
	ticks := 0
	for time.Now().Before(deadline) && ticks < 2 {
		v := c.read()
		switch v["type"] {
		case "stats":
			ticks++
		case "calls":
			t.Fatalf("the call list was re-sent with nothing changed: %v", v)
		}
	}
}

func firstCallID(t *testing.T, base string) string {
	t.Helper()
	v := get(t, base+"/api/calls")
	list, _ := v["calls"].([]any)
	if len(list) == 0 {
		t.Fatal("no calls")
	}
	return list[0].(map[string]any)["id"].(string)
}

func idOf(t *testing.T, msg map[string]any) string {
	t.Helper()
	list, _ := msg["calls"].([]any)
	if len(list) == 0 {
		t.Fatalf("no calls in %v", msg)
	}
	return list[0].(map[string]any)["id"].(string)
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func first(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func TestSafeNameKeepsAFileNameHarmless(t *testing.T) {
	for in, want := range map[string]string{
		"call-3":        "call-3",
		"../../etc/pwd": "------etc-pwd",
		`a"b`:           "a-b",
		"":              "call",
	} {
		if got := safeName(in); got != want {
			t.Errorf("safeName(%q) = %q, want %q", in, got, want)
		}
	}
	if len(safeName(strings.Repeat("x", 300))) != 64 {
		t.Error("safeName does not bound the length")
	}
}

// The UI is plain JavaScript with no build step and no test runner, so a typo
// in an element id is a silent failure in a browser nobody is watching. This
// is the cheapest guard that catches it: every id the script reaches for has
// to exist in the page.
func TestEveryElementTheScriptWantsIsInThePage(t *testing.T) {
	js, err := uiFS.ReadFile("ui/app.js")
	if err != nil {
		t.Fatal(err)
	}
	html, err := uiFS.ReadFile("ui/index.html")
	if err != nil {
		t.Fatal(err)
	}
	page := string(html)
	rest := string(js)
	seen := 0
	for {
		i := strings.Index(rest, "$('")
		if i < 0 {
			break
		}
		rest = rest[i+3:]
		j := strings.Index(rest, "'")
		if j < 0 {
			break
		}
		id := rest[:j]
		rest = rest[j:]
		seen++
		if !strings.Contains(page, `id="`+id+`"`) {
			t.Errorf("app.js asks for #%s, which is not in index.html", id)
		}
	}
	if seen < 20 {
		t.Errorf("found only %d element lookups; this test has stopped reading the script", seen)
	}
}
