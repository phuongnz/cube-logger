package web

// The call side of the API: the list, one call opened, and one call as text.
//
// The index holds no records — only references into the ring — so everything
// here joins those references back against the store. A record the ring has
// overwritten is reported as missing rather than quietly dropped: a ladder with
// half a call in it, presented as the whole call, is how somebody concludes the
// router never sent an ACK it did send.

import (
	"net/http"
	"strings"

	"github.com/phuongnz/cube-logger/internal/calls"
	"github.com/phuongnz/cube-logger/internal/parse"
)

// Lookup resolves a record reference against the ring. It is what the ladder
// and the text export are built from, and it is exported because the index
// holds references rather than records: anything that opens a call needs it.
func (s *Server) Lookup(ref uint64) *parse.Record {
	e, ok := s.Store.Get(ref)
	if !ok || e.Record == nil {
		return nil
	}
	return e.Record.Record
}

// rawLines returns a record exactly as the router printed it.
func (s *Server) rawLines(ref uint64) []string {
	r := s.Lookup(ref)
	if r == nil {
		return nil
	}
	if len(r.Raw) > 0 {
		return r.Raw
	}
	return []string{r.Text}
}

// noCalls answers when the server was started without an index.
func (s *Server) noCalls(w http.ResponseWriter) bool {
	if s.Calls != nil {
		return false
	}
	http.Error(w, "this session has no call index", http.StatusNotFound)
	return true
}

func (s *Server) serveCalls(w http.ResponseWriter, r *http.Request) {
	if s.noCalls(w) {
		return
	}
	q := r.URL.Query()
	keepalives := q.Get("keepalives") == "1"
	// A browser reconnecting asks for what changed rather than the whole list.
	if v := q.Get("since"); v != "" {
		rev, _ := parseUint(v)
		writeJSON(w, s.Calls.Since(rev))
		return
	}
	list := s.Calls.List(atoiDefault(q.Get("limit"), 500), keepalives)
	writeJSON(w, map[string]any{"calls": list, "stats": s.Calls.Stats()})
}

func (s *Server) serveCall(w http.ResponseWriter, r *http.Request) {
	if s.noCalls(w) {
		return
	}
	d, ok := s.Calls.Get(r.PathValue("id"), s.Lookup)
	if !ok {
		http.Error(w, "no such call", http.StatusNotFound)
		return
	}
	writeJSON(w, d)
}

// serveCallText is the export: one call's messages as plain text, which is
// what gets pasted into a ticket or handed to a carrier.
func (s *Server) serveCallText(w http.ResponseWriter, r *http.Request) {
	if s.noCalls(w) {
		return
	}
	id := r.PathValue("id")
	d, ok := s.Calls.Get(id, s.Lookup)
	if !ok {
		http.Error(w, "no such call", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// The browser's download button wants a file name. It is built from the
	// call ID, which this tool minted, so there is nothing of the customer's
	// in it — but filter it anyway rather than trust an ID from a URL.
	w.Header().Set("Content-Disposition", `attachment; filename="`+safeName(d.ID)+`.txt"`)
	_, _ = w.Write([]byte(calls.Text(d, s.rawLines)))
}

// safeName keeps a file name to characters that cannot end a quoted header or
// climb out of a directory.
func safeName(id string) string {
	keep := func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		}
		return '-'
	}
	name := strings.Map(keep, id)
	if name == "" {
		return "call"
	}
	if len(name) > 64 {
		name = name[:64]
	}
	return name
}
