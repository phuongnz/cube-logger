package web

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/phuongnz/cube-logger/internal/ingest"
	"github.com/phuongnz/cube-logger/internal/live"
	"github.com/phuongnz/cube-logger/internal/load"
	"github.com/phuongnz/cube-logger/internal/session"
)

// maxUpload bounds a file opened from the browser. A day of debug output from
// a busy CUBE is a few hundred megabytes, and the ring is what actually limits
// what is kept.
const maxUpload = 512 << 20

// serveSession writes the whole ring out as a session file.
//
// It is a download rather than a path the server writes to, on purpose: the
// browser decides where it lands, and this process never writes a file it was
// not started with.
func (s *Server) serveSession(w http.ResponseWriter, r *http.Request) {
	gz := r.URL.Query().Get("gzip") != ""
	name := "cube-logger-" + time.Now().Format("20060102-1504") + session.Ext
	if gz {
		name += ".gz"
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)

	st := s.Store.Stats()
	entries := s.Store.Recent(st.Records)
	year := time.Now().Year()
	if len(entries) > 0 && entries[0].Record != nil && entries[0].Record.Record != nil {
		year = entries[0].Record.Time.Year()
	}
	sw, err := session.NewWriter(w, session.Header{
		Title:  s.Title,
		Year:   year,
		Listen: s.ListenAddr(),
	}, session.Options{Gzip: gz})
	if err != nil {
		// Nothing has been written yet, so an error is still an error.
		http.Error(w, "session: "+err.Error(), http.StatusInternalServerError)
		return
	}
	for _, e := range entries {
		if err := sw.Record(e.Record); err != nil {
			// The header is already on the wire; the browser will see a file
			// with no end marker, which the reader reports as cut off. That is
			// a better answer than a status code nobody can see.
			return
		}
	}
	_ = sw.Close(s.status().Sources)
}

// ListenAddr is where syslog is received, as a person reads it: each address
// with its transport, because a router has to be told both. It is empty when
// the session was opened from files.
func (s *Server) ListenAddr() string {
	var parts []string
	if s.Listener != nil {
		parts = append(parts, s.Listener.Addr()+"/udp")
	}
	if s.TLS != nil {
		parts = append(parts, s.TLS.Addr()+"/tls")
	}
	return strings.Join(parts, ", ")
}

// loadResult is what the browser is told about a file it opened.
type loadResult struct {
	Name    string   `json:"name"`
	Format  string   `json:"format"`
	Records int      `json:"records"`
	Lines   int      `json:"lines"`
	Sources []string `json:"sources,omitempty"`
	Notes   []string `json:"notes,omitempty"`
}

// serveLoad reads a file the browser sent and adds it to this session.
//
// The records go in through the same door the live path uses, so the call
// index sees them in order and every watcher is told about them the usual way.
// A file opened here sits beside whatever is already in the ring, told apart
// by its device, which is how two CUBEs or a file and a live stream can be
// compared in one table.
func (s *Server) serveLoad(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "post a file here", http.StatusMethodNotAllowed)
		return
	}
	if s.Add == nil {
		http.Error(w, "this session cannot take a file: it was not started with one door into the store",
			http.StatusNotImplemented)
		return
	}
	name := r.URL.Query().Get("name")
	if name == "" {
		name = "uploaded"
	}
	// A path is not a name. Whatever the browser sent, only the last element
	// is used, and it is only ever shown, never opened.
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}

	body := http.MaxBytesReader(w, r.Body, maxUpload)
	defer body.Close()

	rd, isSession, err := session.Sniff(body)
	if err != nil {
		http.Error(w, "read: "+err.Error(), http.StatusBadRequest)
		return
	}

	out := loadResult{Name: name}
	var recs []*live.Record
	var sources []live.SourceStat
	if isSession {
		res, err := session.Read(rd, s.Year)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		recs, sources, out.Notes = res.Records, res.Sources, res.Notes
		out.Format = "a saved session"
		out.Lines = len(res.Records)
	} else {
		res, err := load.File(rd, load.Options{Year: s.Year, Source: name})
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		recs, sources, out.Notes = res.Records, res.Sources, res.Notes
		out.Format = res.Format.Describe()
		out.Lines = res.Lines
		if res.Format == ingest.Unknown {
			out.Format = "an unrecognised format"
		}
	}
	for _, src := range sources {
		out.Sources = append(out.Sources, src.Source)
	}
	out.Records = len(recs)
	if len(recs) == 0 {
		http.Error(w, fmt.Sprintf("%s: nothing in this file could be read as CUBE output (%s)",
			name, out.Format), http.StatusBadRequest)
		return
	}
	s.Add(recs...)
	s.addSources(sources)
	writeJSON(w, out)
}

// addSources records the devices a loaded file brought, for the status bar of
// a session that has no listener to ask.
func (s *Server) addSources(add []live.SourceStat) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, n := range add {
		found := false
		for i, cur := range s.Sources {
			if cur.Source == n.Source {
				s.Sources[i].Records += n.Records
				s.Sources[i].Lines += n.Lines
				s.Sources[i].LostRecords += n.LostRecords
				found = true
				break
			}
		}
		if !found {
			s.Sources = append(s.Sources, n)
		}
	}
}
