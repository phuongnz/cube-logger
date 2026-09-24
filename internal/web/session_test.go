package web

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/phuongnz/cube-logger/internal/calls"
	"github.com/phuongnz/cube-logger/internal/live"
	"github.com/phuongnz/cube-logger/internal/session"
	"github.com/phuongnz/cube-logger/internal/store"
)

// door is the one way into the store, the same shape cmd/cube-logger uses.
type door struct {
	mu sync.Mutex
	st *store.Store
	ix *calls.Index
}

func (d *door) add(recs ...*live.Record) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, e := range d.st.Add(recs...) {
		if d.ix != nil && e.Record != nil && e.Record.Record != nil {
			d.ix.Add(e.ID, e.Record.Record)
		}
	}
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "files", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func post(t *testing.T, url string, body []byte) (int, string) {
	t.Helper()
	resp, err := http.Post(url, "application/octet-stream", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(b)
}

func TestSaveTheSessionAndOpenItAgain(t *testing.T) {
	st := store.New(100)
	st.Add(rec("first", "cube-a", "1", 6), rec("second", "cube-b", "2", 6))
	srv := serve(t, &Server{Store: st, Title: "two devices"})

	resp, err := http.Get(srv.URL + "/api/session")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, session.Ext) {
		t.Errorf("Content-Disposition = %q; a session is a download with a name", cd)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	back, err := session.Read(bytes.NewReader(body), 2026)
	if err != nil {
		t.Fatalf("what the server saved cannot be read back: %v", err)
	}
	if back.Truncated {
		t.Error("the saved file has no end marker")
	}
	if back.Header.Title != "two devices" {
		t.Errorf("title = %q", back.Header.Title)
	}
	if len(back.Records) != 2 {
		t.Fatalf("%d record(s) back, want 2", len(back.Records))
	}
	if back.Records[0].Source != "cube-a" || back.Records[1].Source != "cube-b" {
		t.Errorf("devices = %q, %q", back.Records[0].Source, back.Records[1].Source)
	}
}

func TestOpenAFileIntoARunningSession(t *testing.T) {
	d := &door{st: store.New(1000), ix: calls.New(50)}
	srv := serve(t, &Server{Store: d.st, Calls: d.ix, Add: d.add, Year: 2026})

	code, body := post(t, srv.URL+"/api/load?name=show_logging.txt", fixture(t, "show_logging.txt"))
	if code != http.StatusOK {
		t.Fatalf("status %d: %s", code, body)
	}
	var res loadResult
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatal(err)
	}
	if res.Records != 5 || res.Name != "show_logging.txt" {
		t.Errorf("result = %+v", res)
	}
	if len(res.Sources) != 1 || res.Sources[0] != "cube-a" {
		t.Errorf("devices = %v, want [cube-a] from the prompt", res.Sources)
	}
	if n := d.st.Stats().Records; n != 5 {
		t.Errorf("%d record(s) in the ring, want 5", n)
	}
	// The call index was fed in the same order, so the file's calls are there.
	if n := d.ix.Stats().Total; n == 0 {
		t.Error("the call index saw nothing: the records did not go through the same door")
	}
	// And the devices the file brought are in the status the browser reads.
	if got := get(t, srv.URL+"/api/stats"); len(got["sources"].([]any)) != 1 {
		t.Errorf("sources = %v", got["sources"])
	}
}

func TestOpenASessionFileIntoARunningSession(t *testing.T) {
	// Round trip through the browser's two endpoints: save, then open what was
	// saved into a second session.
	first := store.New(100)
	first.Add(rec("a line", "cube-a", "1", 6))
	one := serve(t, &Server{Store: first})
	resp, err := http.Get(one.URL + "/api/session")
	if err != nil {
		t.Fatal(err)
	}
	saved, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	d := &door{st: store.New(100)}
	two := serve(t, &Server{Store: d.st, Add: d.add, Year: 2026})
	code, body := post(t, two.URL+"/api/load?name=saved.cubelog", saved)
	if code != http.StatusOK {
		t.Fatalf("status %d: %s", code, body)
	}
	if !strings.Contains(body, "a saved session") {
		t.Errorf("the file was not recognised as a session: %s", body)
	}
	if n := d.st.Stats().Records; n != 1 {
		t.Errorf("%d record(s) in the second session, want 1", n)
	}
}

func TestOpenRejectsWhatItCannotRead(t *testing.T) {
	d := &door{st: store.New(100)}
	srv := serve(t, &Server{Store: d.st, Add: d.add})
	code, body := post(t, srv.URL+"/api/load?name=notes.txt",
		[]byte("dear diary, the trunk was down again\n"))
	if code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400: %s", code, body)
	}
	if d.st.Stats().Records != 0 {
		t.Error("a file that could not be read still put something in the ring")
	}
}

func TestOpenIsRefusedWhenThereIsNoDoor(t *testing.T) {
	// A server with no Add cannot take a file, and says so rather than
	// dropping the records where the call index will never see them.
	srv := serve(t, &Server{Store: store.New(100)})
	code, _ := post(t, srv.URL+"/api/load?name=x.txt", fixture(t, "show_logging.txt"))
	if code != http.StatusNotImplemented {
		t.Errorf("status %d, want 501", code)
	}
}

func TestAPathInTheUploadedNameIsNotKept(t *testing.T) {
	d := &door{st: store.New(100)}
	srv := serve(t, &Server{Store: d.st, Add: d.add, Year: 2026})
	code, body := post(t, srv.URL+"/api/load?name=%2Fetc%2Fpasswd%2Fcapture.txt",
		fixture(t, "datagrams_pri.txt"))
	if code != http.StatusOK {
		t.Fatalf("status %d: %s", code, body)
	}
	var res loadResult
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatal(err)
	}
	if res.Name != "capture.txt" {
		t.Errorf("name = %q, want just the last element", res.Name)
	}
}
