package web

// The page's side of the socket. The tests elsewhere in this package check what
// the server sends; these run ui/app.js itself, in node, on a transcript of it
// (see testdata/uicheck.js). Until they existed nothing ran the script at all,
// and selecting a call showed an empty table and no ladder from the day the
// ladder was written.

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// needNode returns node's path, or skips: node is not part of the toolchain
// this project asks for, and a machine without it is not a failure.
func needNode(t *testing.T) string {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("no node on this machine, so the page's script is not run")
	}
	return node
}

// runPage runs testdata/uicheck.js on a transcript and fails the test with its
// report if any check failed.
func runPage(t *testing.T, node string, transcript any) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "transcript.json")
	if err := os.WriteFile(path, mustJSON(t, transcript), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(node, filepath.Join("testdata", "uicheck.js"),
		filepath.Join("ui", "app.js"), path).CombinedOutput()
	if err != nil {
		t.Fatalf("the page, run on what the server sent:\n%s\n%v", out, err)
	}
	t.Logf("the page, run on what the server sent:\n%s", out)
}

func TestTheBrowserShowsASelectedCall(t *testing.T) {
	node := needNode(t)
	s := withCalls(t, "basic_call.txt")
	// A second call, so that selecting one has something to leave out.
	feed(t, s, "failed_call.txt")
	srv := serve(t, s)

	c := dial(t, srv, "/ws")
	stream, ids := greeting(t, c)
	if len(ids) < 2 {
		t.Fatalf("calls = %d, want both fixtures' calls", len(ids))
	}
	selected := map[string]any{}
	for _, id := range ids {
		c.send(0x1, mustJSON(t, map[string]any{"type": "select", "call": id}))
		selected[id] = c.readType("call")
	}

	runPage(t, node, map[string]any{"stream": stream, "calls": selected})
}

// A server restarted under an open page numbers its records and calls from 1
// again. The page used to reconnect asking for what came after its last ID
// and was sent nothing, and kept showing the old process's records until the
// new one's IDs had caught up. Two servers stand in for one restarted: the
// second holds fewer records than the first, so every one of its IDs is one
// the page has already seen.
func TestTheBrowserStartsOverWhenTheServerRestarts(t *testing.T) {
	node := needNode(t)
	before := withCalls(t, "basic_call.txt")
	feed(t, before, "failed_call.txt")
	stream, ids := greeting(t, dial(t, serve(t, before), "/ws"))
	if len(ids) == 0 {
		t.Fatal("no call to have open when the server goes away")
	}

	after := withCalls(t, "failed_call.txt")
	st := before.Store.Stats()
	if after.Store.Stats().Newest >= st.Newest {
		t.Fatalf("the second server holds IDs up to %d, want below %d so that all are IDs the page has seen",
			after.Store.Stats().Newest, st.Newest)
	}
	path := fmt.Sprintf("/ws?since=%d&epoch=%s", st.Newest, url.QueryEscape(st.Epoch))
	restarted, _ := greeting(t, dial(t, serve(t, after), path))

	runPage(t, node, map[string]any{
		"stream":  stream,
		"restart": map[string]any{"path": path, "open": ids[0], "stream": restarted},
	})
}

// greeting reads what a new socket is sent before anything happens: hello,
// the backfill, and the call list. It returns the messages in order and the
// IDs in the call list.
func greeting(t *testing.T, c *client) ([]map[string]any, []string) {
	t.Helper()
	var stream []map[string]any
	for len(stream) == 0 || stream[len(stream)-1]["type"] != "calls" {
		if len(stream) == 50 {
			t.Fatal("no call list in the first 50 messages")
		}
		stream = append(stream, c.read())
	}
	var list struct {
		Calls []struct{ ID string } `json:"calls"`
	}
	if err := json.Unmarshal(mustJSON(t, stream[len(stream)-1]), &list); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, call := range list.Calls {
		ids = append(ids, call.ID)
	}
	return stream, ids
}
