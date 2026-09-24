package parse

import (
	"strings"
	"testing"
	"time"
)

// TestFrameVariants covers the frame as IOS actually writes it under the
// different "service timestamps" and "service sequence-numbers" settings. The
// regex has to be anchored and complete: a loose one matches SIP body text.
func TestFrameVariants(t *testing.T) {
	tests := []struct {
		name      string
		line      string
		wantSeq   uint64
		wantNoSeq bool
		wantTime  string
		wantZone  string
		trusted   bool
		wantText  string
	}{
		{
			name:     "sequence number, msec, no zone",
			line:     "5967001: Sep 24 10:14:20.640: //1234567/0A8B2C00000B/SIP/Msg/x:",
			wantSeq:  5967001,
			wantTime: "2026-09-24T10:14:20.640Z",
			trusted:  true,
			wantText: "//1234567/0A8B2C00000B/SIP/Msg/x:",
		},
		{
			name:      "no sequence number",
			line:      "Sep 24 10:14:20.640: %SIP-5-DIALPEER_STATUS: up",
			wantNoSeq: true,
			wantTime:  "2026-09-24T10:14:20.640Z",
			trusted:   true,
			wantText:  "%SIP-5-DIALPEER_STATUS: up",
		},
		{
			name:     "unsynchronised clock",
			line:     "5967001: *Sep 24 10:14:20.640: x",
			wantSeq:  5967001,
			wantTime: "2026-09-24T10:14:20.640Z",
			wantText: "x",
		},
		{
			name:     "show-timezone",
			line:     "5967001: Sep 24 10:14:20.640 BST: x",
			wantSeq:  5967001,
			wantTime: "2026-09-24T10:14:20.640Z",
			wantZone: "BST",
			trusted:  true,
			wantText: "x",
		},
		{
			name:     "no milliseconds",
			line:     "5967001: Sep  4 10:14:20: x",
			wantSeq:  5967001,
			wantTime: "2026-09-04T10:14:20.000Z",
			trusted:  true,
			wantText: "x",
		},
		{
			name:     "year",
			line:     "5967001: Sep 24 2021 10:14:20.640: x",
			wantSeq:  5967001,
			wantTime: "2021-09-24T10:14:20.640Z",
			trusted:  true,
			wantText: "x",
		},
		{
			name:     "empty payload",
			line:     "5967001: Sep 24 10:14:20.640:",
			wantSeq:  5967001,
			wantTime: "2026-09-24T10:14:20.640Z",
			trusted:  true,
			wantText: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := NewParser("test", 2026)
			p.Line(tc.line)
			r := p.Flush()
			if r == nil {
				t.Fatal("line was not recognised as a framed record")
			}
			if tc.wantNoSeq {
				if r.HasSeq {
					t.Errorf("HasSeq = true, want false")
				}
			} else if r.Seq != tc.wantSeq {
				t.Errorf("Seq = %d, want %d", r.Seq, tc.wantSeq)
			}
			if got := r.Time.Format(time.RFC3339Nano); !strings.HasPrefix(tc.wantTime, strings.TrimSuffix(got, "Z")) {
				t.Errorf("Time = %s, want %s", got, tc.wantTime)
			}
			if r.Zone != tc.wantZone {
				t.Errorf("Zone = %q, want %q", r.Zone, tc.wantZone)
			}
			if r.TimeTrusted != tc.trusted {
				t.Errorf("TimeTrusted = %v, want %v", r.TimeTrusted, tc.trusted)
			}
			if r.Text != tc.wantText {
				t.Errorf("Text = %q, want %q", r.Text, tc.wantText)
			}
		})
	}
}

// TestNotAFrame checks the lines that must not be mistaken for a frame. Every
// one of these appears inside a SIP message, and a loose regex swallows them.
func TestNotAFrame(t *testing.T) {
	for _, line := range []string{
		"Date: Thu, 24 Sep 2026 10:14:20 GMT",
		"Content-Length: 247",
		"CSeq: 101 INVITE",
		"v=0",
		"a=rtpmap:101 telephone-event/8000",
		"Call-ID: 0a1b2c3d-4e5f6071@10.0.0.1",
		"Timestamp: 1790240802",
		"",
	} {
		if _, _, ok := SplitFrame(line); ok {
			t.Errorf("%q was taken for a framed record", line)
		}
	}
}

// TestYearRollover: IOS logs no year, so a capture that crosses New Year has to
// have one supplied and rolled forward.
func TestYearRollover(t *testing.T) {
	p := NewParser("test", 2026)
	p.Line("1: Dec 31 23:59:59.900: a")
	p.Line("2: Jan  1 00:00:00.100: b")
	first := p.Flush()
	_ = first
	// Feed again to read both records out in order.
	p = NewParser("test", 2026)
	var got []time.Time
	for _, l := range []string{"1: Dec 31 23:59:59.900: a", "2: Jan  1 00:00:00.100: b"} {
		if r := p.Line(l); r != nil {
			got = append(got, r.Time)
		}
	}
	if r := p.Flush(); r != nil {
		got = append(got, r.Time)
	}
	if len(got) != 2 {
		t.Fatalf("got %d records, want 2", len(got))
	}
	if got[0].Year() != 2026 || got[1].Year() != 2027 {
		t.Errorf("years = %d, %d; want 2026, 2027", got[0].Year(), got[1].Year())
	}
	if !got[1].After(got[0]) {
		t.Errorf("time went backwards across the year boundary")
	}
}

// TestDebugHeaderVariableLength: the component path has no fixed field count,
// and the Cover Buffer form has none at all.
func TestDebugHeaderVariableLength(t *testing.T) {
	tests := []struct {
		text      string
		callID    int64
		guid      string
		component []string
	}{
		{"//1234567/0A8B2C00000B/SIP/Msg/ccsipDisplayMsg:", 1234567, "0A8B2C00000B", []string{"SIP", "Msg", "ccsipDisplayMsg"}},
		{"//-1/xxxxxxxxxxxx/SIP/Msg/ccsipDisplayMsg:", NoCallID, "", []string{"SIP", "Msg", "ccsipDisplayMsg"}},
		{"//1234567/0A8B2C00000B/CUBE_VT/SIP/FSM/SPI-State-Change:", 1234567, "0A8B2C00000B", []string{"CUBE_VT", "SIP", "FSM", "SPI-State-Change"}},
		{"//1234567/0A8B2C00000B/", 1234567, "0A8B2C00000B", nil},
	}
	for _, tc := range tests {
		d := parseDebugHeader(tc.text)
		if d == nil {
			t.Errorf("%q did not parse", tc.text)
			continue
		}
		if d.CallID != tc.callID || d.GUID != tc.guid {
			t.Errorf("%q: got %d/%q, want %d/%q", tc.text, d.CallID, d.GUID, tc.callID, tc.guid)
		}
		if strings.Join(d.Component, "/") != strings.Join(tc.component, "/") {
			t.Errorf("%q: component = %v, want %v", tc.text, d.Component, tc.component)
		}
	}
}

// TestDebugGUIDFromCiscoGuid checks the derivation documented in
// docs/log-format.md: the first eight characters are the first word in hex and
// the last four are the top 16 bits of the third word.
func TestDebugGUIDFromCiscoGuid(t *testing.T) {
	m := &SIPMessage{CiscoGuid: "0176892928-0000065536-0000761543-0378877706"}
	if got, want := m.DebugGUID(), "0A8B2C00000B"; got != want {
		t.Errorf("DebugGUID() = %q, want %q", got, want)
	}
	if got := (&SIPMessage{}).DebugGUID(); got != "" {
		t.Errorf("DebugGUID() with no header = %q, want empty", got)
	}
	if got := (&SIPMessage{CiscoGuid: "not-a-guid"}).DebugGUID(); got != "" {
		t.Errorf("DebugGUID() of nonsense = %q, want empty", got)
	}
}

// TestBodySeparatorsAreNotBody: a ccsipDisplayMsg record ends with one, three
// or five blank separator lines, and a blank line is also legal inside a body.
// Content-Length is what tells them apart.
func TestBodySeparatorsAreNotBody(t *testing.T) {
	for _, blanks := range []int{1, 3, 5} {
		cont := append([]string{"Sent:", "SIP/2.0 200 OK", "Content-Length: 5", "", "v=0"},
			make([]string, blanks)...)
		m, warns := parseSIPMessage(cont)
		if m == nil {
			t.Fatal("not parsed as a SIP message")
		}
		if m.Body != "v=0" {
			t.Errorf("%d blank lines: Body = %q, want %q", blanks, m.Body, "v=0")
		}
		if m.BodyBytes != 5 || len(warns) != 0 {
			t.Errorf("%d blank lines: BodyBytes = %d, warnings %v", blanks, m.BodyBytes, warns)
		}
	}
}

// TestShortBodyIsFlagged: a body shorter than Content-Length never happened on
// the terminal path, so it is a real lost-record signal rather than noise.
func TestShortBodyIsFlagged(t *testing.T) {
	m, warns := parseSIPMessage([]string{"Received:", "SIP/2.0 200 OK", "Content-Length: 500", "", "v=0", ""})
	if m == nil {
		t.Fatal("not parsed as a SIP message")
	}
	if !m.Truncated {
		t.Error("Truncated = false, want true")
	}
	if len(warns) == 0 {
		t.Error("no warning for a short body")
	}
}

// TestDirectionDetail: the voice-trace form of the direction line carries the
// transport and both socket addresses after the direction.
func TestDirectionDetail(t *testing.T) {
	m, _ := parseSIPMessage([]string{
		"Sent: SIP TLS message from 10.0.0.1:5061 to 192.0.2.10:38208",
		"SIP/2.0 200 OK", "Content-Length: 0", "",
	})
	if m == nil {
		t.Fatal("not parsed as a SIP message")
	}
	if m.Direction != DirSent {
		t.Errorf("Direction = %q, want %q", m.Direction, DirSent)
	}
	if m.Detail != "SIP TLS message from 10.0.0.1:5061 to 192.0.2.10:38208" {
		t.Errorf("Detail = %q", m.Detail)
	}
}

// TestNotASIPMessage: continuation lines that are not a SIP message are left
// alone rather than forced into one.
func TestNotASIPMessage(t *testing.T) {
	if m, _ := parseSIPMessage([]string{"some free text", "more of it"}); m != nil {
		t.Errorf("free text was parsed as a SIP message: %+v", m)
	}
}
