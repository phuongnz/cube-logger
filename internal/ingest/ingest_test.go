package ingest

import (
	"strings"
	"testing"
	"time"
)

// read feeds whole lines and returns what came back, which is how the loader
// uses it.
func read(t *testing.T, text string) (*Reader, []Line) {
	t.Helper()
	r := New()
	r.Year = 2026
	var out []Line
	for _, l := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		out = append(out, r.Line(l))
	}
	return r, out
}

func TestIOSNeedsNoPeeling(t *testing.T) {
	r, got := read(t, "400020: Sep 24 10:00:01.123: %SIP-5-DIALPEER_STATUS: dial-peer 1 is up\n"+
		"Received:\n")
	if r.Format() != IOS {
		t.Fatalf("format = %q, want %q", r.Format(), IOS)
	}
	for i, l := range got {
		if l.Text == "" {
			t.Fatalf("line %d came back empty", i)
		}
	}
	if got[0].Text != "400020: Sep 24 10:00:01.123: %SIP-5-DIALPEER_STATUS: dial-peer 1 is up" {
		t.Errorf("the IOS line was modified: %q", got[0].Text)
	}
	if got[1].Text != "Received:" {
		t.Errorf("a continuation line was modified: %q", got[1].Text)
	}
}

func TestBSD(t *testing.T) {
	r, got := read(t, "Sep 24 10:00:01 cube-a 400020: Sep 24 10:00:01.123: %SIP-5-X: up\n"+
		"Sep 24 10:00:01 cube-a Received:\n")
	if r.Format() != BSD {
		t.Fatalf("format = %q, want %q", r.Format(), BSD)
	}
	if got[0].Host != "cube-a" {
		t.Errorf("host = %q, want cube-a", got[0].Host)
	}
	if got[0].Text != "400020: Sep 24 10:00:01.123: %SIP-5-X: up" {
		t.Errorf("peeled to %q", got[0].Text)
	}
	if !got[0].HasTime || got[0].Time.Month() != time.September || got[0].Time.Day() != 24 {
		t.Errorf("time = %v", got[0].Time)
	}
	// Once the format is known, a continuation line carrying the same prefix
	// is peeled too, even though nothing about what is left says "IOS".
	if got[1].Text != "Received:" {
		t.Errorf("continuation peeled to %q, want %q", got[1].Text, "Received:")
	}
}

func TestISOAndPriority(t *testing.T) {
	r, got := read(t, "2026-09-24T10:00:01.123456+02:00 cube-b 400020: Sep 24 10:00:01.123: %SIP-5-X: up\n")
	if r.Format() != ISO {
		t.Fatalf("format = %q, want %q", r.Format(), ISO)
	}
	if got[0].Host != "cube-b" {
		t.Errorf("host = %q", got[0].Host)
	}
	if !strings.HasPrefix(got[0].Text, "400020: ") {
		t.Errorf("peeled to %q", got[0].Text)
	}
}

func TestRFC5424(t *testing.T) {
	r, got := read(t,
		"<191>1 2026-09-24T10:00:01.123Z cube-c - - - 400020: Sep 24 10:00:01.123: %SIP-5-X: up\n"+
			"<191>1 2026-09-24T10:00:01.124Z cube-c - - - [origin ip=\"192.0.2.1\"] Received:\n")
	if r.Format() != RFC5424 {
		t.Fatalf("format = %q, want %q", r.Format(), RFC5424)
	}
	if got[0].Host != "cube-c" || got[0].Severity != 7 || got[0].Facility != 23 {
		t.Errorf("host/severity/facility = %q/%d/%d", got[0].Host, got[0].Severity, got[0].Facility)
	}
	if got[1].Text != "Received:" {
		t.Errorf("structured data was not skipped: %q", got[1].Text)
	}
}

func TestPRIDatagramDump(t *testing.T) {
	r, got := read(t, "<191>400020: Sep 24 10:00:01.123: %SIP-5-X: up\n<191>Received:\n")
	if r.Format() != PRI {
		t.Fatalf("format = %q, want %q", r.Format(), PRI)
	}
	if got[0].Severity != 7 || got[0].Facility != 23 {
		t.Errorf("severity/facility = %d/%d", got[0].Severity, got[0].Facility)
	}
	if got[1].Text != "Received:" {
		t.Errorf("a priority on a continuation line was not peeled: %q", got[1].Text)
	}
}

func TestPRIIsPeeledEvenInAnIOSFile(t *testing.T) {
	// A file can be a concatenation: some lines went through a syslog server
	// and some were pasted from a terminal. A "<PRI>" is unambiguous, so it is
	// taken off whatever the rest of the file looked like.
	_, got := read(t, "400020: Sep 24 10:00:01.123: %SIP-5-X: up\n"+
		"<190>400021: Sep 24 10:00:02.123: %SIP-5-X: down\n")
	if got[1].Text != "400021: Sep 24 10:00:02.123: %SIP-5-X: down" {
		t.Errorf("peeled to %q", got[1].Text)
	}
	if got[1].Severity != 6 {
		t.Errorf("severity = %d, want 6", got[1].Severity)
	}
}

func TestTSV(t *testing.T) {
	r, got := read(t, "2026-09-24\t10:00:01\tLocal7.Debug\t198.51.100.9\t400020: Sep 24 10:00:01.123: %SIP-5-X: up\n")
	if r.Format() != TSV {
		t.Fatalf("format = %q, want %q", r.Format(), TSV)
	}
	if got[0].Host != "198.51.100.9" {
		t.Errorf("host = %q", got[0].Host)
	}
	if got[0].Severity != 7 || got[0].Facility != 23 {
		t.Errorf("severity/facility = %d/%d, want 7/23", got[0].Severity, got[0].Facility)
	}
}

func TestShowLoggingPreamble(t *testing.T) {
	r, got := read(t, `cube-a#show logging
Syslog logging: enabled (0 messages dropped, 1 messages rate-limited)
    Console logging: disabled
    Buffer logging:  level debugging, 5 messages logged, xml disabled
    Exception Logging: size (4096 bytes)

Log Buffer (8000000 bytes):

400020: Sep 24 10:00:01.123: %SIP-5-X: up
cube-a#
`)
	if r.Host() != "cube-a" {
		t.Errorf("host = %q, want cube-a (from the prompt)", r.Host())
	}
	if n := len(r.Banner()); n != 9 {
		t.Errorf("%d banner line(s), want 9: %q", n, r.Banner())
	}
	for i, l := range got {
		want := i != 8
		if l.Banner != want {
			t.Errorf("line %d (%q): banner = %v, want %v", i, l.Text, l.Banner, want)
		}
	}
	if got[8].Format != IOS {
		t.Errorf("the record line was read as %q", got[8].Format)
	}
}

func TestABlankLineInsideARecordIsNotBanner(t *testing.T) {
	// The blank line between a SIP message's headers and its body is content,
	// and the preamble rules must not eat it.
	_, got := read(t, "400020: Sep 24 10:00:01.123: //1/AAA/SIP/Msg/x:\n"+
		"Content-Length: 4\n"+
		"\n"+
		"v=0\n")
	if got[2].Banner {
		t.Error("the blank line separating headers from body was called banner")
	}
}

func TestSIPBodyIsNeverMistakenForFraming(t *testing.T) {
	// A file that has shown itself to be a terminal capture is never peeled,
	// however a line inside a SIP message happens to be shaped.
	_, got := read(t, "400020: Sep 24 10:00:01.123: //1/AAA/SIP/Msg/x:\n"+
		"Sep 24 10:00:01 something that looks like a syslog server wrote it\n"+
		"<191>not a priority, part of a body\n")
	if got[1].Text != "Sep 24 10:00:01 something that looks like a syslog server wrote it" {
		t.Errorf("a body line was peeled: %q", got[1].Text)
	}
	if got[2].Text != "<191>not a priority, part of a body" {
		t.Errorf("a body line was peeled: %q", got[2].Text)
	}
}

func TestSynthesizedFrameForADeviceWithoutTimestamps(t *testing.T) {
	// "no service timestamps" leaves a line the parser cannot frame. The
	// receiving server's clock rebuilds one for a line that starts a record,
	// and leaves a continuation line alone.
	r, got := read(t, "Sep 24 10:00:01 cube-a %SIP-5-DIALPEER_STATUS: dial-peer 1 is up\n"+
		"Sep 24 10:00:02 cube-a 400021: //1/AAA/SIP/Msg/x:\n"+
		"Sep 24 10:00:02 cube-a Received:\n")
	if r.Format() != BSD {
		t.Fatalf("format = %q", r.Format())
	}
	if !got[0].Synthesized || got[0].Text != "Sep 24 10:00:01.000: %SIP-5-DIALPEER_STATUS: dial-peer 1 is up" {
		t.Errorf("synthesized = %v, text = %q", got[0].Synthesized, got[0].Text)
	}
	if got[1].Text != "400021: Sep 24 10:00:02.000: //1/AAA/SIP/Msg/x:" {
		t.Errorf("the sequence number was not kept: %q", got[1].Text)
	}
	if got[2].Synthesized {
		t.Errorf("a continuation line was given a frame of its own: %q", got[2].Text)
	}
}

func TestTwoDevicesInOneFile(t *testing.T) {
	_, got := read(t, "Sep 24 10:00:01 cube-a 400020: Sep 24 10:00:01.123: %SIP-5-X: up\n"+
		"Sep 24 10:00:02 cube-b 900001: Sep 24 10:00:02.001: %SIP-5-X: up\n")
	if got[0].Host == got[1].Host {
		t.Fatalf("both lines came from %q", got[0].Host)
	}
	if got[1].Host != "cube-b" {
		t.Errorf("host = %q, want cube-b", got[1].Host)
	}
}

func TestUnknownStaysUnknown(t *testing.T) {
	r, got := read(t, "this is not a log file at all\nnor is this\n")
	if r.Format() != Unknown {
		t.Errorf("format = %q, want unknown", r.Format())
	}
	if got[0].Text != "this is not a log file at all" {
		t.Errorf("text = %q", got[0].Text)
	}
}

func TestSeverityByName(t *testing.T) {
	for in, want := range map[string]int{
		"Debug": 7, "Info": 6, "Notice": 5, "Warning": 4, "warn": 4,
		"Error": 3, "err": 3, "Crit": 2, "Alert": 1, "Emerg": 0, "panic": 0,
		"": -1, "nonsense": -1,
	} {
		if got := severityByName(in); got != want {
			t.Errorf("severityByName(%q) = %d, want %d", in, got, want)
		}
	}
}
