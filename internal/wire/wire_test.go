package wire

import "testing"

// Every value below is invented. docs/log-format.md § The UDP path describes
// the shapes; nothing from the real capture is quoted here or anywhere else in
// this repository.

func TestDecode(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want Frame
	}{{
		name: "record head",
		in:   "<191>400001: 7200001: Sep 24 12:00:00.123 UTC: //-1/A1B2C3D4E5F6/SIP/Msg/ccsipDisplayMsg:\r",
		want: Frame{Priority: 191, Facility: 23, Severity: SevDebug, Seq: 400001, HasSeq: true,
			Line: "7200001: Sep 24 12:00:00.123 UTC: //-1/A1B2C3D4E5F6/SIP/Msg/ccsipDisplayMsg:"},
	}, {
		name: "continuation line",
		in:   "<191>400002: Received:\r",
		want: Frame{Priority: 191, Facility: 23, Severity: SevDebug, Seq: 400002, HasSeq: true,
			Line: "Received:"},
	}, {
		// The blank line between a SIP message's headers and its body is a real
		// datagram. Discarding empty payloads would destroy every message body.
		name: "empty datagram, no space after the colon",
		in:   "<191>400020:",
		want: Frame{Priority: 191, Facility: 23, Severity: SevDebug, Seq: 400020, HasSeq: true, Line: ""},
	}, {
		name: "empty datagram with a trailing CR",
		in:   "<191>400021:\r",
		want: Frame{Priority: 191, Facility: 23, Severity: SevDebug, Seq: 400021, HasSeq: true, Line: ""},
	}, {
		name: "no trailing CR at all",
		in:   "<190>400003: 7200002: Sep 24 12:00:01.000 UTC: %SYS-6-LOGGINGHOST_STARTSTOP: Logging to host started",
		want: Frame{Priority: 190, Facility: 23, Severity: SevInformational, Seq: 400003, HasSeq: true,
			Line: "7200002: Sep 24 12:00:01.000 UTC: %SYS-6-LOGGINGHOST_STARTSTOP: Logging to host started"},
	}, {
		name: "error severity",
		in:   "<187>400004: 7200003: Sep 24 12:00:02.000 UTC: %VOICE_IEC-3-GW: SIP: Internal Error",
		want: Frame{Priority: 187, Facility: 23, Severity: SevError, Seq: 400004, HasSeq: true,
			Line: "7200003: Sep 24 12:00:02.000 UTC: %VOICE_IEC-3-GW: SIP: Internal Error"},
	}, {
		// Without "service sequence-numbers" there is no counter on either
		// layer. The line still has to reach the user; only loss detection is lost.
		name: "no outer counter",
		in:   "<191>Sep 24 12:00:00.123 UTC: //-1/A1B2C3D4E5F6/SIP/Msg/ccsipDisplayMsg:",
		want: Frame{Priority: 191, Facility: 23, Severity: SevDebug,
			Line: "Sep 24 12:00:00.123 UTC: //-1/A1B2C3D4E5F6/SIP/Msg/ccsipDisplayMsg:"},
	}, {
		name: "no PRI",
		in:   "400005: 7200004: Sep 24 12:00:03.000 UTC: //12/A1B2C3D4E5F6/SIP/Msg/x:",
		want: Frame{Priority: -1, Severity: -1, Seq: 400005, HasSeq: true,
			Line: "7200004: Sep 24 12:00:03.000 UTC: //12/A1B2C3D4E5F6/SIP/Msg/x:"},
	}, {
		// Nothing recognisable is still shown, never dropped: a device
		// configured in some way nobody has captured is a bug report, not a
		// reason to lose the user's output.
		name: "unrecognisable payload survives",
		in:   "this is not syslog at all",
		want: Frame{Priority: -1, Severity: -1, Line: "this is not syslog at all"},
	}, {
		name: "empty datagram with no framing",
		in:   "",
		want: Frame{Priority: -1, Severity: -1, Line: ""},
	}, {
		name: "unterminated PRI is left alone",
		in:   "<191 400006: hello",
		want: Frame{Priority: -1, Severity: -1, Line: "<191 400006: hello"},
	}, {
		name: "non-numeric PRI is left alone",
		in:   "<abc>400007: hello",
		want: Frame{Priority: -1, Severity: -1, Line: "<abc>400007: hello"},
	}, {
		name: "counter zero",
		in:   "<191>0: 7200005: Sep 24 12:00:04.000 UTC: //-1/-/SIP/Msg/x:",
		want: Frame{Priority: 191, Facility: 23, Severity: SevDebug, Seq: 0, HasSeq: true,
			Line: "7200005: Sep 24 12:00:04.000 UTC: //-1/-/SIP/Msg/x:"},
	}, {
		// A SIP header line is "Name: value", and a colon after non-digits must
		// never be mistaken for the counter.
		name: "a SIP header is not a counter",
		in:   "<191>400008: Content-Length: 312",
		want: Frame{Priority: 191, Facility: 23, Severity: SevDebug, Seq: 400008, HasSeq: true,
			Line: "Content-Length: 312"},
	}, {
		// A continuation carrying only spaces is still content: SDP and message
		// bodies are indentation-sensitive to the eye.
		name: "whitespace-only continuation is preserved",
		in:   "<191>400009:  a=sendrecv",
		want: Frame{Priority: 191, Facility: 23, Severity: SevDebug, Seq: 400009, HasSeq: true,
			Line: " a=sendrecv"},
	}}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Decode(c.in)
			if got != c.want {
				t.Errorf("Decode(%q)\n got %+v\nwant %+v", c.in, got, c.want)
			}
		})
	}
}

func TestDecodeStripsOnlyOneLineEnding(t *testing.T) {
	// A body line that genuinely ends in a blank should keep it; only the
	// transport's own CR comes off.
	got := Decode("<191>400010: v=0\r\r")
	if got.Line != "v=0\r" {
		t.Errorf("Line = %q, want %q", got.Line, "v=0\r")
	}
}

func TestHasPRI(t *testing.T) {
	if !Decode("<191>1: x").HasPRI() {
		t.Error("a datagram with a priority should report HasPRI")
	}
	if Decode("1: x").HasPRI() {
		t.Error("a datagram without a priority should not report HasPRI")
	}
}

func TestSeverityName(t *testing.T) {
	if got := SeverityName(SevDebug); got != "debug" {
		t.Errorf("SeverityName(7) = %q, want debug", got)
	}
	if got := SeverityName(-1); got != "" {
		t.Errorf("SeverityName(-1) = %q, want empty", got)
	}
	if got := SeverityName(8); got != "" {
		t.Errorf("SeverityName(8) = %q, want empty", got)
	}
}

func TestSeverityByName(t *testing.T) {
	cases := map[string]int{
		"debug":         SevDebug,
		"DEBUG":         SevDebug,
		"  warning  ":   SevWarning,
		"err":           SevError,
		"emerg":         SevEmergency,
		"informational": SevInformational,
		"info":          SevInformational,
		"7":             SevDebug,
		"0":             SevEmergency,
		"8":             -1,
		"":              -1,
		"e":             -1, // ambiguous: emergency, error
		"nonsense":      -1,
	}
	for in, want := range cases {
		if got := SeverityByName(in); got != want {
			t.Errorf("SeverityByName(%q) = %d, want %d", in, got, want)
		}
	}
}
