// Package wire decodes the syslog framing that wraps a CUBE log line on the
// UDP path. Text in, a frame out: it does no I/O, so the listener and the
// replay tool share it and a test can drive it from a plain string.
//
// The shape is the one measured in docs/log-format.md § The UDP path, and it
// is not RFC 3164:
//
//	<191>400001: 7200001: Sep 24 12:00:00.123 UTC: //-1/A1B2C3D4E5F6/SIP/Msg/...
//	<191>400002: Received:
//	<191>400020:
//
// Three facts drive everything here.
//
//   - One datagram is one *line*, never a message. A SIP message arrives as
//     about nineteen of them, so what Decode returns is a fragment and the
//     reassembler in internal/live is not optional.
//   - There is no hostname and no syslog timestamp. The only device identity
//     is the datagram's source address, which is why it is not in this struct:
//     the caller gets it from the socket.
//   - The counter after <PRI> advances once per line. It is a different
//     counter from the one inside the IOS frame, which advances once per
//     record, and confusing the two is the whole reason this package exists.
package wire

import (
	"strconv"
	"strings"
)

// Severities, as syslog numbers them. IOS debug output is Debug (7), which is
// why "logging trap informational" silently costs a user every SIP message.
const (
	SevEmergency = iota
	SevAlert
	SevCritical
	SevError
	SevWarning
	SevNotice
	SevInformational
	SevDebug
)

var severityNames = [...]string{
	"emergency", "alert", "critical", "error",
	"warning", "notice", "informational", "debug",
}

// SeverityName names a syslog severity, for the UI's severity column and
// filter. It returns "" for a number outside 0-7.
func SeverityName(sev int) string {
	if sev < 0 || sev >= len(severityNames) {
		return ""
	}
	return severityNames[sev]
}

// SeverityByName is the reverse of SeverityName, for parsing a filter. It
// accepts the full name and any unambiguous prefix of three characters or
// more, and returns -1 for anything else.
func SeverityByName(name string) int {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return -1
	}
	if n, err := strconv.Atoi(name); err == nil && n >= 0 && n <= 7 {
		return n
	}
	// "err" and "emerg" are what people type; both are prefixes of exactly one
	// name, so a prefix match covers them without a synonym table.
	if len(name) < 3 {
		return -1
	}
	found := -1
	for i, s := range severityNames {
		if strings.HasPrefix(s, name) {
			if found >= 0 {
				return -1 // ambiguous
			}
			found = i
		}
	}
	return found
}

// Frame is one datagram's syslog framing with the IOS line left intact.
//
// Line is deliberately *not* parsed here: it is exactly what the same content
// looks like in a saved file, so internal/parse consumes it unchanged and the
// live path and the file path stay one code path.
type Frame struct {
	// Priority is the <PRI> value, or -1 when the datagram carried none.
	Priority int `json:"priority,omitempty"`
	Facility int `json:"facility,omitempty"`
	// Severity is 0-7, or -1 when there was no <PRI>. A continuation line
	// carries its own severity and it matches the record it belongs to.
	Severity int `json:"severity"`

	// Seq is the outer, per-line counter that follows <PRI>. HasSeq is false
	// when the device has no "service sequence-numbers", which costs the
	// receiver its only way to count lost lines.
	Seq    uint64 `json:"seq,omitempty"`
	HasSeq bool   `json:"hasSeq,omitempty"`

	// Line is the payload with the <PRI> and the outer counter removed: an IOS
	// framed line, or a bare continuation line, or "" for one of the empty
	// datagrams that separate a SIP message's headers from its body.
	Line string `json:"line"`
}

// HasPRI reports whether the datagram carried a <PRI>.
func (f Frame) HasPRI() bool { return f.Priority >= 0 }

// Decode splits one datagram payload into its frame and its IOS line.
//
// It never fails. A datagram that matches nothing recognisable comes back as a
// Line with no priority and no sequence number, because dropping it would hide
// output from a device configured in some way nobody has captured yet — and an
// unexplained line on screen is a better bug report than a missing one.
func Decode(payload string) Frame {
	f := Frame{Priority: -1, Severity: -1}

	// Line endings: 1,162 of 1,288 payloads in the capture ended with a bare
	// CR and 126 with nothing. Strip one if it is there; never require it.
	s := strings.TrimSuffix(payload, "\n")
	s = strings.TrimSuffix(s, "\r")

	if rest, pri, ok := cutPRI(s); ok {
		f.Priority, f.Facility, f.Severity = pri, pri/8, pri%8
		s = rest
	}
	if rest, seq, ok := cutCounter(s); ok {
		f.Seq, f.HasSeq = seq, true
		s = rest
	}
	f.Line = s
	return f
}

// cutPRI takes a leading "<n>" priority, if there is one.
func cutPRI(s string) (rest string, pri int, ok bool) {
	if len(s) < 3 || s[0] != '<' {
		return s, 0, false
	}
	end := strings.IndexByte(s, '>')
	// A priority is at most three digits (0-191 in practice, 0-1023 by the RFC).
	if end < 2 || end > 4 {
		return s, 0, false
	}
	n, err := strconv.Atoi(s[1:end])
	if err != nil || n < 0 || n > 1023 {
		return s, 0, false
	}
	return s[end+1:], n, true
}

// cutCounter takes the leading "<digits>: " outer counter, if there is one.
//
// The trailing space is optional because an empty datagram is written
// "<191>400020:" with nothing after the colon, and those datagrams matter:
// they are the blank line between a SIP message's headers and its body.
//
// This is the one genuinely ambiguous decision on the wire. Without "service
// sequence-numbers" there is no outer counter, and a continuation line that
// happened to begin "123: " would be misread as one. No SIP header or IOS
// debug line observed so far starts that way, and the alternative — losing
// loss detection entirely — is worse.
func cutCounter(s string) (rest string, seq uint64, ok bool) {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 || i > 20 || i >= len(s) || s[i] != ':' {
		return s, 0, false
	}
	n, err := strconv.ParseUint(s[:i], 10, 64)
	if err != nil {
		return s, 0, false
	}
	rest = s[i+1:]
	rest = strings.TrimPrefix(rest, " ")
	return rest, n, true
}
