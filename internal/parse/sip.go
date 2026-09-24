package parse

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Directions a ccsipDisplayMsg record can carry. CUBE always states the
// direction explicitly, so the parser never has to infer it.
const (
	DirSent     = "sent"
	DirReceived = "received"
)

// SIPMessage is one SIP message as "debug ccsip messages" printed it.
type SIPMessage struct {
	Direction string `json:"direction"`
	// Detail is the rest of the direction line in the CUBE voice-trace form,
	// "SIP TLS message from <addr:port> to <addr:port>". Empty in the plain form.
	Detail string `json:"detail,omitempty"`

	StartLine  string `json:"startLine"`
	Method     string `json:"method,omitempty"`
	RequestURI string `json:"requestUri,omitempty"`
	Status     int    `json:"status,omitempty"`
	Reason     string `json:"reason,omitempty"`

	// Headers are unfolded, in order, duplicates kept.
	Headers []string `json:"headers,omitempty"`

	CallID     string `json:"callId,omitempty"`
	CSeqNum    int    `json:"cseqNum,omitempty"`
	CSeqMethod string `json:"cseqMethod,omitempty"`
	From       *Party `json:"from,omitempty"`
	To         *Party `json:"to,omitempty"`
	// CiscoGuid is the Cisco-Guid header verbatim: four zero-padded decimal
	// words. Only CUBE-originated messages carry it.
	CiscoGuid string `json:"ciscoGuid,omitempty"`

	ContentLength    int    `json:"contentLength"`
	HasContentLength bool   `json:"hasContentLength,omitempty"`
	BodyBytes        int    `json:"bodyBytes"`
	Body             string `json:"body,omitempty"`
	// Truncated is set when the body is shorter than Content-Length. On the
	// terminal path that never happened once in 41,007 messages, so it is a real
	// lost-record signal and not something to tolerate silently.
	Truncated bool `json:"truncated,omitempty"`
}

// Party is a From or To header: display name, URI and tag.
type Party struct {
	Display string `json:"display,omitempty"`
	URI     string `json:"uri,omitempty"`
	User    string `json:"user,omitempty"`
	Host    string `json:"host,omitempty"`
	Tag     string `json:"tag,omitempty"`
}

// IsRequest reports whether the message is a request rather than a response.
func (m *SIPMessage) IsRequest() bool { return m.Method != "" }

// Summary is the short label a call list or a ladder diagram shows: the method
// for a request, the status line for a response.
func (m *SIPMessage) Summary() string {
	if m.IsRequest() {
		return m.Method
	}
	if m.Reason != "" {
		return strconv.Itoa(m.Status) + " " + m.Reason
	}
	return strconv.Itoa(m.Status)
}

// Header returns the first header with the given name, case-insensitively.
func (m *SIPMessage) Header(name string) string {
	for _, h := range m.Headers {
		n, v, ok := strings.Cut(h, ":")
		if ok && strings.EqualFold(strings.TrimSpace(n), name) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

var ciscoGuidRe = regexp.MustCompile(`^(\d+)-(\d+)-(\d+)-(\d+)$`)

// DebugGUID derives the 12-character debug GUID from the Cisco-Guid header:
// the first eight characters are the first word in hex and the last four are
// the top 16 bits of the third word. It is a cross-check on the correlator, not
// a path it can rely on — 90% of messages carry no Cisco-Guid, and a non-Cisco
// peer never sends one. It returns "" when the header is absent or malformed.
func (m *SIPMessage) DebugGUID() string {
	g := ciscoGuidRe.FindStringSubmatch(m.CiscoGuid)
	if g == nil {
		return ""
	}
	w1, err1 := strconv.ParseUint(g[1], 10, 32)
	w3, err3 := strconv.ParseUint(g[3], 10, 32)
	if err1 != nil || err3 != nil {
		return ""
	}
	return fmt.Sprintf("%08X%04X", w1, w3>>16)
}

var (
	statusLineRe  = regexp.MustCompile(`^SIP/2\.0 (\d{3})(?: +(.*))?$`)
	requestLineRe = regexp.MustCompile(`^([A-Za-z]+) +(\S+) +SIP/2\.0$`)
	cseqRe        = regexp.MustCompile(`^(\d+) +([A-Za-z]+)`)
)

// parseSIPMessage reads the continuation lines of a ccsipDisplayMsg record:
// a direction line, then the SIP message verbatim. It returns nil when the
// lines are not a SIP message, so the caller can leave them as plain text.
func parseSIPMessage(cont []string) (*SIPMessage, []string) {
	if len(cont) == 0 {
		return nil, nil
	}
	dir, detail, ok := strings.Cut(cont[0], ":")
	switch {
	case !ok:
		return nil, nil
	case strings.EqualFold(dir, "sent"):
		dir = DirSent
	case strings.EqualFold(dir, "received"):
		dir = DirReceived
	default:
		return nil, nil
	}

	m := &SIPMessage{Direction: dir, Detail: strings.TrimSpace(detail)}
	var warns []string

	i := 1
	for i < len(cont) && strings.TrimSpace(cont[i]) == "" {
		i++
	}
	if i == len(cont) {
		return m, []string{"SIP message has no start line"}
	}
	m.StartLine = cont[i]
	i++
	switch {
	case statusLineRe.MatchString(m.StartLine):
		g := statusLineRe.FindStringSubmatch(m.StartLine)
		m.Status, _ = strconv.Atoi(g[1])
		m.Reason = g[2]
	case requestLineRe.MatchString(m.StartLine):
		g := requestLineRe.FindStringSubmatch(m.StartLine)
		m.Method, m.RequestURI = strings.ToUpper(g[1]), g[2]
	default:
		warns = append(warns, "unrecognised SIP start line")
	}

	i = m.readHeaders(cont, i)
	warns = append(warns, m.readBody(cont, i)...)
	return m, warns
}

// readHeaders consumes header lines, unfolding continuations, and returns the
// index of the first body line.
func (m *SIPMessage) readHeaders(cont []string, i int) int {
	for ; i < len(cont); i++ {
		line := cont[i]
		if line == "" {
			i++
			break
		}
		// A line starting with whitespace folds onto the header before it. A
		// value's own leading spaces ("Min-SE:  1800") are not folding: those
		// come after the colon.
		if (line[0] == ' ' || line[0] == '\t') && len(m.Headers) > 0 {
			m.Headers[len(m.Headers)-1] += " " + strings.TrimSpace(line)
			continue
		}
		m.Headers = append(m.Headers, line)
	}
	m.derive()
	return i
}

// derive pulls the fields the correlator needs out of the headers.
func (m *SIPMessage) derive() {
	m.CallID = m.Header("Call-ID")
	if m.CallID == "" {
		m.CallID = m.Header("i")
	}
	if c := cseqRe.FindStringSubmatch(m.Header("CSeq")); c != nil {
		m.CSeqNum, _ = strconv.Atoi(c[1])
		m.CSeqMethod = strings.ToUpper(c[2])
	}
	if v := m.Header("From"); v != "" {
		m.From = parseParty(v)
	}
	if v := m.Header("To"); v != "" {
		m.To = parseParty(v)
	}
	m.CiscoGuid = m.Header("Cisco-Guid")
	if v := m.Header("Content-Length"); v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			m.ContentLength, m.HasContentLength = n, true
		}
	}
}

// readBody takes the body, using Content-Length to decide where it ends.
//
// A ccsipDisplayMsg record is followed by one or more blank separator lines —
// one usually, three or five sometimes — and a blank line is also a legal part
// of a body, so trailing blanks cannot simply be stripped. Content-Length says
// which of them belong.
func (m *SIPMessage) readBody(cont []string, i int) []string {
	body := cont[i:]
	trimmed := len(body)
	for trimmed > 0 && body[trimmed-1] == "" {
		trimmed--
	}

	end := trimmed
	if m.HasContentLength {
		for n := trimmed; n <= len(body); n++ {
			if crlfBytes(body[:n]) == m.ContentLength {
				end = n
				break
			}
		}
	}
	m.BodyBytes = crlfBytes(body[:end])
	m.Body = strings.Join(body[:end], "\n")

	var warns []string
	if m.HasContentLength && m.BodyBytes != m.ContentLength {
		m.Truncated = m.BodyBytes < m.ContentLength
		warns = append(warns, fmt.Sprintf(
			"body is %d bytes but Content-Length is %d", m.BodyBytes, m.ContentLength))
	}
	// Messages never interleaved on the terminal path, but a UDP path may not
	// preserve that, and it is cheap to notice a start line where a body should be.
	for _, line := range body[end:] {
		if statusLineRe.MatchString(line) || requestLineRe.MatchString(line) {
			warns = append(warns, "a SIP start line follows the body: records may be interleaved")
			break
		}
	}
	return warns
}

// crlfBytes is the wire length of these lines: IOS counts a body in
// CRLF-terminated bytes, whatever line endings the transport used.
func crlfBytes(lines []string) int {
	n := 0
	for _, l := range lines {
		n += len(l) + 2
	}
	return n
}

// parseParty reads a From or To header value: an optional display name, a URI
// in angle brackets or bare, and parameters including the dialog tag.
func parseParty(v string) *Party {
	p := &Party{}
	v = strings.TrimSpace(v)

	if strings.HasPrefix(v, `"`) {
		if end := strings.Index(v[1:], `"`); end >= 0 {
			p.Display = v[1 : end+1]
			v = strings.TrimSpace(v[end+2:])
		}
	}
	var params string
	if open := strings.Index(v, "<"); open >= 0 {
		if p.Display == "" {
			p.Display = strings.TrimSpace(v[:open])
		}
		if close := strings.Index(v[open:], ">"); close >= 0 {
			p.URI = v[open+1 : open+close]
			params = v[open+close+1:]
		} else {
			p.URI = v[open+1:]
		}
	} else {
		// Without angle brackets the first ";" starts the header parameters.
		p.URI, params, _ = strings.Cut(v, ";")
		p.URI = strings.TrimSpace(p.URI)
	}
	p.User, p.Host = splitURI(p.URI)
	p.Tag = param(params, "tag")
	return p
}

// splitURI returns the user and host parts of a sip:, sips: or tel: URI.
func splitURI(uri string) (user, host string) {
	rest := uri
	for _, scheme := range []string{"sips:", "sip:", "tel:"} {
		if strings.HasPrefix(strings.ToLower(rest), scheme) {
			rest = rest[len(scheme):]
			break
		}
	}
	rest, _, _ = strings.Cut(rest, ";")
	rest, _, _ = strings.Cut(rest, "?")
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		user, host = rest[:at], rest[at+1:]
	} else {
		// A tel: URI, or a URI that names a host only.
		user = rest
	}
	// Drop a port, but leave a bracketed IPv6 literal alone.
	if !strings.HasPrefix(host, "[") {
		if colon := strings.LastIndex(host, ":"); colon >= 0 {
			if _, err := strconv.Atoi(host[colon+1:]); err == nil {
				host = host[:colon]
			}
		}
	}
	return user, host
}

// param returns the value of one ";name=value" parameter.
func param(params, name string) string {
	for _, p := range strings.Split(params, ";") {
		n, v, ok := strings.Cut(p, "=")
		if ok && strings.EqualFold(strings.TrimSpace(n), name) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
