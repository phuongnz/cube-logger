package correlate

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/phuongnz/cube-logger/internal/parse"
)

// Ladder is a call drawn the way a voice engineer draws it on a whiteboard:
// one vertical line per party, and one arrow per SIP message between them.
//
// It is derived, not stored. Building it needs the call's records, which the
// correlator deliberately does not keep on the live path, so the caller passes
// a lookup — the store's by-ID fetch, or an index into a parsed file. A lookup
// that returns nil is a record that has aged out of the ring; those are counted
// in Missing rather than left as a silent hole in the diagram.
type Ladder struct {
	Columns []Column `json:"columns"`
	Arrows  []Arrow  `json:"arrows"`
	Notes   []Note   `json:"notes,omitempty"`
	// Missing is how many of the call's records could not be looked up.
	Missing int `json:"missing,omitempty"`
}

// Column kinds. There is exactly one cube column: CUBE is the back-to-back
// user agent in the middle, and every other column is somebody it talked to.
const (
	ColCUBE = "cube"
	ColPeer = "peer"
)

// Column is one vertical line.
type Column struct {
	Label string `json:"label"`
	Kind  string `json:"kind"`
	// Legs are the call legs that terminate on this party. A peer column
	// normally has one; CUBE has all of them.
	Legs []string `json:"legs,omitempty"`
}

// Arrow classes, which are what the diagram colours by.
const (
	ClassRequest     = "request"
	ClassProvisional = "provisional"
	ClassSuccess     = "success"
	ClassFailure     = "failure"
)

// Arrow is one SIP message, pointing from the party that sent it to the party
// that received it.
type Arrow struct {
	// Ref is the record reference, so clicking an arrow can select the record.
	Ref  uint64    `json:"ref"`
	Time time.Time `json:"time"`
	// From and To index Columns.
	From int `json:"from"`
	To   int `json:"to"`

	Label  string `json:"label"`
	Class  string `json:"class"`
	Method string `json:"method,omitempty"`
	Status int    `json:"status,omitempty"`
	CSeq   string `json:"cseq,omitempty"`
	Leg    string `json:"leg,omitempty"`
	// Body marks a message that carried SDP, which is usually the question an
	// engineer is asking when a call has no audio.
	Body bool `json:"body,omitempty"`
	// Incomplete marks a message whose body was shorter than its
	// Content-Length: lines of it never arrived.
	Incomplete bool `json:"incomplete,omitempty"`
}

// Note is something the router said about the call that is not a SIP message:
// a %VOICE_IEC-3-GW failure, a dial-peer message. It belongs beside the ladder
// because it often carries the actual reason the call failed.
type Note struct {
	Ref      uint64    `json:"ref"`
	Time     time.Time `json:"time"`
	Text     string    `json:"text"`
	Leg      string    `json:"leg,omitempty"`
	Severity int       `json:"severity"`
}

// BuildLadder lays a call out as a ladder.
//
// Columns are ordered the way the call flowed: the inbound leg's peer on the
// left, CUBE in the middle, and the legs CUBE originated to the right. That is
// the order the messages are read in, so arrows mostly travel left to right
// down the page and a call that turned round in the middle looks like one.
func BuildLadder(call *Call, lookup func(ref uint64) *parse.Record) *Ladder {
	l := &Ladder{}
	if call == nil {
		return l
	}

	// One pass to learn who each leg was talking to, and what this CUBE calls
	// itself, before any column exists.
	type legInfo struct {
		leg  *Leg
		peer string
		col  int
	}
	infos := make([]*legInfo, 0, len(call.Legs))
	cube := ""
	for _, leg := range call.Legs {
		peer, self := endpoints(leg, lookup)
		if cube == "" {
			cube = self
		}
		infos = append(infos, &legInfo{leg: leg, peer: peer})
	}
	if cube == "" {
		for _, leg := range call.Legs {
			if leg.Source != "" {
				cube = leg.Source
				break
			}
		}
	}
	if cube == "" {
		cube = "CUBE"
	}

	// The inbound leg, if there is one, goes to the left of CUBE.
	left := -1
	for i, in := range infos {
		if in.leg.Direction == DirInbound {
			left = i
			break
		}
	}

	cubeCol := 0
	byPeer := map[string]int{}
	if left >= 0 {
		l.Columns = append(l.Columns, Column{
			Label: peerLabel(infos[left].peer, infos[left].leg),
			Kind:  ColPeer,
			Legs:  []string{infos[left].leg.ID},
		})
		infos[left].col = 0
		byPeer[infos[left].peer] = 0
		cubeCol = 1
	}
	l.Columns = append(l.Columns, Column{Label: cube, Kind: ColCUBE})

	for i, in := range infos {
		if i == left {
			continue
		}
		// Two legs to the same peer share a column: that is the same box, and
		// drawing it twice would suggest a hop that never happened. A leg whose
		// peer is unknown never shares, because "unknown" is not an identity.
		if col, ok := byPeer[in.peer]; ok && in.peer != "" {
			in.col = col
			l.Columns[col].Legs = append(l.Columns[col].Legs, in.leg.ID)
			continue
		}
		l.Columns = append(l.Columns, Column{
			Label: peerLabel(in.peer, in.leg),
			Kind:  ColPeer,
			Legs:  []string{in.leg.ID},
		})
		in.col = len(l.Columns) - 1
		if in.peer != "" {
			byPeer[in.peer] = in.col
		}
	}
	l.Columns[cubeCol].Legs = legIDs(call)

	for _, in := range infos {
		for _, ref := range in.leg.Records {
			r := lookup(ref)
			if r == nil {
				l.Missing++
				continue
			}
			switch {
			case r.SIP != nil:
				l.Arrows = append(l.Arrows, arrow(ref, r, in.leg, in.col, cubeCol))
			case r.Log != nil:
				l.Notes = append(l.Notes, Note{
					Ref: ref, Time: r.Time, Leg: in.leg.ID, Severity: r.Log.Severity,
					Text: "%" + r.Log.Facility + "-" + strconv.Itoa(r.Log.Severity) +
						"-" + r.Log.Mnemonic + ": " + r.Log.Text,
				})
			}
		}
	}
	// Legs are interleaved in time, so the arrows have to be put back in the
	// order the router printed them. Ties break on the reference, which is the
	// order records were stored in and therefore the order they arrived.
	sort.SliceStable(l.Arrows, func(i, j int) bool {
		if !l.Arrows[i].Time.Equal(l.Arrows[j].Time) {
			return l.Arrows[i].Time.Before(l.Arrows[j].Time)
		}
		return l.Arrows[i].Ref < l.Arrows[j].Ref
	})
	sort.SliceStable(l.Notes, func(i, j int) bool { return l.Notes[i].Ref < l.Notes[j].Ref })
	return l
}

func legIDs(call *Call) []string {
	ids := make([]string, 0, len(call.Legs))
	for _, l := range call.Legs {
		ids = append(ids, l.ID)
	}
	return ids
}

func arrow(ref uint64, r *parse.Record, leg *Leg, peerCol, cubeCol int) Arrow {
	m := r.SIP
	a := Arrow{
		Ref: ref, Time: r.Time, Leg: leg.ID,
		Label:      m.Summary(),
		Method:     m.Method,
		Status:     m.Status,
		Body:       m.BodyBytes > 0,
		Incomplete: m.Truncated,
	}
	if m.CSeqNum > 0 {
		a.CSeq = strconv.Itoa(m.CSeqNum) + " " + m.CSeqMethod
	}
	if m.Direction == parse.DirReceived {
		a.From, a.To = peerCol, cubeCol
	} else {
		a.From, a.To = cubeCol, peerCol
	}
	switch {
	case m.IsRequest():
		a.Class = ClassRequest
	case m.Status < 200:
		a.Class = ClassProvisional
	case m.Status < 300:
		a.Class = ClassSuccess
	default:
		a.Class = ClassFailure
	}
	return a
}

// peerLabel is what a peer column is called when nothing named it. A leg
// always has a direction or an ID, so a column is never blank.
func peerLabel(peer string, leg *Leg) string {
	if peer != "" {
		return peer
	}
	if leg.Direction != "" {
		return leg.Direction + " peer"
	}
	return "peer (" + leg.ID + ")"
}

// endpoints works out who a leg was talking to, and what address this CUBE
// used, from the leg's own messages.
//
// Three sources, most reliable first:
//
//  1. The voice-trace direction line, "Sent: SIP TLS message from A to B",
//     which states both addresses outright. Only about one message in 400
//     carries it, so it cannot be the only path.
//  2. A request CUBE sent: the Request-URI names the peer and the topmost Via
//     names CUBE.
//  3. A request CUBE received: the topmost Via names the peer and the
//     Request-URI names CUBE.
//
// Responses are not used. A response's Request-URI is absent and its Via is a
// copy of the request's, so it says nothing the request did not say better.
func endpoints(leg *Leg, lookup func(ref uint64) *parse.Record) (peer, self string) {
	for _, ref := range leg.Records {
		r := lookup(ref)
		if r == nil || r.SIP == nil {
			continue
		}
		m := r.SIP
		if from, to, ok := detailAddrs(m.Detail); ok {
			if m.Direction == parse.DirReceived {
				return from, to
			}
			return to, from
		}
		if !m.IsRequest() {
			continue
		}
		uri := hostOf(m.RequestURI)
		via := hostOf(viaSentBy(m.Header("Via")))
		if uri == "" && via == "" {
			continue
		}
		if m.Direction == parse.DirReceived {
			return via, uri
		}
		return uri, via
	}
	return "", ""
}

// detailAddrs reads the two addresses out of a voice-trace direction line,
// "SIP TLS message from 10.0.0.1:5061 to 192.0.2.10:38208".
func detailAddrs(detail string) (from, to string, ok bool) {
	i := strings.Index(detail, " from ")
	if i < 0 {
		return "", "", false
	}
	rest := detail[i+len(" from "):]
	j := strings.Index(rest, " to ")
	if j < 0 {
		return "", "", false
	}
	from = hostOf(strings.TrimSpace(rest[:j]))
	to = hostOf(strings.TrimSpace(rest[j+len(" to "):]))
	if from == "" || to == "" {
		return "", "", false
	}
	return from, to, true
}

// viaSentBy returns the address out of a Via header value:
// "SIP/2.0/UDP 10.0.0.5:5060;branch=z9hG4bK..." -> "10.0.0.5:5060".
func viaSentBy(via string) string {
	if via == "" {
		return ""
	}
	// Only the topmost Via matters, and a comma separates stacked ones.
	if i := strings.IndexByte(via, ','); i >= 0 {
		via = via[:i]
	}
	f := strings.Fields(via)
	if len(f) < 2 {
		return ""
	}
	return f[1]
}

// hostOf reduces a SIP URI, a Via sent-by or a bare address to the host part,
// without the scheme, the user, the port or any parameter. An IPv6 literal
// keeps its brackets off but stays whole.
func hostOf(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if i := strings.IndexAny(s, "<"); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.IndexAny(s, ">"); i >= 0 {
		s = s[:i]
	}
	for _, scheme := range [...]string{"sips:", "sip:", "tel:"} {
		if len(s) >= len(scheme) && strings.EqualFold(s[:len(scheme)], scheme) {
			s = s[len(scheme):]
			break
		}
	}
	if i := strings.LastIndexByte(s, '@'); i >= 0 {
		s = s[i+1:]
	}
	// Parameters and headers hang off the host: ;transport=tls, ?x=y.
	if i := strings.IndexAny(s, ";?"); i >= 0 {
		s = s[:i]
	}
	if strings.HasPrefix(s, "[") {
		if i := strings.IndexByte(s, ']'); i > 0 {
			return s[1:i]
		}
		return strings.TrimPrefix(s, "[")
	}
	// A bare IPv6 address has several colons; a host:port has one.
	if strings.Count(s, ":") == 1 {
		s = s[:strings.IndexByte(s, ':')]
	}
	return strings.TrimSpace(s)
}
