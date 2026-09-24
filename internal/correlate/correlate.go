// Package correlate groups parsed records into call legs and calls.
//
// Like the parser it does no I/O: records in, calls out, so live syslog and a
// saved file produce the same result.
//
// The rules it implements come from docs/log-format.md, and the two that shape
// the whole design are worth repeating:
//
//   - A call entry ID identifies one call *leg*, not a call. CUBE is a
//     back-to-back user agent, so a call is normally two legs.
//   - The debug GUID groups the legs of one call, but it is only 12 hex
//     characters and it is reused over time. It is a grouping key scoped by
//     time, never a primary key.
//
// And the awkward case that is not an edge case: an inbound call's first INVITE
// arrives with call entry ID -1, before a leg exists. A leg therefore has to be
// creatable from a SIP Call-ID alone and adopt its call entry ID afterwards.
package correlate

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/phuongnz/cube-logger/internal/parse"
)

// States a leg or a call passes through.
const (
	StateSetup     = "setup"
	StateRinging   = "ringing"
	StateConnected = "connected"
	StateEnded     = "ended"
)

// Directions, as seen from the CUBE: a leg is inbound when CUBE received its
// INVITE and outbound when CUBE sent it.
const (
	DirInbound  = "inbound"
	DirOutbound = "outbound"
)

// Leg is one call leg: everything sharing a call entry ID, plus the records
// that arrived under its SIP Call-ID before that ID existed.
type Leg struct {
	ID          string `json:"id"`
	Source      string `json:"source,omitempty"`
	CallEntryID int64  `json:"callEntryId"`
	GUID        string `json:"guid,omitempty"`
	// SIPCallIDs is normally one Call-ID. More than one means a peer reflected
	// or replaced it, which is worth showing rather than hiding.
	SIPCallIDs []string `json:"sipCallIds,omitempty"`

	Direction string `json:"direction,omitempty"`
	Calling   string `json:"calling,omitempty"`
	Called    string `json:"called,omitempty"`

	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
	State string    `json:"state"`

	// FinalStatus is the final response to the INVITE, when one arrived.
	FinalStatus int    `json:"finalStatus,omitempty"`
	FinalReason string `json:"finalReason,omitempty"`
	// Disconnect is the method that tore the leg down: BYE or CANCEL.
	Disconnect string `json:"disconnect,omitempty"`
	// Cause is the Q.850 cause from a Reason header, IEC the Cisco Internal
	// Error Code from %VOICE_IEC-3-GW.
	Cause string `json:"cause,omitempty"`
	IEC   string `json:"iec,omitempty"`

	// Keepalive marks a leg that only ever carried OPTIONS: a dial-peer probe,
	// not a call. The UI should be able to hide these.
	Keepalive bool `json:"keepalive,omitempty"`

	Records  []int    `json:"records"`
	Warnings []string `json:"warnings,omitempty"`

	call *Call
}

// Call is one call: the legs that share a GUID within a time window, or a
// single leg when no GUID was ever seen.
type Call struct {
	ID      string `json:"id"`
	GUID    string `json:"guid,omitempty"`
	Calling string `json:"calling,omitempty"`
	Called  string `json:"called,omitempty"`

	Start time.Time     `json:"start"`
	End   time.Time     `json:"end"`
	Dur   time.Duration `json:"-"`
	State string        `json:"state"`

	// Result is what happened: the final SIP response when the call failed or
	// was answered, or the method that tore it down.
	Result string `json:"result,omitempty"`
	Cause  string `json:"cause,omitempty"`
	IEC    string `json:"iec,omitempty"`

	Keepalive bool     `json:"keepalive,omitempty"`
	Legs      []*Leg   `json:"legs"`
	Warnings  []string `json:"warnings,omitempty"`

	merged bool
}

// Duration is how long the call lasted, from its first record to its last.
func (c *Call) Duration() time.Duration { return c.End.Sub(c.Start) }

// DefaultGUIDWindow is how long after a call's last record its GUID still
// belongs to it. CUBE forms the second leg of a call within milliseconds, so a
// few seconds is generous; beyond it, a reappearing GUID is a different call.
const DefaultGUIDWindow = 5 * time.Second

// Correlator turns a record stream into calls. Feed records in order with Add
// and read the answer with Result.
type Correlator struct {
	// GUIDWindow scopes GUID grouping in time. Zero means DefaultGUIDWindow.
	GUIDWindow time.Duration

	records []*parse.Record
	legs    []*Leg
	calls   []*Call

	byEntry  map[string]*Leg
	byCallID map[string]*Leg
	openGUID map[string]*Call

	// unattached are records that belong to no call: dial-peer and TLS state,
	// logins, and anything else the box says about itself.
	unattached []int
}

// New returns an empty Correlator.
func New() *Correlator {
	return &Correlator{
		byEntry:  map[string]*Leg{},
		byCallID: map[string]*Leg{},
		openGUID: map[string]*Call{},
	}
}

// Result is the finished grouping.
type Result struct {
	Calls      []*Call  `json:"calls"`
	Unattached []int    `json:"unattached,omitempty"`
	Warnings   []string `json:"warnings,omitempty"`
}

// ids pulls the identifiers out of a record, whichever kind it is.
func ids(r *parse.Record) (entry int64, guid, sipCallID string) {
	entry = parse.NoCallID
	switch {
	case r.Debug != nil:
		entry, guid = r.Debug.CallID, r.Debug.GUID
	case r.Log != nil:
		entry = r.Log.CallID
	}
	if r.SIP != nil {
		sipCallID = r.SIP.CallID
	}
	if r.Cover != nil {
		if entry == parse.NoCallID {
			entry = r.Cover.CallID
		}
		if guid == "" {
			guid = r.Cover.GUID
		}
		if sipCallID == "" {
			sipCallID = r.Cover.SIPCallID
		}
	}
	return entry, guid, sipCallID
}

func entryKey(source string, id int64) string {
	return source + "\x00" + strconv.FormatInt(id, 10)
}

func callIDKey(source, sipCallID string) string {
	return source + "\x00" + sipCallID
}

// Add takes the next record. Records must arrive in the order they were logged.
func (c *Correlator) Add(r *parse.Record) {
	idx := len(c.records)
	c.records = append(c.records, r)

	entry, guid, sipCallID := ids(r)
	leg := c.leg(r, entry, sipCallID)
	if leg == nil {
		c.unattached = append(c.unattached, idx)
		return
	}
	leg.Records = append(leg.Records, idx)
	c.observe(leg, r, guid, sipCallID)
	c.place(leg, guid, r.Time)
}

// leg finds or creates the leg a record belongs to.
func (c *Correlator) leg(r *parse.Record, entry int64, sipCallID string) *Leg {
	if entry != parse.NoCallID {
		if l, ok := c.byEntry[entryKey(r.Source, entry)]; ok {
			return l
		}
	}
	if sipCallID != "" {
		if l, ok := c.byCallID[callIDKey(r.Source, sipCallID)]; ok {
			switch {
			case l.CallEntryID == entry || entry == parse.NoCallID:
				return l
			case l.CallEntryID == parse.NoCallID:
				// The leg was created from the Call-ID of an INVITE that arrived
				// before CUBE had allocated a call entry ID. Adopt it now.
				l.CallEntryID = entry
				c.byEntry[entryKey(r.Source, entry)] = l
				return l
			default:
				// The same Call-ID on two call entry IDs: a peer reflected it.
				// Keep them apart and say so.
				l.Warnings = appendOnce(l.Warnings,
					"SIP Call-ID "+sipCallID+" also appears on another leg")
			}
		}
	}
	if entry == parse.NoCallID && sipCallID == "" {
		return nil // nothing to hang it on: box-level, not call-level
	}

	l := &Leg{
		ID:          "leg-" + strconv.Itoa(len(c.legs)+1),
		Source:      r.Source,
		CallEntryID: entry,
		Start:       r.Time,
		End:         r.Time,
		State:       StateSetup,
	}
	c.legs = append(c.legs, l)
	if entry != parse.NoCallID {
		c.byEntry[entryKey(r.Source, entry)] = l
	}
	if sipCallID != "" {
		c.byCallID[callIDKey(r.Source, sipCallID)] = l
	}
	return l
}

// observe folds one record into the leg it belongs to.
func (c *Correlator) observe(leg *Leg, r *parse.Record, guid, sipCallID string) {
	if r.Time.Before(leg.Start) {
		leg.Start = r.Time
	}
	if r.Time.After(leg.End) {
		leg.End = r.Time
	}
	switch {
	case guid == "":
	case leg.GUID == "":
		leg.GUID = guid
	case leg.GUID != guid:
		leg.Warnings = appendOnce(leg.Warnings, "leg carries two GUIDs: "+leg.GUID+" and "+guid)
	}
	if sipCallID != "" && !contains(leg.SIPCallIDs, sipCallID) {
		leg.SIPCallIDs = append(leg.SIPCallIDs, sipCallID)
		k := callIDKey(r.Source, sipCallID)
		if _, taken := c.byCallID[k]; !taken {
			c.byCallID[k] = leg
		}
	}
	if r.Cover != nil {
		if leg.Calling == "" {
			leg.Calling = r.Cover.Calling
		}
		if leg.Called == "" {
			leg.Called = r.Cover.Called
		}
		if leg.Cause == "" {
			leg.Cause = r.Cover.CauseCode
		}
	}
	if r.Log != nil && r.Log.IEC != "" {
		leg.IEC = r.Log.IEC
	}
	if r.SIP != nil {
		observeSIP(leg, r.SIP, r.Time)
	}
}

// observeSIP advances the leg's state from one SIP message.
func observeSIP(leg *Leg, m *parse.SIPMessage, t time.Time) {
	if m.IsRequest() {
		switch m.Method {
		case "INVITE":
			if leg.Direction == "" {
				if m.Direction == parse.DirReceived {
					leg.Direction = DirInbound
				} else {
					leg.Direction = DirOutbound
				}
			}
			if leg.Calling == "" && m.From != nil {
				leg.Calling = m.From.User
			}
			if leg.Called == "" && m.To != nil {
				leg.Called = m.To.User
			}
			leg.Keepalive = false
		case "OPTIONS":
			// Only a leg that never saw anything else is a keepalive.
			if leg.Direction == "" && leg.FinalStatus == 0 {
				leg.Keepalive = true
			}
		case "BYE", "CANCEL":
			leg.Disconnect = m.Method
			leg.State, leg.End = StateEnded, t
			if cause := q850Cause(m); cause != "" {
				leg.Cause = cause
			}
		}
		return
	}

	if m.CSeqMethod != "INVITE" {
		return
	}
	switch {
	case m.Status == 180 || m.Status == 183:
		if leg.State == StateSetup {
			leg.State = StateRinging
		}
	case m.Status < 200:
	case m.Status < 300:
		leg.FinalStatus, leg.FinalReason = m.Status, m.Reason
		if leg.State != StateEnded {
			leg.State = StateConnected
		}
	default:
		leg.FinalStatus, leg.FinalReason = m.Status, m.Reason
		leg.State, leg.End = StateEnded, t
		if cause := q850Cause(m); cause != "" {
			leg.Cause = cause
		}
	}
}

// q850Cause reads the ISDN cause out of a Reason header, which is where CUBE
// puts the real disconnect reason behind a SIP status code.
func q850Cause(m *parse.SIPMessage) string {
	v := m.Header("Reason")
	if !strings.HasPrefix(strings.ToUpper(v), "Q.850") {
		return ""
	}
	for _, p := range strings.Split(v, ";") {
		name, value, ok := strings.Cut(p, "=")
		if ok && strings.EqualFold(strings.TrimSpace(name), "cause") {
			return "Q.850;cause=" + strings.TrimSpace(value)
		}
	}
	return ""
}

// place attaches a leg to a call, opening a new one when a reused GUID has
// moved on to a different call.
func (c *Correlator) place(leg *Leg, guid string, t time.Time) {
	if leg.call != nil {
		if guid != "" && leg.call.GUID == "" {
			// A leg that started life without a GUID has just learned one. If
			// another call already owns that GUID, the two are one call.
			if open := c.openCall(guid, t); open != nil && open != leg.call {
				c.mergeCalls(open, leg.call)
				return
			}
			leg.call.GUID = guid
			c.openGUID[guid] = leg.call
		}
		return
	}

	var call *Call
	if guid != "" {
		call = c.openCall(guid, t)
	}
	if call == nil {
		call = &Call{ID: "call-" + strconv.Itoa(len(c.calls)+1), GUID: guid, Start: t, End: t}
		c.calls = append(c.calls, call)
		if guid != "" {
			c.openGUID[guid] = call
		}
	}
	call.Legs = append(call.Legs, leg)
	leg.call = call
}

// openCall returns the call a GUID currently belongs to, or nil when the GUID
// has been reused for a new call.
//
// The GUID is 12 hex characters and does repeat within hours, so a GUID stays
// with a call only while one of its legs is still up or its last record is
// recent. This is what stops fifteen unrelated calls collapsing into one.
func (c *Correlator) openCall(guid string, t time.Time) *Call {
	call := c.openGUID[guid]
	if call == nil {
		return nil
	}
	for _, l := range call.Legs {
		if l.State != StateEnded {
			return call
		}
	}
	if t.Sub(call.End) <= c.guidWindow() {
		return call
	}
	delete(c.openGUID, guid)
	return nil
}

func (c *Correlator) guidWindow() time.Duration {
	if c.GUIDWindow > 0 {
		return c.GUIDWindow
	}
	return DefaultGUIDWindow
}

// mergeCalls folds src into dst. It happens when a leg created before its GUID
// was known turns out to belong to a call that already exists.
func (c *Correlator) mergeCalls(dst, src *Call) {
	for _, l := range src.Legs {
		l.call = dst
		dst.Legs = append(dst.Legs, l)
	}
	src.Legs = nil
	src.merged = true
}

// Result finishes the grouping: it rolls each call up from its legs and drops
// the calls that were merged away.
func (c *Correlator) Result() *Result {
	res := &Result{Unattached: c.unattached}
	for _, call := range c.calls {
		if call.merged || len(call.Legs) == 0 {
			continue
		}
		rollUp(call)
		res.Calls = append(res.Calls, call)
	}
	return res
}

// Records returns the records the correlator has seen, in order. A leg's
// Records field indexes into this slice.
func (c *Correlator) Records() []*parse.Record { return c.records }

// rollUp derives a call's summary from its legs.
func rollUp(call *Call) {
	sort.SliceStable(call.Legs, func(i, j int) bool {
		return call.Legs[i].Start.Before(call.Legs[j].Start)
	})

	call.Start, call.End = call.Legs[0].Start, call.Legs[0].End
	call.Keepalive = true
	connected, allEnded := false, true

	for _, l := range call.Legs {
		if l.Start.Before(call.Start) {
			call.Start = l.Start
		}
		if l.End.After(call.End) {
			call.End = l.End
		}
		if !l.Keepalive {
			call.Keepalive = false
		}
		if l.State == StateConnected {
			connected = true
		}
		if l.State != StateEnded {
			allEnded = false
		}
		// The inbound leg names the call: it carries the numbers as the caller
		// dialled them, before any translation rule rewrote them.
		if call.Calling == "" || l.Direction == DirInbound {
			if l.Calling != "" {
				call.Calling = l.Calling
			}
			if l.Called != "" {
				call.Called = l.Called
			}
		}
		if l.IEC != "" {
			call.IEC = l.IEC
		}
		for _, w := range l.Warnings {
			call.Warnings = appendOnce(call.Warnings, l.ID+": "+w)
		}
	}
	call.Dur = call.End.Sub(call.Start)

	switch {
	case allEnded:
		call.State = StateEnded
	case connected:
		call.State = StateConnected
	default:
		call.State = call.Legs[0].State
	}
	call.Result, call.Cause = result(call)
}

// result is what a user wants in the call list: why the call ended.
//
// A failure response beats everything, because it is the reason. Otherwise the
// teardown method, and only then the answer.
func result(call *Call) (string, string) {
	for _, l := range call.Legs {
		if l.FinalStatus >= 300 {
			return strconv.Itoa(l.FinalStatus) + " " + l.FinalReason, l.Cause
		}
	}
	for _, l := range call.Legs {
		if l.Disconnect != "" {
			return l.Disconnect, l.Cause
		}
	}
	for _, l := range call.Legs {
		if l.FinalStatus >= 200 && l.FinalStatus < 300 {
			return strconv.Itoa(l.FinalStatus) + " " + l.FinalReason, l.Cause
		}
	}
	return "", ""
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func appendOnce(ss []string, s string) []string {
	if contains(ss, s) {
		return ss
	}
	return append(ss, s)
}
