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

	// Records references this leg's records. On the file path a reference is
	// the record's index in Correlator.Records(); on the live path it is the
	// store ID the caller passed to AddRef. Either way it is a handle the
	// caller can resolve, never a pointer the correlator has to keep alive.
	Records  []uint64 `json:"records"`
	Warnings []string `json:"warnings,omitempty"`

	call *Call
	// entryKeys and callIDKeys are the index keys this leg owns, so eviction
	// can take them out again without walking every map.
	entryKeys, callIDKeys []string
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

	// mergedInto is set when this call turned out to be another one. The ID
	// stays resolvable, because a browser may still be holding it.
	mergedInto *Call
}

// Duration is how long the call lasted, from its first record to its last.
func (c *Call) Duration() time.Duration { return c.End.Sub(c.Start) }

// DefaultGUIDWindow is how long after a call's last record its GUID still
// belongs to it. CUBE forms the second leg of a call within milliseconds, so a
// few seconds is generous; beyond it, a reappearing GUID is a different call.
const DefaultGUIDWindow = 5 * time.Second

// Correlator turns a record stream into calls. Feed records in order with Add
// and read the answer with Result.
//
// A file ends, so the file path can keep everything: Add holds on to each
// record and Result hands back every call. A live stream does not end, which is
// what MaxCalls and AddRef are for — see AddRef.
type Correlator struct {
	// GUIDWindow scopes GUID grouping in time. Zero means DefaultGUIDWindow.
	GUIDWindow time.Duration

	// MaxCalls bounds how many calls are kept. Zero means no bound, which is
	// right for a file and wrong for a stream that runs for days. Past the
	// bound the oldest finished calls are dropped first.
	MaxCalls int

	// Forget, when set, is called with the ID of a call that has stopped being
	// a call in its own right: it was evicted, or it turned out to be part of
	// another call. A live view keeps a list of calls and needs to be told what
	// to take off it; without this it would have to diff the whole list.
	//
	// A merged ID still resolves through Call — a browser may have selected it
	// before the merge — but it is no longer a row of its own.
	Forget func(id string)

	records []*parse.Record
	calls   []*Call
	byID    map[string]*Call

	nLegs, nCalls int
	evicted       uint64

	byEntry  map[string]*Leg
	byCallID map[string]*Leg
	openGUID map[string]*Call

	// unattached are records that belong to no call: dial-peer and TLS state,
	// logins, and anything else the box says about itself. Only collected when
	// the correlator is keeping records; on a live stream the store has them.
	unattached []uint64
}

// New returns an empty Correlator.
func New() *Correlator {
	return &Correlator{
		byID:     map[string]*Call{},
		byEntry:  map[string]*Leg{},
		byCallID: map[string]*Leg{},
		openGUID: map[string]*Call{},
	}
}

// Result is the finished grouping.
type Result struct {
	Calls      []*Call  `json:"calls"`
	Unattached []uint64 `json:"unattached,omitempty"`
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

// Add takes the next record and keeps it. Records must arrive in the order they
// were logged. A leg's Records then index into Records().
func (c *Correlator) Add(r *parse.Record) {
	ref := uint64(len(c.records))
	c.records = append(c.records, r)
	c.add(ref, r, true)
}

// Records returns the records Add has seen, in order. AddRef keeps none, so on
// the live path this is empty and a leg's Records are the caller's own IDs.
func (c *Correlator) Records() []*parse.Record { return c.records }

// AddRef takes the next record without keeping it. ref is the caller's own
// handle for the record — a store ID on the live path — and it is what a leg's
// Records will contain.
//
// This is the difference between a run that ends and a run that does not. Add
// pins every record it has ever seen, which for a file is exactly right and for
// a session left open overnight is a leak. With AddRef the records live in the
// ring, which already knows how to forget them, and the correlator holds
// nothing but identifiers — so with MaxCalls set it is bounded in both
// directions.
//
// It returns the call the record landed in, or nil when the record belongs to
// no call at all — dial-peer state, a login, anything the box says about
// itself. The caller uses that to know which call to redraw.
func (c *Correlator) AddRef(ref uint64, r *parse.Record) *Call {
	return c.add(ref, r, false)
}

func (c *Correlator) add(ref uint64, r *parse.Record, keep bool) *Call {
	entry, guid, sipCallID := ids(r)
	leg := c.leg(r, entry, sipCallID)
	if leg == nil {
		if keep {
			c.unattached = append(c.unattached, ref)
		}
		return nil
	}
	leg.Records = append(leg.Records, ref)
	c.observe(leg, r, guid, sipCallID)
	c.place(leg, guid, r.Time)
	c.evict()
	// place may have merged this leg's call into another, and eviction may
	// have dropped it outright; either way leg.call is the answer now.
	if leg.call == nil || leg.call.mergedInto != nil {
		return c.resolve(leg.call)
	}
	return leg.call
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
				c.ownEntry(l, entryKey(r.Source, entry))
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

	c.nLegs++
	l := &Leg{
		ID:          "leg-" + strconv.Itoa(c.nLegs),
		Source:      r.Source,
		CallEntryID: entry,
		Start:       r.Time,
		End:         r.Time,
		State:       StateSetup,
	}
	if entry != parse.NoCallID {
		c.ownEntry(l, entryKey(r.Source, entry))
	}
	if sipCallID != "" {
		c.ownCallID(l, callIDKey(r.Source, sipCallID))
	}
	return l
}

// ownEntry and ownCallID point an index key at a leg and remember that the leg
// owns it. Eviction needs the keys back; walking two maps to find them would
// turn forgetting one call into work proportional to the whole session.
func (c *Correlator) ownEntry(l *Leg, key string) {
	c.byEntry[key] = l
	l.entryKeys = append(l.entryKeys, key)
}

func (c *Correlator) ownCallID(l *Leg, key string) {
	c.byCallID[key] = l
	l.callIDKeys = append(l.callIDKeys, key)
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
			c.ownCallID(leg, k)
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
		c.nCalls++
		call = &Call{ID: "call-" + strconv.Itoa(c.nCalls), GUID: guid, Start: t, End: t}
		c.calls = append(c.calls, call)
		c.byID[call.ID] = call
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
	src.mergedInto = dst
	c.forget(src.ID)
}

func (c *Correlator) forget(id string) {
	if c.Forget != nil {
		c.Forget(id)
	}
}

// Call resolves a call ID, following merges: a browser that selected a call
// before its second leg arrived is holding an ID that has since been folded
// into another, and it should land on the call rather than on nothing.
func (c *Correlator) Call(id string) *Call { return c.resolve(c.byID[id]) }

func (c *Correlator) resolve(call *Call) *Call {
	for i := 0; call != nil && call.mergedInto != nil; i++ {
		if i > 100 {
			return nil // a merge cycle cannot happen; do not hang if it does
		}
		call = call.mergedInto
	}
	if call == nil || len(call.Legs) == 0 {
		return nil
	}
	RollUp(call)
	return call
}

// Calls returns the live calls, oldest first, rolled up. Merged and empty ones
// are left out: they are bookkeeping, not calls.
func (c *Correlator) Calls() []*Call {
	out := make([]*Call, 0, len(c.calls))
	for _, call := range c.calls {
		if call.mergedInto != nil || len(call.Legs) == 0 {
			continue
		}
		RollUp(call)
		out = append(out, call)
	}
	return out
}

// Evicted is how many calls have been dropped to stay inside MaxCalls. It is
// this tool running out of room, like the store's own eviction, and it must
// never be shown as if records had been lost on the wire.
func (c *Correlator) Evicted() uint64 { return c.evicted }

// evict drops the oldest calls once there are more than MaxCalls of them.
//
// Finished calls go first: an engineer watching a live system cares about the
// call that is ringing now, and a call that ended an hour ago is the one they
// can afford to lose. Only when every call is still open does the oldest go
// regardless — a stream of calls that never end is a correlator that never
// learned they ended, and the alternative is unbounded memory.
func (c *Correlator) evict() {
	// How far along the list to look for a call that has already finished.
	// The list is in creation order and this runs once per new call, so the
	// bound is what keeps eviction from costing a scan of the whole session
	// every time a phone rings.
	const scan = 64

	for c.MaxCalls > 0 && len(c.calls) > c.MaxCalls {
		victim := 0
		for i := 0; i < len(c.calls) && i < scan; i++ {
			if finished(c.calls[i]) {
				victim = i
				break
			}
		}
		c.drop(c.calls[victim])
		c.calls = append(c.calls[:victim], c.calls[victim+1:]...)
	}
}

// finished reports whether every leg of a call has been torn down. It reads the
// legs rather than Call.State, because Call.State is only as fresh as the last
// RollUp and rolling every candidate up on every eviction would cost more than
// the eviction saves.
func finished(call *Call) bool {
	if call.mergedInto != nil || len(call.Legs) == 0 {
		return true
	}
	for _, l := range call.Legs {
		if l.State != StateEnded {
			return false
		}
	}
	return true
}

// drop forgets one call and everything that points at it.
func (c *Correlator) drop(call *Call) {
	delete(c.byID, call.ID)
	if call.GUID != "" && c.openGUID[call.GUID] == call {
		delete(c.openGUID, call.GUID)
	}
	for _, l := range call.Legs {
		for _, k := range l.entryKeys {
			if c.byEntry[k] == l {
				delete(c.byEntry, k)
			}
		}
		for _, k := range l.callIDKeys {
			if c.byCallID[k] == l {
				delete(c.byCallID, k)
			}
		}
	}
	if call.mergedInto == nil {
		c.evicted++
		c.forget(call.ID)
	}
}

// Result finishes the grouping: it rolls each call up from its legs and drops
// the calls that were merged away.
func (c *Correlator) Result() *Result {
	return &Result{Unattached: c.unattached, Calls: c.Calls()}
}

// RollUp derives a call's summary from its legs.
func RollUp(call *Call) {
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
