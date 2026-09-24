package parse

import "strconv"

// maxPlausibleGap is where "we lost some records" stops being the best
// explanation. Sequence numbers are per device, and a saved file can hold two
// CUBEs in two disjoint numbering spaces: differencing those naively reports
// hundreds of millions of missing records. Above this, the jump is reported as
// a discontinuity instead of loss.
const maxPlausibleGap = 100000

// Gap is a break in a source's sequence numbers.
type Gap struct {
	// After is the last sequence number seen before the break, Before the first
	// one seen after it.
	After  uint64 `json:"after"`
	Before uint64 `json:"before"`
	// Missing is how many records the numbering skipped, for KindLoss only.
	Missing uint64 `json:"missing,omitempty"`
	Kind    string `json:"kind"`
	// Unit is what the counter counts: "" or UnitRecord for the counter inside
	// the IOS frame, UnitLine for the outer, per-datagram counter on the UDP
	// path. The two are different counters and saying which one broke is the
	// difference between "a message is missing" and "a message is incomplete".
	Unit string `json:"unit,omitempty"`
}

// What a sequence counter counts. See docs/log-format.md § The UDP path.
const (
	// UnitRecord is the counter inside the IOS frame: +1 per record.
	UnitRecord = "record"
	// UnitLine is the counter after <PRI> on the UDP path: +1 per line.
	UnitLine = "line"
)

// The kinds of break, in descending order of how much they should worry a user.
const (
	// GapLoss is a forward skip small enough to be genuinely lost records —
	// syslog rate limiting, a buffer overrun, or dropped UDP datagrams.
	GapLoss = "loss"
	// GapBackwards is a sequence number at or below the previous one: the
	// counter was reset by a reload, or the stream mixes two devices.
	GapBackwards = "backwards"
	// GapDiscontinuity is a forward jump too large to be loss, which means the
	// same thing: this is a different numbering space.
	GapDiscontinuity = "discontinuity"
)

// Reason renders the gap as a line for the UI or the CLI.
func (g Gap) Reason() string {
	switch g.Kind {
	case GapLoss:
		// "lost or rate-limited", never "lost": this router rate-limits its own
		// logging, and whether a rate-limited message still consumes a sequence
		// number is open question 2 in docs/log-format.md. Telling an engineer
		// they have a network problem while their router throttles itself sends
		// them looking in the wrong place.
		return "sequence gap: " + strconv.FormatUint(g.Missing, 10) + " " +
			g.unit() + "(s) lost or rate-limited between " +
			strconv.FormatUint(g.After, 10) + " and " + strconv.FormatUint(g.Before, 10)
	case GapBackwards:
		return "sequence went backwards: " + strconv.FormatUint(g.After, 10) +
			" then " + strconv.FormatUint(g.Before, 10) +
			" (device reload, or two devices in one stream)"
	default:
		return "sequence jumped from " + strconv.FormatUint(g.After, 10) +
			" to " + strconv.FormatUint(g.Before, 10) +
			" (too far to be loss; probably a second device)"
	}
}

// unit is the noun for what this counter counts, defaulting to records.
func (g Gap) unit() string {
	if g.Unit == UnitLine {
		return UnitLine
	}
	return UnitRecord
}

// SeqTracker follows one source's sequence numbers and reports the breaks.
// It is the only loss detector there is: IOS rate limiting and buffer overruns
// drop records silently, and on the UDP path so does the network.
type SeqTracker struct {
	Gaps []Gap

	// Unit is stamped onto every gap this tracker reports. The zero value means
	// UnitRecord, which is what the counter in the IOS frame counts.
	Unit string

	last uint64
	seen bool
}

// Observe records one sequence number and returns the gap it opened, if any.
func (t *SeqTracker) Observe(seq uint64) (Gap, bool) {
	prev, seen := t.last, t.seen
	t.last, t.seen = seq, true
	if !seen || seq == prev+1 {
		return Gap{}, false
	}
	g := Gap{After: prev, Before: seq, Unit: t.Unit}
	switch {
	case seq <= prev:
		g.Kind = GapBackwards
	case seq-prev-1 > maxPlausibleGap:
		g.Kind = GapDiscontinuity
	default:
		g.Kind, g.Missing = GapLoss, seq-prev-1
	}
	t.Gaps = append(t.Gaps, g)
	return g, true
}

// TakeGaps returns the gaps seen since the last call and forgets them.
//
// A file is parsed once and reads Gaps at the end; a live stream runs for days,
// so it drains instead. Without this the slice is an unbounded accumulation of
// every loss event in the session.
func (t *SeqTracker) TakeGaps() []Gap {
	g := t.Gaps
	t.Gaps = nil
	return g
}
