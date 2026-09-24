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
}

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
		return "sequence gap: " + strconv.FormatUint(g.Missing, 10) +
			" record(s) missing between " + strconv.FormatUint(g.After, 10) +
			" and " + strconv.FormatUint(g.Before, 10)
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

// SeqTracker follows one source's sequence numbers and reports the breaks.
// It is the only loss detector there is: IOS rate limiting and buffer overruns
// drop records silently, and on the UDP path so does the network.
type SeqTracker struct {
	Gaps []Gap

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
	g := Gap{After: prev, Before: seq}
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
