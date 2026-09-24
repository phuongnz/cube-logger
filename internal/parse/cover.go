package parse

import (
	"strconv"
	"strings"
)

// CoverBuffer is the per-call summary block the CUBE voice-trace feature dumps.
// It states the whole correlation outright — call entry ID, GUID, SIP Call-ID
// and both numbers in one place — so when it is present it is the cheapest
// correlation source there is. It depends on voice trace being configured, and
// was on a small minority of calls in the study capture, so the correlator uses
// it to enrich and cross-check and never depends on it.
type CoverBuffer struct {
	SearchKey  string `json:"searchKey,omitempty"`
	Timestamp  string `json:"timestamp,omitempty"`
	CallID     int64  `json:"callId,omitempty"`
	PeerCallID string `json:"peerCallId,omitempty"`
	Correlator string `json:"correlator,omitempty"`
	Called     string `json:"calledNumber,omitempty"`
	Calling    string `json:"callingNumber,omitempty"`
	SIPCallID  string `json:"sipCallId,omitempty"`
	SessionID  string `json:"sipSessionId,omitempty"`
	GUID       string `json:"guid,omitempty"`
	Tenant     string `json:"tenant,omitempty"`
	CauseCode  string `json:"causeCode,omitempty"`

	// Other holds any field this struct does not name, so a newer IOS release
	// adding one does not lose it.
	Other map[string]string `json:"other,omitempty"`
}

// parseCoverBuffer reads a Cover Buffer block, or returns nil when the
// continuation lines are not one.
func parseCoverBuffer(cont []string) *CoverBuffer {
	found := false
	for _, l := range cont {
		if strings.Contains(l, "Cover Buffer") {
			found = true
			break
		}
	}
	if !found {
		return nil
	}

	c := &CoverBuffer{CallID: NoCallID}
	for _, l := range cont {
		name, value, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if name == "" {
			continue
		}
		if value == "NA" || value == "n/a" {
			value = ""
		}
		switch name {
		case "Search-key":
			c.SearchKey = value
		case "Timestamp":
			c.Timestamp = value
		case "CallID":
			if n, err := strconv.ParseInt(value, 10, 64); err == nil {
				c.CallID = n
			}
		case "Peer-CallID":
			c.PeerCallID = value
		case "Correlator":
			c.Correlator = value
		case "Called-Number":
			c.Called = value
		case "Calling-Number":
			c.Calling = value
		case "SIP CallID":
			c.SIPCallID = value
		case "SIP SessionID":
			c.SessionID = value
		case "GUID":
			c.GUID = value
		case "Tenant":
			c.Tenant = value
		case "Cause-code":
			c.CauseCode = value
		default:
			if value != "" {
				if c.Other == nil {
					c.Other = map[string]string{}
				}
				c.Other[name] = value
			}
		}
	}
	return c
}
