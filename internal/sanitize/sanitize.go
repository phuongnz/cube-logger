// Package sanitize rewrites a raw CUBE capture into text that is safe to commit
// to a public repository.
//
// It replaces IP addresses, phone numbers, the user and host parts of SIP URIs,
// display names, hostnames and domains, and it removes credentials outright.
// Replacements are consistent within a run — the same real IP always becomes
// the same fake IP — so calls still correlate and the output is still a valid
// test fixture.
//
// What it deliberately keeps: sequence numbers, timestamps, call entry IDs,
// GUIDs, SIP tags and branches, CSeq numbers, product versions and SDP media
// parameters. None of them identify a person, and all of them are what the
// parser and correlator are tested against.
//
// The mapping is never written anywhere. It is a re-identification key: with it
// and the sanitized file, the original is recoverable. It lives in memory for
// one run and is discarded.
//
// One known distortion: a replacement rarely has the same length as what it
// replaced, so a sanitized SIP body can disagree with its Content-Length. The
// parser reports that as a warning rather than failing, and the length is not
// adjusted here because rewriting a header to match would hide a genuinely
// truncated message — the thing the check exists to find.
//
// Sanitizing is not a substitute for reading the output. Review every fixture
// before committing it.
package sanitize

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/phuongnz/cube-logger/internal/parse"
)

// Sanitizer holds one run's replacement mapping. It is not safe for concurrent
// use, and a new one should be made per file: consistency is only wanted, and
// only safe, within a file.
type Sanitizer struct {
	ips     map[string]string
	numbers map[string]string
	users   map[string]string
	hosts   map[string]string
	names   map[string]string
	// literals are strings the caller named, and bare hostnames discovered from
	// a terminal prompt. They are replaced wherever they appear.
	literals map[string]string

	// order and numberOrder keep replacement deterministic: a map's iteration
	// order is not, and the same input must always produce the same fixture.
	order        []string // literals, longest first, so a suffix never wins
	numberOrder  []string // numbers, longest first, for the same reason
	numbersRe    *regexp.Regexp
	numbersDirty bool

	// fakeNumbers holds the replacements already handed out. Several rules look
	// at the same line in turn, and without this a number rewritten by the URI
	// rule would be rewritten again by the loose-number rule, so the same real
	// number would come out differently depending on where it appeared.
	fakeNumbers map[string]bool

	redactions int
}

// New returns an empty Sanitizer.
func New() *Sanitizer {
	return &Sanitizer{
		ips:      map[string]string{},
		numbers:  map[string]string{},
		users:    map[string]string{},
		hosts:    map[string]string{},
		names:    map[string]string{},
		literals: map[string]string{},

		fakeNumbers: map[string]bool{},
	}
}

// Stats counts what one run replaced. It is a sanity check for the human
// reviewing the output: zero replaced IP addresses in a CUBE capture means the
// sanitizer did not understand the file.
type Stats struct {
	IPs, Numbers, Users, Hosts, Names, Redactions int
}

// Stats returns the counts so far.
func (s *Sanitizer) Stats() Stats {
	return Stats{
		IPs: len(s.ips), Numbers: len(s.numbers), Users: len(s.users),
		Hosts: len(s.hosts), Names: len(s.names), Redactions: s.redactions,
	}
}

func (st Stats) String() string {
	return fmt.Sprintf("%d addresses, %d numbers, %d users, %d hosts, %d names, %d credentials removed",
		st.IPs, st.Numbers, st.Users, st.Hosts, st.Names, st.Redactions)
}

// AddLiteral registers a string to replace wherever it appears — a hostname, a
// customer name, anything the pattern rules would not catch.
func (s *Sanitizer) AddLiteral(str string) {
	if str == "" {
		return
	}
	s.literal(str)
}

func (s *Sanitizer) literal(str string) string {
	if v, ok := s.literals[str]; ok {
		return v
	}
	v := "host" + strconv.Itoa(len(s.hosts)+len(s.literals)+1)
	s.literals[str] = v
	s.order = append(s.order, str)
	// Longest first: replacing "cube" before "cube-lab-01" would leave a tail.
	for i := len(s.order) - 1; i > 0 && len(s.order[i]) > len(s.order[i-1]); i-- {
		s.order[i], s.order[i-1] = s.order[i-1], s.order[i]
	}
	return v
}

// Reader sanitizes a whole stream. Line endings are preserved exactly: the
// parser has to cope with a file that mixes CRLF and LF, so its fixtures must
// be able to contain one.
func (s *Sanitizer) Reader(r io.Reader, w io.Writer) error {
	br := bufio.NewReader(r)
	bw := bufio.NewWriter(w)
	defer bw.Flush()
	for {
		line, err := br.ReadString('\n')
		if line != "" {
			body, ending := splitEnding(line)
			if _, werr := bw.WriteString(s.Line(body) + ending); werr != nil {
				return werr
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func splitEnding(line string) (body, ending string) {
	switch {
	case strings.HasSuffix(line, "\r\n"):
		return line[:len(line)-2], "\r\n"
	case strings.HasSuffix(line, "\n"):
		return line[:len(line)-1], "\n"
	}
	return line, ""
}

var (
	// authRe matches the headers whose value is a credential. The value is
	// removed rather than replaced: there is nothing in it worth keeping, and a
	// consistently-mapped nonce would still be a credential.
	authRe = regexp.MustCompile(`(?i)^((?:WWW-|Proxy-)?(?:Authorization|Authenticate)) *:.*$`)
	// promptRe matches an IOS command prompt, which names the device.
	promptRe = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9._-]{1,62})([#>])`)
	ipv4Re   = regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)
	// ipv6Re is deliberately narrow. A bare run of hex and colons is
	// indistinguishable from a timestamp, so only bracketed literals and the
	// SDP "IN IP6 <addr>" form are matched.
	ipv6Re = regexp.MustCompile(`\[[0-9A-Fa-f:]+\]|(?:IN IP6 )([0-9A-Fa-f:]+)`)
	// ipv6BareRe catches an address written without brackets, as a Cover Buffer
	// field or a log line does. It is deliberately loose because "09:14:02"
	// matches the same shape; every match is then handed to netip.ParseAddr,
	// which is the only reliable way to tell an address from a timestamp.
	ipv6BareRe = regexp.MustCompile(`[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}`)
	uriRe      = regexp.MustCompile(`(?i)\b(sips?|tel):([^@\s>;,"]*)(@([^\s>;,"]+))?`)
	// quotedRe matches a display name on a SIP header line.
	quotedRe = regexp.MustCompile(`"[^"]*"`)
	headerRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,40} *:`)
	// fqdnRe matches a dotted name whose last label is all letters, which keeps
	// it off version strings like "IOS-17.12.5a" and error codes like "1.1.180.1".
	fqdnRe     = regexp.MustCompile(`[A-Za-z0-9_][A-Za-z0-9_-]*(?:\.[A-Za-z0-9_-]+)*\.[A-Za-z]{2,24}`)
	coverNumRe = regexp.MustCompile(`^(\s*(?:Called-Number|Calling-Number)\s*=\s*)(\S+)\s*$`)
	coverKeyRe = regexp.MustCompile(`^(\s*Search-key\s*=\s*)(\S+)\s*$`)
	numberRe   = regexp.MustCompile(`^[+*#]?[0-9][0-9*#]*$`)
	// plusNumberRe matches an E.164 number anywhere. A "+" followed by seven or
	// more digits is a phone number in any header a vendor invents, and the
	// boundary guard keeps it off the "+" separators inside a SIP tag.
	plusNumberRe = regexp.MustCompile(`\+[0-9]{7,15}`)
	// headerNumberRe matches a header whose whole value is a bare number, which
	// is how non-standard headers carry a caller ID.
	headerNumberRe = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9-]{0,40} *: *)([+*#]?[0-9]{6,20}) *$`)
)

// fakeSuffix is the reserved domain the sanitizer maps hostnames into. Nothing
// under it is remapped on a second pass.
const fakeSuffix = ".example.net"

// Line sanitizes one line, without its line ending.
func (s *Sanitizer) Line(line string) string {
	if m := authRe.FindStringSubmatch(line); m != nil {
		s.redactions++
		return m[1] + ": <removed by cube-logger sanitize>"
	}

	// The IOS frame is a sequence number and a clock reading. Leave it alone.
	frame, payload, _ := parse.SplitFrame(line)
	// A debug header is call entry ID, GUID and a component path — identifiers,
	// not data. Keeping it verbatim also keeps a 7-digit call entry ID from
	// being mistaken for a phone number.
	if strings.HasPrefix(payload, "//") {
		if head, rest, ok := strings.Cut(payload, ":"); ok {
			frame, payload = frame+head+":", rest
		} else {
			return frame + payload
		}
	}

	if m := promptRe.FindStringSubmatch(payload); m != nil && !strings.Contains(m[1], ".") {
		s.literal(m[1])
	}
	for _, lit := range s.order {
		payload = strings.ReplaceAll(payload, lit, s.literals[lit])
	}

	payload = s.replaceIPs(payload)
	payload = s.replaceURIs(payload)
	payload = s.replaceNames(payload)
	payload = s.replaceLooseNumbers(payload)
	payload = s.replaceCoverFields(payload)
	payload = s.replaceKnownNumbers(payload)
	payload = s.replaceFQDNs(payload)
	return frame + payload
}

// replaceIPs rewrites IPv4 and bracketed IPv6 literals.
func (s *Sanitizer) replaceIPs(text string) string {
	text = replaceFunc(text, ipv4Re, func(m string, before, after byte) string {
		// Guard the boundaries by hand: an IEC like "1.1.180.1.29.0" contains
		// something that looks exactly like a dotted quad.
		if isDigitOrDot(before) || isDigitOrDot(after) || !validIPv4(m) {
			return m
		}
		return s.mapIP(m)
	})
	text = ipv6Re.ReplaceAllStringFunc(text, func(m string) string {
		if strings.HasPrefix(m, "[") {
			return "[" + s.mapIP(m[1:len(m)-1]) + "]"
		}
		return "IN IP6 " + s.mapIP(strings.TrimPrefix(m, "IN IP6 "))
	})
	return replaceFunc(text, ipv6BareRe, func(m string, before, after byte) string {
		if isHexOrColon(before) || isHexOrColon(after) || after == '.' {
			return m
		}
		if a, err := netip.ParseAddr(m); err != nil || !a.Is6() {
			return m
		}
		return s.mapIP(m)
	})
}

func isDigitOrDot(b byte) bool { return b == '.' || (b >= '0' && b <= '9') }

func isHexOrColon(b byte) bool {
	return b == ':' || (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

func validIPv4(s string) bool {
	for _, p := range strings.Split(s, ".") {
		n, err := strconv.Atoi(p)
		if err != nil || n > 255 || (len(p) > 1 && p[0] == '0') {
			return false
		}
	}
	return true
}

// replaceURIs rewrites the user and host parts of sip:, sips: and tel: URIs.
// Hosts that are already IP literals were handled by replaceIPs.
func (s *Sanitizer) replaceURIs(text string) string {
	return uriRe.ReplaceAllStringFunc(text, func(m string) string {
		g := uriRe.FindStringSubmatch(m)
		scheme, first, host := g[1], g[2], g[4]
		if g[3] == "" {
			if first == "" {
				// "SIP:" in prose, as a %VOICE_IEC log line writes it. Not a URI.
				return m
			}
			// No "@": the field is a host, not a user. "sip:192.0.2.10" and
			// "tel:+441234567890" are told apart by shape.
			if scheme == "tel" || numberRe.MatchString(first) {
				return scheme + ":" + s.mapNumber(first)
			}
			return scheme + ":" + s.mapHostOrIP(first)
		}
		return scheme + ":" + s.mapUserPart(first) + "@" + s.mapHostOrIP(host)
	})
}

func (s *Sanitizer) mapUserPart(u string) string {
	if u == "" {
		return u
	}
	if numberRe.MatchString(u) {
		return s.mapNumber(u)
	}
	return s.mapUser(u)
}

// mapHostOrIP maps a URI host, keeping any port and leaving an address that
// replaceIPs already rewrote alone.
func (s *Sanitizer) mapHostOrIP(host string) string {
	host, params, hasParams := strings.Cut(host, ";")
	out := host
	port := ""
	if !strings.HasPrefix(host, "[") {
		if i := strings.LastIndex(host, ":"); i >= 0 {
			if _, err := strconv.Atoi(host[i+1:]); err == nil {
				out, port = host[:i], host[i:]
			}
		}
	}
	if !ipv4Re.MatchString(out) && !strings.HasPrefix(out, "[") && !strings.HasSuffix(out, fakeSuffix) {
		out = s.mapHost(out)
	}
	out += port
	if hasParams {
		out += ";" + params
	}
	return out
}

// replaceNames rewrites display names on SIP header lines.
func (s *Sanitizer) replaceNames(text string) string {
	if !headerRe.MatchString(text) {
		return text
	}
	return quotedRe.ReplaceAllStringFunc(text, func(m string) string {
		inner := m[1 : len(m)-1]
		if inner == "" {
			return m
		}
		return `"` + s.mapName(inner) + `"`
	})
}

// replaceCoverFields rewrites the numbers in a voice-trace Cover Buffer block,
// which states them outside any URI.
func (s *Sanitizer) replaceCoverFields(text string) string {
	if m := coverNumRe.FindStringSubmatch(text); m != nil {
		return m[1] + s.mapNumber(m[2])
	}
	if m := coverKeyRe.FindStringSubmatch(text); m != nil {
		// "<calling>:<called>:<call entry id>" — the third field is an ID.
		parts := strings.Split(m[2], ":")
		for i := 0; i < len(parts) && i < 2; i++ {
			parts[i] = s.mapNumber(parts[i])
		}
		return m[1] + strings.Join(parts, ":")
	}
	return text
}

// numericHeaders are the standard headers whose value is a number but not a
// phone number. Everything else with a bare numeric value is treated as one.
var numericHeaders = map[string]bool{
	"content-length": true, "max-forwards": true, "expires": true,
	"min-se": true, "session-expires": true, "timestamp": true,
	"retry-after": true, "rseq": true, "cseq": true, "priority": true,
	"warning": true, "content-disposition": true, "mime-version": true,
}

// replaceLooseNumbers catches phone numbers outside any URI: an E.164 number
// anywhere, and a header whose entire value is a number.
func (s *Sanitizer) replaceLooseNumbers(text string) string {
	if m := headerNumberRe.FindStringSubmatch(text); m != nil {
		name := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(m[1]), ":")))
		if !numericHeaders[name] {
			return m[1] + s.mapNumber(m[2])
		}
	}
	return replaceFunc(text, plusNumberRe, func(m string, before, after byte) string {
		if isAlnum(before) || before == '+' || isAlnum(after) {
			return m
		}
		return s.mapNumber(m)
	})
}

func isAlnum(b byte) bool {
	return isDigit(b) || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// replaceKnownNumbers catches a number already seen in a URI turning up in free
// text — a %VOICE_IEC line, a debug message, a vendor's own header. Only
// numbers already in the mapping are replaced, so nothing else that looks like
// digits is touched.
func (s *Sanitizer) replaceKnownNumbers(text string) string {
	re := s.knownNumbers()
	if re == nil {
		return text
	}
	return replaceFunc(text, re, func(m string, before, after byte) string {
		if isDigit(before) || isDigit(after) {
			return m // part of a longer number, so not this one
		}
		return s.numbers[m]
	})
}

// minFreeTextNumber is how long a number has to be before it is replaced
// outside a URI. Shorter than this and a digit run in a GUID, a branch or a
// CSeq is as likely a match as a real number.
const minFreeTextNumber = 7

// knownNumbers compiles every mapped number into one alternation, rebuilt only
// when the mapping grows. Scanning the list per line instead costs the length
// of the whole capture times the number of distinct numbers in it, which on a
// real capture is minutes.
func (s *Sanitizer) knownNumbers() *regexp.Regexp {
	if !s.numbersDirty {
		return s.numbersRe
	}
	s.numbersDirty = false
	alts := make([]string, 0, len(s.numberOrder))
	// numberOrder is longest first, and Go's alternation prefers the earlier
	// branch, so a number that contains another still wins.
	for _, n := range s.numberOrder {
		// A number stored with its "+" is already replaced everywhere by the
		// E.164 rule, so only the bare forms need to be scanned for. On a real
		// capture that is most of the alternation gone.
		if len(n) >= minFreeTextNumber && n[0] != '+' {
			alts = append(alts, regexp.QuoteMeta(n))
		}
	}
	if len(alts) == 0 {
		s.numbersRe = nil
	} else {
		s.numbersRe = regexp.MustCompile(strings.Join(alts, "|"))
	}
	return s.numbersRe
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

// replaceFQDNs catches a domain outside a URI: a Referred-By, a realm, a
// Via host written by name.
func (s *Sanitizer) replaceFQDNs(text string) string {
	return fqdnRe.ReplaceAllStringFunc(text, func(m string) string {
		if strings.HasSuffix(m, fakeSuffix) || ipv4Re.MatchString(m) {
			return m
		}
		return s.mapHost(m)
	})
}

// mapIP allocates a fake address, keeping the public/private distinction
// because it is part of what an engineer reads off a trace. Public addresses
// come from the RFC 5737 documentation ranges.
func (s *Sanitizer) mapIP(ip string) string {
	if v, ok := s.ips[ip]; ok {
		return v
	}
	if keepAsIs(ip) {
		return ip
	}
	n := len(s.ips)
	var v string
	if strings.Contains(ip, ":") {
		// RFC 3849 reserves 2001:db8::/32 for documentation. Mapping an IPv6
		// peer to an IPv4 address would misrepresent the very thing a fixture
		// exists to show.
		v = fmt.Sprintf("2001:db8::%x", n+1)
	} else if isPrivate(ip) {
		v = fmt.Sprintf("10.%d.%d.%d", n/65024, (n/254)%256, n%254+1)
	} else {
		blocks := []string{"192.0.2", "198.51.100", "203.0.113"}
		v = fmt.Sprintf("%s.%d", blocks[(n/254)%len(blocks)], n%254+1)
	}
	s.ips[ip] = v
	return v
}

// keepAsIs names the addresses that identify nobody. Rewriting them would cost
// the reader information and buy no privacy.
func keepAsIs(ip string) bool {
	switch ip {
	case "0.0.0.0", "255.255.255.255", "::", "::1":
		return true
	}
	return strings.HasPrefix(ip, "127.")
}

func isPrivate(ip string) bool {
	p := strings.Split(ip, ".")
	if len(p) != 4 {
		return false
	}
	a, _ := strconv.Atoi(p[0])
	b, _ := strconv.Atoi(p[1])
	switch {
	case a == 10, a == 127:
		return true
	case a == 172 && b >= 16 && b <= 31:
		return true
	case a == 192 && b == 168:
		return true
	case a == 169 && b == 254:
		return true
	}
	return false
}

// mapNumber keeps a number's length and its leading "+", "*" or "#", because
// dial-plan bugs are about exactly those. Everything else becomes 9s and a
// counter, which no real range can collide with.
func (s *Sanitizer) mapNumber(num string) string {
	if num == "" {
		return num
	}
	if v, ok := s.numbers[num]; ok {
		return v
	}
	if s.fakeNumbers[num] {
		return num
	}
	prefix := ""
	digits := num
	if c := num[0]; c == '+' || c == '*' || c == '#' {
		prefix, digits = string(c), num[1:]
	}
	n := len(digits)
	idx := strconv.Itoa(len(s.numbers) + 1)
	var v string
	switch {
	case n <= len(idx):
		v = prefix + idx[len(idx)-n:]
	case n <= 2:
		v = prefix + strings.Repeat("0", n-len(idx)) + idx
	default:
		v = prefix + "99" + strings.Repeat("0", n-2-len(idx)) + idx
	}
	s.numbers[num] = v
	s.fakeNumbers[v] = true
	s.numbersDirty = true
	// Longest first, so a number that contains another is replaced before it.
	s.numberOrder = append(s.numberOrder, num)
	for i := len(s.numberOrder) - 1; i > 0 && len(s.numberOrder[i]) > len(s.numberOrder[i-1]); i-- {
		s.numberOrder[i], s.numberOrder[i-1] = s.numberOrder[i-1], s.numberOrder[i]
	}
	return v
}

func (s *Sanitizer) mapUser(u string) string {
	if v, ok := s.users[u]; ok {
		return v
	}
	v := "user" + strconv.Itoa(len(s.users)+1)
	s.users[u] = v
	return v
}

func (s *Sanitizer) mapHost(h string) string {
	if v, ok := s.hosts[h]; ok {
		return v
	}
	v := "host" + strconv.Itoa(len(s.hosts)+len(s.literals)+1)
	if strings.Contains(h, ".") {
		v += fakeSuffix
	}
	s.hosts[h] = v
	return v
}

func (s *Sanitizer) mapName(n string) string {
	if v, ok := s.names[n]; ok {
		return v
	}
	v := "Person " + strconv.Itoa(len(s.names)+1)
	s.names[n] = v
	return v
}

// replaceFunc is ReplaceAllStringFunc with the neighbouring bytes, which the
// IPv4 rule needs and Go's regexp cannot express as a lookaround.
func replaceFunc(text string, re *regexp.Regexp, fn func(m string, before, after byte) string) string {
	locs := re.FindAllStringIndex(text, -1)
	if locs == nil {
		return text
	}
	var b strings.Builder
	last := 0
	for _, loc := range locs {
		var before, after byte
		if loc[0] > 0 {
			before = text[loc[0]-1]
		}
		if loc[1] < len(text) {
			after = text[loc[1]]
		}
		b.WriteString(text[last:loc[0]])
		b.WriteString(fn(text[loc[0]:loc[1]], before, after))
		last = loc[1]
	}
	b.WriteString(text[last:])
	return b.String()
}
