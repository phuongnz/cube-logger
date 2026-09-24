package sanitize

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/phuongnz/cube-logger/internal/testutil"
)

const (
	inputPath  = "../../testdata/sanitize/input.txt"
	goldenPath = "../../testdata/sanitize/expected.txt"
)

// run sanitizes the fixture with a fresh Sanitizer and returns the output.
func run(t *testing.T) (string, Stats) {
	t.Helper()
	in, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	s := New()
	if err := s.Reader(bytes.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	return out.String(), s.Stats()
}

func TestGoldenSanitized(t *testing.T) {
	got, _ := run(t)
	testutil.Golden(t, goldenPath, []byte(got))
}

// TestNothingSensitiveSurvives is the check that matters: the fixture's
// invented-but-realistic values must not appear in the output at all. A rule
// that stops matching shows up here rather than in a public commit.
func TestNothingSensitiveSurvives(t *testing.T) {
	got, _ := run(t)
	forbidden := []string{
		// addresses
		"203.0.113.17", "198.51.100.9", "10.20.30.40", "2001:db8:dead:beef::17",
		// numbers
		"441632960123", "441632960999",
		// URI user parts and display names
		"alice.fictional", "Alice Fictional", "trunk-svc",
		// hostnames and domains
		"pbx.corp.example.com", "voice.corp.example.com", "corp.example.com",
		"sbc.carrier.example.org", "carrier.example.org", "cube-edge-01",
		// credentials
		"deadbeefcafe", "0123456789abcdef", "fedcba9876543210",
	}
	for _, f := range forbidden {
		if strings.Contains(got, f) {
			t.Errorf("sanitized output still contains %q", f)
		}
	}
}

// TestCredentialsAreRemovedNotMapped: an Authorization value must be gone, not
// replaced by something reversible. The header name stays so the parser still
// sees the message shape.
func TestCredentialsAreRemovedNotMapped(t *testing.T) {
	got, stats := run(t)
	for _, h := range []string{"Authorization:", "Proxy-Authorization:"} {
		var line string
		for _, l := range strings.Split(got, "\n") {
			if strings.HasPrefix(l, h) {
				line = l
				break
			}
		}
		if line == "" {
			t.Fatalf("%s header disappeared entirely; it should stay with its value removed", h)
		}
		if strings.Contains(line, "Digest") || strings.Contains(line, "username") {
			t.Errorf("%s still carries a credential: %q", h, line)
		}
	}
	if stats.Redactions != 2 {
		t.Errorf("Redactions = %d, want 2", stats.Redactions)
	}
}

// TestConsistentWithinAFile is what lets a sanitized capture still correlate:
// one real address always becomes the same fake one, and two real addresses
// never collapse into one.
func TestConsistentWithinAFile(t *testing.T) {
	s := New()
	first := s.Line("Via: SIP/2.0/UDP 203.0.113.17:5060")
	second := s.Line("Contact: <sip:x@203.0.113.17:5060>")
	other := s.Line("Peer: 203.0.113.18")

	a := between(t, first, "UDP ", ":5060")
	b := between(t, second, "@", ":5060")
	if a != b {
		t.Errorf("the same address mapped to %q and then %q", a, b)
	}
	if strings.Contains(other, a) {
		t.Errorf("two different addresses both mapped to %q", a)
	}
}

// TestIECCodesSurvive: an IEC code is dotted decimal but it is not an address,
// and it is the only machine-readable reason a call failed. Losing it would
// make sanitized fixtures useless for the error paths.
func TestIECCodesSurvive(t *testing.T) {
	got, _ := run(t)
	if !strings.Contains(got, "IEC=1.1.180.1.29.0") {
		t.Error("IEC code was rewritten; the IPv4 rule is too greedy")
	}
	if !strings.Contains(got, "127.0.0.1") {
		t.Error("127.0.0.1 was rewritten; the loopback is not customer data")
	}
}

// TestNumericHeadersSurvive: Content-Length and friends are numbers the parser
// depends on. Rewriting one would break reassembly of the very fixture being
// produced.
func TestNumericHeadersSurvive(t *testing.T) {
	got, _ := run(t)
	for _, h := range []string{"Content-Length: 134", "Content-Length: 0", "Max-Forwards: 70", "Expires: 300", "CSeq: 101 INVITE"} {
		if !strings.Contains(got, h) {
			t.Errorf("%q did not survive sanitizing", h)
		}
	}
}

// TestStructureIsPreserved: sanitizing must not add, drop or reorder lines, and
// must not disturb the syslog frame — the output is meant to be parseable.
func TestStructureIsPreserved(t *testing.T) {
	in, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := run(t)
	if a, b := strings.Count(string(in), "\n"), strings.Count(got, "\n"); a != b {
		t.Errorf("line count changed: %d in, %d out", a, b)
	}
	if !strings.Contains(got, "123456: Sep 24 09:14:02.113: //2540661/A1B2C3D4E5F6/SIP/Msg/ccsipDisplayMsg:") {
		t.Error("the syslog frame or debug header was rewritten")
	}
}

// TestLineEndingsArePreserved: the parser has to cope with a CRLF buffer dump,
// so the sanitizer must be able to hand it one.
func TestLineEndingsArePreserved(t *testing.T) {
	var out bytes.Buffer
	in := "Via: SIP/2.0/UDP 203.0.113.17\r\nTo: <sip:a@b.example.com>\r\n"
	if err := New().Reader(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(out.String(), "\r\n"); n != 2 {
		t.Errorf("got %d CRLF endings, want 2: %q", n, out.String())
	}
}

// TestDeterministic: two fresh runs over the same input must agree byte for
// byte, or the golden file would churn and a diff would stop meaning anything.
func TestDeterministic(t *testing.T) {
	a, _ := run(t)
	b, _ := run(t)
	if a != b {
		t.Error("two runs over the same input produced different output")
	}
}

// TestLiteral covers the escape hatch for anything the patterns cannot know is
// sensitive, such as a customer name.
func TestLiteral(t *testing.T) {
	s := New()
	s.AddLiteral("Widgets Ltd")
	got := s.Line("//-1/xxxxxxxxxxxx/SIP/Info: trunk for Widgets Ltd is up")
	if strings.Contains(got, "Widgets Ltd") {
		t.Errorf("registered literal was not replaced: %q", got)
	}
}

func between(t *testing.T, s, pre, post string) string {
	t.Helper()
	_, rest, ok := strings.Cut(s, pre)
	if !ok {
		t.Fatalf("%q not found in %q", pre, s)
	}
	mid, _, ok := strings.Cut(rest, post)
	if !ok {
		t.Fatalf("%q not found in %q", post, s)
	}
	return mid
}

// TestFakeNumbersAreNotRemapped guards a bug worth naming: several rules see
// each line in turn, so a number the URI rule had already replaced was being
// replaced a second time by the loose-number rule. The same real number then
// came out differently depending on whether it sat in a URI, which silently
// destroys correlation in the fixture.
func TestFakeNumbersAreNotRemapped(t *testing.T) {
	s := New()
	inURI := between(t, s.Line("To: <sip:+441632960123@pbx.example.com>"), "sip:", "@")
	plain := strings.TrimPrefix(s.Line("dst +441632960123"), "dst ")
	if inURI != plain {
		t.Errorf("the same number became %q in a URI and %q in free text", inURI, plain)
	}
}

// TestBareSchemeInProseIsNotAURI: a %VOICE_IEC line starts its text with
// "SIP:", which is not a URI and has no host to map.
func TestBareSchemeInProseIsNotAURI(t *testing.T) {
	s := New()
	got := s.Line("123: Sep 24 09:14:03.001: %VOICE_IEC-3-GW: SIP: Internal Error (Received 503): IEC=1.1.180.1.29.0")
	if !strings.Contains(got, "%VOICE_IEC-3-GW: SIP: Internal Error") {
		t.Errorf("a bare scheme was treated as a URI: %q", got)
	}
}

// TestIPv6IsReplaced: a Cover Buffer states a peer address without brackets,
// where it looks like a timestamp. It still has to be replaced.
func TestIPv6IsReplaced(t *testing.T) {
	s := New()
	got := s.Line("  Peer-Address   = 2001:db8:dead:beef::17")
	if strings.Contains(got, "dead:beef") {
		t.Errorf("bare IPv6 address survived: %q", got)
	}
	if kept := s.Line("123456: Sep 24 09:14:02.113: nothing here"); !strings.Contains(kept, "09:14:02.113") {
		t.Errorf("a timestamp was mistaken for an IPv6 address: %q", kept)
	}
}
