package sanitize

import (
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestFixturesAreSafeToPublish walks everything under testdata/ and fails on any
// value that could be real. This repository is public and a fixture that leaks a
// customer's address or domain cannot be unpublished by a later commit, so the
// check runs on every test run rather than at review time only.
//
// Addresses must be documentation (RFC 5737, RFC 3849), private, loopback or
// unspecified; domains must be under a reserved name (RFC 2606, RFC 6761).
func TestFixturesAreSafeToPublish(t *testing.T) {
	root := filepath.Join("..", "..", "testdata")
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(b)
		rel, _ := filepath.Rel(root, path)
		seen := map[string]bool{}
		report := func(kind, v, why string) {
			if seen[v] {
				return
			}
			seen[v] = true
			t.Errorf("%s: %s %q %s — is it real?", rel, kind, v, why)
		}
		for _, ip := range findAddrs(text) {
			if !reservedAddr(ip) {
				report("address", ip, "is not from a reserved range")
			}
		}
		for _, host := range fqdnRe.FindAllString(text, -1) {
			if plausibleTLD(host) && !reservedName(host) {
				report("domain", host, "is not reserved for documentation")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// fixtureAddrRe is looser than the sanitizer's own rules on purpose: this test
// should complain about anything that even looks like an address.
var fixtureAddrRe = regexp.MustCompile(`[0-9A-Fa-f][0-9A-Fa-f.:]{6,}[0-9A-Fa-f]`)

func findAddrs(text string) []string {
	var out []string
	for _, m := range fixtureAddrRe.FindAllString(text, -1) {
		if a, err := netip.ParseAddr(m); err == nil {
			out = append(out, a.String())
		}
	}
	return out
}

func reservedAddr(s string) bool {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return false
	}
	if a.IsLoopback() || a.IsPrivate() || a.IsUnspecified() || a.IsLinkLocalUnicast() || a.IsMulticast() {
		return true
	}
	for _, p := range []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32", "100.64.0.0/10"} {
		if netip.MustParsePrefix(p).Contains(a) {
			return true
		}
	}
	return false
}

// plausibleTLD keeps the check off things that are dotted but not domains: a
// fixture filename ("voice_trace.txt") and an invented URI user part
// ("alice.fictional") both match the hostname shape.
func plausibleTLD(s string) bool {
	i := strings.LastIndex(s, ".")
	if i < 0 {
		return false
	}
	tld := strings.ToLower(s[i+1:])
	if len(tld) == 2 {
		return true // every ccTLD
	}
	switch tld {
	case "com", "net", "org", "edu", "gov", "mil", "int", "info", "biz", "name",
		"pro", "aero", "coop", "museum", "cloud", "app", "dev", "online", "site",
		"tel", "voip", "sip", "xyz", "example", "invalid", "test", "localhost", "local":
		return true
	}
	return false
}

func reservedName(s string) bool {
	s = strings.ToLower(strings.TrimSuffix(s, "."))
	for _, suf := range []string{"example.com", "example.net", "example.org", ".example", ".invalid", ".test", ".localhost", ".local"} {
		if s == strings.TrimPrefix(suf, ".") || strings.HasSuffix(s, "."+strings.TrimPrefix(suf, ".")) {
			return true
		}
	}
	return false
}
