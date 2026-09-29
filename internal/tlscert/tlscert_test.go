package tlscert

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/phuongnz/cube-logger/internal/listen"
)

// Names from the documentation ranges and a reserved domain: nothing here
// should look like a real network.
var (
	t0    = time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	names = []string{"192.0.2.10", "2001:db8::5", "logger.example", "127.0.0.1", "::1"}
)

func ensure(t *testing.T, dir string, names []string, now time.Time) *Set {
	t.Helper()
	s, err := Ensure(dir, names, now)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func read(t *testing.T, dir, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func write(t *testing.T, dir, name string, b []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureMakesEverythingOnFirstRun(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	s := ensure(t, dir, names, t0)

	if !s.CreatedCA || s.Reissued == "" {
		t.Errorf("CreatedCA=%v Reissued=%q, want a new CA and a new server certificate", s.CreatedCA, s.Reissued)
	}
	var files []string
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		files = append(files, e.Name())
	}
	// Nothing else: a temporary file left behind would be a copy of a key.
	if want := []string{CAFile, caKeyFile, keyFile, certFile}; !slices.Equal(sorted(files), sorted(want)) {
		t.Errorf("directory holds %v, want %v", files, want)
	}
	if runtime.GOOS != "windows" {
		for name, want := range map[string]os.FileMode{caKeyFile: keyPerm, keyFile: keyPerm, CAFile: certPerm, certFile: certPerm} {
			fi, err := os.Stat(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			if got := fi.Mode().Perm(); got != want {
				t.Errorf("%s has mode %v, want %v", name, got, want)
			}
		}
		fi, _ := os.Stat(dir)
		if got := fi.Mode().Perm(); got != dirPerm {
			t.Errorf("directory has mode %v, want %v", got, dirPerm)
		}
	}

	if !s.CA.IsCA || !s.CA.MaxPathLenZero || s.CA.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Errorf("CA: IsCA=%v MaxPathLenZero=%v KeyUsage=%v", s.CA.IsCA, s.CA.MaxPathLenZero, s.CA.KeyUsage)
	}
	if !bytes.Equal(s.CAPEM, read(t, dir, CAFile)) {
		t.Error("CAPEM is not what ca.pem holds")
	}
	leaf := s.Server.Leaf
	if leaf.Subject.CommonName != names[0] {
		t.Errorf("common name %q, want the first name %q", leaf.Subject.CommonName, names[0])
	}
	if !slices.Equal(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) {
		t.Errorf("extended key usage %v, want server auth", leaf.ExtKeyUsage)
	}
	// Addresses first, then host names, as a certificate lists them.
	if got, want := s.Names(), []string{"192.0.2.10", "2001:db8::5", "127.0.0.1", "::1", "logger.example"}; !slices.Equal(got, want) {
		t.Errorf("Names() = %v, want %v", got, want)
	}
	// A router with a slow clock must still accept both.
	for _, c := range []*x509.Certificate{s.CA, leaf} {
		if !c.NotBefore.Before(t0.Add(-time.Hour)) {
			t.Errorf("%s is valid from %v, which a router a little behind would reject", c.Subject.CommonName, c.NotBefore)
		}
	}
	if got := leaf.NotAfter.Sub(t0); got != serverValidity {
		t.Errorf("server certificate lasts %v, want %v", got, serverValidity)
	}
}

// The point of the package: a router that trusts only ca.pem, and speaks only
// the one suite the README tells it to, reaches the listener by any of the
// names.
func TestRouterTrustingTheCAConnects(t *testing.T) {
	dir := t.TempDir()
	s := ensure(t, dir, names, time.Now())
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(read(t, dir, CAFile)) {
		t.Fatal("ca.pem does not parse")
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			cs, err := handshake(listen.ServerConfig(s.Server, nil), &tls.Config{
				RootCAs:    roots,
				ServerName: name,
				MaxVersion: tls.VersionTLS12,
				// "ciphersuite ecdhe-rsa-aes-gcm-sha2" in the logging tls-profile.
				CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
			})
			if err != nil {
				t.Fatal(err)
			}
			if cs.CipherSuite != tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 {
				t.Errorf("negotiated %s", tls.CipherSuiteName(cs.CipherSuite))
			}
		})
	}
	t.Run("a name it was not issued for", func(t *testing.T) {
		_, err := handshake(listen.ServerConfig(s.Server, nil), &tls.Config{RootCAs: roots, ServerName: "198.51.100.99"})
		if err == nil {
			t.Error("connected to an address the certificate does not name")
		}
	})
}

func handshake(server, client *tls.Config) (tls.ConnectionState, error) {
	sc, cc := net.Pipe()
	defer sc.Close()
	defer cc.Close()
	done := make(chan error, 1)
	go func() {
		srv := tls.Server(sc, server)
		done <- srv.Handshake()
		srv.Close()
	}()
	c := tls.Client(cc, client)
	err := c.Handshake()
	cc.Close()
	<-done
	return c.ConnectionState(), err
}

func TestEnsureKeepsWhatStillFits(t *testing.T) {
	dir := t.TempDir()
	first := ensure(t, dir, names, t0)
	ca, cert, key := read(t, dir, CAFile), read(t, dir, certFile), read(t, dir, keyFile)

	// A later run, fewer names (an interface went down): nothing changes.
	s := ensure(t, dir, names[:2], t0.Add(30*24*time.Hour))
	if s.CreatedCA || s.Reissued != "" {
		t.Errorf("CreatedCA=%v Reissued=%q, want everything kept", s.CreatedCA, s.Reissued)
	}
	if !bytes.Equal(ca, read(t, dir, CAFile)) || !bytes.Equal(cert, read(t, dir, certFile)) || !bytes.Equal(key, read(t, dir, keyFile)) {
		t.Error("a file was rewritten although nothing needed to change")
	}
	if !bytes.Equal(s.Server.Leaf.Raw, first.Server.Leaf.Raw) {
		t.Error("the certificate served is not the one on disk")
	}
}

func TestEnsureReissuesAndKeepsTheCA(t *testing.T) {
	later := t0.Add(24 * time.Hour)
	tests := []struct {
		name   string
		names  []string
		now    time.Time
		before func(t *testing.T, dir string)
		want   string
	}{
		{name: "a new name", names: append(slices.Clone(names), "203.0.113.7"), now: later,
			want: "it did not name 203.0.113.7"},
		{name: "a different first name", names: []string{"logger.example", "192.0.2.10"}, now: later,
			want: "its common name was 192.0.2.10, not logger.example"},
		{name: "close to expiry", names: names, now: t0.Add(serverValidity - renewBefore + time.Hour),
			want: "it expires on 2028-09-23"},
		{name: "certificate deleted", names: names, now: later,
			before: func(t *testing.T, dir string) { os.Remove(filepath.Join(dir, certFile)) },
			want:   "there was none"},
		{name: "certificate unreadable", names: names, now: later,
			before: func(t *testing.T, dir string) { write(t, dir, certFile, []byte("not a certificate")) },
			want:   "there was none"},
		{name: "key unreadable", names: names, now: later,
			before: func(t *testing.T, dir string) { write(t, dir, keyFile, []byte("not a key")) },
			want:   "the one on disk does not match its key"},
		{name: "issued by another CA", names: names, now: later,
			before: func(t *testing.T, dir string) {
				other := t.TempDir()
				ensure(t, other, names, t0)
				write(t, dir, certFile, read(t, other, certFile))
				write(t, dir, keyFile, read(t, other, keyFile))
			},
			want: "the one on disk was not issued by ca.pem"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			ensure(t, dir, names, t0)
			ca, caKey := read(t, dir, CAFile), read(t, dir, caKeyFile)
			if tt.before != nil {
				tt.before(t, dir)
			}
			s := ensure(t, dir, tt.names, tt.now)
			if s.Reissued != tt.want {
				t.Errorf("Reissued = %q, want %q", s.Reissued, tt.want)
			}
			if s.CreatedCA || !bytes.Equal(ca, read(t, dir, CAFile)) || !bytes.Equal(caKey, read(t, dir, caKeyFile)) {
				t.Fatal("the CA changed: every router would have to import it again")
			}
			if !bytes.Equal(s.Server.Leaf.Raw, pemDER(t, read(t, dir, certFile))) {
				t.Error("the new certificate was not written to disk")
			}
			if err := s.Server.Leaf.CheckSignatureFrom(s.CA); err != nil {
				t.Errorf("the new certificate is not signed by the CA: %v", err)
			}
			for _, n := range tt.names {
				if err := s.Server.Leaf.VerifyHostname(n); err != nil {
					t.Error(err)
				}
			}
			// And the pair is usable, which also checks key and certificate match.
			if _, err := tls.X509KeyPair(read(t, dir, certFile), read(t, dir, keyFile)); err != nil {
				t.Errorf("server.pem and server-key.pem do not go together: %v", err)
			}
			if again := ensure(t, dir, tt.names, tt.now); again.Reissued != "" {
				t.Errorf("reissued again on the next run: %s", again.Reissued)
			}
		})
	}
}

func TestReissueKeepsAGoodKey(t *testing.T) {
	dir := t.TempDir()
	ensure(t, dir, names, t0)
	key := read(t, dir, keyFile)
	ensure(t, dir, []string{"203.0.113.7"}, t0)
	if !bytes.Equal(key, read(t, dir, keyFile)) {
		t.Error("a reissue for a new name replaced a sound key")
	}
}

func TestServerCertificateNeverOutlivesTheCA(t *testing.T) {
	dir := t.TempDir()
	first := ensure(t, dir, names, t0)
	now := first.CA.NotAfter.Add(-100 * 24 * time.Hour)
	s := ensure(t, dir, names, now)
	if !s.Server.Leaf.NotAfter.Equal(s.CA.NotAfter) {
		t.Errorf("server certificate ends %v, CA ends %v", s.Server.Leaf.NotAfter, s.CA.NotAfter)
	}
}

// Anything wrong with an authority that exists is reported, and the files are
// left exactly as they were: replacing it would silently break every router
// that trusts it.
func TestEnsureNeverReplacesACA(t *testing.T) {
	tests := []struct {
		name   string
		now    time.Time
		before func(t *testing.T, dir string)
		want   string
	}{
		{name: "key missing", before: func(t *testing.T, dir string) { os.Remove(filepath.Join(dir, caKeyFile)) },
			want: "ca-key.pem is missing"},
		{name: "key unreadable", before: func(t *testing.T, dir string) { write(t, dir, caKeyFile, []byte("not a key")) },
			want: "no PEM private key"},
		{name: "key belongs to something else", before: func(t *testing.T, dir string) {
			write(t, dir, caKeyFile, read(t, dir, keyFile))
		}, want: "is not the key of"},
		{name: "certificate unreadable", before: func(t *testing.T, dir string) { write(t, dir, CAFile, []byte("not a certificate")) },
			want: "no PEM certificate"},
		{name: "certificate is not a CA", before: func(t *testing.T, dir string) { write(t, dir, CAFile, read(t, dir, certFile)) },
			want: "is not a certificate authority"},
		{name: "expired", now: t0.Add(caValidity + time.Hour), want: "expired on 2036-09-21"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			ensure(t, dir, names, t0)
			if tt.before != nil {
				tt.before(t, dir)
			}
			snapshot := map[string][]byte{}
			entries, _ := os.ReadDir(dir)
			for _, e := range entries {
				snapshot[e.Name()] = read(t, dir, e.Name())
			}
			now := tt.now
			if now.IsZero() {
				now = t0.Add(time.Hour)
			}
			_, err := Ensure(dir, names, now)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error %v, want one containing %q", err, tt.want)
			}
			if !strings.Contains(err.Error(), "router") {
				t.Errorf("error %q does not say what it means for the routers", err)
			}
			entries, _ = os.ReadDir(dir)
			if len(entries) != len(snapshot) {
				t.Errorf("%d files after, %d before", len(entries), len(snapshot))
			}
			for name, b := range snapshot {
				if !bytes.Equal(b, read(t, dir, name)) {
					t.Errorf("%s was changed", name)
				}
			}
		})
	}
}

// A key without a certificate is what a crash between the two writes leaves.
// Nothing can have trusted it, so it is replaced.
func TestEnsureReplacesAStrayCAKey(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, caKeyFile, []byte("left over"))
	s := ensure(t, dir, names, t0)
	if !s.CreatedCA {
		t.Error("no CA made")
	}
	if _, err := readKey(filepath.Join(dir, caKeyFile)); err != nil {
		t.Errorf("ca-key.pem: %v", err)
	}
}

func TestEnsureRefusesBadNames(t *testing.T) {
	for _, ns := range [][]string{nil, {"has space"}, {"192.0.2.10", "under_score.example"}, {"-lead.example"}} {
		if _, err := Ensure(t.TempDir(), ns, t0); err == nil {
			t.Errorf("Ensure accepted %q", ns)
		}
	}
}

func TestOrderNames(t *testing.T) {
	addrs := []netip.Addr{
		netip.MustParseAddr("2001:db8::5"),
		netip.MustParseAddr("192.0.2.20"),
		netip.MustParseAddr("127.0.0.1"),
		netip.MustParseAddr("fe80::1"),
		netip.MustParseAddr("198.51.100.7"),
		netip.MustParseAddr("192.0.2.3"),
		netip.MustParseAddr("::ffff:203.0.113.9"),
		netip.MustParseAddr("224.0.0.1"),
		netip.MustParseAddr("192.0.2.3"), // on two interfaces
		netip.MustParseAddr("::1"),
	}
	want := []string{"192.0.2.3", "192.0.2.20", "198.51.100.7", "203.0.113.9", "2001:db8::5", "logger", "127.0.0.1", "::1"}
	if got := orderNames(addrs, "logger"); !slices.Equal(got, want) {
		t.Errorf("got  %v\nwant %v", got, want)
	}
	// A computer name DNS cannot carry is left out rather than failing.
	if got := orderNames(nil, "Jo's PC"); !slices.Equal(got, []string{"127.0.0.1", "::1"}) {
		t.Errorf("got %v", got)
	}
}

func TestLocalNamesAreAllUsable(t *testing.T) {
	got := LocalNames()
	if len(got) < 2 || got[len(got)-2] != "127.0.0.1" || got[len(got)-1] != "::1" {
		t.Errorf("LocalNames() = %v, want loopback last", got)
	}
	if _, err := Ensure(t.TempDir(), got, t0); err != nil {
		t.Errorf("this machine's own names were refused: %v", err)
	}
}

func TestMerge(t *testing.T) {
	got := Merge([]string{"203.0.113.5", "logger.example"}, []string{"192.0.2.3", "203.0.113.5", "127.0.0.1"})
	want := []string{"203.0.113.5", "logger.example", "192.0.2.3", "127.0.0.1"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestIsDNSName(t *testing.T) {
	for s, want := range map[string]bool{
		"logger": true, "logger.example": true, "a-b.c-d.example": true, "X1": true,
		"": false, "has space": false, "under_score": false, ".lead": false, "trail.": false,
		"a..b": false, "-a": false, "a-": false, "héllo": false, strings.Repeat("a", 64): false,
	} {
		if got := isDNSName(s); got != want {
			t.Errorf("isDNSName(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestFingerprints(t *testing.T) {
	s := ensure(t, t.TempDir(), names, t0)
	m, h := Fingerprints(s.CA)
	if !regexp.MustCompile(`^([0-9A-F]{8} ){3}[0-9A-F]{8}$`).MatchString(m) {
		t.Errorf("MD5 %q is not in the form IOS shows", m)
	}
	if !regexp.MustCompile(`^([0-9A-F]{8} ){4}[0-9A-F]{8}$`).MatchString(h) {
		t.Errorf("SHA1 %q is not in the form IOS shows", h)
	}
	if want := strings.ToUpper(fmt.Sprintf("%x", md5.Sum(s.CA.Raw))); strings.ReplaceAll(m, " ", "") != want {
		t.Errorf("MD5 %s, want %s", m, want)
	}
	if want := strings.ToUpper(fmt.Sprintf("%x", sha1.Sum(s.CA.Raw))); strings.ReplaceAll(h, " ", "") != want {
		t.Errorf("SHA1 %s, want %s", h, want)
	}
}

func TestLoadPool(t *testing.T) {
	dir := t.TempDir()
	s := ensure(t, dir, names, t0)
	pool, err := LoadPool(filepath.Join(dir, CAFile))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Server.Leaf.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: t0}); err != nil {
		t.Errorf("the pool does not hold the CA: %v", err)
	}
	if _, err := LoadPool(filepath.Join(dir, keyFile)); err == nil || !strings.Contains(err.Error(), "no PEM certificate") {
		t.Errorf("a key file loaded as a pool: %v", err)
	}
	if _, err := LoadPool(filepath.Join(dir, "missing.pem")); err == nil {
		t.Error("a missing file loaded as a pool")
	}
}

func TestDefaultDir(t *testing.T) {
	d, err := DefaultDir()
	if err != nil {
		t.Skip(err)
	}
	if !strings.HasSuffix(d, filepath.Join("cube-logger", "tls")) {
		t.Errorf("DefaultDir() = %s", d)
	}
}

func pemDER(t *testing.T, b []byte) []byte {
	t.Helper()
	c, err := parseCert(b)
	if err != nil {
		t.Fatal(err)
	}
	return c.Raw
}

func sorted(s []string) []string {
	s = slices.Clone(s)
	slices.Sort(s)
	return s
}
