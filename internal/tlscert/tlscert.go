// Package tlscert makes and keeps the certificates syslog over TLS needs, so
// that an engineer does not need a PKI to receive a CUBE's logs securely.
//
// It keeps two things in one directory: a small certificate authority, and a
// server certificate that authority issued for this machine. A router is told
// to trust the authority once, with "crypto pki authenticate". After that the
// server certificate can be remade whenever this machine's addresses change —
// a laptop on a new network, a name added for a port forward — and no router
// has to be touched again.
//
// That makes the authority the one thing that must never change behind the
// engineer's back. It is created when there is none, and otherwise loaded or
// refused: a CA that is unreadable, or whose key is missing, is an error that
// says so, never a quiet replacement that every router would then reject.
package tlscert

import (
	"crypto"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// The files in a certificate directory. The keys are readable by their owner
// only; on Windows that is what the per-user profile directory already gives.
const (
	CAFile     = "ca.pem"
	caKeyFile  = "ca-key.pem"
	certFile   = "server.pem"
	keyFile    = "server-key.pem"
	keyPerm    = 0o600
	certPerm   = 0o644
	dirPerm    = 0o700
	keyBits    = 2048
	caOrg      = "cube-logger"
	caValidity = 10 * 365 * 24 * time.Hour

	// serverValidity is short next to the authority's because remaking the
	// server certificate costs nothing: routers trust the authority.
	serverValidity = 2 * 365 * 24 * time.Hour

	// renewBefore is how close to expiry a server certificate is remade. A
	// router that is sent an expired certificate stops logging without a word
	// on this side, so it is never left that close.
	renewBefore = 30 * 24 * time.Hour

	// backdate is how far before now a certificate becomes valid. Routers are
	// often a little wrong about the time, and one that thinks it is earlier
	// than a certificate's start rejects it.
	backdate = 24 * time.Hour
)

// DefaultDir is where certificates are kept when no directory is given: the
// user's configuration directory, so that one authority serves every session
// and a router imports it once.
func DefaultDir() (string, error) {
	d, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("no directory for certificates (use -tls-dir): %w", err)
	}
	return filepath.Join(d, "cube-logger", "tls"), nil
}

// Set is a loaded certificate directory.
type Set struct {
	Dir string

	// CA is the authority a router has to trust, and CAPEM is what is pasted
	// into "crypto pki authenticate".
	CA    *x509.Certificate
	CAPEM []byte

	// Server is what the listener presents. Its Leaf is set.
	Server tls.Certificate

	// CreatedCA is true when this call made the authority: until a router
	// imports it, that router will refuse to send.
	CreatedCA bool

	// Reissued says why this call made a new server certificate, and is empty
	// when the one on disk was kept.
	Reissued string
}

// Names are the addresses and host names the server certificate is for.
func (s *Set) Names() []string {
	leaf := s.Server.Leaf
	names := make([]string, 0, len(leaf.IPAddresses)+len(leaf.DNSNames))
	for _, ip := range leaf.IPAddresses {
		names = append(names, ip.String())
	}
	return append(names, leaf.DNSNames...)
}

// Ensure loads the certificates in dir, making whatever is missing.
//
// names are the addresses and host names a router may use to reach this
// machine; the first becomes the certificate's common name, for a router that
// looks there rather than at the alternative names. A server certificate that
// does not cover all of them, expires within renewBefore, or was not issued by
// the authority is remade.
func Ensure(dir string, names []string, now time.Time) (*Set, error) {
	if len(names) == 0 {
		return nil, errors.New("a server certificate needs at least one name")
	}
	for _, n := range names {
		if _, err := netip.ParseAddr(n); err != nil && !isDNSName(n) {
			return nil, fmt.Errorf("%q is neither an IP address nor a host name", n)
		}
	}
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return nil, err
	}
	s := &Set{Dir: dir}
	caKey, err := s.loadCA(now)
	if err != nil {
		return nil, err
	}
	if err := s.loadServer(caKey, names, now); err != nil {
		return nil, err
	}
	return s, nil
}

// loadCA loads the authority, or makes one when there is no ca.pem. A stray
// key without a certificate is overwritten: nothing can have trusted it.
func (s *Set) loadCA(now time.Time) (crypto.Signer, error) {
	certPath := filepath.Join(s.Dir, CAFile)
	keyPath := filepath.Join(s.Dir, caKeyFile)
	pemBytes, err := os.ReadFile(certPath)
	if errors.Is(err, fs.ErrNotExist) {
		return s.createCA(now)
	}
	if err != nil {
		return nil, err
	}

	// From here on there is an authority that routers may already trust, so
	// every problem is reported instead of repaired.
	keep := fmt.Sprintf("routers may already trust it: fix or restore it, or move %s away to start over and import the new one on every router", s.Dir)
	ca, err := parseCert(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w; %s", certPath, err, keep)
	}
	if !ca.IsCA {
		return nil, fmt.Errorf("%s is not a certificate authority; %s", certPath, keep)
	}
	if now.After(ca.NotAfter) {
		return nil, fmt.Errorf("the certificate authority in %s expired on %s; move the directory away to make a new one, and import that on every router",
			s.Dir, ca.NotAfter.Format(time.DateOnly))
	}
	key, err := readKey(keyPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s is missing, so %s cannot issue a server certificate; %s", keyPath, CAFile, keep)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w; %s", keyPath, err, keep)
	}
	if !samePublicKey(ca.PublicKey, key) {
		return nil, fmt.Errorf("%s is not the key of %s; %s", keyPath, certPath, keep)
	}
	s.CA, s.CAPEM = ca, pemBytes
	return key, nil
}

func (s *Set) createCA(now time.Time) (crypto.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return nil, err
	}
	serial, err := serialNumber()
	if err != nil {
		return nil, err
	}
	// The host name tells two authorities apart on a router that trusts the
	// cube-logger of more than one machine.
	cn := "cube-logger CA"
	if h, err := os.Hostname(); err == nil && isDNSName(h) {
		cn += " " + h
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{caOrg}},
		NotBefore:             now.Add(-backdate),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		// It issues server certificates, never another authority.
		MaxPathLenZero: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	// The key is written first. A crash between the two writes leaves a key
	// and no certificate, which the next run replaces; the other order would
	// leave an authority nothing can issue from.
	if err := writeFile(filepath.Join(s.Dir, caKeyFile), keyPEM(key), keyPerm); err != nil {
		return nil, err
	}
	pemBytes := certPEM(der)
	if err := writeFile(filepath.Join(s.Dir, CAFile), pemBytes, certPerm); err != nil {
		return nil, err
	}
	s.CA, s.CAPEM, s.CreatedCA = ca, pemBytes, true
	return key, nil
}

// loadServer keeps the server certificate on disk when it still fits, and
// otherwise issues a new one — with the same key when that key is sound, so
// that a reissue changes as little as possible.
func (s *Set) loadServer(caKey crypto.Signer, names []string, now time.Time) error {
	certPath := filepath.Join(s.Dir, certFile)
	keyPath := filepath.Join(s.Dir, keyFile)

	key, err := readKey(keyPath)
	rsaKey, isRSA := key.(*rsa.PrivateKey)
	if err != nil || !isRSA {
		// The server key is disposable: the router never sees it, only the
		// authority's signature on the certificate that goes with it.
		if rsaKey, err = rsa.GenerateKey(rand.Reader, keyBits); err != nil {
			return err
		}
		if err := writeFile(keyPath, keyPEM(rsaKey), keyPerm); err != nil {
			return err
		}
	}

	var leaf *x509.Certificate
	pemBytes, err := os.ReadFile(certPath)
	if err == nil {
		leaf, _ = parseCert(pemBytes)
	}
	why := reissueReason(leaf, s.CA, rsaKey, names, now)
	if why != "" {
		der, err := issue(s.CA, caKey, rsaKey, names, now)
		if err != nil {
			return err
		}
		if leaf, err = x509.ParseCertificate(der); err != nil {
			return err
		}
		if err := writeFile(certPath, certPEM(der), certPerm); err != nil {
			return err
		}
		s.Reissued = why
	}
	s.Server = tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: rsaKey, Leaf: leaf}
	return nil
}

// reissueReason says why leaf will not do, or "" when it will.
func reissueReason(leaf, ca *x509.Certificate, key *rsa.PrivateKey, names []string, now time.Time) string {
	switch {
	case leaf == nil:
		return "there was none"
	case leaf.CheckSignatureFrom(ca) != nil:
		return "the one on disk was not issued by " + CAFile
	case !samePublicKey(leaf.PublicKey, key):
		return "the one on disk does not match its key"
	case leaf.Subject.CommonName != names[0]:
		return fmt.Sprintf("its common name was %s, not %s", leaf.Subject.CommonName, names[0])
	case leaf.NotAfter.Sub(now) < renewBefore:
		return "it expires on " + leaf.NotAfter.Format(time.DateOnly)
	}
	for _, n := range names {
		if leaf.VerifyHostname(n) != nil {
			return "it did not name " + n
		}
	}
	return ""
}

func issue(ca *x509.Certificate, caKey crypto.Signer, key *rsa.PrivateKey, names []string, now time.Time) ([]byte, error) {
	serial, err := serialNumber()
	if err != nil {
		return nil, err
	}
	notAfter := now.Add(serverValidity)
	if notAfter.After(ca.NotAfter) {
		notAfter = ca.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: names[0], Organization: []string{caOrg}},
		NotBefore:    now.Add(-backdate),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, n := range names {
		if ip, err := netip.ParseAddr(n); err == nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, net.IP(ip.AsSlice()))
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	return x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
}

// LocalNames are the names a router could use for this machine, in the order
// that makes the first one the best guess for a common name: private and
// public IPv4 addresses, then IPv6, then the host name, then loopback — which
// is last because no router uses it, and there at all so that "cube-logger
// replay -tls" works against a listener on the same machine.
func LocalNames() []string {
	var addrs []netip.Addr
	if ifaces, err := net.Interfaces(); err == nil {
		for _, ifc := range ifaces {
			if ifc.Flags&net.FlagUp == 0 {
				continue
			}
			as, err := ifc.Addrs()
			if err != nil {
				continue
			}
			for _, a := range as {
				if p, err := netip.ParsePrefix(a.String()); err == nil {
					addrs = append(addrs, p.Addr())
				}
			}
		}
	}
	host, _ := os.Hostname()
	return orderNames(addrs, host)
}

func orderNames(addrs []netip.Addr, host string) []string {
	var v4, v6 []netip.Addr
	for _, a := range addrs {
		a = a.Unmap().WithZone("")
		switch {
		case a.IsLoopback(), a.IsLinkLocalUnicast(), a.IsMulticast(), a.IsUnspecified():
			// A link-local address needs a zone a certificate cannot carry.
		case a.Is4():
			v4 = append(v4, a)
		default:
			v6 = append(v6, a)
		}
	}
	slices.SortFunc(v4, netip.Addr.Compare)
	slices.SortFunc(v6, netip.Addr.Compare)
	var names []string
	for _, a := range slices.Concat(v4, v6) {
		names = append(names, a.String())
	}
	if isDNSName(host) {
		names = append(names, host)
	}
	names = append(names, "127.0.0.1", "::1")
	return slices.Compact(names)
}

// Merge puts the names asked for first, in the order given, and appends the
// rest without repeating any.
func Merge(first, rest []string) []string {
	var out []string
	for _, n := range slices.Concat(first, rest) {
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out
}

// isDNSName is a name a certificate can carry and a router could resolve:
// ASCII letters, digits, hyphens and dots, which rules out whatever a desktop
// operating system allows in a computer name and DNS does not.
func isDNSName(s string) bool {
	if s == "" || len(s) > 253 || strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// Fingerprints are c's MD5 and SHA-1 digests, written the way "crypto pki
// authenticate" shows them, so they can be compared by eye before the router
// is told to trust the certificate.
func Fingerprints(c *x509.Certificate) (md5sum, sha1sum string) {
	m := md5.Sum(c.Raw)
	s := sha1.Sum(c.Raw)
	return grouped(m[:]), grouped(s[:])
}

func grouped(b []byte) string {
	h := strings.ToUpper(fmt.Sprintf("%x", b))
	var groups []string
	for len(h) > 8 {
		groups = append(groups, h[:8])
		h = h[8:]
	}
	return strings.Join(append(groups, h), " ")
}

// LoadPool reads PEM certificates from file, for trusting the routers whose
// certificates they issued.
func LoadPool(file string) (*x509.CertPool, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("%s: no PEM certificate in it", file)
	}
	return pool, nil
}

func parseCert(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("no PEM certificate in it")
	}
	return x509.ParseCertificate(block.Bytes)
}

func readKey(path string) (crypto.Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("no PEM private key in it")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	signer, ok := k.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("a %T cannot sign", k)
	}
	return signer, nil
}

func samePublicKey(pub crypto.PublicKey, key crypto.Signer) bool {
	k, ok := key.Public().(interface{ Equal(crypto.PublicKey) bool })
	return ok && k.Equal(pub)
}

func serialNumber() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

func certPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func keyPEM(key *rsa.PrivateKey) []byte {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		// An RSA key this package generated always marshals.
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// writeFile replaces path in one step, so that a crash or a second instance
// never sees half a key.
func writeFile(path string, data []byte, perm fs.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
