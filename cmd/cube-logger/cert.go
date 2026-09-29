package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/phuongnz/cube-logger/internal/listen"
	"github.com/phuongnz/cube-logger/internal/tlscert"
)

// tlsProfile names both the trustpoint and the logging tls-profile on the
// router. They are separate namespaces in IOS; one name is one less thing to
// get wrong when pasting.
const tlsProfile = "CUBE-LOGGER"

func certCmd(args []string) error { return runCert(os.Stdout, args) }

// runCert makes the certificates if there are none yet and prints what a
// router needs to trust them. It is the step before "live -tls", and it makes
// exactly the certificates live will serve: same directory, same names.
func runCert(w io.Writer, args []string) error {
	fs := flag.NewFlagSet("cert", flag.ExitOnError)
	addr := fs.String("tls", fmt.Sprintf(":%d", listen.DefaultTLSPort),
		"the address live -tls will listen on (only the port is used here)")
	dir := fs.String("tls-dir", "", "directory for the certificates (default: the user configuration directory)")
	pemOnly := fs.Bool("pem", false, "print only the CA certificate, for a file or a router that is not IOS-XE")
	var names stringList
	fs.Var(&names, "tls-name", "an address or host name the router uses to reach this machine, such as a\n"+
		"port-forwarded public address; the first one is also the certificate's common name (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("cert takes no arguments, only flags")
	}

	s, err := loadCerts(*dir, names)
	if err != nil {
		return err
	}
	if *pemOnly {
		_, err := w.Write(s.CAPEM)
		return err
	}

	host := "<this machine's IP>"
	if len(names) > 0 {
		host = names[0]
	}
	printCerts(w, s)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "On the CUBE (IOS-XE 17.2.1 or later), in configuration mode, once per router:")
	fmt.Fprintln(w)
	for _, line := range trustConfig() {
		fmt.Fprintln(w, "  "+line)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "When it asks for the certificate, paste this and then an empty line:")
	fmt.Fprintln(w)
	w.Write(s.CAPEM)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Answer yes only if the fingerprints it shows are the ones above. Then:")
	fmt.Fprintln(w)
	suite := listen.SuiteKeyword(listen.ServerConfig(s.Server, nil))
	for _, line := range tlsRouterConfig(*addr, host, suite, false) {
		fmt.Fprintln(w, "  "+line)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "The router keeps trusting this machine when its addresses change: cube-logger")
	fmt.Fprintln(w, "remakes its own certificate from the same authority. A router that reaches it")
	fmt.Fprintln(w, "through NAT or a port forward needs that address named with -tls-name.")
	return nil
}

// loadCerts loads or makes the certificates for this machine. The names asked
// for come first, so the first of them is the common name; this machine's own
// addresses follow, so that any of them works without being asked for.
func loadCerts(dir string, names []string) (*tlscert.Set, error) {
	if dir == "" {
		d, err := tlscert.DefaultDir()
		if err != nil {
			return nil, err
		}
		dir = d
	}
	return tlscert.Ensure(dir, tlscert.Merge(names, tlscert.LocalNames()), time.Now())
}

// printCerts describes the certificates, fingerprints first: they are what an
// engineer compares against the router before typing yes.
func printCerts(w io.Writer, s *tlscert.Set) {
	md5sum, sha1sum := tlscert.Fingerprints(s.CA)
	made := ""
	if s.CreatedCA {
		made = " (made just now; no router trusts it yet)"
	}
	fmt.Fprintf(w, "certificate authority %s%s\n", filepath.Join(s.Dir, tlscert.CAFile), made)
	fmt.Fprintf(w, "  MD5  %s\n", md5sum)
	fmt.Fprintf(w, "  SHA1 %s\n", sha1sum)
	made = ""
	if s.Reissued != "" && !s.CreatedCA {
		made = fmt.Sprintf(" (made just now: %s)", s.Reissued)
	}
	fmt.Fprintf(w, "server certificate, valid until %s%s, for\n", s.Server.Leaf.NotAfter.Format(time.DateOnly), made)
	fmt.Fprintf(w, "  %s\n", strings.Join(s.Names(), ", "))
}

// trustConfig makes a router trust the authority. "enrollment terminal" is
// what lets the certificate be pasted, and "revocation-check none" is needed
// because this authority publishes no revocation list for the router to fetch.
func trustConfig() []string {
	return []string{
		"crypto pki trustpoint " + tlsProfile,
		" enrollment terminal",
		" revocation-check none",
		" chain-validation stop",
		"crypto pki authenticate " + tlsProfile,
	}
}

// tlsRouterConfig is the TLS version of routerConfig. The cipher suite is not
// a preference: it is the one IOS-XE keyword that Go serves over TLS 1.2 with
// the listener's certificate (see acceptedSuites in internal/listen).
// clientCert adds the line that makes the router present its own certificate,
// for a listener started with -tls-client-ca.
func tlsRouterConfig(addr, host, suite string, clientCert bool) []string {
	port := fmt.Sprint(listen.DefaultTLSPort)
	if _, p, err := net.SplitHostPort(addr); err == nil && p != "" {
		port = p
	}
	lines := []string{
		"logging tls-profile " + tlsProfile,
		" tls-version TLSv1.2",
		" ciphersuite " + suite,
	}
	if clientCert {
		lines = append(lines, " client-id-trustpoint <the trustpoint holding this router's own certificate>")
	}
	return append(lines,
		fmt.Sprintf("logging host %s transport tls port %s profile %s", host, port, tlsProfile),
		"logging trap debugging",
		"service sequence-numbers",
	)
}
