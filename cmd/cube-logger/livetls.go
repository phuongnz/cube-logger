package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"path/filepath"
	"sync"
	"time"

	"github.com/phuongnz/cube-logger/internal/listen"
	"github.com/phuongnz/cube-logger/internal/tlscert"
)

// tlsSetup is the TLS side of "live": what to serve, and what the banner
// says about it.
type tlsSetup struct {
	config *tls.Config
	// about describes the certificate, under the listening line.
	about []string
	// trust is what a router has to trust before it will send.
	trust string
	// host is the address for "logging host": the first -tls-name, or a
	// placeholder when the engineer has to pick one of this machine's.
	host string
	// clientCA is true when routers have to present a certificate.
	clientCA bool
}

// setupTLS loads the certificate to serve: the one given with -tls-cert, or
// the one cube-logger makes and keeps in dir, remade as names require.
func setupTLS(dir string, names []string, certFile, keyFile, clientCA string, now time.Time) (*tlsSetup, error) {
	ts := &tlsSetup{host: "<this machine's IP>"}
	if len(names) > 0 {
		ts.host = names[0]
	}
	var cert tls.Certificate
	if certFile != "" {
		c, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("-tls-cert: %w", err)
		}
		leaf := c.Leaf
		if leaf == nil {
			if leaf, err = x509.ParseCertificate(c.Certificate[0]); err != nil {
				return nil, fmt.Errorf("-tls-cert: %w", err)
			}
		}
		// A router sent an expired certificate stops logging, and says so
		// only on its own console.
		if now.After(leaf.NotAfter) {
			return nil, fmt.Errorf("-tls-cert: %s expired on %s", certFile, leaf.NotAfter.Format(time.DateOnly))
		}
		cert = c
		ts.about = append(ts.about, fmt.Sprintf("certificate %q issued by %q, valid until %s",
			leaf.Subject.CommonName, leaf.Issuer.CommonName, leaf.NotAfter.Format(time.DateOnly)))
		ts.trust = fmt.Sprintf("the CA that issued %s", certFile)
	} else {
		s, err := loadCerts(dir, names)
		if err != nil {
			return nil, err
		}
		cert = s.Server
		_, sha1sum := tlscert.Fingerprints(s.CA)
		ts.about = append(ts.about, fmt.Sprintf("certificate authority %s, SHA1 %s",
			filepath.Join(s.Dir, tlscert.CAFile), sha1sum))
		switch {
		case s.CreatedCA:
			ts.about = append(ts.about, `made just now: no router trusts it yet ("cube-logger cert" prints how)`)
		case s.Reissued != "":
			ts.about = append(ts.about, "server certificate remade ("+s.Reissued+"); routers that trust the authority need nothing")
		}
		ts.trust = `cube-logger's certificate authority ("cube-logger cert" prints how)`
	}

	var pool *x509.CertPool
	if clientCA != "" {
		var err error
		if pool, err = tlscert.LoadPool(clientCA); err != nil {
			return nil, fmt.Errorf("-tls-client-ca: %w", err)
		}
		ts.clientCA = true
		ts.about = append(ts.about, "routers must present a certificate issued by "+clientCA)
	}
	ts.config = listen.ServerConfig(cert, pool)
	return ts, nil
}

// repeatWindow is how long an identical TLS event stays quiet after it is
// printed. A router that cannot complete a handshake retries, and a port the
// internet can reach hears from scanners; neither should bury the terminal,
// and the summary at exit still counts every one.
const repeatWindow = 5 * time.Minute

// maxRemembered bounds the events kept for repeatWindow: a scan from many
// addresses would otherwise grow the map for as long as the session runs.
const maxRemembered = 1024

// eventLog prints what the TLS listener reports.
type eventLog struct {
	w io.Writer
	// quiet leaves out connects and disconnects, never failures: a failure
	// is a router that is configured and still not being heard.
	quiet  bool
	rename func(string) string
	now    func() time.Time

	mu   sync.Mutex
	last map[string]time.Time
}

func (l *eventLog) print(e listen.Event) {
	if l.quiet && (e.Kind == listen.Connected || e.Kind == listen.Disconnected) {
		return
	}
	if l.rename != nil {
		e.Source = l.rename(e.Source)
	}
	text := e.String()
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()
	if t, ok := l.last[text]; ok && now.Sub(t) < repeatWindow {
		return
	}
	if l.last == nil || len(l.last) >= maxRemembered {
		old := l.last
		l.last = map[string]time.Time{}
		for k, t := range old {
			if now.Sub(t) < repeatWindow {
				l.last[k] = t
			}
		}
		if len(l.last) >= maxRemembered {
			// All recent: forgetting them costs a repeated line, not a
			// missed one.
			clear(l.last)
		}
	}
	l.last[text] = now
	fmt.Fprintln(l.w, text)
}
