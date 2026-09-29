package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phuongnz/cube-logger/internal/tlscert"
)

func runCertOK(t *testing.T, args ...string) string {
	t.Helper()
	var out bytes.Buffer
	if err := runCert(&out, args); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func TestCertPrintsWhatTheRouterNeeds(t *testing.T) {
	dir := t.TempDir()
	out := runCertOK(t, "-tls-dir", dir, "-tls-name", "203.0.113.5", "-tls", ":7514")

	ca, err := os.ReadFile(filepath.Join(dir, tlscert.CAFile))
	if err != nil {
		t.Fatal(err)
	}
	s, err := tlscert.Ensure(dir, []string{"203.0.113.5"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	md5sum, sha1sum := tlscert.Fingerprints(s.CA)
	for _, want := range []string{
		"no router trusts it yet",
		"MD5  " + md5sum,
		"SHA1 " + sha1sum,
		"crypto pki trustpoint CUBE-LOGGER\n   enrollment terminal\n   revocation-check none\n",
		"crypto pki authenticate CUBE-LOGGER",
		string(ca),
		"logging tls-profile CUBE-LOGGER\n   tls-version TLSv1.2\n   ciphersuite ecdhe-rsa-aes-gcm-sha2\n",
		"logging host 203.0.113.5 transport tls port 7514 profile CUBE-LOGGER",
		"service sequence-numbers",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	// The name asked for leads, and this machine's own addresses follow.
	if !strings.Contains(out, "  203.0.113.5, ") || !strings.Contains(out, "127.0.0.1") {
		t.Errorf("certificate names not as expected:\n%s", out)
	}

	// Run again: nothing is made, so nothing claims to be.
	again := runCertOK(t, "-tls-dir", dir, "-tls-name", "203.0.113.5")
	if strings.Contains(again, "made just now") || strings.Contains(again, "no router trusts") {
		t.Errorf("a second run claims to have made something:\n%s", again)
	}
	if !strings.Contains(again, "SHA1 "+sha1sum) {
		t.Error("the CA changed between runs")
	}
	if !strings.Contains(again, "logging host 203.0.113.5 transport tls port 6514 profile") {
		t.Errorf("default port is not 6514:\n%s", again)
	}
}

func TestCertWithoutANameSaysWhereTheAddressGoes(t *testing.T) {
	out := runCertOK(t, "-tls-dir", t.TempDir())
	if !strings.Contains(out, "logging host <this machine's IP> transport tls port 6514") {
		t.Errorf("output:\n%s", out)
	}
}

func TestCertReportsAReissue(t *testing.T) {
	dir := t.TempDir()
	runCertOK(t, "-tls-dir", dir)
	out := runCertOK(t, "-tls-dir", dir, "-tls-name", "logger.example")
	if !strings.Contains(out, "made just now: its common name was") {
		t.Errorf("a new first name did not say why the certificate changed:\n%s", out)
	}
}

func TestCertPEMIsOnlyTheCertificate(t *testing.T) {
	dir := t.TempDir()
	out := runCertOK(t, "-tls-dir", dir, "-pem")
	ca, err := os.ReadFile(filepath.Join(dir, tlscert.CAFile))
	if err != nil {
		t.Fatal(err)
	}
	if out != string(ca) {
		t.Errorf("-pem printed more than ca.pem:\n%s", out)
	}
}

func TestCertRefusesABadName(t *testing.T) {
	var out bytes.Buffer
	if err := runCert(&out, []string{"-tls-dir", t.TempDir(), "-tls-name", "not a name"}); err == nil {
		t.Error("accepted a name with a space in it")
	}
	if err := runCert(&out, []string{"-tls-dir", t.TempDir(), "extra"}); err == nil {
		t.Error("accepted an argument")
	}
}
