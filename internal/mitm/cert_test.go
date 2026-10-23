package mitm

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

func TestCertificateLifecycle(t *testing.T) {
	dir := t.TempDir()
	center, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	first := center.Status()
	if !strings.Contains(first.Subject, "Scanning Root CA") {
		t.Fatalf("unexpected subject: %s", first.Subject)
	}
	if first.FingerprintSHA256 == "" || first.ThumbprintSHA1 == "" {
		t.Fatal("missing fingerprints")
	}

	leaf, err := center.CertificateFor("api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.Leaf.VerifyHostname("api.example.com"); err != nil {
		t.Fatalf("hostname verify: %v", err)
	}
	if len(leaf.Certificate) != 2 {
		t.Fatalf("chain length = %d", len(leaf.Certificate))
	}

	block, _ := pem.Decode(center.CAPEM())
	if block == nil {
		t.Fatal("invalid CA PEM")
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.Leaf.CheckSignatureFrom(root); err != nil {
		t.Fatalf("leaf not signed by root: %v", err)
	}

	cached, err := center.CertificateFor("api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if cached != leaf {
		t.Fatal("leaf certificate should be cached")
	}

	if err := center.Rotate(); err != nil {
		t.Fatal(err)
	}
	second := center.Status()
	if first.FingerprintSHA256 == second.FingerprintSHA256 {
		t.Fatal("fingerprint did not change after rotation")
	}

	reloaded, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.Status().FingerprintSHA256; got != second.FingerprintSHA256 {
		t.Fatalf("reloaded fingerprint = %s, want %s", got, second.FingerprintSHA256)
	}
}

func TestCertificateForIP(t *testing.T) {
	center, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := center.CertificateFor("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.Leaf.IPAddresses) != 1 || leaf.Leaf.IPAddresses[0].String() != "127.0.0.1" {
		t.Fatalf("unexpected IP SANs: %+v", leaf.Leaf.IPAddresses)
	}
}
