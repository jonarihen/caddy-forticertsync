package forticertsync

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"
)

// selfSignedChain builds a leaf signed by a CA that is NOT in any system trust
// store — the same shape as a Let's Encrypt STAGING certificate as far as a
// real client is concerned.
func selfSignedChain(t *testing.T, issuerCN string) []byte {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: issuerCN},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "bundle"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"aaris.tech", "*.aaris.tech"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
	return out
}

// The regression for the outage: a certificate from a CA nobody trusts must be
// rejected, because binding it to an inspection profile takes every bundled
// domain down with "unable to get local issuer certificate".
func TestVerifyPubliclyTrustedRejectsUntrustedIssuer(t *testing.T) {
	certPEM := selfSignedChain(t, "(STAGING) Pretend Pear X1")

	err := verifyPubliclyTrusted(certPEM, time.Now())
	if err == nil {
		t.Fatal("a staging/self-signed chain MUST be rejected — binding it is the outage")
	}
	// The operator has to be able to see which issuer was at fault.
	if got := err.Error(); !contains(got, "Pretend Pear") {
		t.Errorf("error should name the issuer, got: %v", got)
	}
}

func TestVerifyPubliclyTrustedRejectsGarbage(t *testing.T) {
	if err := verifyPubliclyTrusted([]byte("not a pem"), time.Now()); err == nil {
		t.Error("unparseable input must not be treated as trusted")
	}
	if err := verifyPubliclyTrusted(nil, time.Now()); err == nil {
		t.Error("empty input must not be treated as trusted")
	}
}

// An expired chain is untrusted too — verified by checking the same chain at a
// time after its NotAfter.
func TestVerifyPubliclyTrustedHonorsTime(t *testing.T) {
	certPEM := selfSignedChain(t, "Whatever CA")
	if err := verifyPubliclyTrusted(certPEM, time.Now().Add(72*time.Hour)); err == nil {
		t.Error("an expired chain must be rejected")
	}
}

func TestLooksLikeStagingCA(t *testing.T) {
	for _, ca := range []string{
		"https://acme-staging-v02.api.letsencrypt.org/directory",
		"https://ACME-STAGING-v02.api.letsencrypt.org/directory",
		"https://test.example/dir",
	} {
		if !looksLikeStagingCA(ca) {
			t.Errorf("%q should be flagged as staging", ca)
		}
	}
	if looksLikeStagingCA(letsEncryptProductionCA) {
		t.Error("the production directory must not be flagged as staging")
	}
}

// Changing `ca` must force a re-issue. Without this the cached staging
// certificate survives the edit, because reconcile otherwise only compares the
// SAN set and the expiry — neither of which changes.
func TestBundleMetaTracksIssuingCA(t *testing.T) {
	dir := t.TempDir()
	m := &bundleManager{
		cfg:     &InspectionBundle{Name: "b", Zones: []BundleZone{{Domain: "example.com"}}},
		logger:  zap.NewNop(),
		dataDir: dir,
	}

	// No meta file yet (a cache written by an older build) reads as unknown,
	// which differs from any configured CA and therefore forces a re-issue.
	if got := m.loadMeta(); got != "" {
		t.Errorf("missing meta should read as empty, got %q", got)
	}
	if got := m.cfg.effectiveCA(); got != letsEncryptProductionCA {
		t.Errorf("default CA = %q", got)
	}

	staging := "https://acme-staging-v02.api.letsencrypt.org/directory"
	if err := m.saveMeta(staging); err != nil {
		t.Fatalf("saveMeta: %v", err)
	}
	if got := m.loadMeta(); got != staging {
		t.Errorf("loadMeta = %q, want %q", got, staging)
	}
	// This inequality is what triggers the re-order when the operator removes
	// the staging line.
	if m.loadMeta() == m.cfg.effectiveCA() {
		t.Error("a cached staging cert must not satisfy a production CA config")
	}

	m.cfg.CA = staging
	if m.loadMeta() != m.cfg.effectiveCA() {
		t.Error("matching CA should not force a re-order")
	}

	if _, err := os.Stat(filepath.Join(dir, "forticertsync", "bundle", "b", "meta.json")); err != nil {
		t.Errorf("meta.json should live beside the cached cert: %v", err)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
