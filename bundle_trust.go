package forticertsync

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// letsEncryptProductionCA is certmagic's default ACME directory. Used only to
// record which CA a cached certificate came from; nothing here hardcodes trust
// decisions to a specific issuer.
const letsEncryptProductionCA = "https://acme-v02.api.letsencrypt.org/directory"

// bundleMeta records how the cached certificate was obtained, so a change to
// the configured CA forces a re-issue.
//
// Without this, editing `ca` (say, removing a staging directory to go live)
// changes nothing: reconcile only compares the SAN set and the expiry date, so
// the cached staging certificate stays in use and keeps getting pushed.
type bundleMeta struct {
	CA string `json:"ca"`
}

// effectiveCA returns the ACME directory the bundle is configured to use.
func (b *InspectionBundle) effectiveCA() string {
	if b.CA != "" {
		return b.CA
	}
	return letsEncryptProductionCA
}

func (m *bundleManager) metaPath() string {
	certPath, _, _ := m.bundlePaths()
	return filepath.Join(filepath.Dir(certPath), "meta.json")
}

// loadMeta returns the CA recorded for the cached certificate, or "" if the
// cache predates this file (treated as unknown, which forces a re-issue).
func (m *bundleManager) loadMeta() string {
	data, err := os.ReadFile(m.metaPath())
	if err != nil {
		return ""
	}
	var meta bundleMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return ""
	}
	return meta.CA
}

func (m *bundleManager) saveMeta(ca string) error {
	data, err := json.MarshalIndent(bundleMeta{CA: ca}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.metaPath()), 0o700); err != nil {
		return err
	}
	return os.WriteFile(m.metaPath(), data, 0o600)
}

// verifyPubliclyTrusted reports whether a certificate chain will actually be
// trusted by ordinary clients — i.e. whether it chains to a root in this
// machine's system trust store.
//
// This is the guard that must never be removed. In "Protecting SSL Server"
// mode the FortiGate presents whatever certificate the inspection profile
// names, to every visitor. Binding an untrusted one takes the site down for
// everybody with "unable to get local issuer certificate" — which is exactly
// what a Let's Encrypt STAGING certificate does, and staging is the normal
// way to test this feature.
//
// Checking against the system trust store rather than string-matching the
// issuer catches staging, private CAs, self-signed certs, and misordered or
// incomplete chains alike: the question asked is the same one a browser asks.
func verifyPubliclyTrusted(certPEM []byte, now time.Time) error {
	blocks, err := splitPEMChain(certPEM)
	if err != nil {
		return fmt.Errorf("parsing chain: %w", err)
	}
	leaf, err := x509.ParseCertificate(blocks[0].Bytes)
	if err != nil {
		return fmt.Errorf("parsing leaf: %w", err)
	}

	intermediates := x509.NewCertPool()
	for _, blk := range blocks[1:] {
		if ca, err := x509.ParseCertificate(blk.Bytes); err == nil {
			intermediates.AddCert(ca)
		}
	}

	roots, err := x509.SystemCertPool()
	if err != nil {
		return fmt.Errorf("loading system trust store: %w", err)
	}

	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		// No DNSName: coverage of the configured subjects is already asserted
		// by sanMatches. What is in question here is only the trust chain.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return fmt.Errorf("chain is not publicly trusted (issuer %q): %w", leaf.Issuer.CommonName, err)
	}
	return nil
}

// looksLikeStagingCA is a best-effort hint for the operator-facing message.
// It never gates anything — verifyPubliclyTrusted is the actual decision.
func looksLikeStagingCA(ca string) bool {
	l := strings.ToLower(ca)
	return strings.Contains(l, "staging") || strings.Contains(l, "test")
}
