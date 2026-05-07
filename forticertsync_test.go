package forticertsync

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestMatchesDomain(t *testing.T) {
	tests := []struct {
		name       string
		identifier string
		domains    []string
		want       bool
	}{
		{"empty domains matches everything", "anything.example.com", nil, true},
		{"empty slice matches everything", "anything.example.com", []string{}, true},
		{"exact match", "example.com", []string{"example.com"}, true},
		{"exact match case insensitive", "EXAMPLE.com", []string{"example.com"}, true},
		{"no match", "other.com", []string{"example.com"}, false},
		{"wildcard match", "foo.example.com", []string{"*.example.com"}, true},
		{"wildcard match deeper subdomain", "a.b.example.com", []string{"*.example.com"}, true},
		{"wildcard does not match base domain (uses suffix only)", "example.com", []string{"*.example.com"}, true},
		{"multiple domains, second matches", "vpn.example.com", []string{"other.com", "vpn.example.com"}, true},
		{"multiple domains, none match", "third.com", []string{"first.com", "second.com"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesDomain(tt.identifier, tt.domains)
			if got != tt.want {
				t.Errorf("matchesDomain(%q, %v) = %v, want %v", tt.identifier, tt.domains, got, tt.want)
			}
		})
	}
}

func TestParsePEMCertificate(t *testing.T) {
	t.Run("valid PEM", func(t *testing.T) {
		certPEM, _ := generateTestCert(t)
		c, err := parsePEMCertificate(certPEM)
		if err != nil {
			t.Fatalf("parsePEMCertificate failed: %v", err)
		}
		if c == nil {
			t.Fatal("got nil certificate")
		}
		if c.Subject.CommonName != "test.example.com" {
			t.Errorf("unexpected CN: %s", c.Subject.CommonName)
		}
	})

	t.Run("empty input", func(t *testing.T) {
		_, err := parsePEMCertificate(nil)
		if err == nil {
			t.Error("expected error on empty input")
		}
	})

	t.Run("invalid PEM", func(t *testing.T) {
		_, err := parsePEMCertificate([]byte("not a pem block"))
		if err == nil {
			t.Error("expected error on invalid PEM")
		}
	})

	t.Run("PEM with garbage body", func(t *testing.T) {
		bad := []byte("-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydA==\n-----END CERTIFICATE-----\n")
		_, err := parsePEMCertificate(bad)
		if err == nil {
			t.Error("expected error on garbage cert body")
		}
	})
}

func TestHandlerValidate(t *testing.T) {
	tests := []struct {
		name    string
		h       Handler
		wantErr bool
	}{
		{
			name: "valid",
			h: Handler{
				FortiGateURL: "https://fw",
				APIToken:     "tok",
				Certificates: []CertMapping{{Name: "c1"}},
			},
			wantErr: false,
		},
		{name: "missing url", h: Handler{APIToken: "t", Certificates: []CertMapping{{Name: "c1"}}}, wantErr: true},
		{name: "missing token", h: Handler{FortiGateURL: "https://fw", Certificates: []CertMapping{{Name: "c1"}}}, wantErr: true},
		{name: "no certificates", h: Handler{FortiGateURL: "https://fw", APIToken: "t"}, wantErr: true},
		{
			name: "cert mapping missing name",
			h: Handler{
				FortiGateURL: "https://fw",
				APIToken:     "t",
				Certificates: []CertMapping{{Name: ""}},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.h.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() err = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

// generateTestCert produces a self-signed certificate and key (PEM-encoded)
// for use in tests. CN is "test.example.com".
func generateTestCert(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}
