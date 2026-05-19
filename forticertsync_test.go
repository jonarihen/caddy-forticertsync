package forticertsync

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
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

func TestSanitizeName(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"dots and dashes replaced", "tm-lestang.dk", "tm_lestang_dk"},
		{"leading wildcard", "*.example.com", "wildcard_example_com"},
		{"deep subdomain", "abs.example.com", "abs_example_com"},
		{"already safe", "plain", "plain"},
		{"uppercase lowercased", "EXAMPLE.com", "example_com"},
		{"non-alnum stripped", "weird!@#.com", "weird_com"},
		{"empty", "", ""},
		{"all special", "!@#$%", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeName(tt.in); got != tt.want {
				t.Errorf("sanitizeName(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}

	t.Run("length truncation with hash suffix", func(t *testing.T) {
		// A 50-char identifier sanitizes to a 50-char string, which must
		// truncate to 23 + "_" + 7-hex = 31 chars total.
		long := strings.Repeat("a", 50)
		got := sanitizeName(long)
		if len(got) != 31 {
			t.Errorf("len = %d, want 31; got %q", len(got), got)
		}
		if got[23] != '_' {
			t.Errorf("expected '_' at index 23, got %q in %q", got[23], got)
		}
		// Different long inputs that share the 23-char prefix must
		// produce different outputs via the hash suffix.
		other := long[:48] + "bb"
		if sanitizeName(other) == got {
			t.Errorf("distinct long inputs collided to %q", got)
		}
	})
}

func TestEffectiveBaseName(t *testing.T) {
	tests := []struct {
		name       string
		mapping    CertMapping
		identifier string
		want       string
	}{
		{
			name:       "zero domains uses mapping name",
			mapping:    CertMapping{Name: "x"},
			identifier: "foo.example.com",
			want:       "x",
		},
		{
			name:       "single domain uses mapping name",
			mapping:    CertMapping{Name: "x", Domains: []string{"example.com"}},
			identifier: "example.com",
			want:       "x",
		},
		{
			name:       "single wildcard uses mapping name",
			mapping:    CertMapping{Name: "wild", Domains: []string{"*.example.com"}},
			identifier: "a.example.com",
			want:       "wild",
		},
		{
			name:       "all wildcards use mapping name",
			mapping:    CertMapping{Name: "wild", Domains: []string{"*.example.com", "*.example.org"}},
			identifier: "a.example.com",
			want:       "wild",
		},
		{
			name:       "two non-wildcards use sanitized identifier",
			mapping:    CertMapping{Name: "tm", Domains: []string{"tm-lestang.dk", "www.tm-lestang.dk"}},
			identifier: "tm-lestang.dk",
			want:       "tm_lestang_dk",
		},
		{
			name:       "two non-wildcards, second identifier",
			mapping:    CertMapping{Name: "tm", Domains: []string{"tm-lestang.dk", "www.tm-lestang.dk"}},
			identifier: "www.tm-lestang.dk",
			want:       "www_tm_lestang_dk",
		},
		{
			name:       "mixed wildcard + single non-wildcard uses mapping name (only one non-wildcard)",
			mapping:    CertMapping{Name: "mixed", Domains: []string{"*.example.com", "example.com"}},
			identifier: "example.com",
			want:       "mixed",
		},
		{
			name:       "two non-wildcards + a wildcard still sanitizes",
			mapping:    CertMapping{Name: "many", Domains: []string{"a.example.com", "b.example.com", "*.example.org"}},
			identifier: "b.example.com",
			want:       "b_example_com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := effectiveBaseName(tt.mapping, tt.identifier); got != tt.want {
				t.Errorf("effectiveBaseName(%+v, %q) = %q, want %q",
					tt.mapping, tt.identifier, got, tt.want)
			}
		})
	}
}

func TestResolveStoragePath(t *testing.T) {
	// Use filepath.Join in expected values so the test passes on both
	// Unix (/var/lib/caddy/...) and Windows (C:\ProgramData\Caddy\...).
	dataDir := filepath.Join(string(filepath.Separator)+"var", "lib", "caddy")
	storageKey := "certificates/acme-v02.api.letsencrypt.org-directory/wildcard_.example.com/wildcard_.example.com.crt"
	wantJoined := filepath.Join(dataDir, "certificates", "acme-v02.api.letsencrypt.org-directory", "wildcard_.example.com", "wildcard_.example.com.crt")

	tests := []struct {
		name       string
		dataDir    string
		storageKey string
		want       string
	}{
		{
			name:       "relative storage key joined to data dir",
			dataDir:    dataDir,
			storageKey: storageKey,
			want:       wantJoined,
		},
		{
			// os.TempDir() is absolute on every supported OS (Unix returns
			// /tmp; Windows returns something like C:\Users\...\Temp), so
			// joining a filename onto it gives a portable absolute path.
			name:       "absolute path passes through unchanged",
			dataDir:    dataDir,
			storageKey: filepath.Join(os.TempDir(), "cert.pem"),
			want:       filepath.Clean(filepath.Join(os.TempDir(), "cert.pem")),
		},
		{
			name:       "empty data dir leaves relative key relative",
			dataDir:    "",
			storageKey: "certificates/foo/bar.crt",
			want:       filepath.Join("certificates", "foo", "bar.crt"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveStoragePath(tt.dataDir, tt.storageKey)
			if got != tt.want {
				t.Errorf("resolveStoragePath(%q, %q) = %q, want %q",
					tt.dataDir, tt.storageKey, got, tt.want)
			}
		})
	}
}

// handleTestFixture sets up a temp data dir with valid cert/key files
// and a mock FortiGate that records every /local/import certname.
type handleTestFixture struct {
	server        *httptest.Server
	dataDir       string
	certStorageKey string
	keyStorageKey  string
	importedNames []string
}

func newHandleTestFixture(t *testing.T) *handleTestFixture {
	t.Helper()
	certPEM, keyPEM := generateTestCert(t)

	dir := t.TempDir()
	certKey := "certificates/test/leaf.crt"
	keyKey := "certificates/test/leaf.key"
	if err := os.MkdirAll(filepath.Join(dir, "certificates", "test"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, certKey), certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, keyKey), keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	f := &handleTestFixture{
		dataDir:        dir,
		certStorageKey: certKey,
		keyStorageKey:  keyKey,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/cmdb/vpn.certificate/local", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"results":[]}`)
	})
	mux.HandleFunc("/api/v2/monitor/vpn-certificate/local/import", func(w http.ResponseWriter, r *http.Request) {
		var p map[string]string
		_ = json.NewDecoder(r.Body).Decode(&p)
		f.importedNames = append(f.importedNames, p["certname"])
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/api/v2/monitor/vpn-certificate/ca/import", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *handleTestFixture) newHandler(t *testing.T, certs []CertMapping, syncAll bool) *Handler {
	t.Helper()
	h := &Handler{
		logger:       zap.NewNop(),
		dataDir:      f.dataDir,
		Certificates: certs,
		SyncAll:      syncAll,
	}
	h.client = NewFortiGateClient(f.server.URL, "tok", "", true, zap.NewNop())
	return h
}

func TestHandle_SyncAllUnmappedIdentifier(t *testing.T) {
	f := newHandleTestFixture(t)
	h := f.newHandler(t, nil, true)

	event := caddy.Event{Data: map[string]any{
		"identifier":       "finebox.nikodyring.dev",
		"certificate_path": f.certStorageKey,
		"private_key_path": f.keyStorageKey,
	}}
	if err := h.Handle(context.Background(), event); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if len(f.importedNames) != 1 {
		t.Fatalf("imports = %d, want 1: %v", len(f.importedNames), f.importedNames)
	}
	today := time.Now().Format("02012006")
	want := "finebox_nikodyring_dev_" + today
	if f.importedNames[0] != want {
		t.Errorf("imported name = %q, want %q", f.importedNames[0], want)
	}
}

func TestHandle_SyncAllMappedIdentifierPrefersMapping(t *testing.T) {
	// When an explicit mapping matches, SyncAll must not double-sync the
	// identifier under an auto-derived name.
	f := newHandleTestFixture(t)
	h := f.newHandler(t, []CertMapping{{
		Name:    "explicit_mapping",
		Domains: []string{"example.com"},
	}}, true)

	event := caddy.Event{Data: map[string]any{
		"identifier":       "example.com",
		"certificate_path": f.certStorageKey,
		"private_key_path": f.keyStorageKey,
	}}
	if err := h.Handle(context.Background(), event); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if len(f.importedNames) != 1 {
		t.Fatalf("imports = %d, want 1 (no double-sync): %v", len(f.importedNames), f.importedNames)
	}
	today := time.Now().Format("02012006")
	want := "explicit_mapping_" + today
	if f.importedNames[0] != want {
		t.Errorf("imported name = %q, want %q (explicit mapping should win)", f.importedNames[0], want)
	}
}

func TestSyncCertToFortiGate_MultiDomainMapping(t *testing.T) {
	// Same mapping covering two non-wildcard domains. Two cert_obtained
	// events must produce two distinct FortiGate cert names so they don't
	// race and overwrite each other.
	var importedNames []string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/cmdb/vpn.certificate/local", func(w http.ResponseWriter, r *http.Request) {
		// Empty cert list — every sync goes down the first-time-import path.
		_, _ = io.WriteString(w, `{"results":[]}`)
	})
	mux.HandleFunc("/api/v2/monitor/vpn-certificate/local/import", func(w http.ResponseWriter, r *http.Request) {
		var p map[string]string
		_ = json.NewDecoder(r.Body).Decode(&p)
		importedNames = append(importedNames, p["certname"])
		w.WriteHeader(http.StatusOK)
	})
	// ca/import called best-effort during syncIntermediateCAs; ignore.
	mux.HandleFunc("/api/v2/monitor/vpn-certificate/ca/import", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	h := &Handler{logger: zap.NewNop()}
	h.client = NewFortiGateClient(srv.URL, "tok", "", true, zap.NewNop())
	mapping := CertMapping{
		Name:    "tm_lestang_dk",
		Domains: []string{"tm-lestang.dk", "www.tm-lestang.dk"},
	}
	certPEM, keyPEM := generateTestCert(t)

	if err := h.syncCertToFortiGate(context.Background(), mapping, "tm-lestang.dk", certPEM, keyPEM); err != nil {
		t.Fatalf("first sync: %v", err)
	}
	if err := h.syncCertToFortiGate(context.Background(), mapping, "www.tm-lestang.dk", certPEM, keyPEM); err != nil {
		t.Fatalf("second sync: %v", err)
	}

	if len(importedNames) != 2 {
		t.Fatalf("imports = %d, want 2: %v", len(importedNames), importedNames)
	}
	today := time.Now().Format("02012006")
	wantA := "tm_lestang_dk_" + today
	wantB := "www_tm_lestang_dk_" + today
	if importedNames[0] != wantA {
		t.Errorf("imports[0] = %q, want %q", importedNames[0], wantA)
	}
	if importedNames[1] != wantB {
		t.Errorf("imports[1] = %q, want %q", importedNames[1], wantB)
	}
	if importedNames[0] == importedNames[1] {
		t.Errorf("multi-domain mapping collapsed to same cert name; race condition not fixed")
	}
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
			name:    "no certificates but sync_all opts in",
			h:       Handler{FortiGateURL: "https://fw", APIToken: "t", SyncAll: true},
			wantErr: false,
		},
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
