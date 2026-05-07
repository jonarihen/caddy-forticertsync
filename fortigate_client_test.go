package forticertsync

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

func newTestClient(t *testing.T, srv *httptest.Server, vdom string) *FortiGateClient {
	t.Helper()
	return NewFortiGateClient(srv.URL, "test-token", vdom, true, zap.NewNop())
}

func TestBuildURL(t *testing.T) {
	c := NewFortiGateClient("https://fw/", "tok", "", false, zap.NewNop())
	if got := c.buildURL("api/v2/foo"); got != "https://fw/api/v2/foo" {
		t.Errorf("no vdom: got %s", got)
	}
	if got := c.buildURL("/api/v2/foo"); got != "https://fw/api/v2/foo" {
		t.Errorf("leading slash: got %s", got)
	}

	cv := NewFortiGateClient("https://fw", "tok", "root", false, zap.NewNop())
	if got := cv.buildURL("api/v2/foo"); got != "https://fw/api/v2/foo?vdom=root" {
		t.Errorf("with vdom: got %s", got)
	}
	if got := cv.buildURL("api/v2/foo", "mkey", "abc"); !strings.Contains(got, "vdom=root") || !strings.Contains(got, "mkey=abc") {
		t.Errorf("with extra params: got %s", got)
	}
}

func TestListCertificates(t *testing.T) {
	body := `{
		"results": [
			{"name":"cert1","subject":"CN=foo","issuer":"CN=ca","valid_from":1700000000,"valid_to":1800000000,"serial_number":"01","source":"user","q_ref":2},
			{"name":"cert2","subject":"CN=bar","issuer":"CN=ca","valid_from":"1710000000","valid_to":"2024-06-01 00:00:00 GMT","serial_number":"02","source":"user","q_ref":0}
		]
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/v2/monitor/vpn-certificate/local/select") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("missing or wrong Authorization header: %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()

	c := newTestClient(t, srv, "")
	certs, err := c.ListCertificates(context.Background())
	if err != nil {
		t.Fatalf("ListCertificates: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("len = %d, want 2", len(certs))
	}
	if certs[0].Name != "cert1" || certs[0].QRef != 2 {
		t.Errorf("certs[0] = %+v", certs[0])
	}
	if certs[0].NotBefore.IsZero() || certs[0].NotAfter.IsZero() {
		t.Errorf("certs[0] dates not parsed: %+v", certs[0])
	}
	wantFrom := time.Unix(1700000000, 0).UTC()
	if !certs[0].NotBefore.Equal(wantFrom) {
		t.Errorf("certs[0].NotBefore = %v, want %v", certs[0].NotBefore, wantFrom)
	}
	if certs[1].NotBefore.IsZero() {
		t.Error("certs[1] NotBefore (string-encoded epoch) not parsed")
	}
	if certs[1].NotAfter.IsZero() {
		t.Error("certs[1] NotAfter (formatted string) not parsed")
	}
}

func TestListCertificates_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"unauthorized"}`)
	}))
	defer srv.Close()

	c := newTestClient(t, srv, "")
	_, err := c.ListCertificates(context.Background())
	if err == nil {
		t.Fatal("expected error on 401")
	}
}

func TestImportCertificate(t *testing.T) {
	var capturedPayload map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		if !strings.Contains(r.URL.Path, "/monitor/vpn-certificate/local/import") {
			t.Errorf("path = %s", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&capturedPayload)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"status":"success"}`)
	}))
	defer srv.Close()

	c := newTestClient(t, srv, "root")
	certPEM := []byte("-----BEGIN CERTIFICATE-----\nQUJDRA==\nRUZHSA==\n-----END CERTIFICATE-----\n")
	keyPEM := []byte("-----BEGIN EC PRIVATE KEY-----\nS0VZQk9EWQ==\n-----END EC PRIVATE KEY-----\n")
	err := c.ImportCertificate(context.Background(), "mycert", certPEM, keyPEM)
	if err != nil {
		t.Fatalf("ImportCertificate: %v", err)
	}
	if capturedPayload["certname"] != "mycert" {
		t.Errorf("certname = %q", capturedPayload["certname"])
	}
	// FortiOS 7.6.6 requires stripped base64 — no BEGIN/END armor, no newlines.
	if capturedPayload["file_content"] != "QUJDRA==RUZHSA==" {
		t.Errorf("file_content = %q, want stripped base64 body", capturedPayload["file_content"])
	}
	if capturedPayload["key_file_content"] != "S0VZQk9EWQ==" {
		t.Errorf("key_file_content = %q, want stripped base64 body", capturedPayload["key_file_content"])
	}
	if capturedPayload["scope"] != "vdom" {
		t.Errorf("scope = %q (vdom set, expected vdom)", capturedPayload["scope"])
	}
	if capturedPayload["type"] != "regular" {
		t.Errorf("type = %q", capturedPayload["type"])
	}
}

func TestImportCertificate_GlobalScope(t *testing.T) {
	var capturedPayload map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&capturedPayload)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(t, srv, "")
	certPEM := []byte("-----BEGIN CERTIFICATE-----\nQUJDRA==\n-----END CERTIFICATE-----\n")
	keyPEM := []byte("-----BEGIN EC PRIVATE KEY-----\nS0VZ\n-----END EC PRIVATE KEY-----\n")
	err := c.ImportCertificate(context.Background(), "mycert", certPEM, keyPEM)
	if err != nil {
		t.Fatalf("ImportCertificate: %v", err)
	}
	if capturedPayload["scope"] != "global" {
		t.Errorf("scope = %q, want global", capturedPayload["scope"])
	}
	if capturedPayload["file_content"] != "QUJDRA==" {
		t.Errorf("file_content = %q, want stripped base64 body", capturedPayload["file_content"])
	}
}

func TestImportCertificate_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"bad cert"}`)
	}))
	defer srv.Close()

	c := newTestClient(t, srv, "")
	err := c.ImportCertificate(context.Background(), "mycert", []byte("p"), []byte("k"))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDeleteCertificate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		if r.URL.Query().Get("mkey") != "oldcert" {
			t.Errorf("mkey = %q", r.URL.Query().Get("mkey"))
		}
		if !strings.Contains(r.URL.Path, "/monitor/vpn-certificate/local/clear") {
			t.Errorf("path = %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(t, srv, "")
	if err := c.DeleteCertificate(context.Background(), "oldcert"); err != nil {
		t.Fatalf("DeleteCertificate: %v", err)
	}
}

func TestDeleteCertificate_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newTestClient(t, srv, "")
	if err := c.DeleteCertificate(context.Background(), "x"); err == nil {
		t.Fatal("expected error")
	}
}

func TestFindCertReferences(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "vpn.ssl/settings"):
			_, _ = io.WriteString(w, `{"results":{"servercert":"oldcert"}}`)
		case strings.Contains(r.URL.Path, "firewall/vip"):
			_, _ = io.WriteString(w, `{"results":[{"name":"vip1","server-cert":"oldcert"},{"name":"vip2","server-cert":"other"}]}`)
		case strings.Contains(r.URL.Path, "system/global"):
			_, _ = io.WriteString(w, `{"results":{"admin-server-cert":"different"}}`)
		case strings.Contains(r.URL.Path, "firewall/ssl-ssh-profile"):
			_, _ = io.WriteString(w, `{"results":[]}`)
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	c := newTestClient(t, srv, "")
	refs, err := c.FindCertReferences(context.Background(), "oldcert")
	if err != nil {
		t.Fatalf("FindCertReferences: %v", err)
	}
	if len(refs) != 2 {
		t.Fatalf("len(refs) = %d, want 2: %+v", len(refs), refs)
	}
	endpoints := map[string]bool{}
	for _, r := range refs {
		endpoints[r.Endpoint] = true
	}
	if !endpoints["vpn.ssl/settings"] || !endpoints["firewall/vip"] {
		t.Errorf("missing expected endpoints: %+v", endpoints)
	}
}

func TestUpdateCertReference(t *testing.T) {
	var capturedPayload map[string]string
	var capturedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("method = %s", r.Method)
		}
		capturedPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&capturedPayload)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(t, srv, "")
	ref := CertReference{
		Endpoint: "firewall/vip",
		MKey:     "vip1",
		Field:    "server-cert",
		OldValue: "oldcert",
	}
	if err := c.UpdateCertReference(context.Background(), ref, "newcert"); err != nil {
		t.Fatalf("UpdateCertReference: %v", err)
	}
	if !strings.HasSuffix(capturedPath, "/api/v2/cmdb/firewall/vip/vip1") {
		t.Errorf("path = %s", capturedPath)
	}
	if capturedPayload["server-cert"] != "newcert" {
		t.Errorf("server-cert payload = %q", capturedPayload["server-cert"])
	}
}

func TestGetCertificateByPattern(t *testing.T) {
	body := `{
		"results": [
			{"name":"example_com","valid_from":1600000000,"valid_to":1700000000},
			{"name":"example_com_07052026","valid_from":1750000000,"valid_to":1800000000},
			{"name":"example_com_01012025","valid_from":1700000000,"valid_to":1750000000},
			{"name":"unrelated_cert","valid_from":1900000000,"valid_to":2000000000}
		]
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()

	c := newTestClient(t, srv, "")

	got, err := c.GetCertificateByPattern(context.Background(), "example_com")
	if err != nil {
		t.Fatalf("GetCertificateByPattern: %v", err)
	}
	if got == nil {
		t.Fatal("got nil, expected match")
	}
	if got.Name != "example_com_07052026" {
		t.Errorf("got name = %q, want example_com_07052026 (newest matching)", got.Name)
	}

	got, err = c.GetCertificateByPattern(context.Background(), "no_match_pattern")
	if err != nil {
		t.Fatalf("GetCertificateByPattern: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for no match, got %+v", got)
	}
}

func TestParseFortiDate(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{"epoch number", `1700000000`, false},
		{"epoch as string", `"1700000000"`, false},
		{"RFC3339", `"2024-06-01T12:00:00Z"`, false},
		{"FortiOS dash format", `"2024-06-01 12:00:00 GMT"`, false},
		{"empty", ``, true},
		{"null", `null`, true},
		{"empty string", `""`, true},
		{"unknown format", `"not a date"`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseFortiDate([]byte(tt.raw))
			if (err != nil) != tt.wantErr {
				t.Errorf("parseFortiDate(%s) err = %v, wantErr = %v", tt.raw, err, tt.wantErr)
			}
		})
	}
}

func TestStripPEMHeaders(t *testing.T) {
	pem := "-----BEGIN CERTIFICATE-----\nABCD\nEFGH\n-----END CERTIFICATE-----\n"
	got := stripPEMHeaders([]byte(pem))
	if got != "ABCDEFGH" {
		t.Errorf("got %q, want %q", got, "ABCDEFGH")
	}
}
