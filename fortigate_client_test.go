package forticertsync

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
	// CMDB response shape from FortiOS 7.6.6:
	//   /api/v2/cmdb/vpn.certificate/local
	body := `{
		"results": [
			{"name":"Fortinet_Factory","source":"factory","last-updated":0},
			{"name":"example_com_07052026","source":"user","last-updated":0}
		]
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/v2/cmdb/vpn.certificate/local") {
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
	if certs[0].Name != "Fortinet_Factory" || certs[0].Source != "factory" {
		t.Errorf("certs[0] = %+v", certs[0])
	}
	if certs[1].Name != "example_com_07052026" || certs[1].Source != "user" {
		t.Errorf("certs[1] = %+v", certs[1])
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
	certPEM := []byte("-----BEGIN CERTIFICATE-----\nQUJDRA==\n-----END CERTIFICATE-----\n")
	keyPEM := []byte("-----BEGIN EC PRIVATE KEY-----\nS0VZQk9EWQ==\n-----END EC PRIVATE KEY-----\n")
	err := c.ImportCertificate(context.Background(), "mycert", certPEM, keyPEM)
	if err != nil {
		t.Fatalf("ImportCertificate: %v", err)
	}
	if capturedPayload["certname"] != "mycert" {
		t.Errorf("certname = %q", capturedPayload["certname"])
	}
	// FortiOS 7.6.6 requires base64 DER of the leaf cert (no PEM armor).
	// Body "QUJDRA==" decodes to "ABCD" → re-encoded as base64 = "QUJDRA==".
	if capturedPayload["file_content"] != "QUJDRA==" {
		t.Errorf("file_content = %q, want base64 DER of leaf", capturedPayload["file_content"])
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
		_, _ = io.WriteString(w, `{"error":-145}`)
	}))
	defer srv.Close()

	c := newTestClient(t, srv, "")
	certPEM := []byte("-----BEGIN CERTIFICATE-----\nQUJDRA==\n-----END CERTIFICATE-----\n")
	keyPEM := []byte("-----BEGIN EC PRIVATE KEY-----\nS0VZQk9EWQ==\n-----END EC PRIVATE KEY-----\n")
	err := c.ImportCertificate(context.Background(), "mycert", certPEM, keyPEM)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestImportCertificate_ChainInput(t *testing.T) {
	// When certPEM contains leaf + intermediate, only the leaf must be sent
	// in the /local/import call. Intermediates are uploaded separately via
	// ImportCACertificate; bundling them in file_content used to break
	// FortiOS's TLS handshake because it parsed only the first ASN.1
	// SEQUENCE and discarded the trailing intermediate bytes.
	var capturedPayload map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&capturedPayload)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	chainPEM := []byte(
		"-----BEGIN CERTIFICATE-----\nQUJDRA==\n-----END CERTIFICATE-----\n" +
			"-----BEGIN CERTIFICATE-----\nRUZHSA==\n-----END CERTIFICATE-----\n")
	keyPEM := []byte("-----BEGIN EC PRIVATE KEY-----\nS0VZQk9EWQ==\n-----END EC PRIVATE KEY-----\n")

	c := newTestClient(t, srv, "")
	if err := c.ImportCertificate(context.Background(), "mycert", chainPEM, keyPEM); err != nil {
		t.Fatalf("ImportCertificate: %v", err)
	}
	if capturedPayload["file_content"] != "QUJDRA==" {
		t.Errorf("file_content = %q, want leaf only (\"QUJDRA==\")", capturedPayload["file_content"])
	}
	if strings.Contains(capturedPayload["file_content"], "RUZHSA") {
		t.Errorf("file_content leaked intermediate bytes: %q", capturedPayload["file_content"])
	}
}

func TestImportCertificate_AlreadyExists(t *testing.T) {
	// FortiOS returns HTTP 500 with {"error":-23} when the same cert is
	// imported twice. We treat that as success.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"error":-23,"status":"error"}`)
	}))
	defer srv.Close()

	c := newTestClient(t, srv, "")
	certPEM := []byte("-----BEGIN CERTIFICATE-----\nQUJDRA==\n-----END CERTIFICATE-----\n")
	keyPEM := []byte("-----BEGIN EC PRIVATE KEY-----\nS0VZ\n-----END EC PRIVATE KEY-----\n")
	if err := c.ImportCertificate(context.Background(), "mycert", certPEM, keyPEM); err != nil {
		t.Fatalf("ImportCertificate with -23 should return nil, got %v", err)
	}
}

func TestDeleteCertificate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("method = %s, want DELETE", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/api/v2/cmdb/vpn.certificate/local/oldcert") {
			t.Errorf("path = %s, want suffix /api/v2/cmdb/vpn.certificate/local/oldcert", r.URL.Path)
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
	var capturedPayload map[string]interface{}
	var capturedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			// Single-cert string field (legacy/normal case).
			_, _ = io.WriteString(w, `{"results":[{"name":"vip1","server-cert":"oldcert"}]}`)
		case http.MethodPut:
			capturedPath = r.URL.Path
			_ = json.NewDecoder(r.Body).Decode(&capturedPayload)
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected method %s", r.Method)
		}
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
	if got, _ := capturedPayload["server-cert"].(string); got != "newcert" {
		t.Errorf("server-cert payload = %v, want \"newcert\"", capturedPayload["server-cert"])
	}
}

func TestUpdateCertReference_MultiValueString(t *testing.T) {
	// FortiGate ssl-ssh-profile in "Protecting SSL Server" (replace) mode
	// returns multiple cert names in a single space-separated string. The
	// rebind must swap only the matching cert and preserve siblings.
	var capturedPayload map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_, _ = io.WriteString(w, `{"results":{"server-cert":"tm_lestang_dk_07052026 wildcard_aaris_tech_07052026 wildcard_aaris_wtf_07052026"}}`)
		case http.MethodPut:
			_ = json.NewDecoder(r.Body).Decode(&capturedPayload)
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected method %s", r.Method)
		}
	}))
	defer srv.Close()

	c := newTestClient(t, srv, "")
	ref := CertReference{
		Endpoint: "firewall/ssl-ssh-profile",
		MKey:     "custom-deep-inspection",
		Field:    "server-cert",
		OldValue: "tm_lestang_dk_07052026",
	}
	if err := c.UpdateCertReference(context.Background(), ref, "tm_lestang_dk_15052026"); err != nil {
		t.Fatalf("UpdateCertReference: %v", err)
	}
	got, _ := capturedPayload["server-cert"].(string)
	want := "tm_lestang_dk_15052026 wildcard_aaris_tech_07052026 wildcard_aaris_wtf_07052026"
	if got != want {
		t.Errorf("server-cert payload =\n  %q\nwant\n  %q", got, want)
	}
}

func TestUpdateCertReference_MultiValueArray(t *testing.T) {
	// FortiGate sometimes returns multi-value fields as an array of
	// {q_origin_key, name} objects. Verify the same preservation logic.
	var capturedPayload map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_, _ = io.WriteString(w, `{"results":{"server-cert":[
				{"q_origin_key":"tm_lestang_dk_07052026","name":"tm_lestang_dk_07052026"},
				{"q_origin_key":"wildcard_aaris_tech_07052026","name":"wildcard_aaris_tech_07052026"}
			]}}`)
		case http.MethodPut:
			_ = json.NewDecoder(r.Body).Decode(&capturedPayload)
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected method %s", r.Method)
		}
	}))
	defer srv.Close()

	c := newTestClient(t, srv, "")
	ref := CertReference{
		Endpoint: "firewall/ssl-ssh-profile",
		MKey:     "custom-deep-inspection",
		Field:    "server-cert",
		OldValue: "tm_lestang_dk_07052026",
	}
	if err := c.UpdateCertReference(context.Background(), ref, "tm_lestang_dk_15052026"); err != nil {
		t.Fatalf("UpdateCertReference: %v", err)
	}
	arr, ok := capturedPayload["server-cert"].([]interface{})
	if !ok {
		t.Fatalf("server-cert payload is not array: %#v", capturedPayload["server-cert"])
	}
	if len(arr) != 2 {
		t.Fatalf("array length = %d, want 2", len(arr))
	}
	names := []string{}
	for _, item := range arr {
		if m, ok := item.(map[string]interface{}); ok {
			if n, _ := m["name"].(string); n != "" {
				names = append(names, n)
			}
		}
	}
	if names[0] != "tm_lestang_dk_15052026" {
		t.Errorf("names[0] = %q, want renamed entry", names[0])
	}
	if names[1] != "wildcard_aaris_tech_07052026" {
		t.Errorf("names[1] = %q, want preserved sibling", names[1])
	}
}

func TestFindCertReferences_MultiValueString(t *testing.T) {
	// ssl-ssh-profile returns a list of profiles. One has server-cert as a
	// space-separated multi-value string. valueContainsCert must split.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "firewall/ssl-ssh-profile"):
			_, _ = io.WriteString(w, `{"results":[{"name":"custom-deep-inspection","server-cert":"tm_lestang_dk_07052026 wildcard_aaris_tech_07052026"}]}`)
		default:
			_, _ = io.WriteString(w, `{"results":[]}`)
		}
	}))
	defer srv.Close()

	c := newTestClient(t, srv, "")
	refs, err := c.FindCertReferences(context.Background(), "tm_lestang_dk_07052026")
	if err != nil {
		t.Fatalf("FindCertReferences: %v", err)
	}
	found := false
	for _, r := range refs {
		if r.Endpoint == "firewall/ssl-ssh-profile" && r.MKey == "custom-deep-inspection" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected multi-value ssl-ssh-profile reference, got: %+v", refs)
	}
}

func TestGetCertificateByPattern(t *testing.T) {
	// CMDB response (FortiOS 7.6.6) — no validity dates, so ordering must
	// fall back to the _ddMMyyyy suffix encoded in the cert name.
	body := `{
		"results": [
			{"name":"example_com","source":"user","last-updated":0},
			{"name":"example_com_07052026","source":"user","last-updated":0},
			{"name":"example_com_01012025","source":"user","last-updated":0},
			{"name":"unrelated_cert","source":"user","last-updated":0}
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

func TestStripPEMHeaders(t *testing.T) {
	pem := "-----BEGIN CERTIFICATE-----\nABCD\nEFGH\n-----END CERTIFICATE-----\n"
	got := stripPEMHeaders([]byte(pem))
	if got != "ABCDEFGH" {
		t.Errorf("got %q, want %q", got, "ABCDEFGH")
	}
}

func TestSplitPEMChain(t *testing.T) {
	leaf := "-----BEGIN CERTIFICATE-----\nQUJDRA==\n-----END CERTIFICATE-----\n"
	inter := "-----BEGIN CERTIFICATE-----\nRUZHSA==\n-----END CERTIFICATE-----\n"
	keyBlock := "-----BEGIN EC PRIVATE KEY-----\nS0VZ\n-----END EC PRIVATE KEY-----\n"

	t.Run("two CERTIFICATE blocks", func(t *testing.T) {
		blocks, err := splitPEMChain([]byte(leaf + inter))
		if err != nil {
			t.Fatalf("splitPEMChain: %v", err)
		}
		if len(blocks) != 2 {
			t.Fatalf("len = %d, want 2", len(blocks))
		}
		if blocks[0].Type != "CERTIFICATE" || blocks[1].Type != "CERTIFICATE" {
			t.Errorf("types = %q, %q", blocks[0].Type, blocks[1].Type)
		}
		if string(blocks[0].Bytes) != "ABCD" {
			t.Errorf("blocks[0].Bytes = %q, want ABCD", string(blocks[0].Bytes))
		}
	})

	t.Run("single CERTIFICATE block", func(t *testing.T) {
		blocks, err := splitPEMChain([]byte(leaf))
		if err != nil {
			t.Fatalf("splitPEMChain: %v", err)
		}
		if len(blocks) != 1 {
			t.Errorf("len = %d, want 1", len(blocks))
		}
	})

	t.Run("non-CERTIFICATE blocks are skipped", func(t *testing.T) {
		blocks, err := splitPEMChain([]byte(keyBlock + leaf))
		if err != nil {
			t.Fatalf("splitPEMChain: %v", err)
		}
		if len(blocks) != 1 || blocks[0].Type != "CERTIFICATE" {
			t.Errorf("got %d blocks, first type = %q", len(blocks), blocks[0].Type)
		}
	})

	t.Run("garbage input errors", func(t *testing.T) {
		if _, err := splitPEMChain([]byte("not a pem block")); err == nil {
			t.Error("expected error on non-PEM input")
		}
	})

	t.Run("empty input errors", func(t *testing.T) {
		if _, err := splitPEMChain(nil); err == nil {
			t.Error("expected error on empty input")
		}
	})
}

func TestImportCACertificate(t *testing.T) {
	var capturedPayload map[string]string
	var capturedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		capturedPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&capturedPayload)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(t, srv, "")
	caDER := []byte("DERBYTES")
	if err := c.ImportCACertificate(context.Background(), "chain_abcd1234", caDER); err != nil {
		t.Fatalf("ImportCACertificate: %v", err)
	}
	if !strings.HasSuffix(capturedPath, "/api/v2/monitor/vpn-certificate/ca/import") {
		t.Errorf("path = %s", capturedPath)
	}
	if capturedPayload["certname"] != "chain_abcd1234" {
		t.Errorf("certname = %q", capturedPayload["certname"])
	}
	if capturedPayload["import_method"] != "file" {
		t.Errorf("import_method = %q, want file", capturedPayload["import_method"])
	}
	if capturedPayload["scope"] != "global" {
		t.Errorf("scope = %q, want global", capturedPayload["scope"])
	}
	// "DERBYTES" base64-encoded is "REVSQllURVM=".
	if capturedPayload["file_content"] != "REVSQllURVM=" {
		t.Errorf("file_content = %q, want base64(DERBYTES)", capturedPayload["file_content"])
	}
	if _, hasKey := capturedPayload["key_file_content"]; hasKey {
		t.Error("ImportCACertificate must not send key_file_content")
	}
}

func TestImportCACertificate_AlreadyExists(t *testing.T) {
	// Renewals re-import the same intermediate every time. FortiOS returns
	// error -23, which we swallow so a renewal isn't a hard failure.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"error":-23,"status":"error"}`)
	}))
	defer srv.Close()

	c := newTestClient(t, srv, "")
	if err := c.ImportCACertificate(context.Background(), "chain_abcd1234", []byte("DER")); err != nil {
		t.Fatalf("ImportCACertificate with -23 should return nil, got %v", err)
	}
}
