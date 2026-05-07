package forticertsync

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"go.uber.org/zap"
)

// rebindMockServer simulates the FortiGate endpoints touched by RebindCertificates.
// State (which references still point to oldCert, whether old cert was deleted)
// can be inspected after the run.
type rebindMockServer struct {
	*httptest.Server
	importCalls atomic.Int32
	deleteCalls atomic.Int32

	oldRefsRemaining atomic.Int32 // number of refs still pointing to oldCert
	updateFailFor    string       // path containing this substring -> update returns 500
}

func newRebindMockServer(initialRefs int) *rebindMockServer {
	m := &rebindMockServer{}
	m.oldRefsRemaining.Store(int32(initialRefs))

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/monitor/vpn-certificate/local/import", func(w http.ResponseWriter, r *http.Request) {
		m.importCalls.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"status":"success"}`)
	})
	mux.HandleFunc("/api/v2/monitor/vpn-certificate/local/clear", func(w http.ResponseWriter, r *http.Request) {
		m.deleteCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	})

	// CMDB GET endpoints — return references depending on remaining count.
	mux.HandleFunc("/api/v2/cmdb/vpn.ssl/settings", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if m.oldRefsRemaining.Load() > 0 {
				_, _ = io.WriteString(w, `{"results":{"servercert":"oldcert"}}`)
			} else {
				_, _ = io.WriteString(w, `{"results":{"servercert":"newcert"}}`)
			}
		case http.MethodPut:
			if m.updateFailFor != "" && strings.Contains(r.URL.Path, m.updateFailFor) {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			m.oldRefsRemaining.Add(-1)
			w.WriteHeader(http.StatusOK)
		}
	})
	mux.HandleFunc("/api/v2/cmdb/firewall/vip", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"results":[]}`)
	})
	mux.HandleFunc("/api/v2/cmdb/system/global", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"results":{"admin-server-cert":"different"}}`)
	})
	mux.HandleFunc("/api/v2/cmdb/firewall/ssl-ssh-profile", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"results":[]}`)
	})

	m.Server = httptest.NewServer(mux)
	return m
}

func TestRebindCertificates_HappyPath(t *testing.T) {
	srv := newRebindMockServer(1)
	defer srv.Close()

	c := NewFortiGateClient(srv.URL, "tok", "", true, zap.NewNop())
	err := RebindCertificates(context.Background(), c, zap.NewNop(),
		"oldcert", "newcert", []byte("CERTPEM"), []byte("KEYPEM"))
	if err != nil {
		t.Fatalf("RebindCertificates: %v", err)
	}
	if srv.importCalls.Load() != 1 {
		t.Errorf("import calls = %d, want 1", srv.importCalls.Load())
	}
	if srv.deleteCalls.Load() != 1 {
		t.Errorf("delete calls = %d, want 1 (refs all rebound, old cert should be deleted)", srv.deleteCalls.Load())
	}
}

func TestRebindCertificates_NoReferences(t *testing.T) {
	// No refs from the start: import succeeds, no PUTs needed, old cert is
	// still deleted because zero refs remain.
	srv := newRebindMockServer(0)
	defer srv.Close()

	c := NewFortiGateClient(srv.URL, "tok", "", true, zap.NewNop())
	err := RebindCertificates(context.Background(), c, zap.NewNop(),
		"oldcert", "newcert", []byte("p"), []byte("k"))
	if err != nil {
		t.Fatalf("RebindCertificates: %v", err)
	}
	if srv.importCalls.Load() != 1 {
		t.Errorf("import calls = %d, want 1", srv.importCalls.Load())
	}
	if srv.deleteCalls.Load() != 1 {
		t.Errorf("delete calls = %d, want 1", srv.deleteCalls.Load())
	}
}

func TestRebindCertificates_PartialRebindFailure(t *testing.T) {
	// Make the PUT to vpn.ssl/settings fail. Rebind should error out and
	// the old cert must NOT be deleted.
	srv := newRebindMockServer(1)
	srv.updateFailFor = "vpn.ssl/settings"
	defer srv.Close()

	c := NewFortiGateClient(srv.URL, "tok", "", true, zap.NewNop())
	err := RebindCertificates(context.Background(), c, zap.NewNop(),
		"oldcert", "newcert", []byte("p"), []byte("k"))
	if err == nil {
		t.Fatal("expected error from partial rebind failure")
	}
	if srv.deleteCalls.Load() != 0 {
		t.Errorf("delete calls = %d, want 0 on rebind failure", srv.deleteCalls.Load())
	}
}

// rebindStuckRefServer simulates a scenario where the rebind PUT silently
// succeeds but a follow-up GET still reports the old reference. Old cert
// must NOT be deleted in that case.
func TestRebindCertificates_ReferencesRemainAfterRebind(t *testing.T) {
	var importCalls, deleteCalls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/monitor/vpn-certificate/local/import", func(w http.ResponseWriter, r *http.Request) {
		importCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/api/v2/monitor/vpn-certificate/local/clear", func(w http.ResponseWriter, r *http.Request) {
		deleteCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	})
	// Always report the old cert as still bound, regardless of PUTs.
	mux.HandleFunc("/api/v2/cmdb/vpn.ssl/settings", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			w.WriteHeader(http.StatusOK)
			return
		}
		_, _ = io.WriteString(w, `{"results":{"servercert":"oldcert"}}`)
	})
	mux.HandleFunc("/api/v2/cmdb/firewall/vip", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"results":[]}`)
	})
	mux.HandleFunc("/api/v2/cmdb/system/global", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"results":{}}`)
	})
	mux.HandleFunc("/api/v2/cmdb/firewall/ssl-ssh-profile", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"results":[]}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewFortiGateClient(srv.URL, "tok", "", true, zap.NewNop())
	err := RebindCertificates(context.Background(), c, zap.NewNop(),
		"oldcert", "newcert", []byte("p"), []byte("k"))
	if err != nil {
		t.Fatalf("RebindCertificates returned error: %v (should be nil — non-fatal)", err)
	}
	if importCalls.Load() != 1 {
		t.Errorf("import calls = %d, want 1", importCalls.Load())
	}
	if deleteCalls.Load() != 0 {
		t.Errorf("delete calls = %d, want 0 (refs remained)", deleteCalls.Load())
	}
}
