package forticertsync

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"go.uber.org/zap"
)

// The profile as it actually stood on JAHE-FW01 when publishing
// music.jackjack.dk failed: 10 of 10 slots taken.
var fullProfile = []string{
	"www_tm_lestang_dk_22062026",
	"wildcard_aaris_wtf_21052026",
	"wildcard_aaris_tech_22062026",
	"tm_lestang_dk_21052026",
	"finebox_nikodyring_dev_22062026",
	"sif_nikodyring_dev_22062026",
	"antistasi_nikodyring_dev_17072026",
	"nikodyring_dev_17072026",
	"hofferson_com_21072026",
	"jackjack_dk_26072026",
}

// fakeFortiGate is a mock FortiOS CMDB good enough to drive the migration.
type fakeFortiGate struct {
	mu          sync.Mutex
	serverCerts []string
	deleted     []string
	puts        int
	refs        map[string]bool // cert name -> still referenced somewhere else
}

func (f *fakeFortiGate) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		path := r.URL.Path

		switch {
		case strings.HasPrefix(path, "/api/v2/cmdb/firewall/ssl-ssh-profile/"):
			if r.Method == http.MethodPut {
				f.puts++
				var body struct {
					Mode  string              `json:"server-cert-mode"`
					Certs []map[string]string `json:"server-cert"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Errorf("bad PUT body: %v", err)
				}
				if body.Mode != "replace" {
					t.Errorf("server-cert-mode = %q, want replace", body.Mode)
				}
				if len(body.Certs) > serverCertMax {
					// This is the FortiOS behavior the whole feature exists to
					// avoid tripping.
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = io.WriteString(w, `{"error":-4,"cli_error":["Too many server certificate entries. Maximum number of entries: 10"]}`)
					return
				}
				f.serverCerts = nil
				for _, c := range body.Certs {
					f.serverCerts = append(f.serverCerts, c["name"])
				}
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, `{"status":"success"}`)
				return
			}
			entries := make([]map[string]string, 0, len(f.serverCerts))
			for _, n := range f.serverCerts {
				entries = append(entries, map[string]string{"name": n})
			}
			out, _ := json.Marshal(map[string]any{"results": map[string]any{"server-cert": entries}})
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(out)

		case strings.HasPrefix(path, "/api/v2/cmdb/vpn.certificate/local/"):
			if r.Method == http.MethodDelete {
				name := strings.TrimPrefix(path, "/api/v2/cmdb/vpn.certificate/local/")
				f.deleted = append(f.deleted, name)
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, `{"status":"success"}`)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"results":[]}`)

		// Reference lookups: firewall/vip and the other endpoints. Report a
		// reference only for certs the test marked as still in use.
		case strings.HasPrefix(path, "/api/v2/cmdb/firewall/vip"):
			var results []map[string]any
			for name, referenced := range f.refs {
				if referenced {
					results = append(results, map[string]any{"name": "vip_" + name, "server-cert": name})
				}
			}
			out, _ := json.Marshal(map[string]any{"results": results})
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(out)

		default:
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"results":[]}`)
		}
	}
}

func newMigrationManager(t *testing.T, fake *fakeFortiGate, managed map[string]string) (*bundleManager, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(fake.handler(t))
	m := &bundleManager{
		cfg:    homelabBundle(),
		client: NewFortiGateClient(srv.URL, "tok", "root", true, zap.NewNop()),
		logger: zap.NewNop(),
		state:  bundleState{Managed: managed},
	}
	return m, srv
}

// The core of the migration: on a profile that is already at 10 of 10, the
// bundle must go in and the certificates it supersedes must come out in ONE
// PUT. Adding first and pruning after would need an 11th slot and be rejected.
func TestBindProfileSwapsAtTheCapInOnePut(t *testing.T) {
	fake := &fakeFortiGate{serverCerts: append([]string{}, fullProfile...)}
	m, srv := newMigrationManager(t, fake, map[string]string{
		"www_tm_lestang_dk":        "www.tm-lestang.dk",
		"finebox_nikodyring_dev":   "finebox.nikodyring.dev",
		"sif_nikodyring_dev":       "sif.nikodyring.dev",
		"antistasi_nikodyring_dev": "antistasi.nikodyring.dev",
	})
	defer srv.Close()

	if err := m.bindProfile(context.Background(), "homelabrrr_inspection_30072026", nil); err != nil {
		t.Fatalf("bindProfile: %v", err)
	}

	if fake.puts != 1 {
		t.Errorf("want exactly 1 PUT (atomic swap), got %d", fake.puts)
	}
	if len(fake.serverCerts) != 1 || fake.serverCerts[0] != "homelabrrr_inspection_30072026" {
		t.Fatalf("profile should hold only the bundle, got %v", fake.serverCerts)
	}
	// Every superseded cert is provably covered, so all 10 get deleted.
	if len(fake.deleted) != len(fullProfile) {
		t.Errorf("want %d superseded certs deleted, got %d: %v", len(fullProfile), len(fake.deleted), fake.deleted)
	}
}

// A certificate the bundle does not cover must survive the swap and keep its
// slot, rather than being silently dropped.
func TestBindProfileKeepsUncoveredCertificates(t *testing.T) {
	fake := &fakeFortiGate{serverCerts: []string{
		"jackjack_dk_26072026",    // covered by the jackjack.dk zone
		"unrelated_corp_01062026", // NOT in any zone
		"Fortinet_Factory",        // built-in, definitely not ours
	}}
	m, srv := newMigrationManager(t, fake, map[string]string{})
	defer srv.Close()

	if err := m.bindProfile(context.Background(), "homelabrrr_inspection_30072026", nil); err != nil {
		t.Fatalf("bindProfile: %v", err)
	}

	got := map[string]bool{}
	for _, n := range fake.serverCerts {
		got[n] = true
	}
	if !got["homelabrrr_inspection_30072026"] {
		t.Error("bundle must be attached")
	}
	if !got["unrelated_corp_01062026"] || !got["Fortinet_Factory"] {
		t.Errorf("uncovered certificates must be kept, got %v", fake.serverCerts)
	}
	if got["jackjack_dk_26072026"] {
		t.Error("covered certificate should have been swapped out")
	}
	for _, d := range fake.deleted {
		if d == "unrelated_corp_01062026" || d == "Fortinet_Factory" {
			t.Errorf("must never delete an uncovered certificate, deleted %q", d)
		}
	}
}

// A superseded certificate that something else still points at (a VIP, say)
// must be detached from the profile but NOT deleted — deleting it would break
// that object, and FortiOS would refuse anyway.
func TestDeleteSupersededSkipsStillReferencedCerts(t *testing.T) {
	fake := &fakeFortiGate{
		serverCerts: []string{"jackjack_dk_26072026"},
		refs:        map[string]bool{"jackjack_dk_26072026": true},
	}
	m, srv := newMigrationManager(t, fake, map[string]string{})
	defer srv.Close()

	if err := m.bindProfile(context.Background(), "homelabrrr_inspection_30072026", nil); err != nil {
		t.Fatalf("bindProfile: %v", err)
	}
	if len(fake.deleted) != 0 {
		t.Errorf("a still-referenced certificate must not be deleted, deleted %v", fake.deleted)
	}
}

// migrate=off attaches the bundle but leaves the old certificates in place.
func TestBindProfileMigrateOffKeepsOldCertificates(t *testing.T) {
	fake := &fakeFortiGate{serverCerts: []string{"jackjack_dk_26072026"}}
	m, srv := newMigrationManager(t, fake, map[string]string{})
	defer srv.Close()
	m.cfg.Migrate = "off"

	if err := m.bindProfile(context.Background(), "homelabrrr_inspection_30072026", nil); err != nil {
		t.Fatalf("bindProfile: %v", err)
	}
	if len(fake.deleted) != 0 {
		t.Errorf("migrate=off must not delete anything, deleted %v", fake.deleted)
	}
	if len(fake.serverCerts) != 1 || fake.serverCerts[0] != "homelabrrr_inspection_30072026" {
		t.Errorf("bundle should still replace the covered entry in the profile, got %v", fake.serverCerts)
	}
}

// If the bundle covers nothing on a full profile, we must fail with a message
// that says what to do — not send an 11-entry PUT that FortiOS rejects.
func TestBindProfileRefusesWhenNothingIsSuperseded(t *testing.T) {
	uncovered := make([]string, 0, serverCertMax)
	for i := 0; i < serverCertMax; i++ {
		uncovered = append(uncovered, "unrelated"+string(rune('a'+i))+"_01062026")
	}
	fake := &fakeFortiGate{serverCerts: uncovered}
	m, srv := newMigrationManager(t, fake, map[string]string{})
	defer srv.Close()

	err := m.bindProfile(context.Background(), "homelabrrr_inspection_30072026", nil)
	if err == nil {
		t.Fatal("want an error when the bundle cannot free a slot")
	}
	if !strings.Contains(err.Error(), "supersede") || !strings.Contains(err.Error(), "inbound-deep-inspection") {
		t.Errorf("error should name the profile and suggest a fix, got: %v", err)
	}
	if fake.puts != 0 {
		t.Errorf("must not attempt a PUT that exceeds the cap, made %d", fake.puts)
	}
}

// Re-running when the profile is already correct must be a no-op.
func TestBindProfileIsIdempotent(t *testing.T) {
	fake := &fakeFortiGate{serverCerts: []string{"homelabrrr_inspection_30072026"}}
	m, srv := newMigrationManager(t, fake, map[string]string{})
	defer srv.Close()

	if err := m.bindProfile(context.Background(), "homelabrrr_inspection_30072026", nil); err != nil {
		t.Fatalf("bindProfile: %v", err)
	}
	if fake.puts != 0 {
		t.Errorf("no PUT should be issued when the profile already matches, made %d", fake.puts)
	}
}

func TestSetProfileServerCertsGuardsTheCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("no request should reach the FortiGate")
	}))
	defer srv.Close()
	c := NewFortiGateClient(srv.URL, "tok", "root", true, zap.NewNop())

	tooMany := make([]string, serverCertMax+1)
	for i := range tooMany {
		tooMany[i] = "c" + string(rune('a'+i))
	}
	if err := c.SetProfileServerCerts(context.Background(), "p", tooMany); err == nil {
		t.Error("want an error above the cap")
	}
	if err := c.SetProfileServerCerts(context.Background(), "p", nil); err == nil {
		t.Error("want an error when clearing the list entirely")
	}
}

func TestCertNamesFromValue(t *testing.T) {
	fromArray := certNamesFromValue([]any{
		map[string]any{"name": "a_01012026"},
		map[string]any{"q_origin_key": "b_01012026"},
	})
	if len(fromArray) != 2 || fromArray[0] != "a_01012026" || fromArray[1] != "b_01012026" {
		t.Errorf("array form: %v", fromArray)
	}
	fromString := certNamesFromValue(`"a_01012026" "b_01012026"`)
	if len(fromString) != 2 || fromString[0] != "a_01012026" {
		t.Errorf("string form: %v", fromString)
	}
	if len(certNamesFromValue(nil)) != 0 {
		t.Error("nil should yield no names")
	}
}
