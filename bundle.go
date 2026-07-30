package forticertsync

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

// InspectionBundle is the "one certificate for the whole FortiGate" mode.
//
// Why it exists: a FortiOS SSL/SSH inspection profile accepts at most 10
// entries in its inbound `server-cert` list. Syncing one Caddy certificate per
// hostname burns a slot per site and the profile fills up — and because FortiOS
// refuses to delete a certificate a profile still references, the old ones
// cannot even be cleared. Publishing an 11th site then fails outright.
//
// The fix is to stop mirroring Caddy's certificates and instead maintain ONE
// certificate whose SAN list covers every name the FortiGate needs to inspect.
// Caddy keeps issuing and serving its own per-site certificates exactly as
// before; the bundle exists solely to be presented by the FortiGate, which
// picks it for every SNI in its SAN list.
//
// The bundle cannot be assembled from certificates Caddy has already issued —
// a SAN list is inside the CA-signed portion of a certificate, so combining
// names means a new ACME order. This type places that order itself, using the
// certmagic ACME issuer that already ships inside Caddy (no new dependency).
//
// Wildcards require DNS-01 validation, so every zone in the bundle needs DNS
// API credentials. Zones without them cannot be bundled; they keep their own
// per-domain certificate and their own slot (see Handler.Handle).
type InspectionBundle struct {
	// Name is the FortiGate certificate base name. The live object is
	// "{name}_{ddMMyyyy}", same convention as per-domain syncing.
	Name string `json:"name,omitempty"`

	// Zones lists the parent domains the bundle covers.
	Zones []BundleZone `json:"zones,omitempty"`

	// Profile is the SSL/SSH inspection profile to bind the bundle to. When
	// empty, the bundle is imported and existing references are rebound, but
	// no profile is newly bound — matching per-domain behavior.
	Profile string `json:"profile,omitempty"`

	// Email is the ACME account contact. Falls back to Caddy's global email.
	Email string `json:"email,omitempty"`

	// CA is the ACME directory URL. Defaults to Let's Encrypt production.
	// Point this at the staging directory while testing — a bundle covering
	// many zones is exactly the kind of order you do not want to rate-limit.
	CA string `json:"ca,omitempty"`

	// RenewBefore is how much remaining validity triggers a renewal.
	// Default 30 days.
	RenewBefore caddy.Duration `json:"renew_before,omitempty"`

	// CheckInterval is how often the bundle's expiry is re-checked.
	// Default 12h. See the comment on Handler.startBundleTicker for why this
	// mode needs a timer when per-domain syncing does not.
	CheckInterval caddy.Duration `json:"check_interval,omitempty"`

	// Migrate controls what happens to the per-domain certificates the bundle
	// supersedes. "off" leaves them alone; "cleanup" (the default) swaps them
	// out of the inspection profile in the same PUT that adds the bundle, then
	// deletes the ones that are provably unreferenced afterwards.
	Migrate string `json:"migrate,omitempty"`

	// Supersede lists extra FortiGate certificate base names to treat as
	// covered by the bundle during migration. Use it for certificates whose
	// coverage cannot be proven automatically — see supersededNames.
	Supersede []string `json:"supersede,omitempty"`

	// DNSRaw is the Caddy DNS provider module (dns.providers.*) used to solve
	// the DNS-01 challenges. Same module you already use in a `tls` block.
	DNSRaw json.RawMessage `json:"dns,omitempty" caddy:"namespace=dns.providers inline_key=name"`
}

// BundleZone is one parent domain's contribution to the bundle's SAN list.
type BundleZone struct {
	// Domain is the parent, e.g. "jackjack.dk".
	Domain string `json:"domain"`

	// Wildcard adds "*.<domain>" — one SAN covering every direct subdomain,
	// which is what makes publishing a new site cost nothing on the FortiGate.
	// Defaults to true.
	Wildcard *bool `json:"wildcard,omitempty"`

	// Apex adds "<domain>" itself. A wildcard does NOT cover the apex, so both
	// are needed to serve example.com and app.example.com. Defaults to true.
	Apex *bool `json:"apex,omitempty"`

	// Names adds further explicit hostnames. Needed for depth-2 names like
	// "a.b.example.com", which "*.example.com" does not cover.
	Names []string `json:"names,omitempty"`
}

const (
	defaultBundleRenewBefore   = 30 * 24 * time.Hour
	defaultBundleCheckInterval = 12 * time.Hour
	// Let's Encrypt allows 100 identifiers per certificate.
	maxBundleIdentifiers = 100
)

// bundleState is the plugin's record of which FortiGate certificate name was
// synced for which Caddy identifier. Migration uses it to prove a per-domain
// certificate is superseded by the bundle instead of guessing from the name,
// which is not reversible (both "a-b.example.com" and "a.b.example.com"
// sanitize to "a_b_example_com", and only the first is wildcard-covered).
type bundleState struct {
	// Managed maps FortiGate cert base name -> Caddy identifier.
	Managed map[string]string `json:"managed"`
}

type bundleManager struct {
	cfg     *InspectionBundle
	client  *FortiGateClient
	logger  *zap.Logger
	dataDir string

	issuer *certmagic.ACMEIssuer

	mu    sync.Mutex // serializes reconcile; the ticker and events both call it
	state bundleState

	// baseCtx is cancelled by stopTicker so a reconcile already in flight is
	// interrupted. Without it, shutdown blocks until an ACME order finishes:
	// the worker only observes `stop` between ticks, never from inside
	// reconcile, which can take minutes.
	baseCtx    context.Context
	cancelWork context.CancelFunc

	stop chan struct{}
	done chan struct{}
}

// enabled reports whether bundle mode is configured.
func (b *InspectionBundle) enabled() bool {
	return b != nil && b.Name != "" && len(b.Zones) > 0
}

func boolOr(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

// Subjects returns the bundle's SAN list: deduplicated, sorted so the set is
// comparable across runs, and validated against the CA's identifier cap.
func (b *InspectionBundle) Subjects() ([]string, error) {
	seen := map[string]bool{}
	var out []string
	add := func(name string) {
		n := strings.ToLower(strings.TrimSpace(name))
		if n == "" || seen[n] {
			return
		}
		seen[n] = true
		out = append(out, n)
	}
	for _, z := range b.Zones {
		domain := strings.ToLower(strings.TrimSpace(z.Domain))
		if domain == "" {
			return nil, fmt.Errorf("inspection_bundle: zone with empty domain")
		}
		if boolOr(z.Apex, true) {
			add(domain)
		}
		if boolOr(z.Wildcard, true) {
			add("*." + domain)
		}
		for _, n := range z.Names {
			add(n)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("inspection_bundle: no subjects derived from zones")
	}
	if len(out) > maxBundleIdentifiers {
		return nil, fmt.Errorf("inspection_bundle: %d identifiers exceeds the %d-per-certificate limit", len(out), maxBundleIdentifiers)
	}
	sort.Strings(out)
	return out, nil
}

// covers reports whether the bundle's SAN list already accounts for a Caddy
// identifier, i.e. whether syncing that identifier separately would waste a
// FortiGate slot. Wildcard matching is single-label, as in TLS itself.
func (b *InspectionBundle) covers(identifier string) bool {
	id := strings.ToLower(strings.TrimSpace(identifier))
	if id == "" {
		return false
	}
	subjects, err := b.Subjects()
	if err != nil {
		return false
	}
	for _, s := range subjects {
		if s == id {
			return true
		}
		if strings.HasPrefix(s, "*.") {
			base := s[2:]
			if strings.HasSuffix(id, "."+base) {
				label := id[:len(id)-len(base)-1]
				if label != "" && !strings.Contains(label, ".") {
					return true
				}
			}
		}
	}
	return false
}

// ── Issuance ─────────────────────────────────────────────────────────────────

// bundlePaths returns where the bundle's certificate and key are cached on disk.
// They are kept outside certmagic's managed storage on purpose: certmagic's
// renewal machinery is strictly one-certificate-per-name (Config.manageAll
// iterates the name list), so it cannot own a multi-SAN certificate's lifecycle.
// This plugin owns it instead.
func (m *bundleManager) bundlePaths() (certPath, keyPath, statePath string) {
	dir := filepath.Join(m.dataDir, "forticertsync", "bundle", m.cfg.Name)
	return filepath.Join(dir, "bundle.crt"), filepath.Join(dir, "bundle.key"), filepath.Join(dir, "state.json")
}

// issue places a single ACME order whose CSR carries every subject. certmagic's
// ACMEIssuer.Issue reads csr.DNSNames in full (namesFromCSR -> acmez
// OrderParametersFromCSR), so one order yields one multi-SAN certificate.
func (m *bundleManager) issue(ctx context.Context, subjects []string) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating bundle key: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshaling bundle key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// No CommonName: it has been deprecated for decades, and leaving it empty
	// keeps the SAN list authoritative. All subjects go in DNSNames.
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		DNSNames: subjects,
	}, key)
	if err != nil {
		return nil, nil, fmt.Errorf("creating bundle CSR: %w", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing bundle CSR: %w", err)
	}

	m.logger.Info("ordering inspection bundle certificate",
		zap.String("bundle", m.cfg.Name),
		zap.Int("identifiers", len(subjects)),
		zap.Strings("subjects", subjects))

	issued, err := m.issuer.Issue(ctx, csr)
	if err != nil {
		return nil, nil, fmt.Errorf("ACME order for bundle %q: %w", m.cfg.Name, err)
	}
	return issued.Certificate, keyPEM, nil
}

// loadCached returns the stored bundle certificate, or nil if there is none.
func (m *bundleManager) loadCached() (*x509.Certificate, []byte, []byte) {
	certPath, keyPath, _ := m.bundlePaths()
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, nil
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, nil
	}
	leaf, err := parsePEMCertificate(certPEM)
	if err != nil {
		return nil, nil, nil
	}
	return leaf, certPEM, keyPEM
}

func (m *bundleManager) storeCached(certPEM, keyPEM []byte) error {
	certPath, keyPath, _ := m.bundlePaths()
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return err
	}
	// The bundle's private key is the single most sensitive artifact this
	// plugin holds — it covers every zone in the SAN list.
	return os.WriteFile(keyPath, keyPEM, 0o600)
}

// sanMatches reports whether a cached certificate's SAN list is exactly the
// desired set. A mismatch means a zone was added or removed in config, which
// must force a re-order regardless of remaining validity.
func sanMatches(leaf *x509.Certificate, subjects []string) bool {
	if len(leaf.DNSNames) != len(subjects) {
		return false
	}
	have := make([]string, len(leaf.DNSNames))
	for i, n := range leaf.DNSNames {
		have[i] = strings.ToLower(n)
	}
	sort.Strings(have)
	for i := range subjects {
		if have[i] != subjects[i] {
			return false
		}
	}
	return true
}

// ── State ────────────────────────────────────────────────────────────────────

func (m *bundleManager) loadState() {
	_, _, statePath := m.bundlePaths()
	m.state = bundleState{Managed: map[string]string{}}
	data, err := os.ReadFile(statePath)
	if err != nil {
		return
	}
	var s bundleState
	if err := json.Unmarshal(data, &s); err != nil {
		m.logger.Warn("could not parse bundle state, starting empty", zap.Error(err))
		return
	}
	if s.Managed != nil {
		m.state.Managed = s.Managed
	}
}

func (m *bundleManager) saveState() {
	_, _, statePath := m.bundlePaths()
	if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
		m.logger.Warn("could not create bundle state dir", zap.Error(err))
		return
	}
	data, err := json.MarshalIndent(m.state, "", "  ")
	if err != nil {
		return
	}
	if err := os.WriteFile(statePath, data, 0o600); err != nil {
		m.logger.Warn("could not write bundle state", zap.Error(err))
	}
}

// recordManaged notes that certBaseName on the FortiGate was synced for a Caddy
// identifier. Migration uses this to prove coverage rather than infer it.
func (m *bundleManager) recordManaged(certBaseName, identifier string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state.Managed == nil {
		m.state.Managed = map[string]string{}
	}
	if m.state.Managed[certBaseName] == identifier {
		return
	}
	m.state.Managed[certBaseName] = identifier
	m.saveState()
}
