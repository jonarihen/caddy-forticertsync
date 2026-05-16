// Package forticertsync provides a Caddy v2 event handler that automatically
// syncs renewed TLS certificates into FortiGate firewalls via the FortiOS REST API.
package forticertsync

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyevents"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler is a Caddy event handler that syncs certificates to FortiGate
// when Caddy obtains or renews a TLS certificate.
type Handler struct {
	// FortiGateURL is the base URL of the FortiGate admin interface
	// (e.g., "https://192.168.1.1:4443").
	FortiGateURL string `json:"fortigate_url"`

	// APIToken is the FortiGate REST API bearer token.
	// Supports Caddy placeholders like {env.FORTIGATE_API_TOKEN}.
	APIToken string `json:"api_token"`

	// VDOM is the target VDOM name. Optional. Leave empty if VDOMs are disabled.
	VDOM string `json:"vdom,omitempty"`

	// Certificates defines the mappings between FortiGate cert slot names
	// and the domain identifiers that should trigger a sync.
	Certificates []CertMapping `json:"certificates"`

	// InsecureSkipVerify disables TLS certificate verification when
	// connecting to FortiGate. Common for homelab setups with self-signed
	// admin certificates.
	InsecureSkipVerify bool `json:"insecure_skip_verify,omitempty"`

	logger  *zap.Logger
	client  *FortiGateClient
	dataDir string
}

// CertMapping maps a FortiGate certificate slot to one or more domain identifiers.
type CertMapping struct {
	// Name is the base certificate name on FortiGate (e.g., "example_com").
	// New certificates will be uploaded as "{name}_{ddMMyyyy}".
	Name string `json:"name"`

	// Domains lists the domain identifiers to match against the event's identifier.
	// Supports exact match and wildcard (e.g., "*.example.com").
	// If empty, matches all domains.
	Domains []string `json:"domains,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "events.handlers.forticertsync",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets up the handler.
func (h *Handler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()

	// Resolve any Caddy placeholders in the API token (e.g., {env.VAR})
	repl := caddy.NewReplacer()
	h.APIToken = repl.ReplaceAll(h.APIToken, "")

	// cert_obtained event data carries storage keys (relative paths) rather
	// than absolute filesystem paths, so we need Caddy's data dir to resolve
	// them with filepath.Join in Handle().
	h.dataDir = caddy.AppDataDir()

	h.client = NewFortiGateClient(h.FortiGateURL, h.APIToken, h.VDOM, h.InsecureSkipVerify, h.logger)
	return nil
}

// Validate ensures the configuration is valid.
func (h *Handler) Validate() error {
	if h.FortiGateURL == "" {
		return fmt.Errorf("fortigate_url is required")
	}
	if h.APIToken == "" {
		return fmt.Errorf("api_token is required")
	}
	if len(h.Certificates) == 0 {
		return fmt.Errorf("at least one certificate mapping is required")
	}
	for i, cert := range h.Certificates {
		if cert.Name == "" {
			return fmt.Errorf("certificate mapping %d: name is required", i)
		}
	}
	return nil
}

// Handle processes a cert_obtained event from Caddy.
//
// Note on event data: Caddy's cert_obtained event provides storage keys
// (relative paths like "certificates/<issuer>/<name>/<name>.crt") in
// `certificate_path` and `private_key_path`, not absolute filesystem
// paths. We resolve them against caddy.AppDataDir() captured during
// Provision, which assumes the default filesystem storage backend. For
// non-filesystem storage (consul, vault, etc.), the handler would need
// to access Caddy's storage interface instead.
func (h *Handler) Handle(ctx context.Context, e caddy.Event) error {
	// Extract event metadata
	identifier, _ := e.Data["identifier"].(string)
	certPath, _ := e.Data["certificate_path"].(string)
	keyPath, _ := e.Data["private_key_path"].(string)

	if identifier == "" || certPath == "" || keyPath == "" {
		h.logger.Warn("incomplete cert event data, skipping",
			zap.String("identifier", identifier),
			zap.String("cert_path", certPath),
			zap.String("key_path", keyPath))
		return nil
	}

	h.logger.Info("received cert_obtained event",
		zap.String("identifier", identifier))

	certFullPath := resolveStoragePath(h.dataDir, certPath)
	keyFullPath := resolveStoragePath(h.dataDir, keyPath)

	// Read cert + key PEM from disk. Failures here are logged and swallowed:
	// returning an error from a Caddy event handler can block other handlers
	// registered for the same event from running, and a transient read failure
	// (or non-filesystem storage backend) should not derail Caddy's pipeline.
	certPEM, err := os.ReadFile(certFullPath)
	if err != nil {
		h.logger.Error("failed to read certificate file, skipping FortiGate sync",
			zap.String("cert_path", certFullPath),
			zap.Error(err))
		return nil
	}
	keyPEM, err := os.ReadFile(keyFullPath)
	if err != nil {
		h.logger.Error("failed to read private key file, skipping FortiGate sync",
			zap.String("key_path", keyFullPath),
			zap.Error(err))
		return nil
	}

	// Process each matching cert mapping. Per-mapping sync failures are logged
	// but never returned: a FortiGate being unreachable must not block other
	// Caddy event handlers, and one mapping failing should not skip the rest.
	for _, mapping := range h.Certificates {
		if !matchesDomain(identifier, mapping.Domains) {
			continue
		}

		h.logger.Info("domain matches cert mapping",
			zap.String("identifier", identifier),
			zap.String("mapping_name", mapping.Name))

		if err := h.syncCertToFortiGate(ctx, mapping, certPEM, keyPEM); err != nil {
			h.logger.Error("failed to sync cert to FortiGate",
				zap.String("identifier", identifier),
				zap.String("mapping_name", mapping.Name),
				zap.Error(err))
		}
	}

	return nil
}

// syncCertToFortiGate handles the full sync lifecycle for a single cert mapping.
func (h *Handler) syncCertToFortiGate(ctx context.Context, mapping CertMapping, certPEM, keyPEM []byte) error {
	// Generate date-suffixed cert name
	newCertName := fmt.Sprintf("%s_%s", mapping.Name, time.Now().Format("02012006"))

	// Validate the new cert parses cleanly before any API calls.
	if _, err := parsePEMCertificate(certPEM); err != nil {
		return fmt.Errorf("parsing new certificate: %w", err)
	}

	// Find the current cert on FortiGate matching this mapping's name pattern
	currentCert, err := h.client.GetCertificateByPattern(ctx, mapping.Name)
	if err != nil {
		h.logger.Warn("could not retrieve current cert from FortiGate, will attempt fresh import",
			zap.String("pattern", mapping.Name),
			zap.Error(err))
	}

	if currentCert != nil {
		// The FortiGate CMDB does not expose certificate validity dates on
		// FortiOS 7.6.6, so we compare by date-suffixed name instead. If a
		// cert with today's suffix already exists, the renewal has already
		// been synced — skip. Otherwise proceed to rebind.
		if currentCert.Name == newCertName {
			h.logger.Info("cert on FortiGate is already current, skipping",
				zap.String("fortigate_cert", currentCert.Name))
			return nil
		}

		// Rebind: import new cert, update references, delete old
		h.logger.Info("newer cert available, performing rebind",
			zap.String("old_cert", currentCert.Name),
			zap.String("new_cert", newCertName))

		if err := RebindCertificates(ctx, h.client, h.logger,
			currentCert.Name, newCertName, certPEM, keyPEM); err != nil {
			return err
		}
	} else {
		// No existing cert found, do a first-time import
		h.logger.Info("no existing cert found on FortiGate, importing fresh",
			zap.String("cert_name", newCertName))

		if err := h.client.ImportCertificate(ctx, newCertName, certPEM, keyPEM); err != nil {
			return err
		}
	}

	// Leaf is now on the FortiGate (via either path). Sync the intermediate
	// CAs so strict TLS clients (Android OkHttp, Java TrustManager) get the
	// full chain in the handshake. Best-effort: any failure here is logged
	// but does not roll back the leaf import.
	h.syncIntermediateCAs(ctx, certPEM)
	return nil
}

// syncIntermediateCAs uploads every non-leaf CERTIFICATE block from certPEM
// into FortiGate's CA store. CA names are derived from sha256(DER) so the
// same intermediate maps to the same name on every renewal — combined with
// ImportCACertificate's error -23 swallow, repeated calls are no-ops.
func (h *Handler) syncIntermediateCAs(ctx context.Context, certPEM []byte) {
	blocks, err := splitPEMChain(certPEM)
	if err != nil {
		h.logger.Warn("could not parse cert chain for intermediate sync",
			zap.Error(err))
		return
	}
	if len(blocks) < 2 {
		return
	}
	for _, blk := range blocks[1:] {
		sum := sha256.Sum256(blk.Bytes)
		caName := fmt.Sprintf("chain_%s", hex.EncodeToString(sum[:8]))
		if err := h.client.ImportCACertificate(ctx, caName, blk.Bytes); err != nil {
			h.logger.Warn("intermediate CA import failed (continuing)",
				zap.String("ca_name", caName),
				zap.Error(err))
		}
	}
}

// matchesDomain checks if an identifier matches a list of domain patterns.
// If domains is empty, it matches everything.
func matchesDomain(identifier string, domains []string) bool {
	if len(domains) == 0 {
		return true
	}
	for _, domain := range domains {
		if strings.EqualFold(identifier, domain) {
			return true
		}
		// Wildcard matching: if the domain pattern is *.example.com,
		// match any subdomain of example.com
		if strings.HasPrefix(domain, "*.") {
			baseDomain := domain[2:] // Remove "*."
			if strings.HasSuffix(strings.ToLower(identifier), strings.ToLower(baseDomain)) {
				return true
			}
		}
	}
	return false
}

// resolveStoragePath joins a Caddy storage key (a relative path emitted by
// the cert_obtained event) onto the configured data directory. If the key
// is already absolute it is returned unchanged, which keeps the door open
// for storage backends that emit absolute paths.
func resolveStoragePath(dataDir, storageKey string) string {
	if filepath.IsAbs(storageKey) {
		return filepath.Clean(storageKey)
	}
	return filepath.Join(dataDir, storageKey)
}

// parsePEMCertificate decodes a PEM-encoded certificate and returns the parsed x509 cert.
func parsePEMCertificate(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in certificate data")
	}
	return x509.ParseCertificate(block.Bytes)
}

// Interface guards ensure Handler implements the required Caddy interfaces.
var (
	_ caddy.Module        = (*Handler)(nil)
	_ caddy.Provisioner   = (*Handler)(nil)
	_ caddy.Validator     = (*Handler)(nil)
	_ caddyevents.Handler = (*Handler)(nil)
)
