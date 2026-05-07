// Package forticertsync provides a Caddy v2 event handler that automatically
// syncs renewed TLS certificates into FortiGate firewalls via the FortiOS REST API.
package forticertsync

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
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

	logger *zap.Logger
	client *FortiGateClient
}

// CertMapping maps a FortiGate certificate slot to one or more domain identifiers.
type CertMapping struct {
	// Name is the base certificate name on FortiGate (e.g., "aaris_tech").
	// New certificates will be uploaded as "{name}_{ddMMyyyy}".
	Name string `json:"name"`

	// Domains lists the domain identifiers to match against the event's identifier.
	// Supports exact match and wildcard (e.g., "*.aaris.tech").
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
// Note on event data: Caddy's cert_obtained event provides filesystem paths
// in `certificate_path` and `private_key_path`. These are concrete paths
// when Caddy is using the default filesystem storage. For non-filesystem
// storage backends (consul, vault, etc.), the handler would need to access
// Caddy's storage interface instead — this implementation assumes filesystem
// storage, which is the default and most common configuration.
func (h *Handler) Handle(ctx context.Context, e caddyevents.Event) error {
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

	// Read cert + key PEM from disk. Failures here are logged and swallowed:
	// returning an error from a Caddy event handler can block other handlers
	// registered for the same event from running, and a transient read failure
	// (or non-filesystem storage backend) should not derail Caddy's pipeline.
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		h.logger.Error("failed to read certificate file, skipping FortiGate sync",
			zap.String("cert_path", certPath),
			zap.Error(err))
		return nil
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		h.logger.Error("failed to read private key file, skipping FortiGate sync",
			zap.String("key_path", keyPath),
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

	// Parse the new cert to get its NotBefore date for comparison
	newCertParsed, err := parsePEMCertificate(certPEM)
	if err != nil {
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
		// Compare: is the new cert actually newer?
		if !newCertParsed.NotBefore.After(currentCert.NotBefore) {
			h.logger.Info("cert on FortiGate is already current or newer, skipping",
				zap.String("fortigate_cert", currentCert.Name),
				zap.Time("fortigate_not_before", currentCert.NotBefore),
				zap.Time("new_not_before", newCertParsed.NotBefore))
			return nil
		}

		// Rebind: import new cert, update references, delete old
		h.logger.Info("newer cert available, performing rebind",
			zap.String("old_cert", currentCert.Name),
			zap.String("new_cert", newCertName))

		return RebindCertificates(ctx, h.client, h.logger,
			currentCert.Name, newCertName, certPEM, keyPEM)
	}

	// No existing cert found, do a first-time import
	h.logger.Info("no existing cert found on FortiGate, importing fresh",
		zap.String("cert_name", newCertName))

	return h.client.ImportCertificate(ctx, newCertName, certPEM, keyPEM)
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
