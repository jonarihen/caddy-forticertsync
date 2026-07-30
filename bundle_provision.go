package forticertsync

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

// provisionBundle builds the ACME issuer and starts the renewal ticker.
func (h *Handler) provisionBundle(ctx caddy.Context) error {
	b := h.Bundle

	if _, err := b.Subjects(); err != nil {
		return err
	}
	if b.DNSRaw == nil {
		return fmt.Errorf("inspection_bundle %q: a `dns` provider is required — the bundle contains wildcards, "+
			"and wildcards can only be validated over DNS-01", b.Name)
	}

	dnsMod, err := ctx.LoadModule(b, "DNSRaw")
	if err != nil {
		return fmt.Errorf("inspection_bundle %q: loading DNS provider: %w", b.Name, err)
	}
	provider, ok := dnsMod.(certmagic.DNSProvider)
	if !ok {
		return fmt.Errorf("inspection_bundle %q: DNS module %T does not implement libdns record append/delete", b.Name, dnsMod)
	}

	// The bundle's lifecycle is ours, but the ACME *account* key must persist
	// across restarts or we re-register with the CA every boot. certmagic's
	// storage handles that; point it at Caddy's data dir.
	storage := &certmagic.FileStorage{Path: caddy.AppDataDir()}
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
			return certmagic.New(nil, certmagic.Config{Storage: storage, Logger: h.logger}), nil
		},
		Logger: h.logger,
	})
	cfg := certmagic.New(cache, certmagic.Config{Storage: storage, Logger: h.logger})

	template := certmagic.ACMEIssuer{
		Agreed: true,
		Email:  b.Email,
		Logger: h.logger,
		DNS01Solver: &certmagic.DNS01Solver{
			DNSManager: certmagic.DNSManager{
				DNSProvider: provider,
				Logger:      h.logger,
			},
		},
	}
	if b.CA != "" {
		template.CA = b.CA
		// An explicit CA is usually the staging directory during testing;
		// don't silently fall back to a different endpoint on retry.
		template.TestCA = b.CA
	}

	h.bundle = &bundleManager{
		cfg:     b,
		client:  h.client,
		logger:  h.logger.With(zap.String("bundle", b.Name)),
		dataDir: h.dataDir,
		issuer:  certmagic.NewACMEIssuer(cfg, template),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	h.bundle.loadState()

	if b.Migrate == "" {
		b.Migrate = "cleanup"
	}
	if !strings.EqualFold(b.Migrate, "off") && !strings.EqualFold(b.Migrate, "cleanup") {
		return fmt.Errorf("inspection_bundle %q: migrate must be \"off\" or \"cleanup\", got %q", b.Name, b.Migrate)
	}

	h.bundle.startTicker()
	return nil
}

// startTicker runs the periodic expiry check.
//
// Per-domain syncing needs no timer because Caddy owns those certificates and
// tells us when they renew. Nothing owns the bundle but us: it is not one of
// Caddy's managed certificates, and certmagic's own renewal machinery is
// strictly one-certificate-per-name (Config.manageAll iterates the name list),
// so it cannot drive a multi-SAN certificate. Relying on unrelated
// cert_obtained events instead would make the bundle's renewal depend on some
// other certificate happening to renew in time — correct only by coincidence.
func (m *bundleManager) startTicker() {
	interval := time.Duration(m.cfg.CheckInterval)
	if interval <= 0 {
		interval = defaultBundleCheckInterval
	}

	go func() {
		defer close(m.done)

		// Reconcile once at startup, slightly delayed so Caddy finishes coming
		// up (and a burst of cert_obtained events settles) first.
		select {
		case <-time.After(15 * time.Second):
		case <-m.stop:
			return
		}
		m.reconcileLogged("startup")

		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				m.reconcileLogged("scheduled check")
			case <-m.stop:
				return
			}
		}
	}()
}

func (m *bundleManager) stopTicker() {
	select {
	case <-m.stop: // already closed
	default:
		close(m.stop)
	}
	select {
	case <-m.done:
	case <-time.After(10 * time.Second):
		m.logger.Warn("bundle worker did not stop within 10s")
	}
}

// reconcileLogged runs a reconcile and swallows the error after logging it.
// A FortiGate or ACME failure must never take Caddy down.
func (m *bundleManager) reconcileLogged(reason string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if err := m.reconcile(ctx, reason); err != nil {
		m.logger.Error("inspection bundle reconcile failed",
			zap.String("reason", reason), zap.Error(err))
	}
}
