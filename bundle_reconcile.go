package forticertsync

import (
	"context"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
)

// reconcile brings the FortiGate in line with the configured bundle. It is
// idempotent and cheap when nothing has changed: the common path parses the
// cached certificate, sees the SAN set matches and expiry is far off, and
// returns without touching the network.
//
// Work happens when the cached certificate is missing, close to expiry, or its
// SAN set no longer matches the configured zones (a zone was added or removed).
//
// Order of operations on the FortiGate is deliberate and must not be changed:
// import the new certificate, THEN point the profile at it, and only THEN
// remove what it replaced. FortiOS refuses to delete a certificate that any
// object still references, so deleting first fails and leaves the profile
// pointing at a certificate that is about to disappear.
func (m *bundleManager) reconcile(ctx context.Context, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	subjects, err := m.cfg.Subjects()
	if err != nil {
		return err
	}

	renewBefore := time.Duration(m.cfg.RenewBefore)
	if renewBefore <= 0 {
		renewBefore = defaultBundleRenewBefore
	}

	leaf, certPEM, keyPEM := m.loadCached()
	needIssue := false
	switch {
	case leaf == nil:
		needIssue = true
		m.logger.Info("no cached bundle certificate, ordering one",
			zap.String("bundle", m.cfg.Name), zap.String("reason", reason))
	case !sanMatches(leaf, subjects):
		needIssue = true
		m.logger.Info("bundle SAN set changed, re-ordering",
			zap.String("bundle", m.cfg.Name),
			zap.Strings("want", subjects),
			zap.Strings("have", leaf.DNSNames))
	case time.Until(leaf.NotAfter) <= renewBefore:
		needIssue = true
		m.logger.Info("bundle certificate is near expiry, renewing",
			zap.String("bundle", m.cfg.Name),
			zap.Time("not_after", leaf.NotAfter))
	}

	if needIssue {
		certPEM, keyPEM, err = m.issue(ctx, subjects)
		if err != nil {
			return err
		}
		if err := m.storeCached(certPEM, keyPEM); err != nil {
			// Not fatal for this run — the certificate is valid and can still
			// be pushed — but it means the next run re-orders needlessly.
			m.logger.Error("could not cache bundle certificate; the next check will re-order",
				zap.Error(err))
		}
		leaf, err = parsePEMCertificate(certPEM)
		if err != nil {
			return fmt.Errorf("parsing freshly issued bundle: %w", err)
		}
	}

	// The FortiGate object name carries the issue date, so a renewal always
	// lands under a new name and the swap below is a genuine replacement.
	newName := fmt.Sprintf("%s_%s", m.cfg.Name, leaf.NotBefore.Format("02012006"))

	certs, err := m.client.ListCertificates(ctx)
	if err != nil {
		return fmt.Errorf("listing FortiGate certificates: %w", err)
	}
	present := false
	for _, c := range certs {
		if c.Name == newName {
			present = true
			break
		}
	}

	if !present {
		if err := m.client.ImportCertificate(ctx, newName, certPEM, keyPEM); err != nil {
			return fmt.Errorf("importing bundle: %w", err)
		}
		// Intermediates so strict TLS clients get a complete chain. Best-effort.
		if blocks, err := splitPEMChain(certPEM); err == nil && len(blocks) > 1 {
			m.syncChain(ctx, blocks[1:])
		}
	} else if !needIssue {
		m.logger.Debug("bundle already current on FortiGate",
			zap.String("cert_name", newName))
	}

	if m.cfg.Profile == "" {
		// No profile configured: still rebind anything already pointing at a
		// previous generation of the bundle, so renewals are not left stale.
		return m.rebindPreviousGenerations(ctx, newName, certs)
	}

	return m.bindProfile(ctx, newName, certs)
}

// syncChain imports intermediate CAs under deterministic names so repeated
// calls are no-ops (ImportCACertificate swallows "already exists").
func (m *bundleManager) syncChain(ctx context.Context, blocks []*pem.Block) {
	for _, blk := range blocks {
		if err := m.client.ImportCACertificate(ctx, chainCAName(blk.Bytes), blk.Bytes); err != nil {
			m.logger.Warn("intermediate CA import failed (continuing)", zap.Error(err))
		}
	}
}

// bindProfile performs the whole migration in a single PUT: the profile's new
// server-cert list is the bundle plus every entry the bundle does NOT cover.
//
// Doing it in one write is what makes this work at the cap. Adding the bundle
// first and pruning afterwards would need an 11th slot on a full profile and
// would be rejected with "Too many server certificate entries" — the exact
// failure this feature exists to remove.
func (m *bundleManager) bindProfile(ctx context.Context, newName string, certs []FortiCert) error {
	existing, err := m.client.GetProfileServerCerts(ctx, m.cfg.Profile)
	if err != nil {
		return err
	}

	superseded := m.supersededNames(certs)
	var keep []string
	var replaced []string
	for _, name := range existing {
		if name == newName {
			continue // re-added at the head below
		}
		if superseded[stripDateSuffix(name)] || stripDateSuffix(name) == m.cfg.Name {
			replaced = append(replaced, name)
			continue
		}
		keep = append(keep, name)
	}

	desired := append([]string{newName}, keep...)
	if len(desired) > serverCertMax {
		return fmt.Errorf(
			"inspection profile %q would hold %d certificates (max %d): the bundle covers %d of the current entries, leaving %s. "+
				"Add the uncovered domains as bundle zones, or list them under `supersede` if they are safe to drop",
			m.cfg.Profile, len(desired), serverCertMax, len(replaced), strings.Join(keep, ", "))
	}

	if sameStringSet(existing, desired) {
		m.logger.Debug("inspection profile already correct", zap.String("profile", m.cfg.Profile))
		return nil
	}

	if err := m.client.SetProfileServerCerts(ctx, m.cfg.Profile, desired); err != nil {
		return fmt.Errorf("binding bundle to profile %q: %w", m.cfg.Profile, err)
	}
	m.logger.Info("inspection profile now presents the bundle",
		zap.String("profile", m.cfg.Profile),
		zap.String("bundle_cert", newName),
		zap.Strings("replaced", replaced),
		zap.Strings("kept", keep),
		zap.Int("slots_used", len(desired)),
		zap.Int("slots_max", serverCertMax))

	if strings.EqualFold(m.cfg.Migrate, "off") {
		m.logger.Info("migrate=off — superseded certificates left on the FortiGate",
			zap.Strings("certs", replaced))
		return nil
	}
	m.deleteSuperseded(ctx, replaced)
	return nil
}

// deleteSuperseded removes certificates the bundle replaced, but only once the
// FortiGate confirms nothing references them any more. A certificate that is
// still referenced somewhere we did not rebind (a VIP, admin-server-cert) is
// left in place and reported — deleting it would break that object.
func (m *bundleManager) deleteSuperseded(ctx context.Context, names []string) {
	for _, name := range names {
		refs, err := m.client.FindCertReferences(ctx, name)
		if err != nil {
			m.logger.Warn("could not verify references; leaving superseded certificate in place",
				zap.String("cert_name", name), zap.Error(err))
			continue
		}
		if len(refs) > 0 {
			where := make([]string, 0, len(refs))
			for _, r := range refs {
				where = append(where, r.Endpoint)
			}
			m.logger.Info("superseded certificate is still referenced elsewhere; not deleting",
				zap.String("cert_name", name), zap.Strings("referenced_by", where))
			continue
		}
		if err := m.client.DeleteCertificate(ctx, name); err != nil {
			m.logger.Warn("could not delete superseded certificate (non-fatal)",
				zap.String("cert_name", name), zap.Error(err))
			continue
		}
		m.mu.Lock()
		delete(m.state.Managed, stripDateSuffix(name))
		m.saveState()
		m.mu.Unlock()
	}
}

// supersededNames returns the set of certificate base names the bundle makes
// redundant. Coverage is PROVEN, never guessed:
//
//   - names this plugin recorded in state.json, whose Caddy identifier the
//     bundle's SAN list demonstrably covers;
//   - the names this plugin would itself mint for a zone's apex and wildcard;
//   - anything the operator explicitly listed under `supersede`.
//
// Deriving the identifier back out of an arbitrary FortiGate name is NOT safe:
// sanitizeName maps both "." and "-" to "_", so "a-b.example.com" (covered by
// *.example.com) and "a.b.example.com" (not covered) both arrive as
// "a_b_example_com". Anything unproven is left attached and logged, which costs
// a slot but can never break a live site.
func (m *bundleManager) supersededNames(certs []FortiCert) map[string]bool {
	out := map[string]bool{}

	for _, z := range m.cfg.Zones {
		domain := strings.ToLower(strings.TrimSpace(z.Domain))
		if domain == "" {
			continue
		}
		if boolOr(z.Apex, true) {
			out[sanitizeName(domain)] = true
		}
		if boolOr(z.Wildcard, true) {
			out[sanitizeName("*."+domain)] = true
		}
		for _, n := range z.Names {
			out[sanitizeName(n)] = true
		}
	}

	for base, identifier := range m.state.Managed {
		if m.cfg.covers(identifier) {
			out[base] = true
		}
	}

	for _, n := range m.cfg.Supersede {
		out[stripDateSuffix(strings.TrimSpace(n))] = true
	}

	// Never supersede the bundle's own current object.
	delete(out, m.cfg.Name)

	if len(certs) > 0 {
		var unproven []string
		for _, c := range certs {
			base := stripDateSuffix(c.Name)
			if out[base] || base == m.cfg.Name {
				continue
			}
			unproven = append(unproven, c.Name)
		}
		if len(unproven) > 0 {
			m.logger.Debug("certificates not provably covered by the bundle; leaving them alone",
				zap.Strings("certs", unproven))
		}
	}
	return out
}

// rebindPreviousGenerations points anything still referencing an older bundle
// object at the current one, for deployments that bind the profile by hand.
func (m *bundleManager) rebindPreviousGenerations(ctx context.Context, newName string, certs []FortiCert) error {
	for _, c := range certs {
		if c.Name == newName || stripDateSuffix(c.Name) != m.cfg.Name {
			continue
		}
		refs, err := m.client.FindCertReferences(ctx, c.Name)
		if err != nil || len(refs) == 0 {
			continue
		}
		for _, ref := range refs {
			if err := m.client.UpdateCertReference(ctx, ref, newName); err != nil {
				m.logger.Warn("could not rebind reference to the new bundle",
					zap.String("endpoint", ref.Endpoint), zap.Error(err))
			}
		}
		if !strings.EqualFold(m.cfg.Migrate, "off") {
			m.deleteSuperseded(ctx, []string{c.Name})
		}
	}
	return nil
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]int{}
	for _, s := range a {
		seen[s]++
	}
	for _, s := range b {
		seen[s]--
		if seen[s] < 0 {
			return false
		}
	}
	return true
}
