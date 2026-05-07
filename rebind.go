package forticertsync

import (
	"context"
	"fmt"

	"go.uber.org/zap"
)

// RebindCertificates handles the full lifecycle of replacing a certificate on FortiGate:
//  1. Import the new certificate
//  2. Find all references to the old certificate
//  3. Update each reference to point to the new certificate
//  4. Verify no references remain to the old certificate
//  5. Delete the old certificate
//
// The function is designed to be as safe as possible: it will NOT delete the old
// certificate if any references still point to it after the rebind attempt.
func RebindCertificates(
	ctx context.Context,
	client *FortiGateClient,
	logger *zap.Logger,
	oldCertName, newCertName string,
	certPEM, keyPEM []byte,
) error {
	// Step 1: Import the new certificate
	logger.Info("importing new certificate",
		zap.String("cert_name", newCertName))

	if err := client.ImportCertificate(ctx, newCertName, certPEM, keyPEM); err != nil {
		return fmt.Errorf("importing new certificate: %w", err)
	}

	// Step 2: Find all references to the old certificate
	logger.Info("searching for references to old certificate",
		zap.String("old_cert", oldCertName))

	refs, err := client.FindCertReferences(ctx, oldCertName)
	if err != nil {
		return fmt.Errorf("finding cert references: %w", err)
	}

	logger.Info("found references to old certificate",
		zap.String("old_cert", oldCertName),
		zap.Int("count", len(refs)))

	// Step 3: Update each reference to point to the new certificate
	var rebindErrors []error
	for _, ref := range refs {
		logger.Info("rebinding reference",
			zap.String("endpoint", ref.Endpoint),
			zap.String("mkey", ref.MKey),
			zap.String("field", ref.Field))

		if err := client.UpdateCertReference(ctx, ref, newCertName); err != nil {
			logger.Error("failed to rebind reference",
				zap.String("endpoint", ref.Endpoint),
				zap.String("mkey", ref.MKey),
				zap.Error(err))
			rebindErrors = append(rebindErrors, err)
		}
	}

	if len(rebindErrors) > 0 {
		return fmt.Errorf("failed to rebind %d of %d references", len(rebindErrors), len(refs))
	}

	// Step 4: Verify no references remain to the old certificate
	remainingRefs, err := client.FindCertReferences(ctx, oldCertName)
	if err != nil {
		logger.Warn("could not verify remaining references, skipping delete of old cert",
			zap.String("old_cert", oldCertName),
			zap.Error(err))
		return nil
	}

	if len(remainingRefs) > 0 {
		logger.Warn("references still point to old certificate, skipping delete",
			zap.String("old_cert", oldCertName),
			zap.Int("remaining_refs", len(remainingRefs)))
		return nil
	}

	// Step 5: Delete the old certificate
	logger.Info("deleting old certificate",
		zap.String("old_cert", oldCertName))

	if err := client.DeleteCertificate(ctx, oldCertName); err != nil {
		logger.Warn("failed to delete old certificate (non-fatal)",
			zap.String("old_cert", oldCertName),
			zap.Error(err))
		// Non-fatal: the new cert is already active, old cert just lingers
		return nil
	}

	logger.Info("certificate rebind complete",
		zap.String("old_cert", oldCertName),
		zap.String("new_cert", newCertName),
		zap.Int("references_updated", len(refs)))

	return nil
}
