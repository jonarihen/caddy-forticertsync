package forticertsync

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// serverCertMax is FortiOS's hard cap on entries in an SSL/SSH inspection
// profile's inbound `server-cert` list. Exceeding it is rejected with:
//
//	Too many server certificate entries. Maximum number of entries: 10;
//	attribute set operator error, -4, discard the setting
//
// It is not configurable on the firewall, which is why the inspection bundle
// exists — see InspectionBundle.
const serverCertMax = 10

// stripDateSuffix removes a trailing "_ddMMyyyy" issue-date stamp from a
// FortiGate certificate name, yielding the stable base name that identifies
// the certificate across renewals.
//
// The day and month ranges are validated so a name that genuinely ends in
// eight digits is not silently truncated.
func stripDateSuffix(name string) string {
	idx := strings.LastIndex(name, "_")
	if idx < 0 || len(name)-idx-1 != 8 {
		return name
	}
	stamp := name[idx+1:]
	day, err := strconv.Atoi(stamp[0:2])
	if err != nil || day < 1 || day > 31 {
		return name
	}
	month, err := strconv.Atoi(stamp[2:4])
	if err != nil || month < 1 || month > 12 {
		return name
	}
	if _, err := strconv.Atoi(stamp[4:8]); err != nil {
		return name
	}
	return name[:idx]
}

// chainCAName derives a deterministic FortiGate CA-store name from a
// certificate's DER body, so the same intermediate maps to the same name on
// every renewal and repeated imports are no-ops.
func chainCAName(der []byte) string {
	sum := sha256.Sum256(der)
	return fmt.Sprintf("chain_%s", hex.EncodeToString(sum[:8]))
}
