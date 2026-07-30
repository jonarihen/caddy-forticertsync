package forticertsync

import (
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

func ptrBool(b bool) *bool { return &b }

// The real zone set from the homelab that hit the 10-certificate cap.
func homelabBundle() *InspectionBundle {
	return &InspectionBundle{
		Name:    "homelabrrr_inspection",
		Profile: "inbound-deep-inspection",
		Zones: []BundleZone{
			{Domain: "aaris.tech"},
			{Domain: "aaris.wtf"},
			{Domain: "tm-lestang.dk"},
			{Domain: "nikodyring.dev"},
			{Domain: "hofferson.com"},
			{Domain: "jackjack.dk"},
		},
	}
}

func TestBundleSubjects(t *testing.T) {
	subjects, err := homelabBundle().Subjects()
	if err != nil {
		t.Fatalf("Subjects: %v", err)
	}
	if len(subjects) != 12 {
		t.Fatalf("want 12 identifiers (apex+wildcard per zone), got %d: %v", len(subjects), subjects)
	}
	// Sorted and deduplicated, so the set is comparable run to run.
	for i := 1; i < len(subjects); i++ {
		if subjects[i-1] >= subjects[i] {
			t.Fatalf("subjects not sorted/deduped at %d: %v", i, subjects)
		}
	}
	want := map[string]bool{"jackjack.dk": true, "*.jackjack.dk": true, "tm-lestang.dk": true, "*.tm-lestang.dk": true}
	for _, s := range subjects {
		delete(want, s)
	}
	if len(want) != 0 {
		t.Fatalf("missing expected subjects: %v", want)
	}
}

func TestBundleSubjectsRespectsZoneFlags(t *testing.T) {
	b := &InspectionBundle{
		Name: "b",
		Zones: []BundleZone{
			{Domain: "apexonly.dk", Wildcard: ptrBool(false)},
			{Domain: "wildonly.dk", Apex: ptrBool(false)},
			{Domain: "deep.dk", Names: []string{"a.b.deep.dk"}},
		},
	}
	subjects, err := b.Subjects()
	if err != nil {
		t.Fatalf("Subjects: %v", err)
	}
	got := map[string]bool{}
	for _, s := range subjects {
		got[s] = true
	}
	for _, want := range []string{"apexonly.dk", "*.wildonly.dk", "deep.dk", "*.deep.dk", "a.b.deep.dk"} {
		if !got[want] {
			t.Errorf("missing subject %q in %v", want, subjects)
		}
	}
	for _, unwanted := range []string{"*.apexonly.dk", "wildonly.dk"} {
		if got[unwanted] {
			t.Errorf("subject %q should have been excluded", unwanted)
		}
	}
}

func TestBundleSubjectsRejectsOversizedSANList(t *testing.T) {
	b := &InspectionBundle{Name: "big"}
	for i := 0; i < 60; i++ {
		b.Zones = append(b.Zones, BundleZone{Domain: string(rune('a'+i%26)) + string(rune('a'+i/26)) + "-zone.example"})
	}
	if _, err := b.Subjects(); err == nil {
		t.Fatal("want an error when the SAN list exceeds the 100-identifier limit")
	}
}

func TestBundleCoversIsSingleLabelWildcardMatching(t *testing.T) {
	b := homelabBundle()

	// This is the case that started it all: music.jackjack.dk is covered by
	// *.jackjack.dk, so publishing it must cost no FortiGate slot.
	if !b.covers("music.jackjack.dk") {
		t.Error("music.jackjack.dk should be covered by *.jackjack.dk")
	}
	if !b.covers("jackjack.dk") {
		t.Error("the apex must be covered explicitly")
	}
	if !b.covers("www.tm-lestang.dk") {
		t.Error("hyphenated parent domains must work")
	}
	// A wildcard covers exactly one label.
	if b.covers("a.b.jackjack.dk") {
		t.Error("*.jackjack.dk must NOT cover a two-label subdomain")
	}
	if b.covers("notjackjack.dk") {
		t.Error("suffix matching must not leak across domains")
	}
	if b.covers("jackjack.dk.evil.com") {
		t.Error("must not match when the zone is a prefix of another domain")
	}
	if b.covers("") {
		t.Error("empty identifier must not be covered")
	}
	if b.covers("elsewhere.example.org") {
		t.Error("unconfigured zones must not be covered")
	}
}

func TestStripDateSuffix(t *testing.T) {
	cases := map[string]string{
		"jackjack_dk_26072026":           "jackjack_dk",
		"homelabrrr_inspection_30072026": "homelabrrr_inspection",
		"wildcard_aaris_tech_22062026":   "wildcard_aaris_tech",
		"no_suffix":                      "no_suffix",
		// 99 is neither a valid day nor month — not a date stamp.
		"weird_99999999": "weird_99999999",
		"short_1234":     "short_1234",
	}
	for in, want := range cases {
		if got := stripDateSuffix(in); got != want {
			t.Errorf("stripDateSuffix(%q) = %q, want %q", in, got, want)
		}
	}
}

// supersededNames must PROVE coverage. Guessing the identifier back out of a
// FortiGate name is impossible ("a-b.x.dk" and "a.b.x.dk" both sanitize to
// "a_b_x_dk"), and a wrong guess deletes a certificate a live site depends on.
func TestSupersededNamesOnlyIncludesProvenCoverage(t *testing.T) {
	m := &bundleManager{
		cfg:    homelabBundle(),
		logger: zap.NewNop(),
		state: bundleState{Managed: map[string]string{
			"music_jackjack_dk": "music.jackjack.dk",   // covered by *.jackjack.dk
			"deep_thing":        "a.b.jackjack.dk",     // NOT covered (two labels)
			"mail_aaris_wtf":    "mail.aaris.wtf",      // covered
			"other_thing":       "thing.elsewhere.org", // different zone entirely
		}},
	}
	got := m.supersededNames(nil)

	for _, want := range []string{
		"music_jackjack_dk", "mail_aaris_wtf",
		"jackjack_dk", "wildcard_jackjack_dk", // zone apex + wildcard names
		"tm_lestang_dk", "wildcard_tm_lestang_dk",
	} {
		if !got[want] {
			t.Errorf("%q should be marked superseded", want)
		}
	}
	for _, unwanted := range []string{"deep_thing", "other_thing", "homelabrrr_inspection"} {
		if got[unwanted] {
			t.Errorf("%q must NOT be marked superseded", unwanted)
		}
	}
}

func TestSupersededNamesHonorsExplicitList(t *testing.T) {
	cfg := homelabBundle()
	cfg.Supersede = []string{"legacy_thing_01012026", "another_legacy"}
	m := &bundleManager{cfg: cfg, logger: zap.NewNop(), state: bundleState{Managed: map[string]string{}}}
	got := m.supersededNames(nil)
	if !got["legacy_thing"] {
		t.Error("explicit supersede entries should have their date suffix stripped")
	}
	if !got["another_legacy"] {
		t.Error("explicit supersede entry missing")
	}
}

func TestSameStringSet(t *testing.T) {
	if !sameStringSet([]string{"a", "b"}, []string{"b", "a"}) {
		t.Error("order must not matter")
	}
	if sameStringSet([]string{"a"}, []string{"a", "b"}) {
		t.Error("different lengths are not the same set")
	}
	if sameStringSet([]string{"a", "a"}, []string{"a", "b"}) {
		t.Error("multiplicity must be respected")
	}
	if !sameStringSet(nil, nil) {
		t.Error("two empty sets are the same")
	}
}

func TestValidateBundleConfig(t *testing.T) {
	base := func() *Handler {
		return &Handler{FortiGateURL: "https://fw", APIToken: "t", Bundle: homelabBundle()}
	}

	if err := base().Validate(); err != nil {
		t.Fatalf("a bundle-only config should validate: %v", err)
	}

	// A bundle alone satisfies the "something to do" requirement.
	h := base()
	h.Certificates = nil
	h.SyncAll = false
	if err := h.Validate(); err != nil {
		t.Errorf("bundle mode should not require cert mappings or sync_all: %v", err)
	}

	h = base()
	h.Bundle.Name = ""
	if err := h.Validate(); err == nil {
		t.Error("a bundle without a name must be rejected")
	}

	h = base()
	h.Bundle.Zones = nil
	if err := h.Validate(); err == nil {
		t.Error("a bundle without zones must be rejected")
	}

	// A wildcard as the zone domain is a config mistake worth catching: it
	// would produce "*.*.example.com".
	h = base()
	h.Bundle.Zones = []BundleZone{{Domain: "*.example.com"}}
	if err := h.Validate(); err == nil {
		t.Error("a wildcard zone domain must be rejected")
	}
}

func TestBundleEnabled(t *testing.T) {
	var nilBundle *InspectionBundle
	if nilBundle.enabled() {
		t.Error("nil bundle must not be enabled")
	}
	if (&InspectionBundle{Name: "x"}).enabled() {
		t.Error("a bundle with no zones must not be enabled")
	}
	if !homelabBundle().enabled() {
		t.Error("a fully configured bundle must be enabled")
	}
}

func TestBundleDefaultsAreSane(t *testing.T) {
	if defaultBundleRenewBefore != 30*24*time.Hour {
		t.Errorf("renew_before default = %v", defaultBundleRenewBefore)
	}
	if defaultBundleCheckInterval > 24*time.Hour {
		t.Error("check interval must be at least daily to catch a 90-day cert's renewal window")
	}
	if serverCertMax != 10 {
		t.Errorf("serverCertMax = %d, FortiOS allows 10", serverCertMax)
	}
	// caddy.Duration is what the Caddyfile parser produces.
	var d caddy.Duration = caddy.Duration(defaultBundleRenewBefore)
	if time.Duration(d) != defaultBundleRenewBefore {
		t.Error("caddy.Duration round-trip failed")
	}
}
