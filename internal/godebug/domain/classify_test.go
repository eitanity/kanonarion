package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/godebug/domain"
)

// TestClassify covers the three taxonomy tiers and the
// fail-safe: a setting the versioned taxonomy does not know must classify as
// TierUnknown, never silently as the benign green tier.
func TestClassify(t *testing.T) {
	cases := map[string]domain.Tier{
		"tlsrsakex":       domain.TierRed,   // security-weakening
		"x509ignoreCN":    domain.TierRed,   // security-weakening
		"tarinsecurepath": domain.TierRed,   // security-weakening
		"http2client":     domain.TierAmber, // behaviour-modifying
		"randautoseed":    domain.TierAmber, // behaviour-modifying
		"asynctimerchan":  domain.TierGreen, // benign
		"madeupsetting":   domain.TierUnknown,
		"":                domain.TierUnknown,
	}
	for name, want := range cases {
		if got := domain.Classify(name); got != want {
			t.Errorf("Classify(%q) = %v, want %v", name, got, want)
		}
	}
}

// TestTierString pins the stable JSON tokens (schema contract).
func TestTierString(t *testing.T) {
	cases := map[domain.Tier]string{
		domain.TierRed:     "red",
		domain.TierAmber:   "amber",
		domain.TierGreen:   "green",
		domain.TierUnknown: "unknown",
	}
	for tier, want := range cases {
		if got := tier.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", tier, got, want)
		}
	}
}

// TestPipelineFingerprintIncludesTaxonomy guards the cache-invalidation
// contract: the fingerprint must fold in the taxonomy version so a taxonomy
// bump alone forces re-classification rather than returning a stale record.
func TestPipelineFingerprintIncludesTaxonomy(t *testing.T) {
	fp := domain.PipelineFingerprint()
	if domain.TaxonomyVersion() == "" {
		t.Fatal("TaxonomyVersion must not be empty")
	}
	if want := domain.PipelineVersion + "+tax." + domain.TaxonomyVersion(); fp != want {
		t.Errorf("PipelineFingerprint() = %q, want %q", fp, want)
	}
}
