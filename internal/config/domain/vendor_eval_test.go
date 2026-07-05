package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/config/domain"
)

// TestVendorPolicyEvaluate is the regression: drift and inconsistency
// resolve to their configured outcomes, an unset category is an implicit
// allow, and an *unrecognised* finding fails safe to the stricter posture
// rather than silently passing (an unclassified discrepancy is
// uncertainty, not a clean tree).
func TestVendorPolicyEvaluate(t *testing.T) {
	p := domain.VendorPolicy{
		OnDrift:         domain.PolicyOutcomeWarn,
		OnInconsistency: domain.PolicyOutcomeNotify,
	}
	cases := map[string]domain.PolicyOutcome{
		domain.VendorDrift:         domain.PolicyOutcomeWarn,
		domain.VendorInconsistency: domain.PolicyOutcomeNotify,
		"something-new":            domain.PolicyOutcomeWarn, // stricter of the two
	}
	for cat, want := range cases {
		if got := p.Evaluate(cat); got != want {
			t.Errorf("Evaluate(%q) = %q, want %q", cat, got, want)
		}
	}

	// Unset drift outcome → implicit allow for the explicit category, but an
	// unknown category still fails safe to warn because an unset posture is
	// treated as warn in the stricter-of comparison.
	empty := domain.VendorPolicy{}
	if got := empty.Evaluate(domain.VendorDrift); got != domain.PolicyOutcomeAllow {
		t.Errorf("empty drift = %q, want allow", got)
	}
	if got := empty.Evaluate("unknown"); got != domain.PolicyOutcomeWarn {
		t.Errorf("empty unknown = %q, want warn (fail-safe)", got)
	}

	// DefaultConfig posture: drift and inconsistency are both flagged (warn)
	// so the `vendor` command gates CI by default (acceptance).
	def := domain.DefaultConfig().VendorPolicy
	if def.Evaluate(domain.VendorDrift) != domain.PolicyOutcomeWarn ||
		def.Evaluate(domain.VendorInconsistency) != domain.PolicyOutcomeWarn {
		t.Errorf("default vendor posture not warn: %+v", def)
	}
}
