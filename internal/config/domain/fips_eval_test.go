package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/config/domain"
)

// TestFIPSPolicyEvaluate is the regression for governance evaluation:
// when Required is false every category resolves to allow (the assessor still
// records facts but they are not violations); when Required is true a
// deviation resolves to OnDeviation and — crucially — an unknown category
// fails safe to warn rather than falling through to allow (absence
// is not a benign answer).
func TestFIPSPolicyEvaluate(t *testing.T) {
	notReq := domain.FIPSPolicy{Required: false, OnDeviation: domain.PolicyOutcomeWarn}
	for _, cat := range []string{
		domain.FIPSCompliant, domain.FIPSDeviation, domain.FIPSUnknown, "garbage",
	} {
		if got := notReq.Evaluate(cat); got != domain.PolicyOutcomeAllow {
			t.Errorf("Required=false Evaluate(%q) = %q, want allow", cat, got)
		}
	}

	req := domain.FIPSPolicy{Required: true, OnDeviation: domain.PolicyOutcomeNotify}
	cases := map[string]domain.PolicyOutcome{
		domain.FIPSCompliant: domain.PolicyOutcomeAllow,
		domain.FIPSDeviation: domain.PolicyOutcomeNotify,
		domain.FIPSUnknown:   domain.PolicyOutcomeWarn, // fail-safe
		"":                   domain.PolicyOutcomeWarn,
	}
	for cat, want := range cases {
		if got := req.Evaluate(cat); got != want {
			t.Errorf("Required=true Evaluate(%q) = %q, want %q", cat, got, want)
		}
	}

	// Required with unset OnDeviation: deviation defaults to warn so a
	// project that opts into FIPS without setting a posture still gates.
	unsetDev := domain.FIPSPolicy{Required: true}
	if got := unsetDev.Evaluate(domain.FIPSDeviation); got != domain.PolicyOutcomeWarn {
		t.Errorf("Required=true unset OnDeviation deviation = %q, want warn", got)
	}

	// DefaultConfig: FIPS is opt-in (Required=false) so a green-field
	// project never trips on FIPS findings until it sets fips_policy.
	def := domain.DefaultConfig().FIPSPolicy
	if got := def.Evaluate(domain.FIPSDeviation); got != domain.PolicyOutcomeAllow {
		t.Errorf("default policy deviation = %q, want allow (FIPS opt-in)", got)
	}
}
