package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/config/domain"
)

// TestGoDebugPolicyEvaluate is the regression for governance
// evaluation: each taxonomy tier resolves to its configured outcome, an
// explicitly-green unset outcome is an implicit allow, and — crucially — an
// unknown tier fails safe to the red posture rather than falling through to
// allow (absence is not a benign answer).
func TestGoDebugPolicyEvaluate(t *testing.T) {
	p := domain.GoDebugPolicy{
		Red:   domain.PolicyOutcomeWarn,
		Amber: domain.PolicyOutcomeNotify,
		// Green intentionally unset → implicit allow.
	}
	cases := map[string]domain.PolicyOutcome{
		domain.GoDebugRed:   domain.PolicyOutcomeWarn,
		domain.GoDebugAmber: domain.PolicyOutcomeNotify,
		domain.GoDebugGreen: domain.PolicyOutcomeAllow, // unset green
		"unknown":           domain.PolicyOutcomeWarn,  // fail-safe to red
		"":                  domain.PolicyOutcomeWarn,  // fail-safe to red
	}
	for tier, want := range cases {
		if got := p.Evaluate(tier); got != want {
			t.Errorf("Evaluate(%q) = %q, want %q", tier, got, want)
		}
	}

	// Empty policy: red posture is itself unset, so the unknown-tier
	// fail-safe still surfaces as warn (the strongest signal) — uncertainty
	// is never silently allowed.
	empty := domain.GoDebugPolicy{}
	if got := empty.Evaluate("unknown"); got != domain.PolicyOutcomeWarn {
		t.Errorf("empty policy unknown tier = %q, want warn", got)
	}
	if got := empty.Evaluate(domain.GoDebugGreen); got != domain.PolicyOutcomeAllow {
		t.Errorf("empty policy green = %q, want allow", got)
	}

	// DefaultConfig posture: red settings are flagged (warn) so the
	// `godebug` command gates CI by default (acceptance).
	def := domain.DefaultConfig().GoDebugPolicy
	if got := def.Evaluate(domain.GoDebugRed); got != domain.PolicyOutcomeWarn {
		t.Errorf("default red = %q, want warn", got)
	}
}
