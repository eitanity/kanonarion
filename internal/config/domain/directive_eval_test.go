package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/config/domain"
)

// TestDirectivePolicyEvaluate is the regression for governance
// evaluation: a category resolves to its configured outcome, an unset
// category falls back to Default, and an unset Default is an implicit allow
// (mirroring license rule resolution).
func TestDirectivePolicyEvaluate(t *testing.T) {
	p := domain.DirectivePolicy{
		LocalPathReplace: domain.PolicyOutcomeWarn,
		Default:          domain.PolicyOutcomeNotify,
		// ModulePathReplace intentionally unset → falls back to Default.
	}
	cases := map[string]domain.PolicyOutcome{
		domain.DirectiveLocalPathReplace:  domain.PolicyOutcomeWarn,
		domain.DirectiveModulePathReplace: domain.PolicyOutcomeNotify, // via Default
		"unrecognised-category":           domain.PolicyOutcomeNotify, // via Default
	}
	for cat, want := range cases {
		if got := p.Evaluate(cat); got != want {
			t.Errorf("Evaluate(%q) = %q, want %q", cat, got, want)
		}
	}

	// Empty policy: everything is an implicit allow.
	empty := domain.DirectivePolicy{}
	if got := empty.Evaluate(domain.DirectiveLocalPathReplace); got != domain.PolicyOutcomeAllow {
		t.Errorf("empty policy Evaluate = %q, want allow", got)
	}

	// DefaultConfig posture: local-path replace is flagged (warn) so the
	// `directives` command gates CI by default (acceptance).
	def := domain.DefaultConfig().DirectivePolicy
	if got := def.Evaluate(domain.DirectiveLocalPathReplace); got != domain.PolicyOutcomeWarn {
		t.Errorf("default local_path_replace = %q, want warn", got)
	}
}
