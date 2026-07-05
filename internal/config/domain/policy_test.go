package domain

import "testing"

func defaultPolicy() LicensePolicy { return DefaultConfig().LicensePolicy }

func TestEvaluateLicense_DefaultPolicy(t *testing.T) {
	p := defaultPolicy()

	tests := []struct {
		name    string
		license string
		scope   string
		wantCat string
		wantOut PolicyOutcome
	}{
		{"permissive production allow", "MIT", "production", "permissive", PolicyOutcomeAllow},
		{"weak copyleft production notify", "MPL-2.0", "production", "weak_copyleft", PolicyOutcomeNotify},
		{"strong copyleft production warn", "GPL-3.0-only", "production", "strong_copyleft", PolicyOutcomeWarn},
		{"strong copyleft tool allow", "GPL-3.0-only", "tool", "strong_copyleft", PolicyOutcomeAllow},
		{"restricted tool notify", "SSPL-1.0", "tool", "restricted", PolicyOutcomeNotify},
		{"test scope treated as tool", "GPL-3.0-only", "test", "strong_copyleft", PolicyOutcomeAllow},
		{"empty scope treated as production", "GPL-3.0-only", "", "strong_copyleft", PolicyOutcomeWarn},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := p.EvaluateLicense(tc.license, tc.scope)
			if got.Category != tc.wantCat {
				t.Errorf("category = %q, want %q", got.Category, tc.wantCat)
			}
			if got.Outcome != tc.wantOut {
				t.Errorf("outcome = %q, want %q", got.Outcome, tc.wantOut)
			}
		})
	}
}

func TestEvaluateLicense_UnknownLicenseUsesDefault(t *testing.T) {
	p := LicensePolicy{
		Categories: map[string][]string{"permissive": {"MIT"}},
		Rules: []LicensePolicyRule{
			{Scope: "production", Allow: []string{"permissive"}, Default: PolicyOutcomeWarn},
		},
	}
	got := p.EvaluateLicense("Totally-Unknown-1.0", "production")
	if got.Category != "" {
		t.Errorf("category = %q, want empty", got.Category)
	}
	if got.Outcome != PolicyOutcomeWarn {
		t.Errorf("outcome = %q, want warn (rule default)", got.Outcome)
	}
}

func TestEvaluateLicense_AbsentDefaultResolvesToAllow(t *testing.T) {
	p := LicensePolicy{
		Categories: map[string][]string{"permissive": {"MIT"}},
		Rules: []LicensePolicyRule{
			{Scope: "production", Allow: []string{"permissive"}}, // no Default set
		},
	}
	// A category not listed anywhere falls back to the (absent) default → allow.
	got := p.EvaluateLicense("GPL-3.0-only", "production")
	if got.Outcome != PolicyOutcomeAllow {
		t.Errorf("outcome = %q, want allow (absent default)", got.Outcome)
	}
}

func TestEvaluateLicense_NoRuleForScopeIsImplicitAllow(t *testing.T) {
	p := LicensePolicy{
		Categories: map[string][]string{"strong_copyleft": {"GPL-3.0-only"}},
		Rules: []LicensePolicyRule{
			{Scope: "production", Warn: []string{"strong_copyleft"}},
		},
	}
	got := p.EvaluateLicense("GPL-3.0-only", "tool")
	if got.Outcome != PolicyOutcomeAllow {
		t.Errorf("outcome = %q, want allow (no rule for scope)", got.Outcome)
	}
	if got.Category != "strong_copyleft" {
		t.Errorf("category = %q, want strong_copyleft", got.Category)
	}
}

func TestEvaluateLicense_CategoryCollisionIsDeterministic(t *testing.T) {
	p := LicensePolicy{
		Categories: map[string][]string{
			"restricted":      {"AGPL-3.0-only"},
			"strong_copyleft": {"AGPL-3.0-only"},
		},
		Rules: []LicensePolicyRule{{Scope: "production"}},
	}
	// Lexicographic scan: "restricted" < "strong_copyleft".
	for i := 0; i < 20; i++ {
		if got := p.EvaluateLicense("AGPL-3.0-only", "production"); got.Category != "restricted" {
			t.Fatalf("category = %q, want restricted (deterministic first-by-name)", got.Category)
		}
	}
}

// TestEvaluateLicense_EmptyLicenseIsUncertain guards an
// undetermined license (empty SPDX) must NOT silently resolve to the rule
// default ("allow" under the default production policy). It must be
// flagged Uncertain, and under the default production unknown_license
// policy ("block") it must also be Blocking with a warn-level outcome.
func TestEvaluateLicense_EmptyLicenseIsUncertain(t *testing.T) {
	p := defaultPolicy()
	got := p.EvaluateLicense("", "production")
	if got.Category != "" {
		t.Errorf("category = %q, want empty", got.Category)
	}
	if !got.Uncertain {
		t.Errorf("Uncertain = false, want true for empty license")
	}
	if !got.Blocking {
		t.Errorf("Blocking = false, want true (default production unknown_license=block)")
	}
	if got.Outcome == PolicyOutcomeAllow {
		t.Errorf("outcome = allow; undetermined license must not read as a clean allow")
	}
	if got.Outcome != PolicyOutcomeWarn {
		t.Errorf("outcome = %q, want warn (block maps to warn severity)", got.Outcome)
	}
}

// TestEvaluateLicense_UnknownLicensePolicyConfigurable guards the
// unknown_license policy is per-scope configurable; "allow" opts out of
// blocking, other scopes default to warn (not block).
func TestEvaluateLicense_UnknownLicensePolicyConfigurable(t *testing.T) {
	p := LicensePolicy{
		Rules: []LicensePolicyRule{
			{Scope: "production", UnknownLicense: UnknownLicenseAllow},
			{Scope: "tool"}, // unset → scope default (warn, not block)
		},
	}
	prod := p.EvaluateLicense("", "production")
	if !prod.Uncertain || prod.Blocking || prod.Outcome != PolicyOutcomeAllow {
		t.Errorf("production allow opt-out: got uncertain=%v blocking=%v outcome=%q, want uncertain=true blocking=false outcome=allow",
			prod.Uncertain, prod.Blocking, prod.Outcome)
	}
	tool := p.EvaluateLicense("", "tool")
	if !tool.Uncertain || tool.Blocking || tool.Outcome != PolicyOutcomeWarn {
		t.Errorf("tool default: got uncertain=%v blocking=%v outcome=%q, want uncertain=true blocking=false outcome=warn",
			tool.Uncertain, tool.Blocking, tool.Outcome)
	}
}

// TestEvaluateLicense_NamedUncategorisedStillDefaults guards that a
// named-but-uncategorised license (non-empty SPDX) keeps the existing
// rule-default behaviour and is NOT treated as uncertain.
func TestEvaluateLicense_NamedUncategorisedStillDefaults(t *testing.T) {
	p := defaultPolicy()
	got := p.EvaluateLicense("Totally-Unknown-1.0", "production")
	if got.Uncertain {
		t.Errorf("a named uncategorised license must not be flagged Uncertain")
	}
	if got.Outcome != PolicyOutcomeAllow {
		t.Errorf("outcome = %q, want allow (default production rule default)", got.Outcome)
	}
}
