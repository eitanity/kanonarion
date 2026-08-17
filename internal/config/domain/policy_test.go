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

// TestEvaluateLicense_NoRuleForScopeIsUnevaluated guards a scope that
// matches no rule must never resolve to an implicit allow: the gate evaluated
// nothing, so the result names itself unevaluated, blocks the run, and lists
// the scopes that do carry rules so the remedy is visible.
func TestEvaluateLicense_NoRuleForScopeIsUnevaluated(t *testing.T) {
	p := LicensePolicy{
		Categories: map[string][]string{"strong_copyleft": {"GPL-3.0-only"}},
		Rules: []LicensePolicyRule{
			{Scope: "production", Warn: []string{"strong_copyleft"}},
		},
	}
	got := p.EvaluateLicense("GPL-3.0-only", "tool")
	if got.Outcome != PolicyOutcomeUnevaluated {
		t.Errorf("outcome = %q, want unevaluated (no rule for scope)", got.Outcome)
	}
	if !got.Unevaluated {
		t.Errorf("Unevaluated = false, want true")
	}
	if !got.Blocking {
		t.Errorf("Blocking = false, want true (an unevaluated gate must not pass)")
	}
	if got.Category != "strong_copyleft" {
		t.Errorf("category = %q, want strong_copyleft", got.Category)
	}
	if len(got.RuleScopes) != 1 || got.RuleScopes[0] != "production" {
		t.Errorf("RuleScopes = %v, want [production]", got.RuleScopes)
	}
}

// TestEvaluateLicense_UndeterminedLicenseUnmatchedScopeIsUnevaluated guards
// that the unmatched-scope guard also covers an undetermined licence: the gap
// is the scope's, and it must block rather than fall back to a scope default
// that implies something was evaluated.
func TestEvaluateLicense_UndeterminedLicenseUnmatchedScopeIsUnevaluated(t *testing.T) {
	p := LicensePolicy{
		Rules: []LicensePolicyRule{{Scope: "production"}},
	}
	got := p.EvaluateLicense("", "tool")
	if !got.Unevaluated || !got.Blocking || got.Outcome != PolicyOutcomeUnevaluated {
		t.Errorf("got unevaluated=%v blocking=%v outcome=%q, want unevaluated=true blocking=true outcome=unevaluated",
			got.Unevaluated, got.Blocking, got.Outcome)
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
	for range 20 {
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
			{Scope: "vendor", UnknownLicense: UnknownLicenseNotify},
		},
	}
	vendor := p.EvaluateLicense("", "vendor")
	if !vendor.Uncertain || vendor.Blocking || vendor.Outcome != PolicyOutcomeNotify {
		t.Errorf("vendor notify: got uncertain=%v blocking=%v outcome=%q, want uncertain=true blocking=false outcome=notify",
			vendor.Uncertain, vendor.Blocking, vendor.Outcome)
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

// TestEvaluateDisjunction_MostFavourableArm pins the per-arm evaluation: a
// module offering a choice of licences takes the best arm's outcome and names
// the arms that carry it, and it is never blocking for want of an election.
func TestEvaluateDisjunction_MostFavourableArm(t *testing.T) {
	p := defaultPolicy()

	tests := []struct {
		name     string
		arms     []string
		scope    string
		want     PolicyOutcome
		wantArms []string
	}{
		{
			name:     "every arm allowed",
			arms:     []string{"Apache-2.0", "BSD-3-Clause", "MIT"},
			scope:    "production",
			want:     PolicyOutcomeAllow,
			wantArms: []string{"Apache-2.0", "BSD-3-Clause", "MIT"},
		},
		{
			name:     "one permissive arm carries the choice",
			arms:     []string{"Apache-2.0", "GPL-3.0-only"},
			scope:    "production",
			want:     PolicyOutcomeAllow,
			wantArms: []string{"Apache-2.0"},
		},
		{
			name:     "no allowed arm keeps the least-bad outcome",
			arms:     []string{"GPL-2.0-only", "GPL-3.0-only"},
			scope:    "production",
			want:     PolicyOutcomeWarn,
			wantArms: []string{"GPL-2.0-only", "GPL-3.0-only"},
		},
		{
			name:     "weak copyleft beats strong copyleft",
			arms:     []string{"GPL-3.0-only", "MPL-2.0"},
			scope:    "production",
			want:     PolicyOutcomeNotify,
			wantArms: []string{"MPL-2.0"},
		},
		{
			name:     "an unversioned identifier falls to the rule default",
			arms:     []string{"Apache-2.0", "GPL-3.0"},
			scope:    "production",
			want:     PolicyOutcomeAllow,
			wantArms: []string{"Apache-2.0", "GPL-3.0"},
		},
	}

	for _, tc := range tests {
		got := p.EvaluateDisjunction(tc.arms, tc.scope)
		if got.Outcome != tc.want {
			t.Errorf("%s: outcome = %q, want %q", tc.name, got.Outcome, tc.want)
		}
		if got.Uncertain || got.Blocking || got.Unevaluated {
			t.Errorf("%s: uncertain=%v blocking=%v unevaluated=%v, want all false — an identified choice is not an uncertainty",
				tc.name, got.Uncertain, got.Blocking, got.Unevaluated)
		}
		if len(got.ElectableArms) != len(tc.wantArms) {
			t.Fatalf("%s: electable arms = %v, want %v", tc.name, got.ElectableArms, tc.wantArms)
		}
		for i, arm := range tc.wantArms {
			if got.ElectableArms[i] != arm {
				t.Errorf("%s: electable arms = %v, want %v", tc.name, got.ElectableArms, tc.wantArms)
				break
			}
		}
		if got.License != tc.wantArms[0] {
			t.Errorf("%s: evaluated licence = %q, want the elected arm %q", tc.name, got.License, tc.wantArms[0])
		}
	}
}

// TestEvaluateDisjunction_NoArmsIsUndetermined guards that the disjunction path
// never invents a permissive answer out of nothing: with no identified arms it
// falls back to the undetermined-licence evaluation, which the production
// default blocks.
func TestEvaluateDisjunction_NoArmsIsUndetermined(t *testing.T) {
	p := defaultPolicy()
	got := p.EvaluateDisjunction(nil, "production")
	if !got.Uncertain || !got.Blocking {
		t.Errorf("no arms: uncertain=%v blocking=%v, want both true", got.Uncertain, got.Blocking)
	}
	if len(got.ElectableArms) != 0 {
		t.Errorf("no arms: electable arms = %v, want none", got.ElectableArms)
	}
}

// TestEvaluateDisjunction_UnmatchedScopeStaysUnevaluated guards that a scope
// carrying no rule reports the gate gap rather than electing an arm: nothing
// was measured, so no arm is named.
func TestEvaluateDisjunction_UnmatchedScopeStaysUnevaluated(t *testing.T) {
	p := defaultPolicy()
	got := p.EvaluateDisjunction([]string{"MIT", "Apache-2.0"}, "no-such-scope")
	if !got.Unevaluated || !got.Blocking || got.Outcome != PolicyOutcomeUnevaluated {
		t.Errorf("unmatched scope: unevaluated=%v blocking=%v outcome=%q, want true/true/unevaluated",
			got.Unevaluated, got.Blocking, got.Outcome)
	}
	if len(got.ElectableArms) != 0 {
		t.Errorf("unmatched scope: electable arms = %v, want none — no arm was measured", got.ElectableArms)
	}
	if len(got.RuleScopes) == 0 {
		t.Errorf("unmatched scope: RuleScopes empty, want the scopes that do carry rules")
	}
}

// TestEvaluateConjunction_LeastFavourableArm is the mirror of the disjunction
// case above: the consumer carries every arm, so the outcome is the arm it
// cannot escape rather than the arm it would elect.
func TestEvaluateConjunction_LeastFavourableArm(t *testing.T) {
	p := defaultPolicy()

	tests := []struct {
		name     string
		arms     []string
		scope    string
		want     PolicyOutcome
		wantArms []string
	}{
		{
			name:  "every arm allowed",
			arms:  []string{"Apache-2.0", "MIT"},
			scope: "production",
			want:  PolicyOutcomeAllow,
		},
		{
			name:     "one strong-copyleft arm governs the permissive one",
			arms:     []string{"GPL-3.0-only", "MIT"},
			scope:    "production",
			want:     PolicyOutcomeWarn,
			wantArms: []string{"GPL-3.0-only"},
		},
		{
			name:     "weak copyleft governs a permissive arm",
			arms:     []string{"MIT", "MPL-2.0"},
			scope:    "production",
			want:     PolicyOutcomeNotify,
			wantArms: []string{"MPL-2.0"},
		},
		{
			name:     "every arm warned names them all",
			arms:     []string{"GPL-2.0-only", "GPL-3.0-only"},
			scope:    "production",
			want:     PolicyOutcomeWarn,
			wantArms: []string{"GPL-2.0-only", "GPL-3.0-only"},
		},
		{
			name:  "a tool-scope rule that allows copyleft still allows the pair",
			arms:  []string{"GPL-3.0-only", "MIT"},
			scope: "tool",
			want:  PolicyOutcomeAllow,
		},
	}

	for _, tc := range tests {
		got := p.EvaluateConjunction(tc.arms, tc.scope)
		if got.Outcome != tc.want {
			t.Errorf("%s: outcome = %q, want %q", tc.name, got.Outcome, tc.want)
		}
		if got.Uncertain || got.Blocking || got.Unevaluated {
			t.Errorf("%s: uncertain=%v blocking=%v unevaluated=%v, want all false — a classified conjunction is determined",
				tc.name, got.Uncertain, got.Blocking, got.Unevaluated)
		}
		if len(got.ElectableArms) != 0 {
			t.Errorf("%s: electable arms = %v, want none — a conjunction offers no election", tc.name, got.ElectableArms)
		}
		if len(got.GoverningArms) != len(tc.wantArms) {
			t.Fatalf("%s: governing arms = %v, want %v", tc.name, got.GoverningArms, tc.wantArms)
		}
		for i, arm := range tc.wantArms {
			if got.GoverningArms[i] != arm {
				t.Errorf("%s: governing arms = %v, want %v", tc.name, got.GoverningArms, tc.wantArms)
				break
			}
		}
	}
}

// TestEvaluateConjunction_UnclassifiedArmIsNotFolded holds the boundary the
// fold was narrowed to. An arm in no category has no known strictness, so the
// strictest arm is unknown and the composite is returned exactly as an
// undetermined licence is — the behaviour a conjunction had before it was
// evaluated at all. Nothing the policy never classified starts being allowed,
// and nothing starts being blocked that was not blocked already.
func TestEvaluateConjunction_UnclassifiedArmIsNotFolded(t *testing.T) {
	p := defaultPolicy()

	got := p.EvaluateConjunction([]string{"Apache-2.0", "CC-BY-SA-4.0"}, "production")
	if !got.Uncertain || !got.Blocking {
		t.Errorf("unclassified arm: uncertain=%v blocking=%v, want both true", got.Uncertain, got.Blocking)
	}
	if got.Outcome != p.EvaluateLicense("", "production").Outcome {
		t.Errorf("unclassified arm: outcome = %q, want the undetermined-licence outcome", got.Outcome)
	}
	if len(got.GoverningArms) != 0 {
		t.Errorf("unclassified arm: governing arms = %v, want none — nothing was folded", got.GoverningArms)
	}

	if got := p.EvaluateConjunction(nil, "production"); !got.Uncertain || !got.Blocking {
		t.Errorf("no arms: uncertain=%v blocking=%v, want both true", got.Uncertain, got.Blocking)
	}
}

// TestEvaluateConjunction_UnmatchedScopeStaysUnevaluated guards that a scope
// carrying no rule reports the gate gap rather than an arm's outcome: nothing
// was measured, so no arm is named.
func TestEvaluateConjunction_UnmatchedScopeStaysUnevaluated(t *testing.T) {
	p := defaultPolicy()
	got := p.EvaluateConjunction([]string{"MIT", "Apache-2.0"}, "no-such-scope")
	if !got.Unevaluated || !got.Blocking || got.Outcome != PolicyOutcomeUnevaluated {
		t.Errorf("unmatched scope: unevaluated=%v blocking=%v outcome=%q, want true/true/unevaluated",
			got.Unevaluated, got.Blocking, got.Outcome)
	}
	if len(got.GoverningArms) != 0 {
		t.Errorf("unmatched scope: governing arms = %v, want none — no arm was measured", got.GoverningArms)
	}
	if len(got.RuleScopes) == 0 {
		t.Errorf("unmatched scope: RuleScopes empty, want the scopes that do carry rules")
	}
}
