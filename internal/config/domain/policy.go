package domain

import "slices"

import "sort"

// PolicyEvaluation is the resolved result of checking a single license against
// the license policy for a given dependency scope.
type PolicyEvaluation struct {
	License  string        // the resolved SPDX identifier that was evaluated
	Category string        // matched category name; "" when no category contains the license
	Scope    string        // the effective scope the rule was selected for
	Outcome  PolicyOutcome // allow | notify | warn
	// Uncertain is true when the evaluated license could not be resolved
	// to any SPDX (empty input): no license record, or extraction status
	// None/Multiple/ExtractionFailed/Cancelled, with no override. Such a
	// result must never be presented as a clean allow without this flag
	Uncertain bool
	// Blocking is true when the result must fail the run: an Uncertain
	// evaluation under an UnknownLicensePolicy of "block", or an Unevaluated
	// gate (no rule for the scope) — either way the caller (audit) must
	// surface it with a non-zero exit.
	Blocking bool
	// Unevaluated is true when the (normalised) scope matched no policy rule:
	// the gate evaluated nothing, which must never read as an allow. When set,
	// RuleScopes names the scopes that do carry rules so the remedy is visible
	// without reading the config file.
	Unevaluated bool
	// RuleScopes lists the scopes the policy has rules for, populated when
	// Unevaluated is true.
	RuleScopes []string
	// ElectableArms names the arms of a disjunction that carry the reported
	// outcome — the licences the consumer may elect between to obtain it.
	// Populated only by EvaluateDisjunction, and information rather than a
	// gate: the outcome already stands on the most favourable arm.
	ElectableArms []string
}

// outcomeRank orders the outcomes from most to least favourable so a
// disjunction can be folded onto the arm the consumer would elect. Lower is
// more favourable: allow < notify < warn < unevaluated.
func outcomeRank(o PolicyOutcome) int {
	switch o {
	case PolicyOutcomeAllow:
		return 0
	case PolicyOutcomeNotify:
		return 1
	case PolicyOutcomeWarn:
		return 2
	default: // PolicyOutcomeUnevaluated, and any value not yet known here
		return 3
	}
}

// EvaluateDisjunction resolves the policy outcome for a module offering a
// choice of licences (a pure "A OR B" expression whose arms were identified).
// Each arm is evaluated on its own and the module takes the most favourable
// arm's outcome, because that is the licence a consumer would elect: a module
// offering a choice cannot oblige worse terms than the best arm on offer, and
// treating the choice as uncertainty ranked it below a determined
// strong-copyleft licence the same rule merely warns on.
//
// The result names the arms sharing that outcome in ElectableArms, so the row
// says which licences carry it. Nothing here gates: recording an election as a
// license_overrides entry still settles the row wholesale, but its absence is
// not itself an open item.
//
// Arms are never uncertain — they are identified SPDX identifiers — so the
// unknown-licence machinery is not consulted. An unresolved disjunction (no
// arms identified) is not this function's business: the caller routes it
// through EvaluateLicense with an empty licence, which keeps the guarantee that
// an undetermined licence never reads as a clean allow. Called with no arms,
// this does the same.
func (p LicensePolicy) EvaluateDisjunction(arms []string, scope string) PolicyEvaluation {
	if len(arms) == 0 {
		return p.EvaluateLicense("", scope)
	}

	best := p.EvaluateLicense(arms[0], scope)
	for _, arm := range arms[1:] {
		if e := p.EvaluateLicense(arm, scope); outcomeRank(e.Outcome) < outcomeRank(best.Outcome) {
			best = e
		}
	}

	// A scope with no rule leaves every arm unevaluated: the gap is the
	// scope's, so it is reported exactly as the single-licence path reports
	// it, with no arms named — none of them was measured.
	if best.Unevaluated {
		return best
	}

	for _, arm := range arms {
		if p.EvaluateLicense(arm, scope).Outcome == best.Outcome {
			best.ElectableArms = append(best.ElectableArms, arm)
		}
	}
	return best
}

// resolveUnknownLicense returns the effective UnknownLicensePolicy for the
// scope: the rule's setting, or the scope default when unset or no rule.
func resolveUnknownLicense(rule LicensePolicyRule, found bool, effScope string) UnknownLicensePolicy {
	if found && rule.UnknownLicense != "" {
		return rule.UnknownLicense
	}
	return DefaultUnknownLicense(effScope)
}

// unknownOutcome maps an UnknownLicensePolicy onto the 3-valued
// PolicyOutcome for display. "block" maps to warn (the strongest existing
// severity); the hard-gate signal is carried separately by
// PolicyEvaluation.Blocking so no fourth PolicyOutcome value is needed.
func unknownOutcome(u UnknownLicensePolicy) PolicyOutcome {
	switch u {
	case UnknownLicenseAllow:
		return PolicyOutcomeAllow
	case UnknownLicenseNotify:
		return PolicyOutcomeNotify
	default: // warn or block
		return PolicyOutcomeWarn
	}
}

// normaliseScope maps a requested scope onto the scope whose rule applies.
// "test" is reserved and treated as "tool" initially; everything else passes
// through unchanged (an empty scope behaves as "production").
func normaliseScope(scope string) string {
	switch scope {
	case "":
		return "production"
	case "test":
		return "tool"
	default:
		return scope
	}
}

// categoryFor returns the category name whose SPDX list contains license.
// Category names are scanned in lexicographic order so a license appearing in
// more than one category resolves deterministically (the first by name wins).
// Returns "" when no category contains the license.
func (p LicensePolicy) categoryFor(license string) string {
	if license == "" {
		return ""
	}
	names := make([]string, 0, len(p.Categories))
	for name := range p.Categories {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if slices.Contains(p.Categories[name], license) {
			return name
		}
	}
	return ""
}

// ruleForScope returns the rule matching the (normalised) scope and whether one
// was found. When no rule exists for a scope, EvaluateLicense reports the gate
// as unevaluated — never an implicit allow.
func (p LicensePolicy) ruleForScope(scope string) (LicensePolicyRule, bool) {
	for _, r := range p.Rules {
		if r.Scope == scope {
			return r, true
		}
	}
	return LicensePolicyRule{}, false
}

// ruleScopes returns the sorted list of scopes that carry a rule, so an
// unevaluated result can name where rules do exist.
func (p LicensePolicy) ruleScopes() []string {
	scopes := make([]string, 0, len(p.Rules))
	for _, r := range p.Rules {
		scopes = append(scopes, r.Scope)
	}
	sort.Strings(scopes)
	return scopes
}

// resolveOutcome maps a category onto its outcome under a single rule.
// A category listed in Allow/Notify/Warn resolves to that outcome; any other
// category (including an unmatched/unknown license) resolves to the rule's
// Default, and an unset Default resolves to allow.
func (r LicensePolicyRule) resolveOutcome(category string) PolicyOutcome {
	if category != "" {
		if slices.Contains(r.Allow, category) {
			return PolicyOutcomeAllow
		}
		if slices.Contains(r.Notify, category) {
			return PolicyOutcomeNotify
		}
		if slices.Contains(r.Warn, category) {
			return PolicyOutcomeWarn
		}
	}
	if r.Default == "" {
		return PolicyOutcomeAllow
	}
	return r.Default
}

// EvaluateLicense resolves the policy outcome for a resolved license under the
// given dependency scope. The license is assumed already resolved (detector
// result with any license_overrides entry applied) by the caller.
//
// Resolution order:
// 1. The scope is normalised ("" → production, "test" → tool).
// 2. The license is mapped to a category (deterministic on collision).
// 3. The rule for the scope is selected. When no rule exists for the scope
// the gate has nothing to evaluate: the result is Unevaluated and Blocking —
// never an implicit allow, which would be indistinguishable from a licence
// that was evaluated and permitted. RuleScopes names where rules do exist.
// (The CLI translates its walk scopes onto policy scopes before calling, so
// this is a guard against a misconfigured or hand-rolled policy, not a path
// a shipped command reaches.)
// 4. The category is resolved against the rule's allow/notify/warn lists,
// falling back to the rule's default (absent default → allow). An unknown
// license (no category) likewise resolves to the rule's default.
// 5. A license that is empty (undetermined: no resolvable SPDX) does NOT
// fall through to the rule default. It is governed by the scope's
// UnknownLicensePolicy and flagged Uncertain (and Blocking when that
// policy is "block"), so uncertainty is never silently allowed.
func (p LicensePolicy) EvaluateLicense(license, scope string) PolicyEvaluation {
	effScope := normaliseScope(scope)
	category := p.categoryFor(license)
	rule, found := p.ruleForScope(effScope)

	// Unmatched scope: no rule means nothing was measured, and a gate that
	// measured nothing must not pass. Determined and undetermined licences
	// alike land here — the gap is the scope's, not the licence's.
	if !found {
		return PolicyEvaluation{
			License:     license,
			Category:    category,
			Scope:       effScope,
			Outcome:     PolicyOutcomeUnevaluated,
			Blocking:    true,
			Unevaluated: true,
			RuleScopes:  p.ruleScopes(),
		}
	}

	// Undetermined license: the detector resolved no SPDX at all. This is
	// the uncertainty case — treat it explicitly, never as the
	// rule default. A named-but-uncategorised license (license != "")
	// keeps the existing rule-default behaviour below.
	if license == "" {
		ulp := resolveUnknownLicense(rule, found, effScope)
		return PolicyEvaluation{
			License:   license,
			Category:  category,
			Scope:     effScope,
			Outcome:   unknownOutcome(ulp),
			Uncertain: true,
			Blocking:  ulp == UnknownLicenseBlock,
		}
	}

	return PolicyEvaluation{
		License:  license,
		Category: category,
		Scope:    effScope,
		Outcome:  rule.resolveOutcome(category),
	}
}
