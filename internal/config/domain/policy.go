package domain

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
	// Blocking is true when Uncertain and the scope's UnknownLicensePolicy
	// is "block" — a hard compliance failure the caller (audit) must
	// surface with a non-zero exit.
	Blocking bool
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
		for _, id := range p.Categories[name] {
			if id == license {
				return name
			}
		}
	}
	return ""
}

// ruleForScope returns the rule matching the (normalised) scope and whether one
// was found. When no rule exists for a scope, callers treat the result as an
// implicit allow.
func (p LicensePolicy) ruleForScope(scope string) (LicensePolicyRule, bool) {
	for _, r := range p.Rules {
		if r.Scope == scope {
			return r, true
		}
	}
	return LicensePolicyRule{}, false
}

// resolveOutcome maps a category onto its outcome under a single rule.
// A category listed in Allow/Notify/Warn resolves to that outcome; any other
// category (including an unmatched/unknown license) resolves to the rule's
// Default, and an unset Default resolves to allow.
func (r LicensePolicyRule) resolveOutcome(category string) PolicyOutcome {
	if category != "" {
		for _, c := range r.Allow {
			if c == category {
				return PolicyOutcomeAllow
			}
		}
		for _, c := range r.Notify {
			if c == category {
				return PolicyOutcomeNotify
			}
		}
		for _, c := range r.Warn {
			if c == category {
				return PolicyOutcomeWarn
			}
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
// 3. The rule for the scope is selected; when no rule exists for the scope
// the outcome is an implicit allow.
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

	if !found {
		return PolicyEvaluation{
			License:  license,
			Category: category,
			Scope:    effScope,
			Outcome:  PolicyOutcomeAllow,
		}
	}
	return PolicyEvaluation{
		License:  license,
		Category: category,
		Scope:    effScope,
		Outcome:  rule.resolveOutcome(category),
	}
}
