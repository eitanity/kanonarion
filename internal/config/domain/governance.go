package domain

import "fmt"

// This file defines the unified supply-chain governance policy: one coherent
// schema covering the four supply-chain gaps (replace/exclude,
// GODEBUG, vendor, FIPS) rather than four ad-hoc additions
// owns the *shape* and its validation invariants; the gap
// tickets wire the evaluation rules. Every block reuses the existing
// PolicyOutcome vocabulary (allow | notify | warn); an empty/zero outcome is
// an implicit allow, which is exactly what a pre-v2 config (no governance
// blocks) resolves to — so the schema bump is additive and back-compatible.

// validGovernanceOutcome reports whether o is an acceptable governance
// outcome. Empty is permitted: it is the unset value resolving to an
// implicit allow, consistent with LicensePolicyRule.resolveOutcome.
func validGovernanceOutcome(o PolicyOutcome) bool {
	switch o {
	case "", PolicyOutcomeAllow, PolicyOutcomeNotify, PolicyOutcomeWarn:
		return true
	default:
		return false
	}
}

// DirectivePolicy governs go.mod/go.work replace & exclude directives by risk
// classification. Local-path replace is the highest-risk class (no
// remote checksum to verify); the default policy flags it.
type DirectivePolicy struct {
	LocalPathReplace  PolicyOutcome // replace -> local path (highest risk)
	ModulePathReplace PolicyOutcome // replace -> different module path (fork)
	VersionReplace    PolicyOutcome // replace -> different version, same module
	ExcludeNewer      PolicyOutcome // exclude of version newer than resolved
	ExcludeOlder      PolicyOutcome // exclude of version older than resolved
	Default           PolicyOutcome // unclassified directive; "" -> allow
}

// Validate checks every outcome is within the allowed vocabulary.
func (p DirectivePolicy) Validate() error {
	for name, o := range map[string]PolicyOutcome{
		"local_path_replace":  p.LocalPathReplace,
		"module_path_replace": p.ModulePathReplace,
		"version_replace":     p.VersionReplace,
		"exclude_newer":       p.ExcludeNewer,
		"exclude_older":       p.ExcludeOlder,
		"default":             p.Default,
	} {
		if !validGovernanceOutcome(o) {
			return fmt.Errorf("directive_policy.%s: invalid outcome %q (want allow, notify, or warn)", name, o)
		}
	}
	return nil
}

// Directive policy category tokens. The directive context maps a
// detected directive to one of these; the mapping lives there so config stays
// ignorant of the directive bounded context.
const (
	DirectiveLocalPathReplace  = "local_path_replace"
	DirectiveModulePathReplace = "module_path_replace"
	DirectiveVersionReplace    = "version_replace"
	DirectiveExcludeNewer      = "exclude_newer"
	DirectiveExcludeOlder      = "exclude_older"
)

// Evaluate resolves the governance outcome for a directive category (one of
// the Directive* tokens). An unrecognised category, or a category whose
// outcome is unset, falls back to Default; an unset Default resolves to an
// implicit allow — mirroring LicensePolicyRule.resolveOutcome so the two
// policy families behave consistently.
func (p DirectivePolicy) Evaluate(category string) PolicyOutcome {
	var o PolicyOutcome
	switch category {
	case DirectiveLocalPathReplace:
		o = p.LocalPathReplace
	case DirectiveModulePathReplace:
		o = p.ModulePathReplace
	case DirectiveVersionReplace:
		o = p.VersionReplace
	case DirectiveExcludeNewer:
		o = p.ExcludeNewer
	case DirectiveExcludeOlder:
		o = p.ExcludeOlder
	}
	if o == "" {
		o = p.Default
	}
	if o == "" {
		return PolicyOutcomeAllow
	}
	return o
}

// GoDebugPolicy governs GODEBUG / //go:debug settings by the versioned
// taxonomy tier assigned in red (security-weakening), amber
// (behaviour-modifying with security implications), green (benign).
type GoDebugPolicy struct {
	Red   PolicyOutcome // security-weakening settings
	Amber PolicyOutcome // behaviour-modifying with security implications
	Green PolicyOutcome // benign (GC/debug logging)
}

// Validate checks every tier outcome is within the allowed vocabulary.
func (p GoDebugPolicy) Validate() error {
	for name, o := range map[string]PolicyOutcome{
		"red":   p.Red,
		"amber": p.Amber,
		"green": p.Green,
	} {
		if !validGovernanceOutcome(o) {
			return fmt.Errorf("godebug_policy.%s: invalid outcome %q (want allow, notify, or warn)", name, o)
		}
	}
	return nil
}

// GODEBUG taxonomy tier tokens. The godebug context maps a detected
// setting's taxonomy tier to one of these; the mapping lives there so config
// stays ignorant of the godebug bounded context.
const (
	GoDebugRed   = "red"
	GoDebugAmber = "amber"
	GoDebugGreen = "green"
)

// Evaluate resolves the governance outcome for a GODEBUG setting's taxonomy
// tier (one of the GoDebug* tokens). An unrecognised tier — crucially the
// "setting not in the taxonomy" case — does NOT fall through to an implicit
// allow: per (absence is not a benign answer) it fails safe to the
// Red posture, so an unclassified runtime-behaviour knob is never silently
// permitted. An explicitly green setting whose outcome is unset still
// resolves to an implicit allow, mirroring the rest of the schema.
func (p GoDebugPolicy) Evaluate(tier string) PolicyOutcome {
	var o PolicyOutcome
	switch tier {
	case GoDebugRed:
		o = p.Red
	case GoDebugAmber:
		o = p.Amber
	case GoDebugGreen:
		o = p.Green
	default:
		// Unknown tier fails safe to the red posture.
		if p.Red == "" {
			return PolicyOutcomeWarn
		}
		return p.Red
	}
	if o == "" {
		return PolicyOutcomeAllow
	}
	return o
}

// VendorPolicy governs vendored-tree analysis: how vendor/ drift and
// vendor/modules.txt inconsistencies are treated, and whether the scan must
// run in airgapped vendor-only mode (no proxy contact).
type VendorPolicy struct {
	OnDrift         PolicyOutcome // vendored file differs from expected checksum
	OnInconsistency PolicyOutcome // modules.txt vs filesystem disagreement
	VendorOnly      bool          // require offline vendor-only scans
}

// Validate checks every outcome is within the allowed vocabulary.
func (p VendorPolicy) Validate() error {
	for name, o := range map[string]PolicyOutcome{
		"on_drift":         p.OnDrift,
		"on_inconsistency": p.OnInconsistency,
	} {
		if !validGovernanceOutcome(o) {
			return fmt.Errorf("vendor_policy.%s: invalid outcome %q (want allow, notify, or warn)", name, o)
		}
	}
	return nil
}

// Vendor finding-category tokens. The vendor context maps each
// detected finding to one of these; the mapping lives there so config stays
// ignorant of the vendor bounded context.
const (
	VendorDrift         = "drift"
	VendorInconsistency = "inconsistency"
)

// Evaluate resolves the governance outcome for a vendor finding category (one
// of the Vendor* tokens). An unrecognised category resolves to the stricter
// of the two configured postures rather than an implicit allow: per
// an unclassified vendor discrepancy is uncertainty, not a clean tree, so it
// must not silently pass. An explicitly-categorised finding whose outcome is
// unset still resolves to an implicit allow, mirroring the rest of the schema.
func (p VendorPolicy) Evaluate(category string) PolicyOutcome {
	switch category {
	case VendorDrift:
		if p.OnDrift == "" {
			return PolicyOutcomeAllow
		}
		return p.OnDrift
	case VendorInconsistency:
		if p.OnInconsistency == "" {
			return PolicyOutcomeAllow
		}
		return p.OnInconsistency
	default:
		return stricterOutcome(p.OnDrift, p.OnInconsistency)
	}
}

// stricterOutcome returns the more severe of two outcomes (warn > notify >
// allow), with an unset outcome treated as warn so an unknown finding fails
// safe.
func stricterOutcome(a, b PolicyOutcome) PolicyOutcome {
	rank := func(o PolicyOutcome) int {
		switch o {
		case PolicyOutcomeNotify:
			return 1
		case PolicyOutcomeAllow:
			return 0
		default: // warn or unset → fail safe
			return 2
		}
	}
	if rank(a) >= rank(b) {
		if rank(a) == 2 {
			return PolicyOutcomeWarn
		}
		return a
	}
	if rank(b) == 2 {
		return PolicyOutcomeWarn
	}
	return b
}

// FIPSPolicy governs FIPS eligibility assessment. Required marks the
// project as needing a FIPS-capable toolchain; OnDeviation is the outcome for
// a toolchain/algorithm deviation from that requirement.
type FIPSPolicy struct {
	Required    bool          // project must build with a FIPS-capable toolchain
	OnDeviation PolicyOutcome // outcome when a deviation is detected
}

// Validate checks the deviation outcome is within the allowed vocabulary.
func (p FIPSPolicy) Validate() error {
	if !validGovernanceOutcome(p.OnDeviation) {
		return fmt.Errorf("fips_policy.on_deviation: invalid outcome %q (want allow, notify, or warn)", p.OnDeviation)
	}
	return nil
}

// FIPS finding-category tokens. The fips context maps each detected
// fact to one of these; the mapping lives there so config stays ignorant of
// the fips bounded context.
const (
	// FIPSCompliant marks a finding that does NOT deviate from the FIPS
	// posture: an algorithm/import the FIPS-validated module covers, or a
	// toolchain confirmed FIPS-capable. It always resolves to allow.
	FIPSCompliant = "fips_compliant"
	// FIPSDeviation marks a finding that breaks FIPS eligibility: a
	// non-FIPS algorithm import, a cgo-linked crypto library, or a
	// toolchain that is not on the catalogue of FIPS-capable variants.
	FIPSDeviation = "fips_deviation"
	// FIPSUnknown marks a finding the assessor cannot classify with
	// confidence — most notably a cgo-crypto dependency whose binding
	// shape sits in the known cgo analysis gap. Per
	// this is NOT silently treated as compliant.
	FIPSUnknown = "fips_unknown"
)

// Evaluate resolves the governance outcome for a FIPS finding category (one
// of the FIPS* tokens). The policy is gated by Required: a project that has
// not opted into FIPS resolves every category to allow — the assessor still
// records the findings as facts, but they are not policy violations. When
// Required is true, a compliant finding allows, a deviation resolves to
// OnDeviation (default warn), and an unknown finding fails safe to warn
// so an unclassified crypto fact is never silently permitted.
func (p FIPSPolicy) Evaluate(category string) PolicyOutcome {
	if !p.Required {
		return PolicyOutcomeAllow
	}
	switch category {
	case FIPSCompliant:
		return PolicyOutcomeAllow
	case FIPSDeviation:
		if p.OnDeviation == "" {
			return PolicyOutcomeWarn
		}
		return p.OnDeviation
	default: // FIPSUnknown or anything unrecognised — fail safe.
		return PolicyOutcomeWarn
	}
}

// ValidateGovernance runs every governance block's invariants. It is the
// single entrypoint `policy validate` and config loading call so the four
// blocks stay one coherent schema rather than four independent checks.
func (c Config) ValidateGovernance() error {
	if err := c.DirectivePolicy.Validate(); err != nil {
		return err
	}
	if err := c.GoDebugPolicy.Validate(); err != nil {
		return err
	}
	if err := c.VendorPolicy.Validate(); err != nil {
		return err
	}
	return c.FIPSPolicy.Validate()
}
