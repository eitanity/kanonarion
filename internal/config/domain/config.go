// Package domain contains the core types for the config bounded context.
package domain

// SupportedSchemaVersion is the config schema version this implementation
// produces and consumes.
//
// v2 adds the unified supply-chain governance blocks
// (directive_policy / godebug_policy / vendor_policy / fips_policy). The bump
// is additive: a v1 config has no governance blocks, they resolve to their
// zero value (implicit allow), so v1 files continue to load unchanged. See
// docs/schema/MIGRATIONS.md and.
const SupportedSchemaVersion = "2"

// PolicyOutcome is the result of evaluating a license against a policy rule.
type PolicyOutcome string

const (
	// PolicyOutcomeAllow means the license is acceptable with no action required.
	PolicyOutcomeAllow PolicyOutcome = "allow"
	// PolicyOutcomeNotify means the license should be surfaced for awareness.
	PolicyOutcomeNotify PolicyOutcome = "notify"
	// PolicyOutcomeWarn means the license requires attention before use.
	PolicyOutcomeWarn PolicyOutcome = "warn"
)

// UnknownLicensePolicy governs how an *undetermined* license is treated
// for a scope. A license is undetermined when the detector could not
// resolve any SPDX identifier at all (no license record, or status
// None/Multiple/ExtractionFailed/Cancelled) and no override applies.
//
// This is deliberately distinct from PolicyOutcome: it adds "block" (a
// hard compliance gate that fails `audit`) so that *uncertainty* is never
// silently rendered as a clean "allow". A named-but-uncategorised
// license (e.g. "Totally-Unknown-1.0") is NOT undetermined — that remains
// a normal rule-default decision.
type UnknownLicensePolicy string

const (
	// UnknownLicenseAllow accepts undetermined licenses silently. Unsafe
	// for production; provided for completeness / opt-out.
	UnknownLicenseAllow UnknownLicensePolicy = "allow"
	// UnknownLicenseNotify surfaces undetermined licenses for awareness.
	UnknownLicenseNotify UnknownLicensePolicy = "notify"
	// UnknownLicenseWarn flags undetermined licenses as needing attention.
	UnknownLicenseWarn UnknownLicensePolicy = "warn"
	// UnknownLicenseBlock treats an undetermined license as a hard
	// compliance failure (non-zero `audit` exit).
	UnknownLicenseBlock UnknownLicensePolicy = "block"
)

// Config is the root configuration type loaded from <store-root>/config.yaml.
type Config struct {
	Version          string
	Preferences      Preferences
	LicensePolicy    LicensePolicy
	LicenseOverrides map[string]string // module path → SPDX license expression
	Callgraph        CallgraphConfig

	// Unified supply-chain governance policy. Each block is a
	// top-level config section; rules are wired by the gap tickets
	// A zero-value block resolves to implicit allow.
	DirectivePolicy DirectivePolicy
	GoDebugPolicy   GoDebugPolicy
	VendorPolicy    VendorPolicy
	FIPSPolicy      FIPSPolicy
}

// Preferences holds sticky per-user output preferences.
type Preferences struct {
	JSON     bool
	LogLevel string
	// Progress enables the throttled fetch-phase progress heartbeat on long
	// walk/inspect runs. Default true; set false (or pass --no-progress) for
	// fully silent runs. The heartbeat is written to stderr, never stdout, so it
	// never affects --json output.
	Progress bool
}

// LicensePolicy defines named license categories and scope-based rules.
type LicensePolicy struct {
	Categories map[string][]string // category name → SPDX identifiers
	Rules      []LicensePolicyRule
}

// LicensePolicyRule maps category names to outcomes for a given dependency scope.
// Categories not listed in Allow, Notify, or Warn resolve to Default.
// When Default is empty (unset), it resolves to PolicyOutcomeAllow.
// The same implicit allow applies when no rule exists for a scope.
type LicensePolicyRule struct {
	Scope   string        // "production" | "tool" | "test"
	Allow   []string      // category names with outcome allow
	Notify  []string      // category names with outcome notify
	Warn    []string      // category names with outcome warn
	Default PolicyOutcome // outcome for categories not listed above; "" → allow
	// UnknownLicense governs *undetermined* licenses (no resolvable SPDX)
	// for this scope. Empty resolves to a scope default: "block" for
	// production, "warn" for any other scope (see DefaultUnknownLicense).
	UnknownLicense UnknownLicensePolicy
}

// DefaultUnknownLicense is the fallback UnknownLicensePolicy for a scope
// when a rule does not set one (or no rule exists). Production defaults to
// block so undetermined licenses fail closed; other scopes warn.
func DefaultUnknownLicense(normalisedScope string) UnknownLicensePolicy {
	if normalisedScope == "production" {
		return UnknownLicenseBlock
	}
	return UnknownLicenseWarn
}

// CallgraphConfig holds call-graph extraction settings.
type CallgraphConfig struct {
	Exclude []string // package import paths excluded from analysis
}

// DefaultConfig returns a Config populated with the built-in defaults documented in.
func DefaultConfig() Config {
	return Config{
		Version: SupportedSchemaVersion,
		Preferences: Preferences{
			JSON:     false,
			LogLevel: "warn",
			Progress: true,
		},
		LicensePolicy: LicensePolicy{
			Categories: map[string][]string{
				"permissive":      {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC"},
				"weak_copyleft":   {"LGPL-2.1-only", "LGPL-3.0-only", "MPL-2.0"},
				"strong_copyleft": {"GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only", "AGPL-3.0-only"},
				"restricted":      {"SSPL-1.0", "BSL-1.1", "AGPL-3.0-only"},
			},
			Rules: []LicensePolicyRule{
				{
					Scope:          "production",
					Allow:          []string{"permissive"},
					Notify:         []string{"weak_copyleft"},
					Warn:           []string{"strong_copyleft", "restricted"},
					Default:        PolicyOutcomeAllow,
					UnknownLicense: UnknownLicenseBlock,
				},
				{
					Scope:          "tool",
					Allow:          []string{"permissive", "weak_copyleft", "strong_copyleft"},
					Notify:         []string{"restricted"},
					Default:        PolicyOutcomeAllow,
					UnknownLicense: UnknownLicenseWarn,
				},
			},
		},
		LicenseOverrides: map[string]string{},
		Callgraph: CallgraphConfig{
			Exclude: []string{},
		},
		// Default governance posture. The highest-risk classes
		// local-path replace, patched-version exclusion, security-weakening
		// GODEBUG settings, vendor drift — are flagged by default; benign
		// classes pass. Gap tickets refine the evaluation semantics.
		DirectivePolicy: DirectivePolicy{
			LocalPathReplace:  PolicyOutcomeWarn,
			ModulePathReplace: PolicyOutcomeWarn,
			VersionReplace:    PolicyOutcomeNotify,
			ExcludeNewer:      PolicyOutcomeWarn,
			ExcludeOlder:      PolicyOutcomeAllow,
			Default:           PolicyOutcomeNotify,
		},
		GoDebugPolicy: GoDebugPolicy{
			Red:   PolicyOutcomeWarn,
			Amber: PolicyOutcomeNotify,
			Green: PolicyOutcomeAllow,
		},
		VendorPolicy: VendorPolicy{
			OnDrift:         PolicyOutcomeWarn,
			OnInconsistency: PolicyOutcomeWarn,
			VendorOnly:      false,
		},
		FIPSPolicy: FIPSPolicy{
			Required:    false,
			OnDeviation: PolicyOutcomeWarn,
		},
	}
}
