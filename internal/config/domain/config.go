// Package domain contains the core types for the config bounded context.
package domain

import (
	"fmt"
	"strings"
	"time"
)

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
	// PolicyOutcomeUnevaluated means the gate ran no rule at all: the scope in
	// force matched no license_policy rule, so nothing was measured. It is an
	// evaluation result only — never a valid outcome in a configured rule —
	// and callers must treat it as non-passing, since an unevaluated gate that
	// exits clean is indistinguishable from one that evaluated and permitted.
	PolicyOutcomeUnevaluated PolicyOutcome = "unevaluated"
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
	// CopyrightDeclarations records, per module path (optionally @version), a
	// copyright line a human read upstream for a module whose archive carries
	// none. It is an operator assertion, not a measurement, which is why it
	// lives here beside license_overrides rather than in the store.
	CopyrightDeclarations map[string]CopyrightDeclaration
	Callgraph             CallgraphConfig
	Staleness             StalenessConfig

	// Unified supply-chain governance policy. Each block is a
	// top-level config section; rules are wired by the gap tickets
	// A zero-value block resolves to implicit allow.
	DirectivePolicy DirectivePolicy
	GoDebugPolicy   GoDebugPolicy
	VendorPolicy    VendorPolicy
	FIPSPolicy      FIPSPolicy
	FetchPolicy     FetchPolicy
}

// FetchPolicy governs the fetch stage's cross-verification posture.
//
// It is separate from the depth policy file, which not every invocation has,
// and which is a per-project artefact. The VCS host set is an operator-level
// decision about what this machine will talk to, so it belongs where the
// operator's other standing decisions live.
type FetchPolicy struct {
	// AllowedVCSHosts names the forges kanonarion may hand to a git subprocess.
	//
	// Nil (absent) is not the same as empty. Absent means "no opinion": the
	// built-in host set applies in ADVISORY mode, so a host outside it is
	// reported and still contacted. Naming the field switches to ENFORCING
	// mode, and a host outside the named set is refused. Empty is rejected at
	// load time rather than read as "trust nobody" — that is --skip-vcs-verify.
	AllowedVCSHosts []string
}

// CopyrightDeclaration is one operator-recorded copyright line for a module
// the copyright extractor found nothing in.
//
// Every field is required. An SPDX identifier is self-evidencing — a reviewer
// checks it against the licence text — but a copyright line is an assertion
// about what a person read somewhere, and without an author, a date and a cited
// basis it cannot be checked by anyone. A partial entry is refused at load
// rather than carried into an attribution document that cannot be audited.
//
// The yaml tags are for `config get`, which marshals the loaded value straight
// back out: without them the output spells keys as Go field names and is not
// valid config to paste back into the file.
type CopyrightDeclaration struct {
	// Copyright is the verbatim line to attribute, exactly as it reads upstream.
	Copyright string `yaml:"copyright"`
	// DeclaredBy names the person accountable for the assertion.
	DeclaredBy string `yaml:"declared_by"`
	// DeclaredOn is the date they read the basis, as an ISO 8601 date.
	DeclaredOn string `yaml:"declared_on"`
	// Basis cites what they read: the upstream file, commit or repository page.
	Basis string `yaml:"basis"`
}

// declarationDateLayout is the only accepted DeclaredOn form. A free-text date
// ("last week", "2024") cannot be compared against a module version's release,
// which is the one thing a reviewer wants to do with it.
const declarationDateLayout = "2006-01-02"

// Validate reports why a declaration cannot be used. The caller prefixes the
// coordinate, so the message names which entry is at fault.
func (d CopyrightDeclaration) Validate() error {
	for _, f := range []struct {
		name, value string
	}{
		{"copyright", d.Copyright},
		{"declared_by", d.DeclaredBy},
		{"declared_on", d.DeclaredOn},
		{"basis", d.Basis},
	} {
		if strings.TrimSpace(f.value) == "" {
			return fmt.Errorf("%s is required: a copyright a human supplied is only auditable with the line, who declared it, when, and the basis they cite", f.name)
		}
	}
	if _, err := time.Parse(declarationDateLayout, d.DeclaredOn); err != nil {
		return fmt.Errorf("declared_on %q: must be an ISO 8601 date (YYYY-MM-DD)", d.DeclaredOn)
	}
	return nil
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
// A scope with no rule at all is different: the gate is unevaluated there and
// EvaluateLicense reports it as blocking, never as an implicit allow.
type LicensePolicyRule struct {
	Scope   string        `yaml:"scope"`   // "production" | "tool" | "test"
	Allow   []string      `yaml:"allow"`   // category names with outcome allow
	Notify  []string      `yaml:"notify"`  // category names with outcome notify
	Warn    []string      `yaml:"warn"`    // category names with outcome warn
	Default PolicyOutcome `yaml:"default"` // outcome for categories not listed above; "" → allow
	// UnknownLicense governs *undetermined* licenses (no resolvable SPDX)
	// for this scope. Empty resolves to a scope default: "block" for
	// production, "warn" for any other scope (see DefaultUnknownLicense).
	//
	// Tagged because `config get license_policy.rules` marshals this struct
	// back out, and the untagged Go name ("unknownlicense") is not the config
	// key an operator would paste back into the file.
	UnknownLicense UnknownLicensePolicy `yaml:"unknown_license"`
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

// StalenessConfig governs the store-backed ledger of latest-version lookups.
type StalenessConfig struct {
	// TTL is how long a recorded lookup may be served before the proxy is asked
	// again. Zero (or negative) disables the ledger for reads, which makes every
	// command re-pay the proxy sweep — the behaviour that predates the ledger,
	// kept reachable rather than removed.
	TTL time.Duration

	// ProbeConcurrency is how many newer-major probe requests may be in flight
	// at once for one command.
	//
	// The probe asks about a module path one major above the pin, which for
	// almost every module does not exist. It is therefore one request per module
	// in the dependency closure, and issuing them one at a time is what made a
	// 552-module sweep take tens of minutes. Measured against proxy.golang.org
	// over 554 real candidates: serial ~1.3 s each, 8-wide 0.194 s each,
	// 16-wide 0.019 s each warm.
	//
	// It is bounded rather than unlimited because the proxy throttles, and a
	// throttled probe does not fail cleanly — it answers 200 with an empty body,
	// which is a lost answer rather than an error. Wider is not simply faster:
	// the same measurement saw 8-wide lose nothing to that condition and 16-wide
	// lose eight, absorbed by the retry decorator. Zero or negative means serial.
	//
	// This is a GLOBAL bound, not a per-host one. 72% of a real corpus is one
	// host and the proxy throttles per origin, so the right primitive is a
	// per-host limiter shared with the walk fetcher; that is owned elsewhere and
	// this key is sized to be replaced by it rather than to outlive it.
	ProbeConcurrency int
}

// DefaultStalenessTTL is the built-in staleness.ttl. An hour is short enough
// that a release published during a working session is picked up the same
// session, and long enough that a gates-and-staleness cadence pays the proxy
// sweep once rather than once per command.
const DefaultStalenessTTL = time.Hour

// DefaultStalenessProbeConcurrency is the built-in staleness.probe_concurrency.
//
// Sixteen is the measured knee: over 554 real probe candidates against
// proxy.golang.org it completed in 10.7 s warm against 107.4 s at eight, and
// the eight empty-200s it provoked are the condition the probe's retry
// decorator already absorbs. Going wider trades wall time for lost answers,
// which is the wrong trade on a surface whose whole purpose is not to lose them.
const DefaultStalenessProbeConcurrency = 16

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
		LicenseOverrides:      map[string]string{},
		CopyrightDeclarations: map[string]CopyrightDeclaration{},
		Callgraph: CallgraphConfig{
			Exclude: []string{},
		},
		Staleness: StalenessConfig{
			TTL:              DefaultStalenessTTL,
			ProbeConcurrency: DefaultStalenessProbeConcurrency,
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
