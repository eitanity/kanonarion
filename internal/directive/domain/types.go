// Package domain holds the pure business rules for the directive bounded
// context: detection, risk classification and deterministic ordering of
// go.mod / go.work `replace` and `exclude` directives. It performs no
// I/O — parsing is a port-backed adapter concern, policy evaluation lives in
// the config context.
package domain

import (
	"errors"
	"time"
)

// DirectiveSchemaVersion is the version of the DirectiveRecord JSON schema.
// Bump on a backwards-incompatible serialisation change.
// v2 adds the ecosystem scope marker.
const DirectiveSchemaVersion = "2"

// EcosystemGo is the only ecosystem kanonarion records describe. The ecosystem
// field declares the schema's scope — kanonarion is fitted for Go — rather than
// enabling polyglot mode. There is deliberately no "npm" or "cargo".
const EcosystemGo = "go"

// ErrUnsupportedEcosystem is returned when a stored record's ecosystem is
// absent or holds a value other than EcosystemGo.
var ErrUnsupportedEcosystem = errors.New("unsupported ecosystem: kanonarion records are Go-only")

// PipelineVersion tracks the directive extraction logic. Bump when detection
// or classification changes such that a re-scan of unchanged inputs would
// differ from a cached record.
const PipelineVersion = "0.1.0"

// Kind is the directive type.
type Kind string

const (
	// KindReplace is a go.mod / go.work `replace` directive.
	KindReplace Kind = "replace"
	// KindExclude is a go.mod `exclude` directive.
	KindExclude Kind = "exclude"
)

// RiskClass is the security risk a directive carries. Ordered most→least
// severe so callers can compare; String is the stable JSON token.
type RiskClass int

const (
	// RiskUnknown is the zero value and must never appear in a persisted
	// record — it signals an unclassified directive (a bug), distinct from a
	// genuine low-risk classification (absence ≠ benign answer).
	RiskUnknown RiskClass = iota
	// RiskHighest — replace → local path: no remote checksum to verify.
	RiskHighest
	// RiskHigh — replace → different module path (fork), or exclude of a
	// version newer than the resolved one (possible patched-version
	// exclusion).
	RiskHigh
	// RiskMedium — replace → different version of the same module.
	RiskMedium
	// RiskLow — exclude of a version older than the resolved one (cleanup).
	RiskLow
)

// String returns the stable JSON token for the class.
func (r RiskClass) String() string {
	switch r {
	case RiskHighest:
		return "highest"
	case RiskHigh:
		return "high"
	case RiskMedium:
		return "medium"
	case RiskLow:
		return "low"
	default:
		return "unknown"
	}
}

// Directive is one detected `replace`/`exclude` with its provenance,
// classification and policy verdict.
type Directive struct {
	Kind Kind
	// Source is the file the directive was read from, relative to the
	// project root ("go.mod" or "go.work").
	Source string
	// Line is the 1-based line number within Source.
	Line int

	// OldPath / OldVersion identify the directive's left-hand side. For an
	// exclude, OldPath@OldVersion is the excluded coordinate. For a replace,
	// OldVersion may be empty (replace-all-versions).
	OldPath    string
	OldVersion string

	// Replace right-hand side. Exactly one of (IsLocal → LocalPath) or
	// (NewPath[@NewVersion]) is set for a replace; all empty for an exclude.
	IsLocal    bool
	LocalPath  string
	NewPath    string
	NewVersion string

	// Applied is false when the directive does not affect the current build
	// (a replace declared by a dependency, not the main module/workspace).
	// Recorded but classified not-applied — never silently dropped.
	Applied bool

	// Class is the risk classification (see Classify).
	Class RiskClass

	// ReachabilityTarget is the module path (or local path) whose code
	// actually compiles for this directive. records it; rewiring
	// reachability to it is.
	ReachabilityTarget string

	// PolicyOutcome is the resolved governance verdict ("allow" | "notify" |
	// "warn"); PolicyBlocking marks a hard failure that fails the command.
	PolicyOutcome  string
	PolicyBlocking bool
}

// ParseResult is the raw, unclassified output of the parser port: the
// directives plus the versions the project resolves each required module to
// (the main module's require entries — sufficient for exclude newer/older
// classification; full MVS closure resolution is not performed here).
type ParseResult struct {
	ProjectModulePath string
	Directives        []Directive
	ResolvedVersions  map[string]string
}

// Record is the persisted, deterministic result of a project directive scan.
type Record struct {
	// Ecosystem declares the schema's scope; always EcosystemGo.
	Ecosystem string
	// ID uniquely identifies one scan invocation. Generated at extraction
	// time (ulid). Required by scan history / diff; empty for
	// pre- records read from older stores.
	ID string
	// ProjectModulePath is the module path declared by the scanned go.mod.
	ProjectModulePath string
	// Directives is the classified, sorted directive set.
	Directives []Directive
	// ResolvedVersions maps module path → the version the build resolves to,
	// used for exclude newer/older classification. Captured for audit.
	ResolvedVersions map[string]string

	// StartedAt / CompletedAt bracket the scan invocation; ExtractedAt is
	// retained as the canonical persistence timestamp (== CompletedAt for
	// new records) so pre- readers continue to see a meaningful value.
	StartedAt       time.Time
	CompletedAt     time.Time
	ExtractedAt     time.Time
	SchemaVersion   string
	PipelineVersion string
	// ContentHash is the deterministic hash of the sorted directive set.
	// Identical inputs produce identical hashes across scans — useful for
	// "no change since last scan" assertions in diff.
	ContentHash string
}
