// Package domain holds the pure business rules for the godebug bounded
// context: detection-result modelling, versioned taxonomy
// classification and deterministic ordering of GODEBUG / //go:debug settings.
// It performs no I/O — source parsing is a port-backed adapter concern and
// policy evaluation lives in the config context.
//
// GODEBUG (env) and //go:debug directives (Go 1.21+, baked into the binary as
// build defaults) change runtime security behaviour invisibly to
// dependency-graph analysis: some settings disable TLS verification, weaken
// crypto defaults, or revert deprecated protocol behaviour. This context
// makes each such setting a first-class, classified, policy-evaluated fact.
package domain

import (
	"errors"
	"time"
)

// GoDebugSchemaVersion is the version of the Record JSON schema. Bump on a
// backwards-incompatible serialisation change. It is independent
// of TaxonomyVersion: the on-disk shape and the risk knowledge evolve apart.
// v2 adds the ecosystem scope marker.
const GoDebugSchemaVersion = "2"

// EcosystemGo is the only ecosystem kanonarion records describe. The ecosystem
// field declares the schema's scope — kanonarion is fitted for Go — rather than
// enabling polyglot mode. There is deliberately no "npm" or "cargo".
const EcosystemGo = "go"

// ErrUnsupportedEcosystem is returned when a stored record's ecosystem is
// absent or holds a value other than EcosystemGo.
var ErrUnsupportedEcosystem = errors.New("unsupported ecosystem: kanonarion records are Go-only")

// PipelineVersion tracks the godebug extraction logic. Bump when detection or
// classification changes such that a re-scan of unchanged inputs would differ
// from a cached record. The embedded taxonomy version is folded in by
// PipelineFingerprint so a taxonomy update alone re-scans.
const PipelineVersion = "0.1.0"

// Tier is the security risk tier the versioned taxonomy assigns a setting.
// Ordered most→least severe so callers can compare; String is the stable
// JSON token.
type Tier int

const (
	// TierUnknown is the zero value: the setting is not in the taxonomy.
	// Per this is NOT silently treated as benign — it is a
	// distinct, surfaced state that the policy mapping fails safe on.
	TierUnknown Tier = iota
	// TierRed — security-weakening (tlsrsakex, tls10server, tls3des,
	// tlssha1, x509ignoreCN, tar/zipinsecurepath, …).
	TierRed
	// TierAmber — behaviour-modifying with security implications (http2
	// tuning, multipart limits, randautoseed, panicnil).
	TierAmber
	// TierGreen — benign (GC / debug logging toggles).
	TierGreen
)

// String returns the stable JSON token for the tier.
func (t Tier) String() string {
	switch t {
	case TierRed:
		return "red"
	case TierAmber:
		return "amber"
	case TierGreen:
		return "green"
	default:
		return "unknown"
	}
}

// Setting is one detected //go:debug setting with its provenance,
// classification and policy verdict.
type Setting struct {
	// Name / Value are the left/right of `//go:debug name=value`.
	Name  string
	Value string

	// Source is the file the directive was read from, relative to the
	// scan root. Line is the 1-based line of the `//go:debug` comment.
	Source string
	Line   int

	// Module is the module the source file belongs to. For an applied
	// setting this is the project module; for a dependency it is that
	// dependency's path (best-effort, from the vendor tree layout).
	Module string

	// Applied is false when the setting does not affect the current build:
	// `//go:debug` only takes effect in the main package of the *main*
	// module, so a directive carried by a dependency is recorded but
	// classified not-applied — never silently dropped.
	Applied bool

	// Tier is the taxonomy classification (see Classify).
	Tier Tier

	// PolicyOutcome is the resolved governance verdict ("allow" | "notify"
	// | "warn"); PolicyBlocking marks a hard failure that fails the command.
	PolicyOutcome  string
	PolicyBlocking bool
}

// ParseResult is the raw, unclassified output of the scanner port: the
// detected settings plus the scanned project's module path.
type ParseResult struct {
	ProjectModulePath string
	Settings          []Setting
}

// Record is the persisted, deterministic result of a project godebug scan.
type Record struct {
	// Ecosystem declares the schema's scope; always EcosystemGo.
	Ecosystem         string
	ProjectModulePath string
	Settings          []Setting

	// TaxonomyVersion records which taxonomy revision classified this scan,
	// so a re-classification under a newer taxonomy is detectable.
	TaxonomyVersion string

	ExtractedAt     time.Time
	SchemaVersion   string
	PipelineVersion string
	// ContentHash is the deterministic hash of the sorted setting set.
	ContentHash string
}
