// Package domain holds the pure business rules for the fips bounded context
// assessment modelling, toolchain & algorithm catalogues, and the
// deterministic ordering of FIPS findings. It performs no I/O — source
// parsing is a port-backed adapter concern (mirroring godebug) and policy
// evaluation lives in the config context.
//
// FIPS 140-3 is a regulatory requirement in target markets (DORA/EBA, US
// federal, NIS2). Stock Go has no CMVP-validated crypto; variants do
// (BoringCrypto Go, Microsoft Go/CNG, Red Hat go-toolset/OpenSSL, AWS Go
// FIPS). Kanonarion reports FIPS *eligibility*, NOT formal CMVP validation —
// every assessment surfaces this distinction explicitly so the output cannot
// be misread as a validation attestation.
package domain

import (
	"errors"
	"time"
)

// FIPSSchemaVersion is the version of the Record JSON schema. Bump on a
// backwards-incompatible serialisation change. It is independent of the
// CatalogueVersion: the on-disk shape and the recognised-variant knowledge
// evolve apart, mirroring godebug's TaxonomyVersion split.
// v2 adds the ecosystem scope marker.
const FIPSSchemaVersion = "2"

// EcosystemGo is the only ecosystem kanonarion records describe. The ecosystem
// field declares the schema's scope — kanonarion is fitted for Go — rather than
// enabling polyglot mode. There is deliberately no "npm" or "cargo".
const EcosystemGo = "go"

// ErrUnsupportedEcosystem is returned when a stored record's ecosystem is
// absent or holds a value other than EcosystemGo.
var ErrUnsupportedEcosystem = errors.New("unsupported ecosystem: kanonarion records are Go-only")

// PipelineVersion tracks the fips extraction logic. Bump when detection or
// classification changes such that a re-scan of unchanged inputs would
// differ from a cached record. The embedded catalogue version is folded in
// by PipelineFingerprint so a catalogue update alone re-scans.
const PipelineVersion = "0.2.0"

// EligibilityCaveat is the verbatim statement included in every Record
// summarising the eligibility-vs-validation distinction. It is part of the
// domain (not display copy) so every consumer — CLI table, JSON output,
// audit envelope, AI agent context — sees the same wording and cannot
// silently drop it.
const EligibilityCaveat = "Kanonarion reports FIPS *eligibility* (toolchain + algorithm posture); it does NOT attest to formal CMVP / FIPS 140-3 validation. A FIPS-capable toolchain may still need vendor-supplied validation evidence."

// Finding categories. Each detected fact is one of these.
type FindingKind string

const (
	// FindingToolchain records the toolchain variant recognised (or not)
	// from the project's go.mod toolchain directive / build-info hint.
	// Exactly one toolchain finding is recorded per scan.
	FindingToolchain FindingKind = "toolchain"
	// FindingAlgorithm records a non-FIPS algorithm import (md5, rc4, …).
	FindingAlgorithm FindingKind = "non_fips_algorithm"
	// FindingDirectRandom records a direct import of crypto/rand. This is
	// a *surface* fact: acceptable under FIPS variants whose runtime
	// re-routes crypto/rand to a validated DRBG, but recorded so the
	// reviewer can audit it.
	FindingDirectRandom FindingKind = "direct_crypto_rand"
	// FindingCgoCrypto records a dependency that links a cgo crypto
	// library. The known cgo gap (no cgo dependency analysis) means we
	// surface the dependency but classify the finding as unknown rather
	// than asserting it is/isn't FIPS-eligible.
	FindingCgoCrypto FindingKind = "cgo_crypto_dependency"
)

// Category is the policy-category token (FIPSCompliant / FIPSDeviation /
// FIPSUnknown in config domain) a finding maps to. Kept as plain strings so
// the fips domain stays free of a config import.
type Category string

const (
	// CategoryCompliant — the finding is compatible with FIPS posture.
	CategoryCompliant Category = "fips_compliant"
	// CategoryDeviation — the finding breaks FIPS eligibility.
	CategoryDeviation Category = "fips_deviation"
	// CategoryUnknown — the assessor cannot classify with confidence
	// (notably cgo-crypto, bounded by the known cgo gap).
	// requires this is NOT silently treated as compliant.
	CategoryUnknown Category = "fips_unknown"
)

// Finding is one assessed fact about FIPS eligibility.
type Finding struct {
	Kind FindingKind

	// Package is the Go import path the finding is about (for algorithm
	// and direct-random findings). Empty for toolchain findings.
	Package string

	// Module is the module path the source file belongs to. For an
	// applied finding this is the project module; for a dependency it is
	// that dependency's module path (best-effort).
	Module string

	// Source is the file the finding was read from, relative to the scan
	// root, with 1-based Line. Empty for toolchain findings (the
	// toolchain directive is fundamentally project-scope, not a line of
	// code: source/line would be misleading provenance).
	Source string
	Line   int

	// Toolchain is the recognised variant for FindingToolchain. Empty
	// when the variant is not in the catalogue (stock Go, or an
	// unrecognised flavour). For other kinds this is empty.
	Toolchain string

	// ToolchainRaw is the raw toolchain string read from go.mod /
	// build-info — preserved for FindingToolchain so the reviewer can
	// see what was matched (or why nothing matched).
	ToolchainRaw string

	// Category is the policy-mapping token; PolicyOutcome / PolicyBlocking
	// are the resolved verdict.
	Category       Category
	PolicyOutcome  string
	PolicyBlocking bool
}

// ParseResult is the raw, unclassified output of the scanner port: the
// detected findings plus the scanned project's module path and the raw
// toolchain string.
type ParseResult struct {
	ProjectModulePath string
	ToolchainRaw      string
	// GoVersion is the version from the go.mod `go` directive (e.g. "1.24",
	// "1.26.4"), empty when absent. Used only to gate native-FIPS capability:
	// the Go Cryptographic Module ships in the standard toolchain from 1.24.
	GoVersion string
	// FIPS140 is the value of the main module's `//go:debug fips140=…`
	// directive, empty when the directive is absent. The declarative,
	// source-visible signal that native FIPS mode is requested.
	FIPS140  string
	Findings []Finding
}

// Record is the persisted, deterministic result of a project FIPS
// assessment. ToolchainCapable is the headline answer for the consumer; the
// per-finding detail lives in Findings.
type Record struct {
	// Ecosystem declares the schema's scope; always EcosystemGo.
	Ecosystem         string
	ProjectModulePath string

	// ToolchainCapable is true when the recognised toolchain variant is
	// on the FIPS-capable catalogue. False for stock Go or an
	// unrecognised flavour — never silently true.
	ToolchainCapable bool
	// ToolchainVariant is the catalogue entry name when recognised
	// ("boringcrypto", "microsoft-fipscapable", …), or empty.
	ToolchainVariant string
	// ToolchainRaw is what was actually read (e.g. "go1.22.0", "go1.22.0
	// X:boringcrypto"). Empty when no toolchain string was available.
	ToolchainRaw string
	// FIPSModeStaticallyEnabled records whether build-info evidence
	// statically confirms FIPS mode (e.g. a recognised build tag).
	// Source-only detection is heuristic: see assessor for derivation.
	FIPSModeStaticallyEnabled bool

	Findings []Finding

	// ComplianceAssessment is a short, deterministic, eligibility-vs-
	// validation-caveated summary line for the consumer ("eligible",
	// "not eligible: …", "limited: cgo crypto"). Stable across runs:
	// driven only by the sorted findings + toolchain capability.
	ComplianceAssessment string

	// Caveat is EligibilityCaveat, recorded on the record so it travels
	// with every serialisation.
	Caveat string

	// CatalogueVersion records which toolchain+algorithm catalogue
	// revision classified this scan.
	CatalogueVersion string

	ExtractedAt     time.Time
	SchemaVersion   string
	PipelineVersion string
	// ContentHash is the deterministic hash of the sorted finding set
	// folded with the toolchain capability headline.
	ContentHash string
}
