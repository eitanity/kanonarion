package domain

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// ScanMode controls how govulncheck analyses a module.
type ScanMode string

const (
	// ScanModeSource builds the full SSA + call graph (default). Precise but slow for large modules.
	ScanModeSource ScanMode = "source"
	// ScanModeBinary builds a test binary then scans its symbol table. Much faster; no call-graph precision.
	ScanModeBinary ScanMode = "binary"
)

// VulnerabilityStatus describes the outcome of a module's vulnerability scan.
type VulnerabilityStatus string

const (
	StatusClean       VulnerabilityStatus = "Clean"
	StatusAffected    VulnerabilityStatus = "Affected"
	StatusUnscannable VulnerabilityStatus = "Unscannable"
	StatusScanFailed  VulnerabilityStatus = "ScanFailed"
)

// UnscanReason is a machine-readable cause code for why a module could not be
// fully scanned from source. It accompanies UnscannableReason (human prose)
// so consumers can filter or route on the root cause without parsing strings.
type UnscanReason string

const (
	// UnscanReasonGeneratedAssets indicates the module zip is missing source
	// files that are produced by a code-generation step (go generate, Makefile,
	// embed directives, etc.). govulncheck hits undefined symbols.
	UnscanReasonGeneratedAssets UnscanReason = "generated-assets-missing"
	// UnscanReasonGoWorkMonorepo indicates the module references siblings via a
	// go.work file that are not present in the module zip.
	UnscanReasonGoWorkMonorepo UnscanReason = "go-work-monorepo"
	// UnscanReasonRelativeReplace indicates the module uses a replace directive
	// pointing to a sibling directory not included in the module zip.
	UnscanReasonRelativeReplace UnscanReason = "relative-replace-directive"
	// UnscanReasonWindowsOnly indicates the module only builds on Windows.
	UnscanReasonWindowsOnly UnscanReason = "windows-only"
	// UnscanReasonCHeadersMissing indicates the module requires C system headers
	// that are not available on the scanning host.
	UnscanReasonCHeadersMissing UnscanReason = "c-headers-missing"
	// UnscanReasonMissingGoSum indicates the module cannot be resolved because a
	// go.sum entry is absent and network access is not available.
	UnscanReasonMissingGoSum UnscanReason = "missing-go-sum"
	// UnscanReasonVersionNotInToolchain indicates a module scanned in isolation
	// re-runs MVS as its own main module and selects a dependency version that is
	// not part of the analysed project's toolchain (its build list resolved a
	// different, usually higher, version). The scan is pinned to the verified
	// store, so that out-of-toolchain version is deliberately absent rather than
	// fetched from the network — which would analyse a dependency graph the
	// project never builds. Surfaced as a coverage gap, never a confident clean.
	UnscanReasonVersionNotInToolchain UnscanReason = "version-not-in-toolchain"
	// UnscanReasonBuildIncompatible is the catch-all for build failures that do
	// not match a more specific pattern.
	UnscanReasonBuildIncompatible UnscanReason = "build-incompatible"
	// UnscanReasonOOMKilled indicates govulncheck was killed by the OS (OOM or
	// SIGKILL / exit 137). The scan is retryable on a host with more memory.
	UnscanReasonOOMKilled UnscanReason = "oom-killed"
	// UnscanReasonNoGoMod indicates the module zip does not contain a go.mod
	// file, so govulncheck cannot be run.
	UnscanReasonNoGoMod UnscanReason = "no-go-mod"
	// UnscanReasonLocalReplace indicates the module is a local filesystem
	// replacement (a replace directive pointing at a working-tree path) rather
	// than a fetched, versioned module, so there is no fetched source to scan.
	UnscanReasonLocalReplace UnscanReason = "local-replace"
)

// ExpectedOutOfToolchain reports whether an Unscannable reason is the expected
// consequence of hermetic per-module scanning rather than a genuine scan fault.
// A module whose isolated build re-selects a dependency version the project's
// build never resolved is not a coverage failure to fix: its project-rooted
// reachability is answered by a whole-build analysis (reachability --local), not
// by re-scanning it in isolation. Distinguishing it lets the presentation layer
// read it as an informational metadata-only outcome instead of alarming like a
// real failure (no-go-mod, oom-killed, build-incompatible), which stay faults.
func (r UnscanReason) ExpectedOutOfToolchain() bool {
	return r == UnscanReasonVersionNotInToolchain
}

// ReachabilityConfidence describes the confidence level of a reachability determination.
type ReachabilityConfidence string

const (
	ConfidenceHigh    ReachabilityConfidence = "High"
	ConfidenceMedium  ReachabilityConfidence = "Medium"
	ConfidenceLow     ReachabilityConfidence = "Low"
	ConfidenceUnknown ReachabilityConfidence = "Unknown"
)

// Severity represents CVSS metrics as provided by the vulnerability database.
type Severity struct {
	Vector string  `json:"vector,omitzero"`
	Score  float64 `json:"score,omitzero"`
	Label  string  `json:"label,omitzero"`
}

// DatabaseSnapshot identifies a pinned snapshot of the vulnerability database.
type DatabaseSnapshot struct {
	Source      string    `json:"source"`
	Version     string    `json:"version"`
	RetrievedAt time.Time `json:"retrieved_at"`
	ContentHash string    `json:"content_hash"`
}

// SnapshotAgeDays reports how many whole days the vulnerability database
// snapshot had already aged by the time the verdict was validated — i.e. the
// lag between when the snapshot was retrieved and when the scan ran. It is a
// stored, deterministic fact (no dependence on the wall clock), letting a
// consumer judge how current the data behind an answer was. A negative gap
// (clock skew, or a zero retrieved-at) clamps to 0.
func SnapshotAgeDays(validatedAt, retrievedAt time.Time) int {
	if retrievedAt.IsZero() || validatedAt.Before(retrievedAt) {
		return 0
	}
	return int(validatedAt.Sub(retrievedAt).Hours() / 24)
}

// ReachabilityResult captures call-graph-based determination of whether a
// vulnerability is reachable from the target's entry points.
type ReachabilityResult struct {
	IsReachable  bool                   `json:"is_reachable"`
	Confidence   ReachabilityConfidence `json:"confidence"`
	ExamplePaths [][]string             `json:"example_paths,omitzero"`
}

// VulnerabilityFinding represents a single vulnerability affecting a module.
type VulnerabilityFinding struct {
	ID               string              `json:"id"`
	Aliases          []string            `json:"aliases,omitzero"`
	Summary          string              `json:"summary"`
	Details          string              `json:"details,omitzero"`
	AffectedRange    string              `json:"affected_range"`
	FixedIn          string              `json:"fixed_in,omitzero"`
	Severity         *Severity           `json:"severity,omitzero"`
	AffectedSymbols  []string            `json:"affected_symbols,omitzero"`
	Reachable        *ReachabilityResult `json:"reachable,omitzero"`
	ReachabilityNote string              `json:"reachability_note,omitzero"`
	References       []string            `json:"references,omitzero"`
	PublishedAt      time.Time           `json:"published_at"`
	ModifiedAt       time.Time           `json:"modified_at"`
}

// FixDisplay renders a finding's remediation state for human-facing output.
// A version bump fixes the finding when FixedIn is set; an empty FixedIn from a
// completed advisory lookup is the actionable "no fix available" state, not
// missing data. It is surfaced explicitly so absence is never shown as a blank
// — a finding exists to answer "will a version bump fix it?", and "no fix
// available" is a real answer.
func (f VulnerabilityFinding) FixDisplay() string {
	if f.FixedIn != "" {
		return "fixed in " + f.FixedIn
	}
	return "no fix available"
}

// SortFindings orders findings deterministically by ID so a record built from
// the metadata path hashes and serialises identically across runs.
func SortFindings(findings []VulnerabilityFinding) {
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].ID < findings[j].ID
	})
}

// VulnerabilityRecord is the aggregate root for a module's vulnerability scan.
type VulnerabilityRecord struct {
	// Ecosystem declares the schema's scope; always fetchdomain.EcosystemGo.
	Ecosystem         string                      `json:"ecosystem"`
	Coordinate        coordinate.ModuleCoordinate `json:"coordinate"`
	WalkID            string                      `json:"walk_id"`
	Findings          []VulnerabilityFinding      `json:"findings,omitzero"`
	OverallStatus     VulnerabilityStatus         `json:"overall_status"`
	UnscanReason      UnscanReason                `json:"unscan_reason,omitempty"`
	UnscannableReason string                      `json:"unscannable_reason,omitempty"`
	ErrorDetail       string                      `json:"error_detail,omitempty"`
	DatabaseSnapshot  DatabaseSnapshot            `json:"database_snapshot"`
	ScannedAt         time.Time                   `json:"scanned_at"`
	// FirstScannedAt anchors when this verdict was first established for the
	// (module, version, pipeline, snapshot) tuple. Unlike ScannedAt — which
	// moves forward to the run that last validated the verdict — it is set once
	// on first insert and never overwritten on reuse/re-attribution, so it
	// answers "when did we first find this out" for triage and audit. It is
	// provenance, not verdict, so it is excluded from ContentHash to keep
	// identity deterministic across re-validation.
	FirstScannedAt  time.Time `json:"first_scanned_at,omitzero"`
	PipelineVersion string    `json:"pipeline_version"`
	// CallGraphCompleteness records the per-module call-graph fidelity level that
	// backed this record's reachability determinations (BUILT_WITH_BODIES down to
	// FAILED / VERSION_NOT_IN_TOOLCHAIN), and CallGraphAlgorithm the algorithm/
	// devirt tier. Both are empty when no call graph was consulted. A scan-run
	// diff that produces a "resolved"/"unaffected" verdict across two records of
	// unequal fidelity is unsound — the finding or its reachability may have
	// changed because fidelity dropped, not because a fix landed — so the diff
	// downgrades such a verdict to UNRESOLVED with the mismatch named.
	CallGraphCompleteness string `json:"callgraph_completeness,omitempty"`
	CallGraphAlgorithm    string `json:"callgraph_algorithm,omitempty"`
	ContentHash           string `json:"content_hash"`
	// Reused is true when this record was served from the per-module cache for
	// the current call rather than freshly scanned (the same module/version was
	// already scanned under this snapshot by an earlier run). It is call-scoped
	// retrieval provenance, never persisted and never part of the content hash,
	// so callers can label a reuse as reuse instead of as a fresh scan.
	Reused bool `json:"-"`
}

// UnmarshalJSON decodes a VulnerabilityRecord and rejects any record whose
// ecosystem field is absent or holds a value other than fetchdomain.EcosystemGo.
// The field declares the schema's Go-only scope; a foreign or missing value is
// a malformed or legacy record.
func (r *VulnerabilityRecord) UnmarshalJSON(data []byte) error {
	type alias VulnerabilityRecord
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return fmt.Errorf("unmarshalling vulnerability record: %w", err)
	}
	if a.Ecosystem != fetchdomain.EcosystemGo {
		return fmt.Errorf("%w: got %q, want %q", fetchdomain.ErrUnsupportedEcosystem, a.Ecosystem, fetchdomain.EcosystemGo)
	}
	*r = VulnerabilityRecord(a)
	return nil
}

// ProjectScanResult is the outcome of a single project-rooted scan: one
// govulncheck run over the project's real import graph from its real entry
// points, at the versions MVS selected. Unlike a per-module isolated scan it
// keeps every finding and attributes it to the module that owns the vulnerable
// symbol, so a project walk derives one verdict per in-build module from a
// single analysis the project actually produces — no module is re-resolved
// alone, so a version-not-in-toolchain gap cannot arise.
type ProjectScanResult struct {
	// FindingsByModule maps each module that owns a reachable finding to those
	// findings. A module absent from the map was analysed and is clean; the
	// caller marks it StatusClean. Stdlib advisories key on the "stdlib"
	// pseudo-module coordinate (empty version); the caller attributes them to
	// the project root.
	FindingsByModule map[coordinate.ModuleCoordinate][]VulnerabilityFinding
	// Status is the scan-level outcome. StatusClean or StatusAffected when the
	// project built and was analysed; StatusUnscannable or StatusScanFailed when
	// the project itself could not be analysed (no go.mod, OOM, a real build
	// break) — a genuine fault the caller surfaces honestly rather than a
	// manufactured per-module gap.
	Status VulnerabilityStatus
	// UnscanReason / UnscannableReason / ErrorDetail carry the diagnostic for a
	// non-analysable outcome, mirroring VulnerabilityRecord's fields.
	UnscanReason      UnscanReason
	UnscannableReason string
	ErrorDetail       string
}

// StdlibModulePath is govulncheck's pseudo-module path for Go standard-library
// advisories. A project-rooted scan attributes such findings to the project
// root rather than to any dependency.
const StdlibModulePath = "stdlib"

// WalkScanStatus describes the outcome of a walk-wide vulnerability scan.
type WalkScanStatus string

const (
	WalkStatusAllClean WalkScanStatus = "AllClean"
	WalkStatusAffected WalkScanStatus = "Affected"
	WalkStatusPartial  WalkScanStatus = "Partial"
	WalkStatusFailed   WalkScanStatus = "ScanFailed"
)

// WalkScanRun records the aggregate results of scanning every module in a walk.
type WalkScanRun struct {
	ID               string                                 `json:"id"`
	WalkID           string                                 `json:"walk_id"`
	Snapshot         DatabaseSnapshot                       `json:"snapshot"`
	PerModuleResults map[coordinate.ModuleCoordinate]string `json:"per_module_results"` // Maps coordinate to VulnerabilityRecord ContentHash
	StartedAt        time.Time                              `json:"started_at"`
	CompletedAt      time.Time                              `json:"completed_at"`
	OverallStatus    WalkScanStatus                         `json:"overall_status"`
	PipelineVersion  string                                 `json:"pipeline_version"`
	Operator         string                                 `json:"operator"`
	ContentHash      string                                 `json:"content_hash"`
}
