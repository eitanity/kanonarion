package domain

import (
	"crypto/sha256"
	"encoding/hex"
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

// VulnerabilityStatus describes the outcome of a module's vulnerability scan as
// a single word.
//
// It collapses two independent axes — coverage and findings — so it can only
// ever carry one of them. It is retained as a stored compatibility summary for
// consumers that display only the summary word; no consumer may derive a
// findings fact from it, because Unscannable and ScanFailed are coverage answers
// occupying the same field, and reading them as "not affected" ranks "we could
// not look" as though it were "we looked and it was clean". Those are opposite
// claims: absence of evidence versus evidence of absence. Read
// RecordCoverageStatus / RecordFindingsStatus instead.
type VulnerabilityStatus string

const (
	StatusClean       VulnerabilityStatus = "Clean"
	StatusAffected    VulnerabilityStatus = "Affected"
	StatusUnscannable VulnerabilityStatus = "Unscannable"
	StatusScanFailed  VulnerabilityStatus = "ScanFailed"
)

// RecordCoverageStatus answers "was this module analysed?" — one of the two axes
// VulnerabilityStatus conflates, at the per-module level where WalkScanRun's
// CoverageStatus answers it for a whole run. It is independent of whether any
// vulnerability was found.
//
// The diagnostic detail for a non-analysed outcome is unchanged and still lives
// beside it on the record: UnscanReason (a machine-readable cause code) and
// UnscannableReason (human prose) for CoverageUnscannable, ErrorDetail for
// CoverageFailed.
type RecordCoverageStatus string

const (
	// CoverageAnalysed means the module was analysed and the findings axis is an
	// answer about it.
	CoverageAnalysed RecordCoverageStatus = "Analysed"
	// CoverageUnscannable means the module could not be analysed at all — see
	// UnscanReason for which of the taxonomy's causes applies.
	CoverageUnscannable RecordCoverageStatus = "Unscannable"
	// CoverageFailedScan means the analysis was attempted and the attempt failed
	// — see ErrorDetail. It is distinct from Unscannable: one is a module that
	// cannot be looked at, the other a look that went wrong.
	CoverageFailedScan RecordCoverageStatus = "Failed"
)

// RecordFindingsStatus answers "did the analysis report a vulnerability?" — the
// other axis, mirroring WalkScanRun's FindingsStatus.
//
// It is independent of coverage, and like the run-level axis it must be read
// alongside coverage to mean anything: FindingsClean on a record whose coverage
// is not Analysed says "no finding is being reported", not "there is nothing
// here". Only CoverageAnalysed + FindingsClean is an all-clear.
type RecordFindingsStatus string

const (
	FindingsRecordAffected RecordFindingsStatus = "Affected"
	FindingsRecordClean    RecordFindingsStatus = "Clean"
)

// DetermineRecordCoverageStatus projects a collapsed status onto the coverage
// axis. The mapping is total: every one of the four values says something about
// coverage, which is why the collapsed field could never be read as a findings
// answer on its own.
func DetermineRecordCoverageStatus(status VulnerabilityStatus) RecordCoverageStatus {
	switch status {
	case StatusUnscannable:
		return CoverageUnscannable
	case StatusScanFailed:
		return CoverageFailedScan
	case StatusClean, StatusAffected:
		return CoverageAnalysed
	default:
		// An unrecognised status is not evidence that the module was analysed.
		// Treating it as coverage-failed keeps an unknown verdict out of the
		// analysed population rather than letting it over-claim completeness —
		// the same rule the run-level tally applies to the same case.
		return CoverageFailedScan
	}
}

// DetermineRecordCoverage answers the coverage axis for a whole record, from the
// evidence the record carries rather than from the collapsed summary word alone.
//
// The summary cannot be trusted for this question, because a writer that has both
// a coverage gap and a matching advisory can only put one of them in the single
// word, and it puts the finding there: a metadata-only fallback for a module that
// does not build reports Affected, and the coverage gap survives only as
// UnscanReason / UnscannableReason. Projecting coverage off that word therefore
// answers "Analysed" for a module that was never analysed — the precise claim the
// axes exist to stop being made.
//
// So the diagnostics decide, and the word is consulted only when the record
// carries none:
//
//   - UnscanReason or UnscannableReason present — the writer named a reason the
//     module could not be analysed, so coverage is Unscannable whatever the
//     summary says.
//   - ErrorDetail alone — an analysis was attempted and failed, which is Failed
//     rather than Unscannable: a look that went wrong, not a module that cannot
//     be looked at.
//   - no diagnostic at all — the record is the output of an analysis that ran, so
//     the summary's projection is the answer.
//
// A stated CoverageStatus always wins over this; RecordAxes and the seal both
// call it only for a record that states none.
func DetermineRecordCoverage(r VulnerabilityRecord) RecordCoverageStatus {
	switch {
	case r.UnscanReason != "" || r.UnscannableReason != "":
		return CoverageUnscannable
	case r.ErrorDetail != "":
		return CoverageFailedScan
	default:
		return DetermineRecordCoverageStatus(r.OverallStatus)
	}
}

// DetermineRecordFindingsStatus projects a collapsed status onto the findings
// axis. Only Affected reports a finding; every other value reports none, which
// on a non-analysed record means "none is being reported", not "none exists" —
// the distinction the coverage axis carries.
func DetermineRecordFindingsStatus(status VulnerabilityStatus) RecordFindingsStatus {
	if status == StatusAffected {
		return FindingsRecordAffected
	}
	return FindingsRecordClean
}

// DetermineRecordOverallStatus collapses the two axes back into the stored
// compatibility summary, so a consumer that displays only a summary word keeps
// seeing exactly the values it always saw.
//
// Coverage outranks findings, the same precedence DetermineWalkScanStatus
// applies one level up: a record that could not be analysed reports that, not a
// findings word it has no standing to assert. The collapse is lossy in exactly
// one direction — a coverage failure that nonetheless matched an advisory
// summarises as Unscannable or ScanFailed while FindingsStatus keeps the
// Affected fact — which is the whole reason the axes are stored beside it.
func DetermineRecordOverallStatus(coverage RecordCoverageStatus, findings RecordFindingsStatus) VulnerabilityStatus {
	switch coverage {
	case CoverageUnscannable:
		return StatusUnscannable
	case CoverageFailedScan:
		return StatusScanFailed
	case CoverageAnalysed:
		if findings == FindingsRecordAffected {
			return StatusAffected
		}
		return StatusClean
	default:
		// An unrecognised coverage value is not a claim that the module was
		// analysed, so it must not summarise as one.
		return StatusScanFailed
	}
}

// RecordAxes returns the record's two verdict axes.
//
// It prefers the stored fields and falls back to deriving them when they are
// empty, which is the case for every record written before the split. The
// derivation is exactly what the write path applies, so a pre-split record is
// read on the same terms as a new one rather than presenting a consumer with an
// empty axis it has no rule for. Coverage is derived from the record's
// diagnostics (DetermineRecordCoverage), not from the summary word, so a
// pre-split metadata-only record is healed to the coverage gap it recorded
// rather than to the Analysed its summary implies.
//
// It is a function rather than a method so that no caller can reach the raw
// fields by accident through a method value on a partially-populated record.
func RecordAxes(r VulnerabilityRecord) (RecordCoverageStatus, RecordFindingsStatus) {
	coverage, findings := r.CoverageStatus, r.FindingsStatus
	if coverage == "" {
		coverage = DetermineRecordCoverage(r)
	}
	if findings == "" {
		findings = DetermineRecordFindingsStatus(r.OverallStatus)
	}
	return coverage, findings
}

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
	// UnscanReasonWorkspaceMode indicates the Go toolchain entered workspace mode
	// while scanning the module in isolation — a go.work was discovered in the
	// extracted module directory or inherited from the environment — and rejected
	// the scan environment. Workspace mode is dev-time configuration that does not
	// apply to an isolated single-module scan, so this names a misconfigured scan
	// environment rather than a module that fails to build.
	UnscanReasonWorkspaceMode UnscanReason = "workspace-mode"
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
	// UnscanReasonVersionNotInToolchainUnverified indicates an offline resolution
	// failed with the shape of version-not-in-toolchain, but the version the
	// toolchain could not resolve could not be recovered from the error — so the
	// out-of-toolchain cause is asserted by the error's shape alone, never checked
	// against the walk's known set. It is deliberately not marked
	// ExpectedOutOfToolchain: an unverified claim must not inherit the confident,
	// informational reading a recovered-and-confirmed one earns, because a genuine
	// scan-cache hole produces the same wording and would otherwise be filed as
	// expected and never investigated — the precise failure this discrimination
	// exists to prevent.
	UnscanReasonVersionNotInToolchainUnverified UnscanReason = "version-not-in-toolchain-unverified"
	// UnscanReasonPackageDeclarationsMissing indicates a package's declarations
	// are absent because every file that would declare them is excluded by build
	// constraints — most often a host Go toolchain outside the range the module
	// supports. Distinct from generated-assets-missing: nothing is missing from
	// the module zip, so there is no code-generation step to run.
	UnscanReasonPackageDeclarationsMissing UnscanReason = "package-declarations-missing"
	// UnscanReasonIncompleteScanCache indicates the isolated scan failed to
	// resolve a module version offline that the walk graph itself knows about —
	// a node, or a superseded requirement recorded on one of its edges. Unlike
	// version-not-in-toolchain, nothing about this is expected: kanonarion
	// undertook to supply that version to the hermetic cache and did not, so the
	// module is a coverage gap that a fix can close rather than an inherent
	// consequence of scanning modules in isolation.
	UnscanReasonIncompleteScanCache UnscanReason = "incomplete-scan-cache"
	// UnscanReasonBuildIncompatible is the catch-all for build failures that do
	// not match a more specific pattern.
	UnscanReasonBuildIncompatible UnscanReason = "build-incompatible"
	// UnscanReasonOOMKilled indicates govulncheck was killed by the OS (OOM or
	// SIGKILL / exit 137). The scan is retryable on a host with more memory.
	UnscanReasonOOMKilled UnscanReason = "oom-killed"
	// UnscanReasonNoGoMod indicates the fetched module zip does not contain a
	// go.mod file and none could be synthesised, so govulncheck cannot be run
	// over it as its own main module. It names a property of the published
	// artefact, not an operator-side input fault.
	UnscanReasonNoGoMod UnscanReason = "no-go-mod"
	// UnscanReasonProjectNoGoMod indicates the project directory supplied for a
	// project-rooted scan contains no go.mod, so there is no main module to root
	// the analysis at. It names an operator-side input fault — the wrong
	// directory, or one that is not a Go module — not a property of any
	// artefact, and is remediable by pointing the scan at a real module root.
	UnscanReasonProjectNoGoMod UnscanReason = "project-no-go-mod"
	// UnscanReasonProjectDirUnavailable indicates the project directory supplied
	// for a project-rooted scan could not be stat'ed at all — it does not exist,
	// or is not readable. It names an operator-side input fault, not a property
	// of any artefact, and says nothing about whether that directory is a Go
	// module: the scan never got far enough to look.
	UnscanReasonProjectDirUnavailable UnscanReason = "project-dir-unavailable"
	// UnscanReasonLocalReplace indicates the module is a local filesystem
	// replacement (a replace directive pointing at a working-tree path) rather
	// than a fetched, versioned module, so there is no fetched source to scan.
	UnscanReasonLocalReplace UnscanReason = "local-replace"
)

// AllUnscanReasons returns every defined UnscanReason, in a stable order.
//
// It exists so a consumer that must handle every reason — a display mapping, a
// roll-up bucket, a severity table — can be proved exhaustive by test rather
// than by inspection. A reason code is an open string type, so the compiler
// cannot enforce that; a reason absent from a display table would otherwise
// render as a bare status with no explanation, which is exactly the silence the
// codebase forbids. A test asserts this list matches the declared constants, so
// adding a reason without adding it here fails rather than degrading quietly.
func AllUnscanReasons() []UnscanReason {
	return []UnscanReason{
		UnscanReasonVersionNotInToolchain,
		UnscanReasonVersionNotInToolchainUnverified,
		UnscanReasonPackageDeclarationsMissing,
		UnscanReasonCHeadersMissing,
		UnscanReasonGeneratedAssets,
		UnscanReasonGoWorkMonorepo,
		UnscanReasonWorkspaceMode,
		UnscanReasonRelativeReplace,
		UnscanReasonWindowsOnly,
		UnscanReasonMissingGoSum,
		UnscanReasonIncompleteScanCache,
		UnscanReasonBuildIncompatible,
		UnscanReasonOOMKilled,
		UnscanReasonNoGoMod,
		UnscanReasonLocalReplace,
		UnscanReasonProjectNoGoMod,
		UnscanReasonProjectDirUnavailable,
	}
}

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
//
// Source and Version name the advisory database and its own generation;
// RetrievedAt records when kanonarion fetched it. Those three answer "how
// current was the data behind this verdict". ContentHash answers the question
// they cannot: whether the bytes a verdict was reached against are the bytes
// still held.
//
// The advisory database is the evidence every finding is derived from, and it
// was the one input to a verdict that was not content-addressed — a snapshot
// was identified by a version string alone, and the version string is metadata
// the blob itself asserts. Two stores both holding "2026-07-24T18:35:55Z" could
// not be shown to hold the same advisories.
type DatabaseSnapshot struct {
	Source      string    `json:"source"`
	Version     string    `json:"version"`
	RetrievedAt time.Time `json:"retrieved_at"`
	// ContentHash is HashSnapshotContent over the snapshot blob, in
	// "sha256:<hex>" form. Empty on snapshots recorded before the hash existed;
	// such a snapshot is unverifiable, never verified-and-clean.
	ContentHash string `json:"content_hash"`
}

// snapshotHashPrefix labels the digest algorithm inside DatabaseSnapshot's
// ContentHash. It is present here — unlike on a VulnerabilityRecord's own bare
// hex hash, whose recipe is frozen by the records already in every store —
// because no snapshot hash has ever been written, so the field is free to take
// the project's normal prefixed form.
const snapshotHashPrefix = "sha256:"

// HashSnapshotContent renders the content hash of a vulnerability database
// snapshot blob: SHA-256 over the bytes verbatim, prefixed with the algorithm.
//
// It hashes the stored bytes rather than any parsed view of them, so the check
// covers exactly what a later scan will feed to govulncheck.
func HashSnapshotContent(blob []byte) string {
	sum := sha256.Sum256(blob)
	return snapshotHashPrefix + hex.EncodeToString(sum[:])
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
	Ecosystem  string                      `json:"ecosystem"`
	Coordinate coordinate.ModuleCoordinate `json:"coordinate"`
	WalkID     string                      `json:"walk_id"`
	Findings   []VulnerabilityFinding      `json:"findings,omitzero"`
	// OverallStatus is a derived, stored compatibility summary. CoverageStatus
	// and FindingsStatus are the two independent axes it collapses; consumers
	// that need a findings fact read FindingsStatus, never OverallStatus. All
	// three are set together by the hasher's seal step, so no writer can produce
	// a record whose summary and axes disagree.
	OverallStatus VulnerabilityStatus `json:"overall_status"`
	// CoverageStatus and FindingsStatus are the two axes. Read them through
	// RecordAxes, which fills them in for records written before the split rather
	// than handing back an empty axis.
	CoverageStatus    RecordCoverageStatus `json:"coverage_status,omitempty"`
	FindingsStatus    RecordFindingsStatus `json:"findings_status,omitempty"`
	UnscanReason      UnscanReason         `json:"unscan_reason,omitempty"`
	UnscannableReason string               `json:"unscannable_reason,omitempty"`
	ErrorDetail       string               `json:"error_detail,omitempty"`
	DatabaseSnapshot  DatabaseSnapshot     `json:"database_snapshot"`
	ScannedAt         time.Time            `json:"scanned_at"`
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
	// ArtefactIdentity names the fetched artefact this record was derived from,
	// in the "zip:h1:..." / "gomod:h1:..." form fetchdomain.ArtefactIdentity
	// renders. It answers the question the coordinate cannot: which bytes were
	// scanned. A coordinate names a module version, and the fetch record for that
	// coordinate may since have been re-measured, so a link by coordinate is a
	// link by convention; this one is by fact, and is covered by ContentHash, so
	// the claim is as tamper-evident as the verdict itself.
	//
	// Empty on records written before the field existed, and on records that
	// analysed no fetched artefact — a metadata-only match by coordinate, a
	// local-replace node, a project-rooted verdict derived from the target's own
	// build. Both read as "not recorded", never as "scanned nothing". Read it
	// back through RecordArtefactIdentity, which draws that distinction; never
	// hand this field to ParseArtefactIdentity directly.
	ArtefactIdentity string `json:"artefact_identity,omitempty"`
	// SourceContentHash is the content hash of the fetch record that supplied
	// those bytes. ArtefactIdentity says which artefact; this says which
	// measurement of it, so a reader can fetch that record and check the claim
	// against it. Empty exactly when ArtefactIdentity is.
	SourceContentHash string `json:"source_content_hash,omitempty"`
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

// WalkScanStatus describes the outcome of a walk-wide vulnerability scan. It
// collapses two independent axes — coverage and findings — into one word, so it
// can only ever carry one of them (see CoverageStatus / FindingsStatus). It is
// retained as a stored compatibility summary for consumers that display only the
// summary word; no consumer may derive a findings fact from it, because a run
// that both found vulnerabilities and left part of the build list unanalysed
// reports Partial and hides the finding.
type WalkScanStatus string

const (
	WalkStatusAllClean WalkScanStatus = "AllClean"
	WalkStatusAffected WalkScanStatus = "Affected"
	WalkStatusPartial  WalkScanStatus = "Partial"
	WalkStatusFailed   WalkScanStatus = "ScanFailed"
)

// CoverageStatus answers "was every module in the build list analysed?" — one of
// the two axes WalkScanStatus conflates. It is independent of whether any
// vulnerability was found.
type CoverageStatus string

const (
	CoverageComplete CoverageStatus = "Complete"
	CoveragePartial  CoverageStatus = "Partial"
	CoverageFailed   CoverageStatus = "Failed"
)

// FindingsStatus answers "did the analysis find vulnerabilities?" — the other
// axis WalkScanStatus conflates. It is independent of coverage: a run can be
// Partial-and-Clean or Complete-and-Affected.
type FindingsStatus string

const (
	FindingsAffected FindingsStatus = "Affected"
	FindingsClean    FindingsStatus = "Clean"
)

// WalkScanCounts is the per-outcome module breakdown a walk scan produces. It is
// the evidence both the coverage and findings verdicts are derived from, stored
// on the run so every consumer can state a count without re-reading each
// module's record. Total = Analysed + Unscannable + Failed, and
// Analysed = clean + Affected.
type WalkScanCounts struct {
	Total       int `json:"total"`
	Analysed    int `json:"analysed"`
	Affected    int `json:"affected"`
	Unscannable int `json:"unscannable"`
	Failed      int `json:"failed"`
}

// WalkScanRun records the aggregate results of scanning every module in a walk.
type WalkScanRun struct {
	ID               string                                 `json:"id"`
	WalkID           string                                 `json:"walk_id"`
	Snapshot         DatabaseSnapshot                       `json:"snapshot"`
	PerModuleResults map[coordinate.ModuleCoordinate]string `json:"per_module_results"` // Maps coordinate to VulnerabilityRecord ContentHash
	StartedAt        time.Time                              `json:"started_at"`
	CompletedAt      time.Time                              `json:"completed_at"`
	// OverallStatus is a derived, stored compatibility summary. CoverageStatus
	// and FindingsStatus are the two independent axes it collapses; consumers
	// that need a findings fact read FindingsStatus, never OverallStatus.
	OverallStatus   WalkScanStatus `json:"overall_status"`
	CoverageStatus  CoverageStatus `json:"coverage_status"`
	FindingsStatus  FindingsStatus `json:"findings_status"`
	Counts          WalkScanCounts `json:"counts"`
	PipelineVersion string         `json:"pipeline_version"`
	Operator        string         `json:"operator"`
	ContentHash     string         `json:"content_hash"`
}
