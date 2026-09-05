package ports

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/audit"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// AuditSink appends an audit event to the assurance log. The shared JSONL
// AuditLog satisfies this; the application depends only on this narrow port,
// not on the factstore adapter that persists it.
type AuditSink interface {
	RecordEvent(audit.Event) error
}

// WalkPresence reports whether the walks a stored scan run names are still held
// by the store. The walk store satisfies it; this context depends only on the
// narrow question, never on the walk adapter.
//
// A scan run is evidence about a dependency set it does not itself contain: the
// run says what was found, the walk says what was scanned, at which versions,
// from which root. Nothing in the schema ties the two, so a run can outlive its
// walk, and a reader that cannot tell reports the stale reference as though it
// resolved. Every id asked about is a key of the result.
type WalkPresence interface {
	PresentWalks(ctx context.Context, walkIDs []string) (map[string]bool, error)
}

// ErrCallGraphNotFound is returned by CallGraphLoader when no record exists for the
// requested coordinate. Callers can use errors.Is to distinguish absence from
// integrity failures.
var ErrCallGraphNotFound = errors.New("call graph record not found")

// ErrVulnIntegrity is returned by the vulnerability store's read paths when a
// stored record's content hash does not describe its contents, and by the write
// path when asked to persist a record whose hash does not describe what it is
// about to store.
//
// A read reports it instead of absence deliberately: a detected tamper reported
// as "nothing here" becomes a silent re-scan that overwrites the evidence of the
// tamper. It lives here rather than in the adapter so a caller can match the
// failure without importing the store.
var ErrVulnIntegrity = errors.New("vulnerability record integrity check failed")

// ErrSnapshotIntegrity is returned by the vulnerability store when the advisory
// database snapshot itself fails its integrity check: on write when the
// caller-declared hash contradicts the bytes handed over, and on read when the
// stored blob no longer matches its stored hash or is not the snapshot the caller
// asked for.
//
// It is separate from ErrVulnIntegrity because the two failures have
// incomparable blast radius. A corrupt record invalidates one module's verdict; a
// corrupt snapshot invalidates every verdict derived from it, and the records in
// a working store reference a handful of snapshots between them. A caller that
// would fail the module on one and abort the run and re-fetch the database on the
// other could not tell them apart while both answered to one sentinel.
//
// It deliberately does not wrap ErrVulnIntegrity. Wrapping would make
// errors.Is(err, ErrVulnIntegrity) true for a snapshot failure — the exact
// conflation this removes — and would keep every existing broad match working
// while making the narrow one impossible to write.
//
// A snapshot that is absent is not an integrity failure and matches neither
// sentinel; nor is a snapshot stored before hashing existed, which reads back as
// unverifiable rather than as corrupt.
var ErrSnapshotIntegrity = errors.New("vulnerability database snapshot integrity check failed")

// SnapshotIntegrityAbort wraps a snapshot integrity failure into the error that
// ends the run, and lives beside the sentinel so both scan paths abort with the
// same sentence rather than each inventing one.
//
// The failure is not survivable by design. The snapshot is the evidence every
// finding in the run rests on, and the run's records name it, so continuing
// against a live database would answer from a different advisory set than the
// records claim — findings indistinguishable from ones actually derived from the
// snapshot they cite. Falling back is worse than the failure it papers over.
//
// This run leaves the corrupt blob alone: it is the evidence of the tamper, and
// re-fetching over it silently would destroy the one artefact an investigation
// needs. The message says so, and says the opposite thing too — that the remedy
// it recommends DOES overwrite it. Measured, not assumed: PutDatabaseSnapshot
// upserts on (source, version), so a --fresh re-fetch of the same dated snapshot
// version replaces the altered bytes in place and leaves nothing to examine. An
// operator who wants the evidence must copy the store first, and would otherwise
// learn that only after destroying it.
func SnapshotIntegrityAbort(snapshot domain.DatabaseSnapshot, err error) error {
	return fmt.Errorf(
		"%w: the advisory database snapshot %s@%s does not match the bytes it is recorded as, "+
			"so no finding derived from it can be vouched for and the run must not claim it; "+
			"this run left the stored blob untouched as evidence — copy the store before re-fetching, "+
			"because re-fetching (--fresh) overwrites this snapshot in place",
		err, snapshot.Source(), snapshot.Version())
}

// ErrSnapshotEmpty is returned when the advisory database a scan was about to be
// measured against was found to hold no advisories.
//
// It is separate from ErrSnapshotIntegrity because the two describe different
// failures of the same object. An integrity failure says the bytes are not the
// bytes that were recorded — something changed them. An empty database says the
// bytes are exactly what was recorded and there is nothing in them: nobody
// tampered, the evidence simply never arrived. A caller that would preserve the
// blob as evidence of a tamper on one, and re-fetch on the other, must be able to
// tell them apart.
//
// It is a precondition failure, not a per-module outcome. The operator asked for
// a measurement against a database that cannot produce one, and recording every
// module Unscannable would be technically honest and practically useless — it
// buries the single fact that matters under one row per module.
var ErrSnapshotEmpty = errors.New("vulnerability database snapshot holds no advisories")

// EmptySnapshotAbort wraps an empty-database finding into the error that ends the
// scan, naming the snapshot and the count that was measured.
//
// It lives beside the sentinel so every extraction site refuses in the same
// sentence, on the terms SnapshotIntegrityAbort already set. The count is in the
// message because it is the whole content of the finding: "no advisories" is what
// distinguishes this from a database that was merely small, and an operator who
// sees the number can tell an empty air-gapped mirror from a scan that worked.
//
// Nothing is written and nothing is left behind to preserve. Unlike a corrupt
// snapshot, an empty one is not evidence of anything having happened to it, so
// the remedy is simply to fetch a database that holds advisories.
func EmptySnapshotAbort(snapshot domain.DatabaseSnapshot, count int) error {
	return fmt.Errorf(
		"%w: the advisory database snapshot %s@%s holds %d advisories, so a scan against it can only report "+
			"that nothing was found because nothing was consulted; no status may be sealed against it — "+
			"fetch a populated database (--fresh) and re-run",
		ErrSnapshotEmpty, snapshot.Source(), snapshot.Version(), count)
}

// ErrSnapshotUnavailable is returned when the advisory database snapshot a scan
// was pinned to could not be put in front of the analyser: the store would not
// produce it, or it could not be unpacked where the analyser can read it.
//
// It is separate from the integrity and empty sentinels because it describes the
// snapshot's availability rather than its contents. The bytes may be perfectly
// good and simply out of reach — a full disk, a store that has lost the blob, a
// permissions failure on the scratch directory.
//
// It is a refusal rather than a fallback, and that is the whole point of naming
// it. The three paths that raise it used to log a warning and hand the analyser
// the live database instead, while the record went on naming the snapshot: an
// entirely live scan sealed under a pinned generation, announced only in a log
// line nothing downstream reads. A record states the database it was judged
// against, so a scan that cannot read that database has no verdict to state.
var ErrSnapshotUnavailable = errors.New("vulnerability database snapshot could not be made available to the analyser")

// UnavailableSnapshotAbort wraps a snapshot-availability failure into the error
// that ends the scan, naming the snapshot and what went wrong reaching it.
//
// It lives beside the sentinel on the terms SnapshotIntegrityAbort set, so every
// seam that cannot deliver the pinned database refuses in the same sentence
// rather than each inventing one — or, as three of them did, inventing none.
func UnavailableSnapshotAbort(snapshot domain.DatabaseSnapshot, stage string, err error) error {
	return fmt.Errorf(
		"%w: %s for the advisory database snapshot %s@%s: %v; the record this scan would write names that "+
			"snapshot, and answering from the live database instead would seal a status against an advisory "+
			"set the record does not state — fix the store or re-fetch the database (--fresh) and re-run",
		ErrSnapshotUnavailable, stage, snapshot.Source(), snapshot.Version(), err)
}

// UnreadableRun names one stored scan run a listing could not verify, together
// with the failure the read path reported.
type UnreadableRun struct {
	// ID is the run identifier carried by the stored bytes, or empty when they
	// could not be parsed far enough to name it. An unnamed row is still
	// reported: "there is a row here I cannot read" is an answer, and dropping
	// it because it will not introduce itself is not.
	ID string

	// Reason is the read failure exactly as it was reported, so a caller that
	// wants to tell generation drift from altered bytes can still match on it.
	Reason error
}

// String renders one unreadable run for a message, naming the run when the
// bytes named themselves.
func (r UnreadableRun) String() string {
	if r.ID == "" {
		return fmt.Sprintf("unidentified run: %v", r.Reason)
	}
	return fmt.Sprintf("run %s: %v", r.ID, r.Reason)
}

// UnreadableRuns reports that a scan-run listing returned every row it could
// verify and names the ones it could not. The verified runs come back as the
// listing's ordinary result alongside it.
//
// It exists so one seam can serve both kinds of caller. It unwraps to
// ErrVulnIntegrity, so a consuming command — one whose answer would be wrong if
// it silently rested on a partial store — matches it exactly as it always did
// and still fails closed. A survey command matches this type instead, prints
// the rows it has and the rows it does not, and exits 0: the tool used to
// diagnose the problem is not the one that refuses to run.
//
// The verified runs are returned WITH the error rather than discarded because
// the alternative failure is worse than aborting. A listing that quietly
// omitted the rows it could not read would answer a question about the store
// with a clean list that is not true of it, and the reader would have no way to
// know.
type UnreadableRuns struct {
	Runs []UnreadableRun
}

// Error renders every unreadable run, so a consuming command that only prints
// the error still says which rows were at fault.
func (e *UnreadableRuns) Error() string {
	parts := make([]string, 0, len(e.Runs))
	for _, r := range e.Runs {
		parts = append(parts, r.String())
	}
	return fmt.Sprintf("%s: %s", ErrVulnIntegrity, strings.Join(parts, "; "))
}

// Unwrap keeps errors.Is(err, ErrVulnIntegrity) true, so every caller that
// classified this failure before this type existed classifies it the same way
// now.
func (e *UnreadableRuns) Unwrap() error { return ErrVulnIntegrity }

// VulnerabilityStore defines the port for persisting vulnerability records.
//
// The zero coordinate is the one value the signatures cannot exclude: Go
// always permits coordinate.ModuleCoordinate{}, and it names no module.
// Implementations MUST refuse it with coordinate.ErrZeroCoordinate — on a
// write because it would key a row on the empty path at the empty version,
// which every later read treats as a genuine measurement, and on a read
// because absence is the wrong answer to a question about no module.
// coordinatetest.AssertRefusesZeroCoordinate pins the rule for every store.
//
// The zero snapshot is the same hazard on the other identity axis, and every
// method that takes a domain.DatabaseSnapshot MUST refuse it with
// domain.ErrZeroSnapshot, on both legs. vulnerability_records is an append-only
// ledger whose composition group is keyed on (coordinate, pipeline version,
// snapshot), so a record admitted under the zero snapshot joins the group
// holding every other record that also named none, and a read composes them as
// though they described one measurement against one advisory database. An empty
// ContentHash does NOT make a snapshot zero: rows written before the hash
// existed legitimately carry none, and refusing those would make every
// un-migrated store unreadable. vulntest.AssertRefusesZeroSnapshot pins the rule
// for every store.
type VulnerabilityStore interface {
	// PutVulnerabilityRecord appends a scan to the ledger. It never updates a
	// record: two distinct scans of one coordinate — under two snapshots, in two
	// analysis frames, or simply repeated — are always two records, and only a
	// byte-identical re-write is idempotent.
	PutVulnerabilityRecord(ctx context.Context, record domain.VulnerabilityRecord) error

	// GetVulnerabilityRecord returns the composed record for a coordinate,
	// pipeline version and snapshot, across every analysis frame the ledger holds.
	// It is the read for a caller that has declined to name a frame; see
	// domain.Compose for the ladder it serves on.
	GetVulnerabilityRecord(
		ctx context.Context,
		coord coordinate.ModuleCoordinate,
		pipelineVersion string,
		snapshot domain.DatabaseSnapshot,
	) (domain.VulnerabilityRecord, bool, error)

	// GetVulnerabilityRecordAt returns the composed record within one analysis
	// frame, and (zero, false, nil) when the ledger holds none reached in it.
	//
	// A caller that has a frame — a scan deciding whether an earlier record may
	// be reused, a run reading back what it wrote — MUST use this rather than
	// GetVulnerabilityRecord. An isolated scan and a target-rooted scan answer
	// different questions, so serving one for the other attributes a reachability
	// finding to a build it was never computed against.
	GetVulnerabilityRecordAt(
		ctx context.Context,
		coord coordinate.ModuleCoordinate,
		pipelineVersion string,
		snapshot domain.DatabaseSnapshot,
		rooting domain.Rooting,
	) (domain.VulnerabilityRecord, bool, error)

	// HasVulnerabilityRecord reports whether the ledger holds the exact
	// generation named by contentHash. It answers "was this measurement kept",
	// which composition cannot: the record a read serves is not necessarily the
	// one a given run wrote, because an earlier generation may outrank it.
	HasVulnerabilityRecord(
		ctx context.Context,
		coord coordinate.ModuleCoordinate,
		pipelineVersion string,
		snapshot domain.DatabaseSnapshot,
		contentHash string,
	) (bool, error)

	// GetLatestVulnerabilityRecord returns the composed record for a coordinate
	// and pipeline version across every snapshot and frame the ledger holds.
	// Returns (zero, false, nil) if no record exists.
	GetLatestVulnerabilityRecord(
		ctx context.Context,
		coord coordinate.ModuleCoordinate,
		pipelineVersion string,
	) (domain.VulnerabilityRecord, bool, error)

	// ListVulnerabilityRecordsForModuleInWalk returns every generation of a
	// coordinate the given walk's scan runs covered, regardless of snapshot,
	// ordered oldest first. An empty slice means that walk covered the module
	// with no readable record.
	//
	// It returns CANDIDATES, never an answer. The store cannot rank them,
	// because ranking them requires an analysis frame and the store has none:
	// the membership index keys on (coordinate, pipeline version, snapshot), so
	// every frame a coordinate was ever measured in at that generation joins to
	// the same walk — an isolated scan of the module and another project's
	// target-rooted scan alongside the walk's own. Composing here served
	// whichever won the frame-blind ladder, which is how a walk-pinned read came
	// to answer from a different walk entirely. The caller knows which frame it
	// asked about and selects on it.
	ListVulnerabilityRecordsForModuleInWalk(
		ctx context.Context,
		coord coordinate.ModuleCoordinate,
		pipelineVersion string,
		walkID string,
	) ([]domain.VulnerabilityRecord, error)

	// PutWalkScanRun persists the aggregate result of a walk scan.
	PutWalkScanRun(ctx context.Context, run domain.WalkScanRun) error

	// GetWalkScanRun retrieves a walk scan run by its ID.
	GetWalkScanRun(ctx context.Context, id string) (domain.WalkScanRun, bool, error)

	// ListWalkScanRuns lists all scan runs for a specific walk.
	//
	// A row that fails its seal does not end the listing. Implementations return
	// every run they could verify AND an *UnreadableRuns naming the rest, so the
	// caller decides: a consumer sees a non-nil error and fails closed as before,
	// a survey reports the named rows and carries on. One unreadable row must
	// never make the store unlistable, because the listing is how an operator
	// finds it.
	ListWalkScanRuns(ctx context.Context, walkID string) ([]domain.WalkScanRun, error)

	// ListAllWalkScanRuns lists all scan runs across all walks, most recent first,
	// on the same partial-result terms as ListWalkScanRuns.
	ListAllWalkScanRuns(ctx context.Context) ([]domain.WalkScanRun, error)

	// PutDatabaseSnapshot persists a vulnerability database snapshot blob.
	PutDatabaseSnapshot(ctx context.Context, snapshot domain.DatabaseSnapshot, content io.Reader) error

	// GetDatabaseSnapshot retrieves the blob content for a pinned snapshot.
	GetDatabaseSnapshot(ctx context.Context, snapshot domain.DatabaseSnapshot) (io.ReadCloser, error)

	// GetLatestDatabaseSnapshot returns the most recently stored snapshot metadata.
	// Returns (zero, false, nil) if no snapshot has been stored yet.
	GetLatestDatabaseSnapshot(ctx context.Context) (domain.DatabaseSnapshot, bool, error)

	// ListDatabaseSnapshots returns all stored snapshot metadata, most recent first.
	ListDatabaseSnapshots(ctx context.Context) ([]domain.DatabaseSnapshot, error)

	// ListVulnerabilityRecordsByFindingID returns the vulnerability records that
	// contain a finding with the given OSV/CVE/GHSA identifier.
	//
	// An empty walkID answers across the whole store — every module version,
	// pipeline version and snapshot generation it holds, including versions no
	// current build contains. A non-empty walkID restricts the answer to the
	// modules a scan run of that walk covered, and an unknown walkID is an
	// error rather than an empty result.
	ListVulnerabilityRecordsByFindingID(ctx context.Context, findingID, walkID string) ([]domain.VulnerabilityRecord, error)

	// ListVulnerabilityRecords returns all vulnerability records for a walk scan run.
	ListVulnerabilityRecords(ctx context.Context, walkScanRunID string) ([]domain.VulnerabilityRecord, error)

	// ListVulnerabilityRecordsForModule returns every generation the ledger holds
	// for a coordinate AT ONE PIPELINE VERSION, across all walks, snapshots and
	// analysis frames, ordered by scanned_at descending (most recent first).
	// Within that generation the superseded snapshots and frames are still here,
	// each stating the evidence it rested on. It is not the history read: a
	// history spanning generations comes from
	// ListVulnerabilityRecordsForModuleAllGenerations.
	//
	// The pipeline version is part of the key, so this read cannot see the
	// generations a bump left behind, and an empty answer from it means "nothing
	// at this generation" — never "nothing at all". A caller turning that empty
	// answer into a statement about the store asks
	// ListVulnerabilityRecordGenerationsForModule which generations exist.
	ListVulnerabilityRecordsForModule(
		ctx context.Context,
		coord coordinate.ModuleCoordinate,
		pipelineVersion string,
	) ([]domain.VulnerabilityRecord, error)

	// ListVulnerabilityRecordsForModuleAllGenerations returns every record the
	// ledger holds for a coordinate, at every pipeline version, across all walks,
	// snapshots and analysis frames, ordered by scanned_at descending.
	//
	// It takes no pipeline version, for the reason
	// ListVulnerabilityRecordsByFindingID takes no walk: spanning generations is
	// the question, not a relaxation of it. This is the read behind a history
	// listing, where the whole point is what the ledger has ever held — including
	// the generations a bump left behind, which the keyed read cannot see and
	// which the census can only count.
	//
	// Nothing point-in-time may be served from it. A record from a superseded
	// generation is not what a current scan would answer, so a caller that
	// renders these rows states which generation each came from.
	ListVulnerabilityRecordsForModuleAllGenerations(
		ctx context.Context,
		coord coordinate.ModuleCoordinate,
	) ([]domain.VulnerabilityRecord, error)

	// ListVulnerabilityRecordGenerationsForModule reports which pipeline
	// versions the ledger holds records for a coordinate at, and how much it
	// holds at each. It takes no pipeline version: answering "what does the
	// store hold for this module" is the one question the keyed reads above
	// cannot ask, and it is the question every empty answer needs before it can
	// name its own cause.
	//
	// It returns a census, never an answer. Counts come from the index columns,
	// so a generation this build cannot decode is still counted — which is what
	// a diagnostic needs, and is exactly why nothing may be served from it.
	// Ordered by pipeline version.
	ListVulnerabilityRecordGenerationsForModule(
		ctx context.Context,
		coord coordinate.ModuleCoordinate,
	) ([]VulnerabilityRecordGeneration, error)
}

// VulnerabilityRecordGeneration is one pipeline version the ledger holds
// records for a coordinate at, with what it holds there.
//
// Findings is the number of finding rows across those records, not a count of
// distinct advisories: one advisory measured in four scans is four rows. It
// sizes what a generation holds; it does not claim how many things are wrong.
type VulnerabilityRecordGeneration struct {
	PipelineVersion string
	Records         int
	Findings        int
	// Walks names the walks whose scans wrote these records, the walk that
	// wrote the newest of them first. A refusal that must name a re-scan needs
	// it: vuln-scan takes a walk id, and its --module form resolves only a walk
	// ROOTED at the coordinate, which a module measured in a consumer's build
	// has none of.
	Walks []string
	// LastScannedAt is the newest scanned_at among these records, and it is what
	// ranks one generation against another: pipeline version strings do not
	// order, and this census is returned in their order for display. Zero when
	// the stored instant cannot be read, which ranks it last rather than
	// failing a diagnostic.
	LastScannedAt time.Time
}

// ScanRequest carries the inputs for one isolated per-module scan.
type ScanRequest struct {
	Coordinate   coordinate.ModuleCoordinate
	ModuleSource io.Reader
	Snapshot     domain.DatabaseSnapshot
	// GoModCache is a pre-populated GOMODCACHE dir; empty lets govulncheck
	// download as needed.
	GoModCache string
	// DBDir is a pre-extracted vuln DB dir; empty extracts from the store on
	// each call.
	DBDir string
	// ScanMode selects source or binary analysis; empty defaults to source.
	ScanMode domain.ScanMode
	// BuildList is the set of module versions the walk resolved and supplies as
	// source. A module zip published before Go modules carries no go.mod, so one
	// is synthesised in the scan's scratch directory and these become its
	// require directives — letting the isolated scan resolve the versions the
	// project actually built instead of whatever a network tidy would pick.
	// Empty means the module is scanned against its own zip alone, which is
	// sufficient whenever it imports nothing outside the standard library.
	BuildList map[coordinate.ModuleCoordinate]struct{}
}

// TargetScanRequest carries the inputs for one target-rooted scan of a walk
// whose root is a published module rather than a local project. The target's
// own zip is the main module of the analysis, and every dependency is reached
// through the target's import graph rather than scanned in isolation.
type TargetScanRequest struct {
	// Coordinate is the walk target: the module the analysis is rooted at.
	Coordinate   coordinate.ModuleCoordinate
	ModuleSource io.Reader
	Snapshot     domain.DatabaseSnapshot
	// GoModCache is the walk's pre-populated GOMODCACHE, holding the versions the
	// target's build selects, so the scan resolves them offline rather than
	// re-resolving against the network.
	GoModCache string
	// DBDir is a pre-extracted vuln DB dir; empty extracts from the store.
	DBDir string
	// BuildList is the set of module versions the walk resolved, used only to
	// synthesise a go.mod when the target's own zip predates Go modules.
	BuildList map[coordinate.ModuleCoordinate]struct{}
}

// ProjectScanRequest carries the inputs for one project-rooted scan of a local
// working tree.
type ProjectScanRequest struct {
	// ProjectDir is the project's working-tree directory (the one holding go.mod).
	ProjectDir string
	Snapshot   domain.DatabaseSnapshot
	// DBDir is a pre-extracted vuln DB dir; empty extracts from the store.
	DBDir string
	// Vendored asks for the analysis to be rooted at the project's vendor/ tree
	// under -mod=vendor, so the bytes measured are the bytes the project
	// compiles. The scanner reports back which surface it could actually use.
	//
	// False is not merely "no preference": for a project that carries
	// vendor/modules.txt the Go toolchain defaults to -mod=vendor on its own, so
	// the fetch path has to be forced explicitly. That is what makes a
	// deliberate fetched-surface comparison run a real comparison rather than a
	// re-run of the vendored one.
	Vendored bool
}

// VendoredClosure is what a project's vendored tree says about its own closure:
// which modules vendor/modules.txt lists, and which of them the tree actually
// holds files for.
type VendoredClosure struct {
	// Vendored is false when the project has no vendor/modules.txt at all, in
	// which case the other fields are empty and mean nothing.
	Vendored bool
	// Listed maps module path → version for every entry in vendor/modules.txt.
	Listed map[string]string
	// Present is the set of module paths the tree holds files for. It is a
	// subset of Listed's keys plus any unlisted module directory found under
	// vendor/; a listed module missing from it is listed-but-absent.
	Present map[string]bool
	// ReplacedBy maps a replacement module path to the original module path it
	// stands in for.
	//
	// A replaced module is vendored under its ORIGINAL path — `go mod vendor`
	// records the replacement only on the modules.txt comment line — while a
	// resolved build list keys on the REPLACEMENT coordinate. The two names
	// never meet in Listed or Present, so a coordinate must be resolved through
	// this mapping before its absence from either means anything.
	//
	// Listed and Present are deliberately left as a faithful reading of
	// modules.txt rather than having the replacement names folded into them: a
	// consumer asking what the tree says gets what the tree says, and the
	// aliasing is applied where the question about a coordinate is actually
	// asked.
	ReplacedBy map[string]string
}

// VendoredClosureReader reads a project's vendored closure from its working
// tree. It is how the vuln stage learns which modules a -mod=vendor analysis
// could have measured, without re-implementing modules.txt parsing: the vendor
// bounded context already owns that parser and this port is satisfied by an
// adapter over it.
type VendoredClosureReader interface {
	// VendoredClosure reads the project rooted at goModPath. A project with no
	// vendor/modules.txt yields a zero VendoredClosure and a nil error — not
	// being vendored is an answer, not a failure.
	VendoredClosure(ctx context.Context, goModPath string) (VendoredClosure, error)
}

// VulnerabilityScanner defines the port for a vulnerability scanner implementation.
type VulnerabilityScanner interface {
	// Preflight verifies the scanner's external prerequisites are available
	// (e.g. the govulncheck binary on PATH) so callers can fail fast with an
	// actionable error before any expensive scan setup. It returns nil when
	// the scanner is ready to run.
	Preflight(ctx context.Context) error
	Scan(ctx context.Context, req ScanRequest) (domain.VulnerabilityRecord, error)
	// ScanProject runs one project-rooted scan over the project's live working
	// tree (the local main module a project walk is rooted at) and returns every
	// reachable finding grouped by the module that owns the vulnerable symbol.
	// It is how a project walk derives a per-module verdict for the whole build
	// from a single analysis the project actually produces, instead of scanning
	// each dependency in isolation. The working tree resolves its own build, so
	// the scan is live and uncached. A genuine fault is carried in the result's
	// Status; the error return is reserved for infrastructure failures.
	ScanProject(ctx context.Context, req ProjectScanRequest) (domain.ProjectScanResult, error)
	// ScanTargetModule runs one target-rooted scan for a walk whose root is a
	// published module, returning every finding grouped by the module that owns
	// the vulnerable symbol. It is the coordinate-keyed counterpart of
	// ScanProject: the target's zip stands in for the project working tree, so
	// each dependency contributes the packages the target's build imports instead
	// of every package it contains. A genuine fault is carried in the result's
	// Status so the caller can fall back to isolated per-module scanning; the
	// error return is reserved for infrastructure failures.
	ScanTargetModule(ctx context.Context, req TargetScanRequest) (domain.ProjectScanResult, error)
	ScannerMetadata() ScannerMetadata
}

// ScannerMetadata provides identity and version information for a scanner.
type ScannerMetadata struct {
	Name    string
	Version string
}

// VulnerabilityDatabase defines the port for managing vulnerability database snapshots.
// AdvisoryIndexEntry is one advisory as the database's module index lists it.
//
// All three fields are compared when two generations are diffed for a module,
// and each carries a different change: a new ID is a new advisory, a changed
// Fixed is a changed remediation, and a changed Modified is any other edit the
// upstream made to the advisory — a withdrawal among them. Comparing only IDs
// would report a withdrawn or re-scoped advisory as no change at all.
type AdvisoryIndexEntry struct {
	// ID is the advisory identifier, e.g. GO-2026-5579.
	ID string
	// Modified is the advisory's own last-modified stamp as the index states it.
	Modified string
	// Fixed is the version that fixes the advisory; empty when unfixed.
	Fixed string
}

// AdvisoryIndex maps a module path to the advisories the database lists for it.
// A module absent from the map has no advisories, which is the same statement as
// an empty slice and is compared as one.
type AdvisoryIndex map[string][]AdvisoryIndexEntry

type VulnerabilityDatabase interface {
	// Snapshot returns a pinned snapshot of the database at this point.
	// Subsequent calls may return different snapshots; the snapshot
	// itself is immutable.
	Snapshot(ctx context.Context) (domain.DatabaseSnapshot, io.ReadCloser, error)

	// LatestVersion returns the generation the database currently publishes,
	// without downloading its body. It is the cheap half of Snapshot: the same
	// string Snapshot would report as the snapshot's Version, read from the
	// database's own index, so a caller can tell whether a download would bring
	// anything new before paying for one.
	LatestVersion(ctx context.Context) (string, error)

	// PublishedAdvisoryIndex returns the module index the database currently
	// publishes, without downloading its body. It is what makes "the generation
	// advanced" a question that can be asked about a particular set of modules
	// rather than about the database as a whole.
	PublishedAdvisoryIndex(ctx context.Context) (AdvisoryIndex, error)

	// SnapshotAdvisoryIndex returns the same index as carried by an
	// already-stored snapshot, read from the store rather than the network.
	SnapshotAdvisoryIndex(ctx context.Context, identity domain.DatabaseSnapshot) (AdvisoryIndex, error)

	// SnapshotToolchainAdvisories returns what an already-stored snapshot says
	// under its toolchain key — the advisories against the go command, compiler
	// and linker, which are keyed separately from stdlib and which no scanned
	// project imports. Both the index and each advisory record are read out of
	// the stored snapshot itself, so the read costs no network.
	//
	// A snapshot whose index carries no toolchain key returns a set with
	// KeyPresent false and no error: that snapshot cannot judge a toolchain, and
	// saying so is the answer rather than a failure.
	SnapshotToolchainAdvisories(ctx context.Context, identity domain.DatabaseSnapshot) (domain.ToolchainAdvisorySet, error)

	// GetSnapshot retrieves a previously-pinned snapshot by identity,
	// for replay or re-scanning.
	GetSnapshot(ctx context.Context, identity domain.DatabaseSnapshot) (io.ReadCloser, error)

	// CheckVulnerable checks if the given modules at specific versions have any
	// known vulnerabilities in the snapshot named by identity. This is a
	// lightweight metadata check, and like LookupFindings it reads the stored
	// snapshot rather than the live database.
	CheckVulnerable(ctx context.Context, modules []coordinate.ModuleCoordinate, identity domain.DatabaseSnapshot) (map[coordinate.ModuleCoordinate][]string, error)

	// LookupFindings returns enriched advisory metadata for every known
	// vulnerability affecting coord, sourced from the per-advisory OSV records:
	// summary, affected range, fixed version, affected symbols, and timestamps.
	// It is the metadata-path equivalent of source-mode findings — used when a
	// module cannot be scanned from source so each finding still answers "will a
	// version bump fix it?" and "which symbol is at risk?" without the user
	// leaving the tool to query the advisory database directly.
	//
	// IT READS THE SNAPSHOT NAMED BY IDENTITY, AND ONLY THAT. The snapshot is a
	// parameter rather than an implicit "whatever the database serves now"
	// because this route runs beside the source analysis and both go into one
	// record. When it read the live database instead, a record could report an
	// advisory published after the pinned generation — an advisory the analyser
	// was never given — and the caller then attributed the analysis's silence
	// about it as a reachability answer. A record states one advisory database,
	// so both routes must read that one.
	//
	// The identity must name a snapshot the store holds; there is no fallback to
	// the network, because a fallback is exactly how the two routes came to read
	// different databases.
	LookupFindings(ctx context.Context, coord coordinate.ModuleCoordinate, identity domain.DatabaseSnapshot) ([]domain.VulnerabilityFinding, error)
}

// ModuleFetcher is a narrow port used by ScanWalkUseCase to pre-fetch modules
// that are missing from the fact store before populating the GOMODCACHE.
type ModuleFetcher interface {
	// FetchModule acquires the full module artefact (zip + go.mod), the source a
	// scan analyses.
	FetchModule(ctx context.Context, coord coordinate.ModuleCoordinate) error
	// FetchModuleGoMod acquires only the module's go.mod, persisting a go.mod-only
	// record (see fetch domain FactRecord.IsGoModOnly). It is used to populate the
	// go.mod closure a pre-pruning module reads while rebuilding its module graph:
	// those versions are never compiled, so downloading their zips is discarded
	// work.
	FetchModuleGoMod(ctx context.Context, coord coordinate.ModuleCoordinate) error
}

// HostMemory reports how much memory the host can hand to new work right now.
// It exists so the module-scan worker pool can size itself against a real
// budget instead of against the CPU count alone: each govulncheck source-mode
// scan of a cloud-SDK-heavy module holds multiple GB, so a pool sized purely by
// cores can exhaust the host and be OOM-killed, which reports every module as
// unanalysed rather than as scanned.
//
// It is a port rather than a direct /proc read so the cap is injectable in
// tests, and so a host that cannot answer degrades to the CPU-only cap instead
// of failing the scan.
type HostMemory interface {
	// AvailableBytes returns the memory available for new allocations without
	// swapping. An error means the reading could not be taken — never that the
	// host has no memory — and callers MUST treat it as "unknown" and fall back
	// to their CPU-derived cap rather than refusing to run.
	AvailableBytes() (uint64, error)
}

// ReachabilityAnalyser defines the port for call-graph-based reachability analysis.
type ReachabilityAnalyser interface {
	Analyse(
		ctx context.Context,
		targetCoord coordinate.ModuleCoordinate,
		targetSymbols []SymbolReference,
		callGraphLoader CallGraphLoader,
	) (domain.ReachabilityResult, error)
}

// SymbolReference uniquely identifies a symbol in the fact base.
type SymbolReference struct {
	Module  string
	Package string
	Symbol  string
}

// CallGraphLoader loads a vuln-local projection of a module's call graph.
// It returns CallGraphProjection rather than callgraph/domain.CallGraphRecord
// so a callgraph schema change does not ripple into this port; the mapping
// lives in the reachability adapter.
type CallGraphLoader interface {
	Load(ctx context.Context, coord coordinate.ModuleCoordinate) (CallGraphProjection, error)
}

// CallGraphProjection is the minimal view of a call graph the reachability
// analyser consumes: the nodes and the directed call edges between them, plus
// the fidelity signature that backed them.
type CallGraphProjection struct {
	Nodes []CallGraphNode
	Edges []CallGraphEdge
	// Completeness and Algorithm carry the per-module fidelity level and the
	// algorithm/devirt tier the graph was built at, as opaque strings so this
	// port stays free of the callgraph domain. A reachability determination is
	// only as sound as this fidelity, so a diff records it on the resulting
	// verdict and checks completeness parity before trusting a green result.
	Completeness string
	Algorithm    string
	// ArtifactKind is what the analysed module is (application or library), as an
	// opaque string for the same reason. Reachability roots are conditioned on
	// it: an application's own code is all reachable, because functions the
	// runtime dispatches to dynamically are still shipped code.
	ArtifactKind string
	// ServableAsCacheHit reports whether the stored graph this projection came
	// from may stand in for a fresh analysis, or whether the coordinate must be
	// analysed again. It is false for a record that failed because the analysis
	// environment could not run: nothing was measured about the module, so the
	// on-demand spawner must not read its presence as "already done".
	//
	// It is a projected boolean rather than the callgraph domain's own rule
	// because this port must stay free of that domain — the rule lives beside
	// composition and the reachability adapter applies it.
	ServableAsCacheHit bool
}

// CallGraphNode is the subset of a call graph node the analyser needs.
type CallGraphNode struct {
	ID            string
	Module        string
	Package       string
	Symbol        string
	Receiver      string
	IsExternal    bool
	IsExportedAPI bool
	// IsTest is the graph's test axis for the node. It is projected so the root
	// selection is fed the fact rather than a zero value that reads as "not a
	// test", leaving the scope the only thing that decides.
	IsTest bool
}

// CallGraphEdge is a directed call edge between two node IDs.
type CallGraphEdge struct {
	FromID string
	ToID   string
}

// CallGraphSpawner runs a callgraph extraction subprocess for a module so that
// a vuln-scan can populate the callgraph store on demand for findings-only
// modules. On exit 0 the record is persisted in the store and available via
// the CallGraphLoader. The raw stderr and any exec error are returned so the
// caller can compose an actionable ReachabilityNote.
type CallGraphSpawner interface {
	// walkID names the walk whose resolved build list the child may pin a
	// pre-modules module's require directives against; empty when the scan names
	// no walk.
	Spawn(ctx context.Context, coord coordinate.ModuleCoordinate, force bool, walkID string) (stderr []byte, err error)
}
