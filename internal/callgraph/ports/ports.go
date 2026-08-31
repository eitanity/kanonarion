package ports

import (
	"context"
	"errors"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/gotoolchain"

	"github.com/eitanity/kanonarion/internal/audit"
	"github.com/eitanity/kanonarion/internal/callgraph/domain"
)

// AuditSink appends an audit event to the assurance log. The shared JSONL
// AuditLog satisfies this; the application depends only on this narrow port,
// not on the factstore adapter that persists it.
type AuditSink interface {
	RecordEvent(audit.Event) error
}

// ErrModuleNotFetched is returned when extraction is attempted for a module
// that has no FactRecord in the store.
var ErrModuleNotFetched = errors.New("module not fetched")

// ErrCallGraphNotFound is returned by CallGraphStore.GetCallGraphRecord when
// no record exists for the given coordinate and pipeline version.
var ErrCallGraphNotFound = errors.New("call graph record not found")

// ErrCallGraphIntegrity is returned when the stored record's content hash does
// not match the recomputed hash.
var ErrCallGraphIntegrity = errors.New("call graph record integrity check failed")

// ErrCallGraphConflict wraps a domain.CallGraphConflict surfaced through the
// store. It marks the answers composition refuses to produce by picking: two
// analyses of one coordinate that name different artefacts, that came from
// different KINDS of source, or that agree on completeness and disagree on the
// graph. Callers route on it rather than on the concrete type so a partial
// answer can be returned alongside it.
var ErrCallGraphConflict = errors.New("conflicting call graph records")

// ErrUnidentifiedWorktree is returned when a record says it was built from a
// working tree but carries no digest of that tree.
//
// It is the worktree counterpart of the zero artefact identity. A fetched
// artefact is named by its hash; a working tree has none, so the digest is the
// only thing that tells one checkout of a module path from another. Without it
// two different trees are one row, and the ledger composes two bodies of code
// into a single answer.
var ErrUnidentifiedWorktree = errors.New("worktree call graph record identifies no tree")

// WorktreePreference names the working tree a reader is standing in, so a query
// about a local coordinate can be answered from THAT tree rather than from
// whichever tree happened to be analysed last.
//
// The zero value expresses no preference, which is the truth for a caller who is
// not inside any module — running a query from elsewhere — and leaves the read
// exactly as it was.
type WorktreePreference struct {
	// ModulePath is the module the tree at Root declares. The preference applies
	// only to that module's local coordinate: standing in project A says nothing
	// about which checkout of project B should answer.
	ModulePath string
	// Root is the absolute, symlink-free directory of the tree, resolved the same
	// way the analysis resolved its own, so one tree reached by two names is one
	// root.
	Root string
}

// IsZero reports whether the preference names no tree.
func (p WorktreePreference) IsZero() bool { return p.ModulePath == "" || p.Root == "" }

// WorktreeRouting reports which working tree answered for one local coordinate,
// and what else the ledger holds for it.
//
// It exists because a routing decision the reader cannot see is the same failure
// as no routing at all: replacing a silent wrong tree with a silent right one
// leaves the reader unable to tell which they got.
type WorktreeRouting struct {
	// LocatedTrees is how many distinct working trees the ledger holds generations
	// from for this coordinate, counted by analysis root.
	LocatedTrees int
	// UnlocatedGenerations is how many worktree generations state no root at all,
	// because they were written before roots were recorded. They are NOT counted
	// as trees: nothing says how many trees they came from, and guessing one
	// either way is a claim the records do not support. What can be said about
	// them is that none of them can be shown to be the caller's, which is what
	// Matched already says.
	UnlocatedGenerations int
	// ServedRoot and ServedDigest describe the generation the read serves. The
	// root is empty when the served generation predates the field.
	ServedRoot   string
	ServedDigest string
	// ServedSource is what the served generation was analysed from.
	//
	// It is here because the counts above are over worktree rows and the served
	// record is over all of them, and without it the two halves could be joined
	// into a sentence neither supports: a ledger holding one located tree and no
	// unlocated generations was reported as having answered from "a generation
	// that recorded no working tree", which describes a row the counts never saw.
	// A zip analysis states no root because it has none, not because it predates
	// the field, and a reader told which it was can act on the difference.
	ServedSource domain.AnalysisSource
	// CallerRoot is the tree the reader is standing in, empty when they are not
	// inside this module.
	CallerRoot string
	// Matched reports whether the served generation was analysed in CallerRoot.
	// False with a non-empty CallerRoot is the miss: the caller's own tree has no
	// generation, and an answer from another tree — or from a generation that
	// states no tree — was served instead.
	Matched bool
}

// WorthReporting reports whether a reader has a routing decision to see.
//
// It also says whether the served-generation fields above were established: a
// store is free to leave them zero when this is false, because establishing them
// means reading the record and nothing renders them. See the sqlite adapter.
//
// Two cases, and only two. Several located trees means the read chose between
// them. A caller standing in a tree that did not answer means the read could not
// choose theirs — including the upgrade case, where every generation predates
// location recording and none of them can be shown to be the tree in front of
// them. Everything else is a single checkout answering for itself, and a line
// saying so on every query is noise on every query.
func (r WorktreeRouting) WorthReporting() bool {
	return r.LocatedTrees >= 2 || (r.CallerRoot != "" && !r.Matched)
}

// ErrUnlocatedWorktree is returned when a record says it was built from a
// working tree but states no root directory for it.
//
// The digest says which tree; this says where it was, and a reader querying a
// symbol from inside a checkout is asking the second question. Without it every
// generation of the coordinate is equally eligible, and the answer comes from
// whichever tree was analysed last — which is a silent wrong answer whenever
// more than one checkout exists.
var ErrUnlocatedWorktree = errors.New("worktree call graph record states no analysis root")

// AnalyserMetadata describes the algorithm and version of a CallGraphAnalyser
// implementation.
type AnalyserMetadata struct {
	Algorithm domain.CallGraphAlgorithm
	Version   string
}

// CallGraphAnalyser performs static call graph analysis on a module's source.
type CallGraphAnalyser interface {
	// Analyse extracts the call graph from a module zip.
	// The zip is in the Go module proxy format (entries prefixed by
	// "module@version/").
	//
	// zipPath is the local filesystem path to the module zip file.
	//
	// inputs carries what the requesting build already resolved. A module
	// published before Go modules ships no go.mod, and the require directives that
	// make it loadable are a property of the build asking, not of the artefact;
	// the zero value offers none and synthesis refuses such a module exactly as it
	// did before the parameter existed.
	//
	// Failures that are a property of the module (load errors, partial parse)
	// are returned in the record's OverallStatus; only infrastructure errors
	// return a non-nil error.
	Analyse(ctx context.Context, zipPath string, coord coordinate.ModuleCoordinate, inputs domain.AnalysisInputs) (domain.CallGraphRecord, error)

	// AnalyserMetadata returns the algorithm and version of this implementation.
	AnalyserMetadata() AnalyserMetadata
}

// LocalCallGraphAnalyser performs static call graph analysis on a Go module
// working tree on disk (no zip), used for local-analysis ingestion so
// kanonarion can resolve callers/callees of its own internal packages
type LocalCallGraphAnalyser interface {
	// AnalyseDir analyses the module rooted at dir. coord.Path must be the
	// module path from the directory's go.mod. Module-property failures are
	// reported via the record's OverallStatus; only infrastructure errors
	// return a non-nil error.
	AnalyseDir(ctx context.Context, dir string, coord coordinate.ModuleCoordinate) (domain.CallGraphRecord, error)

	// TreeIdentity establishes which tree dir currently is, WITHOUT analysing it:
	// the root the analysis would run in, and a digest of the tree's contents.
	//
	// It is separate from AnalyseDir because it is what a caller needs BEFORE
	// deciding to call it. The digest AnalyseDir stamps on its record covers the
	// files the loader resolved, which cannot be known without doing the work;
	// this one is a directory walk, and it is what makes "have I already answered
	// this?" a question a run can afford to ask.
	//
	// A tree that cannot be read at all is an infrastructure error: a run that
	// cannot identify its input must not silently proceed as though it had no
	// record to compare against.
	TreeIdentity(ctx context.Context, dir string) (domain.WorktreeIdentity, error)

	// AnalyserMetadata returns the algorithm and version of this implementation.
	AnalyserMetadata() AnalyserMetadata
}

// CallGraphStore persists CallGraphRecords and supports caller/callee queries.
//
// The zero coordinate is the one value the signatures cannot exclude: Go
// always permits coordinate.ModuleCoordinate{}, and it names no module.
// Implementations MUST refuse it with coordinate.ErrZeroCoordinate — on a
// write because it would key a row on the empty path at the empty version,
// which every later read treats as a genuine measurement, and on a read
// because absence is the wrong answer to a question about no module.
// coordinatetest.AssertRefusesZeroCoordinate pins the rule for every store.
type CallGraphStore interface {
	// PutCallGraphRecord APPENDS a call graph record. It never updates: the
	// ledger key carries the time of measurement and the record's own content
	// hash, so two distinct analyses are two rows. Writing the same record twice
	// is a no-op rather than an error, because a retried write must not fail a run
	// that already succeeded.
	//
	// A record analysed from a fetched artefact must name that artefact; a
	// worktree record must carry its tree digest instead. Both refusals are on the
	// write leg only — see the sqlite implementation for why the read leg must not
	// inherit them.
	PutCallGraphRecord(ctx context.Context, record domain.CallGraphRecord) error

	// GetCallGraphRecord returns the COMPOSED record for the given coordinate and
	// pipeline version: the highest completeness, then the most recent, within the
	// analysis source composition defaults to. Returns (zero, false, nil) if the
	// ledger holds none.
	//
	// Returns ErrCallGraphIntegrity if a stored hash does not verify, and
	// ErrCallGraphConflict for a disagreement composition must not resolve by
	// picking.
	GetCallGraphRecord(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (domain.CallGraphRecord, bool, error)

	// ListCallGraphRecords returns summaries matching the filter, ordered by
	// extracted_at descending.
	ListCallGraphRecords(ctx context.Context, filter CallGraphFilter) ([]CallGraphSummary, error)

	// FindCallers returns all edges in the store where the callee node ID
	// matches symbolID, for the given pipeline version.
	//
	// scope restricts the result to edges owned by a module in that build's
	// resolved version set; the zero ModuleSet imposes no restriction and
	// returns matches across every stored version, which is what a query that
	// names no build means.
	//
	// opts is the caller's choice about the test surface; the zero value
	// includes it, because omitting a caller is the more damaging error.
	FindCallers(ctx context.Context, symbolID string, pipelineVersion string, scope coordinate.ModuleSet, opts EdgeQueryOptions) ([]CallEdgeRef, error)

	// FindCallees returns all edges in the store where the caller node ID
	// matches symbolID, for the given pipeline version. scope and opts behave as
	// in FindCallers.
	FindCallees(ctx context.Context, symbolID string, pipelineVersion string, scope coordinate.ModuleSet, opts EdgeQueryOptions) ([]CallEdgeRef, error)
}

// EdgeQueryOptions narrows a caller/callee query. The zero value is the
// unrestricted query.
type EdgeQueryOptions struct {
	// ExcludeTests drops every edge with a test-scope endpoint. It is opt-in:
	// the default answer covers the whole graph, because a hidden test caller is
	// a false negative — the failure the three-valued verdict exists to prevent
	// — while an unwanted one is merely noise the reader can see and discount.
	ExcludeTests bool
	// Toolchain restricts the query to graphs built by one Go toolchain. The zero
	// value names none and composition groups on its own.
	//
	// It rides here because an edge query resolves, per module, WHICH generation's
	// edges to serve, and that resolution composes: a coordinate holding two
	// toolchains refuses, and without this the reader is told to name a toolchain
	// by a query that has no way to carry one.
	Toolchain gotoolchain.Version
}

// CallGraphRecordLister is the optional history read a store may offer: every
// generation the ledger holds for one coordinate, in the order they were
// appended.
//
// It is separate from CallGraphStore because it is what makes the ledger
// OBSERVABLE rather than what makes it work — no analysis path needs it, and a
// store that cannot answer it is still a usable call graph store. Callers type-
// assert for it.
type CallGraphRecordLister interface {
	// ListCallGraphRecordsFor returns every generation for the coordinate and
	// pipeline version, oldest first, each with its edges reconstructed and its
	// content hash verified.
	ListCallGraphRecordsFor(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) ([]domain.CallGraphRecord, error)
}

// CallGraphCoordinate is one analysed (module, version, pipeline version)
// triple as the ledger's COLUMNS state it.
//
// It answers "which modules has this store analysed, and at what versions" —
// which is a question about the ledger's keys, not about any record's content.
// CallGraphSummary answers the different question "what does the served
// generation say", and pays a composition per multi-generation coordinate to do
// it.
type CallGraphCoordinate struct {
	ModulePath      string
	ModuleVersion   string
	PipelineVersion string
	// AnyPartial reports whether ANY generation at this coordinate states a
	// Partial graph; AnyBelowFull whether any states a definite completeness
	// below BUILT_WITH_BODIES.
	//
	// Both are one-way gates, and that is what makes them usable without
	// composing. The generation composition serves is one of the generations, so
	// false PROVES the served record does not state the condition and no blob need
	// be decoded to learn it. True says only that it might, and a caller that
	// needs to know composes.
	AnyPartial   bool
	AnyBelowFull bool
	// GenerationsDiffer reports whether the generations at this coordinate state
	// different things about themselves: node count, edge count, overall status or
	// completeness is not identical across all of them.
	//
	// One-way like its neighbours and in the same direction. False PROVES every
	// generation states the same counts, status and completeness, so whichever one
	// a read serves, any generation's numbers are that generation's numbers too.
	// True says only that they do not all agree.
	//
	// It is NOT composition's verdict on the coordinate. That verdict is decided
	// over decoded records, and this listing decodes nothing — the cost it exists
	// not to pay. Generations that state different counts can still compose to a
	// served answer, and generations that state identical counts can still fail
	// that comparison. The flag says the generations do not agree with each other,
	// and a caller that needs the served answer reads the coordinate.
	GenerationsDiffer bool
	// Generations is what each generation at this coordinate says about itself,
	// newest first, read from its own row's columns. Empty when the store cannot
	// enumerate them without composing.
	//
	// It is a list rather than a winner because picking one is composition's job,
	// and a listing that printed the winner's counts without saying so would be a
	// derived verdict wearing a row's clothes. A caller that needs the served
	// answer reads the coordinate.
	Generations []CallGraphGeneration
}

// CallGraphGeneration is one row of the callgraph ledger as its own columns
// state it — never what composition would serve for the coordinate it sits at.
//
// Every field is a column, so a whole coordinate's history costs one scan of
// the record table and no blob decode, no edge row and no seal verification.
type CallGraphGeneration struct {
	ExtractedAt    time.Time
	Algorithm      domain.CallGraphAlgorithm
	OverallStatus  domain.CallGraphStatus
	Completeness   domain.CompletenessLevel
	AnalysisSource domain.AnalysisSource
	NodeCount      int
	EdgeCount      int
	// ContentHash is the seal this row carries, used here to NAME the generation
	// so a reader can find it in callgraph-show --history. It is not verified by
	// a listing and nothing may treat it as verified because a listing returned
	// it.
	ContentHash string
}

// StatesTheSame reports whether two generations say the same thing about
// themselves: the same counts, the same overall status and the same
// completeness.
//
// It is the one statement of what CallGraphCoordinate.GenerationsDiffer
// compares, so a store and a fake cannot drift into disagreeing about which
// difference counts. ExtractedAt, the content hash and the analysis source are
// deliberately excluded: every generation has its own, so including them would
// make every re-analysed coordinate differ and the flag would say nothing.
func (g CallGraphGeneration) StatesTheSame(other CallGraphGeneration) bool {
	return g.NodeCount == other.NodeCount &&
		g.EdgeCount == other.EdgeCount &&
		g.OverallStatus == other.OverallStatus &&
		g.Completeness == other.Completeness
}

// CallGraphCoordinateLister is the optional column-only listing: which
// coordinates the ledger holds an analysis of, without composing any of them.
//
// It exists because "which module owns this symbol" and "was this module
// analysed at all" are decided by the coordinate alone. Every caller, callee and
// implementer query asks that question two to four times before it looks at an
// edge, and answering it through ListCallGraphRecords costs a blob decode plus a
// full edge reconstruction for every generation of every multi-generation
// coordinate in the store — work no part of the answer reads.
//
// A store that does not offer it is still a usable call graph store; callers
// type-assert for it and fall back to the composing listing.
type CallGraphCoordinateLister interface {
	// ListCallGraphCoordinates returns one entry per (module, version, pipeline
	// version) the ledger holds, in the same order ListCallGraphRecords returns
	// its summaries, with the same filter applied. Each entry carries what every
	// generation at that coordinate says about itself, so a listing can report a
	// re-analysed module without composing it.
	ListCallGraphCoordinates(ctx context.Context, filter CallGraphFilter) ([]CallGraphCoordinate, error)
}

// ToolchainNamer names the Go toolchain this process's analyses run under, or
// the zero value when the environment cannot say.
//
// It is a function rather than a value because asking costs a subprocess, and
// most runs never need the answer: only a cache lookup that has already met a
// disagreement asks, and a process that extracts nothing never asks at all. The
// caller memoises, so the cost is paid at most once.
//
// It names the toolchain the RUN would analyse under, which is the only thing a
// cache lookup can compare a stored generation against. Nothing here reads a
// record: a record states its own toolchain, and attributing this host's to one
// that named none is the fabrication the toolchain axis exists to stop.
type ToolchainNamer func(ctx context.Context) gotoolchain.Version

// CallGraphSourceReader is the optional dimension-scoped read: the same question
// GetCallGraphRecord answers, restricted to the values of one or more dimensions.
//
// It exists because the source and the toolchain are dimensions rather than
// ladder positions, so "zip or working tree" and "which Go built it" are real
// questions that a coordinate cannot answer. GetCallGraphRecord applies a stated
// default; this is how a caller asks for the other one. It takes the whole
// compose request so a dimension added later reaches every implementation
// through the type rather than through a new parameter on each of them.
type CallGraphSourceReader interface {
	GetCallGraphRecordFrom(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string, req domain.ComposeRequest) (domain.CallGraphRecord, bool, error)
}

// WorktreeGenerationReader is the optional tree-scoped read: the generation the
// ledger holds for ONE working tree, named by the root it was analysed in.
//
// It is separate from CallGraphStore because it answers a question only the
// working-tree route asks. GetCallGraphRecord answers "what is this module's
// graph", and routes a local coordinate to whichever tree the READER is standing
// in — a process-wide preference, which is the right rule for a query and the
// wrong one for a run that has been told which directory to analyse. This takes
// the root as an argument so the answer cannot depend on where a shell happens
// to be.
//
// A store that does not offer it re-derives every run, which is what every store
// did before it existed.
type WorktreeGenerationReader interface {
	// WorktreeGeneration returns the record the ledger holds of ONE STATE of the
	// working tree at root — the state named by scanDigest — or (zero, false, nil)
	// when it holds none.
	//
	// The state is part of the key rather than something the caller checks
	// afterwards, because the ledger holds the tree's whole history and the newest
	// generation is not the only one that can answer. A branch switched away from
	// and back, an edit made and reverted: the tree is once again a state the
	// ledger has a graph of, and re-deriving it would measure again what is
	// already held.
	//
	// An empty scanDigest names no state and matches nothing. Every generation
	// written before the digest existed carries none, and absence cannot show that
	// two runs were handed the same tree.
	//
	// Several generations of one state are ordered by the completeness ladder, so
	// a re-analysis that came back with less than an earlier one does not answer.
	WorktreeGeneration(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion, root, scanDigest string) (domain.CallGraphRecord, bool, error)
}

// IdenticalGenerationReader is the optional after-the-fact read: the generation
// the ledger ALREADY holds that states the measurement a run has just taken.
//
// It answers a question the cache lookup cannot. A cache lookup runs before the
// analysis and asks whether a stored record may be SERVED; for a local
// coordinate the answer is always no, because a local version pins no content
// and the working tree mutates. Recognising afterwards that the analysis came
// back saying what the ledger already says is a different question, and one a
// run can only ask once it holds the answer.
//
// A store that does not offer it appends a generation per run, which is what
// every store did before it existed.
type IdenticalGenerationReader interface {
	// IdenticalGeneration returns the generation stating the same measurement as
	// rec — differing at most in when it was taken — or (zero, false, nil) when
	// the ledger holds none.
	//
	// A record that does not name the content it analysed matches nothing,
	// including another record that names none: absence is not a value two
	// records can share.
	IdenticalGeneration(ctx context.Context, rec domain.CallGraphRecord) (domain.CallGraphRecord, bool, error)
}

// CallGraphFilter constrains ListCallGraphRecords results.
type CallGraphFilter struct {
	ModulePath      string // optional; empty means all modules
	PipelineVersion string // optional; empty means all versions
	// AnalysisSource restricts the listing to records built from one kind of
	// source. The zero value imposes no restriction, which is what a listing that
	// names no source means.
	AnalysisSource domain.AnalysisSource
	Limit          int // 0: no limit
	Offset         int
}

// CallGraphSummary is a lightweight projection of a CallGraphRecord for list
// views. One summary describes the generation composition serves for a module,
// not one row of the ledger.
type CallGraphSummary struct {
	ModulePath      string
	ModuleVersion   string
	PipelineVersion string
	Algorithm       domain.CallGraphAlgorithm
	OverallStatus   domain.CallGraphStatus
	// Completeness is the fidelity the served generation was analysed at, and
	// AnalysisSource what it read. Both are on the summary because both decide
	// which question the row answers, and a list that omits them shows two
	// generations of one module as interchangeable.
	Completeness   domain.CompletenessLevel
	AnalysisSource domain.AnalysisSource
	NodeCount      int
	EdgeCount      int
	ExtractedAt    time.Time
	ContentHash    string
	// Conflict is non-nil when the ledger holds records for this module that
	// composition refuses to resolve by picking. It is reported on the row rather
	// than as the listing's error: a listing spans every module in the store, so
	// one disputed module must not delete every correct row. The other fields are
	// zero when it is set — there is no served generation to describe.
	Conflict error
}

// CallEdgeRef identifies a single call edge in the store, returned by
// FindCallers/FindCallees.
type CallEdgeRef struct {
	ModulePath      string
	ModuleVersion   string
	PipelineVersion string
	FromID          string
	ToID            string
	Confidence      domain.EdgeConfidence
	// IsTest is true when either endpoint is a test-scope node, so a reader can
	// see which part of an answer is the test surface without a second query.
	IsTest bool
	// Kind says whether the edge is a call or a reference to a function value.
	// It is on the ref because an answer that presents a registration as a call
	// asserts an invocation nothing measured — see domain.EdgeKind.
	Kind domain.EdgeKind
}

// CallEdgeRefLess is the canonical ordering for CallEdgeRef slices produced by
// transitive caller/callee queries. It is the same key as domain.CallEdgeLess,
// carried onto the shape a query result has: endpoints first, then where the
// edge was measured, then the edge's own facts, and it covers every field the
// ref carries so no two distinct refs compare equal.
//
// The one substitution is in the middle. domain.CallEdgeLess tiebreaks on the
// call site, which a CallEdgeRef does not carry; a query result instead spans
// modules, so the module a ref came from takes that slot.
func CallEdgeRefLess(a, b CallEdgeRef) bool {
	if a.FromID != b.FromID {
		return a.FromID < b.FromID
	}
	if a.ToID != b.ToID {
		return a.ToID < b.ToID
	}
	if a.ModulePath != b.ModulePath {
		return a.ModulePath < b.ModulePath
	}
	if a.ModuleVersion != b.ModuleVersion {
		return a.ModuleVersion < b.ModuleVersion
	}
	if a.PipelineVersion != b.PipelineVersion {
		return a.PipelineVersion < b.PipelineVersion
	}
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	if a.Confidence != b.Confidence {
		return a.Confidence < b.Confidence
	}
	if a.IsTest != b.IsTest {
		return !a.IsTest
	}
	return false
}

// CallGraphWorktreeRouter is the optional read that reports which working tree
// answered for a local coordinate. A store that cannot distinguish trees does
// not implement it, and a caller that cannot ask simply prints no notice —
// rather than inventing one.
type CallGraphWorktreeRouter interface {
	WorktreeRouting(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (WorktreeRouting, bool, error)
}
