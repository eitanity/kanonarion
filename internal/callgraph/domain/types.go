package domain

import (
	"strings"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/gotoolchain"
)

// CallGraphSchemaVersion is the version of the CallGraphRecord JSON schema.
// Bump when the serialisation format changes in a backwards-incompatible way.
// v4 adds the ecosystem scope marker. v5 adds the per-node body-level fact
// fields (UsesUnsafePointer, IsAssemblyOrLinkname) used by capability analysis.
// v6 adds FailedPackages: the machine-readable set of packages that failed to
// typecheck, so verdicts over a Partial graph can be scoped to the exact
// packages whose edges were dropped rather than inferred from node/edge totals.
// v7 redesigns the edge confidence vocabulary (Direct, CHA-overapprox, VTA,
// Framework, Unknown), folds reflect-dispatched edges into Unknown, and records
// the reflect origin as the per-edge ReflectDispatch attribute.
// v8 adds Completeness: the per-module fidelity level (BUILT_WITH_BODIES,
// TYPE_ONLY, METADATA_ONLY, FAILED, VERSION_NOT_IN_TOOLCHAIN) so a before/after
// diff can assert completeness parity rather than read a "resolved"/"unaffected"
// verdict off an asymmetric comparison.
// v9 adds UsesPlugin: the per-node body-level fact that a function references the
// Go plugin package (plugin.Open / (*Plugin).Lookup), a soundness leaf sink that
// loads code the static graph never sees.
// v10 adds ArtifactKind: whether the analysed module builds a command
// (application) or is consumed as a library. Reachability roots are conditioned
// on it, so an application roots all of its own code and capability sinks the
// runtime dispatches to dynamically are no longer false-negatives.
// v11 qualifies anonymous-function node IDs with their enclosing function's
// identifier, so a closure declared in a method keeps that method's receiver.
// Previously closures in same-named methods on different receivers collapsed
// onto one ID and merged the edge sets of unrelated functions. Node IDs are
// persisted and hashed, so the identities themselves change.
// v12 stops flagging closures and other SSA-synthetic functions as
// IsExportedAPI. A closure is not nameable by a consumer, so rooting library
// reachability at one asserts a path that cannot be triggered.
// v13 opens two axes the graph previously left unmeasured and unstated.
// CallNode.IsTest plus CallGraphRecord.TestScope bring _test.go declarations
// into the graph as first-class nodes and record whether that axis was measured
// at all, so a callers query over a symbol only tests exercise is no longer a
// confident RESOLVED-ABSENT. Interfaces and Implementations make interface
// types and their method sets addressable, so "which concrete types must change
// with this port" is answerable from the graph rather than from a grep.
//
// AnalysisSource and WorktreeDigest joined the record WITHOUT a bump, and that is
// deliberate. Both are json omitempty, so a v13 record re-marshals to the bytes
// it was sealed over and still verifies; and both read as "not recorded" when
// absent, which is the truth about a record written before the field existed.
// Bumping would make every stored record unreadable through the schema gate — a
// purge by another name, and the opposite of what an append-only ledger is for.
// Bump only when a change makes an OLD record say something false, not merely
// something less.
//
// SynthesisedGoMod joined on the same terms, and for the same reason. It is
// omitted from the sealed shape when zero, so every stored record re-marshals to
// the bytes it was sealed over; and an absent value is not an unrecorded third
// state but the truth — nothing synthesised a go.mod before the field existed,
// so no old record can be one that did.
//
// SynthesisedGoMod.Requires and BuildListSource joined on those same terms
// again. Both are omitted when empty, so no stored record's bytes move; and
// neither can read as an unrecorded third state, because nothing pinned a
// require directive or was offered a build list before they existed. The pins
// are part of the graph's identity and feed the graph digest — two analyses of
// one artefact pinned differently are two graphs — while the build list's
// identity is provenance and is cleared before that comparison.
//
// AnalysisRoot joined on those same terms, and the worktree digest CHANGED THE
// VALUE it takes for an unchanged tree at the same time, without a bump either.
// Both deserve the argument.
//
// The root is omitted when empty, so no stored record's bytes move, and an absent
// root is the truth about a record written before the field existed rather than a
// third state — nothing stated where its tree was, because nothing could.
//
// The digest now hashes the loader's file list rather than a filesystem walk, so
// re-analysing an UNCHANGED tree mints a different value than it did before. That
// makes no stored record say anything false: each still identifies the tree it
// read, by the rule in force when it was written, and the scheme prefix on the
// new values is what keeps the two from being compared as one. What it does mean
// is that a digest from before the change can never equal one from after, which
// is why the read that routes a query to the caller's tree routes on
// AnalysisRoot and uses the digest only to REPORT which tree answered. Bumping
// PipelineVersion instead would take every stored generation out of every answer
// to restore a comparison nothing performs.
//
// CallEdge.Kind and CallGraphRecord.ReferenceScope joined on those same terms,
// and the argument is worth stating because a new EDGE kind looks like the sort
// of change that must bump. Both are omitted from the sealed shape when zero, so
// every stored record re-marshals to the bytes it was sealed over and still
// verifies. And neither reads as an unrecorded third state: no analysis before
// them extracted a reference edge, so a stored edge with no kind IS a call, and
// a record with no reference scope DID NOT measure the axis. The rule at the top
// of this comment decides it — bump only when a change makes an OLD record say
// something FALSE, not merely something less. An old record without reference
// edges said something false only while `callers` read its silence as a measured
// absence; ReferenceScope closes that by making the silence self-describing, and
// the verdict layer downgrades to UNRESOLVED over it. Bumping instead would take
// every stored graph out of every answer until re-extraction — a purge by
// another name, to replace a fact the record can simply state.
//
// ForeignModulesBuilt joined on those same terms, and it is the one case where
// the "absent reads as not-measured" argument is carried by THIS constant rather
// than by the field. It is omitted when empty, so every stored record re-marshals
// to the bytes it was sealed over; but an absent value genuinely does read two
// ways — this analysis built no foreign module's packages, or the record predates
// the field — and a consumer that must tell them apart reads the schema version,
// which is what a schema version is for. The alternative considered was an
// always-present key, and it is not available: verification re-marshals the
// struct rather than checking the stored bytes, so a key on every record moves
// every record's digest and the axis would cost a bump plus a migration to state
// a fact that changes no old record's meaning. No old record is made to say
// anything false: they were silent about holding another module's built code, and
// silence is what is being replaced.
const CallGraphSchemaVersion = "13"

// TestScope records whether a module's _test.go declarations were part of the
// analysis. It exists because the alternative — saying nothing — makes an empty
// callers answer indistinguishable from an unmeasured one, and test fakes are a
// large, systematic part of the edit surface of any interface change.
type TestScope string

const (
	// TestScopeUnknown is the zero value: the record makes no claim either way,
	// which every consumer must read as "not measured", never as "no test code".
	TestScopeUnknown TestScope = ""
	// TestScopeAnalysed means test files were loaded and their declarations are
	// present as nodes tagged IsTest. An empty test-scope answer over such a
	// record is a measurement.
	TestScopeAnalysed TestScope = "Analysed"
	// TestScopeExcluded means test files were deliberately not analysed for this
	// module — the load could not be performed with tests enabled.
	// TestScopeDetail carries why.
	TestScopeExcluded TestScope = "Excluded"
)

// IsMeasured reports whether the record's test axis was actually analysed.
// Only TestScopeAnalysed qualifies; both the zero value and an explicit
// exclusion mean an answer scoped to production code alone.
func (t TestScope) IsMeasured() bool { return t == TestScopeAnalysed }

// ArtifactKind describes what the analysed module is, which decides how
// reachability roots are chosen. An application's code all runs under entry
// points the analysis cannot enumerate (framework dispatch, registered
// callbacks, goroutine entries), so every owned function is a root; a library is
// only exercised through what a consumer can call.
type ArtifactKind string

const (
	// ArtifactLibrary is a module with no command: it is reached only through
	// its exported API and package init. It is the zero value, so a record
	// persisted before this field existed keeps the pre-existing behaviour.
	ArtifactLibrary ArtifactKind = ""
	// ArtifactApplication is a module that builds a command — it contains a
	// package main defining func main.
	ArtifactApplication ArtifactKind = "Application"
)

// ExclusionReasonConfig is the CallGraphRecord.ExclusionReason value used when
// a module was skipped because its path is listed in callgraph.exclude.
const ExclusionReasonConfig = "excluded_by_config"

// CallGraphStatus describes the outcome of call graph extraction.
type CallGraphStatus int

const (
	// CallGraphStatusUnknown is the zero value and should never appear in a
	// persisted record.
	CallGraphStatusUnknown CallGraphStatus = iota
	// CallGraphStatusExtracted means the call graph was fully constructed.
	CallGraphStatusExtracted
	// CallGraphStatusPartial means the graph was constructed but some packages
	// had load errors; the result covers only the packages that loaded cleanly.
	CallGraphStatusPartial
	// CallGraphStatusLoadFailed means package loading failed fatally; no graph
	// was produced.
	CallGraphStatusLoadFailed
	// CallGraphStatusOutOfMemory means the extraction hit the configured memory
	// budget and was terminated cleanly.
	CallGraphStatusOutOfMemory
	// CallGraphStatusCancelled means extraction was interrupted by context
	// cancellation.
	CallGraphStatusCancelled
	// CallGraphStatusExtractionFailed covers all other fatal errors.
	CallGraphStatusExtractionFailed
	// CallGraphStatusExcludedByConfig means the module was skipped before
	// traversal because its path is listed in callgraph.exclude. No graph was
	// produced; ExclusionReason and ExclusionList carry the provenance.
	CallGraphStatusExcludedByConfig
)

// String returns the human-readable name of the status.
func (s CallGraphStatus) String() string {
	switch s {
	case CallGraphStatusExtracted:
		return "Extracted"
	case CallGraphStatusPartial:
		return "Partial"
	case CallGraphStatusLoadFailed:
		return "LoadFailed"
	case CallGraphStatusOutOfMemory:
		return "OutOfMemory"
	case CallGraphStatusCancelled:
		return "Cancelled"
	case CallGraphStatusExtractionFailed:
		return "ExtractionFailed"
	case CallGraphStatusExcludedByConfig:
		return "ExcludedByConfig"
	default:
		return "Unknown"
	}
}

// CallGraphAlgorithm names the static analysis algorithm used to produce the
// call graph.
type CallGraphAlgorithm string

const (
	// AlgorithmCHA uses Class Hierarchy Analysis: conservative, fast,
	// over-approximates virtual dispatch.
	AlgorithmCHA CallGraphAlgorithm = "CHA"
	// AlgorithmRTA uses Rapid Type Analysis: more precise than CHA, slower.
	AlgorithmRTA CallGraphAlgorithm = "RTA"
	// AlgorithmStatic records only direct (non-virtual) calls.
	AlgorithmStatic CallGraphAlgorithm = "Static"
)

// EdgeConfidence describes how a call edge was resolved, so consumers can weight
// edges by resolution tier and the verdict layer can key soundness decisions off
// the tag. The vocabulary is ordered from most to least precise: a Direct edge
// names a unique concrete callee; CHA-overapprox and VTA are progressively
// refined interface-dispatch resolutions; Framework is bound by a framework
// model; Unknown is an unresolved edge that must flag verdicts as UNRESOLVED.
type EdgeConfidence string

const (
	// ConfidenceDirect is a statically-known call to a unique concrete callee,
	// including an interface site devirtualised to its sole implementer.
	ConfidenceDirect EdgeConfidence = "Direct"
	// ConfidenceCHAOverapprox is an unrefined Class Hierarchy Analysis
	// over-approximation of an interface dispatch: every type-compatible method
	// is a possible callee.
	ConfidenceCHAOverapprox EdgeConfidence = "CHA-overapprox"
	// ConfidenceVTA is an interface dispatch resolved by the Variable Type
	// Analysis tier, narrowing the CHA over-approximation to the types that
	// actually flow to the call site.
	ConfidenceVTA EdgeConfidence = "VTA"
	// ConfidenceFramework is an edge bound by a framework model or thunk rather
	// than observed in the analysed source.
	ConfidenceFramework EdgeConfidence = "Framework"
	// ConfidenceUnknown is an edge the analyser cannot resolve, including
	// reflect-dispatched calls (see CallEdge.ReflectDispatch). It is a soundness
	// sink: verdicts reaching such an edge must be reported as UNRESOLVED.
	ConfidenceUnknown EdgeConfidence = "Unknown"
)

// EdgeKind names what an edge records: a call, or a reference to a function as
// a value.
//
// The two are not the same fact and must not be read as one. A call edge says
// control transfers from the caller to the callee at that site. A reference edge
// says the callee's function VALUE was taken there — the shape of every Go HTTP
// registration, `r.Get(path, h.Handle)` — and says nothing about when, or
// whether, it is subsequently invoked. Reporting a registration as a call would
// assert an invocation the analysis never witnessed; reporting nothing at all,
// which is what the graph did before this kind existed, made a symbol that is
// driven on every request look like one nothing reaches.
//
// The zero value is a call, which is the truth about every edge recorded before
// the kind existed: reference edges were not extracted, so no stored edge is one.
type EdgeKind string

const (
	// EdgeKindCall is an invocation. It is the zero value.
	EdgeKindCall EdgeKind = ""
	// EdgeKindReference is a function value taken at the FromID site, naming
	// ToID. It is not an invocation and never counts as one.
	EdgeKindReference EdgeKind = "Reference"
)

// IsReference reports whether the edge records a value being taken rather than a
// call being made.
func (k EdgeKind) IsReference() bool { return k == EdgeKindReference }

// ReferenceScope records whether an analysis looked for reference edges at all.
//
// It exists for the same reason TestScope does, and answers the same class of
// question: without it, a record produced before reference extraction existed is
// indistinguishable from one whose analysis looked and found no method values,
// and `callers` would present the first as a measured absence. A record that did
// not measure the axis says so, and a negative answer over it is UNRESOLVED
// rather than RESOLVED-ABSENT.
type ReferenceScope string

const (
	// ReferenceScopeUnknown is the zero value: the record makes no claim, which
	// every consumer must read as "not measured" and never as "no references".
	// It is the truth about every record written before reference edges existed.
	ReferenceScopeUnknown ReferenceScope = ""
	// ReferenceScopeAnalysed means function-value references were extracted
	// alongside calls. An empty callers answer over such a record covers both
	// kinds of edge.
	ReferenceScopeAnalysed ReferenceScope = "Analysed"
)

// IsMeasured reports whether the record's reference axis was actually analysed.
func (r ReferenceScope) IsMeasured() bool { return r == ReferenceScopeAnalysed }

// MigrateConfidence maps a legacy stored confidence string onto the current
// vocabulary, deterministically. The pre-v7 values DynamicDispatch and
// Reflection are folded: DynamicDispatch becomes CHA-overapprox, and Reflection
// becomes Unknown with the reflect-origin flag set so the reflect provenance is
// preserved as an edge attribute. All current values pass through unchanged.
// The boolean result reports whether the edge originated from a reflect call.
func MigrateConfidence(stored string) (EdgeConfidence, bool) {
	switch stored {
	case "DynamicDispatch":
		return ConfidenceCHAOverapprox, false
	case "Reflection":
		return ConfidenceUnknown, true
	default:
		return EdgeConfidence(stored), false
	}
}

// SourcePosition identifies a location in a source file.
type SourcePosition struct {
	File string // path relative to module root or absolute within the analysis
	Line int
}

// CallNode is a function or method node in the call graph.
type CallNode struct {
	// ID is a stable, unique identifier in the form "pkg/path.FuncName" for
	// free functions or "pkg/path.(*RecvType).MethodName" for methods.
	ID            string
	Module        string // module path owning this node; empty for unknown
	Package       string // import path of the package
	Symbol        string // short function/method name
	Receiver      string // receiver type name (empty for free functions)
	IsExternal    bool   // true if this node is outside the analysed module
	IsExportedAPI bool   // true if this node is part of the module's public API
	Position      SourcePosition
	// UsesUnsafePointer is true when the function's own body performs an
	// unsafe.Pointer conversion. This is a body-level capability fact that a
	// callee-identity sink map cannot witness (the unsafe package exposes no
	// callable functions), so it is captured at extraction time and treated as
	// an UNSAFE_POINTER sink during capability analysis.
	UsesUnsafePointer bool
	// IsAssemblyOrLinkname is true when the function has no Go body — it is
	// implemented in assembly or provided via //go:linkname. Such functions are
	// call-graph leaves with no edges into them, so this fact is captured at
	// extraction time and treated as an ARBITRARY_EXECUTION sink during
	// capability analysis.
	IsAssemblyOrLinkname bool
	// UsesPlugin is true when the function's own body references the Go plugin
	// package (plugin.Open / (*Plugin).Lookup). A plugin boundary loads code the
	// static call graph never sees, so an empty callers/callees answer over such
	// a node cannot be trusted as a negative — this fact is captured at extraction
	// time and treated as a leaf soundness sink that downgrades a negative verdict
	// to UNRESOLVED. Capability analysis already witnesses plugin use via the
	// package-import sink map, so this fact is verdict-layer only.
	UsesPlugin bool
	// IsTest is true when the function is declared in a _test.go file or in an
	// external test package. It is the node role that lets a query separate the
	// production blast radius of a change from its test surface without hiding
	// either: both are in the graph, and the caller chooses.
	IsTest bool
}

// InterfaceType is an interface declared in the analysed module, made
// addressable so a port-signature change can ask the type question — which
// concrete method sets must change together — rather than the edge question.
// An interface method is not a call-graph node (nothing calls it; calls go to
// implementations), so it needs its own identity.
type InterfaceType struct {
	// ID is "pkg/path.Name", matching the node-ID convention for a free
	// declaration. The per-method form is "pkg/path.(Name).Method", matching the
	// receiver-parenthesised convention for methods.
	ID      string
	Package string
	Name    string
	// Methods is the interface's full method set including embedded interfaces,
	// sorted. Names only: the signature lives in the declaration this ID points at.
	Methods  []string
	Position SourcePosition
	// IsTest is true when the interface is declared in a _test.go file.
	IsTest bool
}

// MethodID renders the addressable ID of one of the interface's methods.
func (i InterfaceType) MethodID(method string) string {
	return i.Package + ".(" + i.Name + ")." + method
}

// ImplementedMethod binds one interface method name to the concrete call-graph
// node that satisfies it, so the per-method form of an implementers query
// answers with node IDs the edge queries also accept.
type ImplementedMethod struct {
	Method string
	NodeID string
}

// InterfaceImplementation records that a concrete named type in the analysed
// module satisfies an interface the module declares.
//
// The relation is computed over the analysed module's own declarations on both
// sides. A type in another module that satisfies the same interface is not
// recorded here — that module's analysis does not own the interface, and
// computing satisfaction against every interface in the dependency graph is a
// different, far larger measurement. Query output states this scope rather than
// letting the omission read as an empty set.
type InterfaceImplementation struct {
	// InterfaceID is the InterfaceType.ID this implementation satisfies.
	InterfaceID string
	// TypeID is the concrete type in receiver form: "pkg/path.(*Store)" for a
	// pointer-receiver implementation, "pkg/path.(Value)" for a value one. It is
	// the node-ID prefix every method of the implementation shares.
	TypeID   string
	Package  string
	Position SourcePosition
	// IsTest is true when the concrete type is declared in a _test.go file —
	// the test fakes that a port-signature change must be updated alongside.
	IsTest bool
	// Methods maps each interface method to the concrete node implementing it,
	// sorted by method name.
	Methods []ImplementedMethod
}

// CallEdge is a directed call relationship between two nodes.
type CallEdge struct {
	FromID     string
	ToID       string
	CallSite   SourcePosition
	Confidence EdgeConfidence
	// ReflectDispatch is true when the edge was resolved through a reflect
	// call. Such edges carry ConfidenceUnknown — reflection is not a distinct
	// confidence rank — but the reflect provenance is recorded here so the
	// verdict-soundness layer can attribute the UNRESOLVED signal to reflection
	// specifically rather than a generic unresolved dispatch.
	ReflectDispatch bool
	// Kind says whether this edge is a call or a reference to a function value.
	// The zero value is a call; see EdgeKind for why the distinction may never
	// be collapsed.
	Kind EdgeKind
}

// CallGraphRecord is the aggregate root for a module's call graph extraction
// result. It is immutable once ContentHash is set.
type CallGraphRecord struct {
	SchemaVersion string
	// Ecosystem declares the schema's scope; always fetchdomain.EcosystemGo.
	Ecosystem  string
	Coordinate coordinate.ModuleCoordinate
	Algorithm  CallGraphAlgorithm
	// Completeness is the per-module fidelity level at which this graph was
	// analysed (BUILT_WITH_BODIES down to FAILED/VERSION_NOT_IN_TOOLCHAIN),
	// derived from the build outcome at extraction time. It is the machine
	// signal a diff keys completeness-parity off, and the per-module phase
	// caveat keys off, so neither has to infer fidelity from node/edge totals.
	Completeness CompletenessLevel
	// ArtifactKind is what the analysed module is — an application that builds a
	// command, or a library. Reachability roots are conditioned on it: an
	// application roots every owned node, because code the runtime dispatches to
	// dynamically is still the application's own code and its capabilities are
	// really exercised. Empty means library, so pre-v10 records keep their
	// original rooting.
	ArtifactKind ArtifactKind
	Nodes        []CallNode
	Edges        []CallEdge
	// Interfaces are the interface types the analysed module declares, and
	// Implementations the concrete types of that module satisfying them. They
	// are the type-level half of "what must change together", which the edge
	// collections cannot express: an interface method has no callers, only
	// implementations.
	Interfaces      []InterfaceType
	Implementations []InterfaceImplementation
	// TestScope records whether _test.go declarations were part of this
	// analysis. The zero value means the record makes no claim, which consumers
	// must treat as unmeasured rather than as an absence of test code.
	TestScope TestScope
	// TestScopeDetail explains a TestScopeExcluded value. Empty otherwise.
	TestScopeDetail string
	// ReferenceScope records whether function-value references were extracted
	// alongside calls. The zero value means the record makes no claim, which
	// consumers must treat as unmeasured rather than as an absence of
	// references — see ReferenceScope.
	ReferenceScope ReferenceScope
	OverallStatus  CallGraphStatus
	FailureDetail  string
	// FailureCause says what a failing OverallStatus is a statement about: the
	// module, or the run that tried to analyse it. FailureDetail is the prose a
	// human reads; this is the machine axis, classified where the failure was
	// still a value rather than recovered from that prose later.
	//
	// Empty on a record that did not fail, and on a failure record written before
	// the axis existed. Both read as "no cause stated", never as "the module was
	// at fault" — see FailureCause and RecordIsCacheable.
	FailureCause FailureCause
	// FailedPackages is the sorted, deduplicated set of import paths within the
	// analysed module that failed to typecheck (or failed SSA construction).
	// It is populated when OverallStatus is Partial and drives sound verdict
	// caveating: a reachability / callers / callees query whose root or reached
	// nodes fall in one of these packages is under-resolved (edges were dropped)
	// and must be reported as unresolved rather than a confident "none".
	// FailureDetail is the human-readable companion; this is the machine set.
	FailedPackages []string
	// ExclusionReason is non-empty when the module was skipped rather than
	// analysed; currently always ExclusionReasonConfig.
	ExclusionReason string
	// ExclusionList is the callgraph.exclude list that was active when this
	// record was computed, sorted for determinism. Recorded for every record
	// so callgraph-show can report the policy in force at extraction time.
	ExclusionList   []string
	NodeCount       int
	EdgeCount       int
	ExtractedAt     time.Time
	PipelineVersion string
	ContentHash     string
	// ArtefactIdentity names the fetched artefact this record was derived from,
	// in the "zip:h1:..." / "gomod:h1:..." form fetchdomain.ArtefactIdentity
	// renders. It answers the question the coordinate cannot: which bytes
	// produced this finding. A coordinate names a module version, and the fetch
	// record for that coordinate may since have been re-measured, so a link by
	// coordinate is a link by convention; this one is by fact, and is covered by
	// ContentHash, so the claim is as tamper-evident as the finding itself.
	//
	// Empty on records written before the field existed, and on records derived
	// from no fetched artefact at all. Both read as "not recorded", never as
	// "derived from nothing". Read it back through RecordArtefactIdentity,
	// which draws that distinction; never hand this field to
	// ParseArtefactIdentity directly.
	ArtefactIdentity string
	// SourceContentHash is the content hash of the fetch record that supplied
	// those bytes. ArtefactIdentity says which artefact; this says which
	// measurement of it, so a reader can fetch that record and check the claim
	// against it. Empty exactly when ArtefactIdentity is.
	SourceContentHash string
	// AnalysisSource names what the analysis read: a fetched module zip, or a
	// working tree on disk. It is a dimension rather than a ladder position — see
	// AnalysisSource — so it belongs to the record's identity and composition
	// never chooses between its values.
	//
	// Empty on records written before the field existed, which reads as "not
	// recorded" and never as "analysed from nothing".
	AnalysisSource AnalysisSource
	// WorktreeDigest identifies WHICH working tree a worktree analysis read, as a
	// digest over the source the loader actually resolved. Empty for every other
	// source.
	//
	// The value carries a SCHEME PREFIX saying how the identity was established,
	// because more than one way has been used and they are not comparable:
	// "analysed-sha256:" is taken over the loader's own file list (symlinks
	// followed, build tags applied), "scanned-sha256:" over a filesystem walk of
	// the tree, used only when a failed load resolved no files. A bare "sha256:"
	// is a record written before the schemes existed, when the walk was the only
	// method — a truthful identity of that tree under the rule it was computed by,
	// and one nothing may compare against a digest computed since.
	//
	// It is here because a worktree record has no artefact identity — nothing was
	// fetched, so there is nothing to name — and without a discriminator two
	// checkouts of one module path are one row. The absolute path the analysis ran
	// in is deliberately not used: where a tree happened to be mounted is
	// provenance, and two different trees at one path (a branch switch, a
	// rebuild) would share it while two copies of one tree would not.
	WorktreeDigest string
	// WorktreeScanDigest identifies the tree a worktree analysis was ASKED to
	// analyse, taken before the analysis ran, by scanning every .go file under the
	// root plus go.mod and go.sum. Empty for every other source, and on worktree
	// records written before the field existed.
	//
	// It exists because WorktreeDigest cannot be computed without doing the work.
	// That digest covers the files the loader resolved, so it is only knowable
	// once the load has happened — which makes it a perfect identity of what was
	// analysed and useless as a key for deciding whether to analyse at all. This
	// one is computable from the tree alone, in the time a directory walk takes,
	// so a run can ask "is this the tree the record I hold was computed from?"
	// before spending the analysis.
	//
	// The two are not comparable and nothing compares them: they carry different
	// scheme prefixes for that reason. This one is wrong in both directions as a
	// description of what was ANALYSED — it covers files the loader ignores, and
	// misses source the loader follows out of the tree through a symlink — and it
	// is never used to make a claim about the graph. It is used only to decide
	// whether two runs were handed the same tree, where being wrong in the first
	// direction costs a re-analysis and nothing else.
	//
	// It is taken BEFORE the analysis rather than after, deliberately. A tree
	// edited while an analysis is running produces a graph of neither state; a
	// digest of the tree as it was at the start then differs from what the next
	// run scans, and that run re-derives. Stamping the end state instead would let
	// the next run reuse a graph that was taken of a tree that never existed.
	WorktreeScanDigest string
	// AnalysisRoot is the absolute, symlink-free directory a worktree analysis
	// ran in. Empty for every other source, and on worktree records written
	// before the field existed.
	//
	// It answers a different question from WorktreeDigest, and the pair is only
	// coherent because they are different. The digest is the tree's IDENTITY —
	// what it contains — and a path is wrong for that in both directions: two
	// different trees at one path (a branch switch, a rebuild) share it, and two
	// copies of one tree do not. The root is the tree's LOCATION, and location is
	// exactly what a reader standing in a checkout is asking about when they query
	// a symbol: "the tree I am in", not "a tree whose every byte matches mine".
	//
	// Routing on identity instead would answer nothing the moment the caller had an
	// uncommitted edit, because the tree in front of them would then match no
	// content state the ledger holds. Measured on the maintainer's store, one local
	// coordinate held eighteen generations across sixteen distinct digests: one
	// working tree at sixteen content states, not sixteen checkouts.
	//
	// It is provenance rather than claim — two copies of one tree at two paths
	// describe the same graph — so it is cleared before a graph digest is taken.
	AnalysisRoot string
	// Toolchain is the Go toolchain that built this graph, as `go env GOVERSION`
	// of the process the loader drove ("go1.26.6"). It is neither the version
	// kanonarion was compiled with nor the module's own go directive: the graph
	// carries the toolchain's stdlib and its vendored trees, so the toolchain that
	// ran is what decided the answer.
	//
	// It is a DIMENSION, not a ladder position — see gotoolchain.Version.
	// Composition groups on it and never picks between two values.
	//
	// Empty on records written before the field existed, which reads as "not
	// recorded" and never as the reading host's toolchain. Read it back through
	// RecordToolchain, which also recovers what such a record's own stdlib
	// positions still show.
	Toolchain gotoolchain.Version
	// Analyser is the golang.org/x/tools that type-checked this module and built
	// the SSA the graph was computed over, and how the store came to state it.
	//
	// IT IS OUTSIDE THE SEAL, and that is the whole reason it can exist on 811
	// records that were written before it. The canonical encoding does not carry
	// it, so every stored record still marshals to the bytes it was sealed over
	// and verifies against the hash it was written with; this field is filled from
	// the row's own column on the way out, and read from it on the way in. Nothing
	// may move it inside the seal without stranding every generation the store
	// holds — which is exactly what a fact ABOUT the producer must not cost.
	//
	// Because it is outside the seal it is also not evidence a later run may act
	// on: it ranks nothing, gates no cache and pins no reuse. It is read, printed
	// and compared, and that is all. Facts a run DECIDES on live inside the seal,
	// where an edit breaks the record's own integrity check.
	//
	// The zero identity means the row states none. Read it through the identity
	// rather than the bare version: a value inferred from a date and one observed
	// by the extracting binary are different strengths of claim, and the type
	// refuses to render them alike.
	Analyser AnalyserIdentity
	// SynthesisedGoMod is non-zero when the analysed tree is not the published
	// tree: the module zip shipped no go.mod and kanonarion wrote one before
	// loading. It states which module path and which go directive that file
	// declared, so the graph's semantics are readable rather than assumed.
	//
	// The zero value means the published bytes were analysed as published. See
	// SynthesisedGoMod for why that is a statement and not merely an absence.
	SynthesisedGoMod SynthesisedGoMod
	// BuildListSource names the walk whose resolved build list was OFFERED to this
	// analysis, whether or not anything was pinned from it.
	//
	// It is provenance rather than claim — two walks that resolved the same
	// versions produce the same graph — so it is cleared before a graph digest is
	// taken. It is on the record because it is what tells a record produced
	// without any build list from one produced with a build list that pinned
	// nothing, and only the first is worth re-deriving when one becomes available.
	//
	// Empty means no build list reached this analysis. That is the truth about
	// every record written before the field existed, so there is no unrecorded
	// third state to ladder against.
	BuildListSource string
	// PrefixAttributedPackages is the sorted, deduplicated set of import paths
	// this analysis admitted to the analysed module by PATH PREFIX rather than by
	// the toolchain's own answer.
	//
	// Membership is normally taken from go/packages' Package.Module.Path, which is
	// correct by definition: kanonarion reports on what the build contains and does
	// not get to define it. The prefix rule survives only for packages the loader
	// places in no module at all — a module published before modules existed ships
	// no go.mod, and its packages come back with no module attached. For those the
	// prefix is the only test available, and every path decided that way is named
	// here so a reconstruction is never read as a measurement.
	//
	// Empty means the toolchain named every in-module package itself. That is also
	// what a record written before the field existed says, and it is a weaker claim
	// than those records were entitled to make — they decided every package by
	// prefix — so it is read as "no prefix attribution recorded" rather than as
	// "none happened". Nothing may infer from an empty list that a record's
	// membership was measured.
	PrefixAttributedPackages []string
	// ForeignModulesBuilt names every module OTHER than the analysed one whose
	// packages this analysis built with bodies, at the version resolution gave
	// it, sorted.
	//
	// It is the claim the completeness ladder could not make. Completeness is a
	// per-MODULE level, and a record that holds a nested module's built packages
	// says BUILT_WITH_BODIES about code belonging to a module it does not name —
	// so within one record the level meant two different things depending on
	// which node a query landed on. This names the second population, so a
	// negative answered from it can say which record answered and at what version.
	//
	// Empty means this analysis built no foreign module's packages. It is also
	// what a record written before the field existed carries, and those two are
	// separated by the record's own SchemaVersion rather than by an
	// always-present key: the field is omitted from the sealed shape when empty,
	// on the terms every additive field here has used, so every stored record
	// re-marshals to the bytes it was sealed over.
	ForeignModulesBuilt []ForeignModule
	// DerivedBy states WHY this generation exists: which reuse gate governed the
	// append, and whether the run asked it or forced past it. See
	// GenerationDerivation.
	//
	// The zero value means the generation predates the field, or was written by a
	// path that consults no gate — an exclusion record states its reason instead.
	// It is never read as a gate or an outcome of its own, and no comparison or
	// digest sees it, so a generation carrying one still restates one that does
	// not.
	DerivedBy GenerationDerivation
}

// ImplementersOf returns the implementations of interfaceID recorded in rec,
// and whether rec's module declares the interface at all. The two results are
// distinct answers: an interface this module does not declare is outside the
// measurement, whereas a declared interface with no implementations is a
// measured empty set.
//
// It is a function rather than a method because CallGraphRecord is a result
// type: it carries facts, and query behaviour over those facts lives beside it,
// not on it.
func ImplementersOf(rec CallGraphRecord, interfaceID string) (impls []InterfaceImplementation, declared bool) {
	if _, declared = InterfaceByID(rec, interfaceID); !declared {
		return nil, false
	}
	for i := range rec.Implementations {
		if rec.Implementations[i].InterfaceID == interfaceID {
			impls = append(impls, rec.Implementations[i])
		}
	}
	return impls, true
}

// InterfaceByID returns the interface rec's module declares under the given ID.
func InterfaceByID(rec CallGraphRecord, id string) (InterfaceType, bool) {
	for i := range rec.Interfaces {
		if rec.Interfaces[i].ID == id {
			return rec.Interfaces[i], true
		}
	}
	return InterfaceType{}, false
}

// ParseInterfaceMethodID splits an interface-method ID of the form
// "pkg/path.(Name).Method" into the interface ID "pkg/path.Name" and the method
// name. It reports false for any other shape, including a concrete method ID
// with a pointer receiver ("pkg/path.(*Name).Method"), which names a node, not
// an interface method.
func ParseInterfaceMethodID(id string) (interfaceID, method string, ok bool) {
	open := strings.LastIndex(id, ".(")
	if open < 0 {
		return "", "", false
	}
	closeIdx := strings.Index(id[open:], ").")
	if closeIdx < 0 {
		return "", "", false
	}
	closeIdx += open
	name := id[open+2 : closeIdx]
	method = id[closeIdx+2:]
	if name == "" || method == "" || strings.HasPrefix(name, "*") {
		return "", "", false
	}
	if strings.ContainsAny(method, ".()") {
		return "", "", false
	}
	return id[:open] + "." + name, method, true
}
