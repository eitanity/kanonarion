package domain

import (
	"sort"
	"time"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
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
const CallGraphSchemaVersion = "7"

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
}

// CallGraphRecord is the aggregate root for a module's call graph extraction
// result. It is immutable once ContentHash is set.
type CallGraphRecord struct {
	SchemaVersion string
	// Ecosystem declares the schema's scope; always fetchdomain.EcosystemGo.
	Ecosystem     string
	Coordinate    fetchdomain.ModuleCoordinate
	Algorithm     CallGraphAlgorithm
	Nodes         []CallNode
	Edges         []CallEdge
	OverallStatus CallGraphStatus
	FailureDetail string
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
}

// Sort puts all collections into a canonical, deterministic order.
// Must be called before hashing.
func (r *CallGraphRecord) Sort() {
	sort.Strings(r.ExclusionList)
	sort.Strings(r.FailedPackages)
	sort.Slice(r.Nodes, func(i, j int) bool {
		return r.Nodes[i].ID < r.Nodes[j].ID
	})
	sort.Slice(r.Edges, func(i, j int) bool {
		if r.Edges[i].FromID != r.Edges[j].FromID {
			return r.Edges[i].FromID < r.Edges[j].FromID
		}
		if r.Edges[i].ToID != r.Edges[j].ToID {
			return r.Edges[i].ToID < r.Edges[j].ToID
		}
		if r.Edges[i].CallSite.File != r.Edges[j].CallSite.File {
			return r.Edges[i].CallSite.File < r.Edges[j].CallSite.File
		}
		return r.Edges[i].CallSite.Line < r.Edges[j].CallSite.Line
	})
}
