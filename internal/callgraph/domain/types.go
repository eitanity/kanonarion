package domain

import (
	"sort"
	"time"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// CallGraphSchemaVersion is the version of the CallGraphRecord JSON schema.
// Bump when the serialisation format changes in a backwards-incompatible way.
// v4 adds the ecosystem scope marker.
const CallGraphSchemaVersion = "4"

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

// EdgeConfidence describes how certain the analyser is about a call edge.
type EdgeConfidence string

const (
	// ConfidenceDirect is a statically-known call to a concrete function.
	ConfidenceDirect EdgeConfidence = "Direct"
	// ConfidenceDynamicDispatch is a call through an interface or function
	// value; the exact callee is resolved by the algorithm.
	ConfidenceDynamicDispatch EdgeConfidence = "DynamicDispatch"
	// ConfidenceReflection is a call via the reflect package.
	ConfidenceReflection EdgeConfidence = "Reflection"
	// ConfidenceUnknown is used when the analyser cannot classify the edge.
	ConfidenceUnknown EdgeConfidence = "Unknown"
)

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
}

// CallEdge is a directed call relationship between two nodes.
type CallEdge struct {
	FromID     string
	ToID       string
	CallSite   SourcePosition
	Confidence EdgeConfidence
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
