package domain

import (
	"time"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// WalkSchemaVersion is the schema version for WalkRecord JSON. Bump when
// the serialisation format changes in a backwards-incompatible way.
const WalkSchemaVersion = "4"

// WalkScope identifies which dependency set a walk records. The three scopes are
// consistent across every go.mod-walking command so the same question resolves
// to the same set regardless of which command asks it.
type WalkScope string

const (
	// WalkScopeCode is the default: the modules the project's own code builds
	// against, including test code (`go list -deps -test ./...`).
	WalkScopeCode WalkScope = "code"
	// WalkScopeTool is the tooling supply chain: the import closure of the go.mod
	// tool directives.
	WalkScopeTool WalkScope = "tool"
	// WalkScopeComplete is build + tooling: the full Go build list (`go list -m all`).
	WalkScopeComplete WalkScope = "complete"
)

// WalkDepth controls how much of the dependency graph a Walk resolves.
type WalkDepth string

const (
	// WalkDepthFull is the default: the full transitive closure is fetched and
	// resolved. Serialised as an absent field for backward compatibility with
	// records written before this field existed.
	WalkDepthFull WalkDepth = "full"
	// WalkDepthShallow fetches only the target module, lists its go.mod require
	// entries as graph nodes without fetching them, and marks the graph partial.
	// Downstream vuln-scan falls back to OSV metadata for unlisted modules.
	WalkDepthShallow WalkDepth = "shallow"
)

// WalkRecord is the persisted, tamper-evident representation of a completed
// Walk. It is an aggregate root: once written it is immutable.
//
// Serialisation invariants (enforced by WalkRecordHasher):
// - JSON keys are sorted lexicographically at every level.
// - PerNodeResults is serialised as a sorted array of (coordinate, result) pairs.
// - Times are formatted as RFC3339 in UTC with nanosecond precision zeroed.
// - ContentHash is computed over the canonical JSON with ContentHash zeroed,
// preventing circular self-reference.
// - SchemaVersion is always present.
type WalkRecord struct {
	SchemaVersion string                       `json:"schema_version"`
	Ecosystem     string                       `json:"ecosystem"`
	ID            string                       `json:"id"`
	Target        fetchdomain.ModuleCoordinate `json:"target"`
	Scope         WalkScope                    `json:"scope"`
	// Depth is omitted from JSON when WalkDepthFull so existing records remain valid.
	Depth           WalkDepth                                   `json:"depth,omitempty"`
	Graph           Graph                                       `json:"graph"`
	PerNodeResults  map[fetchdomain.ModuleCoordinate]NodeResult `json:"per_node_results"`
	StartedAt       time.Time                                   `json:"started_at"`
	CompletedAt     time.Time                                   `json:"completed_at"`
	OverallStatus   WalkStatus                                  `json:"overall_status"`
	PipelineVersion string                                      `json:"pipeline_version"`
	PolicyVersion   string                                      `json:"policy_version"`
	PolicyHash      string                                      `json:"policy_hash"`
	StageDepths     map[string]StageDepth                       `json:"stage_depths"`
	Operator        string                                      `json:"operator"`
	ContentHash     string                                      `json:"content_hash"`
}

// NewWalkRecord constructs a WalkRecord from a WalkOutcome. ContentHash is
// left empty; call WalkRecordHasher.SetContentHash to populate it.
func NewWalkRecord(id, operator, pipelineVersion string, scope WalkScope, depth WalkDepth, outcome WalkOutcome, policy DepthPolicy, policyHash string) WalkRecord {
	if scope == "" {
		scope = WalkScopeCode
	}
	if depth == "" {
		depth = WalkDepthFull
	}
	return WalkRecord{
		SchemaVersion:   WalkSchemaVersion,
		Ecosystem:       fetchdomain.EcosystemGo,
		ID:              id,
		Target:          outcome.Target,
		Scope:           scope,
		Depth:           depth,
		Graph:           outcome.Graph,
		PerNodeResults:  outcome.PerNodeResults,
		StartedAt:       outcome.StartedAt.UTC().Truncate(0),
		CompletedAt:     outcome.CompletedAt.UTC().Truncate(0),
		OverallStatus:   outcome.OverallStatus,
		PipelineVersion: pipelineVersion,
		PolicyVersion:   policy.Version,
		PolicyHash:      policyHash,
		StageDepths:     policy.Stages,
		Operator:        operator,
	}
}
