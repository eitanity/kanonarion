package domain

import (
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

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
	SchemaVersion string                      `json:"schema_version"`
	Ecosystem     string                      `json:"ecosystem"`
	ID            string                      `json:"id"`
	Target        coordinate.ModuleCoordinate `json:"target"`
	Scope         WalkScope                   `json:"scope"`
	// Depth is omitted from JSON when WalkDepthFull so existing records remain valid.
	Depth           WalkDepth                                  `json:"depth,omitempty"`
	Graph           Graph                                      `json:"graph"`
	PerNodeResults  map[coordinate.ModuleCoordinate]NodeResult `json:"per_node_results"`
	StartedAt       time.Time                                  `json:"started_at"`
	CompletedAt     time.Time                                  `json:"completed_at"`
	OverallStatus   WalkStatus                                 `json:"overall_status"`
	PipelineVersion string                                     `json:"pipeline_version"`
	PolicyVersion   string                                     `json:"policy_version"`
	PolicyHash      string                                     `json:"policy_hash"`
	StageDepths     map[string]StageDepth                      `json:"stage_depths"`
	Operator        string                                     `json:"operator"`
	ContentHash     string                                     `json:"content_hash"`
	// ProjectDir is the working-tree directory the walk was rooted at: the
	// directory holding the main module's go.mod. It is set on a walk of a local
	// project (--gomod, --tool, --project, and the local driver's analysed
	// walks) and empty on a walk of a published coordinate, which has no project
	// root. The empty value is that distinction, not a gap.
	//
	// It exists so a re-scan by walk id can reach the same analysis surface the
	// original run did: a project carrying vendor/modules.txt is analysed from
	// the vendored tree, and without the directory a stored walk could only ever
	// be re-analysed from fetched artefacts — one walk answering differently
	// depending on which spelling of the command asked.
	//
	// It is provenance, NOT identity, and is deliberately OUTSIDE the content
	// hash: it is absent from canonicalWalkRecord, so it neither joins the seal
	// nor survives Marshal/Unmarshal. Two walks that differ only by where on a
	// machine they were taken from are the same walk, and a machine-local path
	// in the hash would make them different ones — permanently, for every record
	// that ever names a walk hash. The store carries it in its own column
	// beside the sealed blob, which is what a fact that is true of the run but
	// not of the walk deserves.
	//
	// Being provenance, it is never an oracle: a reader that finds the directory
	// gone must degrade to what it can measure without it, never fail.
	ProjectDir string `json:"project_dir,omitempty"`

	// IdentityHash names the ANALYSIS this walk performed, as opposed to
	// ContentHash which seals the RECORD. Two runs of an unchanged checkout
	// resolve the same module set under the same parameters and share an
	// identity hash; they do not — and must not — share a content hash, because
	// they happened at different times under different ids and the seal covers
	// exactly that. See canonicalWalkIdentity for the full membership.
	//
	// Like ProjectDir it lives OUTSIDE the content hash and outside the
	// serialised blob, in its own store column: it is derived from the record,
	// so admitting it to the seal would make the seal cover a function of
	// itself, and every walk written before the field existed would stop
	// verifying. A reader that distrusts a stored identity recomputes it from
	// the record it came with — that is the only check it needs, and it costs a
	// hash.
	//
	// Empty means the walk was written before identities were recorded. That is
	// an absent name, not a matching one: a lookup keyed on identity must never
	// treat the empty string as a hit.
	IdentityHash string `json:"-"`
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
