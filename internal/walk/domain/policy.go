package domain

// PolicySchemaVersion is the version of the DepthPolicy YAML schema.
// Bump when the serialisation format changes in a backwards-incompatible way.
const PolicySchemaVersion = "1"

// DepthPolicy controls how deep each pipeline stage traverses the dependency
// graph and which edge types it follows.
//
// Version is the schema version string stored in the YAML source and recorded
// in every WalkRecord that applies this policy. Stages is keyed by stage name
// (e.g. "fetch", "license"); each stage has its own traversal parameters.
//
// Policy is organisational and versioned; it is loaded once at invocation time
// and snapshotted into the WalkRecord. Per-invocation transient parameters
// (Force, WorkerCount) live in WalkRequest instead.
type DepthPolicy struct {
	Version string
	Stages  map[string]StageDepth
}

// StageDepth holds the traversal parameters for a single pipeline stage.
type StageDepth struct {
	// MaxDepth is the maximum number of hops from the target to traverse.
	// 0 means unlimited.
	MaxDepth int
	// FollowReplace controls whether replace directives in the target's go.mod
	// are applied during graph resolution. When false, the original (unreplaced)
	// coordinate is used.
	FollowReplace bool
	// FollowTest controls whether test-only dependencies are included.
	// The flag is part of the persisted policy schema, but go.mod does not
	// carry an explicit test-only marker today, so it currently has no effect
	// at resolution time. It is kept in the schema so policies authored
	// against future test-only signals remain forward-compatible.
	FollowTest bool
	// FollowIndirect controls whether requirements marked // indirect in go.mod
	// are followed. When false, indirect requirements are skipped at every level.
	FollowIndirect bool
}

// DefaultDepthPolicy returns the built-in policy used when no policy file is
// found. It follows all dependencies without depth limit, applies replace
// directives, and follows indirect requirements. Test-only filtering is off.
func DefaultDepthPolicy() DepthPolicy {
	return DepthPolicy{
		Version: PolicySchemaVersion,
		Stages: map[string]StageDepth{
			"fetch": {
				MaxDepth:       0,
				FollowReplace:  true,
				FollowTest:     false,
				FollowIndirect: true,
			},
			"license": {
				MaxDepth:       0,
				FollowReplace:  true,
				FollowTest:     false,
				FollowIndirect: true,
			},
			"interface": {
				MaxDepth:       0,
				FollowReplace:  true,
				FollowTest:     false,
				FollowIndirect: true,
			},
			"callgraph": {
				MaxDepth:       1,
				FollowReplace:  true,
				FollowTest:     false,
				FollowIndirect: true,
			},
			"example": {
				MaxDepth:       1,
				FollowReplace:  true,
				FollowTest:     false,
				FollowIndirect: true,
			},
		},
	}
}

// FetchStage returns the StageDepth for the "fetch" stage, falling back to the
// default fetch stage if the policy does not define one.
func (p DepthPolicy) FetchStage() StageDepth {
	if sd, ok := p.Stages["fetch"]; ok {
		return sd
	}
	return DefaultDepthPolicy().Stages["fetch"]
}
