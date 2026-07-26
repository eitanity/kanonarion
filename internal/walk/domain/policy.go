package domain

import (
	"fmt"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

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
	// AllowedVCSHosts overrides the built-in VCS forge allowlist used when a
	// module's repository is cross-verified against its proxy zip. It is
	// meaningful on the fetch stage, where that verification runs.
	//
	// Unlike the bool fields above, this one keys on FIELD PRESENCE rather than
	// its zero value, hence the pointer: nil means the field was absent from the
	// policy and the built-in default applies. Zero-value-on-omit is fine for a
	// traversal toggle, but for a security trust list it is a footgun — an
	// operator who sets only max_depth under fetch would otherwise empty the
	// host list and silently push every module to checksum-DB-only verification.
	//
	// A present list replaces the default wholesale (it does not merge). A
	// present but empty list is a load error: "trust no forge" is not a value of
	// this field, it is the orthogonal --skip-vcs-verify flag.
	//
	// The json tag is omitempty so `kanonarion policy show` renders a policy
	// that does not override the allowlist exactly as it did before this field
	// existed; the resolved set is reported separately as effective_vcs_hosts.
	AllowedVCSHosts *[]string `json:"AllowedVCSHosts,omitempty"`
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

// VCSHostAllowlist resolves the stage's effective VCS forge allowlist: the
// built-in default when the field is absent, the configured set when present.
//
// The returned allowlist is never empty. An error means the policy carries an
// unusable list (empty, or an entry that is not a bare lowercased hostname) —
// the caller must fail rather than fall back, because falling back would widen
// or narrow the operator's declared trust without saying so.
func (s StageDepth) VCSHostAllowlist() (fetchdomain.VCSHostAllowlist, error) {
	if s.AllowedVCSHosts == nil {
		return fetchdomain.DefaultVCSHostAllowlist(), nil
	}
	allowlist, err := fetchdomain.NewVCSHostAllowlist(*s.AllowedVCSHosts)
	if err != nil {
		return fetchdomain.VCSHostAllowlist{}, fmt.Errorf("resolving allowed_vcs_hosts: %w", err)
	}
	return allowlist, nil
}
