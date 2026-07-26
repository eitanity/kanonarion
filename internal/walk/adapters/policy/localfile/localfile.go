// Package localfile implements PolicyStore by reading a YAML policy file from disk.
//
// The YAML schema is versioned. The current supported schema version is "1".
// Unknown stage names are accepted and ignored for forward compatibility.
// A schema version ahead of the supported version is a fatal error; behind is
// accepted with a best-effort migration (unknown fields are zero-valued).
package localfile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
	"gopkg.in/yaml.v3"
)

// SupportedSchemaVersion is the policy schema version this adapter can parse.
const SupportedSchemaVersion = walkdomain.PolicySchemaVersion

// PolicyStore loads a DepthPolicy from a YAML file at a fixed path.
type PolicyStore struct {
	path string
}

// New returns a PolicyStore that loads from path.
func New(path string) *PolicyStore {
	return &PolicyStore{path: path}
}

// LoadPolicy reads and parses the YAML file at the configured path.
// Returns ErrPolicyNotFound (unwrappable via errors.Is) when the file does
// not exist — callers may then fall back to defaults.
func (s *PolicyStore) LoadPolicy(_ context.Context) (walkports.PolicyLoadResult, error) {
	data, err := os.ReadFile(s.path) //nolint:gosec // operator-supplied path is intentional
	if err != nil {
		if os.IsNotExist(err) {
			return walkports.PolicyLoadResult{}, fmt.Errorf("%w: %s", ErrPolicyNotFound, s.path)
		}
		return walkports.PolicyLoadResult{}, fmt.Errorf("reading policy file %s: %w", s.path, err)
	}

	policy, err := Parse(data)
	if err != nil {
		return walkports.PolicyLoadResult{}, fmt.Errorf("parsing policy file %s: %w", s.path, err)
	}

	sum := sha256.Sum256(data)
	hash := "sha256:" + hex.EncodeToString(sum[:])

	return walkports.PolicyLoadResult{
		Policy:      policy,
		ContentHash: hash,
		Source:      s.path,
	}, nil
}

// ErrPolicyNotFound is returned by LoadPolicy when the policy file does not exist.
var ErrPolicyNotFound = fmt.Errorf("policy file not found")

// policyYAML is the YAML wire format for a DepthPolicy.
type policyYAML struct {
	Version string                    `yaml:"version"`
	Stages  map[string]stageDepthYAML `yaml:"stages"`
}

type stageDepthYAML struct {
	MaxDepth       int  `yaml:"max_depth"`
	FollowReplace  bool `yaml:"follow_replace"`
	FollowTest     bool `yaml:"follow_test"`
	FollowIndirect bool `yaml:"follow_indirect"`
	// AllowedVCSHosts is a pointer so an absent key (nil) is distinguishable
	// from an empty list. Absent means "use the built-in allowlist"; empty is
	// rejected below. The bool fields above cannot make that distinction, which
	// is safe for traversal toggles and unsafe for a trust list.
	AllowedVCSHosts *[]string `yaml:"allowed_vcs_hosts"`
}

// Parse parses YAML policy bytes into a DepthPolicy. It is exported so that
// callers can validate policy content without a filesystem path.
func Parse(data []byte) (walkdomain.DepthPolicy, error) {
	var y policyYAML
	if err := yaml.Unmarshal(data, &y); err != nil {
		return walkdomain.DepthPolicy{}, fmt.Errorf("invalid YAML: %w", err)
	}

	if y.Version == "" {
		return walkdomain.DepthPolicy{}, fmt.Errorf("missing required field: version")
	}
	if y.Version > SupportedSchemaVersion {
		return walkdomain.DepthPolicy{}, fmt.Errorf(
			"policy schema version %q is newer than supported %q; upgrade kanonarion to use this policy",
			y.Version, SupportedSchemaVersion,
		)
	}
	// y.Version < SupportedSchemaVersion: accept; unknown fields are zero-valued.

	stages := make(map[string]walkdomain.StageDepth, len(y.Stages))
	for name, sd := range y.Stages {
		hosts, err := parseAllowedVCSHosts(name, sd.AllowedVCSHosts)
		if err != nil {
			return walkdomain.DepthPolicy{}, err
		}
		stages[name] = walkdomain.StageDepth{
			MaxDepth:        sd.MaxDepth,
			FollowReplace:   sd.FollowReplace,
			FollowTest:      sd.FollowTest,
			FollowIndirect:  sd.FollowIndirect,
			AllowedVCSHosts: hosts,
		}
	}

	return walkdomain.DepthPolicy{
		Version: y.Version,
		Stages:  stages,
	}, nil
}

// vcsVerifyingStage is the only stage that performs VCS cross-verification, and
// so the only stage on which allowed_vcs_hosts means anything.
const vcsVerifyingStage = "fetch"

// parseAllowedVCSHosts validates the allowed_vcs_hosts field of one stage.
// It fails closed at load time — a typo'd or malformed entry is rejected naming
// the entry, never silently dropped, because a silently narrowed trust list
// degrades the affected modules to checksum-DB-only verification without any
// signal. An absent field (nil) passes through as nil: the built-in allowlist
// applies.
//
// The field is also rejected on any stage other than fetch. Only the fetch
// stage cross-verifies against a repository, so the key elsewhere is an
// authoring mistake that would otherwise load cleanly and do nothing — an
// operator would read their policy as narrowing trust while every forge stayed
// trusted. That is precisely the silent-weakening failure this field exists to
// prevent, so a misplaced key is an error rather than a no-op. Unknown stage
// NAMES remain accepted for forward compatibility; it is the misplaced trust
// list, not the unknown stage, that is refused.
func parseAllowedVCSHosts(stage string, hosts *[]string) (*[]string, error) {
	if hosts == nil {
		return nil, nil
	}
	if stage != vcsVerifyingStage {
		return nil, fmt.Errorf(
			"stage %q: allowed_vcs_hosts is only meaningful on the %q stage, which is where VCS "+
				"cross-verification runs; move it there (a list here would load cleanly and change nothing)",
			stage, vcsVerifyingStage)
	}
	// Building the allowlist is the validation: it rejects an empty list naming
	// --skip-vcs-verify, and every entry that is not a bare lowercased hostname.
	if _, err := fetchdomain.NewVCSHostAllowlist(*hosts); err != nil {
		return nil, fmt.Errorf("stage %q: allowed_vcs_hosts: %w", stage, err)
	}
	out := make([]string, len(*hosts))
	copy(out, *hosts)
	return &out, nil
}
