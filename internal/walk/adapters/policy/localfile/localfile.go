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
		stages[name] = walkdomain.StageDepth{
			MaxDepth:       sd.MaxDepth,
			FollowReplace:  sd.FollowReplace,
			FollowTest:     sd.FollowTest,
			FollowIndirect: sd.FollowIndirect,
		}
	}

	return walkdomain.DepthPolicy{
		Version: y.Version,
		Stages:  stages,
	}, nil
}
