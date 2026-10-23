package domain

import (
	"encoding/json"
	"fmt"
)

// GitReference identifies a specific commit in a VCS repository.
type GitReference struct {
	// URL is the canonical clone URL of the repository.
	URL string
	// Ref is the tag or branch ref, e.g. "refs/tags/v1.8.1".
	// Empty for pseudo-versions where only the commit hash is known.
	Ref string
	// CommitHash is the full 40-character hex SHA-1 commit hash.
	CommitHash string
	// Subdir is the directory, relative to the repository root and
	// slash-separated, whose tree the VCS leg hashed: RepoRoot for the root,
	// empty when nothing was hashed.
	Subdir string
}

// RepoRoot is the Subdir of a module hashed at the repository root, so that
// root is never confused with "no directory recorded".
const RepoRoot = "."

// RepoSubdir is a recorded Subdir. Its JSON form is null when the record names
// no directory: no leg hashed one, or the record predates the field.
type RepoSubdir string

// MarshalJSON renders an empty RepoSubdir as null.
func (d RepoSubdir) MarshalJSON() ([]byte, error) {
	if d == "" {
		return []byte("null"), nil
	}
	b, err := marshalJSONString(string(d))
	if err != nil {
		return nil, fmt.Errorf("marshalling git_subdir: %w", err)
	}
	return b, nil
}

// marshalJSONString is a seam over json.Marshal: a string cannot fail to
// marshal, so the error branches it feeds are reachable only through it.
var marshalJSONString = func(s string) ([]byte, error) { return json.Marshal(s) }

// ShortHash returns the first 12 characters of CommitHash, matching the
// commit prefix embedded in pseudo-versions.
func (r GitReference) ShortHash() string {
	if len(r.CommitHash) < 12 {
		return r.CommitHash
	}
	return r.CommitHash[:12]
}

// Validate checks that the GitReference has the required fields.
func (r GitReference) Validate() error {
	if r.URL == "" {
		return fmt.Errorf("git reference URL must not be empty")
	}
	if len(r.CommitHash) != 40 {
		return fmt.Errorf("git commit hash must be 40 hex chars, got %d", len(r.CommitHash))
	}
	return nil
}
