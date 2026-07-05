package domain

import "fmt"

// GitReference identifies a specific commit in a VCS repository.
type GitReference struct {
	// URL is the canonical clone URL of the repository.
	URL string
	// Ref is the tag or branch ref, e.g. "refs/tags/v1.8.1".
	// Empty for pseudo-versions where only the commit hash is known.
	Ref string
	// CommitHash is the full 40-character hex SHA-1 commit hash.
	CommitHash string
}

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
