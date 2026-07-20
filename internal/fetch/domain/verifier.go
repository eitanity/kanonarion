package domain

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"golang.org/x/mod/module"
	modzip "golang.org/x/mod/zip"
)

// ModuleZipHasher computes the dirhash h1 of a module ZIP. It is implemented by
// the shared ziparchive adapter and injected into Verifier so the domain holds
// no archive/zip dependency — only the pure verification rule.
type ModuleZipHasher interface {
	HashModuleZip(data []byte) (string, error)
}

// Verifier is a domain service for cross-checking module artefacts.
// Its rules are pure: no persistent I/O, no network access. Archive parsing is
// delegated to the injected ModuleZipHasher.
type Verifier struct {
	hasher ModuleZipHasher
}

// NewVerifier constructs a Verifier backed by hasher.
func NewVerifier(hasher ModuleZipHasher) Verifier {
	return Verifier{hasher: hasher}
}

// HashDirAsModuleZip builds a module zip from dir using the standard
// golang.org/x/mod/zip rules (excludes vendor/, nested modules, symlinks,
// etc.) and returns its h1 hash. This matches what the proxy/sumdb hash
// covers, unlike dirhash.HashDir which hashes every file in the tree.
func (v Verifier) HashDirAsModuleZip(dir string, coord coordinate.ModuleCoordinate) (ModuleHash, error) {
	var buf bytes.Buffer
	mv := module.Version{Path: coord.Path, Version: coord.Version}
	if err := modzip.CreateFromDir(&buf, mv, dir); err != nil {
		return ModuleHash{}, fmt.Errorf("creating module zip from checkout: %w", err)
	}
	h, err := v.hasher.HashModuleZip(buf.Bytes())
	if err != nil {
		return ModuleHash{}, fmt.Errorf("hashing checkout zip: %w", err)
	}
	return ParseModuleHash(h)
}

// VerifyPseudoVersionCommit checks that a pseudo-version's embedded commit
// prefix matches the first 12 chars of the resolved commit hash.
func (Verifier) VerifyPseudoVersionCommit(coord coordinate.ModuleCoordinate, commitHash string) error {
	prefix, err := coord.ExtractCommitPrefix()
	if err != nil {
		return fmt.Errorf("extracting commit prefix: %w", err)
	}
	if len(commitHash) < 12 {
		return fmt.Errorf("commit hash too short: %q", commitHash)
	}
	actual := strings.ToLower(commitHash[:12])
	expected := strings.ToLower(prefix)
	if actual != expected {
		return fmt.Errorf("pseudo-version commit prefix %q does not match resolved commit %q", expected, actual)
	}
	return nil
}
