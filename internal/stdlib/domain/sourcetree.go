package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"strings"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// SourceManifest builds a deterministic content manifest of a standard-library
// source tree (the fs.FS rooted at $GOROOT/src). Every regular file is hashed
// with SHA-256 and rendered as one "<sha256hex>  <path>\n" line, sorted by path,
// in the same shape a SHA256SUMS file takes. The manifest is a stable,
// content-addressed serialisation of the tree: identical source bytes always
// yield identical manifest bytes, independent of file order, mtimes or modes.
//
// It is NOT a byte-for-byte reproduction of go.dev/dl's src.tar.gz — the offline
// path never downloads that tarball — so the digests taken over this manifest
// anchor to the local toolchain's source content, not to the published tarball.
func SourceManifest(fsys fs.FS) ([]byte, error) {
	var lines []string
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !d.Type().IsRegular() {
			return nil
		}
		sum, herr := hashFile(fsys, path)
		if herr != nil {
			return herr
		}
		lines = append(lines, sum+"  "+path+"\n")
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking stdlib source tree: %w", err)
	}
	sort.Strings(lines)
	return []byte(strings.Join(lines, "")), nil
}

// ComputeSourceDigests returns the artefact digests over the canonical
// SourceManifest of fsys, so the local stdlib source populates GraphNode.Digests
// with the same three SHA-2 algorithms every other node carries.
func ComputeSourceDigests(fsys fs.FS) (fetchdomain.ArtifactDigests, error) {
	manifest, err := SourceManifest(fsys)
	if err != nil {
		return fetchdomain.ArtifactDigests{}, err
	}
	return fetchdomain.ComputeArtifactDigests(manifest), nil
}

// hashFile returns the lowercase hex SHA-256 of a single file's contents.
func hashFile(fsys fs.FS, path string) (string, error) {
	f, err := fsys.Open(path)
	if err != nil {
		return "", fmt.Errorf("opening %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hashing %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
