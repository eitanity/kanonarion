package domain

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sort"
)

// Snapshot is a frozen, coherent view of a local Go workspace's source files.
// It captures the contents of every.go, go.mod, and go.sum file at a single
// point in time. Once created, a Snapshot is immutable.
//
// The Files map uses absolute file paths as keys and is safe for direct use
// as golang.org/x/tools/go/packages.Config.Overlay, ensuring that the Go
// parser operates on the frozen memory map rather than physical disk reads.
type Snapshot struct {
	// Files maps absolute file paths to their byte contents.
	Files map[string][]byte
	// VersionID is a deterministic pseudo-version derived from the snapshot
	// contents. Format: "local-<64-char-sha256-hex>". It can be used as a
	// cache key or for change detection between snapshots.
	VersionID string
}

// NewSnapshot constructs a Snapshot from a map of absolute file paths to
// contents. A deterministic VersionID is computed from the map. The files map
// is not copied; callers must not modify it after passing it here.
func NewSnapshot(files map[string][]byte) Snapshot {
	return Snapshot{
		Files:     files,
		VersionID: computeVersionID(files),
	}
}

// computeVersionID hashes all file paths and their contents in sorted key
// order, producing a deterministic "local-<sha256>" identifier.
// Length-prefixed encoding prevents ambiguity between path and content bytes.
func computeVersionID(files map[string][]byte) string {
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	h := sha256.New()
	var buf [8]byte
	for _, p := range paths {
		binary.BigEndian.PutUint64(buf[:], uint64(len(p)))
		h.Write(buf[:])
		h.Write([]byte(p))
		content := files[p]
		binary.BigEndian.PutUint64(buf[:], uint64(len(content)))
		h.Write(buf[:])
		h.Write(content)
	}
	return "local-" + hex.EncodeToString(h.Sum(nil))
}
