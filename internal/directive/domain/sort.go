package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Sort orders directives deterministically: by source, then line, then kind,
// then old path/version. Output must be stable before hashing/serialising
// (determinism rule).
func Sort(ds []Directive) {
	sort.SliceStable(ds, func(i, j int) bool {
		a, b := ds[i], ds[j]
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.OldPath != b.OldPath {
			return a.OldPath < b.OldPath
		}
		return a.OldVersion < b.OldVersion
	})
}

// Hash returns a deterministic content hash of the sorted directive set. The
// caller must Sort first; Hash does not re-sort so the hash reflects exactly
// what is serialised.
func Hash(ds []Directive) string {
	var b strings.Builder
	for _, d := range ds {
		fmt.Fprintf(&b, "%s|%s|%d|%s|%s|%t|%s|%s|%s|%t|%s\n",
			d.Kind, d.Source, d.Line, d.OldPath, d.OldVersion,
			d.IsLocal, d.LocalPath, d.NewPath, d.NewVersion,
			d.Applied, d.Class)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return "sha256:" + hex.EncodeToString(sum[:])
}
