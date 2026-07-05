package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Sort orders settings deterministically: by source, then line, then name,
// then value. Output must be stable before hashing/serialising (/
// determinism rule).
func Sort(ss []Setting) {
	sort.SliceStable(ss, func(i, j int) bool {
		a, b := ss[i], ss[j]
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Value < b.Value
	})
}

// Hash returns a deterministic content hash of the sorted setting set. The
// caller must Sort first; Hash does not re-sort so the hash reflects exactly
// what is serialised.
func Hash(ss []Setting) string {
	var b strings.Builder
	for _, s := range ss {
		fmt.Fprintf(&b, "%s|%s|%s|%d|%s|%t|%s\n",
			s.Name, s.Value, s.Source, s.Line, s.Module,
			s.Applied, s.Tier)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return "sha256:" + hex.EncodeToString(sum[:])
}
