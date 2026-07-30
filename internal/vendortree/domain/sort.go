package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// SortModules orders modules by path then version (determinism).
func SortModules(ms []VendoredModule) {
	sort.SliceStable(ms, func(i, j int) bool {
		if ms[i].Path != ms[j].Path {
			return ms[i].Path < ms[j].Path
		}
		return ms[i].Version < ms[j].Version
	})
}

// SortFindings orders findings by module, then kind, then version, then file so
// output is stable before hashing/serialising. The file is part of the order
// because the drift axis emits one finding per file, so module/kind/version
// alone no longer identifies a finding.
func SortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Module != b.Module {
			return a.Module < b.Module
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		return a.File < b.File
	})
}

// Hash returns a deterministic content hash over the sorted module and
// finding sets. The caller must sort first; Hash does not re-sort so the hash
// reflects exactly what is serialised.
func Hash(ms []VendoredModule, fs []Finding) string {
	var b strings.Builder
	for _, m := range ms {
		fmt.Fprintf(&b, "M|%s|%s|%t|%t|%s\n",
			m.Path, m.Version, m.Explicit, m.Present, m.ExpectedHash)
	}
	for _, f := range fs {
		fmt.Fprintf(&b, "F|%s|%s|%s|%s|%s|%s\n",
			f.Kind, f.Module, f.Version, f.File, f.Expected, f.Actual)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return "sha256:" + hex.EncodeToString(sum[:])
}
