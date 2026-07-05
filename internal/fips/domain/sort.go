package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// kindRank orders FindingKind for stable sorting so a toolchain finding —
// the headline fact of an assessment — always leads, followed by algorithm
// imports, then direct-random surface facts, then cgo-crypto uncertainty.
func kindRank(k FindingKind) int {
	switch k {
	case FindingToolchain:
		return 0
	case FindingAlgorithm:
		return 1
	case FindingDirectRandom:
		return 2
	case FindingCgoCrypto:
		return 3
	default:
		return 4
	}
}

// Sort orders findings deterministically: by kind (rank), then source,
// then line, then package, then module. Output must be stable before
// hashing/serialising (determinism rule).
func Sort(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if ka, kb := kindRank(a.Kind), kindRank(b.Kind); ka != kb {
			return ka < kb
		}
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Package != b.Package {
			return a.Package < b.Package
		}
		return a.Module < b.Module
	})
}

// Hash returns a deterministic content hash of the sorted finding set
// folded with the toolchain capability headline. The caller must Sort
// first; Hash does not re-sort so the hash reflects exactly what is
// serialised.
func Hash(toolchainCapable bool, toolchainVariant, toolchainRaw string, fs []Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "TC|%t|%s|%s\n", toolchainCapable, toolchainVariant, toolchainRaw)
	for _, f := range fs {
		fmt.Fprintf(&b, "%s|%s|%s|%s|%d|%s|%s|%s\n",
			f.Kind, f.Package, f.Module, f.Source, f.Line,
			f.Toolchain, f.ToolchainRaw, f.Category)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return "sha256:" + hex.EncodeToString(sum[:])
}
