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

// FindingLess is the canonical ordering for Finding slices: the kind's rank
// first, so a toolchain finding leads, then where the finding was read from and
// what it says.
//
// It was keyed on the RANK, source, line, package and module. The rank is not
// the kind — every kind outside the catalogue collapses to rank 4, so two
// findings of different kinds tied — and the toolchain variant, its raw
// spelling and the category were invisible to the comparator. A tie left the
// pair to the sort, and the pair's order reaches both the rendered list and
// Hash. Every field the type carries is keyed here, so two distinct findings
// always have a defined order.
func FindingLess(a, b Finding) bool {
	if ka, kb := kindRank(a.Kind), kindRank(b.Kind); ka != kb {
		return ka < kb
	}
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
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
	if a.Module != b.Module {
		return a.Module < b.Module
	}
	if a.Toolchain != b.Toolchain {
		return a.Toolchain < b.Toolchain
	}
	if a.ToolchainRaw != b.ToolchainRaw {
		return a.ToolchainRaw < b.ToolchainRaw
	}
	if a.Category != b.Category {
		return a.Category < b.Category
	}
	if a.PolicyOutcome != b.PolicyOutcome {
		return a.PolicyOutcome < b.PolicyOutcome
	}
	if a.PolicyBlocking != b.PolicyBlocking {
		return !a.PolicyBlocking
	}
	return false
}

// Sort orders findings by FindingLess. Output must be in a canonical order
// before hashing or serialising, and the comparator is a total order, so the
// result is a function of the set and not of the order the scan produced it in.
func Sort(fs []Finding) {
	sort.Slice(fs, func(i, j int) bool { return FindingLess(fs[i], fs[j]) })
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
