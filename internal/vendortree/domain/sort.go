package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// VendoredModuleLess is the canonical ordering for VendoredModule slices: the
// coordinate first, then everything the reconciliation measured about it.
//
// Path and version alone are not an identity here. A vendor tree can present one
// coordinate twice — once as itself and once as the target of a replace — and
// the two entries then differ in the replacement coordinate, the package count
// and the files compared, all of which reach Hash. Every field the type carries
// is keyed here, so two distinct entries always have a defined order.
func VendoredModuleLess(a, b VendoredModule) bool {
	if a.Path != b.Path {
		return a.Path < b.Path
	}
	if a.Version != b.Version {
		return a.Version < b.Version
	}
	if a.ReplacementPath != b.ReplacementPath {
		return a.ReplacementPath < b.ReplacementPath
	}
	if a.ReplacementVersion != b.ReplacementVersion {
		return a.ReplacementVersion < b.ReplacementVersion
	}
	if a.ExpectedHash != b.ExpectedHash {
		return a.ExpectedHash < b.ExpectedHash
	}
	if a.PackageCount != b.PackageCount {
		return a.PackageCount < b.PackageCount
	}
	if a.FilesCompared != b.FilesCompared {
		return a.FilesCompared < b.FilesCompared
	}
	if a.Explicit != b.Explicit {
		return !a.Explicit
	}
	if a.Present != b.Present {
		return !a.Present
	}
	return a.Dir < b.Dir
}

// FindingLess is the canonical ordering for Finding slices: the module first,
// because that is what a reader scans the list by, then the kind, the version
// and the file the drift was found in.
//
// The expected and actual values were invisible to the comparator, and both
// reach Hash: two findings of one kind on one file, differing only in what was
// expected against what was found, were left to the sort. Every field the type
// carries is keyed here.
func FindingLess(a, b Finding) bool {
	if a.Module != b.Module {
		return a.Module < b.Module
	}
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	if a.Version != b.Version {
		return a.Version < b.Version
	}
	if a.File != b.File {
		return a.File < b.File
	}
	if a.Expected != b.Expected {
		return a.Expected < b.Expected
	}
	if a.Actual != b.Actual {
		return a.Actual < b.Actual
	}
	if a.Detail != b.Detail {
		return a.Detail < b.Detail
	}
	if a.PolicyOutcome != b.PolicyOutcome {
		return a.PolicyOutcome < b.PolicyOutcome
	}
	if a.PolicyBlocking != b.PolicyBlocking {
		return !a.PolicyBlocking
	}
	return false
}

// SortModules orders modules by VendoredModuleLess, a total order, so the
// result is a function of the set and not of the order the vendor tree was
// walked in.
func SortModules(ms []VendoredModule) {
	sort.Slice(ms, func(i, j int) bool { return VendoredModuleLess(ms[i], ms[j]) })
}

// SortFindings orders findings by FindingLess, a total order, so the result is
// a function of the set and not of the order reconciliation produced it in.
func SortFindings(fs []Finding) {
	sort.Slice(fs, func(i, j int) bool { return FindingLess(fs[i], fs[j]) })
}

// Hash returns a deterministic content hash over the sorted module and
// finding sets. The caller must sort first; Hash does not re-sort so the hash
// reflects exactly what is serialised.
func Hash(ms []VendoredModule, fs []Finding) string {
	var b strings.Builder
	for _, m := range ms {
		// The replacement coordinate and the files-compared count are in the
		// hash because both are facts about the measurement this record IS: a
		// tree re-vendored against a different fork, or a run that compared
		// fewer files, is a different reconciliation and must not hash to the
		// same value as the one before it.
		fmt.Fprintf(&b, "M|%s|%s|%t|%t|%s|%d|%s|%s|%d\n",
			m.Path, m.Version, m.Explicit, m.Present, m.ExpectedHash, m.PackageCount,
			m.ReplacementPath, m.ReplacementVersion, m.FilesCompared)
	}
	for _, f := range fs {
		fmt.Fprintf(&b, "F|%s|%s|%s|%s|%s|%s\n",
			f.Kind, f.Module, f.Version, f.File, f.Expected, f.Actual)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return "sha256:" + hex.EncodeToString(sum[:])
}
