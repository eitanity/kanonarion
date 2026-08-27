package domain

import (
	"math"
	"sort"
)

// This file holds the one canonical ordering per collection in a LicenseRecord.
//
// Every one of them used to be keyed on a single field: files on Path,
// alternative matches on Confidence, copyright statements on Verbatim. None of
// those identifies its element. Two detector candidates at equal coverage carry
// equal Confidence — a float the detector reports in coarse steps, so this ties
// routinely rather than rarely — and one licence file repeats a copyright line
// as often as its authors did. On a tie the comparator gave no answer and
// sort.Slice, which is not stable, put the pair in whatever order the input
// happened to produce. The sealed bytes moved with it.
//
// Each comparator is keyed on every field the canonical wire shape carries, so
// no two distinct elements compare equal and the order is a function of the set
// alone. sort.SliceStable is not the alternative: the input order comes from an
// archive walk and from map iteration, so it is not a property of the module.

// AltMatchLess is the canonical ordering for AltMatch slices: highest
// confidence first, as the record documents, then the identifier. SPDX is the
// tiebreak that makes it total — the detector cannot report one identifier
// twice for one file, so two alternatives always differ here.
func AltMatchLess(a, b AltMatch) bool {
	if result, decided := confidenceDesc(a.Confidence, b.Confidence); decided {
		return result
	}
	return a.SPDX < b.SPDX
}

// CopyrightStatementLess is the canonical ordering for CopyrightStatement
// slices. Verbatim leads, as the record documents; the parsed fields follow so
// that two statements holding one line of text still order by what was read out
// of them.
func CopyrightStatementLess(a, b CopyrightStatement) bool {
	if a.Verbatim != b.Verbatim {
		return a.Verbatim < b.Verbatim
	}
	if a.Source != b.Source {
		return a.Source < b.Source
	}
	if a.Years != b.Years {
		return a.Years < b.Years
	}
	result, _ := sliceLess(a.Holders, b.Holders, stringLess)
	return result
}

// LicenseFileEntryLess is the canonical ordering for the record's LicenseFiles.
// Path leads, as the record documents, and the remaining wire fields follow it
// down to the entry's own two lists. Sort those lists first.
func LicenseFileEntryLess(a, b LicenseFileEntry) bool {
	if a.Path != b.Path {
		return a.Path < b.Path
	}
	if a.SPDX != b.SPDX {
		return a.SPDX < b.SPDX
	}
	if result, decided := confidenceAsc(a.Confidence, b.Confidence); decided {
		return result
	}
	if a.FileHash != b.FileHash {
		return a.FileHash < b.FileHash
	}
	if a.FileSize != b.FileSize {
		return a.FileSize < b.FileSize
	}
	if a.IsVendored != b.IsVendored {
		return !a.IsVendored
	}
	if a.IsPerFile != b.IsPerFile {
		return !a.IsPerFile
	}
	if a.LowConfidenceSPDX != b.LowConfidenceSPDX {
		return a.LowConfidenceSPDX < b.LowConfidenceSPDX
	}
	if result, decided := confidenceAsc(a.LowConfidenceCoverage, b.LowConfidenceCoverage); decided {
		return result
	}
	if result, decided := sliceLess(a.AltMatches, b.AltMatches, AltMatchLess); decided {
		return result
	}
	result, _ := sliceLess(a.CopyrightStatements, b.CopyrightStatements, CopyrightStatementLess)
	return result
}

// RootCandidateLess orders the root-level licence files an expression is
// derived from: highest confidence first, then path, then identifier. The
// order decides which file becomes the primary licence, so a tie here would
// make the record's Expression and PrimarySPDX depend on the archive walk.
func RootCandidateLess(a, b LicenseFileEntry) bool {
	if result, decided := confidenceDesc(a.Confidence, b.Confidence); decided {
		return result
	}
	if a.Path != b.Path {
		return a.Path < b.Path
	}
	return a.SPDX < b.SPDX
}

// confidenceAsc and confidenceDesc order two confidences, reporting whether
// they decided anything. NaN is ordered after every number in both directions:
// a detector that emitted one would otherwise make the comparator answer "not
// less" for a pair in both directions while claiming to have decided, which is
// not a strict weak ordering and which sort.Slice is entitled to do anything
// with.
func confidenceAsc(a, b float64) (result, decided bool) {
	switch {
	case math.IsNaN(a) && math.IsNaN(b):
		return false, false
	case math.IsNaN(a):
		return false, true
	case math.IsNaN(b):
		return true, true
	case a != b:
		return a < b, true
	}
	return false, false
}

func confidenceDesc(a, b float64) (result, decided bool) {
	switch {
	case math.IsNaN(a) && math.IsNaN(b):
		return false, false
	case math.IsNaN(a):
		return false, true
	case math.IsNaN(b):
		return true, true
	case a != b:
		return a > b, true
	}
	return false, false
}

// stringLess adapts string ordering to the generic slice comparator.
func stringLess(a, b string) bool { return a < b }

// sliceLess orders two slices of already-canonically-ordered elements,
// shorter-first, then element by element. decided is false when the two slices
// hold equal elements throughout, which lets a caller fall through to its next
// key rather than reading "not less" as "less-or-equal".
func sliceLess[T any](a, b []T, less func(x, y T) bool) (result, decided bool) {
	if len(a) != len(b) {
		return len(a) < len(b), true
	}
	for i := range a {
		switch {
		case less(a[i], b[i]):
			return true, true
		case less(b[i], a[i]):
			return false, true
		}
	}
	return false, false
}

// sortSlice orders a slice through one of the named comparators above.
func sortSlice[T any](s []T, less func(a, b T) bool) {
	sort.Slice(s, func(i, j int) bool { return less(s[i], s[j]) })
}

// sortLicenseFiles puts a licence-file list into canonical order, each entry's
// own lists first: a comparator that descends into a nested collection is only
// comparing like with like once that collection is itself sorted.
func sortLicenseFiles(files []LicenseFileEntry) {
	for i := range files {
		f := &files[i]
		sortSlice(f.AltMatches, AltMatchLess)
		sortSlice(f.CopyrightStatements, CopyrightStatementLess)
	}
	sortSlice(files, LicenseFileEntryLess)
}
