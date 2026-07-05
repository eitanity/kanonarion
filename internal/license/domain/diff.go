package domain

import (
	"slices"
)

// LicenseDiff is the deterministic delta between two LicenseRecords.
// It is produced by DiffRecords — a pure function with no I/O.
type LicenseDiff struct {
	RecordA LicenseRecord
	RecordB LicenseRecord

	// SPDXChanged is non-nil when PrimarySPDX differs between A and B.
	SPDXChanged *SPDXChange
	// StatusChanged is non-nil when OverallStatus differs between A and B.
	StatusChanged *StatusChange
	// FilesAdded contains license files present in B but not in A, sorted by Path.
	FilesAdded []LicenseFileEntry
	// FilesRemoved contains license files present in A but not in B, sorted by Path.
	FilesRemoved []LicenseFileEntry
	// CopyrightAdded contains copyright statements present in B but not in A
	// (deduplicated across files, sorted by Verbatim).
	CopyrightAdded []CopyrightStatement
	// CopyrightRemoved contains copyright statements present in A but not in B
	// (deduplicated across files, sorted by Verbatim).
	CopyrightRemoved []CopyrightStatement
	// Escalation is non-nil when the primary SPDX changed from a permissive
	// license to a stronger copyleft (the Redis/Terraform/HashiCorp pattern).
	Escalation *LicenseEscalation
}

// HasChanges reports whether any aspect of the license record changed.
func (d LicenseDiff) HasChanges() bool {
	return d.SPDXChanged != nil ||
		d.StatusChanged != nil ||
		len(d.FilesAdded) > 0 ||
		len(d.FilesRemoved) > 0 ||
		len(d.CopyrightAdded) > 0 ||
		len(d.CopyrightRemoved) > 0
}

// SPDXChange records a primary SPDX identifier transition.
type SPDXChange struct {
	From string
	To   string
}

// StatusChange records an OverallStatus transition.
type StatusChange struct {
	From LicenseStatus
	To   LicenseStatus
}

// LicenseEscalation records a copyleft-strength escalation in the primary license.
// From is always CopyleftNone (permissive); To is the new strength.
type LicenseEscalation struct {
	From CopyleftStrength
	To   CopyleftStrength
}

// DiffRecords computes the deterministic delta between two LicenseRecords. It
// is a pure function: no I/O, no clock. The output is sorted for determinism.
func DiffRecords(a, b LicenseRecord) LicenseDiff {
	diff := LicenseDiff{RecordA: a, RecordB: b}

	if a.PrimarySPDX != b.PrimarySPDX {
		diff.SPDXChanged = &SPDXChange{From: a.PrimarySPDX, To: b.PrimarySPDX}

		strengthA, okA := CopyleftStrengthOf(a.PrimarySPDX)
		strengthB, okB := CopyleftStrengthOf(b.PrimarySPDX)
		if okA && okB && strengthA == CopyleftNone && strengthB > CopyleftNone {
			diff.Escalation = &LicenseEscalation{From: strengthA, To: strengthB}
		}
	}

	if a.OverallStatus != b.OverallStatus {
		diff.StatusChanged = &StatusChange{From: a.OverallStatus, To: b.OverallStatus}
	}

	diff.FilesAdded, diff.FilesRemoved = diffFiles(a.LicenseFiles, b.LicenseFiles)
	diff.CopyrightAdded, diff.CopyrightRemoved = diffCopyright(a.LicenseFiles, b.LicenseFiles)

	return diff
}

// diffFiles returns (added, removed) license file entries between a and b.
// Identity is the file Path; entries are sorted by Path for determinism.
func diffFiles(filesA, filesB []LicenseFileEntry) (added, removed []LicenseFileEntry) {
	idxA := make(map[string]struct{}, len(filesA))
	idxB := make(map[string]struct{}, len(filesB))
	for _, f := range filesA {
		idxA[f.Path] = struct{}{}
	}
	for _, f := range filesB {
		idxB[f.Path] = struct{}{}
	}

	for _, f := range filesB {
		if _, ok := idxA[f.Path]; !ok {
			added = append(added, f)
		}
	}
	for _, f := range filesA {
		if _, ok := idxB[f.Path]; !ok {
			removed = append(removed, f)
		}
	}

	slices.SortFunc(added, func(x, y LicenseFileEntry) int {
		if x.Path < y.Path {
			return -1
		}
		if x.Path > y.Path {
			return 1
		}
		return 0
	})
	slices.SortFunc(removed, func(x, y LicenseFileEntry) int {
		if x.Path < y.Path {
			return -1
		}
		if x.Path > y.Path {
			return 1
		}
		return 0
	})
	return added, removed
}

// diffCopyright returns (added, removed) copyright statements between a and b.
// Statements are deduplicated across files; result is sorted by Verbatim.
func diffCopyright(filesA, filesB []LicenseFileEntry) (added, removed []CopyrightStatement) {
	setA := collectCopyright(filesA)
	setB := collectCopyright(filesB)

	for v, stmt := range setB {
		if _, ok := setA[v]; !ok {
			added = append(added, stmt)
		}
	}
	for v, stmt := range setA {
		if _, ok := setB[v]; !ok {
			removed = append(removed, stmt)
		}
	}

	slices.SortFunc(added, func(x, y CopyrightStatement) int {
		if x.Verbatim < y.Verbatim {
			return -1
		}
		if x.Verbatim > y.Verbatim {
			return 1
		}
		return 0
	})
	slices.SortFunc(removed, func(x, y CopyrightStatement) int {
		if x.Verbatim < y.Verbatim {
			return -1
		}
		if x.Verbatim > y.Verbatim {
			return 1
		}
		return 0
	})
	return added, removed
}

func collectCopyright(files []LicenseFileEntry) map[string]CopyrightStatement {
	m := make(map[string]CopyrightStatement)
	for _, f := range files {
		for _, s := range f.CopyrightStatements {
			m[s.Verbatim] = s
		}
	}
	return m
}
