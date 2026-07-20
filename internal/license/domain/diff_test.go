package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/license/domain"
)

func coord(path, ver string) coordinate.ModuleCoordinate {
	return coordinate.ModuleCoordinate{Path: path, Version: ver}
}

func makeRecord(path, ver, spdx string, status domain.LicenseStatus, files ...domain.LicenseFileEntry) domain.LicenseRecord {
	return domain.LicenseRecord{
		Coordinate:    coord(path, ver),
		PrimarySPDX:   spdx,
		OverallStatus: status,
		LicenseFiles:  files,
	}
}

func file(path, spdx string, stmts ...domain.CopyrightStatement) domain.LicenseFileEntry {
	return domain.LicenseFileEntry{Path: path, SPDX: spdx, CopyrightStatements: stmts}
}

func stmt(verbatim string) domain.CopyrightStatement {
	return domain.CopyrightStatement{Verbatim: verbatim}
}

// identical records produce no diff.
func TestDiffRecords_NoChange(t *testing.T) {
	r := makeRecord("example.com/foo", "v1.0.0", "MIT", domain.LicenseStatusDetected,
		file("LICENSE", "MIT"))

	diff := domain.DiffRecords(r, r)

	if diff.HasChanges() {
		t.Fatal("expected no changes for identical records")
	}
	if diff.SPDXChanged != nil {
		t.Errorf("SPDXChanged = %v, want nil", diff.SPDXChanged)
	}
	if diff.StatusChanged != nil {
		t.Errorf("StatusChanged = %v, want nil", diff.StatusChanged)
	}
	if diff.Escalation != nil {
		t.Errorf("Escalation = %v, want nil", diff.Escalation)
	}
}

// SPDX change is reported and HasChanges returns true.
func TestDiffRecords_SPDXChange(t *testing.T) {
	a := makeRecord("example.com/foo", "v1.0.0", "MIT", domain.LicenseStatusDetected)
	b := makeRecord("example.com/foo", "v2.0.0", "Apache-2.0", domain.LicenseStatusDetected)

	diff := domain.DiffRecords(a, b)

	if !diff.HasChanges() {
		t.Fatal("expected HasChanges = true for SPDX change")
	}
	if diff.SPDXChanged == nil {
		t.Fatal("SPDXChanged is nil, want non-nil")
	}
	if diff.SPDXChanged.From != "MIT" {
		t.Errorf("SPDXChanged.From = %q, want MIT", diff.SPDXChanged.From)
	}
	if diff.SPDXChanged.To != "Apache-2.0" {
		t.Errorf("SPDXChanged.To = %q, want Apache-2.0", diff.SPDXChanged.To)
	}
	// MIT → Apache-2.0 is permissive → permissive: no escalation.
	if diff.Escalation != nil {
		t.Errorf("Escalation = %v, want nil for permissive-to-permissive change", diff.Escalation)
	}
}

// permissive → strong copyleft sets Escalation.
func TestDiffRecords_PermissiveToCopyleftEscalation(t *testing.T) {
	a := makeRecord("example.com/foo", "v1.0.0", "MIT", domain.LicenseStatusDetected)
	b := makeRecord("example.com/foo", "v2.0.0", "GPL-3.0-only", domain.LicenseStatusDetected)

	diff := domain.DiffRecords(a, b)

	if diff.Escalation == nil {
		t.Fatal("Escalation is nil, want non-nil for MIT → GPL-3.0-only")
	}
	if diff.Escalation.From != domain.CopyleftNone {
		t.Errorf("Escalation.From = %v, want CopyleftNone", diff.Escalation.From)
	}
	if diff.Escalation.To != domain.CopyleftStrong {
		t.Errorf("Escalation.To = %v, want CopyleftStrong", diff.Escalation.To)
	}
}

// permissive → network copyleft (AGPL) sets Escalation.
func TestDiffRecords_PermissiveToNetworkCopyleft(t *testing.T) {
	a := makeRecord("example.com/foo", "v1.0.0", "Apache-2.0", domain.LicenseStatusDetected)
	b := makeRecord("example.com/foo", "v2.0.0", "AGPL-3.0-only", domain.LicenseStatusDetected)

	diff := domain.DiffRecords(a, b)

	if diff.Escalation == nil {
		t.Fatal("Escalation is nil, want non-nil for Apache-2.0 → AGPL-3.0-only")
	}
	if diff.Escalation.To != domain.CopyleftNetwork {
		t.Errorf("Escalation.To = %v, want CopyleftNetwork", diff.Escalation.To)
	}
}

// status change is reported.
func TestDiffRecords_StatusChange(t *testing.T) {
	a := makeRecord("example.com/foo", "v1.0.0", "MIT", domain.LicenseStatusDetected)
	b := makeRecord("example.com/foo", "v2.0.0", "MIT", domain.LicenseStatusMultiple)

	diff := domain.DiffRecords(a, b)

	if diff.StatusChanged == nil {
		t.Fatal("StatusChanged is nil, want non-nil")
	}
	if diff.StatusChanged.From != domain.LicenseStatusDetected {
		t.Errorf("StatusChanged.From = %v, want Detected", diff.StatusChanged.From)
	}
	if diff.StatusChanged.To != domain.LicenseStatusMultiple {
		t.Errorf("StatusChanged.To = %v, want Multiple", diff.StatusChanged.To)
	}
}

// files added and removed between records.
func TestDiffRecords_FilesAddedRemoved(t *testing.T) {
	a := makeRecord("example.com/foo", "v1.0.0", "MIT", domain.LicenseStatusDetected,
		file("LICENSE", "MIT"),
		file("vendor/dep/LICENSE", "Apache-2.0"),
	)
	b := makeRecord("example.com/foo", "v2.0.0", "MIT", domain.LicenseStatusDetected,
		file("LICENSE", "MIT"),
		file("NOTICE", "Apache-2.0"),
	)

	diff := domain.DiffRecords(a, b)

	if len(diff.FilesAdded) != 1 || diff.FilesAdded[0].Path != "NOTICE" {
		t.Errorf("FilesAdded = %v, want [NOTICE]", diff.FilesAdded)
	}
	if len(diff.FilesRemoved) != 1 || diff.FilesRemoved[0].Path != "vendor/dep/LICENSE" {
		t.Errorf("FilesRemoved = %v, want [vendor/dep/LICENSE]", diff.FilesRemoved)
	}
}

// copyright statements added and removed.
func TestDiffRecords_CopyrightChanges(t *testing.T) {
	a := makeRecord("example.com/foo", "v1.0.0", "MIT", domain.LicenseStatusDetected,
		file("LICENSE", "MIT", stmt("Copyright 2020 Alice")),
	)
	b := makeRecord("example.com/foo", "v2.0.0", "MIT", domain.LicenseStatusDetected,
		file("LICENSE", "MIT", stmt("Copyright 2020 Alice"), stmt("Copyright 2023 Bob")),
	)

	diff := domain.DiffRecords(a, b)

	if diff.SPDXChanged != nil {
		t.Error("unexpected SPDXChanged")
	}
	if len(diff.CopyrightAdded) != 1 || diff.CopyrightAdded[0].Verbatim != "Copyright 2023 Bob" {
		t.Errorf("CopyrightAdded = %v, want [Copyright 2023 Bob]", diff.CopyrightAdded)
	}
	if len(diff.CopyrightRemoved) != 0 {
		t.Errorf("CopyrightRemoved = %v, want empty", diff.CopyrightRemoved)
	}
}

// output is deterministic (same input always yields identical order).
func TestDiffRecords_DeterministicOrder(t *testing.T) {
	a := makeRecord("example.com/foo", "v1.0.0", "MIT", domain.LicenseStatusDetected)
	b := makeRecord("example.com/foo", "v2.0.0", "MIT", domain.LicenseStatusDetected,
		file("z_LICENSE", "MIT"),
		file("a_LICENSE", "Apache-2.0"),
	)

	d1 := domain.DiffRecords(a, b)
	d2 := domain.DiffRecords(a, b)

	if len(d1.FilesAdded) != len(d2.FilesAdded) {
		t.Fatalf("len mismatch: %d vs %d", len(d1.FilesAdded), len(d2.FilesAdded))
	}
	for i := range d1.FilesAdded {
		if d1.FilesAdded[i].Path != d2.FilesAdded[i].Path {
			t.Errorf("FilesAdded[%d] not deterministic: %q vs %q", i, d1.FilesAdded[i].Path, d2.FilesAdded[i].Path)
		}
	}
	if len(d1.FilesAdded) >= 2 && d1.FilesAdded[0].Path > d1.FilesAdded[1].Path {
		t.Errorf("FilesAdded not sorted: %q > %q", d1.FilesAdded[0].Path, d1.FilesAdded[1].Path)
	}
}
