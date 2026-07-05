package domain

import (
	"testing"
)

func TestDerivePackageLicenses_empty(t *testing.T) {
	got := DerivePackageLicenses(nil)
	if got != nil {
		t.Errorf("expected nil for empty entries, got %v", got)
	}
}

func TestDerivePackageLicenses_rootOnly(t *testing.T) {
	entries := []LicenseFileEntry{
		{Path: "LICENSE", SPDX: "MIT", Confidence: 0.99},
		{Path: "NOTICE", SPDX: "", Confidence: 0},
	}
	got := DerivePackageLicenses(entries)
	if len(got) != 0 {
		t.Errorf("expected no package licenses for root-only module, got %v", got)
	}
}

func TestDerivePackageLicenses_uniformModule(t *testing.T) {
	// Regression: a module with only a root LICENSE and no sub-package
	// license files must report zero PackageLicenses.
	entries := []LicenseFileEntry{
		{Path: "LICENSE", SPDX: "Apache-2.0", Confidence: 0.98},
		{Path: "vendor/dep/LICENSE", SPDX: "MIT", Confidence: 0.95, IsVendored: true},
	}
	got := DerivePackageLicenses(entries)
	if len(got) != 0 {
		t.Errorf("uniform module: expected 0 PackageLicenses, got %d: %v", len(got), got)
	}
}

func TestDerivePackageLicenses_subPackageDiffers(t *testing.T) {
	// A module with a differently-licensed sub-package must surface it.
	entries := []LicenseFileEntry{
		{Path: "LICENSE", SPDX: "Apache-2.0", Confidence: 0.98},
		{Path: "internal/parser/LICENSE", SPDX: "MIT", Confidence: 0.95},
	}
	got := DerivePackageLicenses(entries)
	if len(got) != 1 {
		t.Fatalf("expected 1 package license, got %d: %v", len(got), got)
	}
	pl := got[0]
	if pl.PackagePath != "internal/parser" {
		t.Errorf("PackagePath: want %q, got %q", "internal/parser", pl.PackagePath)
	}
	if pl.SPDX != "MIT" {
		t.Errorf("SPDX: want MIT, got %q", pl.SPDX)
	}
	if pl.SourceFile != "internal/parser/LICENSE" {
		t.Errorf("SourceFile: want %q, got %q", "internal/parser/LICENSE", pl.SourceFile)
	}
}

func TestDerivePackageLicenses_vendoredExcluded(t *testing.T) {
	entries := []LicenseFileEntry{
		{Path: "LICENSE", SPDX: "Apache-2.0", Confidence: 0.98},
		{Path: "vendor/github.com/foo/bar/LICENSE", SPDX: "MIT", Confidence: 0.95, IsVendored: true},
	}
	got := DerivePackageLicenses(entries)
	if len(got) != 0 {
		t.Errorf("vendored entries must not produce PackageLicenses, got %v", got)
	}
}

func TestDerivePackageLicenses_noticeExcluded(t *testing.T) {
	entries := []LicenseFileEntry{
		{Path: "LICENSE", SPDX: "MIT", Confidence: 0.99},
		{Path: "cmd/tool/NOTICE", SPDX: "", Confidence: 0},
		{Path: "cmd/tool/NOTICE.txt", SPDX: "", Confidence: 0},
	}
	got := DerivePackageLicenses(entries)
	if len(got) != 0 {
		t.Errorf("NOTICE files must not produce PackageLicenses, got %v", got)
	}
}

func TestDerivePackageLicenses_multipleSubPackages(t *testing.T) {
	entries := []LicenseFileEntry{
		{Path: "LICENSE", SPDX: "Apache-2.0", Confidence: 0.98},
		{Path: "cmd/foo/LICENSE", SPDX: "MIT", Confidence: 0.95},
		{Path: "cmd/bar/LICENSE", SPDX: "BSD-3-Clause", Confidence: 0.90},
		{Path: "internal/x/LICENSE", SPDX: "Apache-2.0", Confidence: 0.97},
	}
	got := DerivePackageLicenses(entries)
	if len(got) != 3 {
		t.Fatalf("expected 3 package licenses, got %d: %v", len(got), got)
	}
	// Must be sorted by PackagePath.
	paths := []string{got[0].PackagePath, got[1].PackagePath, got[2].PackagePath}
	want := []string{"cmd/bar", "cmd/foo", "internal/x"}
	for i := range want {
		if paths[i] != want[i] {
			t.Errorf("PackagePath[%d]: want %q, got %q", i, want[i], paths[i])
		}
	}
}

func TestDerivePackageLicenses_multipleFilesInSameDir(t *testing.T) {
	// When a directory has multiple license files, the highest-confidence one wins.
	entries := []LicenseFileEntry{
		{Path: "LICENSE", SPDX: "MIT", Confidence: 0.99},
		{Path: "cmd/tool/LICENSE", SPDX: "Apache-2.0", Confidence: 0.80},
		{Path: "cmd/tool/LICENSE.txt", SPDX: "MIT", Confidence: 0.95},
	}
	got := DerivePackageLicenses(entries)
	if len(got) != 1 {
		t.Fatalf("expected 1 package license, got %d: %v", len(got), got)
	}
	if got[0].SPDX != "MIT" {
		t.Errorf("highest-confidence file should win: want MIT, got %q", got[0].SPDX)
	}
	if got[0].SourceFile != "cmd/tool/LICENSE.txt" {
		t.Errorf("SourceFile: want cmd/tool/LICENSE.txt, got %q", got[0].SourceFile)
	}
}

func TestDerivePackageLicenses_unclassified(t *testing.T) {
	// A sub-package license file that cannot be classified should still appear.
	entries := []LicenseFileEntry{
		{Path: "LICENSE", SPDX: "MIT", Confidence: 0.99},
		{Path: "proprietary/module/LICENSE", SPDX: "", Confidence: 0},
	}
	got := DerivePackageLicenses(entries)
	if len(got) != 1 {
		t.Fatalf("expected 1 package license, got %d: %v", len(got), got)
	}
	if got[0].SPDX != "" {
		t.Errorf("unclassified: SPDX should be empty, got %q", got[0].SPDX)
	}
	if got[0].PackagePath != "proprietary/module" {
		t.Errorf("PackagePath: want proprietary/module, got %q", got[0].PackagePath)
	}
}

func TestDerivePackageLicenses_deeplyNested(t *testing.T) {
	entries := []LicenseFileEntry{
		{Path: "LICENSE", SPDX: "Apache-2.0", Confidence: 0.98},
		{Path: "internal/a/b/c/LICENSE", SPDX: "MIT", Confidence: 0.95},
	}
	got := DerivePackageLicenses(entries)
	if len(got) != 1 {
		t.Fatalf("expected 1, got %d: %v", len(got), got)
	}
	if got[0].PackagePath != "internal/a/b/c" {
		t.Errorf("PackagePath: want internal/a/b/c, got %q", got[0].PackagePath)
	}
}
