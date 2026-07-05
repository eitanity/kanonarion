package domain_test

import (
	"reflect"
	"testing"

	"github.com/eitanity/kanonarion/internal/license/domain"
)

func TestDeriveEffectiveLicenseSet_SingleLicense(t *testing.T) {
	// Regression: a clean single-license module must yield effective set of size 1.
	entries := []domain.LicenseFileEntry{
		{Path: "LICENSE", SPDX: "MIT", Confidence: 0.99, IsVendored: false},
	}
	got := domain.DeriveEffectiveLicenseSet(entries)

	if !reflect.DeepEqual(got.RootSPDXs, []string{"MIT"}) {
		t.Errorf("RootSPDXs: got %v, want [MIT]", got.RootSPDXs)
	}
	if len(got.Components) != 0 {
		t.Errorf("Components: got %d, want 0", len(got.Components))
	}
	if !reflect.DeepEqual(got.AllSPDXs, []string{"MIT"}) {
		t.Errorf("AllSPDXs: got %v, want [MIT]", got.AllSPDXs)
	}
}

func TestDeriveEffectiveLicenseSet_EmbeddedComponent(t *testing.T) {
	// Module with MIT root license and a vendored BSD-3-Clause snappy component.
	entries := []domain.LicenseFileEntry{
		{Path: "LICENSE", SPDX: "MIT", Confidence: 0.99, IsVendored: false},
		{Path: "vendor/github.com/google/snappy/LICENSE", SPDX: "BSD-3-Clause", Confidence: 0.97, IsVendored: true},
	}
	got := domain.DeriveEffectiveLicenseSet(entries)

	if !reflect.DeepEqual(got.RootSPDXs, []string{"MIT"}) {
		t.Errorf("RootSPDXs: got %v, want [MIT]", got.RootSPDXs)
	}
	if len(got.Components) != 1 {
		t.Fatalf("Components: got %d, want 1", len(got.Components))
	}
	comp := got.Components[0]
	if comp.PathPrefix != "vendor/github.com/google/snappy" {
		t.Errorf("Component.PathPrefix: got %q, want vendor/github.com/google/snappy", comp.PathPrefix)
	}
	if !reflect.DeepEqual(comp.SPDXs, []string{"BSD-3-Clause"}) {
		t.Errorf("Component.SPDXs: got %v, want [BSD-3-Clause]", comp.SPDXs)
	}
	// AllSPDXs must be the union of root + component, sorted.
	wantAll := []string{"BSD-3-Clause", "MIT"}
	if !reflect.DeepEqual(got.AllSPDXs, wantAll) {
		t.Errorf("AllSPDXs: got %v, want %v", got.AllSPDXs, wantAll)
	}
}

func TestDeriveEffectiveLicenseSet_EmbeddedDuplicateSPDX(t *testing.T) {
	// Root and embedded component share the same license; AllSPDXs is deduped.
	entries := []domain.LicenseFileEntry{
		{Path: "LICENSE", SPDX: "MIT", Confidence: 0.99, IsVendored: false},
		{Path: "vendor/dep/LICENSE", SPDX: "MIT", Confidence: 0.98, IsVendored: true},
	}
	got := domain.DeriveEffectiveLicenseSet(entries)

	if !reflect.DeepEqual(got.AllSPDXs, []string{"MIT"}) {
		t.Errorf("AllSPDXs: got %v, want [MIT] (deduped)", got.AllSPDXs)
	}
}

func TestDeriveEffectiveLicenseSet_NoLicense(t *testing.T) {
	// Module with no license files → empty effective set.
	got := domain.DeriveEffectiveLicenseSet(nil)
	if len(got.RootSPDXs) != 0 {
		t.Errorf("RootSPDXs: got %v, want empty", got.RootSPDXs)
	}
	if len(got.Components) != 0 {
		t.Errorf("Components: got %v, want empty", got.Components)
	}
	if len(got.AllSPDXs) != 0 {
		t.Errorf("AllSPDXs: got %v, want empty", got.AllSPDXs)
	}
}

func TestDeriveEffectiveLicenseSet_NoticeFilesExcluded(t *testing.T) {
	// NOTICE files must not contribute to the effective license set.
	entries := []domain.LicenseFileEntry{
		{Path: "LICENSE", SPDX: "Apache-2.0", Confidence: 0.99, IsVendored: false},
		{Path: "NOTICE", SPDX: "Apache-2.0", Confidence: 0.90, IsVendored: false},
		{Path: "vendor/dep/NOTICE", SPDX: "MIT", Confidence: 0.95, IsVendored: true},
	}
	got := domain.DeriveEffectiveLicenseSet(entries)

	if !reflect.DeepEqual(got.AllSPDXs, []string{"Apache-2.0"}) {
		t.Errorf("AllSPDXs: got %v, want [Apache-2.0] (NOTICE excluded)", got.AllSPDXs)
	}
	if len(got.Components) != 0 {
		t.Errorf("Components: got %d, want 0 (NOTICE files excluded)", len(got.Components))
	}
}

func TestDeriveEffectiveLicenseSet_SubdirectoryEmbeddedComponent(t *testing.T) {
	// Non-vendored subdirectory license files (e.g. klauspost/compress's snappy/ subdir)
	// are treated as embedded components in the effective set.
	entries := []domain.LicenseFileEntry{
		{Path: "LICENSE", SPDX: "Apache-2.0", Confidence: 0.99, IsVendored: false},
		{Path: "snappy/LICENSE", SPDX: "BSD-3-Clause", Confidence: 0.97, IsVendored: false},
		{Path: "zstd/internal/xxhash/LICENSE.txt", SPDX: "MIT", Confidence: 0.98, IsVendored: false},
	}
	got := domain.DeriveEffectiveLicenseSet(entries)

	if !reflect.DeepEqual(got.RootSPDXs, []string{"Apache-2.0"}) {
		t.Errorf("RootSPDXs: got %v, want [Apache-2.0]", got.RootSPDXs)
	}
	if len(got.Components) != 2 {
		t.Fatalf("Components: got %d, want 2", len(got.Components))
	}
	wantPrefixes := []string{"snappy", "zstd/internal/xxhash"}
	for i, comp := range got.Components {
		if comp.PathPrefix != wantPrefixes[i] {
			t.Errorf("Components[%d].PathPrefix: got %q, want %q", i, comp.PathPrefix, wantPrefixes[i])
		}
	}
	wantAll := []string{"Apache-2.0", "BSD-3-Clause", "MIT"}
	if !reflect.DeepEqual(got.AllSPDXs, wantAll) {
		t.Errorf("AllSPDXs: got %v, want %v", got.AllSPDXs, wantAll)
	}
}

func TestDeriveEffectiveLicenseSet_MultipleComponents(t *testing.T) {
	// Multiple vendored components, each with their own license.
	entries := []domain.LicenseFileEntry{
		{Path: "LICENSE", SPDX: "Apache-2.0", Confidence: 0.99, IsVendored: false},
		{Path: "vendor/github.com/google/snappy/LICENSE", SPDX: "BSD-3-Clause", Confidence: 0.97, IsVendored: true},
		{Path: "vendor/github.com/klauspost/compress/LICENSE", SPDX: "MIT", Confidence: 0.98, IsVendored: true},
		{Path: "vendor/github.com/klauspost/compress/zstd/LICENSE", SPDX: "MIT", Confidence: 0.96, IsVendored: true},
	}
	got := domain.DeriveEffectiveLicenseSet(entries)

	if len(got.Components) != 3 {
		t.Fatalf("Components: got %d, want 3", len(got.Components))
	}
	// klauspost/compress and klauspost/compress/zstd are distinct prefixes.
	wantPrefixes := []string{
		"vendor/github.com/google/snappy",
		"vendor/github.com/klauspost/compress",
		"vendor/github.com/klauspost/compress/zstd",
	}
	for i, comp := range got.Components {
		if comp.PathPrefix != wantPrefixes[i] {
			t.Errorf("Components[%d].PathPrefix: got %q, want %q", i, comp.PathPrefix, wantPrefixes[i])
		}
	}
	// AllSPDXs: Apache-2.0 + BSD-3-Clause + MIT (deduped), sorted.
	wantAll := []string{"Apache-2.0", "BSD-3-Clause", "MIT"}
	if !reflect.DeepEqual(got.AllSPDXs, wantAll) {
		t.Errorf("AllSPDXs: got %v, want %v", got.AllSPDXs, wantAll)
	}
}

func TestDeriveEffectiveLicenseSet_UnclassifiedEmbedded(t *testing.T) {
	// Non-root file with no SPDX match must not appear in effective set.
	entries := []domain.LicenseFileEntry{
		{Path: "LICENSE", SPDX: "MIT", Confidence: 0.99, IsVendored: false},
		{Path: "vendor/dep/LICENSE", SPDX: "", Confidence: 0, IsVendored: true},
		{Path: "third_party/dep/LICENSE", SPDX: "", Confidence: 0, IsVendored: false},
	}
	got := domain.DeriveEffectiveLicenseSet(entries)

	if len(got.Components) != 0 {
		t.Errorf("Components: got %d, want 0 (unclassified embedded excluded)", len(got.Components))
	}
	if !reflect.DeepEqual(got.AllSPDXs, []string{"MIT"}) {
		t.Errorf("AllSPDXs: got %v, want [MIT]", got.AllSPDXs)
	}
}
