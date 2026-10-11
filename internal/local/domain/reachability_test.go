package domain_test

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/local/domain"
)

func TestSortProbeModules_SortsByPath(t *testing.T) {
	mods := []domain.ModuleProbeResult{
		{Path: "github.com/z/z", Version: "v1.0.0"},
		{Path: "github.com/a/a", Version: "v1.0.0"},
		{Path: "github.com/m/m", Version: "v1.0.0"},
	}
	domain.SortProbeModules(mods)
	want := []string{"github.com/a/a", "github.com/m/m", "github.com/z/z"}
	for i, m := range mods {
		if m.Path != want[i] {
			t.Errorf("mods[%d].Path = %q, want %q", i, m.Path, want[i])
		}
	}
}

func TestSortProbeModules_Empty(t *testing.T) {
	// Must not panic on empty slice.
	domain.SortProbeModules(nil)
	domain.SortProbeModules([]domain.ModuleProbeResult{})
}

func TestSortProbeModules_SingleElement(t *testing.T) {
	mods := []domain.ModuleProbeResult{{Path: "github.com/foo/bar"}}
	domain.SortProbeModules(mods)
	if mods[0].Path != "github.com/foo/bar" {
		t.Errorf("unexpected path after sort: %q", mods[0].Path)
	}
}

func TestSymbolProbeVerdictConstants(t *testing.T) {
	if domain.SymbolProbePresent != "present" {
		t.Errorf("SymbolProbePresent = %q, want %q", domain.SymbolProbePresent, "present")
	}
	if domain.SymbolProbeAbsent != "absent" {
		t.Errorf("SymbolProbeAbsent = %q, want %q", domain.SymbolProbeAbsent, "absent")
	}
	if domain.SymbolProbeUnknown != "unknown" {
		t.Errorf("SymbolProbeUnknown = %q, want %q", domain.SymbolProbeUnknown, "unknown")
	}
}

// The uncovered list is sorted so a probe's answer is byte-stable across runs
// that resolve the build in a different order — and by version within a path,
// because one module can appear twice at two versions in one build.
func TestSortUncovered(t *testing.T) {
	mods := []domain.UncoveredModule{
		{Path: "example.com/b", Version: "v1.0.0"},
		{Path: "example.com/a", Version: "v2.0.0"},
		{Path: "example.com/a", Version: "v1.0.0"},
	}
	domain.SortUncovered(mods)
	want := []domain.UncoveredModule{
		{Path: "example.com/a", Version: "v1.0.0"},
		{Path: "example.com/a", Version: "v2.0.0"},
		{Path: "example.com/b", Version: "v1.0.0"},
	}
	for i := range want {
		if mods[i] != want[i] {
			t.Fatalf("sorted[%d] = %+v, want %+v (full: %+v)", i, mods[i], want[i], mods)
		}
	}
}

// The probed-binary list is sorted so a multi-main project's answer is stable
// across runs that enumerate the mains in a different order.
func TestSortProbedBinaries(t *testing.T) {
	bins := []domain.ProbedBinary{
		{ImportPath: "example.com/app/cmd/zeta"},
		{ImportPath: "example.com/app/cmd/alpha", BuildError: "boom"},
		{ImportPath: "example.com/app/cmd/mid"},
	}
	domain.SortProbedBinaries(bins)
	want := []string{
		"example.com/app/cmd/alpha",
		"example.com/app/cmd/mid",
		"example.com/app/cmd/zeta",
	}
	for i := range want {
		if bins[i].ImportPath != want[i] {
			t.Fatalf("sorted[%d] = %q, want %q (full: %+v)", i, bins[i].ImportPath, want[i], bins)
		}
	}
	// The build error travels with its binary, not with its position.
	if bins[0].BuildError != "boom" {
		t.Errorf("alpha.BuildError = %q, want %q", bins[0].BuildError, "boom")
	}
	// Must not panic on empty input.
	domain.SortProbedBinaries(nil)
}

func TestSortHarnessOmissions_SortsBySymbolThenReason(t *testing.T) {
	got := []domain.HarnessOmission{
		{Symbol: "example.com/b.F", Reason: "r"},
		{Symbol: "example.com/a.F", Reason: "z"},
		{Symbol: "example.com/a.F", Reason: "a"},
	}
	domain.SortHarnessOmissions(got)
	want := []domain.HarnessOmission{
		{Symbol: "example.com/a.F", Reason: "a"},
		{Symbol: "example.com/a.F", Reason: "z"},
		{Symbol: "example.com/b.F", Reason: "r"},
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sorted = %v, want %v", got, want)
		}
	}
}

// A library absence names the count of omitted declarations, and only when
// there are some: with none, the reason is the plain library one.
func TestLibraryAbsentReason_NamesOmissionsOnlyWhenThereAreSome(t *testing.T) {
	if got := domain.LibraryAbsentReason(0); got != domain.ProbeAbsentLibraryReason {
		t.Errorf("LibraryAbsentReason(0) = %q, want the plain library reason", got)
	}
	got := domain.LibraryAbsentReason(2)
	if !strings.HasPrefix(got, domain.ProbeAbsentLibraryReason) || !strings.Contains(got, "2 exported declaration(s)") {
		t.Errorf("LibraryAbsentReason(2) = %q, want the library reason naming 2 declarations", got)
	}
}
