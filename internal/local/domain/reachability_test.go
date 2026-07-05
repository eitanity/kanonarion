package domain_test

import (
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
