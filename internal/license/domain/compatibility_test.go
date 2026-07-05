package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/license/domain"
)

// TestCheckPairCompatibility_KnownConflicts verifies that known
// incompatible pairs are flagged and that the engine never silently passes
// an unmodelled pair.
func TestCheckPairCompatibility_KnownConflicts(t *testing.T) {
	t.Parallel()
	tests := []struct {
		dep    string
		target string
		want   domain.CompatibilityVerdict
	}{
		// Permissive deps are always compatible with permissive targets.
		{"MIT", "Apache-2.0", domain.VerdictCompatible},
		{"BSD-3-Clause", "Apache-2.0", domain.VerdictCompatible},
		{"ISC", "Apache-2.0", domain.VerdictCompatible},
		{"Apache-2.0", "Apache-2.0", domain.VerdictCompatible},
		// Weak copyleft is compatible with permissive targets (linking allowed).
		{"MPL-2.0", "Apache-2.0", domain.VerdictCompatible},
		{"LGPL-2.1-only", "Apache-2.0", domain.VerdictCompatible},
		{"LGPL-2.1-or-later", "Apache-2.0", domain.VerdictCompatible},
		{"LGPL-3.0-only", "Apache-2.0", domain.VerdictCompatible},
		// GPL-2.0-only vs Apache-2.0 is the canonical explicit conflict (FSF).
		{"GPL-2.0-only", "Apache-2.0", domain.VerdictIncompatible},
		{"GPL-2.0-or-later", "Apache-2.0", domain.VerdictIncompatible},
		{"GPL-3.0-only", "Apache-2.0", domain.VerdictIncompatible},
		{"GPL-3.0-or-later", "Apache-2.0", domain.VerdictIncompatible},
		// AGPL propagation: strong copyleft + network-use trigger.
		{"AGPL-3.0-only", "Apache-2.0", domain.VerdictIncompatible},
		{"AGPL-3.0-or-later", "Apache-2.0", domain.VerdictIncompatible},
		// GPL-2.0-or-later code is compatible with a GPL-3 target.
		{"GPL-2.0-or-later", "GPL-3.0-only", domain.VerdictCompatible},
		{"GPL-2.0-or-later", "GPL-3.0-or-later", domain.VerdictCompatible},
	}

	for _, tc := range tests {
		got := domain.CheckPairCompatibility(tc.dep, tc.target)
		if got != tc.want {
			t.Errorf("CheckPairCompatibility(%q, %q) = %s, want %s",
				tc.dep, tc.target, got, tc.want)
		}
	}
}

// TestCheckPairCompatibility_UnmodelledPairFlagsForReview is the
// regression test required by an unmodelled pair MUST return
// VerdictUnknownPair, never VerdictCompatible.
func TestCheckPairCompatibility_UnmodelledPairFlagsForReview(t *testing.T) {
	t.Parallel()
	// Neither side of each pair is the same — the important invariant is that
	// absence of data is never treated as "compatible".
	unmodelledPairs := [][2]string{
		{"UNKNOWN-1.0", "Apache-2.0"},
		{"MIT", "CUSTOM-CORP-1.0"},
		{"GPL-3.0-only", "UNKNOWN-1.0"},
		{"UNKNOWN-A", "UNKNOWN-B"},
		{"CC-BY-SA-4.0", "Apache-2.0"}, // CC-BY-SA not in dataset
	}

	for _, pair := range unmodelledPairs {
		got := domain.CheckPairCompatibility(pair[0], pair[1])
		if got == domain.VerdictCompatible {
			t.Errorf("CheckPairCompatibility(%q, %q) = compatible — unmodelled pair must not be silently compatible",
				pair[0], pair[1])
		}
		if got != domain.VerdictUnknownPair {
			t.Errorf("CheckPairCompatibility(%q, %q) = %s, want unknown_pair",
				pair[0], pair[1], got)
		}
	}
}

// TestCheckClosureCompatibility_PermissiveOnlyIsClean verifies that a
// closure containing only permissive licenses produces a clean report.
func TestCheckClosureCompatibility_PermissiveOnlyIsClean(t *testing.T) {
	t.Parallel()
	modules := []domain.CompatibilityInput{
		{ModulePath: "github.com/spf13/cobra", ModuleVersion: "v1.8.1", SPDX: "Apache-2.0"},
		{ModulePath: "github.com/google/uuid", ModuleVersion: "v1.6.0", SPDX: "BSD-3-Clause"},
		{ModulePath: "github.com/dustin/go-humanize", ModuleVersion: "v1.0.1", SPDX: "MIT"},
		{ModulePath: "github.com/spf13/pflag", ModuleVersion: "v1.0.5", SPDX: "BSD-3-Clause"},
		{ModulePath: "golang.org/x/mod", ModuleVersion: "v0.22.0", SPDX: "BSD-3-Clause"},
	}

	report := domain.CheckClosureCompatibility(modules, "Apache-2.0")
	if !report.Clean {
		t.Errorf("permissive-only closure should be clean, got conflicts: %v", report.Conflicts)
	}
	if len(report.Conflicts) != 0 {
		t.Errorf("expected 0 conflicts, got %d", len(report.Conflicts))
	}
}

// TestCheckClosureCompatibility_GPLConflict verifies that a GPL dep
// produces a conflict in an Apache-2.0-targeted closure.
func TestCheckClosureCompatibility_GPLConflict(t *testing.T) {
	t.Parallel()
	modules := []domain.CompatibilityInput{
		{ModulePath: "github.com/permissive/lib", ModuleVersion: "v1.0.0", SPDX: "MIT"},
		{ModulePath: "github.com/gpl/lib", ModuleVersion: "v2.0.0", SPDX: "GPL-2.0-only"},
	}

	report := domain.CheckClosureCompatibility(modules, "Apache-2.0")
	if report.Clean {
		t.Error("closure with GPL-2.0-only should not be clean")
	}
	if len(report.Conflicts) != 1 {
		t.Fatalf("expected 1 conflict, got %d: %v", len(report.Conflicts), report.Conflicts)
	}
	c := report.Conflicts[0]
	if c.ModulePath != "github.com/gpl/lib" {
		t.Errorf("conflict module path = %q, want %q", c.ModulePath, "github.com/gpl/lib")
	}
	if c.Verdict != domain.VerdictIncompatible {
		t.Errorf("conflict verdict = %s, want incompatible", c.Verdict)
	}
	if c.Kind != domain.ConflictCopyleftPropagation {
		t.Errorf("conflict kind = %s, want copyleft_propagation", c.Kind)
	}
}

// TestCheckClosureCompatibility_AGPLNetworkTrigger verifies that AGPL
// produces a network-trigger conflict kind.
func TestCheckClosureCompatibility_AGPLNetworkTrigger(t *testing.T) {
	t.Parallel()
	modules := []domain.CompatibilityInput{
		{ModulePath: "example.com/agpl-dep", ModuleVersion: "v1.0.0", SPDX: "AGPL-3.0-only"},
	}

	report := domain.CheckClosureCompatibility(modules, "Apache-2.0")
	if report.Clean {
		t.Error("closure with AGPL-3.0-only should not be clean")
	}
	if len(report.Conflicts) != 1 {
		t.Fatalf("expected 1 conflict, got %d", len(report.Conflicts))
	}
	c := report.Conflicts[0]
	if c.Kind != domain.ConflictNetworkTrigger {
		t.Errorf("conflict kind = %s, want network_trigger", c.Kind)
	}
}

// TestCheckClosureCompatibility_EmptySPDXIsUnknown verifies that a
// module with no detected SPDX id is flagged as unknown, not compatible
func TestCheckClosureCompatibility_EmptySPDXIsUnknown(t *testing.T) {
	t.Parallel()
	modules := []domain.CompatibilityInput{
		{ModulePath: "example.com/no-license", ModuleVersion: "v0.1.0", SPDX: ""},
	}

	report := domain.CheckClosureCompatibility(modules, "Apache-2.0")
	if report.Clean {
		t.Error("module with empty SPDX should produce an unknown_pair conflict")
	}
	if len(report.Conflicts) != 1 {
		t.Fatalf("expected 1 conflict, got %d", len(report.Conflicts))
	}
	c := report.Conflicts[0]
	if c.Verdict != domain.VerdictUnknownPair {
		t.Errorf("conflict verdict = %s, want unknown_pair", c.Verdict)
	}
}

// TestCheckClosureCompatibility_ConflictsSorted verifies that conflicts
// are returned sorted by ModulePath then ModuleVersion for determinism.
func TestCheckClosureCompatibility_ConflictsSorted(t *testing.T) {
	t.Parallel()
	modules := []domain.CompatibilityInput{
		{ModulePath: "z.example.com/gpl", ModuleVersion: "v1.0.0", SPDX: "GPL-3.0-only"},
		{ModulePath: "a.example.com/agpl", ModuleVersion: "v1.0.0", SPDX: "AGPL-3.0-only"},
		{ModulePath: "m.example.com/gpl", ModuleVersion: "v2.0.0", SPDX: "GPL-2.0-only"},
		{ModulePath: "m.example.com/gpl", ModuleVersion: "v1.0.0", SPDX: "GPL-2.0-only"},
	}

	report := domain.CheckClosureCompatibility(modules, "Apache-2.0")
	if len(report.Conflicts) != 4 {
		t.Fatalf("expected 4 conflicts, got %d", len(report.Conflicts))
	}
	paths := make([]string, len(report.Conflicts))
	for i, c := range report.Conflicts {
		paths[i] = c.ModulePath + "@" + c.ModuleVersion
	}
	want := []string{
		"a.example.com/agpl@v1.0.0",
		"m.example.com/gpl@v1.0.0",
		"m.example.com/gpl@v2.0.0",
		"z.example.com/gpl@v1.0.0",
	}
	for i, w := range want {
		if paths[i] != w {
			t.Errorf("conflicts[%d] = %q, want %q", i, paths[i], w)
		}
	}
}

// TestCopyleftStrengthOf_KnownLicenses verifies that key SPDX ids map
// to the expected copyleft strength.
func TestCopyleftStrengthOf_KnownLicenses(t *testing.T) {
	t.Parallel()
	tests := []struct {
		spdx string
		want domain.CopyleftStrength
		ok   bool
	}{
		{"MIT", domain.CopyleftNone, true},
		{"Apache-2.0", domain.CopyleftNone, true},
		{"BSD-3-Clause", domain.CopyleftNone, true},
		{"MPL-2.0", domain.CopyleftWeak, true},
		{"LGPL-2.1-only", domain.CopyleftWeak, true},
		{"GPL-2.0-only", domain.CopyleftStrong, true},
		{"GPL-3.0-only", domain.CopyleftStrong, true},
		{"AGPL-3.0-only", domain.CopyleftNetwork, true},
		{"AGPL-3.0-or-later", domain.CopyleftNetwork, true},
		{"TOTALLY-UNKNOWN-1.0", domain.CopyleftNone, false}, // not ok
	}

	for _, tc := range tests {
		got, ok := domain.CopyleftStrengthOf(tc.spdx)
		if ok != tc.ok {
			t.Errorf("CopyleftStrengthOf(%q) ok = %v, want %v", tc.spdx, ok, tc.ok)
			continue
		}
		if ok && got != tc.want {
			t.Errorf("CopyleftStrengthOf(%q) = %s, want %s", tc.spdx, got, tc.want)
		}
	}
}
