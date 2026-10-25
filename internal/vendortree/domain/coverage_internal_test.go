package domain

import (
	"strings"
	"testing"
)

func TestReplacementCoordinates(t *testing.T) {
	for _, tc := range []struct {
		m          VendoredModule
		path, ver  string
		attested   bool
		rendered   string
		isReplaced bool
	}{
		{VendoredModule{Path: "a", Version: "v1"}, "a", "v1", true, "", false},
		{VendoredModule{Path: "a", Version: "v1", ReplacementPath: "../fork"}, "", "", false, "../fork", true},
		{VendoredModule{Path: "a", Version: "v1", ReplacementPath: "b", ReplacementVersion: "v2"}, "b", "v2", true, "b v2", true},
	} {
		p, v, ok := tc.m.AttestedCoordinate()
		if p != tc.path || v != tc.ver || ok != tc.attested {
			t.Errorf("%+v: AttestedCoordinate = %q %q %v", tc.m, p, v, ok)
		}
		if got := tc.m.ReplacementCoordinate(); got != tc.rendered {
			t.Errorf("%+v: ReplacementCoordinate = %q, want %q", tc.m, got, tc.rendered)
		}
		if tc.m.IsReplaced() != tc.isReplaced {
			t.Errorf("%+v: IsReplaced = %v", tc.m, !tc.isReplaced)
		}
	}
}

func findingDetail(fs []Finding, kind FindingKind) string {
	for _, f := range fs {
		if f.Kind == kind {
			return f.Detail
		}
	}
	return ""
}

// The three answers a replaced module's go.sum lookup can give.
func TestAggregate_ReplacedModules(t *testing.T) {
	in := ParseResult{
		VendorDir: "vendor",
		ModulesTxt: []VendoredModule{
			{Path: "example.com/fs", Version: "v1.0.0", PackageCount: 1, ReplacementPath: "../fork"},
			{Path: "example.com/nosum", Version: "v1.0.0", PackageCount: 1, ReplacementPath: "example.com/r", ReplacementVersion: "v1.1.0"},
			{Path: "example.com/drift", Version: "v1.0.0", PackageCount: 1, ReplacementPath: "example.com/d", ReplacementVersion: "v2.0.0"},
		},
		GoSum:       map[string]string{"example.com/d@v2.0.0": "h1:X"},
		PresentDirs: map[string]bool{"example.com/fs": true, "example.com/nosum": true, "example.com/drift": true},
		Files: map[string]ModuleFiles{"example.com/drift": {
			ZipHeld: true, Zip: map[string]string{"a.go": "h:1"}, Vendored: map[string]string{"a.go": "h:2"},
		}},
	}
	_, fs, _ := Aggregate(in)
	var unverified []string
	for _, f := range fs {
		if f.Kind == FindingUnverified {
			unverified = append(unverified, f.Detail)
		}
	}
	joined := strings.Join(unverified, "\n")
	if !strings.Contains(joined, "filesystem path ../fork") {
		t.Errorf("a filesystem replacement is not stated as uncheckable:\n%s", joined)
	}
	if !strings.Contains(joined, "replaces this module with example.com/r v1.1.0") {
		t.Errorf("a replaced module with no go.sum line does not name the replacement:\n%s", joined)
	}
	if d := findingDetail(fs, FindingDrift); d != "" && !strings.Contains(d, "example.com/d v2.0.0") {
		t.Errorf("drift against a replacement does not name its zip: %q", d)
	}
}

func TestOracleName_NamesTheReplacement(t *testing.T) {
	m := VendoredModule{Path: "a", ReplacementPath: "b", ReplacementVersion: "v2"}
	if got := oracleName(m, "b", "v2"); !strings.Contains(got, "b v2") {
		t.Errorf("oracleName = %q", got)
	}
}

// Versions equal by semver but spelled differently are ordered by spelling.
func TestOrdering_SemverEqualVersionsFallBackToSpelling(t *testing.T) {
	a := VendoredModule{Path: "p", Version: "v1.0.0+a", ReplacementPath: "r", ReplacementVersion: "v1.0.0+a"}
	b := a
	b.Version = "v1.0.0+b"
	if !VendoredModuleLess(a, b) {
		t.Error("module version spelling does not break the tie")
	}
	b = a
	b.ReplacementVersion = "v1.0.0+b"
	if !VendoredModuleLess(a, b) {
		t.Error("replacement version spelling does not break the tie")
	}
	fa := Finding{Module: "p", Kind: FindingDrift, Version: "v1.0.0+a"}
	fb := fa
	fb.Version = "v1.0.0+b"
	if !FindingLess(fa, fb) {
		t.Error("finding version spelling does not break the tie")
	}
	scope := ScopeOverTree([]VendoredModule{
		{Path: "p", Version: "v1.0.0+b"}, {Path: "p", Version: "v1.0.0+a"}, {Path: "p", Version: "v0.9.0"},
	}, nil)
	got := []string{scope.Uncovered[0].Version, scope.Uncovered[1].Version, scope.Uncovered[2].Version}
	if strings.Join(got, ",") != "v0.9.0,v1.0.0+a,v1.0.0+b" {
		t.Errorf("uncovered order = %v", got)
	}
}
