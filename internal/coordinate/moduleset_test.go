package coordinate_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
)

func mustCoord(t *testing.T, path, version string) coordinate.ModuleCoordinate {
	t.Helper()
	c, err := coordinate.NewModuleCoordinate(path, version)
	if err != nil {
		t.Fatalf("NewModuleCoordinate(%q, %q): %v", path, version, err)
	}
	return c
}

// TestModuleSet_ZeroValueIsUnrestricted pins the default that keeps an unscoped
// query answering across every stored version.
func TestModuleSet_ZeroValueIsUnrestricted(t *testing.T) {
	var s coordinate.ModuleSet
	if s.IsRestricted() {
		t.Fatal("zero ModuleSet reports restricted")
	}
	if !s.Contains(mustCoord(t, "example.com/mod", "v1.0.0")) {
		t.Error("unrestricted set rejected a coordinate")
	}
	if !s.ContainsPathVersion("example.com/other", "v9.9.9") {
		t.Error("unrestricted set rejected a path/version pair")
	}
	if !s.HasPath("anything.example") {
		t.Error("unrestricted set reported a path absent")
	}
}

// TestModuleSet_EmptyIsRestricted is the distinction the zero value cannot
// carry: a build that resolved no modules matches nothing, and must not decay
// into the unrestricted set.
func TestModuleSet_EmptyIsRestricted(t *testing.T) {
	s := coordinate.NewModuleSet(nil)
	if !s.IsRestricted() {
		t.Fatal("NewModuleSet(nil) reports unrestricted")
	}
	if s.Contains(mustCoord(t, "example.com/mod", "v1.0.0")) {
		t.Error("empty restricted set admitted a coordinate")
	}
	if s.HasPath("example.com/mod") {
		t.Error("empty restricted set reported a path present")
	}
}

func TestModuleSet_MembershipIsVersionExact(t *testing.T) {
	s := coordinate.NewModuleSet([]coordinate.ModuleCoordinate{
		mustCoord(t, "example.com/mod", "v1.1.0"),
		mustCoord(t, "example.com/other", "v2.0.0"),
	})

	if !s.ContainsPathVersion("example.com/mod", "v1.1.0") {
		t.Error("member coordinate not admitted")
	}
	if s.ContainsPathVersion("example.com/mod", "v1.0.0") {
		t.Error("a different version of a member module was admitted")
	}
	if !s.HasPath("example.com/mod") {
		t.Error("HasPath missed a member module")
	}
	if got := s.VersionsOf("example.com/mod"); len(got) != 1 || got[0] != "v1.1.0" {
		t.Errorf("VersionsOf = %v, want [v1.1.0]", got)
	}
	if got := s.VersionsOf("example.com/absent"); len(got) != 0 {
		t.Errorf("VersionsOf(absent) = %v, want empty", got)
	}
	if s.Len() != 2 {
		t.Errorf("Len = %d, want 2", s.Len())
	}
}

// TestModuleSet_DropsZeroCoordinates keeps the set from claiming membership for
// the coordinate that names no module.
func TestModuleSet_DropsZeroCoordinates(t *testing.T) {
	s := coordinate.NewModuleSet([]coordinate.ModuleCoordinate{
		{},
		mustCoord(t, "example.com/mod", "v1.0.0"),
	})
	if s.Len() != 1 {
		t.Errorf("Len = %d, want 1 (zero coordinate dropped)", s.Len())
	}
	if s.Contains(coordinate.ModuleCoordinate{}) {
		t.Error("restricted set admitted the zero coordinate")
	}
}

func TestModuleSet_CoordinatesAreSorted(t *testing.T) {
	s := coordinate.NewModuleSet([]coordinate.ModuleCoordinate{
		mustCoord(t, "example.com/b", "v1.0.0"),
		mustCoord(t, "example.com/a", "v2.0.0"),
		mustCoord(t, "example.com/a", "v1.0.0"),
	})
	got := s.Coordinates()
	want := []string{"example.com/a@v1.0.0", "example.com/a@v2.0.0", "example.com/b@v1.0.0"}
	if len(got) != len(want) {
		t.Fatalf("Coordinates() len = %d, want %d", len(got), len(want))
	}
	for i, c := range got {
		if c.Path()+"@"+c.Version() != want[i] {
			t.Errorf("Coordinates()[%d] = %s@%s, want %s", i, c.Path(), c.Version(), want[i])
		}
	}
}
