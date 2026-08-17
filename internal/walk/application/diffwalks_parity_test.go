package application

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/walk/domain"
)

func walkWith(id string, scope domain.WalkScope, depth domain.WalkDepth) domain.WalkRecord {
	return domain.WalkRecord{ID: id, Scope: scope, Depth: depth}
}

// TestDiffRecords_CompletenessMismatch asserts the walk diff flags an asymmetric
// comparison when the two walks were resolved at a different scope or depth, and
// stays clean when they match.
func TestDiffRecords_CompletenessMismatch(t *testing.T) {
	cases := []struct {
		name       string
		a, b       domain.WalkRecord
		wantSubstr string // "" means no mismatch expected
	}{
		{
			name: "same scope and depth",
			a:    walkWith("a", domain.WalkScopeCode, domain.WalkDepthFull),
			b:    walkWith("b", domain.WalkScopeCode, domain.WalkDepthFull),
		},
		{
			name:       "scope differs",
			a:          walkWith("a", domain.WalkScopeCode, domain.WalkDepthFull),
			b:          walkWith("b", domain.WalkScopeComplete, domain.WalkDepthFull),
			wantSubstr: "walk scope differs",
		},
		{
			name:       "depth differs",
			a:          walkWith("a", domain.WalkScopeCode, domain.WalkDepthFull),
			b:          walkWith("b", domain.WalkScopeCode, domain.WalkDepthShallow),
			wantSubstr: "walk depth differs",
		},
		{
			name: "empty depth equals full",
			a:    walkWith("a", domain.WalkScopeCode, ""),
			b:    walkWith("b", domain.WalkScopeCode, domain.WalkDepthFull),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := diffRecords(tc.a, tc.b).CompletenessMismatch
			if tc.wantSubstr == "" {
				if got != "" {
					t.Fatalf("expected no mismatch, got %q", got)
				}
				return
			}
			if !strings.Contains(got, tc.wantSubstr) {
				t.Fatalf("expected mismatch mentioning %q, got %q", tc.wantSubstr, got)
			}
		})
	}
}

// TestDiffRecords_CarriesTheComparedPopulation asserts the diff reports the node
// counts and build frames it was taken over, on both sides, whether or not there
// is a delta.
//
// They exist for the empty diff: a result with nothing in it is the evidence for
// "the dependency set did not move", and that claim is only readable if the
// answer says what was on each side of the comparison.
func TestDiffRecords_CarriesTheComparedPopulation(t *testing.T) {
	depOne, _ := coordinate.NewModuleCoordinate("example.com/one", "v1.0.0")
	depTwo, _ := coordinate.NewModuleCoordinate("example.com/two", "v1.0.0")

	a := walkWith("a", domain.WalkScopeCode, domain.WalkDepthFull)
	a.Graph = domain.Graph{
		Nodes:    []domain.GraphNode{{Coordinate: depOne}, {Coordinate: depTwo}},
		BuildEnv: domain.BuildEnv{GOOS: "linux", GOARCH: "amd64", GoVersion: "go1.26.5"},
	}
	b := walkWith("b", domain.WalkScopeCode, domain.WalkDepthFull)
	b.Graph = domain.Graph{
		Nodes:    []domain.GraphNode{{Coordinate: depOne}, {Coordinate: depTwo}},
		BuildEnv: domain.BuildEnv{GOOS: "darwin", GOARCH: "arm64", GoVersion: "go1.26.5"},
	}

	got := diffRecords(a, b)
	if len(got.Added) != 0 || len(got.Removed) != 0 || len(got.VersionChanged) != 0 {
		t.Fatalf("expected an empty delta, got %+v", got)
	}
	if got.NodesA != 2 || got.NodesB != 2 {
		t.Errorf("node counts = %d/%d, want 2/2", got.NodesA, got.NodesB)
	}
	if got.FrameA.Text != "linux/amd64" || got.FrameB.Text != "darwin/arm64" {
		t.Errorf("frames = %q/%q, want linux/amd64 and darwin/arm64", got.FrameA, got.FrameB)
	}
	if got.FrameA.Basis != domain.FrameBasisPlatform || got.FrameB.Basis != domain.FrameBasisPlatform {
		t.Errorf("bases = %q/%q, want both platform", got.FrameA.Basis, got.FrameB.Basis)
	}
}

// TestDiffRecords_UnrecordedFrameIsNamed asserts a walk whose target is not even
// known reports its frame as unrecorded rather than as an empty frame, so the
// empty-diff statement cannot print a blank where a platform belongs.
func TestDiffRecords_UnrecordedFrameIsNamed(t *testing.T) {
	got := diffRecords(walkWith("a", domain.WalkScopeCode, ""), walkWith("b", domain.WalkScopeCode, ""))
	if got.FrameA.Text != "unrecorded" || got.FrameB.Text != "unrecorded" {
		t.Fatalf("frames = %q/%q, want unrecorded on both sides", got.FrameA, got.FrameB)
	}
	if got.FrameA.Basis != domain.FrameBasisUnrecorded || got.FrameB.Basis != domain.FrameBasisUnrecorded {
		t.Fatalf("bases = %q/%q, want unrecorded on both sides", got.FrameA.Basis, got.FrameB.Basis)
	}
}

// TestDiffRecords_TwoModuleRootedWalksDoNotShareAFrame is the diff half of the
// frame fix. Two walks of DIFFERENT published modules resolve no platform each,
// and the empty-diff statement prints a frame for both sides. Rendering that as
// a platform token made them read as having been resolved in the same frame —
// they were not; neither has one. The token says so, and the basis is what a
// consumer keys on.
func TestDiffRecords_TwoModuleRootedWalksDoNotShareAFrame(t *testing.T) {
	one, _ := coordinate.NewModuleCoordinate("example.com/one", "v1.0.0")
	two, _ := coordinate.NewModuleCoordinate("example.com/two", "v2.0.0")

	a := walkWith("a", domain.WalkScopeCode, domain.WalkDepthFull)
	a.Graph = domain.Graph{Target: one}
	b := walkWith("b", domain.WalkScopeCode, domain.WalkDepthFull)
	b.Graph = domain.Graph{Target: two}

	got := diffRecords(a, b)
	for _, f := range []domain.WalkFrame{got.FrameA, got.FrameB} {
		if f.Basis != domain.FrameBasisNotPlatformScoped {
			t.Errorf("module-rooted walk basis = %q, want %q", f.Basis, domain.FrameBasisNotPlatformScoped)
		}
		if f.Text == "unrecorded" {
			t.Errorf("a module-rooted walk claims its platform was not recorded: %q", f.Text)
		}
		if strings.Contains(f.Text, "/") {
			t.Errorf("a walk with no platform rendered one: %q", f.Text)
		}
	}
}
