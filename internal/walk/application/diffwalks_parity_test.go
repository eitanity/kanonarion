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
	if got.FrameA != "linux/amd64" || got.FrameB != "darwin/arm64" {
		t.Errorf("frames = %q/%q, want linux/amd64 and darwin/arm64", got.FrameA, got.FrameB)
	}
}

// TestDiffRecords_UnrecordedFrameIsNamed asserts a walk that captured no build
// environment reports it as unrecorded rather than as an empty frame, so the
// empty-diff statement cannot print a blank where a platform belongs.
func TestDiffRecords_UnrecordedFrameIsNamed(t *testing.T) {
	got := diffRecords(walkWith("a", domain.WalkScopeCode, ""), walkWith("b", domain.WalkScopeCode, ""))
	if got.FrameA != "unrecorded" || got.FrameB != "unrecorded" {
		t.Fatalf("frames = %q/%q, want unrecorded on both sides", got.FrameA, got.FrameB)
	}
}
