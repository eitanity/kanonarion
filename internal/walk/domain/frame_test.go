package domain_test

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/walk/domain"
)

func mustFrameCoord(t *testing.T, path, version string) coordinate.ModuleCoordinate {
	t.Helper()
	c, err := coordinate.NewModuleCoordinate(path, version)
	if err != nil {
		t.Fatalf("coordinate %s@%s: %v", path, version, err)
	}
	return c
}

// TestFrameOf_ThreeSituationsAreThreeAnswers pins the derivation every surface
// renders from. The three cases are three different facts about the same
// absence, and the reason they must not collapse is what a reader does next: a
// platform is a platform; a module-rooted walk resolves none and re-walking it
// never will; an unknown platform is a fact that is missing and could be
// recovered.
func TestFrameOf_ThreeSituationsAreThreeAnswers(t *testing.T) {
	project := mustFrameCoord(t, "example.com/project", coordinate.LocalVersion)
	published := mustFrameCoord(t, "example.com/published", "v1.2.3")

	for _, tc := range []struct {
		name      string
		target    coordinate.ModuleCoordinate
		env       domain.BuildEnv
		wantText  string
		wantBasis domain.FrameBasis
	}{
		{
			name:      "a project walk that resolved a platform states it",
			target:    project,
			env:       domain.BuildEnv{GOOS: "linux", GOARCH: "amd64", GoVersion: "go1.26.6"},
			wantText:  "linux/amd64",
			wantBasis: domain.FrameBasisPlatform,
		},
		{
			name:      "a module-rooted walk is not platform-scoped",
			target:    published,
			wantText:  "not-platform-scoped",
			wantBasis: domain.FrameBasisNotPlatformScoped,
		},
		{
			name:      "a project walk with no stored platform is unrecorded",
			target:    project,
			wantText:  "unrecorded",
			wantBasis: domain.FrameBasisUnrecorded,
		},
		{
			name:      "a walk whose target is not known either is unrecorded",
			wantText:  "unrecorded",
			wantBasis: domain.FrameBasisUnrecorded,
		},
		{
			name:      "a module-rooted walk that somehow carries a platform still states it",
			target:    published,
			env:       domain.BuildEnv{GOOS: "darwin", GOARCH: "arm64"},
			wantText:  "darwin/arm64",
			wantBasis: domain.FrameBasisPlatform,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := domain.FrameOf(tc.target, tc.env)
			if got.Text != tc.wantText {
				t.Errorf("text = %q, want %q", got.Text, tc.wantText)
			}
			if got.Basis != tc.wantBasis {
				t.Errorf("basis = %q, want %q", got.Basis, tc.wantBasis)
			}
			if got.String() != tc.wantText {
				t.Errorf("String() = %q, want the text %q", got.String(), tc.wantText)
			}
		})
	}
}

// TestFrameOf_ModuleRootedNeverClaimsTheFactWasNotRecorded is the defect this
// derivation exists to close. "unrecorded" says the fact is missing and could be
// recovered by walking again; a walk rooted at a published coordinate resolves
// no platform at all, so walking it again never produces one. The two readings
// are opposite, and the module-rooted walk must not borrow the other's word.
func TestFrameOf_ModuleRootedNeverClaimsTheFactWasNotRecorded(t *testing.T) {
	got := domain.FrameOf(mustFrameCoord(t, "github.com/golang-jwt/jwt/v4", "v4.5.2"), domain.BuildEnv{})
	if got.Text == "unrecorded" || got.Basis == domain.FrameBasisUnrecorded {
		t.Fatalf("a module-rooted walk reports its platform as not recorded: %+v", got)
	}
	if strings.Contains(got.Text, "/") {
		t.Fatalf("a walk with no platform rendered one: %q", got.Text)
	}
}

// TestGraphFrame_DerivesOverItsOwnTarget asserts the graph does not need a
// caller to remember to pass the target: the two inputs travel together, and a
// site that had only the BuildEnv is what produced the wrong answer.
func TestGraphFrame_DerivesOverItsOwnTarget(t *testing.T) {
	g := domain.Graph{Target: mustFrameCoord(t, "gonum.org/v1/gonum", "v0.16.0")}
	if got := g.Frame(); got.Basis != domain.FrameBasisNotPlatformScoped {
		t.Errorf("graph frame basis = %q, want %q", got.Basis, domain.FrameBasisNotPlatformScoped)
	}
}
