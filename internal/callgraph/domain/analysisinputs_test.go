package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
)

func mustCoordinate(t *testing.T, path, version string) coordinate.ModuleCoordinate {
	t.Helper()
	c, err := coordinate.NewModuleCoordinate(path, version)
	if err != nil {
		t.Fatalf("NewModuleCoordinate(%q, %q): %v", path, version, err)
	}
	return c
}

func buildListOf(t *testing.T, coords ...coordinate.ModuleCoordinate) map[coordinate.ModuleCoordinate]struct{} {
	t.Helper()
	out := make(map[coordinate.ModuleCoordinate]struct{}, len(coords))
	for _, c := range coords {
		out[c] = struct{}{}
	}
	return out
}

// TestPinRequires_PinsEveryImportToTheVersionTheBuildResolved is the feature in
// one assertion: the versions written into a synthesised go.mod are the ones the
// requesting build already selected, so the resulting graph names coordinates the
// rest of the ledger also holds.
func TestPinRequires_PinsEveryImportToTheVersionTheBuildResolved(t *testing.T) {
	target := mustCoordinate(t, "github.com/example/sprigalike", "v2.22.0+incompatible")
	pinned, unpinned := domain.PinRequires(
		target,
		[]string{"github.com/example/mergo", "github.com/example/xstrings/pkg"},
		domain.AnalysisInputs{
			BuildList: buildListOf(t,
				mustCoordinate(t, "github.com/example/mergo", "v0.3.16"),
				mustCoordinate(t, "github.com/example/xstrings", "v1.4.0"),
				mustCoordinate(t, "github.com/example/unrelated", "v9.9.9"),
			),
			Source: "01WALK",
		},
	)
	if len(unpinned) != 0 {
		t.Fatalf("imports left unpinned: %v", unpinned)
	}
	want := []domain.SynthesisedRequire{
		{Path: "github.com/example/mergo", Version: "v0.3.16"},
		{Path: "github.com/example/xstrings", Version: "v1.4.0"},
	}
	if len(pinned) != len(want) {
		t.Fatalf("pinned %+v, want %+v", pinned, want)
	}
	for i := range want {
		if pinned[i] != want[i] {
			t.Errorf("require %d = %+v, want %+v", i, pinned[i], want[i])
		}
	}
	// The control that must be non-zero in the other direction: a build-list entry
	// nothing imported contributes no require, so the load is not made to resolve
	// the whole graph for one module.
	for _, r := range pinned {
		if r.Path == "github.com/example/unrelated" {
			t.Error("a module the target never imports was written into its go.mod")
		}
	}
}

// TestPinRequires_RefusesEverythingWhenOneImportCannotBePinned pins the
// all-or-nothing rule. A file naming two of three dependencies still sends the
// loader to whatever is latest for the third, which is the outcome refusing
// exists to prevent — so a partial pin is not a partial answer.
func TestPinRequires_RefusesEverythingWhenOneImportCannotBePinned(t *testing.T) {
	target := mustCoordinate(t, "example.com/premod", "v1.0.0")
	pinned, unpinned := domain.PinRequires(
		target,
		[]string{"github.com/example/mergo", "github.com/example/absent"},
		domain.AnalysisInputs{
			BuildList: buildListOf(t, mustCoordinate(t, "github.com/example/mergo", "v0.3.16")),
			Source:    "01WALK",
		},
	)
	if len(pinned) != 0 {
		t.Errorf("wrote %d require(s) for a module one of whose imports could not be pinned: %+v", len(pinned), pinned)
	}
	if len(unpinned) != 1 || unpinned[0] != "github.com/example/absent" {
		t.Errorf("unpinned = %v, want exactly the import the build list does not provide", unpinned)
	}
}

// TestPinRequires_WithoutABuildListRefusesExactlyAsBefore is the no-regression
// control: the zero inputs are what a coordinate asked about on its own carries,
// and such a request must behave as it did before build lists existed.
func TestPinRequires_WithoutABuildListRefusesExactlyAsBefore(t *testing.T) {
	target := mustCoordinate(t, "example.com/premod", "v1.0.0")
	pinned, unpinned := domain.PinRequires(target, []string{"github.com/example/mergo"}, domain.AnalysisInputs{})
	if len(pinned) != 0 {
		t.Errorf("pinned %+v from no build list at all", pinned)
	}
	if len(unpinned) != 1 {
		t.Errorf("unpinned = %v, want the one import that could not be pinned", unpinned)
	}
}

// TestPinRequires_HighestVersionWinsForARepeatedPath pins the rule a build list
// forces: a replaced node is recorded alongside the coordinate it stands in for,
// so one path can appear twice, and go.mod admits one require per path.
func TestPinRequires_HighestVersionWinsForARepeatedPath(t *testing.T) {
	target := mustCoordinate(t, "example.com/premod", "v1.0.0")
	pinned, unpinned := domain.PinRequires(
		target,
		[]string{"github.com/example/mergo"},
		domain.AnalysisInputs{
			BuildList: buildListOf(t,
				mustCoordinate(t, "github.com/example/mergo", "v0.3.16"),
				mustCoordinate(t, "github.com/example/mergo", "v0.3.12"),
			),
			Source: "01WALK",
		},
	)
	if len(unpinned) != 0 {
		t.Fatalf("unpinned: %v", unpinned)
	}
	if len(pinned) != 1 || pinned[0].Version != "v0.3.16" {
		t.Errorf("pinned = %+v, want a single require at v0.3.16", pinned)
	}
}

// TestPinnedAnalysisSupersedes_TheCachedFailureThatMustNotBeServed states each
// case of the cache decision, so a change to it has to change this table.
func TestPinnedAnalysisSupersedes_TheCachedFailureThatMustNotBeServed(t *testing.T) {
	dep := mustCoordinate(t, "github.com/example/mergo", "v0.3.16")
	withList := domain.AnalysisInputs{
		BuildList: buildListOf(t, dep),
		Source:    "01WALKB",
	}
	moduleFault := domain.CallGraphRecord{
		OverallStatus: domain.CallGraphStatusLoadFailed,
		Completeness:  domain.CompletenessMetadataOnly,
		FailureCause:  domain.FailureCauseModule,
	}

	cases := []struct {
		name     string
		existing domain.CallGraphRecord
		inputs   domain.AnalysisInputs
		want     bool
	}{
		{
			name:     "a module fault from before any build list is re-derivable",
			existing: moduleFault,
			inputs:   withList,
			want:     true,
		},
		{
			name:     "the same failure is served when the request brings nothing new",
			existing: moduleFault,
			inputs:   domain.AnalysisInputs{},
			want:     false,
		},
		{
			name: "a failure already offered this build list is served",
			existing: func() domain.CallGraphRecord {
				r := moduleFault
				r.BuildListSource = withList.Source
				return r
			}(),
			inputs: withList,
			want:   false,
		},
		{
			name: "a failure offered a DIFFERENT build list is not re-derived again",
			existing: func() domain.CallGraphRecord {
				r := moduleFault
				r.BuildListSource = "01WALKA"
				return r
			}(),
			inputs: withList,
			want:   false,
		},
		{
			name: "a graph pinned by another build list answers a different question",
			existing: domain.CallGraphRecord{
				OverallStatus:   domain.CallGraphStatusExtracted,
				Completeness:    domain.CompletenessBuiltWithBodies,
				BuildListSource: "01WALKA",
				SynthesisedGoMod: domain.SynthesisedGoMod{
					ModulePath:  "example.com/premod",
					GoDirective: "1.16",
					Requires:    []domain.SynthesisedRequire{{Path: dep.Path(), Version: "v0.3.12"}},
				},
			},
			inputs: withList,
			want:   true,
		},
		{
			name: "an ordinary extracted record is never re-derived",
			existing: domain.CallGraphRecord{
				OverallStatus: domain.CallGraphStatusExtracted,
				Completeness:  domain.CompletenessBuiltWithBodies,
			},
			inputs: withList,
			want:   false,
		},
		{
			name: "a module excluded by config is not a failure to re-derive",
			existing: domain.CallGraphRecord{
				OverallStatus: domain.CallGraphStatusExcludedByConfig,
				Completeness:  domain.CompletenessUnknown,
			},
			inputs: withList,
			want:   false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := domain.PinnedAnalysisSupersedes(tc.existing, tc.inputs); got != tc.want {
				t.Errorf("PinnedAnalysisSupersedes = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestSynthesisedGoMod_PinnedRequiresDecideTheGraphDigest is the identity claim:
// two analyses of the same bytes pinned to different versions are two different
// graphs, and the digest has to say so or the ledger composes them into one.
func TestSynthesisedGoMod_PinnedRequiresDecideTheGraphDigest(t *testing.T) {
	base := domain.CallGraphRecord{
		SchemaVersion: domain.CallGraphSchemaVersion,
		Coordinate:    mustCoordinate(t, "example.com/premod", "v1.0.0"),
		Algorithm:     domain.AlgorithmCHA,
		OverallStatus: domain.CallGraphStatusExtracted,
		SynthesisedGoMod: domain.SynthesisedGoMod{
			ModulePath:  "example.com/premod",
			GoDirective: "1.16",
			Requires:    []domain.SynthesisedRequire{{Path: "github.com/example/mergo", Version: "v0.3.16"}},
		},
	}
	other := base
	other.SynthesisedGoMod.Requires = []domain.SynthesisedRequire{
		{Path: "github.com/example/mergo", Version: "v0.3.12"},
	}
	if domain.GraphDigest(base) == domain.GraphDigest(other) {
		t.Error("two graphs pinned to different versions share a digest; the ledger would treat " +
			"them as agreeing measurements of one thing")
	}

	// The control in the other direction: WHICH walk supplied identical pins is
	// provenance, not claim, and must not split one graph into two.
	sameGraph := base
	sameGraph.BuildListSource = "01WALKA"
	otherWalk := base
	otherWalk.BuildListSource = "01WALKB"
	if domain.GraphDigest(sameGraph) != domain.GraphDigest(otherWalk) {
		t.Error("identical pins from two walks produced different graph digests; the walk " +
			"identifier is provenance and must be cleared before comparison")
	}
}
