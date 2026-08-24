package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	coordinatetest "github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

func diffGeneration(t *testing.T, coord coordinate.ModuleCoordinate, buildList string, at time.Time, nodes []cgdomain.CallNode) cgdomain.CallGraphRecord {
	t.Helper()
	r := cgdomain.CallGraphRecord{
		SchemaVersion:    cgdomain.CallGraphSchemaVersion,
		Ecosystem:        fetchdomain.EcosystemGo,
		Coordinate:       coord,
		Algorithm:        cgdomain.AlgorithmCHA,
		Completeness:     cgdomain.CompletenessBuiltWithBodies,
		AnalysisSource:   cgdomain.AnalysisSourceModuleZip,
		ArtefactIdentity: "zip:h1:a",
		BuildListSource:  buildList,
		Nodes:            nodes,
		NodeCount:        len(nodes),
		OverallStatus:    cgdomain.CallGraphStatusExtracted,
		ExtractedAt:      at,
		PipelineVersion:  cgapp.PipelineVersion,
	}
	var h cgdomain.CallGraphRecordHasher
	sealed, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	return sealed
}

// TestCallGraphShowDiff_NamesTheInputRatherThanTwoDigests.
//
// --history prints a digest per generation, which says THAT two measurements
// differ. This is the read that says what about: the worked case is two
// generations whose graphs are identical and whose build lists are not, and the
// answer has to be the build list.
func TestCallGraphShowDiff_NamesTheInputRatherThanTwoDigests(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	coord := coordinatetest.MustNew("example.com/mod", "v1.0.0")
	nodes := []cgdomain.CallNode{
		{ID: "example.com/mod.Foo", Symbol: "Foo", Package: "example.com/mod"},
	}
	older := diffGeneration(t, coord, "walk-a", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), nodes)
	newer := diffGeneration(t, coord, "walk-b", time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC), nodes)
	uc.AddGeneration(coord, cgapp.PipelineVersion, older)
	uc.AddGeneration(coord, cgapp.PipelineVersion, newer)

	var buf bytes.Buffer
	flags := callGraphShowFlags{diff: true, limitNodes: 50, limitEdges: 100}
	if err := runCallGraphShow(context.Background(), "example.com/mod@v1.0.0", flags, false, uc, &buf); err != nil {
		t.Fatalf("runCallGraphShow --diff: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"2 distinct measurement(s) and 1 distinct graph(s)",
		"the graphs agree; the generations differ in what they were asked",
		"build_list_source",
		"walk-a",
		"walk-b",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("--diff output does not contain %q:\n%s", want, out)
		}
	}
}

// TestCallGraphShowDiff_ListsTheMembersThatDiffer: where the graphs genuinely
// differ, the reader is handed the symbols rather than a count.
func TestCallGraphShowDiff_ListsTheMembersThatDiffer(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	coord := coordinatetest.MustNew("example.com/mod", "v1.0.0")
	base := []cgdomain.CallNode{{ID: "example.com/mod.Foo", Symbol: "Foo", Package: "example.com/mod"}}
	grown := append(append([]cgdomain.CallNode(nil), base...),
		cgdomain.CallNode{ID: "vendor/x/idna.isASCII", Symbol: "isASCII", Package: "vendor/x/idna", IsExternal: true})
	uc.AddGeneration(coord, cgapp.PipelineVersion,
		diffGeneration(t, coord, "walk-a", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), base))
	uc.AddGeneration(coord, cgapp.PipelineVersion,
		diffGeneration(t, coord, "walk-a", time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC), grown))

	var buf bytes.Buffer
	flags := callGraphShowFlags{diff: true, limitNodes: 50, limitEdges: 100}
	if err := runCallGraphShow(context.Background(), "example.com/mod@v1.0.0", flags, false, uc, &buf); err != nil {
		t.Fatalf("runCallGraphShow --diff: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "+ vendor/x/idna.isASCII") {
		t.Errorf("--diff does not name the node only one generation reached:\n%s", out)
	}
	if !strings.Contains(out, "0 only in left, 1 only in right") {
		t.Errorf("--diff does not count the membership difference:\n%s", out)
	}
}

// TestCallGraphShowDiff_NothingToCompare: one measurement, however many times it
// was recorded, is not a disagreement — and saying so is what stops a reader
// reading a re-analysis as a second answer.
func TestCallGraphShowDiff_NothingToCompare(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	coord := coordinatetest.MustNew("example.com/mod", "v1.0.0")
	nodes := []cgdomain.CallNode{{ID: "example.com/mod.Foo", Symbol: "Foo", Package: "example.com/mod"}}
	uc.AddGeneration(coord, cgapp.PipelineVersion,
		diffGeneration(t, coord, "walk-a", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), nodes))
	uc.AddGeneration(coord, cgapp.PipelineVersion,
		diffGeneration(t, coord, "walk-a", time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC), nodes))

	var buf bytes.Buffer
	flags := callGraphShowFlags{diff: true, limitNodes: 50, limitEdges: 100}
	if err := runCallGraphShow(context.Background(), "example.com/mod@v1.0.0", flags, false, uc, &buf); err != nil {
		t.Fatalf("runCallGraphShow --diff: %v", err)
	}
	if !strings.Contains(buf.String(), "all stating the same measurement") {
		t.Errorf("--diff over one measurement does not say so:\n%s", buf.String())
	}
}
