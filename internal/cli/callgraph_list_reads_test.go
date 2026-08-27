package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
)

const listModule = "example.com/reanalysed"

// listGeneration builds one generation of listModule with counts of its own, so
// a row that reported another generation's numbers is visible in the output.
func listGeneration(at time.Time, status cgdomain.CallGraphStatus, nodes, edges int, hash string) cgdomain.CallGraphRecord {
	return cgdomain.CallGraphRecord{
		Coordinate:      coordinatetest.MustNew(listModule, "v1.0.0"),
		Algorithm:       cgdomain.AlgorithmCHA,
		Completeness:    cgdomain.CompletenessBuiltWithBodies,
		AnalysisSource:  cgdomain.AnalysisSourceModuleZip,
		OverallStatus:   status,
		NodeCount:       nodes,
		EdgeCount:       edges,
		ExtractedAt:     at,
		PipelineVersion: cgapp.PipelineVersion,
		ContentHash:     hash,
	}
}

// fakeWithGenerations stages one coordinate holding three generations that
// disagree about their counts.
func fakeWithGenerations() *testfakes.FakeQueryCallGraph {
	uc := testfakes.NewFakeQueryCallGraph()
	uc.SetList([]cgports.CallGraphSummary{{
		ModulePath: listModule, ModuleVersion: "v1.0.0",
		PipelineVersion: cgapp.PipelineVersion,
	}})
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	coord := coordinatetest.MustNew(listModule, "v1.0.0")
	uc.AddGeneration(coord, cgapp.PipelineVersion, listGeneration(base, cgdomain.CallGraphStatusPartial, 10, 11, "sha256:oldest"))
	uc.AddGeneration(coord, cgapp.PipelineVersion, listGeneration(base.Add(time.Hour), cgdomain.CallGraphStatusExtracted, 20, 22, "sha256:middle"))
	uc.AddGeneration(coord, cgapp.PipelineVersion, listGeneration(base.Add(2*time.Hour), cgdomain.CallGraphStatusExtracted, 30, 33, "sha256:newest"))
	return uc
}

// fakeWithAgreeingGenerations stages the same coordinate holding three
// generations that state the SAME counts, status and completeness — the same
// history without the disagreement, so a test can tell the two apart.
func fakeWithAgreeingGenerations() *testfakes.FakeQueryCallGraph {
	uc := testfakes.NewFakeQueryCallGraph()
	uc.SetList([]cgports.CallGraphSummary{{
		ModulePath: listModule, ModuleVersion: "v1.0.0",
		PipelineVersion: cgapp.PipelineVersion,
	}})
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	coord := coordinatetest.MustNew(listModule, "v1.0.0")
	for i, hash := range []string{"sha256:oldest", "sha256:middle", "sha256:newest"} {
		uc.AddGeneration(coord, cgapp.PipelineVersion, listGeneration(
			base.Add(time.Duration(i)*time.Hour), cgdomain.CallGraphStatusExtracted, 30, 33, hash))
	}
	return uc
}

// TestCallGraphList_ListsCoordinatesNeverComposedSummaries pins the read the
// listing is allowed to make.
//
// Every field it prints is a column on the record table. The summary listing
// answers the different question "what does the served generation say", and for
// a coordinate holding more than one generation that means composing them — a
// blob decode plus a full reconstruction of each generation's edge set, to read
// eight scalars off the winner. On a real ledger that was the entire cost of
// the command, and none of it reached the output.
func TestCallGraphList_ListsCoordinatesNeverComposedSummaries(t *testing.T) {
	for _, jsonMode := range []bool{false, true} {
		name := "text"
		if jsonMode {
			name = "json"
		}
		t.Run(name, func(t *testing.T) {
			restore := jsonOut
			jsonOut = jsonMode
			t.Cleanup(func() { jsonOut = restore })

			uc := fakeWithGenerations()
			var buf bytes.Buffer
			if err := runCallGraphList(context.Background(), "", 20, 0, uc, &buf, &bytes.Buffer{}); err != nil {
				t.Fatalf("runCallGraphList: %v", err)
			}
			if uc.ListCalls != 0 {
				t.Errorf("the composing summary listing was read %d time(s); a listing reads columns", uc.ListCalls)
			}
			if uc.CoordinateListCalls == 0 {
				t.Error("no coordinate listing was read at all; the rows have to come from somewhere")
			}
			if uc.RecordReads != 0 {
				t.Errorf("%d record(s) were composed to print a listing", uc.RecordReads)
			}
		})
	}
}

// TestCallGraphList_ZeroResultNoticeComposesNothing is the same rule on the
// path that costs most: a listing that matched nothing re-asks the store how
// many records it holds at all, and asked of the composing listing that made
// the emptiest possible answer the most expensive one.
func TestCallGraphList_ZeroResultNoticeComposesNothing(t *testing.T) {
	uc := fakeWithGenerations()
	var buf bytes.Buffer
	if err := runCallGraphList(context.Background(), "example.com/absent", 20, 0, uc, &buf, &bytes.Buffer{}); err != nil {
		t.Fatalf("runCallGraphList: %v", err)
	}
	if !strings.Contains(buf.String(), "example.com/absent") {
		t.Errorf("the zero notice does not name the filter that matched nothing: %q", buf.String())
	}
	if uc.ListCalls != 0 {
		t.Errorf("the composing summary listing was read %d time(s) to count what the store holds", uc.ListCalls)
	}
}

// TestCallGraphShow_SupersededNoteComposesNothing pins the same rule on
// callgraph-show's not-found path. Which pipeline versions a coordinate exists
// under is a question about the ledger's keys; asked of the composing listing
// it reconstructed every generation of every version of the module to say that
// a version nobody analysed was not analysed.
func TestCallGraphShow_SupersededNoteComposesNothing(t *testing.T) {
	uc := fakeWithGenerations()
	note, err := supersededGenerationsNote(context.Background(),
		coordinatetest.MustNew(listModule, "v9.9.9"), uc)
	if err != nil {
		t.Fatalf("supersededGenerationsNote: %v", err)
	}
	if note != "" {
		t.Errorf("note = %q, want none: every generation is at the serving pipeline version", note)
	}
	if uc.ListCalls != 0 {
		t.Errorf("the composing summary listing was read %d time(s) to read pipeline versions", uc.ListCalls)
	}
}

// TestCallGraphList_DifferingGenerationsStateThatInsteadOfACount is the
// falsifying case.
//
// Three analyses that state different counts have no count the row may put
// forward as the coordinate's. Which one a read serves is decided by
// composition — over decoded records, which this listing does not read — so a
// row that printed the newest generation's numbers would be answering a
// question it did not ask. It says the generations differ and names the command
// that shows them.
func TestCallGraphList_DifferingGenerationsStateThatInsteadOfACount(t *testing.T) {
	uc := fakeWithGenerations()
	coords, err := uc.ListCallGraphCoordinates(context.Background(), cgports.CallGraphFilter{})
	if err != nil {
		t.Fatalf("ListCallGraphCoordinates: %v", err)
	}
	if len(coords) != 1 || !coords[0].GenerationsDiffer {
		t.Fatalf("GenerationsDiffer = %v for generations stating 10/20/30 nodes, want true", coords)
	}

	var buf bytes.Buffer
	if err := runCallGraphList(context.Background(), "", 20, 0, uc, &buf, &bytes.Buffer{}); err != nil {
		t.Fatalf("runCallGraphList: %v", err)
	}
	out := buf.String()
	if lines := strings.Count(out, "\n"); lines != 1 {
		t.Errorf("the coordinate rendered as %d lines, want 1:\n%s", lines, out)
	}
	if !strings.Contains(out, "3 generations state different counts, status or completeness") {
		t.Errorf("the row does not say the generations disagree: %q", out)
	}
	if !strings.Contains(out, "kanonarion callgraph-show "+listModule+"@v1.0.0 --history") {
		t.Errorf("the row does not name the command that shows the generations: %q", out)
	}
	for _, n := range []string{"10 nodes", "20 nodes", "30 nodes"} {
		if strings.Contains(out, n) {
			t.Errorf("the row presents %s as the coordinate's own count: %q", n, out)
		}
	}
	// The listing cannot know composition's verdict, so it must not speak in its
	// vocabulary: a coordinate whose generations differ may still compose.
	for _, w := range []string{"conflict", "refus", "unavailable"} {
		if strings.Contains(strings.ToLower(out), w) {
			t.Errorf("the row says %q, which is composition's verdict and not what a column proves: %q", w, out)
		}
	}
}

// TestCallGraphList_AgreeingGenerationsKeepTheirCounts is the control that
// keeps the flag from degenerating into "has history".
//
// Three analyses that state the same counts have a count the row may print: it
// is every generation's, whichever one a read serves. The row prints it and
// names the generation it was read off, exactly as before.
func TestCallGraphList_AgreeingGenerationsKeepTheirCounts(t *testing.T) {
	uc := fakeWithAgreeingGenerations()
	coords, err := uc.ListCallGraphCoordinates(context.Background(), cgports.CallGraphFilter{})
	if err != nil {
		t.Fatalf("ListCallGraphCoordinates: %v", err)
	}
	if len(coords) != 1 || coords[0].GenerationsDiffer {
		t.Fatalf("GenerationsDiffer = %v for three generations stating identical counts, want false", coords)
	}

	var buf bytes.Buffer
	if err := runCallGraphList(context.Background(), "", 20, 0, uc, &buf, &bytes.Buffer{}); err != nil {
		t.Fatalf("runCallGraphList: %v", err)
	}
	out := buf.String()
	if lines := strings.Count(out, "\n"); lines != 1 {
		t.Errorf("the coordinate rendered as %d lines, want 1:\n%s", lines, out)
	}
	for _, want := range []string{
		"Extracted    30 nodes    33 edges",
		"[3 generations; counts from 2026-01-01T02:00:00Z]",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the row does not contain %q: %q", want, out)
		}
	}
}

// TestCallGraphList_SingleGenerationRowIsUnchanged is the control. One
// generation is the served generation, so naming it would state something the
// reader can already see — the row is the line it has always been, and nothing
// about a re-analysed coordinate leaks into a coordinate that was analysed once.
func TestCallGraphList_SingleGenerationRowIsUnchanged(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	uc.SetList([]cgports.CallGraphSummary{{
		ModulePath: "example.com/once", ModuleVersion: "v1.0.0",
		PipelineVersion: cgapp.PipelineVersion,
		OverallStatus:   cgdomain.CallGraphStatusExtracted,
		NodeCount:       5, EdgeCount: 8,
	}})
	var buf bytes.Buffer
	if err := runCallGraphList(context.Background(), "", 20, 0, uc, &buf, &bytes.Buffer{}); err != nil {
		t.Fatalf("runCallGraphList: %v", err)
	}
	const want = "example.com/once@v1.0.0                                      " +
		cgapp.PipelineVersion + "        Extracted     5 nodes     8 edges\n"
	if buf.String() != want {
		t.Errorf("row rendered as\n%q\nwant\n%q", buf.String(), want)
	}
}

// TestCallGraphList_JSONSingleGenerationKeepsItsShape is the same control on
// the parsed surface: a coordinate with one analysis carries its counts and
// none of the multi-generation fields. generations_differ is there and false —
// one generation cannot disagree with itself, and a flag emitted only when true
// would make "they agree" and "this build does not derive it" the same bytes.
func TestCallGraphList_JSONSingleGenerationKeepsItsShape(t *testing.T) {
	restore := jsonOut
	jsonOut = true
	t.Cleanup(func() { jsonOut = restore })

	uc := testfakes.NewFakeQueryCallGraph()
	uc.SetList([]cgports.CallGraphSummary{{
		ModulePath: "example.com/once", ModuleVersion: "v1.0.0",
		PipelineVersion: cgapp.PipelineVersion,
		OverallStatus:   cgdomain.CallGraphStatusExtracted,
		NodeCount:       5, EdgeCount: 8,
	}})
	var buf bytes.Buffer
	if err := runCallGraphList(context.Background(), "", 20, 0, uc, &buf, &bytes.Buffer{}); err != nil {
		t.Fatalf("runCallGraphList: %v", err)
	}
	var got []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("decoding listing: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("entries = %d, want 1", len(got))
	}
	want := map[string]any{
		"module": "example.com/once", "version": "v1.0.0",
		"pipeline_version": cgapp.PipelineVersion, "status": "Extracted",
		"node_count": float64(5), "edge_count": float64(8),
		"generations_differ": false,
	}
	if len(got[0]) != len(want) {
		t.Errorf("entry has fields %v, want exactly %v", got[0], want)
	}
	for k, v := range want {
		if got[0][k] != v {
			t.Errorf("%s = %v, want %v", k, got[0][k], v)
		}
	}
}

// TestCallGraphList_JSONDifferingGenerationsStateNoHeadlineCount is the same
// pair on the parsed surface, which carries more detail and no different fact:
// the generations array stays, because an agent without it pays one extra
// invocation per coordinate to rebuild what this call already read, and a
// terminal page is the only thing the per-generation lines cost.
func TestCallGraphList_JSONDifferingGenerationsStateNoHeadlineCount(t *testing.T) {
	restore := jsonOut
	jsonOut = true
	t.Cleanup(func() { jsonOut = restore })

	var buf bytes.Buffer
	if err := runCallGraphList(context.Background(), "", 20, 0, fakeWithGenerations(), &buf, &bytes.Buffer{}); err != nil {
		t.Fatalf("runCallGraphList: %v", err)
	}
	var got []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("decoding listing: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("entries = %d, want 1", len(got))
	}
	e := got[0]
	if e["generations_differ"] != true {
		t.Errorf("generations_differ = %v, want true", e["generations_differ"])
	}
	// Stated as null, not left out: "no count is stated here" and "this build
	// does not derive counts" must not be the same bytes.
	for _, k := range []string{"status", "node_count", "edge_count"} {
		v, present := e[k]
		if !present {
			t.Errorf("%s is absent; it must be stated as null", k)
		}
		if v != nil {
			t.Errorf("%s = %v is stated as the coordinate's own, and no generation's counts are", k, v)
		}
	}
	if _, present := e["counts_from"]; present {
		t.Errorf("counts_from = %v names a generation whose counts were not printed", e["counts_from"])
	}
	gens, ok := e["generations"].([]any)
	if !ok || len(gens) != 3 {
		t.Fatalf("generations = %v, want three entries", e["generations"])
	}
	wantCounts := []float64{30, 20, 10}
	for i, g := range gens {
		gm, gok := g.(map[string]any)
		if !gok {
			t.Fatalf("generation %d is %T, want an object", i, g)
		}
		if gm["node_count"] != wantCounts[i] {
			t.Errorf("generation %d node_count = %v, want %v", i, gm["node_count"], wantCounts[i])
		}
	}
}

// TestCallGraphList_JSONAgreeingGenerationsCarryTheirCounts is the control:
// where the generations agree the entry keeps the shape it always had, plus the
// history, and says nothing about disagreeing.
func TestCallGraphList_JSONAgreeingGenerationsCarryTheirCounts(t *testing.T) {
	restore := jsonOut
	jsonOut = true
	t.Cleanup(func() { jsonOut = restore })

	var buf bytes.Buffer
	if err := runCallGraphList(context.Background(), "", 20, 0, fakeWithAgreeingGenerations(), &buf, &bytes.Buffer{}); err != nil {
		t.Fatalf("runCallGraphList: %v", err)
	}
	var got []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("decoding listing: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("entries = %d, want 1", len(got))
	}
	e := got[0]
	if v, present := e["generations_differ"]; !present || v != false {
		t.Errorf("generations_differ = %v (present=%t) for generations stating identical counts, want false", v, present)
	}
	want := map[string]any{
		"status": "Extracted", "node_count": float64(30), "edge_count": float64(33),
		"counts_from": "2026-01-01T02:00:00Z",
	}
	for k, v := range want {
		if e[k] != v {
			t.Errorf("%s = %v, want %v", k, e[k], v)
		}
	}
	if gens, gok := e["generations"].([]any); !gok || len(gens) != 3 {
		t.Fatalf("generations = %v, want three entries", e["generations"])
	}
}

// noGenerationLister is a store seam that lists coordinates but cannot say what
// each generation holds — the shape the use case falls back to when the store
// is not a coordinate lister, where a composed summary is the only thing it
// could offer and offering it would state a composed answer as a row's own.
type noGenerationLister struct {
	*testfakes.FakeQueryCallGraph
}

func (n *noGenerationLister) ListCallGraphCoordinates(ctx context.Context, filter cgports.CallGraphFilter) ([]cgports.CallGraphCoordinate, error) {
	coords, err := n.FakeQueryCallGraph.ListCallGraphCoordinates(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("listing coordinates: %w", err)
	}
	for i := range coords {
		coords[i].Generations = nil
	}
	return coords, nil
}

// TestCallGraphList_UnenumeratedGenerationsAreStatedNotZeroed pins the
// never-silent edge: a store that lists coordinates without enumerating their
// generations has no counts to print, and printing zeroes would read as a
// measured empty graph.
func TestCallGraphList_UnenumeratedGenerationsAreStatedNotZeroed(t *testing.T) {
	uc := &noGenerationLister{FakeQueryCallGraph: fakeWithGenerations()}
	var buf bytes.Buffer
	if err := runCallGraphList(context.Background(), "", 20, 0, uc, &buf, &bytes.Buffer{}); err != nil {
		t.Fatalf("runCallGraphList: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "no per-generation counts") {
		t.Errorf("the row does not state that the counts were not enumerated: %q", out)
	}
	if strings.Contains(out, "0 nodes") {
		t.Errorf("a coordinate with no enumerated generation was printed as a measured empty graph: %q", out)
	}
}
