package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"

	cgsqlite "github.com/eitanity/kanonarion/internal/callgraph/adapters/store/sqlite"
	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// disclosureCoord is the coordinate every case here holds generations of.
var disclosureCoord = coordinatetest.MustNew("example.com/mod", "v1.2.3")

// generationSpec is one row of the ledger as these tests need to state it: when
// it was written, which library parsed it, and at which record schema.
type generationSpec struct {
	at       time.Time
	analyser cgdomain.AnalyserVersion
	schema   string
	callee   string
}

// disclosureStore writes the given generations to a real SQLite store, through
// the real write leg, and returns a use case reading them back.
//
// A real store rather than a fake, because the fact under test is produced by
// the store: decodeRecord drops a row at a superseded record schema, and the
// column listing does not, because schema_version lives inside the blob. A fake
// that modelled the two listings as agreeing would pass whatever the CLI did.
func disclosureStore(t *testing.T, specs ...generationSpec) *cgapp.QueryCallGraphUseCase {
	t.Helper()
	store, err := cgsqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if cerr := store.Close(); cerr != nil {
			t.Errorf("Close: %v", cerr)
		}
	})
	for _, spec := range specs {
		if err := store.PutCallGraphRecord(context.Background(), disclosureRecord(t, spec)); err != nil {
			t.Fatalf("PutCallGraphRecord: %v", err)
		}
	}
	return cgapp.NewQueryCallGraphUseCase(store)
}

func disclosureRecord(t *testing.T, spec generationSpec) cgdomain.CallGraphRecord {
	t.Helper()
	schema := spec.schema
	if schema == "" {
		schema = cgdomain.CallGraphSchemaVersion
	}
	callee := spec.callee
	if callee == "" {
		callee = "example.com/mod.Bar"
	}
	r := cgdomain.CallGraphRecord{
		SchemaVersion:  schema,
		Ecosystem:      fetchdomain.EcosystemGo,
		Coordinate:     disclosureCoord,
		Algorithm:      cgdomain.AlgorithmCHA,
		Completeness:   cgdomain.CompletenessBuiltWithBodies,
		AnalysisSource: cgdomain.AnalysisSourceModuleZip,
		Nodes: []cgdomain.CallNode{
			{ID: "example.com/mod.Foo", Package: "example.com/mod", Symbol: "Foo"},
		},
		Edges: []cgdomain.CallEdge{
			{
				FromID:     "example.com/mod.Foo",
				ToID:       callee,
				CallSite:   cgdomain.SourcePosition{File: "foo.go", Line: 10},
				Confidence: cgdomain.ConfidenceDirect,
			},
		},
		OverallStatus:    cgdomain.CallGraphStatusExtracted,
		ArtefactIdentity: "zip:h1:a",
		NodeCount:        1,
		EdgeCount:        1,
		ExtractedAt:      spec.at,
		PipelineVersion:  cgapp.PipelineVersion,
		Analyser:         cgdomain.ObservedAnalyser(spec.analyser),
	}
	var h cgdomain.CallGraphRecordHasher
	sealed, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	return sealed
}

// mixedSchemaStore is the subject: one coordinate, two generations at the served
// pipeline version, parsed by different libraries, one of them written at a
// record schema this build no longer decodes.
func mixedSchemaStore(t *testing.T) *cgapp.QueryCallGraphUseCase {
	t.Helper()
	return disclosureStore(t,
		generationSpec{at: time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC), analyser: "v0.47.0", schema: "9"},
		generationSpec{at: time.Date(2026, 1, 1, 11, 0, 0, 0, time.UTC), analyser: "v0.49.0"},
	)
}

func historyOutput(t *testing.T, uc QueryCallGraphUseCase, coord coordinate.ModuleCoordinate) string {
	t.Helper()
	var buf bytes.Buffer
	if err := runCallGraphHistory(context.Background(), coord, uc, &buf); err != nil {
		t.Fatalf("runCallGraphHistory: %v", err)
	}
	return buf.String()
}

// TestCallGraphHistory_EveryAnalyserTheNoticeNamesIsFindable is the property.
//
// The disagreement notice on a composed read speaks from the column listing,
// which has no schema filter; --history speaks from the reading leg, which drops
// a row at a superseded record schema. Where those two disagree about which
// generations exist, the notice sends an operator to a view that silently omits
// one of the versions it just named. The assertion is the property, not the
// wording: every version the notice names must be findable through --history.
func TestCallGraphHistory_EveryAnalyserTheNoticeNamesIsFindable(t *testing.T) {
	uc := mixedSchemaStore(t)
	ctx := context.Background()

	served, found, err := uc.GetCallGraphRecordFrom(ctx, disclosureCoord, cgapp.PipelineVersion, cgdomain.ComposeRequest{})
	if err != nil {
		t.Fatalf("GetCallGraphRecordFrom: %v", err)
	}
	if !found {
		t.Fatal("no generation was served: the subject must hold one servable generation")
	}
	disagreement, disagrees, err := analyserDisagreement(ctx, disclosureCoord, served, uc)
	if err != nil {
		t.Fatalf("analyserDisagreement: %v", err)
	}
	if !disagrees {
		t.Fatal("the subject states no analyser disagreement: it cannot exercise the property")
	}

	history := historyOutput(t, uc, disclosureCoord)
	for _, id := range disagreement.Identities {
		if !strings.Contains(history, string(id.Version)) {
			t.Errorf("the notice names %s, which --history does not mention:\n%s", id.Version, history)
		}
	}
}

// TestCallGraphHistory_SaysWhyAGenerationIsNotListed: naming the version is not
// enough on its own. A version that appeared with no reason beside it would read
// as a listing defect rather than as a record this build has stopped serving,
// and the operator would have no remedy.
func TestCallGraphHistory_SaysWhyAGenerationIsNotListed(t *testing.T) {
	history := historyOutput(t, mixedSchemaStore(t), disclosureCoord)
	for _, want := range []string{
		"record schema",
		"v0.47.0",
		"kanonarion callgraph example.com/mod@v1.2.3",
	} {
		if !strings.Contains(history, want) {
			t.Errorf("--history does not state %q:\n%s", want, history)
		}
	}
	// The served generation is still listed in full: the disclosure is an
	// addition to the view, never a replacement for it.
	if !strings.Contains(history, "1 generation(s) for example.com/mod@v1.2.3") {
		t.Errorf("--history stopped listing the generation it serves:\n%s", history)
	}
}

// TestCallGraphHistory_AllServableGainsNoLine is the control. A store every
// generation of which this build decodes has nothing to disclose, so the view
// must be exactly what it was — including where the generations name different
// analysers, which is the case that exercises the notice without exercising the
// schema gate.
func TestCallGraphHistory_AllServableGainsNoLine(t *testing.T) {
	for _, tc := range []struct {
		name  string
		specs []generationSpec
	}{
		{"one binary", []generationSpec{
			{at: time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC), analyser: "v0.49.0"},
			{at: time.Date(2026, 1, 1, 11, 0, 0, 0, time.UTC), analyser: "v0.49.0", callee: "example.com/mod.Baz"},
		}},
		{"analysers differ", []generationSpec{
			{at: time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC), analyser: "v0.47.0"},
			{at: time.Date(2026, 1, 1, 11, 0, 0, 0, time.UTC), analyser: "v0.49.0", callee: "example.com/mod.Baz"},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			history := historyOutput(t, disclosureStore(t, tc.specs...), disclosureCoord)
			if strings.Contains(history, "not listed above") {
				t.Errorf("a fully servable coordinate gained a disclosure line:\n%s", history)
			}
			if !strings.Contains(history, "2 generation(s) for example.com/mod@v1.2.3") {
				t.Errorf("--history did not list both generations:\n%s", history)
			}
		})
	}
}

// TestCallGraphHistory_AllUnservableSchemaSaysWhy: where NOTHING at the served
// pipeline version decodes, the view must still separate "never held" from
// "held and no longer served". That is the rule this view already states for
// itself, and before this it held only for a superseded pipeline version.
func TestCallGraphHistory_AllUnservableSchemaSaysWhy(t *testing.T) {
	uc := disclosureStore(t,
		generationSpec{at: time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC), analyser: "v0.47.0", schema: "9"},
		generationSpec{at: time.Date(2026, 1, 1, 11, 0, 0, 0, time.UTC), analyser: "v0.49.0", schema: "9", callee: "example.com/mod.Baz"},
	)
	history := historyOutput(t, uc, disclosureCoord)
	for _, want := range []string{
		"no callgraph records for example.com/mod@v1.2.3",
		"record schema",
		"v0.47.0",
		"v0.49.0",
		"kanonarion callgraph example.com/mod@v1.2.3",
	} {
		if !strings.Contains(history, want) {
			t.Errorf("--history does not state %q:\n%s", want, history)
		}
	}
}

// TestCallGraphHistory_NeverHeldSaysSo is the falsifying companion: a
// coordinate the store has never held must not acquire a disclosure about
// generations that do not exist.
func TestCallGraphHistory_NeverHeldSaysSo(t *testing.T) {
	history := historyOutput(t, disclosureStore(t), disclosureCoord)
	if strings.Contains(history, "record schema") || strings.Contains(history, "not listed above") {
		t.Errorf("a coordinate the store never held was described as no longer served:\n%s", history)
	}
	if !strings.Contains(history, "no callgraph records for example.com/mod@v1.2.3") {
		t.Errorf("--history does not report the absence:\n%s", history)
	}
}
