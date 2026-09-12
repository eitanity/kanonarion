package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
)

// The shape the store actually holds: a record about the parent module that also
// carries a nested module's nodes, built with bodies under the parent's path
// prefix. github.com/bytedance/sonic@v1.15.1 is the measured exemplar — 504 of
// its external nodes belong to github.com/bytedance/sonic/loader, and 396 of
// those carry outgoing edges against 7 of 593 for every other external node.
const (
	foreignParent = "github.com/bytedance/sonic"
	foreignNested = "github.com/bytedance/sonic/loader"
	foreignTarget = "github.com/bytedance/sonic/internal/rt.MoreStack"
	foreignCaller = "github.com/bytedance/sonic/loader.(*Loader).LoadOne"
	ownCaller     = "github.com/bytedance/sonic/encoder.Encode"
)

// parentHoldingNested is the parent's record, stating the nested module it built
// with bodies at the version resolution gave it.
func parentHoldingNested() cgdomain.CallGraphRecord {
	rec := builtRecord([]cgdomain.CallNode{
		{ID: foreignTarget, Module: foreignParent, Package: "github.com/bytedance/sonic/internal/rt", Symbol: "MoreStack"},
		{ID: foreignCaller, Module: foreignNested, Package: foreignNested, Symbol: "LoadOne", IsExternal: true},
		{ID: ownCaller, Module: foreignParent, Package: "github.com/bytedance/sonic/encoder", Symbol: "Encode"},
	}, nil)
	rec.NodeCount = len(rec.Nodes)
	rec.ForeignModulesBuilt = []cgdomain.ForeignModule{{Path: foreignNested, Version: "v0.3.0"}}
	return rec
}

func edgeInto(fromID string) cgports.CallEdgeRef {
	return cgports.CallEdgeRef{
		ModulePath:      foreignParent,
		ModuleVersion:   "v1.15.1",
		PipelineVersion: cgapp.PipelineVersion,
		FromID:          fromID,
		ToID:            foreignTarget,
		Confidence:      cgdomain.ConfidenceDirect,
	}
}

// TestCallGraphShow_NamesForeignModulesBuiltWithBodies: the record holds another
// module's code built with bodies, and the axis says so beside test scope and
// reference scope — with the version, which is the half the record could not
// previously state.
func TestCallGraphShow_NamesForeignModulesBuiltWithBodies(t *testing.T) {
	var buf bytes.Buffer
	if err := printCallGraphRecord(parentHoldingNested(), 10, 10, &buf); err != nil {
		t.Fatalf("printCallGraphRecord: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"foreign modules built:", foreignNested + "@v0.3.0", "built with bodies"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

// TestCallGraphShow_SaysNothingWhenNoForeignModuleWasBuilt is the zero-paired
// control the ticket names. Of the four large parents measured on the store,
// three build no nested module at all — hashicorp/go-msgpack@v1.1.5 and
// aws-sdk-go-v2@v1.42.0 among them — and a line on those records would be noise
// on the overwhelming majority of the store.
func TestCallGraphShow_SaysNothingWhenNoForeignModuleWasBuilt(t *testing.T) {
	rec := builtRecord([]cgdomain.CallNode{{ID: "example.com/m.Root", Symbol: "Root"}}, nil)
	rec.NodeCount = len(rec.Nodes)

	var buf bytes.Buffer
	if err := printCallGraphRecord(rec, 10, 10, &buf); err != nil {
		t.Fatalf("printCallGraphRecord: %v", err)
	}
	if strings.Contains(buf.String(), "foreign modules built:") {
		t.Errorf("a record that built no foreign module still reported one:\n%s", buf.String())
	}
}

// TestCallGraphShowJSON_CarriesForeignModulesBuilt: a machine consumer reads the
// pair as fields. Absent means either "built none" or "predates the field", and
// schema_version is what separates those — so both must be present together.
func TestCallGraphShowJSON_CarriesForeignModulesBuilt(t *testing.T) {
	out := toCallGraphJSON(parentHoldingNested())
	if len(out.ForeignModulesBuilt) != 1 {
		t.Fatalf("foreign_modules_built = %+v, want one entry", out.ForeignModulesBuilt)
	}
	if out.ForeignModulesBuilt[0].Path != foreignNested || out.ForeignModulesBuilt[0].Version != "v0.3.0" {
		t.Errorf("foreign_modules_built[0] = %+v", out.ForeignModulesBuilt[0])
	}

	data, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshalling the record document: %v", err)
	}
	if !strings.Contains(string(data), `"foreign_modules_built"`) {
		t.Errorf("the emitted document does not name the key:\n%s", data)
	}
	if !strings.Contains(string(data), `"schema_version"`) {
		t.Error("the document omits schema_version, which is what tells absence from emptiness")
	}

	clean := toCallGraphJSON(builtRecord(nil, nil))
	data, err = json.Marshal(clean)
	if err != nil {
		t.Fatalf("marshalling the control document: %v", err)
	}
	if strings.Contains(string(data), `"foreign_modules_built"`) {
		t.Errorf("a record that built no foreign module emits the key:\n%s", data)
	}
}

// TestRunCallers_StatesAnAnswerDrawnFromAForeignModule: the misleading case.
// The caller returned is a node of a module the answering record is not about,
// held as a partial copy inside it, and the answer line says so with the version.
func TestRunCallers_StatesAnAnswerDrawnFromAForeignModule(t *testing.T) {
	uc := fakeWithRecord(foreignParent, "v1.15.1", cgapp.PipelineVersion, parentHoldingNested())
	uc.SetCallers([]cgports.CallEdgeRef{edgeInto(foreignCaller)})

	var buf bytes.Buffer
	if err := runCallers(context.Background(), foreignTarget, false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatalf("runCallers: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "answer: RESOLVED-PRESENT") {
		t.Fatalf("no answer line on an answer drawn from a foreign module:\n%s", out)
	}
	for _, want := range []string{
		"1 of 1 callers",
		foreignNested + "@v0.3.0",
		foreignParent + "@v1.15.1",
		"own record",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the answer line omits %q:\n%s", want, out)
		}
	}
}

// TestRunCallers_SaysNothingWhenTheAnswerIsTheModulesOwn is the other direction
// the ticket requires tested. The record holds a foreign module, but this
// answer's rows are the module's own nodes, so there is nothing to state and a
// statement would be a false narrowing.
func TestRunCallers_SaysNothingWhenTheAnswerIsTheModulesOwn(t *testing.T) {
	uc := fakeWithRecord(foreignParent, "v1.15.1", cgapp.PipelineVersion, parentHoldingNested())
	uc.SetCallers([]cgports.CallEdgeRef{edgeInto(ownCaller)})

	var buf bytes.Buffer
	if err := runCallers(context.Background(), foreignTarget, false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatalf("runCallers: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "answer:") {
		t.Errorf("an answer drawn from the module's own nodes carries an answer line:\n%s", out)
	}
	if !strings.Contains(out, ownCaller) {
		t.Errorf("the caller itself is missing from the answer:\n%s", out)
	}
}

// TestRunCallers_MixedAnswerCountsBothPopulations: the count is the point of the
// pair. "1 of 2" and "2 of 2" are different answers, and a reader deciding
// whether to re-ask against the nested module's own record needs to know which.
func TestRunCallers_MixedAnswerCountsBothPopulations(t *testing.T) {
	uc := fakeWithRecord(foreignParent, "v1.15.1", cgapp.PipelineVersion, parentHoldingNested())
	uc.SetCallers([]cgports.CallEdgeRef{edgeInto(ownCaller), edgeInto(foreignCaller)})

	var buf bytes.Buffer
	if err := runCallers(context.Background(), foreignTarget, false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatalf("runCallers: %v", err)
	}
	if !strings.Contains(buf.String(), "1 of 2 callers") {
		t.Errorf("the answer line does not count both populations:\n%s", buf.String())
	}
}

// TestRunCallers_RecordPredatingTheFieldStatesNothing: a record written before
// the axis existed makes no claim, and the query layer must not invent one from
// the node's path. Silence here is the truth about that record.
func TestRunCallers_RecordPredatingTheFieldStatesNothing(t *testing.T) {
	rec := parentHoldingNested()
	rec.ForeignModulesBuilt = nil
	uc := fakeWithRecord(foreignParent, "v1.15.1", cgapp.PipelineVersion, rec)
	uc.SetCallers([]cgports.CallEdgeRef{edgeInto(foreignCaller)})

	var buf bytes.Buffer
	if err := runCallers(context.Background(), foreignTarget, false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatalf("runCallers: %v", err)
	}
	if strings.Contains(buf.String(), "answer:") {
		t.Errorf("a record stating no foreign module produced a foreign-module answer line:\n%s", buf.String())
	}
}

// TestRunCallees_StatesAnAnswerDrawnFromAForeignModule: the callee side reads
// the other end of the edge, and must classify it the same way.
func TestRunCallees_StatesAnAnswerDrawnFromAForeignModule(t *testing.T) {
	uc := fakeWithRecord(foreignParent, "v1.15.1", cgapp.PipelineVersion, parentHoldingNested())
	uc.SetCallees([]cgports.CallEdgeRef{{
		ModulePath:      foreignParent,
		ModuleVersion:   "v1.15.1",
		PipelineVersion: cgapp.PipelineVersion,
		FromID:          ownCaller,
		ToID:            foreignCaller,
		Confidence:      cgdomain.ConfidenceDirect,
	}})

	var buf bytes.Buffer
	if err := runCallees(context.Background(), ownCaller, false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatalf("runCallees: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "answer: RESOLVED-PRESENT") || !strings.Contains(out, "1 of 1 callees") {
		t.Errorf("the callee side does not state the foreign draw:\n%s", out)
	}
}

// TestRunCallers_EmptyAnswerKeepsItsOwnVerdict: an empty answer was drawn from
// nothing, so the foreign statement must not displace the three-valued verdict
// that empty answers carry.
func TestRunCallers_EmptyAnswerKeepsItsOwnVerdict(t *testing.T) {
	uc := fakeWithRecord(foreignParent, "v1.15.1", cgapp.PipelineVersion, parentHoldingNested())

	var buf bytes.Buffer
	if err := runCallers(context.Background(), foreignTarget, false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatalf("runCallers: %v", err)
	}
	if !strings.Contains(buf.String(), "answer: RESOLVED-ABSENT") {
		t.Errorf("an empty answer lost its verdict:\n%s", buf.String())
	}
}

// TestForeignDrawClause_RendersNothingWhenNothingWasDrawn pins the guard the
// three renderers rely on to stay silent by default.
func TestForeignDrawClause_RendersNothingWhenNothingWasDrawn(t *testing.T) {
	if got := (foreignDraw{total: 3}).clause("callers"); got != "" {
		t.Errorf("clause() on an untouched answer = %q, want empty", got)
	}
	if got := (foreignDraw{}).foreignModuleJSONs(); got != nil {
		t.Errorf("foreignModuleJSONs() on an untouched answer = %+v, want nil", got)
	}
}

// TestForeignDraw_RendersProseInTextAndFieldsInJSON: a module resolution gave no
// version reads as prose on the answer line and as an empty version field in the
// document — the same fact, never the prose in the field.
func TestForeignDraw_RendersProseInTextAndFieldsInJSON(t *testing.T) {
	d := foreignDraw{rows: 1, total: 1, modules: []cgdomain.ForeignModule{{Path: "example.com/nested"}}}
	if got := d.clause("callers"); !strings.Contains(got, "example.com/nested (no version resolved)") {
		t.Errorf("clause() = %q; an unversioned module must say so rather than render a bare @", got)
	}
	got := d.foreignModuleJSONs()
	if len(got) != 1 || got[0].Path != "example.com/nested" || got[0].Version != "" {
		t.Errorf("foreignModuleJSONs() = %+v, want one entry with an empty version", got)
	}
}

// TestImplementers_StatesTypesFromAForeignModule: the type-level answer has the
// same exposure. The relation is computed over the analysed module's own
// declarations, so a foreign implementer is the case where the record holds a
// nested module's types and the count would otherwise read as the searched
// module's own.
func TestImplementers_StatesTypesFromAForeignModule(t *testing.T) {
	iface := cgdomain.InterfaceType{
		ID: foreignParent + ".Encoder", Package: foreignParent, Name: "Encoder",
		Methods: []string{"Encode"},
	}
	rec := parentHoldingNested()
	rec.Interfaces = []cgdomain.InterfaceType{iface}
	rec.Implementations = []cgdomain.InterfaceImplementation{
		{InterfaceID: iface.ID, TypeID: foreignNested + ".(*Loader)", Package: foreignNested,
			Methods: []cgdomain.ImplementedMethod{{Method: "Encode", NodeID: foreignNested + ".(*Loader).Encode"}}},
		{InterfaceID: iface.ID, TypeID: foreignParent + ".(*Frozen)", Package: foreignParent,
			Methods: []cgdomain.ImplementedMethod{{Method: "Encode", NodeID: foreignParent + ".(*Frozen).Encode"}}},
	}
	uc := fakeWithRecord(foreignParent, "v1.15.1", cgapp.PipelineVersion, rec)

	var buf bytes.Buffer
	if err := runImplementers(context.Background(), iface.ID, false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatalf("runImplementers: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "answer: RESOLVED-PRESENT") {
		t.Fatalf("no answer line:\n%s", out)
	}
	for _, want := range []string{"1 of 2 implementers", foreignNested + "@v0.3.0"} {
		if !strings.Contains(out, want) {
			t.Errorf("the answer line omits %q:\n%s", want, out)
		}
	}

	var doc bytes.Buffer
	if err := runImplementers(context.Background(), iface.ID, true, uc, &doc, buildScope{}, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatalf("runImplementers --json: %v", err)
	}
	var res implementersResult
	if err := json.Unmarshal(doc.Bytes(), &res); err != nil {
		t.Fatalf("decoding the implementers document: %v", err)
	}
	if len(res.AnswerForeignModules) != 1 || res.AnswerForeignModules[0].Path != foreignNested {
		t.Errorf("answer_foreign_modules = %+v, want the nested module", res.AnswerForeignModules)
	}
}

// TestImplementers_SaysNothingWhenEveryTypeIsTheSearchedModulesOwn is the
// control: a record that holds a foreign module still says nothing when this
// answer's rows are all its own declarations.
func TestImplementers_SaysNothingWhenEveryTypeIsTheSearchedModulesOwn(t *testing.T) {
	iface := cgdomain.InterfaceType{
		ID: foreignParent + ".Encoder", Package: foreignParent, Name: "Encoder",
		Methods: []string{"Encode"},
	}
	rec := parentHoldingNested()
	rec.Interfaces = []cgdomain.InterfaceType{iface}
	rec.Implementations = []cgdomain.InterfaceImplementation{
		{InterfaceID: iface.ID, TypeID: foreignParent + ".(*Frozen)", Package: foreignParent,
			Methods: []cgdomain.ImplementedMethod{{Method: "Encode", NodeID: foreignParent + ".(*Frozen).Encode"}}},
	}
	uc := fakeWithRecord(foreignParent, "v1.15.1", cgapp.PipelineVersion, rec)

	var buf bytes.Buffer
	if err := runImplementers(context.Background(), iface.ID, false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatalf("runImplementers: %v", err)
	}
	if strings.Contains(buf.String(), "module the answering record is not about") {
		t.Errorf("an answer of the module's own types claimed a foreign draw:\n%s", buf.String())
	}
}

// TestRunCallersTransitive_CountsNodesNotEdges: a transitive answer LISTS
// reached nodes, and a walk reaches one node over several edges. Counting edges
// would state a proportion of a population the reader cannot see.
func TestRunCallersTransitive_CountsNodesNotEdges(t *testing.T) {
	uc := fakeWithRecord(foreignParent, "v1.15.1", cgapp.PipelineVersion, parentHoldingNested())
	// Two edges reach the one foreign node; one more reaches the module's own.
	uc.SetTraverseCallers([]cgports.CallEdgeRef{
		edgeInto(foreignCaller),
		{ModulePath: foreignParent, ModuleVersion: "v1.15.1", PipelineVersion: cgapp.PipelineVersion,
			FromID: foreignCaller, ToID: ownCaller},
		edgeInto(ownCaller),
	}, []string{foreignCaller, ownCaller})

	var buf bytes.Buffer
	if err := runCallersTransitive(context.Background(), foreignTarget, 0, false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatalf("runCallersTransitive: %v", err)
	}
	if !strings.Contains(buf.String(), "1 of 2 transitive callers") {
		t.Errorf("the transitive answer line does not count nodes:\n%s", buf.String())
	}
}
