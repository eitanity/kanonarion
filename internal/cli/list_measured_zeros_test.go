package cli

import (
	"bytes"
	"encoding/json"
	"testing"

	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	ifaceapp "github.com/eitanity/kanonarion/internal/iface/application"
	ifacedomain "github.com/eitanity/kanonarion/internal/iface/domain"
	ifaceports "github.com/eitanity/kanonarion/internal/iface/ports"
)

// interfaceListRows renders the list through the production presenter and
// decodes the rows it wrote. The row type is declared INSIDE that function, so
// there is no type a reflection guard could reach and no way to assert this
// except by rendering.
func interfaceListRows(t *testing.T, sums []ifaceports.InterfaceSummary) []map[string]any {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if err := printInterfaceList(sums, true, 0, 0, listZeroScope{}, &stdout, &stderr); err != nil {
		t.Fatalf("printing interface list: %v", err)
	}
	var rows []map[string]any
	decodeListingRecords(t, stdout.String(), &rows)
	return rows
}

// TestInterfaceListJSON_SupersededIsEmittedAtFalse pins the half of the pair
// that says a record IS servable.
//
// pipeline_version and superseded are one statement: without the pair a
// consumer reads a listed record as an available one and finds every query
// about it empty. The half erased was the one meaning "this one can be queried"
// — measured on the live store, 2 rows of 474, which is the whole set of rows
// a reader would have acted on.
func TestInterfaceListJSON_SupersededIsEmittedAtFalse(t *testing.T) {
	rows := interfaceListRows(t, []ifaceports.InterfaceSummary{{
		ModulePath:      "example.com/current",
		ModuleVersion:   "v1.0.0",
		PipelineVersion: ifaceapp.PipelineVersion,
		OverallStatus:   ifacedomain.InterfaceStatusExtracted,
		PackageCount:    4,
	}, {
		// Non-zero control: a record from older extraction logic, which this
		// build does not serve. The flag is derived by comparing the row's
		// pipeline against the one this binary serves, not written in.
		ModulePath:      "example.com/stale",
		ModuleVersion:   "v0.9.0",
		PipelineVersion: "0.0.1-old",
		OverallStatus:   ifacedomain.InterfaceStatusExtracted,
		PackageCount:    2,
	}})
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(rows))
	}

	got, present := rows[0]["superseded"]
	if !present {
		t.Fatal("superseded is absent on a servable record; that is the row a consumer can actually query, and it is the row the pair was silent about")
	}
	if got != false {
		t.Errorf("superseded = %v on a current-pipeline record, want false", got)
	}
	if rows[0]["pipeline_version"] != ifaceapp.PipelineVersion {
		t.Errorf("pipeline_version = %v, want the served pipeline", rows[0]["pipeline_version"])
	}
	if rows[1]["superseded"] != true {
		t.Errorf("superseded = %v on a record from superseded logic, want true", rows[1]["superseded"])
	}
	if rows[0]["superseded"] == rows[1]["superseded"] {
		t.Error("a servable record and a superseded one carry the same superseded; the list cannot separate them")
	}
}

// TestTransitiveJSON_MaxDepthIsEmittedAtZero pins the traversal's own bound.
//
// 0 is the answer "unlimited" — the flag's default, and the depth every
// unbounded traversal runs at — so omitting it made the commonest run report no
// bound at all, which reads as a build that does not state one.
func TestTransitiveJSON_MaxDepthIsEmittedAtZero(t *testing.T) {
	render := func(depth int) map[string]any {
		t.Helper()
		var stdout bytes.Buffer
		if err := printTransitiveResult("callers", "example.com/mod.Root", depth,
			[]string{"example.com/mod.Root"}, []cgports.CallEdgeRef{}, true, &stdout, cgports.EdgeQueryOptions{}); err != nil {
			t.Fatalf("printing transitive result: %v", err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
			t.Fatalf("decoding transitive result: %v", err)
		}
		return decoded
	}

	unbounded := render(0)
	got, present := unbounded["max_depth"]
	if !present {
		t.Fatal("max_depth is absent on an unbounded traversal; unbounded is the answer, and a reader cannot tell it from a report that does not state depth")
	}
	if got.(float64) != 0 {
		t.Errorf("max_depth = %v on an unbounded traversal, want 0", got)
	}

	// Non-zero control: the bound the caller asked for is carried through.
	if got := render(3)["max_depth"]; got.(float64) != 3 {
		t.Errorf("max_depth = %v under --depth 3, want 3", got)
	}
}

// TestWalkSelectionJSON_CandidatesIsNullWhenNothingWasEnumerated pins the
// selection statement.
//
// This one is a pointer, and it is the case the plain-value rule does not fit:
// a caller who named a walk with --walk-id had no candidate set enumerated at
// all, and 0 would state a count that is never true — the store holds at least
// the walk the document names. Null says nothing was counted.
func TestWalkSelectionJSON_CandidatesIsNullWhenNothingWasEnumerated(t *testing.T) {
	keys := func(sel selectionJSON) map[string]any {
		t.Helper()
		data, err := json.Marshal(sel)
		if err != nil {
			t.Fatalf("marshalling selection: %v", err)
		}
		var decoded map[string]any
		if uerr := json.Unmarshal(data, &decoded); uerr != nil {
			t.Fatalf("unmarshalling selection: %v", uerr)
		}
		return decoded
	}

	pinned := keys(pinnedSelection())
	got, present := pinned["candidates"]
	if !present {
		t.Fatal("candidates is absent on a pinned selection; the key must state that no candidate set was enumerated")
	}
	if got != nil {
		t.Errorf("candidates = %v on a pinned walk, want null", got)
	}
	if pinned["rule"] != "pinned" {
		t.Errorf("rule = %v, want pinned", pinned["rule"])
	}

	// Non-zero control: a choice made among candidates carries the count it was
	// made from, through the same renderer.
	chosen := keys(walkChoice{rule: walkChosenRecencyNoMatch, candidates: 5}.selection())
	if got := chosen["candidates"]; got == nil || got.(float64) != 5 {
		t.Errorf("candidates = %v for a choice among five walks, want 5", got)
	}

	// The count of one is the case omitempty could not erase but the reader
	// still needs: a sole walk was enumerated, and one was found.
	sole := keys(walkChoice{rule: walkChosenSole, candidates: 1}.selection())
	if got := sole["candidates"]; got == nil || got.(float64) != 1 {
		t.Errorf("candidates = %v for a sole walk, want 1", got)
	}
}

// TestInterfaceDiffJSON_CallerLineIsAbsentOnlyWhenNoPositionWasRecorded is the
// check behind the one exemption in the package-wide guard.
//
// `line` on a used-by caller was absent on every entry measured, and absence
// could have meant either of two things: a line of 0 erased by omitempty, or a
// position the analysis never recorded. It is the second. Lines come from
// go/token and are numbered from 1, the analyser writes the zero
// SourcePosition when a declaration has no valid position, and `file` is empty
// on exactly those rows — so an absent line is "no position was recorded",
// which is true, and the tag stays.
func TestInterfaceDiffJSON_CallerLineIsAbsentOnlyWhenNoPositionWasRecorded(t *testing.T) {
	consumer := coordinatetest.MustNew("example.com/app", "local")
	refs := []cgports.CallEdgeRef{
		{ModulePath: "example.com/app", FromID: "example.com/app.located", ToID: "example.com/dep.Parse"},
		{ModulePath: "example.com/app", FromID: "example.com/app.unlocated", ToID: "example.com/dep.Parse"},
	}
	positions := map[string]cgdomain.SourcePosition{
		"example.com/app.located": {File: "main.go", Line: 42},
		// The second caller is a node the analyser recorded with no valid
		// position, which is the zero SourcePosition.
		"example.com/app.unlocated": {},
	}
	sites, callers := consumerCallers(refs, consumer, positions)
	if sites != 2 || len(callers) != 2 {
		t.Fatalf("consumerCallers = %d sites / %d callers, want 2/2", sites, len(callers))
	}

	rendered := toUsedSymbolsJSON([]usedSymbol{{
		Symbol:     ifacedomain.SymbolID{Package: "example.com/dep", Kind: ifacedomain.SymbolFunc, Name: "Parse"},
		Measurable: true, NodeID: "example.com/dep.Parse", Sites: sites, Callers: callers,
	}}, "removed")
	data, err := json.Marshal(rendered)
	if err != nil {
		t.Fatalf("marshalling used symbols: %v", err)
	}
	var decoded []map[string]any
	if uerr := json.Unmarshal(data, &decoded); uerr != nil {
		t.Fatalf("unmarshalling used symbols: %v", uerr)
	}
	rows, _ := decoded[0]["callers"].([]any)
	if len(rows) != 2 {
		t.Fatalf("callers = %v, want 2", decoded[0]["callers"])
	}

	// Non-zero control: the caller whose declaration the analysis did locate
	// carries the line it was declared at.
	located := rows[0].(map[string]any)
	if got := located["line"]; got == nil || got.(float64) != 42 {
		t.Errorf("line = %v for a caller with a recorded position, want 42", got)
	}
	if located["file"] != "main.go" {
		t.Errorf("file = %v, want main.go", located["file"])
	}

	// The absent case, and why it is honest: no line AND no file. The two
	// vanish together because they are one fact, and neither says "line 0".
	unlocated := rows[1].(map[string]any)
	if _, present := unlocated["line"]; present {
		t.Errorf("line is present (%v) for a caller with no recorded position; the exemption in the guard assumes it is absent here", unlocated["line"])
	}
	if _, present := unlocated["file"]; present {
		t.Errorf("file is present (%v) with no line; the pair must vanish together, or absence stops meaning 'no position'", unlocated["file"])
	}
}
