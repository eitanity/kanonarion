package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	ifaceapp "github.com/eitanity/kanonarion/internal/iface/application"
	ifacedomain "github.com/eitanity/kanonarion/internal/iface/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

func ifaceDiffCoords() (coordinate.ModuleCoordinate, coordinate.ModuleCoordinate) {
	return coordinatetest.MustNew("example.com/mod", "v1.0.0"),
		coordinatetest.MustNew("example.com/mod", "v2.0.0")
}

// diffWithOneRemoval builds a delta holding a single removed function, which is
// what the used-by join is asked about below.
func diffWithOneRemoval(t *testing.T) ifacedomain.InterfaceDiff {
	t.Helper()
	a, b := ifaceDiffCoords()
	return ifacedomain.InterfaceDiff{
		RecordA: ifacedomain.InterfaceRecord{Coordinate: a},
		RecordB: ifacedomain.InterfaceRecord{Coordinate: b},
		Removed: []ifacedomain.Symbol{{
			ID:        ifacedomain.SymbolID{Package: "example.com/mod", Kind: ifacedomain.SymbolFunc, Name: "Gone"},
			Signature: "func Gone() error",
		}},
	}
}

// A missing record on either side is ExitNotFound: absence is surfaced, never
// reported as "no change".
func TestInterfaceDiffWith_RecordNotFound(t *testing.T) {
	a, b := ifaceDiffCoords()
	ctr := &Container{DiffInterface: &testfakes.FakeDiffInterface{
		Err: &ifaceapp.ErrInterfaceRecordNotFound{Coordinate: a},
	}}
	var out bytes.Buffer
	err := interfaceDiffWith(context.Background(), ctr, a, b, interfaceDiffFlags{}, &out)
	requireExit(t, err, ExitNotFound)
	if !strings.Contains(err.Error(), "kanonarion interface") {
		t.Errorf("refusal does not name the command that produces the record: %v", err)
	}
}

// The headline states the fact and the scope it holds over, on one line, and a
// zero is never rendered as a verdict. A measured zero-breaking bump changed 38
// behavioural outcomes; the line must not invite the reader to conclude
// otherwise.
func TestPrintInterfaceDiff_HeadlineStatesFactAndScope(t *testing.T) {
	a, b := ifaceDiffCoords()
	diff := ifacedomain.InterfaceDiff{
		RecordA:  ifacedomain.InterfaceRecord{Coordinate: a},
		RecordB:  ifacedomain.InterfaceRecord{Coordinate: b},
		Spelling: []ifacedomain.SignatureChange{{Symbol: ifacedomain.SymbolID{Name: "F"}}},
	}
	var out bytes.Buffer
	if err := printInterfaceDiff(diff, nil, &out); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	headline := strings.SplitN(got, "\n", 2)[0]
	for _, want := range []string{
		"0 breaking change(s) among exported Go declarations",
		"example.com/mod@v1.0.0 → example.com/mod@v2.0.0",
		"behaviour and string-keyed registries are outside this comparison",
	} {
		if !strings.Contains(headline, want) {
			t.Errorf("headline missing %q:\n%s", want, headline)
		}
	}
	for _, forbidden := range []string{"safe", "additive-only", "no consumer impact"} {
		if strings.Contains(strings.ToLower(got), forbidden) {
			t.Errorf("output renders a zero as a verdict (%q):\n%s", forbidden, got)
		}
	}
	if !strings.Contains(got, "spelling: 1") {
		t.Errorf("spelling count not reported:\n%s", got)
	}
	if !strings.Contains(got, interfaceDiffCoverageNote) {
		t.Error("coverage note missing from a run that found no breaking change")
	}
}

// Every section renders, and a registry surface carries its statement that the
// keys are not read.
func TestPrintInterfaceDiff_AllSections(t *testing.T) {
	a, b := ifaceDiffCoords()
	diff := ifacedomain.InterfaceDiff{
		RecordA:         ifacedomain.InterfaceRecord{Coordinate: a},
		RecordB:         ifacedomain.InterfaceRecord{Coordinate: b},
		PackagesAdded:   []string{"example.com/mod/fresh"},
		PackagesRemoved: []string{"example.com/mod/gone"},
		Added: []ifacedomain.Symbol{{
			ID:        ifacedomain.SymbolID{Package: "example.com/mod", Kind: ifacedomain.SymbolFunc, Name: "New"},
			Signature: "func New() error",
		}},
		Removed: []ifacedomain.Symbol{{
			ID: ifacedomain.SymbolID{Package: "example.com/mod", Kind: ifacedomain.SymbolConst, Name: "Limit"},
		}},
		Changed: []ifacedomain.SignatureChange{{
			Symbol: ifacedomain.SymbolID{Package: "example.com/mod", Kind: ifacedomain.SymbolFunc, Name: "Run"},
			From:   "func Run() error", To: "func Run(ctx context.Context) error",
		}},
		Spelling: []ifacedomain.SignatureChange{{
			Symbol: ifacedomain.SymbolID{Package: "example.com/mod", Kind: ifacedomain.SymbolFunc, Name: "Cast"},
			From:   "func Cast(i interface{}) error", To: "func Cast(i any) error",
		}},
		Registries: []ifacedomain.RegistrySurface{{
			Symbol: ifacedomain.SymbolID{Package: "example.com/mod", Kind: ifacedomain.SymbolFunc, Name: "FuncMap"},
			Shape:  "template.FuncMap", Side: ifacedomain.RegistryInBoth,
		}},
		ExcludedTestdataPackages: []string{"example.com/mod/testdata/one"},
	}
	var out bytes.Buffer
	if err := printInterfaceDiff(diff, nil, &out); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, want := range []string{
		"package added: example.com/mod/fresh",
		"package removed: example.com/mod/gone",
		"Removed (1)", "Added (1)", "Changed (1)",
		"Spelling (type-alias-equivalent, not breaking) (1)",
		"func Run(ctx context.Context) error",
		"String-keyed registries (1)",
		"template.FuncMap",
		"resolved at run time",
		"Excluded from the comparison (1 testdata package(s)",
		"example.com/mod/testdata/one",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
}

// The machine-readable shape keeps the record's own short names for the
// declaration kinds, spells an empty collection "[]" rather than "null", and
// carries the scope statement so a JSON consumer cannot read the count without
// it.
func TestInterfaceDiffJSON_ShapeAndNaming(t *testing.T) {
	a, b := ifaceDiffCoords()
	diff := ifacedomain.InterfaceDiff{
		RecordA: ifacedomain.InterfaceRecord{Coordinate: a},
		RecordB: ifacedomain.InterfaceRecord{Coordinate: b},
		Removed: []ifacedomain.Symbol{{
			ID:        ifacedomain.SymbolID{Package: "example.com/mod", Kind: ifacedomain.SymbolVar, Name: "Default"},
			Signature: "*Client",
		}},
	}
	raw, err := json.Marshal(toInterfaceDiffJSON(diff, nil))
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		"module_a", "module_b", "breaking_count", "scope",
		"packages_added", "packages_removed", "added", "removed", "changed",
		"spelling", "registries", "excluded_testdata_packages",
	} {
		if _, ok := decoded[key]; !ok {
			t.Errorf("JSON missing key %q: %s", key, raw)
		}
	}
	if decoded["breaking_count"].(float64) != 1 {
		t.Errorf("breaking_count = %v, want 1", decoded["breaking_count"])
	}
	if _, ok := decoded["used_by"]; ok {
		t.Error("used_by present without --used-by")
	}
	for _, want := range []string{`"added":[]`, `"changed":[]`, `"spelling":[]`, `"registries":[]`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("empty collection not rendered as []: want %s in %s", want, raw)
		}
	}
	// The kind vocabulary is the record's own: funcs, consts, vars.
	if !strings.Contains(string(raw), `"kind":"var"`) {
		t.Errorf("declaration kind not named as the record names it: %s", raw)
	}
}

// -- the used-by join --

// usedByContainer wires a project walk, a consumer call graph, and one caller
// edge into the seam the join reads.
func usedByContainer(t *testing.T, edges []cgports.CallEdgeRef) (*Container, string) {
	t.Helper()
	consumer, err := coordinate.NewLocalCoordinate("example.com/app")
	if err != nil {
		t.Fatal(err)
	}
	walks := testfakes.NewFakeQueryWalks()
	walks.SetSummaries([]walkports.WalkSummary{{
		ID: "walk-1", Target: consumer, OverallStatus: walkdomain.WalkSucceeded,
	}})
	walks.AddWalk(walkdomain.WalkRecord{
		ID:     "walk-1",
		Target: consumer,
		Graph: walkdomain.Graph{
			Target: consumer,
			Nodes: []walkdomain.GraphNode{
				{Coordinate: consumer},
				{Coordinate: coordinatetest.MustNew("example.com/mod", "v1.0.0")},
			},
		},
	})

	cg := testfakes.NewFakeQueryCallGraph()
	cg.AddRecord(consumer, cgapp.PipelineVersion, cgdomain.CallGraphRecord{
		Coordinate: consumer,
		Nodes: []cgdomain.CallNode{{
			ID:       "example.com/app/service.Handle",
			Position: cgdomain.SourcePosition{File: "service/handle.go", Line: 42},
		}},
	})
	cg.SetCallersFor("example.com/mod.Gone", edges)

	gomodDir := t.TempDir()
	gomod := filepath.Join(gomodDir, "go.mod")
	if err := os.WriteFile(gomod, []byte("module example.com/app\n\ngo 1.24\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	return &Container{
		DiffInterface:  &testfakes.FakeDiffInterface{Result: diffWithOneRemoval(t)},
		QueryWalks:     walks,
		QueryCallGraph: cg,
	}, gomod
}

// The join is a read of the STORED call graph, and it reports where the
// consumer's own code calls a removed declaration — with the site count and the
// caller's location — then fires the gate it was asked for.
func TestInterfaceDiffWith_UsedBy_ReachedSymbolIsExitPolicy(t *testing.T) {
	ctr, gomod := usedByContainer(t, []cgports.CallEdgeRef{{
		ModulePath: "example.com/app", ModuleVersion: coordinate.LocalVersion,
		FromID: "example.com/app/service.Handle", ToID: "example.com/mod.Gone",
	}})
	a, b := ifaceDiffCoords()

	var out bytes.Buffer
	err := interfaceDiffWith(context.Background(), ctr, a, b, interfaceDiffFlags{usedBy: gomod}, &out)
	requireExit(t, err, ExitPolicy)

	got := out.String()
	for _, want := range []string{
		"Used by example.com/app",
		`walk "walk-1"`,
		"example.com/mod.Gone (func) [removed] — 1 call site",
		"example.com/app/service.Handle  service/handle.go:42",
		usedByCoverageNote,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("used-by output missing %q:\n%s", want, got)
		}
	}
	if !strings.Contains(err.Error(), "breaking within the used set") {
		t.Errorf("gate message does not name what fired: %v", err)
	}
}

// An edge owned by another dependency is not the consumer's code: it is a call
// the consumer did not write and cannot fix, so it must not make the gate fire.
func TestInterfaceDiffWith_UsedBy_ForeignEdgeDoesNotCount(t *testing.T) {
	ctr, gomod := usedByContainer(t, []cgports.CallEdgeRef{{
		ModulePath: "example.com/other", ModuleVersion: "v1.0.0",
		FromID: "example.com/other.Call", ToID: "example.com/mod.Gone",
	}})
	a, b := ifaceDiffCoords()

	var out bytes.Buffer
	if err := interfaceDiffWith(context.Background(), ctr, a, b, interfaceDiffFlags{usedBy: gomod}, &out); err != nil {
		t.Fatalf("want exit 0 when only a third party calls the symbol, got: %v", err)
	}
	if !strings.Contains(out.String(), "no call edge recorded from example.com/app") {
		t.Errorf("an unreached symbol was not reported as unreached:\n%s", out.String())
	}
}

// A declaration with no call-graph node is not "unused": the call graph cannot
// answer the question, and the output says so rather than counting a silence as
// a clean result.
func TestInterfaceDiffWith_UsedBy_KindsWithoutNodesAreUnmeasured(t *testing.T) {
	ctr, gomod := usedByContainer(t, nil)
	diff := diffWithOneRemoval(t)
	diff.Removed = append(diff.Removed, ifacedomain.Symbol{
		ID: ifacedomain.SymbolID{Package: "example.com/mod", Kind: ifacedomain.SymbolConst, Name: "Limit"},
	})
	ctr.DiffInterface = &testfakes.FakeDiffInterface{Result: diff}
	a, b := ifaceDiffCoords()

	var out bytes.Buffer
	if err := interfaceDiffWith(context.Background(), ctr, a, b, interfaceDiffFlags{usedBy: gomod}, &out); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out.String(), "unmeasured: no call-graph node for this kind") {
		t.Errorf("a constant was reported as unreached rather than unmeasured:\n%s", out.String())
	}
}

// A method is looked up under the receiver form it was declared with. The other
// form finds nothing, and nothing would have read as "not called".
func TestCallGraphNodeID_ReceiverForm(t *testing.T) {
	cases := []struct {
		name        string
		id          ifacedomain.SymbolID
		ptrReceiver bool
		want        string
		measurable  bool
	}{
		{
			name:       "function",
			id:         ifacedomain.SymbolID{Package: "example.com/mod", Kind: ifacedomain.SymbolFunc, Name: "Run"},
			want:       "example.com/mod.Run",
			measurable: true,
		},
		{
			name:        "pointer-receiver method",
			id:          ifacedomain.SymbolID{Package: "example.com/mod", Kind: ifacedomain.SymbolMethod, Name: "Client.Do"},
			ptrReceiver: true,
			want:        "example.com/mod.(*Client).Do",
			measurable:  true,
		},
		{
			name:       "value-receiver method",
			id:         ifacedomain.SymbolID{Package: "example.com/mod", Kind: ifacedomain.SymbolMethod, Name: "Form.String"},
			want:       "example.com/mod.(Form).String",
			measurable: true,
		},
		{
			name: "a method identity with no receiver is not looked up",
			id:   ifacedomain.SymbolID{Package: "example.com/mod", Kind: ifacedomain.SymbolMethod, Name: "Orphan"},
		},
		{
			name: "type",
			id:   ifacedomain.SymbolID{Package: "example.com/mod", Kind: ifacedomain.SymbolType, Name: "Client"},
		},
		{
			name: "const",
			id:   ifacedomain.SymbolID{Package: "example.com/mod", Kind: ifacedomain.SymbolConst, Name: "Limit"},
		},
		{
			name: "var",
			id:   ifacedomain.SymbolID{Package: "example.com/mod", Kind: ifacedomain.SymbolVar, Name: "Default"},
		},
		{
			name: "an unknown kind is not guessed at",
			id:   ifacedomain.SymbolID{Package: "example.com/mod", Kind: "widget", Name: "W"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, measurable := callGraphNodeID(tc.id, tc.ptrReceiver)
			if got != tc.want || measurable != tc.measurable {
				t.Errorf("callGraphNodeID = (%q, %v), want (%q, %v)", got, measurable, tc.want, tc.measurable)
			}
		})
	}
}

// A project with no stored call graph produces no measurement, and the output
// refuses to let the resulting silence read as "nothing is affected".
func TestInterfaceDiffWith_UsedBy_NoStoredCallGraph(t *testing.T) {
	ctr, gomod := usedByContainer(t, nil)
	ctr.QueryCallGraph = testfakes.NewFakeQueryCallGraph()
	a, b := ifaceDiffCoords()

	var out bytes.Buffer
	if err := interfaceDiffWith(context.Background(), ctr, a, b, interfaceDiffFlags{usedBy: gomod}, &out); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "no stored call graph for example.com/app") {
		t.Errorf("a missing call graph was not surfaced:\n%s", got)
	}
	if !strings.Contains(got, "kanonarion local .") {
		t.Errorf("the absence names no remedy:\n%s", got)
	}
}

// A go.mod with no succeeded project walk is refused with the walk command that
// would produce one, not with an empty answer.
func TestInterfaceDiffWith_UsedBy_NoProjectWalk(t *testing.T) {
	ctr, gomod := usedByContainer(t, nil)
	ctr.QueryWalks = testfakes.NewFakeQueryWalks()
	a, b := ifaceDiffCoords()

	var out bytes.Buffer
	err := interfaceDiffWith(context.Background(), ctr, a, b, interfaceDiffFlags{usedBy: gomod}, &out)
	if err == nil {
		t.Fatal("want a refusal, got none")
	}
	if !strings.Contains(err.Error(), "kanonarion walk --gomod") {
		t.Errorf("refusal does not name the command that produces the walk: %v", err)
	}
}

// Under --json the join is carried in the document, and the gate still fires:
// a machine-readable answer must not be a quieter answer.
func TestInterfaceDiffWith_UsedBy_JSONCarriesTheJoinAndTheGate(t *testing.T) {
	ctr, gomod := usedByContainer(t, []cgports.CallEdgeRef{{
		ModulePath: "example.com/app", ModuleVersion: coordinate.LocalVersion,
		FromID: "example.com/app/service.Handle", ToID: "example.com/mod.Gone",
	}})
	a, b := ifaceDiffCoords()

	jsonOut = true
	defer func() { jsonOut = false }()

	var out bytes.Buffer
	err := interfaceDiffWith(context.Background(), ctr, a, b, interfaceDiffFlags{usedBy: gomod}, &out)
	requireExit(t, err, ExitPolicy)

	var decoded struct {
		UsedBy *struct {
			WalkID         string `json:"walk_id"`
			Consumer       string `json:"consumer"`
			ScopeSize      int    `json:"scope_size"`
			CallGraphFound bool   `json:"call_graph_found"`
			ReachedCount   int    `json:"reached_count"`
			Coverage       string `json:"coverage"`
			Symbols        []struct {
				Name    string `json:"name"`
				Class   string `json:"class"`
				NodeID  string `json:"node_id"`
				Sites   int    `json:"sites"`
				Callers []struct {
					ID   string `json:"id"`
					File string `json:"file"`
					Line int    `json:"line"`
				} `json:"callers"`
			} `json:"symbols"`
		} `json:"used_by"`
	}
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("decoding JSON: %v\n%s", err, out.String())
	}
	if decoded.UsedBy == nil {
		t.Fatalf("used_by absent from JSON:\n%s", out.String())
	}
	if decoded.UsedBy.WalkID != "walk-1" || decoded.UsedBy.ReachedCount != 1 ||
		!decoded.UsedBy.CallGraphFound || decoded.UsedBy.ScopeSize != 2 {
		t.Errorf("used_by = %+v", decoded.UsedBy)
	}
	if decoded.UsedBy.Coverage != usedByCoverageNote {
		t.Error("the JSON join carries no coverage statement")
	}
	if len(decoded.UsedBy.Symbols) != 1 {
		t.Fatalf("symbols = %+v", decoded.UsedBy.Symbols)
	}
	sym := decoded.UsedBy.Symbols[0]
	if sym.Name != "Gone" || sym.Class != "removed" || sym.NodeID != "example.com/mod.Gone" || sym.Sites != 1 {
		t.Errorf("symbol = %+v", sym)
	}
	if len(sym.Callers) != 1 || sym.Callers[0].File != "service/handle.go" || sym.Callers[0].Line != 42 {
		t.Errorf("callers = %+v", sym.Callers)
	}
}

// A spelling change is not joined. Asking whether the consumer reaches a
// declaration that did not really change would manufacture a finding out of a
// non-finding.
func TestUsedBy_SpellingChangesAreNotJoined(t *testing.T) {
	diff := ifacedomain.InterfaceDiff{
		Spelling: []ifacedomain.SignatureChange{{
			Symbol: ifacedomain.SymbolID{Package: "example.com/mod", Kind: ifacedomain.SymbolFunc, Name: "Cast"},
		}},
		Changed: []ifacedomain.SignatureChange{{
			Symbol: ifacedomain.SymbolID{Package: "example.com/mod", Kind: ifacedomain.SymbolFunc, Name: "Run"},
		}},
	}
	got := breakingSymbols(diff)
	if len(got) != 1 || got[0].Symbol.Name != "Run" {
		t.Errorf("breakingSymbols = %+v, want only the real change", got)
	}
}

// Nothing to join is not a gate firing.
func TestUsedSetBreakingErr_QuietWhenNothingIsReached(t *testing.T) {
	if err := usedSetBreakingErr(nil); err != nil {
		t.Errorf("no join produced an error: %v", err)
	}
	if err := usedSetBreakingErr(&usedByResult{Symbols: []usedSymbol{{Measurable: true}}}); err != nil {
		t.Errorf("an unreached symbol produced an error: %v", err)
	}
}

// -- grammar and remedies --

// A flag that takes a value takes it as the next argument. Declaring a
// NoOptDefVal on a value-taking flag makes "--used-by ./go.mod" parse as a bare
// flag followed by a stray positional, which is the argument-grammar edge this
// command must not have.
func TestInterfaceDiffCmd_UsedByRequiresItsValue(t *testing.T) {
	cmd := newInterfaceDiffCmd(io.Discard, io.Discard)
	if noOpt := cmd.Flags().Lookup("used-by").NoOptDefVal; noOpt != "" {
		t.Errorf("--used-by declares NoOptDefVal %q; a value-taking flag must not", noOpt)
	}
	if err := cmd.ParseFlags([]string{"--used-by"}); err == nil {
		t.Error("a valueless --used-by parsed; it must be refused")
	}
	cmd = newInterfaceDiffCmd(io.Discard, io.Discard)
	if err := cmd.ParseFlags([]string{"--used-by", "./go.mod"}); err != nil {
		t.Errorf("the space-separated form was refused: %v", err)
	}
	if got := cmd.Flags().Lookup("used-by").Value.String(); got != "./go.mod" {
		t.Errorf("--used-by = %q, want %q", got, "./go.mod")
	}
}

// The command takes exactly two @-qualified coordinates, exactly as license-diff
// does. One or three is a usage error, not a half-run.
func TestInterfaceDiffCmd_TakesTwoCoordinates(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"example.com/mod@v1.0.0"},
		{"example.com/mod@v1.0.0", "example.com/mod@v2.0.0", "example.com/mod@v3.0.0"},
	} {
		cmd := newInterfaceDiffCmd(io.Discard, io.Discard)
		cmd.SetArgs(args)
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		if err := cmd.Execute(); err == nil {
			t.Errorf("args %v were accepted; want a usage error", args)
		}
	}
}

// Every invocation this command prints as a remedy must be one the CLI's own
// parser accepts. A remedy the tool then rejects costs the caller exactly the
// round trip the remedy existed to save.
func TestInterfaceDiffRemedies_EveryLineIsAcceptedByTheParser(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/mod", "v1.0.0")
	notFound := (&ifaceapp.ErrInterfaceRecordNotFound{Coordinate: coord}).Error()

	lines := []string{
		"kanonarion interface " + coord.String(),
		"kanonarion local .",
		"kanonarion walk --gomod ./go.mod",
		"kanonarion interface-diff example.com/mod@v1.0.0 example.com/mod@v2.0.0 --used-by ./go.mod",
	}
	for _, line := range lines {
		if err := parseInvocation(t, line); err != nil {
			t.Errorf("remedy line %q is rejected by the CLI's own parser: %v", line, err)
		}
	}
	// The refusal must actually print the invocation the parser was just given.
	if !strings.Contains(notFound, "kanonarion interface "+coord.String()) {
		t.Errorf("the not-found refusal does not print a runnable invocation: %s", notFound)
	}
}

// -- cross-major pairs --

// crossMajorDiff is the sprig shape: the whole surface carried over under a new
// module path, nothing else changed.
func crossMajorDiff(t *testing.T) ifacedomain.InterfaceDiff {
	t.Helper()
	a := coordinatetest.MustNew("example.com/mod", "v2.22.0+incompatible")
	b := coordinatetest.MustNew("example.com/mod/v3", "v3.3.0")
	return ifacedomain.InterfaceDiff{
		RecordA:       ifacedomain.InterfaceRecord{Coordinate: a},
		RecordB:       ifacedomain.InterfaceRecord{Coordinate: b},
		MajorPathPair: true,
		RenamedPath: []ifacedomain.RenamedSymbol{
			{
				From:      ifacedomain.SymbolID{Package: "example.com/mod", Kind: ifacedomain.SymbolFunc, Name: "TxtFuncMap"},
				To:        ifacedomain.SymbolID{Package: "example.com/mod/v3", Kind: ifacedomain.SymbolFunc, Name: "TxtFuncMap"},
				Signature: "func TxtFuncMap() ttemplate.FuncMap",
			},
			{
				From: ifacedomain.SymbolID{Package: "example.com/mod", Kind: ifacedomain.SymbolType, Name: "DSAKeyFormat"},
				To:   ifacedomain.SymbolID{Package: "example.com/mod/v3", Kind: ifacedomain.SymbolType, Name: "DSAKeyFormat"},
			},
		},
	}
}

// A cross-major pair says what it costs — every import rewritten — and reports
// the carried-over surface as renamed-path rather than as a wall of removals.
// The pair's own path shift is not a package coming or going.
func TestPrintInterfaceDiff_CrossMajorStatesTheRewrite(t *testing.T) {
	var out bytes.Buffer
	if err := printInterfaceDiff(crossMajorDiff(t), nil, &out); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, want := range []string{
		"0 breaking change(s)",
		"renamed-path: 2",
		"cross-major pair: the module path changes from example.com/mod to example.com/mod/v3",
		"every import of it must be rewritten",
		"Renamed path (2) — same declaration under the new module path, not breaking:",
		"example.com/mod.TxtFuncMap (func)",
		"example.com/mod/v3.TxtFuncMap (func)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("cross-major output missing %q:\n%s", want, got)
		}
	}
	for _, forbidden := range []string{"package removed:", "package added:"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("the pair's own path shift was reported as %q:\n%s", forbidden, got)
		}
	}
}

// The control: a same-path comparison gains no renamed-path column and no
// cross-major line, so the change is confined to the pair it is about.
func TestPrintInterfaceDiff_SamePathGainsNoCrossMajorOutput(t *testing.T) {
	var out bytes.Buffer
	if err := printInterfaceDiff(diffWithOneRemoval(t), nil, &out); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, forbidden := range []string{"renamed-path:", "cross-major pair:", "Renamed path ("} {
		if strings.Contains(got, forbidden) {
			t.Errorf("a same-path comparison printed %q:\n%s", forbidden, got)
		}
	}
}

// -- the zero-breaking statement --

// A zero over a delta that is not empty carries the statement, where the reader
// meets the zero rather than in the footer, and names what would answer it.
func TestPrintInterfaceDiff_ZeroBreakingStatementFires(t *testing.T) {
	a, b := ifaceDiffCoords()
	diff := ifacedomain.InterfaceDiff{
		RecordA: ifacedomain.InterfaceRecord{Coordinate: a},
		RecordB: ifacedomain.InterfaceRecord{Coordinate: b},
		Spelling: []ifacedomain.SignatureChange{{
			Symbol: ifacedomain.SymbolID{Package: "example.com/mod", Kind: ifacedomain.SymbolFunc, Name: "Cast"},
			From:   "func Cast(i interface{}) error", To: "func Cast(i any) error",
		}},
	}
	var out bytes.Buffer
	if err := printInterfaceDiff(diff, nil, &out); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.Contains(got, zeroBreakingBehaviourNote) {
		t.Errorf("zero-breaking statement missing:\n%s", got)
	}
	if !strings.Contains(got, zeroBreakingNoUsedByNote) {
		t.Errorf("the statement names nothing that would answer it:\n%s", got)
	}
	// Where the reader meets the zero: before the sections, not after the
	// coverage footer that three triage runs already read past.
	if strings.Index(got, zeroBreakingBehaviourNote) > strings.Index(got, "Spelling (") {
		t.Errorf("the statement is printed after the delta it qualifies:\n%s", got)
	}
	if strings.Contains(got, zeroBreakingCrossMajorNote) {
		t.Errorf("a same-path pair was given the cross-major clause:\n%s", got)
	}
}

// A genuinely empty delta keeps today's terse output. The statement is for the
// case that looks safe and is not; there is nothing here to misread.
func TestPrintInterfaceDiff_EmptyDeltaStaysTerse(t *testing.T) {
	a, b := ifaceDiffCoords()
	diff := ifacedomain.InterfaceDiff{
		RecordA: ifacedomain.InterfaceRecord{Coordinate: a},
		RecordB: ifacedomain.InterfaceRecord{Coordinate: b},
	}
	var out bytes.Buffer
	if err := printInterfaceDiff(diff, nil, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), zeroBreakingBehaviourNote) {
		t.Errorf("an empty delta carried the zero-breaking statement:\n%s", out.String())
	}
}

// The statement never appears beside a non-zero breaking count, where it would
// dilute a real finding into a general caution.
func TestPrintInterfaceDiff_StatementNeverBesideARealFinding(t *testing.T) {
	diff := diffWithOneRemoval(t)
	diff.Spelling = []ifacedomain.SignatureChange{{
		Symbol: ifacedomain.SymbolID{Package: "example.com/mod", Kind: ifacedomain.SymbolFunc, Name: "Cast"},
	}}
	var out bytes.Buffer
	if err := printInterfaceDiff(diff, nil, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), zeroBreakingBehaviourNote) {
		t.Errorf("the statement appeared beside a breaking change:\n%s", out.String())
	}
}

// The interaction between the two changes: a cross-major pair whose surface only
// moved now HAS a zero-breaking headline, and that is exactly the reader who
// needs the statement — a new major is the author declaring an incompatible
// change. The clause says so without pretending it is a signature finding.
func TestPrintInterfaceDiff_ZeroBreakingStatementFiresOnAManufacturedZero(t *testing.T) {
	var out bytes.Buffer
	if err := printInterfaceDiff(crossMajorDiff(t), nil, &out); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.Contains(got, zeroBreakingBehaviourNote) {
		t.Errorf("the zero a cross-major reclassification manufactured carries no statement:\n%s", got)
	}
	if !strings.Contains(got, zeroBreakingCrossMajorNote) {
		t.Errorf("the cross-major clause is missing from a cross-major zero:\n%s", got)
	}
}

// -- the zero-breaking statement over --used-by --

// zeroBreakingUsedByContainer wires a consumer that calls a respelt declaration:
// zero breaking changes, and call sites that a reader must be told about.
func zeroBreakingUsedByContainer(t *testing.T) (*Container, string) {
	t.Helper()
	ctr, gomod := usedByContainer(t, nil)
	a, b := ifaceDiffCoords()
	ctr.DiffInterface = &testfakes.FakeDiffInterface{Result: ifacedomain.InterfaceDiff{
		RecordA: ifacedomain.InterfaceRecord{Coordinate: a},
		RecordB: ifacedomain.InterfaceRecord{Coordinate: b},
		Spelling: []ifacedomain.SignatureChange{{
			Symbol: ifacedomain.SymbolID{Package: "example.com/mod", Kind: ifacedomain.SymbolFunc, Name: "Cast"},
			From:   "func Cast(i interface{}) error", To: "func Cast(i any) error",
		}},
	}}
	cg := testfakes.NewFakeQueryCallGraph()
	consumer, err := coordinate.NewLocalCoordinate("example.com/app")
	if err != nil {
		t.Fatal(err)
	}
	cg.AddRecord(consumer, cgapp.PipelineVersion, cgdomain.CallGraphRecord{
		Coordinate: consumer,
		Nodes: []cgdomain.CallNode{{
			ID:       "example.com/app/service.Handle",
			Position: cgdomain.SourcePosition{File: "service/handle.go", Line: 42},
		}},
	})
	cg.SetCallersFor("example.com/mod.Cast", []cgports.CallEdgeRef{
		{
			ModulePath: "example.com/app", ModuleVersion: coordinate.LocalVersion,
			FromID: "example.com/app/service.Handle", ToID: "example.com/mod.Cast",
		},
		{
			ModulePath: "example.com/app", ModuleVersion: coordinate.LocalVersion,
			FromID: "example.com/app/service.Handle", ToID: "example.com/mod.Cast",
		},
	})
	ctr.QueryCallGraph = cg
	return ctr, gomod
}

// "zero breaking, 2 reached call sites" is a materially different statement from
// "zero breaking, none", and the tool already knows which it is. It reports the
// count — and it does NOT gate: there is nothing here to be broken by.
func TestInterfaceDiffWith_ZeroBreakingReportsReachedSitesAndDoesNotGate(t *testing.T) {
	ctr, gomod := zeroBreakingUsedByContainer(t)
	a, b := ifaceDiffCoords()

	var out bytes.Buffer
	if err := interfaceDiffWith(context.Background(), ctr, a, b, interfaceDiffFlags{usedBy: gomod}, &out); err != nil {
		t.Fatalf("a zero-breaking delta fired the used-set gate: %v", err)
	}
	got := out.String()
	for _, want := range []string{
		zeroBreakingBehaviourNote,
		"example.com/app own code calls 1 of the 1 declaration(s) it moved, at 2 recorded call sites",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("zero-breaking used-by output missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, zeroBreakingNoUsedByNote) {
		t.Errorf("the join was made and the output still told the reader to make it:\n%s", got)
	}
}

// The reach count in the zero-breaking statement is a join against the stored
// call graph, so a consumer with no stored graph joins against nothing and the
// count is 0 for a reason that has nothing to do with the consumer's code. It
// must not be printed as a measurement: "calls none of what moved" reads as
// permission to bump, and it is the one line of the block a reader quotes.
func TestInterfaceDiffWith_ZeroBreakingReachIsNotMeasuredWithoutAStoredGraph(t *testing.T) {
	ctr, gomod := zeroBreakingUsedByContainer(t)
	ctr.QueryCallGraph = testfakes.NewFakeQueryCallGraph()
	a, b := ifaceDiffCoords()

	var out bytes.Buffer
	if err := interfaceDiffWith(context.Background(), ctr, a, b, interfaceDiffFlags{usedBy: gomod}, &out); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := out.String()
	if strings.Contains(got, "own code calls 0 of the") {
		t.Errorf("an empty join was printed as a measured zero:\n%s", got)
	}
	for _, want := range []string{
		"could NOT be measured",
		"no stored call graph for it",
		"kanonarion local .",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the unmeasured reach is missing %q:\n%s", want, got)
		}
	}
	// The statement still names the size of what moved: that count comes from
	// the delta, not from the graph, and it is what the reader has to test.
	if !strings.Contains(got, "1 declaration(s) it moved") {
		t.Errorf("the statement dropped the size of the moved set:\n%s", got)
	}
	// The caveat qualifies what it is printed beside, in both directions. It may
	// not point down the page at a number that is above it.
	if strings.Contains(got, "nothing below is a measurement") {
		t.Errorf("the caveat still aims below itself:\n%s", got)
	}
	if !strings.Contains(got, "every reach count and per-declaration row in this report is an absence of evidence") {
		t.Errorf("the caveat does not name what it qualifies:\n%s", got)
	}
}

// The negative control for the test above: a consumer that DOES have a stored
// graph still gets the counts, unchanged. The guard must suppress an absence,
// not a measurement.
func TestInterfaceDiffWith_ZeroBreakingReachIsStillPrintedWithAStoredGraph(t *testing.T) {
	ctr, gomod := zeroBreakingUsedByContainer(t)
	a, b := ifaceDiffCoords()

	var out bytes.Buffer
	if err := interfaceDiffWith(context.Background(), ctr, a, b, interfaceDiffFlags{usedBy: gomod}, &out); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "example.com/app own code calls 1 of the 1 declaration(s) it moved, at 2 recorded call sites") {
		t.Errorf("a measured reach was suppressed:\n%s", got)
	}
	if strings.Contains(got, "could NOT be measured") {
		t.Errorf("a measured reach was reported as unmeasurable:\n%s", got)
	}
	if strings.Contains(got, "no stored call graph") {
		t.Errorf("a consumer with a stored graph was told it has none:\n%s", got)
	}
}

// The JSON shape carries the same discriminator the text does. Every reach
// count in the document is joined against the stored call graph, so a zero is
// only readable beside call_graph_found — which is emitted unconditionally, in
// the same object, with no omitempty to drop it when it is false.
func TestInterfaceDiffJSON_ZeroReachIsAccompaniedByTheAbsenceOfAGraph(t *testing.T) {
	ctr, gomod := zeroBreakingUsedByContainer(t)
	ctr.QueryCallGraph = testfakes.NewFakeQueryCallGraph()
	a, b := ifaceDiffCoords()

	jsonOut = true
	defer func() { jsonOut = false }()

	var out bytes.Buffer
	if err := interfaceDiffWith(context.Background(), ctr, a, b, interfaceDiffFlags{usedBy: gomod}, &out); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var decoded struct {
		UsedBy *map[string]any `json:"used_by"`
	}
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("decoding JSON: %v\n%s", err, out.String())
	}
	if decoded.UsedBy == nil {
		t.Fatalf("used_by absent from JSON:\n%s", out.String())
	}
	got := *decoded.UsedBy
	found, present := got["call_graph_found"]
	if !present {
		t.Fatalf("the counts ship without the field that qualifies them: %+v", got)
	}
	if found != false {
		t.Errorf("call_graph_found = %v, want false", found)
	}
	for _, k := range []string{"reached_count", "touched_reached_count", "touched_call_sites"} {
		v, ok := got[k]
		if !ok {
			t.Errorf("%s absent from the document", k)
			continue
		}
		if v != float64(0) {
			t.Errorf("%s = %v with no stored graph, want 0", k, v)
		}
	}
}

// The control for the line above: the same consumer against a delta that really
// does break it still gates.
func TestInterfaceDiffWith_BreakingStillGatesAlongsideTheStatement(t *testing.T) {
	ctr, gomod := usedByContainer(t, []cgports.CallEdgeRef{{
		ModulePath: "example.com/app", ModuleVersion: coordinate.LocalVersion,
		FromID: "example.com/app/service.Handle", ToID: "example.com/mod.Gone",
	}})
	a, b := ifaceDiffCoords()

	var out bytes.Buffer
	err := interfaceDiffWith(context.Background(), ctr, a, b, interfaceDiffFlags{usedBy: gomod}, &out)
	requireExit(t, err, ExitPolicy)
	if strings.Contains(out.String(), zeroBreakingBehaviourNote) {
		t.Errorf("the statement diluted a real finding:\n%s", out.String())
	}
}

// -- JSON parity --

// The machine-readable answer gains everything the text answer did. A JSON
// consumer that cannot see the renamed-path category or the statement would be
// reading a different diff from the one on screen.
func TestInterfaceDiffJSON_CarriesRenamedPathAndTheStatement(t *testing.T) {
	raw, err := json.Marshal(toInterfaceDiffJSON(crossMajorDiff(t), nil))
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		BreakingCount        int    `json:"breaking_count"`
		MajorPathPair        bool   `json:"major_path_pair"`
		ZeroBreakingAdvisory string `json:"zero_breaking_advisory"`
		PackagesAdded        []any  `json:"packages_added"`
		RenamedPath          []struct {
			Package        string `json:"package"`
			Kind           string `json:"kind"`
			Name           string `json:"name"`
			MovedToPackage string `json:"moved_to_package"`
			Signature      string `json:"signature"`
		} `json:"renamed_path"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.BreakingCount != 0 || !decoded.MajorPathPair {
		t.Errorf("breaking_count=%d major_path_pair=%v", decoded.BreakingCount, decoded.MajorPathPair)
	}
	if len(decoded.RenamedPath) != 2 {
		t.Fatalf("renamed_path = %+v", decoded.RenamedPath)
	}
	r := decoded.RenamedPath[0]
	if r.Package != "example.com/mod" || r.MovedToPackage != "example.com/mod/v3" ||
		r.Name != "TxtFuncMap" || r.Kind != "func" || r.Signature == "" {
		t.Errorf("renamed_path row = %+v", r)
	}
	if !strings.Contains(decoded.ZeroBreakingAdvisory, zeroBreakingBehaviourNote) ||
		!strings.Contains(decoded.ZeroBreakingAdvisory, zeroBreakingCrossMajorNote) {
		t.Errorf("zero_breaking_advisory = %q", decoded.ZeroBreakingAdvisory)
	}
	if !strings.Contains(string(raw), `"renamed_path":[`) {
		t.Errorf("renamed_path is not rendered as an array: %s", raw)
	}
}

// The control: an empty delta and a breaking delta both carry no advisory, and a
// same-path comparison spells renamed_path as an empty array rather than null.
func TestInterfaceDiffJSON_AdvisoryAbsentWhereTheTextIsSilent(t *testing.T) {
	a, b := ifaceDiffCoords()
	for _, tc := range []struct {
		name string
		diff ifacedomain.InterfaceDiff
	}{
		{"empty delta", ifacedomain.InterfaceDiff{
			RecordA: ifacedomain.InterfaceRecord{Coordinate: a},
			RecordB: ifacedomain.InterfaceRecord{Coordinate: b},
		}},
		{"breaking delta", diffWithOneRemoval(t)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(toInterfaceDiffJSON(tc.diff, nil))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), "zero_breaking_advisory") {
				t.Errorf("advisory present where the text is silent: %s", raw)
			}
			if !strings.Contains(string(raw), `"renamed_path":[]`) {
				t.Errorf("renamed_path not rendered as []: %s", raw)
			}
			if !strings.Contains(string(raw), `"major_path_pair":false`) {
				t.Errorf("major_path_pair not stated: %s", raw)
			}
		})
	}
}

// The touched join is in the JSON with its counts, and it is a separate set from
// the gating one so a machine consumer cannot mistake it for a breaking finding.
func TestInterfaceDiffJSON_TouchedJoinIsSeparateFromTheGate(t *testing.T) {
	ctr, gomod := zeroBreakingUsedByContainer(t)
	a, b := ifaceDiffCoords()

	jsonOut = true
	defer func() { jsonOut = false }()

	var out bytes.Buffer
	if err := interfaceDiffWith(context.Background(), ctr, a, b, interfaceDiffFlags{usedBy: gomod}, &out); err != nil {
		t.Fatalf("the zero-breaking join gated: %v", err)
	}
	var decoded struct {
		UsedBy struct {
			ReachedCount        int `json:"reached_count"`
			TouchedReachedCount int `json:"touched_reached_count"`
			TouchedSites        int `json:"touched_call_sites"`
			Symbols             []struct {
				Name string `json:"name"`
			} `json:"symbols"`
			Touched []struct {
				Name  string `json:"name"`
				Class string `json:"class"`
				Sites int    `json:"sites"`
			} `json:"touched"`
		} `json:"used_by"`
	}
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("decoding JSON: %v\n%s", err, out.String())
	}
	if decoded.UsedBy.ReachedCount != 0 || len(decoded.UsedBy.Symbols) != 0 {
		t.Errorf("a non-breaking declaration reached the gating set: %+v", decoded.UsedBy)
	}
	if decoded.UsedBy.TouchedReachedCount != 1 || decoded.UsedBy.TouchedSites != 2 {
		t.Errorf("touched counts = %+v", decoded.UsedBy)
	}
	if len(decoded.UsedBy.Touched) != 1 || decoded.UsedBy.Touched[0].Name != "Cast" ||
		decoded.UsedBy.Touched[0].Class != "touched" || decoded.UsedBy.Touched[0].Sites != 2 {
		t.Errorf("touched = %+v", decoded.UsedBy.Touched)
	}
}

// A cross-major rename is joined on the A-side identity — what the consumer
// calls today, and what its recorded call-graph nodes are spelled as. Joining on
// the B side would find nothing and read as "you do not use this".
func TestTouchedSymbols_RenamesAreNamedOnTheSideTheConsumerCalls(t *testing.T) {
	got := touchedSymbols(crossMajorDiff(t))
	if len(got) != 2 {
		t.Fatalf("touchedSymbols = %+v", got)
	}
	for _, d := range got {
		if d.Symbol.Package != "example.com/mod" {
			t.Errorf("touched symbol named on the B side: %+v", d)
		}
		if d.Removed {
			t.Errorf("a touched declaration was classed as removed: %+v", d)
		}
	}
	// And the gating set stays empty: nothing here can break a consumer.
	if bs := breakingSymbols(crossMajorDiff(t)); len(bs) != 0 {
		t.Errorf("breakingSymbols = %+v on a pure rename", bs)
	}
}
