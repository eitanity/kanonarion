package cli

import (
	"context"
	"errors"
	"testing"
	"time"

	cgsqlite "code.eitanity.com/kanonarion/internal/callgraph/adapters/store/sqlite"
	cgapp "code.eitanity.com/kanonarion/internal/callgraph/application"
	cgdomain "code.eitanity.com/kanonarion/internal/callgraph/domain"
	capapp "code.eitanity.com/kanonarion/internal/capability/application"
	"code.eitanity.com/kanonarion/internal/coordinate/coordinatetest"
	fetchdomain "code.eitanity.com/kanonarion/internal/fetch/domain"
	"code.eitanity.com/kanonarion/internal/vuln/adapters/reachability"
	"code.eitanity.com/kanonarion/internal/vuln/adapters/rootclass"
	vuldomain "code.eitanity.com/kanonarion/internal/vuln/domain"
)

var (
	inheritCoord = coordinatetest.MustNew("example.com/app", "v1.0.0")
	inheritWasm  = cgdomain.BuildFrame{GOOS: "wasip1", GOARCH: "wasm"}
)

// inheritRecord is one frame's graph of inheritCoord, holding one function
// named for the frame, so a read shows which frame answered by which node it
// finds.
func inheritRecord(t *testing.T, f cgdomain.BuildFrame, symbol string, at time.Time) cgdomain.CallGraphRecord {
	t.Helper()
	id := "example.com/app/handlers." + symbol
	r := cgdomain.CallGraphRecord{
		SchemaVersion: cgdomain.CallGraphSchemaVersion, Ecosystem: fetchdomain.EcosystemGo,
		Coordinate: inheritCoord, Algorithm: cgdomain.AlgorithmCHA,
		Completeness: cgdomain.CompletenessBuiltWithBodies, OverallStatus: cgdomain.CallGraphStatusExtracted,
		AnalysisSource: cgdomain.AnalysisSourceModuleZip, ArtefactIdentity: "zip:h1:app",
		Nodes: []cgdomain.CallNode{
			{ID: id, Module: "example.com/app", Package: "example.com/app/handlers", Symbol: symbol, IsExportedAPI: true},
			{ID: "os.Getenv", Package: "os", Symbol: "Getenv", IsExternal: true},
		},
		Edges:     []cgdomain.CallEdge{{FromID: id, ToID: "os.Getenv", Confidence: cgdomain.ConfidenceDirect, CallSite: cgdomain.SourcePosition{File: "h.go", Line: 3}}},
		NodeCount: 2, EdgeCount: 1, ExtractedAt: at, PipelineVersion: cgapp.PipelineVersion, Frame: f,
	}
	sealed, err := cgdomain.CallGraphRecordHasher{}.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	return sealed
}

// inheritStore holds a host and a wasip1 graph of one coordinate, the wasip1 one
// newer, and reads in frame.
func inheritStore(t *testing.T, frame cgdomain.BuildFrame) *cgsqlite.Store {
	t.Helper()
	s, err := cgsqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for i, r := range []cgdomain.CallGraphRecord{
		inheritRecord(t, hostFrame(), "Host", at), inheritRecord(t, inheritWasm, "Wasm", at.Add(time.Hour)),
	} {
		if perr := s.PutCallGraphRecord(context.Background(), r); perr != nil {
			t.Fatalf("PutCallGraphRecord %d: %v", i, perr)
		}
	}
	s.WithReadFrame(frame)
	return s
}

// inheritCases are the two frames a read can be in, and the function each
// frame's graph holds.
func inheritCases() []struct {
	frame  cgdomain.BuildFrame
	symbol string
} {
	return []struct {
		frame  cgdomain.BuildFrame
		symbol string
	}{{inheritWasm, "Wasm"}, {hostFrame(), "Host"}}
}

// Capability reads through GetCallGraphRecord and is served the read frame's
// graph with no frame of its own.
func TestReadFrame_CapabilityInheritsTheSelection(t *testing.T) {
	for _, tc := range inheritCases() {
		uc := capapp.NewAnalyseCapabilitiesUseCase(inheritStore(t, tc.frame))
		report, err := uc.Analyse(context.Background(), inheritCoord, cgapp.PipelineVersion, cgdomain.RootScopeProduction)
		if err != nil {
			t.Fatalf("Analyse under %s: %v", tc.frame, err)
		}
		found := false
		for _, r := range report.Rows {
			found = found || r.Caller == "example.com/app/handlers."+tc.symbol
		}
		if !found {
			t.Errorf("capability under %s did not read the %s graph: %+v", tc.frame, tc.symbol, report.Rows)
		}
	}
}

// The vuln reachability loader projects the read frame's graph.
func TestReadFrame_VulnLoaderInheritsTheSelection(t *testing.T) {
	for _, tc := range inheritCases() {
		proj, err := reachability.NewCallGraphStoreLoader(inheritStore(t, tc.frame), cgapp.PipelineVersion).
			Load(context.Background(), inheritCoord)
		if err != nil {
			t.Fatalf("Load under %s: %v", tc.frame, err)
		}
		found := false
		for _, n := range proj.Nodes {
			found = found || n.ID == "example.com/app/handlers."+tc.symbol
		}
		if !found {
			t.Errorf("the loader under %s projected %+v, want the %s graph", tc.frame, proj.Nodes, tc.symbol)
		}
	}
	if _, err := reachability.NewCallGraphStoreLoader(inheritStore(t, cgdomain.BuildFrame{GOOS: "plan9", GOARCH: "386"}), cgapp.PipelineVersion).
		Load(context.Background(), inheritCoord); err == nil {
		t.Error("a frame the ledger holds no graph of was served one")
	}
}

// The call-site reader answers from the read frame's graph.
func TestReadFrame_CallSiteReaderInheritsTheSelection(t *testing.T) {
	wasm := "example.com/app/handlers.Wasm"
	for _, tc := range inheritCases() {
		known := tc.symbol == "Wasm"
		ans, err := reachability.NewCallSiteStoreReader(inheritStore(t, tc.frame), cgapp.PipelineVersion).
			ReadCallSites(context.Background(), inheritCoord, []string{wasm})
		if err != nil {
			t.Fatalf("ReadCallSites under %s: %v", tc.frame, err)
		}
		if !ans.Served || ans.KnownCallers[wasm] != known {
			t.Errorf("under %s: served=%v, %s known=%v, want known=%v", tc.frame, ans.Served, wasm, ans.KnownCallers[wasm], known)
		}
	}
}

// The route-root classifier resolves an entry point against the read frame's
// graph: the wasip1 function is a node there and absent from the host graph.
func TestReadFrame_RootClassifierInheritsTheSelection(t *testing.T) {
	route := vuldomain.ReachabilityRoute{
		{ModulePath: "example.com/app", ModuleVersion: "v1.0.0", Package: "example.com/app/handlers", Symbol: "Wasm"},
		{ModulePath: "example.com/dep", ModuleVersion: "v1.2.0", Package: "example.com/dep", Symbol: "Parse"},
	}
	rooting := vuldomain.TargetRootedAt(inheritCoord)
	for _, tc := range inheritCases() {
		resolved := tc.symbol == "Wasm"
		got := rootclass.New(inheritStore(t, tc.frame), cgapp.PipelineVersion).
			Classify(context.Background(), rooting, inheritCoord, route)
		if (got.NodeID == "example.com/app/handlers.Wasm") != resolved {
			t.Errorf("under %s the root resolved to %q (%s), want resolved=%v", tc.frame, got.NodeID, got.Reason, resolved)
		}
	}
}

// Under no read frame, two frames of one coordinate are refused by name rather
// than one of them answering.
func TestReadFrame_NoneInForceRefusesSeveralFrames(t *testing.T) {
	_, _, err := inheritStore(t, cgdomain.BuildFrame{}).GetCallGraphRecord(context.Background(), inheritCoord, cgapp.PipelineVersion)
	var c cgdomain.CallGraphConflict
	if !errors.As(err, &c) || c.Field != cgdomain.ConflictFieldFrame {
		t.Fatalf("GetCallGraphRecord with no read frame = %v, want a frame conflict", err)
	}
}
