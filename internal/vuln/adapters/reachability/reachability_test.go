package reachability_test

import (
	"context"
	"fmt"
	"testing"

	callgraphdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/vuln/adapters/reachability"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

// fakeLoader is a ports.CallGraphLoader backed by a fixed record.
type fakeLoader struct {
	record ports.CallGraphProjection
	err    error
}

func (f *fakeLoader) Load(_ context.Context, _ fetchdomain.ModuleCoordinate) (ports.CallGraphProjection, error) {
	return f.record, f.err
}

func TestAnalyse_NoCallGraph_ReturnsUnknown(t *testing.T) {
	a := reachability.New()
	coord := fetchdomain.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}
	symbols := []ports.SymbolReference{{Module: "github.com/foo/bar", Package: "bar", Symbol: "Vulnerable"}}

	result, err := a.Analyse(t.Context(), coord, symbols, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Confidence != domain.ConfidenceUnknown {
		t.Errorf("confidence: got %s, want %s", result.Confidence, domain.ConfidenceUnknown)
	}
	if result.IsReachable {
		t.Error("expected not reachable when no call graph provided")
	}
}

func TestAnalyse_EmptySymbols_NotReachable(t *testing.T) {
	a := reachability.New()
	coord := fetchdomain.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}

	result, err := a.Analyse(t.Context(), coord, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsReachable {
		t.Error("expected not reachable for empty symbol list")
	}
}

func TestAnalyse_ReturnsUnknownConfidence(t *testing.T) {
	a := reachability.New()
	coord := fetchdomain.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}
	symbols := []ports.SymbolReference{
		{Module: "github.com/foo/bar", Package: "bar", Symbol: "DoSomething"},
		{Module: "github.com/foo/bar", Package: "bar", Symbol: "DoSomethingElse"},
	}

	result, err := a.Analyse(t.Context(), coord, symbols, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Confidence != domain.ConfidenceUnknown {
		t.Errorf("confidence: got %s, want Unknown", result.Confidence)
	}
}

func TestAnalyse_LoadError_ReturnsError(t *testing.T) {
	a := reachability.New()
	coord := fetchdomain.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}
	symbols := []ports.SymbolReference{{Module: "github.com/foo/bar", Symbol: "Vuln"}}
	loader := &fakeLoader{err: fmt.Errorf("store unavailable")}

	_, err := a.Analyse(t.Context(), coord, symbols, loader)
	if err == nil {
		t.Fatal("expected error from failed loader, got nil")
	}
}

func TestAnalyse_Reachable_DirectEntryPoint(t *testing.T) {
	// The vulnerable function IS an exported entry point — trivially reachable.
	a := reachability.New()
	coord := fetchdomain.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}

	loader := &fakeLoader{record: ports.CallGraphProjection{
		Nodes: []ports.CallGraphNode{
			{ID: "github.com/foo/bar.Vuln", Module: "github.com/foo/bar", Package: "github.com/foo/bar", Symbol: "Vuln", IsExportedAPI: true, IsExternal: false},
		},
	}}
	symbols := []ports.SymbolReference{{Module: "github.com/foo/bar", Symbol: "Vuln"}}

	result, err := a.Analyse(t.Context(), coord, symbols, loader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsReachable {
		t.Error("expected reachable")
	}
	if result.Confidence != domain.ConfidenceHigh {
		t.Errorf("confidence: got %s, want High", result.Confidence)
	}
	if len(result.ExamplePaths) == 0 || len(result.ExamplePaths[0]) == 0 {
		t.Error("expected non-empty example path")
	}
}

// dynamicSinkProjection mirrors the capability-domain fixture: an exported API
// plus an unexported, non-init function that reaches the vulnerable symbol and
// is entered only by runtime dispatch. Nothing exported calls it.
func dynamicSinkProjection(kind string) ports.CallGraphProjection {
	return ports.CallGraphProjection{
		Nodes: []ports.CallGraphNode{
			{ID: "github.com/foo/bar.Exported", Module: "github.com/foo/bar", Symbol: "Exported", IsExportedAPI: true},
			{ID: "github.com/foo/bar.handler", Module: "github.com/foo/bar", Symbol: "handler"},
			{ID: "github.com/foo/bar.Vuln", Module: "github.com/foo/bar", Symbol: "Vuln"},
		},
		Edges: []ports.CallGraphEdge{
			{FromID: "github.com/foo/bar.handler", ToID: "github.com/foo/bar.Vuln"},
		},
		ArtifactKind: kind,
	}
}

func TestAnalyse_Application_ReachesDynamicallyDispatchedSymbol(t *testing.T) {
	a := reachability.New()
	coord := fetchdomain.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}
	loader := &fakeLoader{record: dynamicSinkProjection(string(callgraphdomain.ArtifactApplication))}
	symbols := []ports.SymbolReference{{Module: "github.com/foo/bar", Symbol: "Vuln"}}

	result, err := a.Analyse(t.Context(), coord, symbols, loader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsReachable {
		t.Error("expected reachable: the handler is application code whatever dispatches it")
	}
}

func TestAnalyse_Library_DoesNotReachDynamicallyDispatchedSymbol(t *testing.T) {
	// The library side of the same switch: a consumer can only enter through the
	// exported API, which does not reach the vulnerable symbol.
	a := reachability.New()
	coord := fetchdomain.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}
	loader := &fakeLoader{record: dynamicSinkProjection(string(callgraphdomain.ArtifactLibrary))}
	symbols := []ports.SymbolReference{{Module: "github.com/foo/bar", Symbol: "Vuln"}}

	result, err := a.Analyse(t.Context(), coord, symbols, loader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsReachable {
		t.Error("expected not reachable from a library's exported API")
	}
}

func TestAnalyse_Reachable_TransitiveCall(t *testing.T) {
	// Entry → Intermediate → Vulnerable
	a := reachability.New()
	coord := fetchdomain.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}

	loader := &fakeLoader{record: ports.CallGraphProjection{
		Nodes: []ports.CallGraphNode{
			{ID: "github.com/foo/bar.Entry", Module: "github.com/foo/bar", Symbol: "Entry", IsExportedAPI: true, IsExternal: false},
			{ID: "github.com/foo/bar.Mid", Module: "github.com/foo/bar", Symbol: "Mid", IsExportedAPI: false, IsExternal: false},
			{ID: "github.com/foo/bar.Vuln", Module: "github.com/foo/bar", Symbol: "Vuln", IsExportedAPI: false, IsExternal: false},
		},
		Edges: []ports.CallGraphEdge{
			{FromID: "github.com/foo/bar.Entry", ToID: "github.com/foo/bar.Mid"},
			{FromID: "github.com/foo/bar.Mid", ToID: "github.com/foo/bar.Vuln"},
		},
	}}
	symbols := []ports.SymbolReference{{Module: "github.com/foo/bar", Symbol: "Vuln"}}

	result, err := a.Analyse(t.Context(), coord, symbols, loader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsReachable {
		t.Error("expected reachable via transitive call")
	}
	if result.Confidence != domain.ConfidenceHigh {
		t.Errorf("confidence: got %s, want High", result.Confidence)
	}
	// Path should be Entry → Mid → Vuln (3 nodes)
	if len(result.ExamplePaths) == 0 || len(result.ExamplePaths[0]) != 3 {
		t.Errorf("expected path length 3, got %v", result.ExamplePaths)
	}
}

func TestAnalyse_NotReachable_DisconnectedGraph(t *testing.T) {
	// Entry exists, Vulnerable exists, but no edge connecting them.
	a := reachability.New()
	coord := fetchdomain.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}

	loader := &fakeLoader{record: ports.CallGraphProjection{
		Nodes: []ports.CallGraphNode{
			{ID: "github.com/foo/bar.Entry", Module: "github.com/foo/bar", Symbol: "Entry", IsExportedAPI: true, IsExternal: false},
			{ID: "github.com/foo/bar.Vuln", Module: "github.com/foo/bar", Symbol: "Vuln", IsExportedAPI: false, IsExternal: false},
		},
		// No edges
	}}
	symbols := []ports.SymbolReference{{Module: "github.com/foo/bar", Symbol: "Vuln"}}

	result, err := a.Analyse(t.Context(), coord, symbols, loader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsReachable {
		t.Error("expected not reachable in disconnected graph")
	}
	if result.Confidence != domain.ConfidenceHigh {
		t.Errorf("confidence: got %s, want High", result.Confidence)
	}
}

func TestAnalyse_ReachableViaInitRoot(t *testing.T) {
	// The vulnerable function is reachable ONLY through a package init chain,
	// with no exported-API path. An exported node is present so the owned-node
	// fallback does not fire — this isolates init as a reachability root.
	a := reachability.New()
	coord := fetchdomain.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}

	loader := &fakeLoader{record: ports.CallGraphProjection{
		Nodes: []ports.CallGraphNode{
			{ID: "github.com/foo/bar.Exported", Module: "github.com/foo/bar", Symbol: "Exported", IsExportedAPI: true, IsExternal: false},
			{ID: "github.com/foo/bar.init", Module: "github.com/foo/bar", Symbol: "init", IsExportedAPI: false, IsExternal: false},
			{ID: "github.com/foo/bar.Vuln", Module: "github.com/foo/bar", Symbol: "Vuln", IsExportedAPI: false, IsExternal: false},
		},
		Edges: []ports.CallGraphEdge{
			// Only the init chain reaches Vuln; Exported reaches nothing.
			{FromID: "github.com/foo/bar.init", ToID: "github.com/foo/bar.Vuln"},
		},
	}}
	symbols := []ports.SymbolReference{{Module: "github.com/foo/bar", Symbol: "Vuln"}}

	result, err := a.Analyse(t.Context(), coord, symbols, loader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsReachable {
		t.Error("expected reachable via package init root")
	}
	if len(result.ExamplePaths) == 0 || result.ExamplePaths[0][0] != "github.com/foo/bar.init" {
		t.Errorf("expected witness path rooted at init, got %v", result.ExamplePaths)
	}
}

func TestAnalyse_NoExportedOrInit_FallsBackToOwnedRoots(t *testing.T) {
	// Graph has only internal non-exported, non-init nodes. With no exported API
	// or init to root at, the shared selector falls back to every owned node, so
	// the vulnerable owned node is itself a root and reports reachable.
	a := reachability.New()
	coord := fetchdomain.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}

	loader := &fakeLoader{record: ports.CallGraphProjection{
		Nodes: []ports.CallGraphNode{
			{ID: "github.com/foo/bar.internal", Module: "github.com/foo/bar", Symbol: "internal", IsExportedAPI: false, IsExternal: false},
			{ID: "github.com/foo/bar.Vuln", Module: "github.com/foo/bar", Symbol: "Vuln", IsExportedAPI: false, IsExternal: false},
		},
	}}
	symbols := []ports.SymbolReference{{Module: "github.com/foo/bar", Symbol: "Vuln"}}

	result, err := a.Analyse(t.Context(), coord, symbols, loader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsReachable {
		t.Error("expected reachable via owned-node fallback root")
	}
	if result.Confidence != domain.ConfidenceHigh {
		t.Errorf("confidence: got %s, want High", result.Confidence)
	}
}

func TestAnalyse_SymbolNotInGraph_HighConfidenceNotReachable(t *testing.T) {
	// Symbol doesn't appear in the call graph at all.
	a := reachability.New()
	coord := fetchdomain.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}

	loader := &fakeLoader{record: ports.CallGraphProjection{
		Nodes: []ports.CallGraphNode{
			{ID: "github.com/foo/bar.Entry", Module: "github.com/foo/bar", Symbol: "Entry", IsExportedAPI: true, IsExternal: false},
		},
	}}
	symbols := []ports.SymbolReference{{Module: "github.com/foo/bar", Symbol: "DoesNotExist"}}

	result, err := a.Analyse(t.Context(), coord, symbols, loader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsReachable {
		t.Error("expected not reachable when symbol not in graph")
	}
	if result.Confidence != domain.ConfidenceHigh {
		t.Errorf("confidence: got %s, want High", result.Confidence)
	}
}

func TestAnalyse_MethodSymbol_MatchedByReceiverDotName(t *testing.T) {
	// govulncheck emits method symbols as "(*T).Method"; match against receiver.symbol.
	a := reachability.New()
	coord := fetchdomain.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}

	loader := &fakeLoader{record: ports.CallGraphProjection{
		Nodes: []ports.CallGraphNode{
			{ID: "github.com/foo/bar.(*Client).Do", Module: "github.com/foo/bar", Symbol: "Do", Receiver: "(*Client)", IsExportedAPI: true, IsExternal: false},
		},
	}}
	symbols := []ports.SymbolReference{{Module: "github.com/foo/bar", Symbol: "(*Client).Do"}}

	result, err := a.Analyse(t.Context(), coord, symbols, loader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsReachable {
		t.Error("expected method to be reachable when it is an exported entry point")
	}
}
