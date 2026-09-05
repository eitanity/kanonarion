package domain

import (
	"reflect"
	"testing"

	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
)

func node(id, pkg, sym string, external, exported bool) cgdomain.CallNode {
	return cgdomain.CallNode{
		ID:            id,
		Package:       pkg,
		Symbol:        sym,
		IsExternal:    external,
		IsExportedAPI: exported,
	}
}

func edge(from, to string, c cgdomain.EdgeConfidence) cgdomain.CallEdge {
	return cgdomain.CallEdge{FromID: from, ToID: to, Confidence: c}
}

// richGraph exercises all four confidences and multiple capabilities.
func richGraph() cgdomain.CallGraphRecord {
	return cgdomain.CallGraphRecord{
		OverallStatus: cgdomain.CallGraphStatusExtracted,
		Nodes: []cgdomain.CallNode{
			node("m.Root", "m", "Root", false, true),
			node("m.Mid", "m", "Mid", false, false),
			node("net/http.Get", "net/http", "Get", true, false),
			node("net.Dial", "net", "Dial", true, false),
			node("os/exec.Command", "os/exec", "Command", true, false),
			node("reflect.ValueOf", "reflect", "ValueOf", true, false),
			node("syscall.Syscall", "syscall", "Syscall", true, false),
			node("dangling.Fn", "dangling", "Fn", true, false), // not a sink
		},
		Edges: []cgdomain.CallEdge{
			edge("m.Root", "m.Mid", cgdomain.ConfidenceDirect),
			edge("m.Root", "m.Mid", cgdomain.ConfidenceCHAOverapprox), // adjacency tiebreak
			edge("m.Mid", "net/http.Get", cgdomain.ConfidenceDirect),
			edge("m.Root", "net.Dial", cgdomain.ConfidenceUnknown), // weaker NETWORK witness
			edge("m.Root", "os/exec.Command", cgdomain.ConfidenceCHAOverapprox),
			edge("m.Mid", "reflect.ValueOf", cgdomain.ConfidenceUnknown),
			edge("m.Root", "syscall.Syscall", cgdomain.ConfidenceUnknown),
			edge("m.Mid", "missing.Node", cgdomain.ConfidenceDirect), // ToID not in nodes
		},
	}
}

func findingFor(r CapabilityReport, c Capability) (CapabilityFinding, bool) {
	for _, f := range r.Findings {
		if f.Capability == c {
			return f, true
		}
	}
	return CapabilityFinding{}, false
}

func observationFor(r CapabilityReport, c Capability) (CapabilityFinding, bool) {
	for _, f := range r.Observations {
		if f.Capability == c {
			return f, true
		}
	}
	return CapabilityFinding{}, false
}

// TestAnalyseWitnessesBodyLevelCapabilities is the body-level capability
// regression: two capabilities are properties of the module's OWN function
// bodies, not of any callee identity, so the sink map alone cannot witness them.
// UNSAFE_POINTER comes from an owned helper that converts through
// unsafe.Pointer; ARBITRARY_EXECUTION from an owned assembly/linkname leaf with
// no Go body. Both are in non-sink packages, so without the body facts neither
// would appear.
func TestAnalyseWitnessesBodyLevelCapabilities(t *testing.T) {
	unsafeLeaf := cgdomain.CallNode{
		ID: "m/internal.toBytes", Package: "m/internal", Module: "m",
		Symbol: "toBytes", UsesUnsafePointer: true,
	}
	asmLeaf := cgdomain.CallNode{
		ID: "m/internal.asmRound", Package: "m/internal", Module: "m",
		Symbol: "asmRound", IsAssemblyOrLinkname: true,
	}
	rec := cgdomain.CallGraphRecord{
		OverallStatus: cgdomain.CallGraphStatusExtracted,
		Nodes: []cgdomain.CallNode{
			node("m.Root", "m", "Root", false, true),
			unsafeLeaf,
			asmLeaf,
		},
		Edges: []cgdomain.CallEdge{
			edge("m.Root", "m/internal.toBytes", cgdomain.ConfidenceDirect),
			edge("m.Root", "m/internal.asmRound", cgdomain.ConfidenceCHAOverapprox),
		},
	}

	report := Analyse(rec, SelectRoots(rec, cgdomain.RootScopeProduction))

	up, ok := findingFor(report, CapabilityUnsafePointer)
	if !ok {
		t.Fatalf("UNSAFE_POINTER not witnessed; got %v", report.Capabilities())
	}
	if up.Basis != BasisUse {
		t.Errorf("UNSAFE_POINTER basis = %q, want use", up.Basis)
	}
	if up.WeakestConfidence != cgdomain.ConfidenceDirect {
		t.Errorf("UNSAFE_POINTER weakest = %q, want Direct", up.WeakestConfidence)
	}
	if up.SinkPackage != "m/internal" || up.SinkSymbol != "toBytes" {
		t.Errorf("UNSAFE_POINTER sink = %s.%s, want m/internal.toBytes", up.SinkPackage, up.SinkSymbol)
	}

	ae, ok := findingFor(report, CapabilityArbitraryExecution)
	if !ok {
		t.Fatalf("ARBITRARY_EXECUTION not witnessed; got %v", report.Capabilities())
	}
	if ae.Basis != BasisUse {
		t.Errorf("ARBITRARY_EXECUTION basis = %q, want use", ae.Basis)
	}
	if ae.WeakestConfidence != cgdomain.ConfidenceCHAOverapprox {
		t.Errorf("ARBITRARY_EXECUTION weakest = %q, want CHA-overapprox", ae.WeakestConfidence)
	}

	// Control: strip the body facts and the two capabilities vanish — proving
	// they are witnessed only by the facts, never by callee identity.
	rec.Nodes[1].UsesUnsafePointer = false
	rec.Nodes[2].IsAssemblyOrLinkname = false
	if got := Analyse(rec, SelectRoots(rec, cgdomain.RootScopeProduction)); len(got.Findings) != 0 {
		t.Errorf("without body facts the non-sink leaves witness nothing, got %v", got.Capabilities())
	}
}

// TestAnalyseDoesNotWitnessExternalBodyFacts is the same graph with the two
// body-fact leaves owned by somebody else. Taking a mutex is not this module's
// unsafe pointer arithmetic and sleeping is not its arbitrary execution, so
// neither is a capability — and neither is silently dropped either.
func TestAnalyseDoesNotWitnessExternalBodyFacts(t *testing.T) {
	rec := cgdomain.CallGraphRecord{
		OverallStatus: cgdomain.CallGraphStatusExtracted,
		Nodes: []cgdomain.CallNode{
			node("m.Root", "m", "Root", false, true),
			{
				ID: "sync.(*RWMutex).Lock", Package: "sync", Receiver: "*RWMutex", Symbol: "Lock",
				IsExternal: true, UsesUnsafePointer: true,
			},
			{
				ID: "time.Sleep", Package: "time", Symbol: "Sleep",
				IsExternal: true, IsAssemblyOrLinkname: true,
			},
		},
		Edges: []cgdomain.CallEdge{
			edge("m.Root", "sync.(*RWMutex).Lock", cgdomain.ConfidenceDirect),
			edge("m.Root", "time.Sleep", cgdomain.ConfidenceDirect),
		},
	}

	report := Analyse(rec, SelectRoots(rec, cgdomain.RootScopeProduction))
	if len(report.Findings) != 0 {
		t.Errorf("external body facts are not capabilities, got %v", report.Capabilities())
	}
	for _, c := range []Capability{CapabilityUnsafePointer, CapabilityArbitraryExecution} {
		obs, ok := observationFor(report, c)
		if !ok {
			t.Fatalf("%s should be reported as an observation, not dropped", c)
		}
		if obs.Basis != BasisCalleeBodyFact {
			t.Errorf("%s observation basis = %q, want callee_body_fact", c, obs.Basis)
		}
	}
}

// TestAnalyseTreatsExternalInitAsLinkage covers the other half: reaching a
// package's initialiser says the package is linked, and a real call into the
// same package still witnesses the capability outright.
func TestAnalyseTreatsExternalInitAsLinkage(t *testing.T) {
	rec := cgdomain.CallGraphRecord{
		OverallStatus: cgdomain.CallGraphStatusExtracted,
		Nodes: []cgdomain.CallNode{
			node("m.Root", "m", "Root", false, true),
			node("m.init", "m", "init", false, false),
			node("os/exec.init", "os/exec", "init", true, false),
			node("net/http.init", "net/http", "init", true, false),
			node("net/http.Get", "net/http", "Get", true, false),
		},
		Edges: []cgdomain.CallEdge{
			edge("m.init", "os/exec.init", cgdomain.ConfidenceDirect),
			edge("m.init", "net/http.init", cgdomain.ConfidenceDirect),
			edge("m.Root", "net/http.Get", cgdomain.ConfidenceDirect),
		},
	}

	report := Analyse(rec, SelectRoots(rec, cgdomain.RootScopeProduction))

	if _, ok := findingFor(report, CapabilityExec); ok {
		t.Error("reaching os/exec.init must not witness EXEC")
	}
	obs, ok := observationFor(report, CapabilityExec)
	if !ok {
		t.Fatal("EXEC should be reported as a linkage observation")
	}
	if obs.Basis != BasisLinkageOnly {
		t.Errorf("EXEC observation basis = %q, want linkage_only", obs.Basis)
	}
	// The init root itself still works, and the real call outranks the linkage:
	// NETWORK is a capability and carries no observation beside it.
	net, ok := findingFor(report, CapabilityNetwork)
	if !ok || net.SinkSymbol != "Get" {
		t.Fatalf("NETWORK should be witnessed by net/http.Get, got %+v", net)
	}
	if _, ok := observationFor(report, CapabilityNetwork); ok {
		t.Error("a capability with a real witness must not also carry an observation")
	}
}

func TestAnalyseReaches12of12WithBodyFacts(t *testing.T) {
	rec := cgdomain.CallGraphRecord{
		OverallStatus: cgdomain.CallGraphStatusExtracted,
		Nodes: []cgdomain.CallNode{
			node("m.Root", "m", "Root", false, true),
			node("net/http.Get", "net/http", "Get", true, false),
			node("os.ReadFile", "os", "ReadFile", true, false),
			node("os/exec.Command", "os/exec", "Command", true, false),
			node("reflect.ValueOf", "reflect", "ValueOf", true, false),
			node("runtime/cgo.Handle", "runtime/cgo", "NewHandle", true, false),
			node("syscall.Syscall", "syscall", "Syscall", true, false),
			node("runtime.GC", "runtime", "GC", true, false),
			node("os.Getenv", "os", "Getenv", true, false),
			node("os/signal.Notify", "os/signal", "Notify", true, false),
			node("os.Getpid", "os", "Getpid", true, false),
			{ID: "m/internal.unsafeFn", Package: "m/internal", Symbol: "unsafeFn", UsesUnsafePointer: true},
			{ID: "m/internal.asmFn", Package: "m/internal", Symbol: "asmFn", IsAssemblyOrLinkname: true},
		},
	}
	for _, n := range rec.Nodes {
		if n.ID == "m.Root" {
			continue
		}
		rec.Edges = append(rec.Edges, edge("m.Root", n.ID, cgdomain.ConfidenceDirect))
	}

	report := Analyse(rec, SelectRoots(rec, cgdomain.RootScopeProduction))
	got := report.Capabilities()
	if len(got) != 12 {
		t.Fatalf("got %d capabilities, want 12: %v", len(got), got)
	}
	for _, want := range AllCapabilities() {
		if _, ok := findingFor(report, want); !ok {
			t.Errorf("missing capability %s", want)
		}
	}
	if len(report.Observations) != 0 {
		t.Errorf("no observation expected, got %+v", report.Observations)
	}
}

func TestAnalyseWitnessesCapabilitiesWithWeakestEdge(t *testing.T) {
	rec := richGraph()
	report := Analyse(rec, SelectRoots(rec, cgdomain.RootScopeProduction))

	if report.Partial {
		t.Error("Extracted graph should not be Partial")
	}

	want := map[Capability]cgdomain.EdgeConfidence{
		CapabilityNetwork:     cgdomain.ConfidenceDirect,        // via m.Mid → net/http.Get, all Direct
		CapabilityExec:        cgdomain.ConfidenceCHAOverapprox, // root → os/exec.Command
		CapabilityReflect:     cgdomain.ConfidenceUnknown,       // reflect edge folds to Unknown
		CapabilitySystemCalls: cgdomain.ConfidenceUnknown,       // Unknown edge
	}
	if len(report.Findings) != len(want) {
		t.Fatalf("got %d findings, want %d: %+v", len(report.Findings), len(want), report.Capabilities())
	}
	for c, conf := range want {
		f, ok := findingFor(report, c)
		if !ok {
			t.Errorf("missing capability %s", c)
			continue
		}
		if f.WeakestConfidence != conf {
			t.Errorf("%s weakest = %q, want %q (path %v)", c, f.WeakestConfidence, conf, f.Path)
		}
	}
}

func TestAnalyseKeepsStrongestWitnessPerCapability(t *testing.T) {
	// NETWORK is witnessed by a Direct path (net/http.Get) and an Unknown path
	// (net.Dial); the Direct one must win.
	rec := richGraph()
	report := Analyse(rec, SelectRoots(rec, cgdomain.RootScopeProduction))
	f, ok := findingFor(report, CapabilityNetwork)
	if !ok {
		t.Fatal("NETWORK not found")
	}
	if f.WeakestConfidence != cgdomain.ConfidenceDirect {
		t.Errorf("NETWORK weakest = %q, want Direct", f.WeakestConfidence)
	}
	wantPath := []string{"m.Root", "m.Mid", "net/http.Get"}
	if !reflect.DeepEqual(f.Path, wantPath) {
		t.Errorf("NETWORK path = %v, want %v", f.Path, wantPath)
	}
	if f.SinkPackage != "net/http" || f.SinkSymbol != "Get" {
		t.Errorf("sink = %s.%s, want net/http.Get", f.SinkPackage, f.SinkSymbol)
	}
}

func TestAnalyseRootIsItselfASink(t *testing.T) {
	rec := richGraph()
	// Root the analysis directly at a sink node: zero-edge path, Direct.
	report := Analyse(rec, []string{"net/http.Get"})
	f, ok := findingFor(report, CapabilityNetwork)
	if !ok {
		t.Fatal("NETWORK not found")
	}
	if f.WeakestConfidence != cgdomain.ConfidenceDirect {
		t.Errorf("zero-edge weakest = %q, want Direct", f.WeakestConfidence)
	}
	if !reflect.DeepEqual(f.Path, []string{"net/http.Get"}) {
		t.Errorf("path = %v, want single node", f.Path)
	}
}

func TestAnalyseSkipsMissingRoot(t *testing.T) {
	rec := richGraph()
	report := Analyse(rec, []string{"does.NotExist"})
	if len(report.Findings) != 0 {
		t.Errorf("missing root should witness nothing, got %v", report.Capabilities())
	}
}

func TestAnalysePartialGraphIsCaveated(t *testing.T) {
	rec := richGraph()
	rec.OverallStatus = cgdomain.CallGraphStatusPartial
	report := Analyse(rec, SelectRoots(rec, cgdomain.RootScopeProduction))
	if !report.Partial {
		t.Fatal("Partial status should set Partial")
	}
	if report.Caveat == "" {
		t.Error("Partial report must carry a Caveat")
	}
}

func TestCapabilitiesSorted(t *testing.T) {
	r := CapabilityReport{Findings: []CapabilityFinding{
		{Capability: CapabilityReflect},
		{Capability: CapabilityExec},
		{Capability: CapabilityNetwork},
	}}
	got := r.Capabilities()
	want := []Capability{CapabilityExec, CapabilityNetwork, CapabilityReflect}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Capabilities = %v, want %v", got, want)
	}
}

// TestAnalyseWitnessesInitOnlyCapability is the init-root regression: a
// capability sink reachable ONLY through a package init chain — with no
// exported-API path — must still be witnessed, because init runs
// unconditionally at package load. Before init nodes rooted the traversal this
// was a false-"safe" omission.
func TestAnalyseWitnessesInitOnlyCapability(t *testing.T) {
	rec := cgdomain.CallGraphRecord{
		OverallStatus: cgdomain.CallGraphStatusExtracted,
		Nodes: []cgdomain.CallNode{
			node("m.init", "m", "init", false, false),        // owned init, not exported
			node("m.Exported", "m", "Exported", false, true), // exported, reaches no sink
			node("net/http.Get", "net/http", "Get", true, false),
		},
		Edges: []cgdomain.CallEdge{
			edge("m.init", "net/http.Get", cgdomain.ConfidenceDirect),
		},
	}

	report := Analyse(rec, SelectRoots(rec, cgdomain.RootScopeProduction))
	f, ok := findingFor(report, CapabilityNetwork)
	if !ok {
		t.Fatalf("NETWORK not witnessed via init root; got %v", report.Capabilities())
	}
	if f.Path[0] != "m.init" {
		t.Errorf("witness path should root at init, got %v", f.Path)
	}

	// Control: with the init edge removed, the exported API reaches nothing, so
	// the capability vanishes — proving init roots are what witness it.
	rec.Edges = nil
	if got := Analyse(rec, SelectRoots(rec, cgdomain.RootScopeProduction)); len(got.Findings) != 0 {
		t.Errorf("without the init edge nothing is witnessed, got %v", got.Capabilities())
	}
}

// dynamicSinkGraph is a module with an exported API and, separately, an
// unexported non-init function that reaches a capability sink and is entered
// only by runtime dispatch (a gRPC handler, a registered callback). No edge
// leads to it from the exported API, so it is the exact shape that made
// handler-only capabilities false-negatives.
func dynamicSinkGraph() cgdomain.CallGraphRecord {
	return cgdomain.CallGraphRecord{
		OverallStatus: cgdomain.CallGraphStatusExtracted,
		Nodes: []cgdomain.CallNode{
			node("m.Exported", "m", "Exported", false, true),
			node("m.handler", "m", "handler", false, false),
			node("os/exec.Command", "os/exec", "Command", true, false),
		},
		Edges: []cgdomain.CallEdge{
			edge("m.handler", "os/exec.Command", cgdomain.ConfidenceDirect),
		},
	}
}

func TestAnalyseWitnessesDynamicallyDispatchedSinkInApplication(t *testing.T) {
	rec := dynamicSinkGraph()
	rec.ArtifactKind = cgdomain.ArtifactApplication

	report := Analyse(rec, SelectRoots(rec, cgdomain.RootScopeProduction))

	f, ok := findingFor(report, CapabilityExec)
	if !ok {
		t.Fatalf("EXEC not witnessed in application artifact; got %v", report.Capabilities())
	}
	if f.SinkSymbol != "Command" {
		t.Errorf("EXEC sink symbol = %q, want Command", f.SinkSymbol)
	}
}

func TestAnalyseSkipsDynamicallyDispatchedSinkInLibrary(t *testing.T) {
	// The same graph as a library: a consumer can only call the exported API, and
	// nothing exported reaches the sink, so it is correctly not reported. This
	// pins the library side of the switch — dependency rooting is unchanged.
	rec := dynamicSinkGraph()
	rec.ArtifactKind = cgdomain.ArtifactLibrary

	if got := Analyse(rec, SelectRoots(rec, cgdomain.RootScopeProduction)); len(got.Findings) != 0 {
		t.Errorf("library artifact witnessed %v, want none", got.Capabilities())
	}
}

func TestSelectRootsApplicationIncludesUnexportedNonInit(t *testing.T) {
	rec := dynamicSinkGraph()
	rec.ArtifactKind = cgdomain.ArtifactApplication

	got := SelectRoots(rec, cgdomain.RootScopeProduction)
	if want := []string{"m.Exported", "m.handler"}; !reflect.DeepEqual(got, want) {
		t.Errorf("SelectRoots = %v, want %v", got, want)
	}
}

func TestSelectRootsIncludesInit(t *testing.T) {
	rec := cgdomain.CallGraphRecord{Nodes: []cgdomain.CallNode{
		node("m.Exported", "m", "Exported", false, true),
		node("m.init", "m", "init", false, false),
		node("m.internal", "m", "internal", false, false),
		node("ext.init", "ext", "init", true, false),
	}}
	got := SelectRoots(rec, cgdomain.RootScopeProduction)
	if !reflect.DeepEqual(got, []string{"m.Exported", "m.init"}) {
		t.Errorf("SelectRoots = %v, want [m.Exported m.init]", got)
	}
}

func TestSelectRootsPrefersExported(t *testing.T) {
	rec := cgdomain.CallGraphRecord{Nodes: []cgdomain.CallNode{
		node("m.Exported", "m", "Exported", false, true),
		node("m.internal", "m", "internal", false, false),
		node("ext.Fn", "ext", "Fn", true, true),
	}}
	got := SelectRoots(rec, cgdomain.RootScopeProduction)
	if !reflect.DeepEqual(got, []string{"m.Exported"}) {
		t.Errorf("SelectRoots = %v, want [m.Exported]", got)
	}
}

func TestSelectRootsFallsBackToOwned(t *testing.T) {
	rec := cgdomain.CallGraphRecord{Nodes: []cgdomain.CallNode{
		node("m.b", "m", "b", false, false),
		node("m.a", "m", "a", false, false),
		node("ext.Fn", "ext", "Fn", true, false),
	}}
	got := SelectRoots(rec, cgdomain.RootScopeProduction)
	if !reflect.DeepEqual(got, []string{"m.a", "m.b"}) {
		t.Errorf("SelectRoots = %v, want [m.a m.b]", got)
	}
}

func TestSelectRootsAllExternal(t *testing.T) {
	rec := cgdomain.CallGraphRecord{Nodes: []cgdomain.CallNode{
		node("ext.Fn", "ext", "Fn", true, true),
	}}
	if got := SelectRoots(rec, cgdomain.RootScopeProduction); len(got) != 0 {
		t.Errorf("SelectRoots = %v, want empty", got)
	}
}

func TestConfRankAndBack(t *testing.T) {
	cases := []struct {
		c    cgdomain.EdgeConfidence
		rank int
	}{
		{cgdomain.ConfidenceDirect, 4},
		{cgdomain.ConfidenceVTA, 3},
		{cgdomain.ConfidenceFramework, 2},
		{cgdomain.ConfidenceCHAOverapprox, 1},
		{cgdomain.ConfidenceUnknown, 0},
		{cgdomain.EdgeConfidence("weird"), 0},
	}
	for _, tc := range cases {
		if got := confRank(tc.c); got != tc.rank {
			t.Errorf("confRank(%q) = %d, want %d", tc.c, got, tc.rank)
		}
	}
	// confidenceForRank round-trips, and rankInf maps to Direct.
	if confidenceForRank(rankInf) != cgdomain.ConfidenceDirect {
		t.Error("rankInf should map to Direct")
	}
	if confidenceForRank(3) != cgdomain.ConfidenceVTA {
		t.Error("rank 3 should map to VTA")
	}
	if confidenceForRank(2) != cgdomain.ConfidenceFramework {
		t.Error("rank 2 should map to Framework")
	}
	if confidenceForRank(1) != cgdomain.ConfidenceCHAOverapprox {
		t.Error("rank 1 should map to CHA-overapprox")
	}
	if confidenceForRank(0) != cgdomain.ConfidenceUnknown {
		t.Error("rank 0 should map to Unknown")
	}
}

func TestStrongerFindingTiebreaks(t *testing.T) {
	base := CapabilityFinding{WeakestConfidence: cgdomain.ConfidenceDirect, Path: []string{"a", "z"}}

	// Higher confidence wins.
	weaker := CapabilityFinding{WeakestConfidence: cgdomain.ConfidenceUnknown, Path: []string{"a"}}
	if !strongerFinding(base, weaker) {
		t.Error("higher confidence should be stronger")
	}
	// Equal confidence: shorter path wins.
	shorter := CapabilityFinding{WeakestConfidence: cgdomain.ConfidenceDirect, Path: []string{"a"}}
	if !strongerFinding(shorter, base) {
		t.Error("shorter path should be stronger")
	}
	// Equal confidence and length: smaller sink ID wins.
	small := CapabilityFinding{WeakestConfidence: cgdomain.ConfidenceDirect, Path: []string{"a", "b"}}
	big := CapabilityFinding{WeakestConfidence: cgdomain.ConfidenceDirect, Path: []string{"a", "c"}}
	if !strongerFinding(small, big) {
		t.Error("smaller sink ID should be stronger")
	}
}

func TestSinkIDEmptyPath(t *testing.T) {
	if got := sinkID(CapabilityFinding{}); got != "" {
		t.Errorf("sinkID(empty) = %q, want empty", got)
	}
}

// TestAnalyseRelaxesToSettledNode drives the case where an edge points at an
// already-settled node (inner settled check) and where two roots tie in the
// priority queue (Less depth/id tiebreaks). Two exported roots reach the same
// sink; a weaker late edge targets the already-settled sink.
func TestAnalyseRelaxesToSettledNode(t *testing.T) {
	rec := cgdomain.CallGraphRecord{
		OverallStatus: cgdomain.CallGraphStatusExtracted,
		Nodes: []cgdomain.CallNode{
			node("m.RootA", "m", "RootA", false, true),
			node("m.RootB", "m", "RootB", false, true),
			node("m.C", "m", "C", false, false),
			node("m.D", "m", "D", false, false),
			node("m.E", "m", "E", false, false),
			node("m.F", "m", "F", false, false),
			node("net/http.Get", "net/http", "Get", true, false),
		},
		Edges: []cgdomain.CallEdge{
			edge("m.RootA", "net/http.Get", cgdomain.ConfidenceDirect),
			edge("m.RootB", "m.C", cgdomain.ConfidenceUnknown),
			edge("m.C", "net/http.Get", cgdomain.ConfidenceUnknown), // targets settled sink
			// Equal-rank (Direct) nodes at different depths coexist in the
			// heap: m.F is depth 1 while m.E (via m.D) is depth 2, forcing the
			// priority queue's depth tiebreak.
			edge("m.RootA", "m.D", cgdomain.ConfidenceDirect),
			edge("m.D", "m.E", cgdomain.ConfidenceDirect),
			edge("m.RootB", "m.F", cgdomain.ConfidenceDirect),
		},
	}
	report := Analyse(rec, SelectRoots(rec, cgdomain.RootScopeProduction))
	f, ok := findingFor(report, CapabilityNetwork)
	if !ok {
		t.Fatal("NETWORK not witnessed")
	}
	// The Direct path from RootA must win over the Unknown path via C.
	if f.WeakestConfidence != cgdomain.ConfidenceDirect {
		t.Errorf("weakest = %q, want Direct", f.WeakestConfidence)
	}
}

// testNode is a declaration in a _test.go file or an external test package. It
// is exported and owned like any other node, which is what made it a root.
func testNode(id, pkg, sym string) cgdomain.CallNode {
	n := node(id, pkg, sym, false, true)
	n.IsTest = true
	return n
}

// bothRootsReachOneSink is the case no real module in the store proves: one
// sink reached from an exported function and from a test, so excluding the test
// root must not remove the capability, only re-witness it.
func bothRootsReachOneSink() cgdomain.CallGraphRecord {
	return cgdomain.CallGraphRecord{
		OverallStatus: cgdomain.CallGraphStatusExtracted,
		Nodes: []cgdomain.CallNode{
			node("m.Exported", "m", "Exported", false, true),
			testNode("m_test.TestExported", "m_test", "TestExported"),
			node("os/exec.Command", "os/exec", "Command", true, false),
		},
		Edges: []cgdomain.CallEdge{
			edge("m.Exported", "os/exec.Command", cgdomain.ConfidenceDirect),
			edge("m_test.TestExported", "os/exec.Command", cgdomain.ConfidenceDirect),
		},
	}
}

func TestAnalyseKeepsCapabilityReachedFromBothRootsAndWitnessesTheProductionPath(t *testing.T) {
	rec := bothRootsReachOneSink()

	report := Analyse(rec, SelectRoots(rec, cgdomain.RootScopeProduction))
	f, ok := findingFor(report, CapabilityExec)
	if !ok {
		t.Fatalf("EXEC lost when the test root was excluded; got %v", report.Capabilities())
	}
	if want := []string{"m.Exported", "os/exec.Command"}; !reflect.DeepEqual(f.Path, want) {
		t.Errorf("witness = %v, want the production path %v", f.Path, want)
	}
}

func TestAnalyseDropsCapabilityWitnessedOnlyByATestRoot(t *testing.T) {
	// The same graph with the production edge removed: the sink is now reachable
	// only from the test, so the production scope witnesses nothing and the
	// widened scope still witnesses EXEC. The pair is what shows the exclusion
	// is doing the work.
	rec := bothRootsReachOneSink()
	rec.Edges = rec.Edges[1:]

	if got := Analyse(rec, SelectRoots(rec, cgdomain.RootScopeProduction)); len(got.Findings) != 0 {
		t.Errorf("test-only sink witnessed under the production scope: %v", got.Capabilities())
	}
	withTests := Analyse(rec, SelectRoots(rec, cgdomain.RootScopeWithTests))
	if _, ok := findingFor(withTests, CapabilityExec); !ok {
		t.Errorf("EXEC not witnessed with tests included; got %v", withTests.Capabilities())
	}
}

func TestAnalyseKeepsAnInitOnlyCapabilityUnderTheProductionScope(t *testing.T) {
	// Package init runs unconditionally at package load, so an init-only sink is
	// reachable in any real execution. Excluding test roots must not narrow that.
	rec := cgdomain.CallGraphRecord{
		OverallStatus: cgdomain.CallGraphStatusExtracted,
		Nodes: []cgdomain.CallNode{
			node("m.init", "m", "init", false, false),
			node("m.helper", "m", "helper", false, false),
			testNode("m_test.TestHelper", "m_test", "TestHelper"),
			node("net/http.Get", "net/http", "Get", true, false),
		},
		Edges: []cgdomain.CallEdge{
			edge("m.init", "m.helper", cgdomain.ConfidenceDirect),
			edge("m.helper", "net/http.Get", cgdomain.ConfidenceDirect),
		},
	}

	report := Analyse(rec, SelectRoots(rec, cgdomain.RootScopeProduction))
	f, ok := findingFor(report, CapabilityNetwork)
	if !ok {
		t.Fatalf("init-rooted NETWORK lost; got %v", report.Capabilities())
	}
	if want := []string{"m.init", "m.helper", "net/http.Get"}; !reflect.DeepEqual(f.Path, want) {
		t.Errorf("witness = %v, want %v", f.Path, want)
	}
}

func TestSelectRootsProductionScopeExcludesTestNodes(t *testing.T) {
	rec := bothRootsReachOneSink()
	if got, want := SelectRoots(rec, cgdomain.RootScopeProduction), []string{"m.Exported"}; !reflect.DeepEqual(got, want) {
		t.Errorf("SelectRoots = %v, want %v", got, want)
	}
	if got, want := SelectRoots(rec, cgdomain.RootScopeWithTests),
		[]string{"m.Exported", "m_test.TestExported"}; !reflect.DeepEqual(got, want) {
		t.Errorf("SelectRoots with tests = %v, want %v", got, want)
	}
}
