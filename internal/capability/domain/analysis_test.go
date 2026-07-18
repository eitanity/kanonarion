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
			edge("m.Root", "m.Mid", cgdomain.ConfidenceDynamicDispatch), // adjacency tiebreak
			edge("m.Mid", "net/http.Get", cgdomain.ConfidenceDirect),
			edge("m.Root", "net.Dial", cgdomain.ConfidenceUnknown),  // weaker NETWORK witness
			edge("m.Root", "os/exec.Command", cgdomain.ConfidenceDynamicDispatch),
			edge("m.Mid", "reflect.ValueOf", cgdomain.ConfidenceReflection),
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

// TestAnalyseWitnessesBodyLevelCapabilities is the body-level capability regression: two
// capabilities are properties of a reachable function's body, not its callee
// identity, so the sink map alone cannot witness them. UNSAFE_POINTER comes
// from a dependency leaf that converts through unsafe.Pointer; ARBITRARY_EXECUTION
// from an assembly/linkname leaf with no Go body. Both are non-sink packages,
// so without the body facts neither would appear.
func TestAnalyseWitnessesBodyLevelCapabilities(t *testing.T) {
	unsafeLeaf := cgdomain.CallNode{
		ID: "goja/unistring.(String).AsUtf16", Package: "goja/unistring",
		Symbol: "AsUtf16", IsExternal: true, UsesUnsafePointer: true,
	}
	asmLeaf := cgdomain.CallNode{
		ID: "xxhash.writeBlocks", Package: "klauspost/compress/zstd/internal/xxhash",
		Symbol: "writeBlocks", IsExternal: true, IsAssemblyOrLinkname: true,
	}
	rec := cgdomain.CallGraphRecord{
		OverallStatus: cgdomain.CallGraphStatusExtracted,
		Nodes: []cgdomain.CallNode{
			node("m.Root", "m", "Root", false, true),
			unsafeLeaf,
			asmLeaf,
		},
		Edges: []cgdomain.CallEdge{
			edge("m.Root", "goja/unistring.(String).AsUtf16", cgdomain.ConfidenceDirect),
			edge("m.Root", "xxhash.writeBlocks", cgdomain.ConfidenceDynamicDispatch),
		},
	}

	report := Analyse(rec, SelectRoots(rec))

	up, ok := findingFor(report, CapabilityUnsafePointer)
	if !ok {
		t.Fatalf("UNSAFE_POINTER not witnessed; got %v", report.Capabilities())
	}
	if up.WeakestConfidence != cgdomain.ConfidenceDirect {
		t.Errorf("UNSAFE_POINTER weakest = %q, want Direct", up.WeakestConfidence)
	}
	if up.SinkPackage != "goja/unistring" || up.SinkSymbol != "AsUtf16" {
		t.Errorf("UNSAFE_POINTER sink = %s.%s, want goja/unistring.AsUtf16", up.SinkPackage, up.SinkSymbol)
	}

	ae, ok := findingFor(report, CapabilityArbitraryExecution)
	if !ok {
		t.Fatalf("ARBITRARY_EXECUTION not witnessed; got %v", report.Capabilities())
	}
	if ae.WeakestConfidence != cgdomain.ConfidenceDynamicDispatch {
		t.Errorf("ARBITRARY_EXECUTION weakest = %q, want DynamicDispatch", ae.WeakestConfidence)
	}

	// Control: strip the body facts and the two capabilities vanish — proving
	// they are witnessed only by the facts, never by callee identity.
	rec.Nodes[1].UsesUnsafePointer = false
	rec.Nodes[2].IsAssemblyOrLinkname = false
	if got := Analyse(rec, SelectRoots(rec)); len(got.Findings) != 0 {
		t.Errorf("without body facts the non-sink leaves witness nothing, got %v", got.Capabilities())
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
			{ID: "dep.unsafeFn", Package: "dep", Symbol: "unsafeFn", IsExternal: true, UsesUnsafePointer: true},
			{ID: "dep.asmFn", Package: "dep", Symbol: "asmFn", IsExternal: true, IsAssemblyOrLinkname: true},
		},
	}
	for _, n := range rec.Nodes {
		if n.ID == "m.Root" {
			continue
		}
		rec.Edges = append(rec.Edges, edge("m.Root", n.ID, cgdomain.ConfidenceDirect))
	}

	report := Analyse(rec, SelectRoots(rec))
	got := report.Capabilities()
	if len(got) != 12 {
		t.Fatalf("got %d capabilities, want 12: %v", len(got), got)
	}
	for _, want := range AllCapabilities() {
		if _, ok := findingFor(report, want); !ok {
			t.Errorf("missing capability %s", want)
		}
	}
}

func TestAnalyseWitnessesCapabilitiesWithWeakestEdge(t *testing.T) {
	rec := richGraph()
	report := Analyse(rec, SelectRoots(rec))

	if report.Partial {
		t.Error("Extracted graph should not be Partial")
	}

	want := map[Capability]cgdomain.EdgeConfidence{
		CapabilityNetwork:     cgdomain.ConfidenceDirect,         // via m.Mid → net/http.Get, all Direct
		CapabilityExec:        cgdomain.ConfidenceDynamicDispatch, // root → os/exec.Command
		CapabilityReflect:     cgdomain.ConfidenceReflection,     // weakest edge is Reflection
		CapabilitySystemCalls: cgdomain.ConfidenceUnknown,        // Unknown edge
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
	report := Analyse(rec, SelectRoots(rec))
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
	report := Analyse(rec, SelectRoots(rec))
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
			node("m.init", "m", "init", false, false),         // owned init, not exported
			node("m.Exported", "m", "Exported", false, true),  // exported, reaches no sink
			node("net/http.Get", "net/http", "Get", true, false),
		},
		Edges: []cgdomain.CallEdge{
			edge("m.init", "net/http.Get", cgdomain.ConfidenceDirect),
		},
	}

	report := Analyse(rec, SelectRoots(rec))
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
	if got := Analyse(rec, SelectRoots(rec)); len(got.Findings) != 0 {
		t.Errorf("without the init edge nothing is witnessed, got %v", got.Capabilities())
	}
}

func TestSelectRootsIncludesInit(t *testing.T) {
	rec := cgdomain.CallGraphRecord{Nodes: []cgdomain.CallNode{
		node("m.Exported", "m", "Exported", false, true),
		node("m.init", "m", "init", false, false),
		node("m.internal", "m", "internal", false, false),
		node("ext.init", "ext", "init", true, false),
	}}
	got := SelectRoots(rec)
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
	got := SelectRoots(rec)
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
	got := SelectRoots(rec)
	if !reflect.DeepEqual(got, []string{"m.a", "m.b"}) {
		t.Errorf("SelectRoots = %v, want [m.a m.b]", got)
	}
}

func TestSelectRootsAllExternal(t *testing.T) {
	rec := cgdomain.CallGraphRecord{Nodes: []cgdomain.CallNode{
		node("ext.Fn", "ext", "Fn", true, true),
	}}
	if got := SelectRoots(rec); len(got) != 0 {
		t.Errorf("SelectRoots = %v, want empty", got)
	}
}

func TestConfRankAndBack(t *testing.T) {
	cases := []struct {
		c    cgdomain.EdgeConfidence
		rank int
	}{
		{cgdomain.ConfidenceDirect, 3},
		{cgdomain.ConfidenceDynamicDispatch, 2},
		{cgdomain.ConfidenceReflection, 1},
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
	if confidenceForRank(2) != cgdomain.ConfidenceDynamicDispatch {
		t.Error("rank 2 should map to DynamicDispatch")
	}
	if confidenceForRank(1) != cgdomain.ConfidenceReflection {
		t.Error("rank 1 should map to Reflection")
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
	report := Analyse(rec, SelectRoots(rec))
	f, ok := findingFor(report, CapabilityNetwork)
	if !ok {
		t.Fatal("NETWORK not witnessed")
	}
	// The Direct path from RootA must win over the Unknown path via C.
	if f.WeakestConfidence != cgdomain.ConfidenceDirect {
		t.Errorf("weakest = %q, want Direct", f.WeakestConfidence)
	}
}
