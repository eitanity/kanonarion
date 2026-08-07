package rootclass_test

import (
	"context"
	"strings"
	"testing"

	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/vuln/adapters/rootclass"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

// registeredHandlerGraph is the shape the measurement exists for: confirmEmail
// classifies `internal` — it is unexported and has an in-project caller — while
// an HTTP request drives it, and the only thing in the graph that says so is the
// chain of edges up to a ServeHTTP method.
//
//	(*Server).ServeHTTP --Direct--> (*Mux).route --CHA--> (*H).dispatch
//	                    --Reference--> (*H).confirmEmail
//
// The reference hop is the registration. It is on the path deliberately: a
// distance measured through one may not be read as an all-calls chain.
func registeredHandlerGraph() cgdomain.CallGraphRecord {
	const (
		serve    = "example.com/app/handlers.(*Server).ServeHTTP"
		route    = "example.com/app/handlers.(*Mux).route"
		dispatch = "example.com/app/handlers.(*H).dispatch"
		confirm  = "example.com/app/handlers.(*H).confirmEmail"
	)
	return appRecord([]cgdomain.CallNode{
		node(serve, "*Server", "ServeHTTP", exported),
		node(route, "*Mux", "route"),
		node(dispatch, "*H", "dispatch"),
		node(confirm, "*H", "confirmEmail"),
	}, []cgdomain.CallEdge{
		{FromID: serve, ToID: route, Confidence: cgdomain.ConfidenceDirect},
		{FromID: route, ToID: dispatch, Confidence: cgdomain.ConfidenceCHAOverapprox},
		{FromID: dispatch, ToID: confirm, Confidence: cgdomain.ConfidenceDirect, Kind: cgdomain.EdgeKindReference},
	})
}

func classifyEntry(t *testing.T, rec cgdomain.CallGraphRecord, symbol, receiver string) vuldomain.RouteRoot {
	t.Helper()
	graphs := &fakeGraphs{records: map[string]cgdomain.CallGraphRecord{appCoord(t).String(): rec}}
	c := rootclass.New(graphs, pipelineVersion)
	return c.Classify(context.Background(), targetRooted(t), appCoord(t), routeFrom(handlerFrame(symbol, receiver)))
}

// TestClassify_MeasuresTheDistanceToTheNearestEntryPoint is the fact the kind
// could not carry: the node stays `internal` and states how far below an entry
// point it sits, and how weak the weakest hop on that path was.
func TestClassify_MeasuresTheDistanceToTheNearestEntryPoint(t *testing.T) {
	root := classifyEntry(t, registeredHandlerGraph(), "confirmEmail", "*H")

	if root.Kind != vuldomain.RootInternal {
		t.Errorf("Kind = %s, want internal: the distance qualifies the kind, it does not replace it", root.Kind)
	}
	a := root.Ancestry
	if !a.IsRecorded() {
		t.Fatal("the ancestry was not computed at all")
	}
	if !a.Found {
		t.Fatalf("no entry-point ancestor found; the chain up to ServeHTTP is right there: %+v", a)
	}
	if a.Hops != 3 {
		t.Errorf("Hops = %d, want 3", a.Hops)
	}
	if !strings.HasSuffix(a.EntryPointID, "(*Server).ServeHTTP") {
		t.Errorf("EntryPointID = %q, want the ServeHTTP method", a.EntryPointID)
	}
	if a.Weakest != string(cgdomain.ConfidenceCHAOverapprox) {
		t.Errorf("Weakest = %q, want CHA-overapprox: the path is only as good as its worst hop", a.Weakest)
	}
	if !a.ViaReference {
		t.Error("ViaReference is false, but the last hop is a registration")
	}
	if a.IsAllDirectCallPath() {
		t.Error("a path through a CHA hop and a registration must not read as an all-Direct call path")
	}
	if !strings.Contains(root.String(), "3 hops below") {
		t.Errorf("the rendered root does not state the distance: %q", root.String())
	}
}

// TestClassify_AReferenceHopNeverMakesAPathAllDirect is the ruling that keeps
// the measurement honest. Every EDGE on this path resolves exactly — the
// analyser knows which function's value was taken — so a confidence-only reading
// would call it all-Direct and present a registration as a chain of calls.
func TestClassify_AReferenceHopNeverMakesAPathAllDirect(t *testing.T) {
	const (
		main    = "example.com/app/handlers.main"
		mount   = "example.com/app/handlers.mount"
		handler = "example.com/app/handlers.handle"
	)
	rec := appRecord([]cgdomain.CallNode{
		node(main, "", "main"),
		node(mount, "", "mount"),
		node(handler, "", "handle"),
	}, []cgdomain.CallEdge{
		{FromID: main, ToID: mount, Confidence: cgdomain.ConfidenceDirect},
		{FromID: mount, ToID: handler, Confidence: cgdomain.ConfidenceDirect, Kind: cgdomain.EdgeKindReference},
	})

	root := classifyEntry(t, rec, "handle", "")
	a := root.Ancestry
	if !a.Found || a.Hops != 2 {
		t.Fatalf("ancestry = %+v, want found at 2 hops", a)
	}
	if a.Weakest != string(cgdomain.ConfidenceDirect) {
		t.Errorf("Weakest = %q: every edge on this path is Direct, so the confidence must say so", a.Weakest)
	}
	if a.IsAllDirectCallPath() {
		t.Error("a registration laundered into an all-Direct CALL path — this is the over-approximation the measurement refuses")
	}

	// The control that keeps the assertion meaningful: the same shape with a
	// call instead of a registration IS an all-Direct call path.
	rec.Edges[1].Kind = cgdomain.EdgeKindCall
	ctrl := classifyEntry(t, rec, "handle", "").Ancestry
	if !ctrl.IsAllDirectCallPath() {
		t.Errorf("an all-calls Direct path stopped qualifying, so the rule rejects everything: %+v", ctrl)
	}
}

// TestClassify_NoAncestorIsAnAnswerAndNotTheAbsenceOfOne separates the two
// negatives a reader must never conflate: a search that ran and found nothing,
// and a search that never ran.
func TestClassify_NoAncestorIsAnAnswerAndNotTheAbsenceOfOne(t *testing.T) {
	const orphan = "example.com/app/handlers.orphan"
	rec := appRecord([]cgdomain.CallNode{node(orphan, "", "orphan")}, nil)

	measured := classifyEntry(t, rec, "orphan", "").Ancestry
	if !measured.IsRecorded() {
		t.Fatal("the search did not run over a graph that was available")
	}
	if measured.Found {
		t.Errorf("found an ancestor in a graph with no edges: %+v", measured)
	}
	if measured.SearchBound != 0 {
		t.Errorf("SearchBound = %d, want 0 (unbounded): a bounded miss says something narrower", measured.SearchBound)
	}
	if !strings.Contains(measured.String(), "no entry-point ancestor anywhere") {
		t.Errorf("the rendering does not state what the miss covers: %q", measured.String())
	}

	// The control: a route whose root resolves to no node at all was never
	// searched, and says so by not being recorded.
	unresolved := classifyEntry(t, rec, "notInTheGraph", "").Ancestry
	if unresolved.IsRecorded() {
		t.Errorf("an unresolved root reported a computed search: %+v", unresolved)
	}
}

// TestClassify_TheNearestEntryPointWins guards the breadth-first property: a
// distant strong path must not beat a near weak one, because the question is how
// far, not how good.
func TestClassify_TheNearestEntryPointWins(t *testing.T) {
	const (
		initFn = "example.com/app/handlers.init"
		mainFn = "example.com/app/handlers.main"
		mid    = "example.com/app/handlers.mid"
		leaf   = "example.com/app/handlers.leaf"
	)
	rec := appRecord([]cgdomain.CallNode{
		node(initFn, "", "init"),
		node(mainFn, "", "main"),
		node(mid, "", "mid"),
		node(leaf, "", "leaf"),
	}, []cgdomain.CallEdge{
		{FromID: initFn, ToID: leaf, Confidence: cgdomain.ConfidenceUnknown},
		{FromID: mainFn, ToID: mid, Confidence: cgdomain.ConfidenceDirect},
		{FromID: mid, ToID: leaf, Confidence: cgdomain.ConfidenceDirect},
	})
	a := classifyEntry(t, rec, "leaf", "").Ancestry
	if a.Hops != 1 || !strings.HasSuffix(a.EntryPointID, ".init") {
		t.Errorf("ancestry = %+v, want the 1-hop init rather than the 2-hop main", a)
	}
	if a.Weakest != string(cgdomain.ConfidenceUnknown) {
		t.Errorf("Weakest = %q, want Unknown: the nearest path is the one being described", a.Weakest)
	}
}
