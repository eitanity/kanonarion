package cli

import (
	"context"
	"encoding/json"
	"testing"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

// appGraphWith builds the application call graph the route below is classified
// against: an http.Handler the runtime enters, and a handler function it
// reaches, joined by an edge of the kind given.
//
// The graph is what makes these controls real. The two flags under test are not
// stored anywhere — they are derived, per query, by the entry-point search in
// the rootclass adapter — so a fixture that wrote them into a struct would
// assert the json tag and nothing about whether they are ever computed.
func appGraphWith(kind cgdomain.EdgeKind) cgdomain.CallGraphRecord {
	coord := coordinatetest.MustNew("example.com/app", "local")
	return cgdomain.CallGraphRecord{
		Coordinate:    coord,
		Algorithm:     cgdomain.AlgorithmCHA,
		OverallStatus: cgdomain.CallGraphStatusExtracted,
		Nodes: []cgdomain.CallNode{
			{
				ID: "example.com/app/handlers.(*Server).ServeHTTP", Module: "example.com/app",
				Package: "example.com/app/handlers", Symbol: "ServeHTTP", Receiver: "*Server",
			},
			{
				ID: "example.com/app/handlers.handleParse", Module: "example.com/app",
				Package: "example.com/app/handlers", Symbol: "handleParse",
			},
		},
		Edges: []cgdomain.CallEdge{{
			FromID:     "example.com/app/handlers.(*Server).ServeHTTP",
			ToID:       "example.com/app/handlers.handleParse",
			Confidence: cgdomain.ConfidenceDirect,
			Kind:       kind,
		}},
	}
}

// routeFrom is a route whose first frame is the application handler above and
// whose last is the vulnerable dependency symbol.
func routeFrom(rootModule string) vuldomain.ReachabilityRoute {
	return vuldomain.ReachabilityRoute{
		{ModulePath: rootModule, Package: "example.com/app/handlers", Symbol: "handleParse"},
		{ModulePath: "example.com/dep", ModuleVersion: "v1.2.0", Package: "example.com/dep", Symbol: "Parse"},
	}
}

// measuredRouteRoot runs the production classifier over one route against one
// stored graph, and returns the curated JSON object the presenters emit.
func measuredRouteRoot(t *testing.T, rec cgdomain.CallGraphRecord, rooting vuldomain.Rooting, route vuldomain.ReachabilityRoute) map[string]any {
	t.Helper()
	graphs := testfakes.NewFakeQueryCallGraph()
	graphs.AddRecord(rec.Coordinate, cgapp.PipelineVersion, rec)

	record := vuldomain.VulnerabilityRecord{
		Coordinate: coordinatetest.MustNew("example.com/dep", "v1.2.0"),
		Rooting:    rooting,
	}
	classify := newRouteRootFunc(context.Background(), graphs, record)
	out := rootToOutput(classify(route))
	if out == nil {
		t.Fatal("the route was not classified at all; the fixture no longer exercises the classifier")
	}
	data, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshalling route root: %v", err)
	}
	var decoded map[string]any
	if uerr := json.Unmarshal(data, &decoded); uerr != nil {
		t.Fatalf("unmarshalling route root: %v", uerr)
	}
	return decoded
}

// ancestryOf returns the entry-point ancestry object, failing when the search
// did not run — the object's absence means something different from any value
// inside it, and these assertions are only meaningful when it is present.
func ancestryOf(t *testing.T, root map[string]any) map[string]any {
	t.Helper()
	a, ok := root["entry_point_ancestry"].(map[string]any)
	if !ok {
		t.Fatalf("entry_point_ancestry is absent (%v); the search did not run, so nothing below can be asserted", root["entry_point_ancestry"])
	}
	return a
}

// TestReachabilityJSON_ViaReferenceIsEmittedAtFalse pins the caveat that
// qualifies a "reachable" verdict most strongly.
//
// via_reference says at least one hop on the path from an entry point is a
// place the function's VALUE was taken rather than a call — a registration. The
// object carrying it is built only when the search ran, so false is the
// measurement "every hop here is a call", and erasing it left a clean chain
// looking exactly like one from a build that never measured the distinction.
func TestReachabilityJSON_ViaReferenceIsEmittedAtFalse(t *testing.T) {
	rooting := vuldomain.TargetRootedAt(coordinatetest.MustNew("example.com/app", "local"))

	calls := ancestryOf(t, measuredRouteRoot(t, appGraphWith(cgdomain.EdgeKindCall), rooting, routeFrom("example.com/app")))
	got, present := calls["via_reference"]
	if !present {
		t.Fatal("via_reference is absent on an all-calls chain; the reader cannot tell a chain with no registration in it from one where registrations were never measured")
	}
	if got != false {
		t.Errorf("via_reference = %v on a path of direct calls, want false", got)
	}
	if calls["found"] != true || calls["hops"].(float64) != 1 {
		t.Fatalf("the ancestry search did not measure the fixture (found=%v hops=%v); the false above would then be vacuous", calls["found"], calls["hops"])
	}

	// Non-zero control: the same graph with the one hop recorded as a
	// REFERENCE. The flag is derived by the entry-point search, so this fails if
	// the search stops carrying the distinction as well as if the key is erased.
	reference := ancestryOf(t, measuredRouteRoot(t, appGraphWith(cgdomain.EdgeKindReference), rooting, routeFrom("example.com/app")))
	if reference["via_reference"] != true {
		t.Errorf("via_reference = %v on a path whose only hop is a registration, want true", reference["via_reference"])
	}
	if reference["found"] != true {
		t.Error("the reference path did not reach the entry point; the control is not exercising the search")
	}

	// The two must be tellable apart from the documents alone, which is the
	// whole claim and was false while the false one was omitted.
	if calls["via_reference"] == reference["via_reference"] {
		t.Error("a call chain and a registration chain carry the same via_reference; the document cannot separate them")
	}
}

// TestReachabilityJSON_ClosureRootedIsEmittedAtFalse pins the other half of the
// route root.
//
// closure_rooted says the route does not begin in the module the analysis was
// rooted at — the application's own entry points were never analysed, so the hop
// above this root is missing rather than absent. This object exists only when a
// root WAS classified, so false is always a measurement.
func TestReachabilityJSON_ClosureRootedIsEmittedAtFalse(t *testing.T) {
	rooted := measuredRouteRoot(t,
		appGraphWith(cgdomain.EdgeKindCall),
		vuldomain.TargetRootedAt(coordinatetest.MustNew("example.com/app", "local")),
		routeFrom("example.com/app"))
	got, present := rooted["closure_rooted"]
	if !present {
		t.Fatal("closure_rooted is absent on a route that does begin in the rooted module; absence is the same document a build that never classified roots would produce")
	}
	if got != false {
		t.Errorf("closure_rooted = %v on a route rooted in the analysed application, want false", got)
	}

	// Non-zero control: the same route, from a record scanned in the isolated
	// frame. No application was rooted at, so the classification says so — and
	// the domain adds the remedy that would fix it.
	isolated := measuredRouteRoot(t, appGraphWith(cgdomain.EdgeKindCall), vuldomain.RootingIsolated, routeFrom("example.com/app"))
	if isolated["closure_rooted"] != true {
		t.Errorf("closure_rooted = %v on an isolated-frame route, want true", isolated["closure_rooted"])
	}
	if isolated["remedy"] == nil || isolated["remedy"] == "" {
		t.Error("a closure-rooted classification named no remedy; the flag and its remedy are one statement")
	}
}
