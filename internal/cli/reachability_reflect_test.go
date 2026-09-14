package cli

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"

	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"

	"github.com/eitanity/kanonarion/internal/vuln/adapters/reachability"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

// A reachability negative says no route was found. It cannot say no route
// exists, and one of the ways a route hides is a call whose target is chosen at
// run time. These tests pin what the answer now says about those calls, on both
// surfaces a reader has.
//
// Nothing here is hand-stamped. The graph below is a call-graph RECORD, served
// through the real loader and searched by the real searcher, so every value
// asserted was decided by the code under test rather than written into the
// fixture. That matters because the defect this guards against is a
// classification mistake: a fixture that states its own answer would pass
// whatever the classifier decided.

// reflectFixtureCoord is the module the fixture graph describes. It matches the
// coordinate the record is written against so the search runs at all.
var reflectFixtureCoord = coordinatetest.MustNew("example.com/dep", "v1.2.3")

// reflectGraphStore serves one call-graph record. Only the read is exercised;
// the rest of the interface is present so the loader will accept it.
type reflectGraphStore struct{ record cgdomain.CallGraphRecord }

func (s *reflectGraphStore) GetCallGraphRecord(context.Context, coordinate.ModuleCoordinate, string) (cgdomain.CallGraphRecord, bool, error) {
	return s.record, true, nil
}

func (s *reflectGraphStore) PutCallGraphRecord(context.Context, cgdomain.CallGraphRecord) error {
	return nil
}

func (s *reflectGraphStore) ListCallGraphRecords(context.Context, cgports.CallGraphFilter) ([]cgports.CallGraphSummary, error) {
	return nil, nil
}

func (s *reflectGraphStore) FindCallers(context.Context, string, string, coordinate.ModuleSet, cgports.EdgeQueryOptions) ([]cgports.CallEdgeRef, error) {
	return nil, nil
}

func (s *reflectGraphStore) FindCallees(context.Context, string, string, coordinate.ModuleSet, cgports.EdgeQueryOptions) ([]cgports.CallEdgeRef, error) {
	return nil, nil
}

// reflectFixtureGraph is a small library graph holding one of each case that
// matters, shaped after the only real one on a working store.
//
//	Exported              exported API, so an entry point
//	  -> bindFields       internal, reached from that entry point
//	       -> reflect.(Value).FieldByName   at bind.go:10   DISPATCHING, reachable
//	       -> reflect.(Value).FieldByName   at bind.go:31   DISPATCHING, reachable
//	       -> reflect.TypeOf                at bind.go:12   attribute set, NOT a dispatch
//	  -> reflect.DeepEqual                  at api.go:7     attribute set, NOT a dispatch
//	testHelper            internal, nothing reaches it
//	       -> reflect.(Value).MethodByName  at exec.go:80   DISPATCHING, unreachable
//	Parse                 the symbol the advisory names, reached by nothing
//
// The two edges that carry the reflect attribute and are NOT dispatches are the
// whole reason this fixture is bigger than it looks. Counting them is the
// mistake that overstated this population by two orders of magnitude, and a
// fixture without them cannot catch it coming back.
func reflectFixtureGraph() cgdomain.CallGraphRecord {
	const mod = "example.com/dep"
	node := func(id, pkg, symbol string, exported bool) cgdomain.CallNode {
		return cgdomain.CallNode{ID: id, Module: mod, Package: pkg, Symbol: symbol, IsExportedAPI: exported}
	}
	reflectNode := func(id, receiver, symbol string) cgdomain.CallNode {
		return cgdomain.CallNode{ID: id, Module: "stdlib", Package: "reflect", Receiver: receiver, Symbol: symbol, IsExternal: true}
	}
	edge := func(from, to, file string, line int, isReflect bool) cgdomain.CallEdge {
		return cgdomain.CallEdge{
			FromID:          from,
			ToID:            to,
			CallSite:        cgdomain.SourcePosition{File: file, Line: line},
			Confidence:      cgdomain.ConfidenceUnknown,
			ReflectDispatch: isReflect,
		}
	}
	return cgdomain.CallGraphRecord{
		Coordinate:   reflectFixtureCoord,
		Algorithm:    cgdomain.AlgorithmCHA,
		Completeness: cgdomain.CompletenessBuiltWithBodies,
		ArtifactKind: cgdomain.ArtifactLibrary,
		Nodes: []cgdomain.CallNode{
			node(mod+".Exported", mod, "Exported", true),
			node(mod+".bindFields", mod, "bindFields", false),
			node(mod+"/internal/testenv.testHelper", mod+"/internal/testenv", "testHelper", false),
			node(mod+".Parse", mod, "Parse", true),
			reflectNode("reflect.(Value).FieldByName", "Value", "FieldByName"),
			reflectNode("reflect.(Value).MethodByName", "Value", "MethodByName"),
			reflectNode("reflect.TypeOf", "", "TypeOf"),
			reflectNode("reflect.DeepEqual", "", "DeepEqual"),
		},
		Edges: []cgdomain.CallEdge{
			edge(mod+".Exported", mod+".bindFields", "api.go", 4, false),
			edge(mod+".Exported", "reflect.DeepEqual", "api.go", 7, true),
			edge(mod+".bindFields", "reflect.(Value).FieldByName", "bind.go", 10, true),
			edge(mod+".bindFields", "reflect.TypeOf", "bind.go", 12, true),
			edge(mod+".bindFields", "reflect.(Value).FieldByName", "bind.go", 31, true),
			edge(mod+"/internal/testenv.testHelper", "reflect.(Value).MethodByName", "exec.go", 80, true),
		},
	}
}

// searchedReflectAnswer runs the whole read path over that graph and returns the
// answer a command would render: record in, curated reply out.
//
// Parse is named by the advisory and reached by nothing, so the search comes
// back empty and the verdict stays NOT reachable. That is the case this reports
// on — a negative is the only verdict a hidden route could be wrong about.
func searchedReflectAnswer(t *testing.T) vulnReachabilityQuery {
	t.Helper()

	rec := vuldomain.VulnerabilityRecord{
		Coordinate:    reflectFixtureCoord,
		OverallStatus: vuldomain.StatusAffected,
		Findings: []vuldomain.VulnerabilityFinding{{
			ID:              "GO-2021-0113",
			AffectedSymbols: []string{"Parse"},
			Reachable: &vuldomain.ReachabilityResult{
				IsReachable: false,
				Confidence:  vuldomain.ConfidenceHigh,
				DerivedBy: vuldomain.ReachabilityDerivation{
					Analyser: vuldomain.AnalyserGovulncheck,
					Fidelity: string(vuldomain.ScanModeSource),
					Rooting:  vuldomain.RootingIsolated,
				},
			},
		}},
	}

	loader := reachability.NewCallGraphStoreLoader(&reflectGraphStore{record: reflectFixtureGraph()}, "p1")
	reachability.NewNegativeSearcher(loader).Search(t.Context(), &rec)

	res, err := vulnReachabilityAnswer(reflectFixtureCoord, rec, true, "GO-2021-0113", nil, nil)
	if err != nil {
		t.Fatalf("building the answer: %v", err)
	}
	if res.ReachabilityState != verdictNotReachable {
		t.Fatalf("the fixture's verdict is %q, want %q — this reports on negatives", res.ReachabilityState, verdictNotReachable)
	}
	return res
}

// TestReachabilityJSON_NegativeNamesTheReflectiveDispatchItCouldNotFollow is the
// acceptance on the machine surface.
//
// Three claims, and the third is the one that keeps the other two honest:
// how many calls the search could not follow, how many of those anything can
// actually reach, and which they are. A call in code no entry point reaches
// cannot be on a route into this module, so reporting a bare count would make a
// negative look weaker than it is.
func TestReachabilityJSON_NegativeNamesTheReflectiveDispatchItCouldNotFollow(t *testing.T) {
	t.Parallel()

	doc := decodeAnswer(t, searchedReflectAnswer(t))
	search, ok := doc["negative_search"].(map[string]any)
	if !ok {
		t.Fatalf("the answer carries no negative_search: %v", doc)
	}
	d, ok := search["reflective_dispatch"].(map[string]any)
	if !ok {
		t.Fatalf("the search states nothing about reflective dispatch: %v", search)
	}

	// Three of the six edges carry the reflect attribute and are not dispatches.
	// A count of four or more means the attribute is being read as a dispatch
	// count, which overstates it by roughly two orders of magnitude on a real
	// graph.
	if got := d["site_count"]; got != float64(3) {
		t.Errorf("site_count = %v, want 3 — the graph holds 3 calls into a reflect method that picks its target at run time", got)
	}
	if got := d["reachable_site_count"]; got != float64(2) {
		t.Errorf("reachable_site_count = %v, want 2 — the third sits in code no entry point reaches", got)
	}

	sites, ok := search["reflective_dispatch"].(map[string]any)["sites"].([]any)
	if !ok || len(sites) != 3 {
		t.Fatalf("sites does not name the 3 call sites: %v", d["sites"])
	}
	byCallSite := map[string]map[string]any{}
	for _, raw := range sites {
		site, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("a site is not an object: %v", raw)
		}
		callSite, _ := site["call_site"].(string)
		byCallSite[callSite] = site
	}
	// Two calls from one function to one reflect method on two lines are two
	// sites. Collapsing them would send a reader to one of the two places.
	for _, want := range []struct {
		callSite  string
		callee    string
		reachable bool
	}{
		{"bind.go:10", "reflect.(Value).FieldByName", true},
		{"bind.go:31", "reflect.(Value).FieldByName", true},
		{"exec.go:80", "reflect.(Value).MethodByName", false},
	} {
		site, present := byCallSite[want.callSite]
		if !present {
			t.Errorf("no site at %s; got %v", want.callSite, byCallSite)
			continue
		}
		if got := site["callee"]; got != want.callee {
			t.Errorf("site at %s names callee %v, want %s", want.callSite, got, want.callee)
		}
		if got := site["reachable_from_entry_point"]; got != want.reachable {
			t.Errorf("site at %s reports reachable_from_entry_point %v, want %t", want.callSite, got, want.reachable)
		}
	}
	// The two calls into reflect that bound perfectly must not appear anywhere.
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	for _, bounded := range []string{"reflect.TypeOf", "reflect.DeepEqual"} {
		if strings.Contains(string(raw), bounded) {
			t.Errorf("the answer names %s as a reflective dispatch; it has one callee and bounds perfectly:\n%s", bounded, raw)
		}
	}
}

// TestReachabilityJSON_AGraphWithNoReflectiveDispatchStatesZero is the other
// acceptance, and the commoner case by far.
//
// Zero is stated rather than omitted because zero is a measurement: the search
// ran over the graph and found none. An absent key says nothing, and a consumer
// cannot tell it from a build that never looked.
func TestReachabilityJSON_AGraphWithNoReflectiveDispatchStatesZero(t *testing.T) {
	t.Parallel()

	graph := reflectFixtureGraph()
	// Keep only the edges whose callee bounds perfectly. The attribute is still
	// set on them, so a build that read the attribute alone would still report
	// sites here.
	var kept []cgdomain.CallEdge
	for _, e := range graph.Edges {
		if !strings.Contains(e.ToID, "(Value)") {
			kept = append(kept, e)
		}
	}
	graph.Edges = kept

	rec := vuldomain.VulnerabilityRecord{
		Coordinate:    reflectFixtureCoord,
		OverallStatus: vuldomain.StatusAffected,
		Findings: []vuldomain.VulnerabilityFinding{{
			ID:              "GO-2021-0113",
			AffectedSymbols: []string{"Parse"},
			Reachable: &vuldomain.ReachabilityResult{
				IsReachable: false,
				Confidence:  vuldomain.ConfidenceHigh,
				DerivedBy: vuldomain.ReachabilityDerivation{
					Analyser: vuldomain.AnalyserGovulncheck,
					Fidelity: string(vuldomain.ScanModeSource),
					Rooting:  vuldomain.RootingIsolated,
				},
			},
		}},
	}
	loader := reachability.NewCallGraphStoreLoader(&reflectGraphStore{record: graph}, "p1")
	reachability.NewNegativeSearcher(loader).Search(t.Context(), &rec)
	res, err := vulnReachabilityAnswer(reflectFixtureCoord, rec, true, "GO-2021-0113", nil, nil)
	if err != nil {
		t.Fatalf("building the answer: %v", err)
	}

	doc := decodeAnswer(t, res)
	search, ok := doc["negative_search"].(map[string]any)
	if !ok {
		t.Fatalf("the answer carries no negative_search: %v", doc)
	}
	d, present := search["reflective_dispatch"]
	if !present {
		t.Fatal("reflective_dispatch is absent; a stated zero is evidence and an omitted key is not")
	}
	obj, ok := d.(map[string]any)
	if !ok {
		t.Fatalf("reflective_dispatch is not an object: %v", d)
	}
	if got := obj["site_count"]; got != float64(0) {
		t.Errorf("site_count = %v, want 0 — every remaining reflect edge bounds perfectly", got)
	}
	if got := obj["reachable_site_count"]; got != float64(0) {
		t.Errorf("reachable_site_count = %v, want 0", got)
	}

	var buf bytes.Buffer
	printVulnReachability(&buf, res)
	if !strings.Contains(buf.String(), "reflective dispatch: none") {
		t.Errorf("the text answer does not state that the search found none:\n%s", buf.String())
	}
}

// TestPrintVulnReachability_NegativeNamesTheReflectiveDispatchItCouldNotFollow is
// the same acceptance on the surface an operator reads.
//
// It goes through printVulnReachability, the command's own printer, rather than
// the helper behind it: the helper could be perfect and never be called. The
// count, the reachable count and each site must all reach the page.
func TestPrintVulnReachability_NegativeNamesTheReflectiveDispatchItCouldNotFollow(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	printVulnReachability(&buf, searchedReflectAnswer(t))
	got := buf.String()

	if !strings.Contains(got, "reflective dispatch: 3 call sites the search could not follow") {
		t.Errorf("the answer does not say how many calls the search could not follow:\n%s", got)
	}
	// The distinction the measurement demanded. Without it the line qualifies a
	// negative on the strength of code nothing enters.
	if !strings.Contains(got, "2 of them are reachable from an entry point") {
		t.Errorf("the answer does not separate the reachable sites from the rest:\n%s", got)
	}
	for _, want := range []string{
		"example.com/dep.bindFields -> reflect.(Value).FieldByName at bind.go:10 — reachable from an entry point",
		"example.com/dep.bindFields -> reflect.(Value).FieldByName at bind.go:31 — reachable from an entry point",
		"example.com/dep/internal/testenv.testHelper -> reflect.(Value).MethodByName at exec.go:80 — not reachable from any entry point",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the answer does not name the site %q:\n%s", want, got)
		}
	}
	for _, bounded := range []string{"reflect.TypeOf", "reflect.DeepEqual"} {
		if strings.Contains(got, bounded) {
			t.Errorf("the answer names %s, which has one callee and bounds perfectly:\n%s", bounded, got)
		}
	}
	// The control. This states what a search could not follow; it does not change
	// what the search concluded.
	if !strings.Contains(got, "is NOT reachable") {
		t.Errorf("the verdict moved:\n%s", got)
	}
	if !strings.Contains(got, "soundness: inferred") {
		t.Errorf("the soundness rung moved:\n%s", got)
	}
}

// TestPrintVulnReachability_NoSearchSaysNothingAboutReflection separates the two
// silences.
//
// A search that could not be made has measured nothing, so it must not print a
// zero: "the graph holds no reflective dispatch" and "no graph was searched" are
// different facts, and the second is already stated on the rung.
func TestPrintVulnReachability_NoSearchSaysNothingAboutReflection(t *testing.T) {
	t.Parallel()

	rec := searchedNegativeRecord(&vuldomain.NegativeSearch{
		NotSearched: "the store holds no call graph for example.com/dep@v1.2.3",
	})
	res, err := vulnReachabilityAnswer(reachCoord, rec, true, "GO-2021-0113", nil, nil)
	if err != nil {
		t.Fatalf("building the answer: %v", err)
	}
	var buf bytes.Buffer
	printVulnReachability(&buf, res)
	if strings.Contains(buf.String(), "reflective dispatch") {
		t.Errorf("a search that never ran reports on reflective dispatch:\n%s", buf.String())
	}
}

// TestReachabilityJSON_ASearchThatNeverRanStatesWhyItsZerosAreNotMeasurements is
// the JSON counterpart of the test above, and it pins the one thing the machine
// surface does differently from the text one.
//
// The text surface can stay silent. JSON cannot: this object spells out every
// field on every search, so a consumer never has to tell a false from a producer
// that omits it. That leaves one hazard — a zero here read as "the graph holds
// none" when nothing was ever looked at — and not_searched is the key that
// settles it, for this field and for every field beside it.
func TestReachabilityJSON_ASearchThatNeverRanStatesWhyItsZerosAreNotMeasurements(t *testing.T) {
	t.Parallel()

	const why = "the store holds no call graph for example.com/dep@v1.2.3"
	rec := searchedNegativeRecord(&vuldomain.NegativeSearch{NotSearched: why})
	res, err := vulnReachabilityAnswer(reachCoord, rec, true, "GO-2021-0113", nil, nil)
	if err != nil {
		t.Fatalf("building the answer: %v", err)
	}

	search, ok := decodeAnswer(t, res)["negative_search"].(map[string]any)
	if !ok {
		t.Fatal("the answer carries no negative_search")
	}
	if got := search["not_searched"]; got != why {
		t.Fatalf("not_searched = %v, want the reason the search declined", got)
	}
	d, present := search["reflective_dispatch"]
	if !present {
		t.Fatal("reflective_dispatch is absent; every field of this object is spelled out on every search")
	}
	obj, ok := d.(map[string]any)
	if !ok {
		t.Fatalf("reflective_dispatch is not an object: %v", d)
	}
	if got := obj["site_count"]; got != float64(0) {
		t.Errorf("site_count = %v over a search that never ran, want 0", got)
	}
	// No sites may be named. A list beside a zero that means "nothing was
	// measured" would be the one way this object could contradict itself.
	if sites, present := obj["sites"]; present {
		t.Errorf("a search that never ran names %v as reflective dispatch sites", sites)
	}
}

// The graph below is NOT written here. It is the analyser's own output, captured
// from `callgraph-show <mod> --json` over a real module and stored verbatim in
// testdata. That is the point of it.
//
// A call-graph record built by hand in a test encodes whatever the author
// believed the analyser emits — which node is exported API, what a reflect
// callee id looks like, which confidence an unresolvable call carries, whether a
// package init shows up as a node at all. If any of those beliefs is wrong the
// test passes while the production path fails, and the graph has quietly become
// the thing being faked. Loading the analyser's own bytes removes that whole
// class.

// fakeCompressGraphJSON is the captured record, read from testdata.
//
//go:embed testdata/fakecompress-graph.json
var fakeCompressGraphJSON []byte

// fakeCompressCoord is the module the captured graph describes.
var fakeCompressCoord = coordinatetest.MustNew("github.com/klauspost/compress", "v1.18.2")

// loadCapturedGraph decodes a `callgraph-show --json` document back into the
// domain record the loader consumes.
//
// It decodes into callEdgeJSON and callNodeJSON — the very structs the command
// prints through — so the field names cannot drift from the captured bytes
// without this failing to compile. Only the enum spellings are mapped, because
// the JSON renders them for a reader: a library's stored artifact kind is the
// empty string and prints as "Library".
//
// Nothing here supplies data. Every value asserted downstream comes out of the
// file.
func loadCapturedGraph(t *testing.T, raw []byte) cgdomain.CallGraphRecord {
	t.Helper()

	var doc callGraphRecordJSON
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decoding the captured graph: %v", err)
	}
	kind := cgdomain.ArtifactKind(doc.ArtifactKind)
	if doc.ArtifactKind == cgdomain.ArtifactLibrary.String() {
		kind = cgdomain.ArtifactLibrary
	}
	rec := cgdomain.CallGraphRecord{
		Coordinate:   fakeCompressCoord,
		Algorithm:    cgdomain.CallGraphAlgorithm(doc.Algorithm),
		Completeness: cgdomain.CompletenessLevel(doc.Completeness),
		ArtifactKind: kind,
	}
	for _, n := range doc.Nodes {
		rec.Nodes = append(rec.Nodes, cgdomain.CallNode{
			ID: n.ID, Module: n.Module, Package: n.Package, Symbol: n.Symbol,
			Receiver: n.Receiver, IsExternal: n.IsExternal,
			IsExportedAPI: n.IsExportedAPI, IsTest: n.IsTest,
		})
	}
	for _, e := range doc.Edges {
		rec.Edges = append(rec.Edges, cgdomain.CallEdge{
			FromID:          e.FromID,
			ToID:            e.ToID,
			CallSite:        cgdomain.SourcePosition{File: e.CallSiteFile, Line: e.CallSiteLine},
			Confidence:      cgdomain.EdgeConfidence(e.Confidence),
			ReflectDispatch: e.ReflectDispatch,
		})
	}
	if len(rec.Nodes) == 0 || len(rec.Edges) == 0 {
		t.Fatalf("the captured graph decoded to %d nodes and %d edges", len(rec.Nodes), len(rec.Edges))
	}
	return rec
}

// TestReachabilityJSON_ReachIsDerivedByWalkingARealGraph is the primary evidence
// that the reach derivation works, because it runs on a graph the analyser
// produced rather than one this file imagined.
//
// The captured module reflects in two places and they differ in the only way
// that matters:
//
//	NewDict (the only exported API)
//	  -> configure -> prepare -> resolve -> apply -> bindFields
//	                                                   -> reflect.(Value).FieldByName
//	orphan (called by nothing)
//	  -> reflect.(Value).Call, reflect.(Value).MethodByName
//
// So one site is reachable from the module's single entry point and two are not,
// in one real graph. Nothing is hand-set: the loader picks the three dispatching
// sites out of the edges, the shared selector picks the entry points out of the
// nodes, and the traversal decides the rest.
//
// The chain is long on purpose and must not be shortened. bindFields sits FIVE
// hops below the entry point, so a traversal that walks a bounded number of
// steps and stops is caught here rather than looking correct. Measured at bounds
// of one, two and four, each of which reports the reachable site as unreachable
// — the direction that makes a negative look STRONGER than the analysis can
// support.
func TestReachabilityJSON_ReachIsDerivedByWalkingARealGraph(t *testing.T) {
	t.Parallel()

	graph := loadCapturedGraph(t, fakeCompressGraphJSON)
	rec := vuldomain.VulnerabilityRecord{
		Coordinate:    fakeCompressCoord,
		OverallStatus: vuldomain.StatusAffected,
		Findings: []vuldomain.VulnerabilityFinding{{
			ID:              "GO-2026-5841",
			AffectedSymbols: []string{"NewDict"},
			Reachable: &vuldomain.ReachabilityResult{
				IsReachable: false,
				Confidence:  vuldomain.ConfidenceHigh,
				DerivedBy: vuldomain.ReachabilityDerivation{
					Analyser: vuldomain.AnalyserGovulncheck,
					Fidelity: string(vuldomain.ScanModeSource),
					Rooting:  vuldomain.RootingIsolated,
				},
			},
		}},
	}
	loader := reachability.NewCallGraphStoreLoader(&reflectGraphStore{record: graph}, "p1")
	reachability.NewNegativeSearcher(loader).Search(t.Context(), &rec)
	res, err := vulnReachabilityAnswer(fakeCompressCoord, rec, true, "GO-2026-5841", nil, nil)
	if err != nil {
		t.Fatalf("building the answer: %v", err)
	}

	search, ok := decodeAnswer(t, res)["negative_search"].(map[string]any)
	if !ok {
		t.Fatal("the answer carries no negative_search")
	}
	// Guards. Without entry points nothing is walked and the assertions below
	// would pass over an empty question.
	if got := search["entry_point_roots"]; got == float64(0) {
		t.Fatal("the captured graph named no entry point, so nothing was walked")
	}
	d, ok := search["reflective_dispatch"].(map[string]any)
	if !ok {
		t.Fatalf("the search states nothing about reflective dispatch: %v", search)
	}
	// Three of the graph's reflect edges dispatch. The other six — ValueOf, Elem,
	// CanSet, IsValid, SetString, init — carry the same attribute and bound
	// perfectly, so a build reading the attribute alone would report nine.
	if got := d["site_count"]; got != float64(3) {
		t.Fatalf("site_count = %v, want 3 — the graph holds 9 calls into reflect and 3 that dispatch", got)
	}
	if got := d["reachable_site_count"]; got != float64(1) {
		t.Errorf("reachable_site_count = %v, want 1 — only the site under bindFields is entered", got)
	}

	reach := map[string]bool{}
	sites, ok := d["sites"].([]any)
	if !ok {
		t.Fatalf("sites is not a list: %v", d["sites"])
	}
	for _, raw := range sites {
		site, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("a site is not an object: %v", raw)
		}
		caller, _ := site["caller"].(string)
		callee, _ := site["callee"].(string)
		reachable, _ := site["reachable_from_entry_point"].(bool)
		reach[caller+" -> "+callee] = reachable
	}
	const zstd = "github.com/klauspost/compress/zstd"
	// Reachable: two hops below the module's only exported function.
	if !reach[zstd+".bindFields -> reflect.(Value).FieldByName"] {
		t.Errorf("the site under bindFields reports unreachable; it is entered from NewDict through configure, prepare, resolve and apply: %v", reach)
	}
	// Unreachable: nothing calls orphan, so nothing can reach either call in it.
	for _, callee := range []string{"reflect.(Value).Call", "reflect.(Value).MethodByName"} {
		if reach[zstd+".orphan -> "+callee] {
			t.Errorf("the site %s in uncalled code reports reachable: %v", callee, reach)
		}
	}
}
