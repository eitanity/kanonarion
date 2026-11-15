package cli

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/coordinate"
	"code.eitanity.com/kanonarion/internal/coordinate/coordinatetest"

	cgdomain "code.eitanity.com/kanonarion/internal/callgraph/domain"
	cgports "code.eitanity.com/kanonarion/internal/callgraph/ports"

	"code.eitanity.com/kanonarion/internal/vuln/adapters/reachability"
	vuldomain "code.eitanity.com/kanonarion/internal/vuln/domain"
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
//	       -> reflect.(Value).Method        at bind.go:10   LOOKUP, reachable
//	       -> reflect.(Value).Method        at bind.go:31   LOOKUP, reachable
//	       -> reflect.TypeOf                at bind.go:12   attribute set, NOT a lookup
//	  -> reflect.DeepEqual                  at api.go:7     attribute set, NOT a lookup
//	testHelper            internal, nothing reaches it
//	       -> reflect.(Value).MethodByName  at exec.go:80   LOOKUP, unreachable
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
			reflectNode("reflect.(Value).Method", "Value", "Method"),
			reflectNode("reflect.(Value).MethodByName", "Value", "MethodByName"),
			reflectNode("reflect.TypeOf", "", "TypeOf"),
			reflectNode("reflect.DeepEqual", "", "DeepEqual"),
		},
		Edges: []cgdomain.CallEdge{
			edge(mod+".Exported", mod+".bindFields", "api.go", 4, false),
			edge(mod+".Exported", "reflect.DeepEqual", "api.go", 7, true),
			edge(mod+".bindFields", "reflect.(Value).Method", "bind.go", 10, true),
			edge(mod+".bindFields", "reflect.TypeOf", "bind.go", 12, true),
			edge(mod+".bindFields", "reflect.(Value).Method", "bind.go", 31, true),
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
		callSite := optAs[string](t, site["call_site"])
		byCallSite[callSite] = site
	}
	// Two calls from one function to one reflect method on two lines are two
	// sites. Collapsing them would send a reader to one of the two places.
	assertReflectSites(t, byCallSite)
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

// assertReflectSites checks each call site into reflect is named apart, with
// its callee and whether an entry point reaches it.
func assertReflectSites(t *testing.T, byCallSite map[string]map[string]any) {
	t.Helper()
	for _, want := range []struct {
		callSite  string
		callee    string
		reachable bool
	}{
		{"bind.go:10", "reflect.(Value).Method", true},
		{"bind.go:31", "reflect.(Value).Method", true},
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

// TestPrintVulnReachability_NegativeNamesTheReflectiveDispatchItSearchedPast is
// the same acceptance on the surface an operator reads.
//
// It goes through printVulnReachability, the command's own printer, rather than
// the helper behind it: the helper could be perfect and never be called. The
// count, the reachable count and each site must all reach the page.
func TestPrintVulnReachability_NegativeNamesTheReflectiveDispatchItSearchedPast(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	printVulnReachability(&buf, searchedReflectAnswer(t))
	got := buf.String()

	if !strings.Contains(got, "reflective dispatch: 3 call sites that look a method up by reflection") {
		t.Errorf("the answer does not say how many lookup sites the graph holds:\n%s", got)
	}
	// The distinction the measurement demanded. Without it the line qualifies a
	// negative on the strength of code nothing enters.
	if !strings.Contains(got, "2 of them are reachable from an entry point") {
		t.Errorf("the answer does not separate the reachable sites from the rest:\n%s", got)
	}
	for _, want := range []string{
		"example.com/dep.bindFields -> reflect.(Value).Method at bind.go:10 — reachable from an entry point, the methods it can return are not known, so the search cannot follow it",
		"example.com/dep.bindFields -> reflect.(Value).Method at bind.go:31 — reachable from an entry point, the methods it can return are not known, so the search cannot follow it",
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
	// The control. Binding the sites changes no verdict, and here no rung: the
	// search ran over the module's own graph in another build's frame.
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
	for _, n := range *doc.Nodes {
		rec.Nodes = append(rec.Nodes, cgdomain.CallNode{
			ID: n.ID, Module: n.Module, Package: n.Package, Symbol: n.Symbol,
			Receiver: n.Receiver, IsExternal: n.IsExternal,
			IsExportedAPI: n.IsExportedAPI, IsTest: n.IsTest,
		})
	}
	for _, e := range *doc.Edges {
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

// reflectSiteReach maps each listed site, "caller -> callee", to whether an entry
// point reaches it.
func reflectSiteReach(t *testing.T, d map[string]any) map[string]bool {
	t.Helper()
	sites, ok := d["sites"].([]any)
	if !ok {
		t.Fatalf("sites is not a list: %v", d["sites"])
	}
	reach := map[string]bool{}
	for _, raw := range sites {
		site, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("a site is not an object: %v", raw)
		}
		caller := optAs[string](t, site["caller"])
		callee := optAs[string](t, site["callee"])
		reach[caller+" -> "+callee] = optAs[bool](t, site["reachable_from_entry_point"])
	}
	return reach
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
//	                                                   -> reflect.(Value).Method
//	orphan (called by nothing)
//	  -> reflect.(Value).Call, reflect.(Value).MethodByName
//
// The captured bindFields site was reflect.(Value).FieldByName, which is not a
// lookup, so that one callee is renamed below; the graph's shape is still the
// analyser's. One site is reachable from the module's single entry point and one
// is not, in one real graph. Nothing else is hand-set: the loader picks the
// lookups out of the edges, the shared selector picks the entry points out of
// the nodes, and the traversal decides the rest.
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
	for i, e := range graph.Edges {
		if e.ToID == "reflect.(Value).FieldByName" {
			graph.Edges[i].ToID = "reflect.(Value).Method"
		}
	}
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
	// Two of the graph's reflect edges are lookups. The other seven — Call,
	// ValueOf, Elem, CanSet, IsValid, SetString, init — carry the same attribute
	// and are not, so a build reading the attribute alone would report nine.
	if got := d["site_count"]; got != float64(2) {
		t.Fatalf("site_count = %v, want 2 — the graph holds 9 calls into reflect and 2 lookups", got)
	}
	if got := d["reachable_site_count"]; got != float64(1) {
		t.Errorf("reachable_site_count = %v, want 1 — only the site under bindFields is entered", got)
	}

	reach := reflectSiteReach(t, d)
	const zstd = "github.com/klauspost/compress/zstd"
	// Reachable: two hops below the module's only exported function.
	if !reach[zstd+".bindFields -> reflect.(Value).Method"] {
		t.Errorf("the site under bindFields reports unreachable; it is entered from NewDict through configure, prepare, resolve and apply: %v", reach)
	}
	// Unreachable: nothing calls orphan, so nothing can reach either call in it.
	if _, listed := reach[zstd+".orphan -> reflect.(Value).Call"]; listed {
		t.Errorf("reflect.(Value).Call is listed as a site; it fetches nothing: %v", reach)
	}
	for _, callee := range []string{"reflect.(Value).MethodByName"} {
		if entered, present := reach[zstd+".orphan -> "+callee]; !present || entered {
			t.Errorf("the site %s in uncalled code reports reachable or is missing: %v", callee, reach)
		}
	}
}

// clearNamedSiteAnswer is searchedReflectAnswer with the advisory's symbol
// unexported so the search runs clean, and the given callee and name on the
// sites under bindFields.
func clearNamedSiteAnswer(t *testing.T, callee, name string) vulnReachabilityQuery {
	t.Helper()

	graph := reflectFixtureGraph()
	for i, n := range graph.Nodes {
		if n.Symbol == "Parse" {
			graph.Nodes[i].IsExportedAPI = false
		}
	}
	for i, e := range graph.Edges {
		if e.ToID == "reflect.(Value).Method" {
			graph.Edges[i].ToID = callee
			graph.Edges[i].LookupName = name
		}
	}
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
	return res
}

// TestReachability_AReachableLookupConfirmsOnlyWhenItsNamesAreKnown is the
// whole change, on the two surfaces a reader has: a site with a known name set
// is searched past and a clean negative confirms, naming it; a site without one
// holds the negative at unconfirmed, naming it.
func TestReachability_AReachableLookupConfirmsOnlyWhenItsNamesAreKnown(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		callee, name string
		want         vuldomain.ReachabilitySoundness
		says         string
	}{
		{callee: "reflect.(*rtype).MethodByName", name: "Run", want: vuldomain.SoundnessConfirmed,
			says: "from the 2 reachable lookup sites: example.com/dep.bindFields -> reflect.(*rtype).MethodByName at bind.go:10 (no exported method named Run is in the graph searched"},
		{callee: "text/template.(*Template).Execute", name: "Run", want: vuldomain.SoundnessConfirmed,
			says: "from the 2 reachable lookup sites: example.com/dep.bindFields -> text/template.(*Template).Execute at bind.go:10 ("},
		{callee: "reflect.(*rtype).MethodByName", want: vuldomain.SoundnessUnconfirmed,
			says: "reach 2 reflective method lookup sites whose methods are not known"},
		{callee: "text/template.(*Template).Execute", want: vuldomain.SoundnessUnconfirmed,
			says: "reach 2 reflective method lookup sites whose methods are not known"},
		{callee: "net/rpc.Register", want: vuldomain.SoundnessUnconfirmed,
			says: "reach 2 reflective method lookup sites whose methods are not known"},
	} {
		t.Run(tt.callee+"/"+tt.name, func(t *testing.T) {
			t.Parallel()

			res := clearNamedSiteAnswer(t, tt.callee, tt.name)
			if res.Soundness != tt.want {
				t.Errorf("soundness = %s (%s), want %s", res.Soundness, res.SoundnessReason, tt.want)
			}
			search, ok := decodeAnswer(t, res)["negative_search"].(map[string]any)
			if !ok {
				t.Fatal("the answer carries no negative_search")
			}
			d := mustAs[map[string]any](t, search["reflective_dispatch"])
			if got := d["reachable_site_count"]; got != float64(2) {
				t.Errorf("reachable_site_count = %v, want 2", got)
			}
			for _, raw := range mustAs[[]any](t, d["sites"]) {
				site := mustAs[map[string]any](t, raw)
				if site["reachable_from_entry_point"] == true && site["bound"] != (tt.name != "") {
					t.Errorf("site = %v, want bound %t", site, tt.name != "")
				}
			}
			var buf bytes.Buffer
			printVulnReachability(&buf, res)
			got := buf.String()
			for _, want := range []string{"soundness: " + string(tt.want), tt.says} {
				if !strings.Contains(got, want) {
					t.Errorf("the answer does not say %q:\n%s", want, got)
				}
			}
		})
	}
}

// TestPrintVulnReachability_NoSiteStatesOnlyWhatWasMeasured: the none line says
// what the searched graph holds, and no more. Go has no lookup of a function by
// name, but that is not something this graph measured about the build.
func TestPrintVulnReachability_NoSiteStatesOnlyWhatWasMeasured(t *testing.T) {
	t.Parallel()

	rec := searchedNegativeRecord(&vuldomain.NegativeSearch{EntryPointRoots: 3, Fidelity: "BUILT_WITH_BODIES"})
	res, err := vulnReachabilityAnswer(reachCoord, rec, true, "GO-2021-0113", nil, nil)
	if err != nil {
		t.Fatalf("building the answer: %v", err)
	}
	var buf bytes.Buffer
	printVulnReachability(&buf, res)
	got := buf.String()
	want := "reflective dispatch: none — the graph searched holds no reflective method lookup and no call to a standard-library function that makes one\n"
	if !strings.Contains(got, want) {
		t.Errorf("the answer does not state %q:\n%s", want, got)
	}
	if strings.Contains(got, "could be hiding") {
		t.Errorf("the none line still claims no route could be hiding:\n%s", got)
	}
}

// TestReachabilityJSON_ANamedLookupStatesItsNameAndBinding: a MethodByName site
// with a recorded name carries it and the count of methods it bound, in JSON
// and text. reflect.(Value).MethodByName is the one method of that name here.
func TestReachabilityJSON_ANamedLookupStatesItsNameAndBinding(t *testing.T) {
	t.Parallel()

	res := clearNamedSiteAnswer(t, "reflect.(Value).MethodByName", "MethodByName")
	search, ok := decodeAnswer(t, res)["negative_search"].(map[string]any)
	if !ok {
		t.Fatal("the answer carries no negative_search")
	}
	sites := mustAs[[]any](t, mustAs[map[string]any](t, search["reflective_dispatch"])["sites"])
	named := 0
	for _, raw := range sites {
		site := mustAs[map[string]any](t, raw)
		if site["reachable_from_entry_point"] != true {
			continue
		}
		named++
		if site["lookup_name"] != "MethodByName" || site["methods_bound"] != float64(1) {
			t.Errorf("site = %v, want lookup_name MethodByName and methods_bound 1", site)
		}
	}
	if named != 2 {
		t.Errorf("%d reachable sites, want 2: %v", named, sites)
	}
	var buf bytes.Buffer
	printVulnReachability(&buf, res)
	if want := "at bind.go:10 — reachable from an entry point, bound to the 1 exported method named MethodByName"; !strings.Contains(buf.String(), want) {
		t.Errorf("the answer does not say %q:\n%s", want, buf.String())
	}
}
