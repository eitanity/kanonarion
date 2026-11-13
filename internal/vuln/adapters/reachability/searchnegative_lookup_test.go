package reachability_test

import (
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/coordinate/coordinatetest"

	"code.eitanity.com/kanonarion/internal/vuln/adapters/reachability"
	"code.eitanity.com/kanonarion/internal/vuln/domain"
	"code.eitanity.com/kanonarion/internal/vuln/ports"
)

// lookupGraph is libraryGraph with one lookup site in bind, which the entry
// point calls, and the methods a lookup could return around it:
//
//   - T.Run calls the vulnerable symbol; U.Run, on a second type, does not.
//   - T.Other is exported and calls the vulnerable symbol too.
//   - T.run is unexported and Fake.Probe is test code, and both call it.
//   - orphan holds a second site that nothing reaches.
func lookupGraph(site ports.CallGraphReflectSite) ports.CallGraphProjection {
	proj := libraryGraph("BUILT_WITH_BODIES", false)
	method := func(id, recv, sym string, test bool) ports.CallGraphNode {
		return ports.CallGraphNode{ID: id, Module: searchedModule, Package: searchedModule, Receiver: recv, Symbol: sym, IsTest: test}
	}
	proj.Nodes = append(proj.Nodes,
		ports.CallGraphNode{ID: "bind", Module: searchedModule, Package: searchedModule, Symbol: "bind"},
		ports.CallGraphNode{ID: "orphan", Module: searchedModule, Package: searchedModule, Symbol: "orphan"},
		method("T.Run", "T", "Run", false),
		method("U.Run", "*U", "Run", false),
		method("T.Other", "T", "Other", false),
		method("T.run", "T", "run", false),
		method("Fake.Probe", "Fake", "Probe", true),
		method("T.Run$1", "T", "Run$1", false),
	)
	proj.Edges = append(proj.Edges,
		ports.CallGraphEdge{FromID: "entry", ToID: "bind"},
		ports.CallGraphEdge{FromID: "T.Run", ToID: "vuln"},
		ports.CallGraphEdge{FromID: "T.Other", ToID: "vuln"},
		ports.CallGraphEdge{FromID: "T.run", ToID: "vuln"},
		ports.CallGraphEdge{FromID: "Fake.Probe", ToID: "vuln"},
		ports.CallGraphEdge{FromID: "T.Run$1", ToID: "vuln"},
	)
	proj.ReflectiveDispatch = []ports.CallGraphReflectSite{
		site,
		{CallerID: "orphan", CalleeID: "reflect.(Value).MethodByName", File: "orphan.go", Line: 2},
	}
	return proj
}

func searchLookup(t *testing.T, proj ports.CallGraphProjection) (*domain.NegativeSearch, domain.ReachabilitySoundness, string) {
	t.Helper()
	rec := searchedRecord(domain.TargetRootedAt(coordinatetest.MustNew(searchedModule, "v1.0.0")), []string{"vulnerable"})
	reachability.NewNegativeSearcher(&countingLoader{projection: proj}).Search(t.Context(), &rec)
	search := rec.Findings[0].NegativeSearch
	if search == nil || search.NotSearched != "" {
		t.Fatalf("the search did not run: %+v", search)
	}
	got, reason := domain.NegativeSoundness(rec.Findings[0])
	return search, got, reason
}

// siteFor is the reported site whose caller is caller.
func siteFor(t *testing.T, s *domain.NegativeSearch, caller string) domain.ReflectiveDispatchSite {
	t.Helper()
	for _, site := range s.ReflectiveDispatch {
		if site.Caller == caller {
			return site
		}
	}
	t.Fatalf("no site in %s: %+v", caller, s.ReflectiveDispatch)
	return domain.ReflectiveDispatchSite{}
}

// TestSearchNegative_ALookupBindsTheMethodsItCanReturn covers each site with a
// known name set: a constant MethodByName name binds the exported, non-test
// methods of that name on every type, and a template the exported methods its
// module's constant texts name. A bound method that reaches the vulnerable
// symbol disputes the negative, over a hop annotated reflect.
func TestSearchNegative_ALookupBindsTheMethodsItCanReturn(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name, callee, lookup string
		bound                int
		via                  string
	}{
		{name: "Value.MethodByName constant", callee: "reflect.(Value).MethodByName", lookup: "Run", bound: 2, via: "T.Run"},
		{name: "Type.MethodByName constant", callee: "reflect.(*rtype).MethodByName", lookup: "Run", bound: 2, via: "T.Run"},
		{name: "constant name of the other method", callee: "reflect.(Value).MethodByName", lookup: "Other", bound: 1, via: "T.Other"},
		{name: "template naming Run", callee: "text/template.(*Template).Execute", lookup: "Run", bound: 2, via: "T.Run"},
		{name: "template naming several", callee: "html/template.(*Template).ExecuteTemplate", lookup: "Missing,Other,Run", bound: 3},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s, got, reason := searchLookup(t, lookupGraph(ports.CallGraphReflectSite{
				CallerID: "bind", CalleeID: tt.callee, File: "bind.go", Line: 7, LookupName: tt.lookup,
			}))
			if got != domain.SoundnessDisputed {
				t.Fatalf("soundness = %s (%s), want %s", got, reason, domain.SoundnessDisputed)
			}
			if site := siteFor(t, s, "bind"); !site.ReachableFromEntryPoint || site.MethodsBound != tt.bound || site.LookupName != tt.lookup {
				t.Errorf("site = %+v, want reachable, %d bound, name %q", site, tt.bound, tt.lookup)
			}
			assertLookupRoute(t, s.Route, tt.callee, tt.via)
			if !strings.Contains(reason, "from the 1 reachable lookup site: bind -> "+tt.callee+" at bind.go:7 (bound to the ") {
				t.Errorf("the reason does not name the site: %s", reason)
			}
			if !strings.Contains(reason, "is reflect, at bind.go:7") {
				t.Errorf("the reason does not state the reflective hop: %s", reason)
			}
		})
	}
}

// assertLookupRoute checks a route entry -> bind -> <method> -> vulnerable whose
// one added hop reads reflect and names the site, and whose call hops do not.
func assertLookupRoute(t *testing.T, route domain.ReachabilityRoute, callee, via string) {
	t.Helper()
	if len(route) != 4 || route[1].Symbol != "bind" || route[3].Symbol != "vulnerable" {
		t.Fatalf("route = %s, want entry -> bind -> <method> -> vulnerable", route)
	}
	if via != "" && route[2].Receiver+"."+route[2].Symbol != via {
		t.Errorf("route goes through %s.%s, want %s", route[2].Receiver, route[2].Symbol, via)
	}
	hop := route[2].Dispatch
	if hop.Kind != domain.DispatchReflect || hop.CallSite != "bind.go:7" || !strings.Contains(hop.Reason, "bind -> "+callee) {
		t.Errorf("the hop over the added edge reads %+v, want reflect naming the site", hop)
	}
	if route[1].Dispatch.IsRecorded() || route[3].Dispatch.IsRecorded() {
		t.Errorf("a hop over a call edge was annotated: %+v", route)
	}
}

// TestSearchNegative_AnUnboundLookupHoldsTheRung: a site whose methods are not
// known adds no edge, so a clean search past a reachable one reads
// unconfirmed and names it. A template whose texts name nothing is bound, to
// nothing, and confirms.
func TestSearchNegative_AnUnboundLookupHoldsTheRung(t *testing.T) {
	t.Parallel()

	for _, callee := range []string{
		"reflect.(Value).MethodByName", "reflect.(*rtype).MethodByName", "reflect.(Value).Method",
		"reflect.(*rtype).Methods", "text/template.(*Template).Execute", "net/rpc.Register",
	} {
		t.Run(callee, func(t *testing.T) {
			t.Parallel()
			s, got, reason := searchLookup(t, lookupGraph(ports.CallGraphReflectSite{CallerID: "bind", CalleeID: callee, File: "bind.go", Line: 7}))
			if got != domain.SoundnessUnconfirmed {
				t.Fatalf("soundness = %s (%s), want %s", got, reason, domain.SoundnessUnconfirmed)
			}
			if site := siteFor(t, s, "bind"); site.Bound || site.MethodsBound != 0 || !site.ReachableFromEntryPoint {
				t.Errorf("site = %+v, want reachable, unbound, nothing bound", site)
			}
			if !strings.Contains(reason, "whose methods are not known, which this search cannot follow, so a route may exist that it could not see: bind -> "+callee+" at bind.go:7") {
				t.Errorf("the reason does not name the unbound site: %s", reason)
			}
		})
	}

	s, got, reason := searchLookup(t, lookupGraph(ports.CallGraphReflectSite{
		CallerID: "bind", CalleeID: "text/template.(*Template).Execute", LookupName: "-",
	}))
	if got != domain.SoundnessConfirmed {
		t.Fatalf("a template naming nothing: soundness = %s (%s), want %s", got, reason, domain.SoundnessConfirmed)
	}
	if site := siteFor(t, s, "bind"); !site.Bound || site.NameCount != 0 || site.MethodsBound != 0 {
		t.Errorf("site = %+v, want bound to no name", site)
	}
}

// TestSearchNegative_ALookupThatBindsNothingReachingTheSymbolConfirms is the
// other side of the binding: a name matching no method, a name only an
// unexported method has, and a name only test code has all bind no route, so
// the clean search confirms and its reason names the site.
func TestSearchNegative_ALookupThatBindsNothingReachingTheSymbolConfirms(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name, lookup string
	}{
		{name: "no method of that name", lookup: "Missing"},
		{name: "only an unexported method", lookup: "run"},
		{name: "only a test method", lookup: "Probe"},
		{name: "only a closure", lookup: "Run$1"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s, got, reason := searchLookup(t, lookupGraph(ports.CallGraphReflectSite{
				CallerID: "bind", CalleeID: "reflect.(Value).MethodByName", File: "bind.go", Line: 7, LookupName: tt.lookup,
			}))
			if got != domain.SoundnessConfirmed {
				t.Fatalf("soundness = %s (%s), want %s", got, reason, domain.SoundnessConfirmed)
			}
			if site := siteFor(t, s, "bind"); site.MethodsBound != 0 || !site.ReachableFromEntryPoint {
				t.Errorf("site = %+v, want reachable with nothing bound", site)
			}
			if !strings.Contains(reason, "no exported method named "+tt.lookup+" is in the graph searched") {
				t.Errorf("the reason does not name the site and its binding: %s", reason)
			}
		})
	}
}

// TestSearchNegative_ALookupNothingReachesAddsNothing: the only site that could
// bind T.Run is in code no entry point reaches, so it binds nothing and the
// clean search confirms.
func TestSearchNegative_ALookupNothingReachesAddsNothing(t *testing.T) {
	t.Parallel()

	proj := lookupGraph(ports.CallGraphReflectSite{CallerID: "orphan", CalleeID: "reflect.(*rtype).Method", File: "orphan.go", Line: 9})
	s, got, reason := searchLookup(t, proj)
	if got != domain.SoundnessConfirmed {
		t.Fatalf("soundness = %s (%s), want %s", got, reason, domain.SoundnessConfirmed)
	}
	for _, site := range s.ReflectiveDispatch {
		if site.ReachableFromEntryPoint || site.MethodsBound != 0 {
			t.Errorf("an unreached site was bound: %+v", site)
		}
	}
	if strings.Contains(reason, "reachable lookup site") {
		t.Errorf("the reason names a site nothing reaches: %s", reason)
	}
}

// TestSearchNegative_AMethodALookupReachesCanReachAFurtherLookup: the second
// site sits in a method only the first one binds, so it is reached, and bound,
// only once the first one's edges are in the graph.
func TestSearchNegative_AMethodALookupReachesCanReachAFurtherLookup(t *testing.T) {
	t.Parallel()

	proj := libraryGraph("BUILT_WITH_BODIES", false)
	proj.Nodes = append(proj.Nodes,
		ports.CallGraphNode{ID: "A.First", Module: searchedModule, Package: searchedModule, Receiver: "A", Symbol: "First"},
		ports.CallGraphNode{ID: "B.Second", Module: searchedModule, Package: searchedModule, Receiver: "B", Symbol: "Second"},
	)
	proj.Edges = append(proj.Edges, ports.CallGraphEdge{FromID: "B.Second", ToID: "vuln"})
	proj.ReflectiveDispatch = []ports.CallGraphReflectSite{
		{CallerID: "A.First", CalleeID: "reflect.(Value).MethodByName", LookupName: "Second"},
		{CallerID: "entry", CalleeID: "reflect.(Value).MethodByName", LookupName: "First"},
	}
	s, got, reason := searchLookup(t, proj)
	if got != domain.SoundnessDisputed {
		t.Fatalf("soundness = %s (%s), want %s", got, reason, domain.SoundnessDisputed)
	}
	if len(s.Route) != 4 || s.Route[1].Symbol != "First" || s.Route[2].Symbol != "Second" {
		t.Errorf("route = %s, want Serve -> A.First -> B.Second -> vulnerable", s.Route)
	}
	if s.Route[1].Dispatch.Kind != domain.DispatchReflect || s.Route[2].Dispatch.Kind != domain.DispatchReflect {
		t.Errorf("both added hops should read reflect: %+v", s.Route)
	}
	if n := s.ReachableReflectiveDispatch(); n != 2 {
		t.Errorf("reachable sites = %d, want 2: %+v", n, s.ReflectiveDispatch)
	}
}

// TestSearchNegative_ALookupBindingAnUnjoinedMethodKeepsTheRecordedRung: the
// project's lookup binds a method of a module whose graph is not held. The
// method is reached only through the added edge, and the route may continue
// there, so the joined search does not confirm and names the call.
func TestSearchNegative_ALookupBindingAnUnjoinedMethodKeepsTheRecordedRung(t *testing.T) {
	project := projectGraph("parse", "wasmexport", "Parse", linkedClosure)
	project.Nodes = append(project.Nodes, ports.CallGraphNode{
		ID: "example.com/wrap.(T).Run", Package: "example.com/wrap", Receiver: "T", Symbol: "Run", IsExternal: true,
	})

	// The control: without the site the joined search confirms.
	if _, got, reason := searchDependency(t, dependencyLoader(project), advisoryPackages, advisorySymbols); got != domain.SoundnessConfirmed {
		t.Fatalf("control soundness = %s (%s), want %s", got, reason, domain.SoundnessConfirmed)
	}

	project.ReflectiveDispatch = []ports.CallGraphReflectSite{
		{CallerID: consumerModule + ".parse", CalleeID: "reflect.(Value).MethodByName", File: "main.go", Line: 4, LookupName: "Run"},
	}
	s, got, reason := searchDependency(t, dependencyLoader(project), advisoryPackages, advisorySymbols)
	if got == domain.SoundnessConfirmed {
		t.Fatalf("soundness = %s (%s), want the recorded rung", got, reason)
	}
	if !strings.Contains(s.NotJoined, "not joined (example.com/wrap.(T).Run)") {
		t.Errorf("the answer does not name the unjoined call: %q", s.NotJoined)
	}
}

// TestSearchNegative_ACallerWithManySitesAddsEachMethodOnce: two sites in one
// caller whose name sets overlap share their edges, and a method the caller
// already calls keeps its call edge, so the route over it is not a reflect hop.
func TestSearchNegative_ACallerWithManySitesAddsEachMethodOnce(t *testing.T) {
	t.Parallel()

	proj := lookupGraph(ports.CallGraphReflectSite{CallerID: "bind", CalleeID: "reflect.(Value).MethodByName", LookupName: "Run"})
	proj.ReflectiveDispatch = append(proj.ReflectiveDispatch,
		ports.CallGraphReflectSite{CallerID: "bind", CalleeID: "reflect.(Value).MethodByName", LookupName: "Other,Run"})
	proj.Edges = append([]ports.CallGraphEdge{{FromID: "bind", ToID: "T.Other"}}, proj.Edges...)
	s, got, reason := searchLookup(t, proj)
	if got != domain.SoundnessDisputed {
		t.Fatalf("soundness = %s (%s), want %s", got, reason, domain.SoundnessDisputed)
	}
	if len(s.Route) != 4 || s.Route[2].Symbol != "Other" || s.Route[2].Dispatch.IsRecorded() {
		t.Errorf("route = %+v, want the call edge into T.Other, unannotated", s.Route)
	}
	var names []string
	for _, site := range s.ReflectiveDispatch {
		if site.Caller == "bind" {
			names = append(names, site.LookupName)
		}
	}
	if len(names) != 2 || names[0] != "Other,Run" || names[1] != "Run" {
		t.Errorf("the two sites in bind are ordered %q, want them ordered by name set", names)
	}
}

// TestSearchNegative_UnderTinyGoALookupReturnsNoMethod: a TinyGo graph at 0.44
// or older binds no method to a reached site, so the route through T.Run is not
// found and the negative confirms. No frame, a newer TinyGo, and a TinyGo graph
// with no version keep Go's rule and find it.
func TestSearchNegative_UnderTinyGoALookupReturnsNoMethod(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name, target, version string
		noMethod              bool
	}{
		{name: "TinyGo 0.44.0", target: "wasip1", version: "0.44.0", noMethod: true},
		{name: "TinyGo 0.40.0", target: "pico", version: "0.40.0", noMethod: true},
		{name: "no TinyGo frame"},
		{name: "TinyGo 0.45.0", target: "wasip1", version: "0.45.0"},
		{name: "TinyGo 0.100.0", target: "wasip1", version: "0.100.0"},
		{name: "TinyGo, no version", target: "wasip1"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			proj := lookupGraph(ports.CallGraphReflectSite{
				CallerID: "bind", CalleeID: "reflect.(*rawType).MethodByName", File: "bind.go", Line: 7, LookupName: "Run",
			})
			proj.TinyGoTarget, proj.TinyGoVersion = tt.target, tt.version
			s, got, reason := searchLookup(t, proj)
			site := siteFor(t, s, "bind")
			if !tt.noMethod {
				if got != domain.SoundnessDisputed || site.ReturnsNoMethod || site.MethodsBound != 2 {
					t.Fatalf("Go's rule: soundness = %s, site = %+v (%s), want disputed with 2 bound", got, site, reason)
				}
				return
			}
			if s.PathFound || got != domain.SoundnessConfirmed {
				t.Fatalf("soundness = %s, path found %v (%s), want confirmed with no path", got, s.PathFound, reason)
			}
			if !site.ReachableFromEntryPoint || !site.ReturnsNoMethod || site.MethodsBound != 0 {
				t.Errorf("site = %+v, want reached, returning no method, nothing bound", site)
			}
			if !strings.Contains(reason, "bind -> reflect.(*rawType).MethodByName at bind.go:7 (TinyGo's reflect panics on a method lookup") {
				t.Errorf("the reason does not name the TinyGo site: %s", reason)
			}
		})
	}
}
