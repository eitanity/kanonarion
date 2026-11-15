package domain_test

import (
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/vuln/domain"
)

// TestReflectiveDispatchSite_BindingSaysWhatTheSearchAdded covers each binding
// a site can have: not reached, a name nothing has, a name, and no name.
func TestReflectiveDispatchSite_BindingSaysWhatTheSearchAdded(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		site domain.ReflectiveDispatchSite
		want string
	}{
		{site: domain.ReflectiveDispatchSite{LookupName: "Run", Bound: true, NameCount: 1, MethodsBound: 3}, want: "not reached, so nothing bound"},
		{site: domain.ReflectiveDispatchSite{ReachableFromEntryPoint: true},
			want: "the methods it can return are not known, so the search cannot follow it"},
		{site: domain.ReflectiveDispatchSite{ReachableFromEntryPoint: true, LookupName: "Run", Bound: true, NameCount: 1},
			want: "no exported method named Run is in the graph searched, so nothing was bound"},
		{site: domain.ReflectiveDispatchSite{ReachableFromEntryPoint: true, LookupName: "Run", Bound: true, NameCount: 1, MethodsBound: 2},
			want: "bound to the 2 exported methods named Run"},
		{site: domain.ReflectiveDispatchSite{ReachableFromEntryPoint: true, LookupName: "A,B", Bound: true, NameCount: 2},
			want: "no exported method named in its module's constant templates (2 names) is in the graph searched, so nothing was bound"},
		{site: domain.ReflectiveDispatchSite{ReachableFromEntryPoint: true, LookupName: "A,B", Bound: true, NameCount: 2, MethodsBound: 5},
			want: "bound to the 5 exported methods named in its module's constant templates (2 names)"},
	} {
		if got := tt.site.Binding(); got != tt.want {
			t.Errorf("Binding(%+v) = %q, want %q", tt.site, got, tt.want)
		}
	}
	site := domain.ReflectiveDispatchSite{Caller: "a.f", Callee: "reflect.(Value).MethodByName", CallSite: "a.go:3", ReachableFromEntryPoint: true,
		LookupName: "Run", Bound: true, NameCount: 1, MethodsBound: 1}
	if got, want := site.String(), "a.f -> reflect.(Value).MethodByName at a.go:3 (bound to the 1 exported method named Run)"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

// TestLookupHopDispatch_NamesTheSiteItWasAddedFor: the hop reads reflect, at
// the lookup's call site, and its reason names the lookup and its binding.
func TestLookupHopDispatch_NamesTheSiteItWasAddedFor(t *testing.T) {
	t.Parallel()

	site := domain.ReflectiveDispatchSite{Caller: "m.main", Callee: "reflect.(Value).MethodByName", CallSite: "main.go:13",
		ReachableFromEntryPoint: true, LookupName: "Run", Bound: true, NameCount: 1, MethodsBound: 1}
	hop := domain.LookupHopDispatch(site)
	if hop.Kind != domain.DispatchReflect || hop.CallSite != "main.go:13" {
		t.Errorf("hop = %+v, want reflect at main.go:13", hop)
	}
	if want := "an edge the search added for the reflective method lookup m.main -> reflect.(Value).MethodByName, bound to the 1 exported method named Run"; hop.Reason != want {
		t.Errorf("reason = %q, want %q", hop.Reason, want)
	}
}

// TestSearchedNegative_ARouteOverAnAddedEdgeSaysSoInText: the disputed reason
// states each reflect hop, so the text answer carries what the JSON hop does,
// and a reason naming many sites names five and points at the full list.
func TestSearchedNegative_ARouteOverAnAddedEdgeSaysSoInText(t *testing.T) {
	t.Parallel()

	site := domain.ReflectiveDispatchSite{Caller: "m.main", Callee: "reflect.(Value).MethodByName", CallSite: "main.go:13",
		ReachableFromEntryPoint: true, LookupName: "Run", Bound: true, NameCount: 1, MethodsBound: 1}
	route := domain.ReachabilityRoute{
		{ModulePath: "m", Package: "m", Symbol: "main"},
		{ModulePath: "m", Package: "m", Receiver: "D", Symbol: "Run", Dispatch: domain.LookupHopDispatch(site)},
		{ModulePath: "x", Package: "x", Symbol: "Vulnerable"},
	}
	sites := []domain.ReflectiveDispatchSite{site, site, site, site, site, site, site}
	search := domain.NegativeSearch{PathFound: true, InRecordedFrame: true, Route: route, ReflectiveDispatch: sites,
		EntryPointRoots: 1, Fidelity: "BUILT_WITH_BODIES"}
	got, reason := domain.NegativeSoundness(searchedNegative(&search))
	if got != domain.SoundnessDisputed {
		t.Fatalf("rung = %s (%s), want %s", got, reason, domain.SoundnessDisputed)
	}
	if want := "On that route, m main -> m (D).Run is reflect, at main.go:13, an edge the search added for the reflective method lookup m.main"; !strings.Contains(reason, want) {
		t.Errorf("the reason does not state the reflect hop %q: %s", want, reason)
	}
	if want := "from the 7 reachable lookup sites: "; !strings.Contains(reason, want) {
		t.Errorf("the reason does not count the sites: %s", reason)
	}
	if want := "; and 2 more, listed under reflective dispatch"; !strings.Contains(reason, want) {
		t.Errorf("the reason does not cap the list at five: %s", reason)
	}
}

// TestLocalProbeSettles_NamesOnlyTheNegativesTheProbeCanSettle: a local-rooted
// negative held by an unknown lookup, or disputed, is one a linked build
// answers; an isolated, a module-level (TinyGo) and an inferred one are not.
func TestLocalProbeSettles_NamesOnlyTheNegativesTheProbeCanSettle(t *testing.T) {
	t.Parallel()

	unbound := domain.NegativeSearch{EntryPointRoots: 1, Fidelity: "BUILT_WITH_BODIES",
		ReflectiveDispatch: []domain.ReflectiveDispatchSite{{Caller: "m.f", Callee: "text/template.(*Template).Execute", ReachableFromEntryPoint: true}}}
	disputed := domain.NegativeSearch{EntryPointRoots: 1, Fidelity: "BUILT_WITH_BODIES", PathFound: true, InRecordedFrame: true,
		Route: domain.ReachabilityRoute{{ModulePath: "m", Package: "m", Symbol: "main"}, {ModulePath: "x", Package: "x", Symbol: "Vulnerable"}}}
	isolated := searchedNegative(&unbound)
	isolated.Reachable.DerivedBy.Rooting = domain.RootingIsolated
	moduleLevel := searchedNegative(&unbound)
	moduleLevel.Reachable.DerivedBy.Fidelity = string(domain.ScanModeModule)
	inferred := searchedNegative(&domain.NegativeSearch{NotSearched: "no graph"})

	for _, tt := range []struct {
		name string
		f    domain.VulnerabilityFinding
		want bool
	}{
		{"local-rooted, unknown lookup", searchedNegative(&unbound), true},
		{"local-rooted, disputed", searchedNegative(&disputed), true},
		{"isolated frame", isolated, false},
		{"module-level TinyGo answer", moduleLevel, false},
		{"inferred", inferred, false},
	} {
		if got := domain.LocalProbeSettles(tt.f); got != tt.want {
			rung, reason := domain.NegativeSoundness(tt.f)
			t.Errorf("%s: LocalProbeSettles = %v, want %v (rung %s: %s)", tt.name, got, tt.want, rung, reason)
		}
	}
}

// TestTinyGoSite_ReturnsNoMethodAndHoldsNoRung: under TinyGo's reflect a reached
// lookup binds nothing, says why, and a clean search past it confirms whether
// or not its names were known.
func TestTinyGoSite_ReturnsNoMethodAndHoldsNoRung(t *testing.T) {
	t.Parallel()

	want := "TinyGo's reflect panics on a method lookup, so it returns no method and nothing was bound"
	for _, site := range []domain.ReflectiveDispatchSite{
		{Caller: "m.main", Callee: "reflect.(Value).MethodByName", ReachableFromEntryPoint: true, ReturnsNoMethod: true},
		{Caller: "m.main", Callee: "reflect.(*rawType).MethodByName", ReachableFromEntryPoint: true, ReturnsNoMethod: true,
			LookupName: "Run", Bound: true, NameCount: 1},
	} {
		if got := site.Binding(); got != want {
			t.Errorf("Binding(%+v) = %q, want %q", site, got, want)
		}
		search := domain.NegativeSearch{EntryPointRoots: 1, Fidelity: "BUILT_WITH_BODIES",
			ReflectiveDispatch: []domain.ReflectiveDispatchSite{site}}
		rung, reason := domain.NegativeSoundness(searchedNegative(&search))
		if rung != domain.SoundnessConfirmed {
			t.Errorf("bound=%v: rung = %s (%s), want %s", site.Bound, rung, reason, domain.SoundnessConfirmed)
		}
		if !strings.Contains(reason, site.Callee+" ("+want+")") {
			t.Errorf("bound=%v: the reason does not name the TinyGo site: %s", site.Bound, reason)
		}
	}
	unreached := domain.ReflectiveDispatchSite{ReturnsNoMethod: true}
	if got := unreached.Binding(); got != "not reached, so nothing bound" {
		t.Errorf("an unreached TinyGo site's binding = %q", got)
	}
}

// TestTinyGoReflectReturnsNoMethod_ComparesTheVersion: 0.44.x and older return
// no method; a newer release, and an unrecorded or unparseable one, do not.
func TestTinyGoReflectReturnsNoMethod_ComparesTheVersion(t *testing.T) {
	t.Parallel()

	for version, want := range map[string]bool{
		"0.40.0": true, "0.44.0": true, "0.44.9": true, "0.44.1-dev": true,
		"0.45.0": false, "0.100.0": false, "1.0.0": false, "": false, "dev": false,
	} {
		if got := domain.TinyGoReflectReturnsNoMethod(version); got != want {
			t.Errorf("TinyGoReflectReturnsNoMethod(%q) = %v, want %v", version, got, want)
		}
	}
}
