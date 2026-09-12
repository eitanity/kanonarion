package domain_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// TestDispatchKindOfEdge_ReadsTheEdgeAndNeverGuesses pins the one mapping from
// an edge's own fields to a dispatch kind.
//
// The cases that matter are the ones that could fall into "direct" by accident:
// an unresolved edge, a reflect edge (which carries an unresolved confidence, so
// only its own flag distinguishes it), a reference edge (which is not a call at
// all), and a confidence string this build has never seen. None of them is a
// direct call and none of them may be reported as one.
func TestDispatchKindOfEdge_ReadsTheEdgeAndNeverGuesses(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		confidence string
		reflect    bool
		reference  bool
		want       domain.DispatchKind
	}{
		{"direct", "Direct", false, false, domain.DispatchDirect},
		{"cha over-approximated interface dispatch", "CHA-overapprox", false, false, domain.DispatchInterface},
		{"vta-refined interface dispatch", "VTA", false, false, domain.DispatchInterface},
		{"framework-bound", "Framework", false, false, domain.DispatchFramework},
		{"unresolved", "Unknown", false, false, domain.DispatchUnresolved},
		{"reflect edges carry an unresolved confidence", "Unknown", true, false, domain.DispatchReflect},
		{"a reflect edge is reflect whatever its confidence says", "Direct", true, false, domain.DispatchReflect},
		{"a reference is never a call", "Direct", false, true, domain.DispatchReference},
		{"a reference wins over reflect", "Unknown", true, true, domain.DispatchReference},
		{"a confidence this build does not know is unresolved", "SomeFutureTier", false, false, domain.DispatchUnresolved},
		{"an edge with no confidence at all is unresolved", "", false, false, domain.DispatchUnresolved},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := domain.DispatchKindOfEdge(tc.confidence, tc.reflect, tc.reference)
			if got != tc.want {
				t.Errorf("DispatchKindOfEdge(%q, reflect=%t, reference=%t) = %q, want %q",
					tc.confidence, tc.reflect, tc.reference, got, tc.want)
			}
			if got == domain.DispatchDirect && tc.want != domain.DispatchDirect {
				t.Errorf("an edge that is not a direct call was reported as one")
			}
		})
	}
}

// TestDispatchKind_IsAnnotated separates the kinds that state a measurement from
// the three that state an absence. The route-entry kind is the one most likely
// to be counted as annotated by mistake: it is a positive value, but what it
// says is that there was no edge to read.
func TestDispatchKind_IsAnnotated(t *testing.T) {
	t.Parallel()

	annotated := []domain.DispatchKind{
		domain.DispatchDirect, domain.DispatchInterface, domain.DispatchReflect,
		domain.DispatchFramework, domain.DispatchUnresolved, domain.DispatchReference,
	}
	for _, kind := range annotated {
		if !kind.IsAnnotated() {
			t.Errorf("%q states a measured edge and is not counted as annotated", kind)
		}
	}
	for _, kind := range []domain.DispatchKind{
		domain.DispatchUnrecorded, domain.DispatchRouteEntry, domain.DispatchNotAnnotated,
		domain.DispatchKind("something else"),
	} {
		if kind.IsAnnotated() {
			t.Errorf("%q states no measured edge and is counted as annotated", kind)
		}
	}
}

// TestDispatchKind_StringNamesTheAbsences checks that neither absence renders as
// an empty field, which a reader would have to interpret.
func TestDispatchKind_StringNamesTheAbsences(t *testing.T) {
	t.Parallel()

	if got := domain.DispatchUnrecorded.String(); got != "not recorded" {
		t.Errorf("DispatchUnrecorded.String() = %q", got)
	}
	if got := domain.DispatchNotAnnotated.String(); got != "not annotated" {
		t.Errorf("DispatchNotAnnotated.String() = %q", got)
	}
	if got := domain.DispatchDirect.String(); got != "direct" {
		t.Errorf("DispatchDirect.String() = %q", got)
	}
}

// TestHopDispatch_StringStatesTheBasis checks the rendering carries the kind and
// what it rests on, and that an empty annotation says so rather than rendering
// as a blank.
func TestHopDispatch_StringStatesTheBasis(t *testing.T) {
	t.Parallel()

	if got := (domain.HopDispatch{}).String(); got != "dispatch not recorded" {
		t.Errorf("zero HopDispatch renders as %q", got)
	}
	if (domain.HopDispatch{}).IsRecorded() {
		t.Error("the zero HopDispatch reports itself as recorded")
	}

	full := domain.HopDispatch{
		Kind:                 domain.DispatchInterface,
		Confidence:           "CHA-overapprox",
		Graph:                "example.com/mod@v1.2.3",
		GraphCompleteness:    "BUILT_WITH_BODIES",
		CallSite:             "auto/uploader.go:167",
		Interface:            "example.com/mod/auto.StorageClient",
		ImplementationModule: "example.com/mod",
		Implementers:         4,
		ImplementersQuery:    "kanonarion implementers 'example.com/mod/auto.StorageClient'",
	}
	got := full.String()
	for _, want := range []string{
		"interface", "CHA-overapprox", "example.com/mod/auto.StorageClient",
		"4 implementer(s) recorded", "implementation from example.com/mod",
		"auto/uploader.go:167", "BUILT_WITH_BODIES",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("rendering %q omits %q", got, want)
		}
	}

	refusal := domain.HopDispatch{
		Kind:   domain.DispatchNotAnnotated,
		Graph:  "stdlib@v1.26.5",
		Reason: "no call graph is held for stdlib@v1.26.5",
	}
	if got := refusal.String(); !strings.Contains(got, "not annotated") || !strings.Contains(got, "no call graph is held") {
		t.Errorf("a refusal renders as %q, which does not say it is a refusal with a reason", got)
	}
	if strings.Contains(refusal.String(), "direct") {
		t.Errorf("a refusal renders as %q, which mentions a direct call", refusal.String())
	}
}

// TestHopDispatch_IsOmittedFromJSONWhenUnrecorded is the hash-transparency
// check. A frame carrying no annotation must serialise exactly as it did before
// the field existed, or every record already in the store stops verifying.
func TestHopDispatch_IsOmittedFromJSONWhenUnrecorded(t *testing.T) {
	t.Parallel()

	frame := domain.ReachabilityFrame{
		ModulePath:    "example.com/mod",
		ModuleVersion: "v1.2.3",
		Package:       "example.com/mod/pkg",
		Symbol:        "Do",
	}
	raw, err := json.Marshal(frame)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	const want = `{"module_path":"example.com/mod","module_version":"v1.2.3","package":"example.com/mod/pkg","symbol":"Do"}`
	if string(raw) != want {
		t.Errorf("an unannotated frame serialises as\n%s\nwant\n%s", raw, want)
	}

	frame.Dispatch = domain.HopDispatch{Kind: domain.DispatchDirect, Confidence: "Direct"}
	raw, err = json.Marshal(frame)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"dispatch":{"kind":"direct","confidence":"Direct"}`) {
		t.Errorf("an annotated frame serialises as %s", raw)
	}
}

// TestReachabilityFrame_NodeID pins the call-graph node-ID form a hop is matched
// against, including the two shapes that yield no id at all.
func TestReachabilityFrame_NodeID(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		frame domain.ReachabilityFrame
		want  string
	}{
		{
			name:  "free function",
			frame: domain.ReachabilityFrame{Package: "example.com/mod/pkg", Symbol: "Do"},
			want:  "example.com/mod/pkg.Do",
		},
		{
			name:  "method keeps its receiver in parentheses",
			frame: domain.ReachabilityFrame{Package: "example.com/mod/pkg", Receiver: "*Client", Symbol: "Get"},
			want:  "example.com/mod/pkg.(*Client).Get",
		},
		{
			name:  "no package is no identity",
			frame: domain.ReachabilityFrame{Symbol: "Do"},
			want:  "",
		},
		{
			name:  "no symbol is no identity",
			frame: domain.ReachabilityFrame{Package: "example.com/mod/pkg"},
			want:  "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.frame.NodeID(); got != tc.want {
				t.Errorf("NodeID() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestAnnotateRouteEntries_StampsTheFirstHopOnly checks that the route's entry
// point is stated rather than left to fall into the unannotated bucket, that
// nothing else on the route is touched, and that an annotation already present
// is never overwritten.
func TestAnnotateRouteEntries_StampsTheFirstHopOnly(t *testing.T) {
	t.Parallel()

	routes := []domain.ReachabilityRoute{
		{
			{Package: "example.com/mod/a", Symbol: "Entry"},
			{Package: "example.com/mod/b", Symbol: "Next"},
		},
		{},
		{
			{Package: "example.com/mod/c", Symbol: "Already", Dispatch: domain.HopDispatch{Kind: domain.DispatchDirect}},
		},
	}
	if got := domain.AnnotateRouteEntries(routes); got != 1 {
		t.Errorf("AnnotateRouteEntries stamped %d hops, want 1", got)
	}
	if routes[0][0].Dispatch.Kind != domain.DispatchRouteEntry {
		t.Errorf("the first hop is %q, want the route-entry kind", routes[0][0].Dispatch.Kind)
	}
	if routes[0][0].Dispatch.Reason == "" {
		t.Error("the route-entry annotation states no reason")
	}
	if routes[0][1].Dispatch.IsRecorded() {
		t.Error("a hop that is not the route's first was stamped")
	}
	if routes[2][0].Dispatch.Kind != domain.DispatchDirect {
		t.Error("an annotation already on the first hop was overwritten")
	}
}

// TestTallyDispatch_DecomposesEveryHop is the acceptance figure's arithmetic:
// the annotated count, the total, and the per-kind split that makes the two
// reconcilable.
func TestTallyDispatch_DecomposesEveryHop(t *testing.T) {
	t.Parallel()

	routes := []domain.ReachabilityRoute{
		{
			{Symbol: "a", Dispatch: domain.HopDispatch{Kind: domain.DispatchRouteEntry}},
			{Symbol: "b", Dispatch: domain.HopDispatch{Kind: domain.DispatchDirect}},
			{Symbol: "c", Dispatch: domain.HopDispatch{Kind: domain.DispatchInterface}},
			{Symbol: "d", Dispatch: domain.HopDispatch{Kind: domain.DispatchNotAnnotated}},
			{Symbol: "e"},
		},
	}
	tally := domain.TallyDispatch(routes)
	if tally.Hops != 5 {
		t.Errorf("Hops = %d, want 5", tally.Hops)
	}
	if got := tally.Annotated(); got != 2 {
		t.Errorf("Annotated() = %d, want 2 — only the direct and interface hops state a measured edge", got)
	}
	if tally.ByKind[domain.DispatchUnrecorded] != 1 {
		t.Errorf("a hop carrying nothing was not counted as unrecorded: %v", tally.ByKind)
	}
	line := tally.String()
	for _, want := range []string{"2 of 5 hops annotated", "direct 1", "interface 1", "not annotated 1", "not recorded 1"} {
		if !strings.Contains(line, want) {
			t.Errorf("tally renders as %q, which omits %q", line, want)
		}
	}

	empty := domain.TallyDispatch(nil)
	if empty.Hops != 0 || empty.Annotated() != 0 {
		t.Errorf("an empty tally reports %d hops and %d annotated", empty.Hops, empty.Annotated())
	}
	if got := empty.String(); got != "0 of 0 hops annotated" {
		t.Errorf("an empty tally renders as %q", got)
	}
}
