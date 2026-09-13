package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

// TestHopDispatchLine_NeverRendersAnAbsenceAsADirectCall is the rendering half
// of the ticket's named failure. The annotation can be right in the record and
// still reach a reader as a direct call if a surface prints nothing for the
// absences, so every one of them is asserted to say something here.
func TestHopDispatchLine_NeverRendersAnAbsenceAsADirectCall(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		dispatch vuldomain.HopDispatch
		want     string
	}{
		{
			name:     "a hop stored before the annotation existed",
			dispatch: vuldomain.HopDispatch{},
			want:     "not recorded",
		},
		{
			name:     "the route's first hop",
			dispatch: vuldomain.HopDispatch{Kind: vuldomain.DispatchRouteEntry},
			want:     "entry point",
		},
		{
			name: "a hop no graph could corroborate",
			dispatch: vuldomain.HopDispatch{
				Kind:   vuldomain.DispatchNotAnnotated,
				Reason: "no call graph is held for stdlib@v1.26.5",
			},
			want: "not annotated",
		},
		{
			name:     "an unresolved edge",
			dispatch: vuldomain.HopDispatch{Kind: vuldomain.DispatchUnresolved, Confidence: "Unknown"},
			want:     "unresolved",
		},
		{
			name:     "a reference is not a call",
			dispatch: vuldomain.HopDispatch{Kind: vuldomain.DispatchReference, Confidence: "Direct"},
			want:     "reference",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := hopDispatchLine(tc.dispatch)
			if got == "" {
				t.Fatal("renders nothing, which a reader cannot tell from a hop nobody looked at")
			}
			if !strings.Contains(got, tc.want) {
				t.Errorf("renders %q, which does not say %q", got, tc.want)
			}
			// The kind leads the line, so a rendering that ASSERTS a direct call
			// starts with one. The phrase appearing later is a denial — "it is not a
			// direct call" — and denying it is the point.
			if strings.HasPrefix(got, "direct") && tc.dispatch.Kind != vuldomain.DispatchDirect {
				t.Errorf("renders %q, which asserts a direct call", got)
			}
		})
	}
}

// TestPrintRoute_SaysWhenNoHopStatesItsDispatch pins the rendering of a route
// stored before the annotation existed. Printing the hops unchanged is exactly
// the reading the ticket calls misleading, so the route says once, at the top,
// that none of its hops is a direct call unless a re-scan says so.
func TestPrintRoute_SaysWhenNoHopStatesItsDispatch(t *testing.T) {
	t.Parallel()

	res := vulnReachabilityQuery{Routes: []reachabilityRouteOutput{{
		Versioned: true,
		Frames: []reachabilityFrameOutput{
			{Module: "example.com/app", Package: "example.com/app", Symbol: "main"},
			{Module: "example.com/mod", Version: "v1.2.0", Package: "example.com/mod", Symbol: "Parse"},
		},
	}}}
	var out bytes.Buffer
	printRoute(&out, res)
	got := out.String()
	if !strings.Contains(got, "no hop on this route says how control reached it") {
		t.Errorf("an unannotated route renders as\n%s\nwith no statement that it says nothing about dispatch", got)
	}
	if strings.Contains(got, "reached by:") {
		t.Errorf("an unannotated route renders a per-hop dispatch line:\n%s", got)
	}
}

// TestPrintRoute_StatesEveryHopWhenAnyHopSpeaks checks the other rendering: once
// one hop states a dispatch, the silence of another hop is a measurement about
// THAT hop and has to be printed beside it.
func TestPrintRoute_StatesEveryHopWhenAnyHopSpeaks(t *testing.T) {
	t.Parallel()

	res := vulnReachabilityQuery{Routes: []reachabilityRouteOutput{{
		Versioned: true,
		Frames: []reachabilityFrameOutput{
			{
				Module: "example.com/app", Package: "example.com/app", Symbol: "main",
				Dispatch: vuldomain.HopDispatch{Kind: vuldomain.DispatchRouteEntry},
			},
			{Module: "example.com/mod", Version: "v1.2.0", Package: "example.com/mod", Symbol: "Parse"},
		},
	}}}
	var out bytes.Buffer
	printRoute(&out, res)
	got := out.String()
	if strings.Count(got, "reached by:") != 2 {
		t.Errorf("an annotated route renders %d dispatch lines over 2 hops:\n%s", strings.Count(got, "reached by:"), got)
	}
	if !strings.Contains(got, "not recorded") {
		t.Errorf("a silent hop beside an annotated one renders as\n%s\nwithout saying it states nothing", got)
	}
}

// TestScanRouteJSONOf_CarriesTheDispatch pins the scan-diff JSON surface. A diff
// is read by the consumer least able to go and look, and a route whose hops are
// all direct calls is a different answer from one whose middle hop is an
// interface dispatch.
func TestScanRouteJSONOf_CarriesTheDispatch(t *testing.T) {
	t.Parallel()

	route := vuldomain.ReachabilityRoute{
		{ModulePath: "example.com/app", Package: "example.com/app", Symbol: "main"},
		{
			ModulePath: "example.com/mod", ModuleVersion: "v1.2.0", Package: "example.com/mod", Symbol: "Parse",
			Dispatch: vuldomain.HopDispatch{
				Kind:       vuldomain.DispatchInterface,
				Confidence: "CHA-overapprox",
				Interface:  "example.com/mod.Parser",
			},
		},
	}
	raw, err := json.Marshal(scanRouteJSONOf(route))
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	body := string(raw)
	if !strings.Contains(body, `"dispatch":{"kind":"interface"`) {
		t.Errorf("the diff's route renders as %s, with no dispatch on the annotated hop", body)
	}
	if strings.Count(body, `"dispatch"`) != 1 {
		t.Errorf("the diff's route renders %d dispatch objects over one annotated hop: %s",
			strings.Count(body, `"dispatch"`), body)
	}
	if scanRouteJSONOf(nil) != nil {
		t.Error("a nil route renders as an empty one")
	}
}

// reflectHop builds a hop the way a scan builds one: the kind comes from the
// call graph's own mapping, never hand-stamped. That is what makes the
// assertions below bite. Hand-writing DispatchReflect would render the same
// line whatever the mapping decided, and the test would pass against the
// defect it exists to pin.
//
// Both edges carry the reflect_dispatch attribute and the same Unknown
// confidence, because the attribute marks any callee in package reflect. Only
// the callee tells them apart.
func reflectHop(calleeID string) vuldomain.HopDispatch {
	return vuldomain.HopDispatch{
		Kind:       vuldomain.DispatchKindOfEdge(calleeID, "Unknown", true, false),
		Confidence: "Unknown",
		Graph:      "example.com/mod@v1.2.0",
		CallSite:   "pkg/expr/gval.go:42",
	}
}

// TestHopDispatchLine_ReflectOnlyWhereTheCalleeCanDispatch is the text half of
// the named failure, on the renderer a report actually prints through.
//
// A call into package reflect is not by itself a reflective dispatch.
// reflect.(Value).MethodByName picks what runs from a string at run time, so
// the analysis cannot bound it. reflect.TypeOf has exactly one callee. A reader
// must be able to tell those two lines apart.
func TestHopDispatchLine_ReflectOnlyWhereTheCalleeCanDispatch(t *testing.T) {
	t.Parallel()

	dispatching := hopDispatchLine(reflectHop("reflect.(Value).MethodByName"))
	bounded := hopDispatchLine(reflectHop("reflect.TypeOf"))

	if dispatching == bounded {
		t.Fatalf("a call that reflection steers and a call that bounds perfectly render the same line: %q", dispatching)
	}
	if !strings.HasPrefix(dispatching, "reflect") {
		t.Errorf("the hop into reflect.(Value).MethodByName renders as %q, which does not lead with the reflect kind", dispatching)
	}
	if strings.Contains(bounded, "reflect") {
		t.Errorf("the hop into reflect.TypeOf renders as %q, which calls it reflection; it has one callee and bounds perfectly", bounded)
	}
	if !strings.HasPrefix(bounded, "unresolved") {
		t.Errorf("the hop into reflect.TypeOf renders as %q, want the unresolved kind — its edge confidence is Unknown", bounded)
	}
	// Neither may fall into one of the two absence branches: both hops WERE read
	// off an edge, and both state a measured kind.
	for _, line := range []string{dispatching, bounded} {
		if strings.Contains(line, "not recorded") || strings.Contains(line, "entry point") {
			t.Errorf("a hop read off an edge renders as %q, which states an absence", line)
		}
	}
}

// TestPrintRoute_RendersAReflectHopAndABoundedOneDifferently walks the same two
// hops through printRoute, the reachability command's own printer, so the
// assertion covers the line a reader sees and not only the helper behind it.
func TestPrintRoute_RendersAReflectHopAndABoundedOneDifferently(t *testing.T) {
	t.Parallel()

	res := vulnReachabilityQuery{Routes: []reachabilityRouteOutput{{
		Versioned: true,
		Frames: []reachabilityFrameOutput{
			{
				Module: "example.com/mod", Version: "v1.2.0", Package: "example.com/mod/expr", Symbol: "gvalFunc",
				Dispatch: reflectHop("reflect.(Value).MethodByName"),
			},
			{
				Module: "example.com/mod", Version: "v1.2.0", Package: "example.com/mod/opts", Symbol: "fill",
				Dispatch: reflectHop("reflect.TypeOf"),
			},
		},
	}}}
	var out bytes.Buffer
	printRoute(&out, res)
	got := out.String()

	if strings.Count(got, "reached by:") != 2 {
		t.Fatalf("printRoute renders %d dispatch lines over 2 hops:\n%s", strings.Count(got, "reached by:"), got)
	}
	if strings.Count(got, "reflect") != 1 {
		t.Errorf("printRoute names reflection %d times over one dispatching hop and one bounded one:\n%s",
			strings.Count(got, "reflect"), got)
	}
	if !strings.Contains(got, "reached by: unresolved") {
		t.Errorf("printRoute does not report the hop into reflect.TypeOf as unresolved:\n%s", got)
	}
}

// TestPrintFindingLines_RendersAReflectHopAndABoundedOneDifferently is the
// second call site of the same renderer, measured rather than assumed to be
// covered by the first.
func TestPrintFindingLines_RendersAReflectHopAndABoundedOneDifferently(t *testing.T) {
	t.Parallel()

	rec := vuldomain.VulnerabilityRecord{
		Findings: []vuldomain.VulnerabilityFinding{{
			ID: "GO-2026-5026",
			Reachable: &vuldomain.ReachabilityResult{
				IsReachable: true,
				Confidence:  vuldomain.ConfidenceHigh,
				Routes: []vuldomain.ReachabilityRoute{{
					{
						ModulePath: "example.com/mod", ModuleVersion: "v1.2.0",
						Package: "example.com/mod/expr", Symbol: "gvalFunc",
						Dispatch: reflectHop("reflect.(Value).MethodByName"),
					},
					{
						ModulePath: "example.com/mod", ModuleVersion: "v1.2.0",
						Package: "example.com/mod/opts", Symbol: "fill",
						Dispatch: reflectHop("reflect.TypeOf"),
					},
				}},
			},
		}},
	}
	var out bytes.Buffer
	printFindingLines(&out, rec, func(vuldomain.ReachabilityRoute) vuldomain.RouteRoot {
		return vuldomain.RouteRoot{}
	})
	got := out.String()

	if strings.Count(got, "reached by:") != 2 {
		t.Fatalf("printFindingLines renders %d dispatch lines over 2 hops:\n%s", strings.Count(got, "reached by:"), got)
	}
	if strings.Count(got, "reflect") != 1 {
		t.Errorf("printFindingLines names reflection %d times over one dispatching hop and one bounded one:\n%s",
			strings.Count(got, "reflect"), got)
	}
	if !strings.Contains(got, "reached by: unresolved") {
		t.Errorf("printFindingLines does not report the hop into reflect.TypeOf as unresolved:\n%s", got)
	}
}
