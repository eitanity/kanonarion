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
