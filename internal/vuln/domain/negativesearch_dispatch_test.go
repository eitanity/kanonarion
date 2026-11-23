package domain_test

import (
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/vuln/domain"
)

// A route found only from a method a dependency could call holds a clean search
// at unconfirmed, in the recorded frame or out of it, and never disputes: the
// hand-off may never run. The reason names the method, the hand-off and the
// route.
func TestDispatchRouteHoldsTheNegativeUnconfirmed(t *testing.T) {
	route := domain.ReachabilityRoute{
		{ModulePath: "example.com/mod", Package: "example.com/mod/api", Receiver: "*body", Symbol: "Read"},
		{ModulePath: "example.com/mod", Package: "example.com/mod/api", Symbol: "Vulnerable"},
	}
	for _, inFrame := range []bool{true, false} {
		got, reason := domain.NegativeSoundness(searchedNegative(&domain.NegativeSearch{
			EntryPointRoots: 3, Fidelity: "BUILT_WITH_BODIES", InRecordedFrame: inFrame,
			DispatchPathFound: true, DispatchRoute: route, DispatchDetail: "a dependency can call it through io.Reader",
		}))
		if got != domain.SoundnessUnconfirmed {
			t.Errorf("in frame %v -> %s, want %s", inFrame, got, domain.SoundnessUnconfirmed)
		}
		for _, want := range []string{route[0].String(), "(a dependency can call it through io.Reader)", " along " + route.String(), "no edge for"} {
			if !strings.Contains(reason, want) {
				t.Errorf("in frame %v the reason does not state %q: %q", inFrame, want, reason)
			}
		}
	}

	// A one-hop route names no "along", and a missing detail no parenthesis.
	_, reason := domain.NegativeSoundness(searchedNegative(&domain.NegativeSearch{
		EntryPointRoots: 3, Fidelity: "BUILT_WITH_BODIES", DispatchPathFound: true, DispatchRoute: route[:1],
	}))
	if strings.Contains(reason, " along ") || strings.Contains(reason, "it (") {
		t.Errorf("a one-hop route with no detail renders %q", reason)
	}
	_, reason = domain.NegativeSoundness(searchedNegative(&domain.NegativeSearch{
		EntryPointRoots: 3, Fidelity: "BUILT_WITH_BODIES", DispatchPathFound: true,
	}))
	if !strings.HasPrefix(reason, "the route's root is a method a dependency could call") {
		t.Errorf("a route-less search renders %q", reason)
	}
}
