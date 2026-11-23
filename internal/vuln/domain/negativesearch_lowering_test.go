package domain_test

import (
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/vuln/domain"
)

// A search over a graph without TinyGo's compiler-inserted calls neither
// confirms nor disputes a negative, found route or not, and says why.
func TestLoweringGapHoldsTheNegativeUnconfirmed(t *testing.T) {
	route := domain.ReachabilityRoute{{ModulePath: "example.com/mod", Package: "example.com/mod", Symbol: "Vulnerable"}}
	for _, tc := range []struct {
		name   string
		search domain.NegativeSearch
		says   string
	}{
		{"clean", domain.NegativeSearch{EntryPointRoots: 3, Fidelity: "BUILT_WITH_BODIES"}, "found no path"},
		{"path in frame", domain.NegativeSearch{EntryPointRoots: 3, Fidelity: "BUILT_WITH_BODIES", InRecordedFrame: true,
			PathFound: true, Route: route}, "found the route " + route.String()},
	} {
		s := tc.search
		s.LoweringGap = "example.com/mod@local: TinyGo 0.45.0 ran"
		got, reason := domain.NegativeSoundness(searchedNegative(&s))
		if got != domain.SoundnessUnconfirmed || !strings.Contains(reason, "holds none of the calls TinyGo's compiler inserts (example.com/mod@local: TinyGo 0.45.0 ran)") ||
			!strings.Contains(reason, tc.says) {
			t.Errorf("%s: %s %q", tc.name, got, reason)
		}
	}
}
