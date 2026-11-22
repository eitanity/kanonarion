package domain

import (
	"strings"
	"testing"

	cgdomain "code.eitanity.com/kanonarion/internal/callgraph/domain"
)

// A graph the analysing binary could not read is caveated with that reason and,
// while it binds this binary, the build that lifts it.
func TestAnalyseAnalyserLimitIsCaveatedWithTheReason(t *testing.T) {
	restore := cgdomain.SetAnalysingGo("go1.26.6")
	defer restore()
	rec := cgdomain.CallGraphRecord{
		OverallStatus: cgdomain.CallGraphStatusPartial,
		FailureDetail: "main.go:1:1: package requires newer Go version go1.27 (application built with go1.26)",
	}
	got := Analyse(rec, nil, cgdomain.RootScopeProduction).Caveat
	for _, want := range []string{"built with go1.26 and the code requires go1.27", "lower bound", "kanonarion built with go1.27 or newer"} {
		if !strings.Contains(got, want) {
			t.Errorf("caveat lacks %q: %s", want, got)
		}
	}
}

// A TinyGo record without its compiler's inserted calls is caveated with the
// release and what closes it.
func TestAnalyseLoweringGapIsCaveatedWithTheRelease(t *testing.T) {
	rec := cgdomain.CallGraphRecord{
		OverallStatus: cgdomain.CallGraphStatusPartial,
		FailureDetail: cgdomain.TinyGoLoweringGap{Found: "0.45.0", Covered: []string{"0.44.0"}}.Clause(),
	}
	got := Analyse(rec, nil, cgdomain.RootScopeProduction).Caveat
	for _, want := range []string{"holds none of the calls TinyGo's compiler inserts (TinyGo 0.45.0 ran", "lower bound", "lowering table covers TinyGo 0.45.0"} {
		if !strings.Contains(got, want) {
			t.Errorf("caveat lacks %q: %s", want, got)
		}
	}
}
