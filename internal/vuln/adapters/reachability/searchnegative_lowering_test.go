package reachability_test

import (
	"context"
	"strings"
	"testing"

	callgraphdomain "code.eitanity.com/kanonarion/internal/callgraph/domain"

	"code.eitanity.com/kanonarion/internal/vuln/adapters/reachability"
	"code.eitanity.com/kanonarion/internal/vuln/domain"
)

// A record without TinyGo's compiler-inserted calls is projected with the gap,
// and a clean search over it does not confirm the negative; the same record
// without the gap confirms, as before.
func TestSearchNegative_ALoweringGapHoldsTheNegativeUnconfirmed(t *testing.T) {
	load := func(detail string) domain.VulnerabilityFinding {
		rec := callgraphdomain.CallGraphRecord{
			Coordinate:   loaderCoord,
			Completeness: callgraphdomain.CompletenessBuiltWithBodies, ArtifactKind: callgraphdomain.ArtifactLibrary, PipelineVersion: "p1",
			OverallStatus: callgraphdomain.CallGraphStatusPartial, FailureDetail: detail,
			Nodes: []callgraphdomain.CallNode{
				{ID: "entry", Module: searchedModule, Package: searchedModule, Symbol: "Serve", IsExportedAPI: true},
				{ID: "vuln", Module: searchedModule, Package: searchedModule, Symbol: "vulnerable"},
			},
		}
		proj, err := reachability.NewCallGraphStoreLoader(&fakeStore{record: rec, found: true}, "p1").Load(context.Background(), loaderCoord)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		return searchOver(t, proj)
	}
	gap := callgraphdomain.TinyGoLoweringGap{Found: "0.45.0", Covered: []string{"0.44.0"}}.Clause()
	f := load(gap)
	if got, reason := domain.NegativeSoundness(f); got != domain.SoundnessUnconfirmed ||
		!strings.Contains(reason, loaderCoord.String()+": TinyGo 0.45.0 ran") {
		t.Errorf("over the gap: %s (%s), want unconfirmed naming the record and the release", got, reason)
	}
	if got, reason := domain.NegativeSoundness(load("")); got != domain.SoundnessConfirmed {
		t.Errorf("without the gap: %s (%s), want confirmed", got, reason)
	}
}
