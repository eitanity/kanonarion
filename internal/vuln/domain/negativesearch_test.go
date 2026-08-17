package domain_test

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// searchedNegative is a negative recorded from govulncheck's silence — the only
// kind the read-time search speaks to — with a search result attached.
func searchedNegative(search *domain.NegativeSearch) domain.VulnerabilityFinding {
	return domain.VulnerabilityFinding{
		ID:              "GO-0000-0000",
		AffectedSymbols: []string{"Vulnerable"},
		Reachable: &domain.ReachabilityResult{
			IsReachable: false,
			Confidence:  domain.ConfidenceHigh,
			DerivedBy: domain.ReachabilityDerivation{
				Analyser: domain.AnalyserGovulncheck,
				Fidelity: string(domain.ScanModeSource),
				Rooting:  domain.Rooting("target-rooted:example.com/mod@local"),
			},
		},
		NegativeSearch: search,
	}
}

// TestSearchedNegativeConfirmsAtBuiltWithBodies is the whole point of the read-time
// search: a negative stamped from silence, which rule 4 refuses to confirm, is
// confirmed once a search over a graph built with bodies has run over it and
// come back empty. Nothing in the record changed to make that true.
func TestSearchedNegativeConfirmsAtBuiltWithBodies(t *testing.T) {
	f := searchedNegative(&domain.NegativeSearch{Fidelity: "BUILT_WITH_BODIES"})

	got, reason := domain.NegativeSoundness(f)

	if got != domain.SoundnessConfirmed {
		t.Errorf("a clean search over a BUILT_WITH_BODIES graph -> %s, want %s", got, domain.SoundnessConfirmed)
	}
	if !strings.Contains(reason, "call-graph search") {
		t.Errorf("the reason does not name the search: %q", reason)
	}
	// Rule 4 is untouched: the same finding without the search still reads the
	// silence it was stamped from.
	f.NegativeSearch = nil
	if got, _ := domain.NegativeSoundness(f); got != domain.SoundnessInferred {
		t.Errorf("without a search -> %s, want %s", got, domain.SoundnessInferred)
	}
}

// TestSearchedNegativeBelowBodiesIsUnconfirmed pins the ladder's existing rung
// under the search: a graph with unbuilt bodies cannot support a negative, so a
// search over one states what it searched rather than confirming.
func TestSearchedNegativeBelowBodiesIsUnconfirmed(t *testing.T) {
	for _, fidelity := range []string{"METADATA_ONLY", "TYPE_ONLY"} {
		got, reason := domain.NegativeSoundness(searchedNegative(&domain.NegativeSearch{Fidelity: fidelity}))
		if got != domain.SoundnessUnconfirmed {
			t.Errorf("a search over a %s graph -> %s, want %s", fidelity, got, domain.SoundnessUnconfirmed)
		}
		if !strings.Contains(reason, fidelity) {
			t.Errorf("the reason for a %s graph does not name it: %q", fidelity, reason)
		}
	}
}

// TestFoundPathInTheRecordedFrameIsDisputed is the disagreement case. The stored
// verdict is a measurement and is not overwritten; the search is a measurement
// and is not suppressed; the rung is what tells the reader the two disagree.
func TestFoundPathInTheRecordedFrameIsDisputed(t *testing.T) {
	f := searchedNegative(&domain.NegativeSearch{
		Fidelity:        "BUILT_WITH_BODIES",
		PathFound:       true,
		InRecordedFrame: true,
		Route: domain.ReachabilityRoute{
			{ModulePath: "example.com/mod", Package: "example.com/mod/api", Symbol: "Serve"},
			{ModulePath: "example.com/mod", Package: "example.com/mod/api", Symbol: "Vulnerable"},
		},
	})

	got, reason := domain.NegativeSoundness(f)

	if got != domain.SoundnessDisputed {
		t.Errorf("a path found in the record's own frame -> %s, want %s", got, domain.SoundnessDisputed)
	}
	for _, want := range []string{"govulncheck", "BUILT_WITH_BODIES", "Vulnerable", "NOT confirmed"} {
		if !strings.Contains(reason, want) {
			t.Errorf("the reason does not mention %q: %q", want, reason)
		}
	}
	// The recorded verdict is untouched. A tool that flipped it would be
	// overwriting one analyser's measurement with another's.
	if f.Reachable.IsReachable {
		t.Error("the stored verdict was flipped by the search")
	}
}

// TestFoundPathOutsideTheRecordedFrameIsStatedNotDisputed guards the asymmetry.
// A path inside a dependency's own graph does not contradict a negative measured
// in a consumer's build — a different question — so the recorded rung stands. It
// is still reported: a route found and hidden is the one thing this must not do.
func TestFoundPathOutsideTheRecordedFrameIsStatedNotDisputed(t *testing.T) {
	got, reason := domain.NegativeSoundness(searchedNegative(&domain.NegativeSearch{
		Fidelity:        "BUILT_WITH_BODIES",
		PathFound:       true,
		InRecordedFrame: false,
		Route:           domain.ReachabilityRoute{{Symbol: "Vulnerable"}},
	}))

	if got != domain.SoundnessInferred {
		t.Errorf("a path found outside the record's frame -> %s, want %s", got, domain.SoundnessInferred)
	}
	if !strings.Contains(reason, "different question") {
		t.Errorf("the reason does not state the frame difference: %q", reason)
	}
}

// TestUnsearchableIsCheckedBeforeTheSearch keeps the floor where it was: an
// advisory that names no symbols reads unsearchable whatever a search says,
// because there was never a symbol for one to look for.
func TestUnsearchableIsCheckedBeforeTheSearch(t *testing.T) {
	f := searchedNegative(&domain.NegativeSearch{Fidelity: "BUILT_WITH_BODIES"})
	f.AffectedSymbols = nil
	f.AdvisoryNamesNoSymbols = true

	if got, _ := domain.NegativeSoundness(f); got != domain.SoundnessUnsearchable {
		t.Errorf("an advisory naming no symbols -> %s, want %s", got, domain.SoundnessUnsearchable)
	}
}

// TestNegativeSearchIsNotSerialised pins that a search never changes a record's
// bytes. It is what lets every stored negative be reclassified with no pipeline
// generation and no re-scan, and what keeps a content hash verifiable after a
// read has run.
func TestNegativeSearchIsNotSerialised(t *testing.T) {
	hasher := domain.VulnerabilityRecordHasher{}
	rec := domain.VulnerabilityRecord{
		Ecosystem: "go",
		Findings:  []domain.VulnerabilityFinding{searchedNegative(nil)},
	}
	sealed, err := hasher.SetContentHash(rec)
	if err != nil {
		t.Fatalf("sealing: %v", err)
	}
	sealed.Findings[0].NegativeSearch = &domain.NegativeSearch{Fidelity: "BUILT_WITH_BODIES", PathFound: true}
	if err := hasher.VerifyContentHash(sealed); err != nil {
		t.Errorf("a searched record no longer verifies: %v", err)
	}
}

// TestRouteStringElidesTheMiddle pins that a long route keeps both ends. The two
// hops a reader checks are where a path starts and what it reaches.
func TestRouteStringElidesTheMiddle(t *testing.T) {
	route := make(domain.ReachabilityRoute, 0, 9)
	for _, sym := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "target"} {
		route = append(route, domain.ReachabilityFrame{Symbol: sym})
	}
	got := route.String()
	if !strings.HasPrefix(got, "a -> b") || !strings.HasSuffix(got, "-> target") {
		t.Errorf("route rendering lost an end: %q", got)
	}
	if !strings.Contains(got, "more)") {
		t.Errorf("route rendering does not say how much it elided: %q", got)
	}
}
