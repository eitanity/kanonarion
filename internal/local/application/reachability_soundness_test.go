package application

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/local/domain"
	"github.com/eitanity/kanonarion/internal/local/ports"
)

// The local probe publishes two kinds of negative and they are not the same
// claim. One it measured — the affected symbol is not in the symbol table of the
// binary this build links — and one it carried from a stored scan, which is an
// analyser's silence recorded somewhere else. Each states the rung its own
// instrument earns; neither borrows the other's.

// TestMeasuredAbsenceStatesItsOwnRung pins the rung a symbol-table absence
// earns. It is deliberately not "confirmed": no call graph was built, so this is
// an absence from the artefact and not a search that ran over call edges.
func TestMeasuredAbsenceStatesItsOwnRung(t *testing.T) {
	f := ports.VulnFinding{
		ID:              "GO-2025-0001",
		AffectedSymbols: []string{"Handshake"},
		// A stored rung is present and must NOT be the one reported: this verdict
		// was measured here, and republishing the stored scan's rung would state
		// the soundness of a search this answer did not come from.
		ReachableSoundness:       "inferred",
		ReachableSoundnessReason: "govulncheck said nothing",
	}
	got := probeOneFinding(f, "golang.org/x/crypto", domain.ProbeKindBinary, map[string]struct{}{}, nil)

	if got.Verdict != domain.SymbolProbeAbsent {
		t.Fatalf("verdict = %q, want the measured negative under test", got.Verdict)
	}
	if got.Soundness != domain.ProbeSoundnessUnconfirmed {
		t.Errorf("soundness = %q, want %q", got.Soundness, domain.ProbeSoundnessUnconfirmed)
	}
	if got.SoundnessReason != domain.ProbeAbsentReason {
		t.Errorf("reason = %q, want the symbol-table basis", got.SoundnessReason)
	}
	if strings.Contains(got.SoundnessReason, "govulncheck") {
		t.Error("a measured absence republished the stored scan's basis")
	}
}

// TestMeasuredAbsenceNamesIncompleteCoverage pins the two weaker forms of the
// same absence. A main that failed to build may still link the symbol, and a
// library workspace's harness ships nowhere — collapsing either into the plain
// reason would let the weakest evidence read as the strongest.
func TestMeasuredAbsenceNamesIncompleteCoverage(t *testing.T) {
	f := ports.VulnFinding{ID: "GO-2025-0001", AffectedSymbols: []string{"Handshake"}}

	partial := probeOneFinding(f, "golang.org/x/crypto", domain.ProbeKindBinary, map[string]struct{}{},
		[]ports.ProbedBinary{{ImportPath: "example.com/app/cmd/a"}, {ImportPath: "example.com/app/cmd/b", BuildError: "boom"}})
	if partial.SoundnessReason != domain.ProbeAbsentPartialReason {
		t.Errorf("a probe that lost a main reported %q, want the partial-coverage reason", partial.SoundnessReason)
	}

	library := probeOneFinding(f, "golang.org/x/crypto", domain.ProbeKindLibrary, map[string]struct{}{}, nil)
	if library.SoundnessReason != domain.ProbeAbsentLibraryReason {
		t.Errorf("a library probe reported %q, want the harness reason", library.SoundnessReason)
	}
}

// TestCarriedNegativeCarriesTheStoredRung pins the seeded negative. This verdict
// was not measured here at all, so the rung is the stored scan's own.
func TestCarriedNegativeCarriesTheStoredRung(t *testing.T) {
	no := false
	f := ports.VulnFinding{
		ID:                       "GO-2025-0002",
		Reachable:                &no,
		ReachableBasis:           "by govulncheck, fidelity source",
		ReachableSoundness:       "inferred",
		ReachableSoundnessReason: "govulncheck analysed this build from source and reported no route",
	}
	got := probeOneFinding(f, "golang.org/x/crypto", domain.ProbeKindSkipped, nil, nil)

	if got.Verdict != domain.SymbolProbeUnreachable {
		t.Fatalf("verdict = %q, want the carried negative under test", got.Verdict)
	}
	if got.Soundness != "inferred" {
		t.Errorf("soundness = %q, want the stored scan's rung", got.Soundness)
	}
	if !strings.Contains(got.SoundnessReason, "govulncheck") {
		t.Errorf("reason = %q, want the stored scan's basis", got.SoundnessReason)
	}
}

// TestPositiveAndUndeterminedStateNoRung pins the other side of the rule: a
// verdict with no absence to qualify must not invent one.
func TestPositiveAndUndeterminedStateNoRung(t *testing.T) {
	present := probeOneFinding(
		ports.VulnFinding{ID: "GO-2025-0003", AffectedSymbols: []string{"Dial"}},
		"golang.org/x/crypto", domain.ProbeKindBinary,
		map[string]struct{}{"golang.org/x/crypto/ssh.Dial": {}}, nil)
	if present.Verdict != domain.SymbolProbePresent {
		t.Fatalf("verdict = %q, want the positive under test", present.Verdict)
	}
	if present.Soundness != domain.ProbeSoundnessNotStated {
		t.Errorf("a positive carried soundness %q", present.Soundness)
	}

	unknown := probeOneFinding(
		ports.VulnFinding{ID: "GO-2025-0004", AdvisoryNamesNoSymbols: true},
		"golang.org/x/crypto", domain.ProbeKindSkipped, nil, nil)
	if unknown.Verdict != domain.SymbolProbeUnknown {
		t.Fatalf("verdict = %q, want the undetermined one under test", unknown.Verdict)
	}
	if unknown.Soundness != domain.ProbeSoundnessNotStated {
		t.Errorf("an undetermined verdict carried soundness %q", unknown.Soundness)
	}
}

// TestSymbolMatchIsDeterministic pins an answer that used to move without its
// input moving. A module and its own /vN major-version line share a path prefix,
// so both can carry a symbol of the same unqualified name; the match walked a Go
// map and returned whichever came first, so two probes of one unchanged tree
// reported different matched_symbols.
func TestSymbolMatchIsDeterministic(t *testing.T) {
	symbols := map[string]struct{}{
		"github.com/go-chi/chi/middleware.NewWrapResponseWriter":    {},
		"github.com/go-chi/chi/v5/middleware.NewWrapResponseWriter": {},
	}
	first := findInBinary("NewWrapResponseWriter", "github.com/go-chi/chi", symbols)
	for i := range 200 {
		if got := findInBinary("NewWrapResponseWriter", "github.com/go-chi/chi", symbols); got != first {
			t.Fatalf("iteration %d matched %q, first run matched %q", i, got, first)
		}
	}
}
