package domain_test

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
)

var levels = []domain.CompletenessLevel{
	domain.CompletenessBuiltWithBodies,
	domain.CompletenessTypeOnly,
	domain.CompletenessMetadataOnly,
	domain.CompletenessFailed,
	domain.CompletenessVersionNotInToolchain,
	domain.CompletenessUnknown,
}

func TestCompletenessLevel_String(t *testing.T) {
	if got := domain.CompletenessUnknown.String(); got != "Unknown" {
		t.Errorf("zero value should render Unknown, got %q", got)
	}
	if got := domain.CompletenessBuiltWithBodies.String(); got != "BUILT_WITH_BODIES" {
		t.Errorf("unexpected string %q", got)
	}
}

func TestCompletenessLevel_IsBuiltWithBodies(t *testing.T) {
	for _, l := range levels {
		want := l == domain.CompletenessBuiltWithBodies
		if got := l.IsBuiltWithBodies(); got != want {
			t.Errorf("%s.IsBuiltWithBodies()=%v, want %v", l, got, want)
		}
	}
}

// TestCompletenessParity_AllLevelPairings asserts parity holds exactly when both
// the level and the algorithm match, over every level pairing, and that the
// reason names the differing axis.
func TestCompletenessParity_AllLevelPairings(t *testing.T) {
	for _, before := range levels {
		for _, after := range levels {
			ok, reason := domain.CompletenessParity(
				domain.CompletenessDescriptor{Level: before, Algorithm: domain.AlgorithmCHA},
				domain.CompletenessDescriptor{Level: after, Algorithm: domain.AlgorithmCHA},
			)
			wantOK := before == after
			if ok != wantOK {
				t.Fatalf("parity(%s,%s)=%v, want %v", before, after, ok, wantOK)
			}
			if !ok {
				if !strings.Contains(reason, "completeness level differs") {
					t.Fatalf("reason must name level mismatch, got %q", reason)
				}
				if !strings.Contains(reason, before.String()) || !strings.Contains(reason, after.String()) {
					t.Fatalf("reason must name both levels, got %q", reason)
				}
			} else if reason != "" {
				t.Fatalf("parity holds but reason non-empty: %q", reason)
			}
		}
	}
}

func TestCompletenessParity_AlgorithmMismatch(t *testing.T) {
	ok, reason := domain.CompletenessParity(
		domain.CompletenessDescriptor{Level: domain.CompletenessBuiltWithBodies, Algorithm: domain.AlgorithmCHA},
		domain.CompletenessDescriptor{Level: domain.CompletenessBuiltWithBodies, Algorithm: domain.AlgorithmRTA},
	)
	if ok {
		t.Fatal("same level, different algorithm must not be in parity")
	}
	if !strings.Contains(reason, "algorithm/devirt tier differs") {
		t.Fatalf("reason must name algorithm mismatch, got %q", reason)
	}
}

func TestRecordCompleteness(t *testing.T) {
	r := domain.CallGraphRecord{Completeness: domain.CompletenessTypeOnly, Algorithm: domain.AlgorithmCHA}
	d := domain.RecordCompleteness(r)
	if d.Level != domain.CompletenessTypeOnly || d.Algorithm != domain.AlgorithmCHA {
		t.Fatalf("unexpected descriptor %+v", d)
	}
}

// TestCompletenessCaveat_PhaseConditioning asserts the caveat is empty at full
// fidelity and phase-appropriate below it: coding instructs a rebuild, inclusion
// explains a degraded verdict, diff points at parity.
func TestCompletenessCaveat_PhaseConditioning(t *testing.T) {
	if got := domain.CompletenessCaveat(domain.CompletenessBuiltWithBodies, domain.PhaseCoding); got != "" {
		t.Errorf("full fidelity must warrant no caveat, got %q", got)
	}
	cases := []struct {
		phase domain.AnalysisPhase
		want  string
	}{
		{domain.PhaseCoding, "go generate"},
		{domain.PhaseInclusion, "untrusted"},
		{domain.PhaseDiff, "before/after"},
	}
	for _, tc := range cases {
		got := domain.CompletenessCaveat(domain.CompletenessMetadataOnly, tc.phase)
		if got == "" || !strings.Contains(got, tc.want) {
			t.Errorf("phase %s caveat %q must mention %q", tc.phase, got, tc.want)
		}
		if !strings.Contains(got, "METADATA_ONLY") {
			t.Errorf("phase %s caveat must name the level, got %q", tc.phase, got)
		}
	}

	// An unrecognised phase still yields a generic, level-naming caveat.
	generic := domain.CompletenessCaveat(domain.CompletenessFailed, domain.AnalysisPhase("audit-x"))
	if !strings.Contains(generic, "FAILED") || !strings.Contains(generic, "may be incomplete") {
		t.Errorf("unknown phase must yield a generic caveat naming the level, got %q", generic)
	}
}
