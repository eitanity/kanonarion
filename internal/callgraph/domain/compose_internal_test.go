package domain

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestGraphDigest_MarshalFailureIsNotAgreement covers the guard, not its
// absence. A digest that failed to compute must not come back as a value two
// records could match on: composition compares digests to decide whether two
// analyses AGREE about the graph, and a shared empty string would report
// agreement that was never measured.
func TestGraphDigest_MarshalFailureIsNotAgreement(t *testing.T) {
	original := canonicalMarshal
	t.Cleanup(func() { canonicalMarshal = original })
	injected := errors.New("injected marshal failure")
	canonicalMarshal = func(any) ([]byte, error) { return nil, injected }

	got := GraphDigest(CallGraphRecord{})
	if !strings.HasPrefix(got, "unhashable:") {
		t.Fatalf("GraphDigest() = %q, want a distinct marker a comparison cannot read as a digest", got)
	}
	if !strings.Contains(got, injected.Error()) {
		t.Errorf("GraphDigest() = %q, want it to carry why the digest could not be computed", got)
	}
	// Two failures must not collapse into one another either: the marker is only
	// safe because it is not a digest, and the test says so rather than implying it.
	if got == GraphDigest(CallGraphRecord{ContentHash: "sha256:different"}) && got == "" {
		t.Error("the failure marker is empty, which every comparison would read as a match")
	}
}

// TestIdentifiedOrAll_KeepsUnidentifiedWhenNothingNamesAnArtefact: dropping the
// records that name no artefact is only sound while a better-evidenced one
// remains. With none, discarding them would leave composition with nothing to
// answer from at all.
func TestIdentifiedOrAll_KeepsUnidentifiedWhenNothingNamesAnArtefact(t *testing.T) {
	t.Parallel()
	records := []CallGraphRecord{
		{ContentHash: "sha256:a"},
		{ContentHash: "sha256:b"},
	}
	got := identifiedOrAll(records)
	if len(got) != len(records) {
		t.Fatalf("identifiedOrAll kept %d of %d records that name no artefact", len(got), len(records))
	}
}

// TestDisagreement_UnstatedValueIsNotAThirdAnswer: a record that says nothing
// about a field has not contradicted one that does. Counting the empty value as
// a distinct answer would report a conflict between a measurement and a silence.
func TestDisagreement_UnstatedValueIsNotAThirdAnswer(t *testing.T) {
	t.Parallel()
	records := []CallGraphRecord{
		{ContentHash: "sha256:a", ArtefactIdentity: "zip:h1:one="},
		{ContentHash: "sha256:b", ArtefactIdentity: ""},
	}
	value := func(r CallGraphRecord) string { return r.ArtefactIdentity }
	if c := disagreement(records, "artefact_identity", value); c != nil {
		t.Fatalf("disagreement reported a conflict between a stated value and an unstated one: %+v", c)
	}

	// The same records, both stating a value, DO conflict — otherwise the test
	// above would pass for the wrong reason.
	records[1].ArtefactIdentity = "zip:h1:two="
	if c := disagreement(records, "artefact_identity", value); c == nil {
		t.Fatal("disagreement missed a conflict between two stated, differing values")
	}
}

// TestCompletenessRung_UnknownLevelOutranksNothing: a level written by a newer
// generation is not evidence this one can order, so it must sit at the bottom of
// the ladder rather than be guessed into the middle of it.
func TestCompletenessRung_UnknownLevelOutranksNothing(t *testing.T) {
	t.Parallel()
	future := CallGraphRecord{Completeness: CompletenessLevel("BUILT_WITH_EVERYTHING")}
	if got := completenessRung(future); got != 0 {
		t.Errorf("completenessRung(unrecognised level) = %d, want 0", got)
	}
	if completenessRung(future) >= completenessRung(CallGraphRecord{Completeness: CompletenessFailed}) {
		t.Error("an unrecognised level outranks a stated FAILED, which is better evidence than silence")
	}
}

// TestStatesAGraph_UnknownLevelClaimsNothing: the same unrecognised level must
// not be allowed to CONTRADICT a record that did produce a graph. Ordering and
// claiming are different questions, and a value this generation cannot read
// answers neither.
func TestStatesAGraph_UnknownLevelClaimsNothing(t *testing.T) {
	t.Parallel()
	if statesAGraph(CallGraphRecord{Completeness: CompletenessLevel("BUILT_WITH_EVERYTHING")}) {
		t.Error("an unrecognised completeness level claims to state a graph")
	}
}

// TestGraphDisagreement_UnreadableEncodingFallsBackRatherThanAgreeing covers the
// guard, not its absence.
//
// Deciding which fields a record states means reading its canonical encoding as
// an object. When that cannot be done, which fields are shared is unknown — and
// "unknown" must not resolve to "they share everything", which would report two
// records as agreeing about a graph neither could be read.
func TestGraphDisagreement_UnreadableEncodingFallsBackRatherThanAgreeing(t *testing.T) {
	tests := []struct {
		name    string
		marshal func(any) ([]byte, error)
	}{
		{
			// The encoding could not be produced at all.
			name:    "marshal fails",
			marshal: func(any) ([]byte, error) { return nil, errors.New("injected marshal failure") },
		},
		{
			// The encoding was produced but is not an object, so it names no fields.
			// Each call returns different bytes so the fallback's whole-record digests
			// differ and the fallback is observable in the result.
			name: "encoding is not an object",
			marshal: func() func(any) ([]byte, error) {
				n := 0
				return func(any) ([]byte, error) {
					n++
					return fmt.Appendf(nil, "[%d]", n), nil
				}
			}(),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			original := canonicalMarshal
			t.Cleanup(func() { canonicalMarshal = original })
			canonicalMarshal = tc.marshal

			records := []CallGraphRecord{
				{ContentHash: "sha256:a", Completeness: CompletenessBuiltWithBodies},
				{ContentHash: "sha256:b", Completeness: CompletenessBuiltWithBodies},
			}
			got := graphDisagreement(records)
			if got == nil {
				t.Fatal("an unreadable encoding was composed as agreement about the graph")
			}
			if got.Field != ConflictFieldCallGraph {
				t.Errorf("conflict field %q, want %q", got.Field, ConflictFieldCallGraph)
			}
		})
	}
}
