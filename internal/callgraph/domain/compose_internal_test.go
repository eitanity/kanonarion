package domain

import (
	"errors"
	"fmt"
	"reflect"
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
	future := CompletenessLevel("BUILT_WITH_EVERYTHING")
	if got := completenessRung(future); got != 0 {
		t.Errorf("completenessRung(unrecognised level) = %d, want 0", got)
	}
	if completenessRung(future) >= completenessRung(CompletenessFailed) {
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

// TestGraphClaimFields_ClassifiesEveryCanonicalField establishes the graph
// comparison's field list FROM the canonical record shape rather than from a
// list somebody kept in their head.
//
// Every field the sealed shape carries is either part of the graph claim or not,
// and this enumerates the shape by reflection so that adding a field to it
// without deciding which fails here. That matters in one direction more than the
// other: a collection added to the record and forgotten here would be a graph
// difference the conflict check stopped seeing, which is the failure mode a
// silent comparison is supposed to prevent.
func TestGraphClaimFields_ClassifiesEveryCanonicalField(t *testing.T) {
	t.Parallel()

	// notTheGraph is every canonical field that carries something OTHER than the
	// graph: identity and keying, provenance forGraphComparison already blanks,
	// the scope an analysis ran under, and diagnostics describing the run. A
	// record differing on any of these while holding the same nodes and edges has
	// not contradicted anything about the graph.
	notTheGraph := map[string]string{
		"algorithm":                  "how the graph was derived, not what it says",
		"analysis_root":              "where a tree was mounted: provenance",
		"analysis_source":            "which kind of source was read: a dimension",
		"artefact_identity":          "which bytes were read: compared as its own conflict first",
		"artifact_kind":              "what sort of artefact was analysed",
		"build_list_source":          "which walk offered the build list: provenance",
		"completeness":               "how far the analysis got: the ladder, and already tied before comparing",
		"content_hash":               "the record's own seal",
		"coordinate":                 "which module: the key",
		"ecosystem":                  "which ecosystem: the key",
		"exclusion_list":             "what was left out, which shows up in the nodes if it changed the graph",
		"exclusion_reason":           "why something was left out",
		"extracted_at":               "when: provenance",
		"failed_packages":            "which packages did not load: a diagnostic",
		"failure_cause":              "why the analysis failed: a diagnostic",
		"failure_detail":             "how the analysis failed: a diagnostic",
		"overall_status":             "the status derived from the run",
		"pipeline_version":           "which pipeline wrote it: the key",
		"prefix_attributed_packages": "how packages were attributed: a diagnostic",
		"reference_scope":            "whether reference edges were extracted, which shows up in the edges",
		"schema_version":             "which shape: the key",
		"source_content_hash":        "which fetch supplied the bytes: provenance",
		"synthesised_go_mod":         "what kanonarion wrote to make the build work",
		"test_scope":                 "whether tests were analysed, which shows up in the nodes",
		"test_scope_detail":          "how the test scope was decided",
		"worktree_digest":            "what the tree contained: identity, not graph",
		"worktree_scan_digest":       "which tree the analysis was handed: the reuse key, not graph",
	}
	claim := map[string]bool{}
	for _, name := range GraphClaimFields() {
		claim[name] = true
	}

	seen := map[string]bool{}
	shape := reflect.TypeOf(canonicalRecord{})
	for i := range shape.NumField() {
		tag := shape.Field(i).Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name == "" || name == "-" {
			t.Fatalf("canonical field %q carries no json name", shape.Field(i).Name)
		}
		seen[name] = true
		_, excluded := notTheGraph[name]
		switch {
		case claim[name] && excluded:
			t.Errorf("canonical field %q is classified both as the graph and as not the graph", name)
		case !claim[name] && !excluded:
			t.Errorf("canonical field %q is in the sealed shape but classified neither way: "+
				"decide whether it is part of the graph claim and add it to GraphClaimFields or to notTheGraph", name)
		}
	}
	for name := range claim {
		if !seen[name] {
			t.Errorf("GraphClaimFields names %q, which the canonical shape does not carry, so it is compared on nothing", name)
		}
	}
}
