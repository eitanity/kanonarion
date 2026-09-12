package domain

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
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
		"derived_by":                 "why the run appended it: provenance about the run, not the graph",
		"dropped_replaces":           "which directives kanonarion removed to make the build work, which shows up in the nodes",
		"ecosystem":                  "which ecosystem: the key",
		"exclusion_list":             "what was left out, which shows up in the nodes if it changed the graph",
		"exclusion_reason":           "why something was left out",
		"extracted_at":               "when: provenance",
		"failed_packages":            "which packages did not load: a diagnostic",
		"failure_cause":              "why the analysis failed: a diagnostic",
		"failure_detail":             "how the analysis failed: a diagnostic",
		"foreign_modules_built":      "which other modules' packages were built with bodies: a scope, which shows up in the nodes",
		"overall_status":             "the status derived from the run",
		"pipeline_version":           "which pipeline wrote it: the key",
		"prefix_attributed_packages": "how packages were attributed: a diagnostic",
		"reference_scope":            "whether reference edges were extracted, which shows up in the edges",
		"schema_version":             "which shape: the key",
		"source_content_hash":        "which fetch supplied the bytes: provenance",
		"synthesised_go_mod":         "what kanonarion wrote to make the build work",
		"test_scope":                 "whether tests were analysed, which shows up in the nodes",
		"test_scope_detail":          "how the test scope was decided",
		"toolchain":                  "which Go built it: a dimension, compared as its own conflict first",
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

// TestGraphClaimDigest_MatchesMaterialisedFields is the equality the conflict
// comparison rests on. The digest is streamed rather than built, and streaming
// it may change what a comparison COSTS and may not change what it compares —
// so it is asserted against the materialised form directly, over every record
// shape the canonical encoder is exercised with, and over field sets that
// include one the record does not state.
func TestGraphClaimDigest_MatchesMaterialisedFields(t *testing.T) {
	for _, tc := range graphClaimCorpus() {
		for _, names := range [][]string{
			GraphClaimFields(),
			{"edges"},
			{"edge_count", "node_count"},
			{"edges", "nodes"},
			{"implementations", "interfaces"},
			{"edges", "not_a_field_any_record_states"},
			nil,
		} {
			t.Run(tc.name+"/"+strings.Join(names, "+"), func(t *testing.T) {
				want := materialisedGraphClaimDigest(t, tc.record, names)
				got, err := graphClaimDigest(tc.record, names)
				if err != nil {
					t.Fatalf("graphClaimDigest: %v", err)
				}
				if got != want {
					t.Errorf("graphClaimDigest() = %s, want %s (the digest of the materialised canonical fields)", got, want)
				}
			})
		}
	}
}

// TestGraphFieldNames_MatchesMaterialisedFieldKeys proves the name pass sees the
// same fields the materialised map's keys did. Which fields two records share is
// what scopes the comparison, so a name the walk missed would silently drop a
// field from every digest that record takes part in.
func TestGraphFieldNames_MatchesMaterialisedFieldKeys(t *testing.T) {
	for _, tc := range graphClaimCorpus() {
		t.Run(tc.name, func(t *testing.T) {
			want := materialisedGraphFields(t, tc.record)
			got, err := graphFieldNames(tc.record)
			if err != nil {
				t.Fatalf("graphFieldNames: %v", err)
			}
			if len(got) != len(want) {
				t.Errorf("graphFieldNames() named %d fields, want %d", len(got), len(want))
			}
			for name := range want {
				if !got[name] {
					t.Errorf("graphFieldNames() did not name %q, which the record states", name)
				}
			}
			for name := range got {
				if _, ok := want[name]; !ok {
					t.Errorf("graphFieldNames() named %q, which the record does not state", name)
				}
			}
		})
	}
}

// TestCanonicalFields_HandsBackTheSameBytesAsDecoding pins the span arithmetic.
// The values are sub-slices of the encoding rather than copies of it, and an
// off-by-one there would hash bytes no field carries.
func TestCanonicalFields_HandsBackTheSameBytesAsDecoding(t *testing.T) {
	for _, tc := range graphClaimCorpus() {
		t.Run(tc.name, func(t *testing.T) {
			data, err := marshalCanonical(forGraphComparison(tc.record))
			if err != nil {
				t.Fatalf("marshalCanonical: %v", err)
			}
			var want map[string]json.RawMessage
			if uerr := json.Unmarshal(data, &want); uerr != nil {
				t.Fatalf("unmarshal canonical record: %v", uerr)
			}
			got := map[string]string{}
			if ferr := canonicalFields(data, func(name string, value []byte) {
				got[name] = string(value)
			}); ferr != nil {
				t.Fatalf("canonicalFields: %v", ferr)
			}
			if len(got) != len(want) {
				t.Fatalf("canonicalFields visited %d fields, want %d", len(got), len(want))
			}
			for name, raw := range want {
				if got[name] != string(raw) {
					t.Errorf("canonicalFields(%q) = %q, want %q", name, got[name], string(raw))
				}
			}
		})
	}
}

// TestCanonicalFields_RefusesAnEncodingItCannotWalk keeps the walk from reporting
// a field set it never read. A record whose encoding cannot be walked states
// nothing measurable, and reporting that as an empty field set would make two
// unreadable records agree.
func TestCanonicalFields_RefusesAnEncodingItCannotWalk(t *testing.T) {
	for _, tc := range []struct{ name, data string }{
		{"not an object", `["edges"]`},
		{"empty input", ``},
		{"truncated object", `{"edges":[1,2`},
		{"truncated value", `{"edges":`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := canonicalFields([]byte(tc.data), func(string, []byte) {})
			if err == nil {
				t.Fatal("canonicalFields() error = nil, want a refusal to report fields it did not read")
			}
		})
	}
}

// TestGraphClaimDigest_MarshalFailureIsReported covers the guard on the same
// terms GraphDigest's does: a digest that failed to compute must never come back
// as a value two records could match on.
func TestGraphClaimDigest_MarshalFailureIsReported(t *testing.T) {
	original := canonicalMarshal
	t.Cleanup(func() { canonicalMarshal = original })
	injected := errors.New("injected marshal failure")
	canonicalMarshal = func(any) ([]byte, error) { return nil, injected }

	if _, err := graphClaimDigest(CallGraphRecord{}, GraphClaimFields()); !errors.Is(err, injected) {
		t.Errorf("graphClaimDigest() error = %v, want it to wrap the injected error", err)
	}
	if _, err := graphFieldNames(CallGraphRecord{}); !errors.Is(err, injected) {
		t.Errorf("graphFieldNames() error = %v, want it to wrap the injected error", err)
	}
}

// graphClaimCorpus is the hash-streaming corpus plus the shapes that decide
// which fields a record STATES: the interface and implementation collections are
// omitted when empty, so a record carrying them states two fields a record
// without them does not.
func graphClaimCorpus() []hashStreamCase {
	cases := hashStreamCorpus()

	withCollections := recordWithEdges(edgeRun(3))
	withCollections.Interfaces = []InterfaceType{
		{ID: "example.com/mod.Reader", Name: "Reader", Package: "example.com/mod", Methods: []string{"Read", "Close"}, Position: SourcePosition{File: "i.go", Line: 4}},
	}
	withCollections.Implementations = []InterfaceImplementation{
		{InterfaceID: "example.com/mod.Reader", TypeID: "example.com/mod.File", Package: "example.com/mod", Position: SourcePosition{File: "f.go", Line: 7},
			Methods: []ImplementedMethod{{Method: "Read", NodeID: "example.com/mod.(*File).Read"}}},
	}
	withCollections.Completeness = CompletenessBuiltWithBodies
	cases = append(cases, hashStreamCase{"interfaces and implementations", withCollections})

	bare := recordWithEdges(nil)
	bare.Nodes = nil
	bare.NodeCount = 0
	cases = append(cases, hashStreamCase{"no nodes and no edges", bare})

	// Every collection the record carries, each with more than one element, so
	// that reading a record's field names from a truncated stand-in is asserted
	// against the full encoding for all of them rather than for nodes alone.
	every := withCollections
	every.Interfaces = append(every.Interfaces, InterfaceType{ID: "example.com/mod.Writer", Name: "Writer", Package: "example.com/mod", Methods: []string{"Write"}})
	every.Implementations = append(every.Implementations, InterfaceImplementation{
		InterfaceID: "example.com/mod.Writer", TypeID: "example.com/mod.Buffer", Package: "example.com/mod",
		Methods: []ImplementedMethod{{Method: "Write", NodeID: "example.com/mod.(*Buffer).Write"}}})
	every.FailedPackages = []string{"example.com/mod/a", "example.com/mod/b"}
	every.ExclusionList = []string{"example.com/mod/c", "example.com/mod/d"}
	every.PrefixAttributedPackages = []string{"example.com/mod/e", "example.com/mod/f"}
	every.ForeignModulesBuilt = []ForeignModule{{Path: "example.com/dep", Version: "v1.2.3"}, {Path: "example.com/other", Version: "v0.1.0"}}
	every.DroppedReplaces = []DroppedReplace{{Path: "example.com/x", Target: "../x"}, {Path: "example.com/y", Target: "../y"}}
	every.SynthesisedGoMod = SynthesisedGoMod{ModulePath: "example.com/mod", GoDirective: "1.26",
		Requires: []SynthesisedRequire{{Path: "example.com/dep", Version: "v1.2.3"}, {Path: "example.com/other", Version: "v0.1.0"}}}
	every.ExclusionReason = "vendored"
	every.FailureDetail = "none"
	cases = append(cases, hashStreamCase{"every collection populated", every})

	return cases
}

// TestFieldPresenceProbe_LeavesTheCallersCollectionsAlone guards the truncation:
// it cuts a copy's slice headers, and a record handed to a read must come back
// from a comparison with every element it arrived with.
func TestFieldPresenceProbe_LeavesTheCallersCollectionsAlone(t *testing.T) {
	for _, tc := range graphClaimCorpus() {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.record
			nodes, edges, ifaces := len(r.Nodes), len(r.Edges), len(r.Interfaces)
			var firstEdge CallEdge
			if len(r.Edges) > 0 {
				firstEdge = r.Edges[0]
			}
			_ = fieldPresenceProbe(r)
			if len(r.Nodes) != nodes || len(r.Edges) != edges || len(r.Interfaces) != ifaces {
				t.Fatalf("fieldPresenceProbe truncated the caller's record: nodes %d->%d, edges %d->%d, interfaces %d->%d",
					nodes, len(r.Nodes), edges, len(r.Edges), ifaces, len(r.Interfaces))
			}
			if len(r.Edges) > 0 && r.Edges[0] != firstEdge {
				t.Errorf("fieldPresenceProbe rewrote the caller's first edge: got %+v, want %+v", r.Edges[0], firstEdge)
			}
		})
	}
}

// materialisedGraphFields is what graphFields did: the whole record marshalled to
// canonical JSON and decoded into a map that retains every field's bytes. It is
// the reference the streamed digest is asserted against, and it lives in the test
// because holding those bytes is the cost the implementation exists to avoid.
func materialisedGraphFields(t *testing.T, r CallGraphRecord) map[string]json.RawMessage {
	t.Helper()
	data, err := marshalCanonical(forGraphComparison(r))
	if err != nil {
		t.Fatalf("marshalCanonical: %v", err)
	}
	var fields map[string]json.RawMessage
	if uerr := json.Unmarshal(data, &fields); uerr != nil {
		t.Fatalf("unmarshal canonical record: %v", uerr)
	}
	return fields
}

// materialisedGraphClaimDigest is what digestOfFields did, byte for byte.
func materialisedGraphClaimDigest(t *testing.T, r CallGraphRecord, names []string) string {
	t.Helper()
	fields := materialisedGraphFields(t, r)
	var b bytes.Buffer
	b.WriteByte('{')
	for i, name := range names {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.Quote(name))
		b.WriteByte(':')
		b.Write(fields[name])
	}
	b.WriteByte('}')
	sum := sha256.Sum256(b.Bytes())
	return "sha256:" + hex.EncodeToString(sum[:])
}
