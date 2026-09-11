package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

func TestMarshalCanonical_MarshalFailure(t *testing.T) {
	original := canonicalMarshal
	t.Cleanup(func() { canonicalMarshal = original })
	injected := errors.New("injected marshal failure")
	canonicalMarshal = func(any) ([]byte, error) { return nil, injected }

	_, err := CallGraphRecordHasher{}.SetContentHash(CallGraphRecord{})
	if err == nil {
		t.Fatal("SetContentHash() error = nil, want wrapped marshal error")
	}
	if !errors.Is(err, injected) {
		t.Errorf("SetContentHash() error = %v, want it to wrap the injected error", err)
	}
	if !strings.Contains(err.Error(), "canonical callgraph record") {
		t.Errorf("SetContentHash() error = %q, want it to name the record being marshalled", err.Error())
	}
}

func TestVerifyContentHash_MarshalFailure(t *testing.T) {
	original := canonicalMarshal
	t.Cleanup(func() { canonicalMarshal = original })
	injected := errors.New("injected marshal failure")
	canonicalMarshal = func(any) ([]byte, error) { return nil, injected }

	err := CallGraphRecordHasher{}.VerifyContentHash(CallGraphRecord{})
	if !errors.Is(err, injected) {
		t.Errorf("VerifyContentHash() error = %v, want it to wrap the injected error", err)
	}
}

// TestHashCanonicalMatchesMarshalCanonical is the guard on the whole streaming
// digest: a verified read may cost less, and may not verify anything different.
// It asserts the digest over the streamed bytes is the digest over the bytes
// marshalCanonical produces, for records chosen to stress every seam the
// streaming introduces — the chunk boundary, an empty array, an out-of-order
// input, and the characters JSON escapes.
func TestHashCanonicalMatchesMarshalCanonical(t *testing.T) {
	for _, tc := range hashStreamCorpus() {
		t.Run(tc.name, func(t *testing.T) {
			data, err := marshalCanonical(tc.record)
			if err != nil {
				t.Fatalf("marshalCanonical: %v", err)
			}
			sum := sha256.Sum256(data)
			want := "sha256:" + hex.EncodeToString(sum[:])

			got, err := hashCanonical(tc.record)
			if err != nil {
				t.Fatalf("hashCanonical: %v", err)
			}
			if got != want {
				t.Errorf("hashCanonical() = %s, want %s (the digest of the materialised canonical bytes)", got, want)
			}
		})
	}
}

// TestHashCanonicalDoesNotReorderTheCallersEdges guards the copy-elision: the
// ordering step returns the caller's own slice when it is already in canonical
// order, so it must never sort in place.
func TestHashCanonicalDoesNotReorderTheCallersEdges(t *testing.T) {
	r := recordWithEdges(edgeRun(8))
	r.Edges[0], r.Edges[7] = r.Edges[7], r.Edges[0]
	before := append([]CallEdge(nil), r.Edges...)

	if _, err := hashCanonical(r); err != nil {
		t.Fatalf("hashCanonical: %v", err)
	}
	for i := range before {
		if r.Edges[i] != before[i] {
			t.Fatalf("hashCanonical reordered the caller's edges at %d: got %+v, want %+v", i, r.Edges[i], before[i])
		}
	}
}

// TestHashCanonicalRefusesAnAmbiguousPlaceholder proves the split is a located
// span rather than a guess. Sealing a record over bytes nobody chose is the
// failure this refusal exists to prevent.
func TestHashCanonicalRefusesAnAmbiguousPlaceholder(t *testing.T) {
	for _, tc := range []struct {
		name  string
		bytes []byte
	}{
		{"absent", []byte(`{"edge_count":0}`)},
		{"twice", []byte(`{"edges":null,"edges":null}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := canonicalMarshal
			t.Cleanup(func() { canonicalMarshal = original })
			canonicalMarshal = func(any) ([]byte, error) { return tc.bytes, nil }

			_, err := hashCanonical(recordWithEdges(edgeRun(2)))
			if err == nil {
				t.Fatal("hashCanonical() error = nil, want a refusal to guess which span is the edge array")
			}
			if !strings.Contains(err.Error(), "edge array") {
				t.Errorf("hashCanonical() error = %q, want it to name the edge array", err.Error())
			}
		})
	}
}

type hashStreamCase struct {
	name   string
	record CallGraphRecord
}

func hashStreamCorpus() []hashStreamCase {
	cases := []hashStreamCase{
		{"zero record", CallGraphRecord{}},
		{"no edges", recordWithEdges(nil)},
		{"empty non-nil edge slice", recordWithEdges([]CallEdge{})},
	}
	// The chunk boundary is the seam where the streamed array is joined back
	// together, so it is exercised from both sides and on it.
	for _, n := range []int{1, 2, canonicalEdgeChunk - 1, canonicalEdgeChunk, canonicalEdgeChunk + 1, 2*canonicalEdgeChunk + 3} {
		cases = append(cases, hashStreamCase{
			name:   "edges=" + strconv.Itoa(n),
			record: recordWithEdges(edgeRun(n)),
		})
	}

	unsorted := recordWithEdges(edgeRun(16))
	slices.Reverse(unsorted.Edges)
	cases = append(cases, hashStreamCase{"edges out of canonical order", unsorted})

	// Every character class encoding/json treats specially, in the fields that
	// carry identifiers: HTML escaping, quoting, control characters, multi-byte
	// runes and bytes that are not valid UTF-8 at all.
	awkward := []string{
		`a<b>c&d`,
		`quote"back\slash`,
		"tab\tnewline\nnull\x00",
		"ünïcödé/日本語/🙂",
		"invalid\xff\xfeutf8",
		"line separator ",
	}
	var escaping []CallEdge
	for i, s := range awkward {
		escaping = append(escaping, CallEdge{
			FromID:     s,
			ToID:       s + "/callee",
			CallSite:   SourcePosition{File: s + ".go", Line: i + 1},
			Confidence: ConfidenceVTA,
			Kind:       EdgeKindReference,
		})
	}
	cases = append(cases, hashStreamCase{"escaped characters", recordWithEdges(escaping)})

	// Every confidence and both kinds, so the ordering tie-breaks that decide
	// canonical edge order are exercised on identical endpoints.
	tied := recordWithEdges(nil)
	for _, c := range []EdgeConfidence{ConfidenceDirect, ConfidenceCHAOverapprox, ConfidenceVTA, ConfidenceFramework, ConfidenceUnknown} {
		for _, k := range []EdgeKind{EdgeKindCall, EdgeKindReference} {
			tied.Edges = append(tied.Edges, CallEdge{
				FromID: "m/p.A", ToID: "m/p.B",
				CallSite:        SourcePosition{File: "a.go", Line: 1},
				Confidence:      c,
				Kind:            k,
				ReflectDispatch: c == ConfidenceUnknown,
			})
		}
	}
	cases = append(cases, hashStreamCase{"all confidences and kinds on one site", tied})
	return cases
}

func recordWithEdges(edges []CallEdge) CallGraphRecord {
	coord, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
	if err != nil {
		panic(err)
	}
	return CallGraphRecord{
		SchemaVersion: CallGraphSchemaVersion,
		Ecosystem:     fetchdomain.EcosystemGo,
		Coordinate:    coord,
		Algorithm:     AlgorithmCHA,
		Nodes: []CallNode{
			{ID: "example.com/mod.Alpha", Module: "example.com/mod", Package: "example.com/mod", Symbol: "Alpha", Position: SourcePosition{File: "a.go", Line: 3}},
			{ID: "example.com/mod.Beta", Module: "example.com/mod", Package: "example.com/mod", Symbol: "Beta", Position: SourcePosition{File: "a.go", Line: 9}},
		},
		Edges:           edges,
		OverallStatus:   CallGraphStatusExtracted,
		NodeCount:       2,
		EdgeCount:       len(edges),
		ExtractedAt:     time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		PipelineVersion: "0.6.0",
	}
}

func edgeRun(n int) []CallEdge {
	edges := make([]CallEdge, 0, n)
	for i := range n {
		edges = append(edges, CallEdge{
			FromID:     "example.com/mod.Alpha",
			ToID:       "example.com/mod.Callee" + strconv.Itoa(i),
			CallSite:   SourcePosition{File: "a.go", Line: i},
			Confidence: ConfidenceDirect,
		})
	}
	return edges
}
