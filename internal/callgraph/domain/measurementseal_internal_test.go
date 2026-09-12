package domain

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
)

// sealTestRecord is a record the append-side reuse check would actually compare:
// it names the content it analysed, so NamesAnalysedContent holds and the
// comparison is reached rather than refused before it.
func sealTestRecord(t *testing.T, n int) CallGraphRecord {
	t.Helper()
	coord, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	nodes := make([]CallNode, n)
	edges := make([]CallEdge, n)
	for i := range nodes {
		id := fmt.Sprintf("example.com/mod.Func%d", i)
		nodes[i] = CallNode{
			ID: id, Module: "example.com/mod", Package: "example.com/mod",
			Symbol:   fmt.Sprintf("Func%d", i),
			Position: SourcePosition{File: fmt.Sprintf("f%d.go", i), Line: i + 1},
		}
		edges[i] = CallEdge{
			FromID:     id,
			ToID:       fmt.Sprintf("example.com/mod.Func%d", (i+1)%n),
			CallSite:   SourcePosition{File: fmt.Sprintf("f%d.go", i), Line: i + 2},
			Confidence: ConfidenceDirect,
		}
	}
	r := CallGraphRecord{
		SchemaVersion:    CallGraphSchemaVersion,
		Ecosystem:        "go",
		Coordinate:       coord,
		Algorithm:        AlgorithmCHA,
		Completeness:     CompletenessBuiltWithBodies,
		AnalysisSource:   AnalysisSourceModuleZip,
		ArtefactIdentity: "zip:h1:tree-one=",
		OverallStatus:    CallGraphStatusExtracted,
		Nodes:            nodes,
		Edges:            edges,
		NodeCount:        n,
		EdgeCount:        n,
		ExtractedAt:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		PipelineVersion:  "0.6.0",
	}
	if !NamesAnalysedContent(r) {
		t.Fatal("the fixture names no analysed content, so the comparison is never reached")
	}
	return r
}

// sealTestVariants are the ways one record can differ from another, on both
// sides of the line: the circumstances of the run, which the comparison sets
// aside, and everything else, which separates two measurements.
func sealTestVariants() map[string]func(r CallGraphRecord) CallGraphRecord {
	return map[string]func(r CallGraphRecord) CallGraphRecord{
		"unchanged":   func(r CallGraphRecord) CallGraphRecord { return r },
		"later clock": func(r CallGraphRecord) CallGraphRecord { r.ExtractedAt = r.ExtractedAt.Add(time.Hour); return r },
		"another seal": func(r CallGraphRecord) CallGraphRecord {
			r.ContentHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
			return r
		},
		"another derivation": func(r CallGraphRecord) CallGraphRecord {
			r.DerivedBy = DerivationFor(ReuseGateLedger, true)
			return r
		},
		"another fetch record": func(r CallGraphRecord) CallGraphRecord { r.SourceContentHash = "sha256:beef"; return r },
		"one edge fewer":       func(r CallGraphRecord) CallGraphRecord { r.Edges = r.Edges[:len(r.Edges)-1]; return r },
		"one edge elsewhere": func(r CallGraphRecord) CallGraphRecord {
			e := append([]CallEdge(nil), r.Edges...)
			e[len(e)-1].ToID = "example.com/mod.Elsewhere"
			r.Edges = e
			return r
		},
		"one node renamed": func(r CallGraphRecord) CallGraphRecord {
			n := append([]CallNode(nil), r.Nodes...)
			n[1].Symbol = "Renamed"
			r.Nodes = n
			return r
		},
		"another completeness": func(r CallGraphRecord) CallGraphRecord { r.Completeness = CompletenessMetadataOnly; return r },
		"another artefact":     func(r CallGraphRecord) CallGraphRecord { r.ArtefactIdentity = "zip:h1:tree-two="; return r },
		"another build list":   func(r CallGraphRecord) CallGraphRecord { r.BuildListSource = "walk-2"; return r },
		"another root":         func(r CallGraphRecord) CallGraphRecord { r.AnalysisRoot = "/elsewhere"; return r },
		"another toolchain":    func(r CallGraphRecord) CallGraphRecord { r.Toolchain = "go1.26.5"; return r },
	}
}

// TestMeasurementSeal_IsTheComparisonItReplaced.
//
// The reuse check used to marshal both records whole and compare the bytes. It
// now streams each side into a digest and compares those, which is cheaper and
// is a DIFFERENT statement — "the same seal over the compared fields" rather
// than "the same bytes". For this question the two coincide, and that is shown
// here rather than assumed: the seal must answer exactly what bytes.Equal over
// the materialised canonical encodings answers, on records that agree and on
// records that differ in each of the ways a record can.
func TestMeasurementSeal_IsTheComparisonItReplaced(t *testing.T) {
	t.Parallel()

	var agreed, differed int
	for name, mutate := range sealTestVariants() {
		base := sealTestRecord(t, 40)
		other := mutate(sealTestRecord(t, 40))

		ab, err := marshalCanonical(withoutRunCircumstance(withoutFetchProvenance(base)))
		if err != nil {
			t.Fatalf("%s: marshalCanonical: %v", name, err)
		}
		bb, err := marshalCanonical(withoutRunCircumstance(withoutFetchProvenance(other)))
		if err != nil {
			t.Fatalf("%s: marshalCanonical: %v", name, err)
		}
		sameBytes := bytes.Equal(ab, bb)

		sealed, named, err := SealAnalysis(base)
		if err != nil || !named {
			t.Fatalf("%s: SealAnalysis: err=%v named=%v", name, err, named)
		}
		sameSeal, err := sealed.RestatedBy(other)
		if err != nil {
			t.Fatalf("%s: RestatedBy: %v", name, err)
		}
		if sameSeal != sameBytes {
			t.Errorf("%s: the seal says %v and the bytes say %v", name, sameSeal, sameBytes)
		}

		// The pair form must not have drifted from the sealed one it now delegates
		// to, or two callers of one rule would answer differently.
		pairwise, err := RestatesAnalysis(base, other)
		if err != nil {
			t.Fatalf("%s: RestatesAnalysis: %v", name, err)
		}
		if pairwise != sameBytes {
			t.Errorf("%s: RestatesAnalysis says %v and the bytes say %v", name, pairwise, sameBytes)
		}

		if sameBytes {
			agreed++
		} else {
			differed++
		}
	}
	// A population that never agreed, or never differed, would pass this test
	// while proving one half of it.
	if agreed == 0 || differed == 0 {
		t.Errorf("the population is one-sided: %d agreed, %d differed", agreed, differed)
	}
}

// TestMeasurementSeal_AnUnsealedComparisonRefuses. A seal is taken OVER a
// record, so the zero value was taken over none. Answering "not the same
// measurement" would report the outcome of a comparison that never happened, and
// on this path that outcome is "append another generation".
func TestMeasurementSeal_AnUnsealedComparisonRefuses(t *testing.T) {
	t.Parallel()

	_, err := MeasurementSeal{}.SameAs(sealTestRecord(t, 4))
	if !errors.Is(err, ErrUnsealedMeasurement) {
		t.Errorf("SameAs on a zero seal = %v, want ErrUnsealedMeasurement", err)
	}
	_, err = AnalysisRestatement{}.RestatedBy(sealTestRecord(t, 4))
	if !errors.Is(err, ErrUnsealedMeasurement) {
		t.Errorf("RestatedBy on a zero restatement = %v, want ErrUnsealedMeasurement", err)
	}
}

// TestSealAnalysis_ARecordNamingNoAnalysedContentSealsNothing. The naming rule
// is what makes dropping SourceContentHash sound, so it has to be refused before
// a seal exists rather than inside the comparison — a caller that got a seal
// back would walk every candidate to be told no by each of them.
func TestSealAnalysis_ARecordNamingNoAnalysedContentSealsNothing(t *testing.T) {
	t.Parallel()

	unnamed := sealTestRecord(t, 4)
	unnamed.ArtefactIdentity = ""
	unnamed.AnalysisSource = AnalysisSourceUnrecorded
	if NamesAnalysedContent(unnamed) {
		t.Fatal("the fixture still names its analysed content")
	}
	sealed, named, err := SealAnalysis(unnamed)
	if err != nil {
		t.Fatalf("SealAnalysis: %v", err)
	}
	if named {
		t.Error("a record naming no analysed content was sealed")
	}
	if sealed != (AnalysisRestatement{}) {
		t.Error("a refused seal came back with a value in it")
	}

	// And the held side is refused too, on the same rule.
	held := sealTestRecord(t, 4)
	held.ArtefactIdentity = ""
	held.AnalysisSource = AnalysisSourceUnrecorded
	fresh, named, err := SealAnalysis(sealTestRecord(t, 4))
	if err != nil || !named {
		t.Fatalf("SealAnalysis: err=%v named=%v", err, named)
	}
	same, err := fresh.RestatedBy(held)
	if err != nil {
		t.Fatalf("RestatedBy: %v", err)
	}
	if same {
		t.Error("a held record naming no analysed content was read as a restatement")
	}
}

// TestMeasurementSeal_AMarshalFailureIsNotAgreement covers the guard on the
// terms the rest of this package's digests are held to: a seal that failed to
// compute must never come back as a value two records could match on. On this
// path a false match means declining to append a measurement the ledger does not
// hold.
//
// The marshal is a fault seam: no value this shape carries can make json.Marshal
// fail today, so this proves the error is propagated rather than that the
// failure is reachable.
func TestMeasurementSeal_AMarshalFailureIsNotAgreement(t *testing.T) {
	original := canonicalMarshal
	t.Cleanup(func() { canonicalMarshal = original })
	injected := errors.New("injected marshal failure")

	sealed, named, err := SealAnalysis(sealTestRecord(t, 2))
	if err != nil || !named {
		t.Fatalf("SealAnalysis: err=%v named=%v", err, named)
	}
	held := sealTestRecord(t, 2)

	canonicalMarshal = func(any) ([]byte, error) { return nil, injected }

	if _, err := SealMeasurement(sealTestRecord(t, 2)); !errors.Is(err, injected) {
		t.Errorf("SealMeasurement error = %v, want it to wrap the injected error", err)
	}
	if _, _, err := SealAnalysis(sealTestRecord(t, 2)); !errors.Is(err, injected) {
		t.Errorf("SealAnalysis error = %v, want it to wrap the injected error", err)
	}
	same, err := sealed.RestatedBy(held)
	if !errors.Is(err, injected) {
		t.Errorf("RestatedBy error = %v, want it to wrap the injected error", err)
	}
	if same {
		t.Error("a failed seal reported a restatement")
	}
	if _, err := SameMeasurement(sealTestRecord(t, 2), held); !errors.Is(err, injected) {
		t.Errorf("SameMeasurement error = %v, want it to wrap the injected error", err)
	}
	if _, err := RestatesAnalysis(sealTestRecord(t, 2), held); !errors.Is(err, injected) {
		t.Errorf("RestatesAnalysis error = %v, want it to wrap the injected error", err)
	}
	if d := MeasurementDigest(sealTestRecord(t, 2)); !strings.HasPrefix(d, "unhashable:") {
		t.Errorf("MeasurementDigest = %q, want an unhashable marker", d)
	}
}
