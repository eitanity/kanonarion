package cyclonedx_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/sbom/adapters/generator/cyclonedx"
	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

// scopeBOM is the part of the document these tests read: the vulnerability list
// and the annotations that qualify it.
type scopeBOM struct {
	Vulnerabilities []struct {
		BOMRef     string          `json:"bom-ref"`
		ID         string          `json:"id"`
		Analysis   json.RawMessage `json:"analysis"`
		Properties json.RawMessage `json:"properties"`
	} `json:"vulnerabilities"`
	Annotations []struct {
		BOMRef    string   `json:"bom-ref"`
		Subjects  []string `json:"subjects"`
		Timestamp string   `json:"timestamp"`
		Text      string   `json:"text"`
		Annotator struct {
			Component struct {
				Name string `json:"name"`
			} `json:"component"`
		} `json:"annotator"`
	} `json:"annotations"`
}

func generateWithTwoAdvisories(t *testing.T) ([]byte, scopeBOM) {
	t.Helper()
	coord := mustCoord(t, "github.com/golang-jwt/jwt/v4", "v4.5.1")
	walk := makeWalk(t, []coordinate.ModuleCoordinate{coord})
	gen := cyclonedx.New(testPipelineVersion)

	scanRunID := "scan-scope"
	records := []vulndomain.VulnerabilityRecord{{
		Coordinate:     coord,
		OverallStatus:  vulndomain.StatusAffected,
		CoverageStatus: vulndomain.CoverageAnalysed,
		FindingsStatus: vulndomain.FindingsRecordAffected,
		Findings: []vulndomain.VulnerabilityFinding{
			{ID: "GO-2025-3553", Summary: "unverified parse"},
			{ID: "GO-2024-1111", Summary: "another"},
		},
	}}

	rec, err := gen.Generate(t.Context(), walk, nil, records, makeGenReq(&scanRunID))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var bom scopeBOM
	if err := json.Unmarshal(rec.Content, &bom); err != nil {
		t.Fatalf("unmarshal bom: %v", err)
	}
	return rec.Content, bom
}

// The defect, measured on a CycloneDX 1.6 document for a real project: 52
// vulnerabilities emitted, one carrying any analysis at all, while the store
// held reachability answers for the same scan. A reader could not tell that the
// difference between a reachable and an unreachable advisory was known, or that
// it could be obtained. The document now states its own scope.
func TestGenerate_VulnerabilityListStatesItsScope(t *testing.T) {
	_, bom := generateWithTwoAdvisories(t)

	if len(bom.Annotations) != 1 {
		t.Fatalf("annotations = %d, want exactly the scope statement", len(bom.Annotations))
	}
	a := bom.Annotations[0]
	for _, want := range []string{
		"does NOT state whether any of them is reachable in this build",
		cyclonedx.ReachabilityQueryInvocation,
		"not proof that none exists",
	} {
		if !strings.Contains(a.Text, want) {
			t.Errorf("scope statement missing %q:\n%s", want, a.Text)
		}
	}
	if a.Annotator.Component.Name != "kanonarion" {
		t.Errorf("annotator = %q, want the generator naming itself", a.Annotator.Component.Name)
	}
}

// The statement is subject-linked to the vulnerability entries themselves, not
// filed under metadata: a consumer asking "what does this document say about
// this entry" resolves it by bom-ref, and one rendering the list meets it there.
func TestGenerate_ScopeStatementIsSubjectLinkedToEveryAdvisory(t *testing.T) {
	_, bom := generateWithTwoAdvisories(t)

	want := make(map[string]bool, len(bom.Vulnerabilities))
	for _, v := range bom.Vulnerabilities {
		want[v.BOMRef] = true
	}
	if len(want) == 0 {
		t.Fatal("no vulnerabilities emitted; this test measures nothing")
	}
	for _, s := range bom.Annotations[0].Subjects {
		delete(want, s)
	}
	if len(want) != 0 {
		t.Errorf("advisories not covered by the scope statement: %v", want)
	}
}

// No VEX. A per-advisory reachability claim — an analysis block, a property, any
// shape — would freeze at generation time an answer that improves as the graph
// improves, and would publish exactly the context-free verdict this tool exists
// to replace. A live advisory therefore carries neither.
func TestGenerate_NoPerAdvisoryReachabilityClaim(t *testing.T) {
	_, bom := generateWithTwoAdvisories(t)

	for _, v := range bom.Vulnerabilities {
		if len(v.Analysis) != 0 {
			t.Errorf("%s carries an analysis block: %s", v.ID, v.Analysis)
		}
		if len(v.Properties) != 0 {
			t.Errorf("%s carries properties: %s", v.ID, v.Properties)
		}
	}
}

// A document with no advisories has no list to qualify, and a statement about a
// list that is not there would be noise a reader has to rule out.
func TestGenerate_NoVulnerabilitiesNoScopeAnnotation(t *testing.T) {
	coord := mustCoord(t, "github.com/example/foo", "v1.0.0")
	walk := makeWalk(t, []coordinate.ModuleCoordinate{coord})
	gen := cyclonedx.New(testPipelineVersion)

	rec, err := gen.Generate(t.Context(), walk, nil, nil, makeGenReq(nil))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var bom scopeBOM
	if err := json.Unmarshal(rec.Content, &bom); err != nil {
		t.Fatalf("unmarshal bom: %v", err)
	}
	if len(bom.Annotations) != 0 {
		t.Errorf("annotations emitted for a document with no vulnerability list: %+v", bom.Annotations)
	}
}

// Byte-identical re-emission from the same inputs is a shipped property of this
// generator, and the statement must not cost it. Every field of the annotation
// is derived from inputs the document already carries — a fixed bom-ref, the
// aggregation's own vulnerability order, and the document's clock-free
// timestamp — so a second generation reproduces it exactly.
func TestGenerate_ScopeStatementKeepsTheDocumentDeterministic(t *testing.T) {
	first, _ := generateWithTwoAdvisories(t)
	second, _ := generateWithTwoAdvisories(t)
	if string(first) != string(second) {
		t.Error("two generations from identical inputs produced different bytes")
	}
}
