package cyclonedx_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/sbom/adapters/generator/cyclonedx"
	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

// TestGenerate_WithdrawnAdvisoryIsMarkedNotOmitted covers the SBOM's own copy of
// the withdrawn-advisory defect. The generator projected every finding on every
// record straight into the document, so a retracted advisory was published to
// third parties as a live vulnerability of the component, identical in shape to
// the ones beside it.
//
// It is marked rather than dropped: a document that simply omitted it would be
// indistinguishable from one produced before the advisory was ever published, and
// a consumer diffing two SBOMs across the retraction would read the disappearance
// as a fix — the same unattributed resolution the CLI diff had.
func TestGenerate_WithdrawnAdvisoryIsMarkedNotOmitted(t *testing.T) {
	coord := mustCoord(t, "go.etcd.io/bbolt", "v1.4.3")
	walk := makeWalk(t, []coordinate.ModuleCoordinate{coord})
	gen := cyclonedx.New(testPipelineVersion)

	scanRunID := "scan-withdrawn"
	records := []vulndomain.VulnerabilityRecord{{
		Coordinate:     coord,
		OverallStatus:  vulndomain.StatusWithdrawn,
		CoverageStatus: vulndomain.CoverageAnalysed,
		FindingsStatus: vulndomain.FindingsRecordWithdrawn,
		Findings: []vulndomain.VulnerabilityFinding{{
			ID:          "GO-2026-4923",
			Summary:     "WITHDRAWN: out-of-range-index in go.etcd.io/bbolt",
			WithdrawnAt: time.Date(2026, 4, 8, 13, 33, 56, 0, time.UTC),
		}},
	}}

	rec, err := gen.Generate(t.Context(), walk, nil, records, makeGenReq(&scanRunID))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var bom struct {
		Vulnerabilities []struct {
			ID       string `json:"id"`
			Analysis *struct {
				State  string `json:"state"`
				Detail string `json:"detail"`
			} `json:"analysis"`
			Ratings json.RawMessage `json:"ratings"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(rec.Content, &bom); err != nil {
		t.Fatalf("unmarshal bom: %v", err)
	}

	if len(bom.Vulnerabilities) != 1 {
		t.Fatalf("vulnerabilities = %d, want the retracted advisory retained", len(bom.Vulnerabilities))
	}
	v := bom.Vulnerabilities[0]
	if v.ID != "GO-2026-4923" {
		t.Errorf("vulnerability id = %q, want GO-2026-4923", v.ID)
	}
	if v.Analysis == nil {
		t.Fatal("no analysis block: the advisory is published as though it stood against the component")
	}
	if v.Analysis.State != "false_positive" {
		t.Errorf("analysis state = %q, want false_positive — the VEX state a consumer routes on", v.Analysis.State)
	}
	// The date is asserted, not just the word: the upstream summary already begins
	// "WITHDRAWN: ", so a detail string echoing that prose would pass a word-only
	// check on the unfixed tree.
	if !strings.Contains(v.Analysis.Detail, "2026-04-08T13:33:56Z") {
		t.Errorf("analysis detail = %q, want it to carry the retraction date", v.Analysis.Detail)
	}
	// A rating is a claim about how severely the advisory affects the component,
	// and a retracted advisory makes none. Leaving one on meant a consumer tallying
	// severities across the document counted a report that does not stand — and that
	// consumer need never read the analysis block to do the tally.
	if len(v.Ratings) != 0 {
		t.Errorf("a retracted advisory carries a severity rating: %s", v.Ratings)
	}
}

// TestGenerate_LiveAdvisoryCarriesNoAnalysis is the control. A change that
// attached false_positive to everything would satisfy the test above while
// silently excusing every real finding in the document.
func TestGenerate_LiveAdvisoryCarriesNoAnalysis(t *testing.T) {
	coord := mustCoord(t, "golang.org/x/text", "v0.37.0")
	walk := makeWalk(t, []coordinate.ModuleCoordinate{coord})
	gen := cyclonedx.New(testPipelineVersion)

	scanRunID := "scan-live"
	records := []vulndomain.VulnerabilityRecord{{
		Coordinate:     coord,
		OverallStatus:  vulndomain.StatusAffected,
		CoverageStatus: vulndomain.CoverageAnalysed,
		FindingsStatus: vulndomain.FindingsRecordAffected,
		Findings: []vulndomain.VulnerabilityFinding{{
			ID:      "GO-2026-5970",
			Summary: "Infinite loop on invalid input in golang.org/x/text",
		}},
	}}

	rec, err := gen.Generate(t.Context(), walk, nil, records, makeGenReq(&scanRunID))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var bom struct {
		Vulnerabilities []struct {
			ID       string          `json:"id"`
			Analysis json.RawMessage `json:"analysis"`
			Ratings  json.RawMessage `json:"ratings"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(rec.Content, &bom); err != nil {
		t.Fatalf("unmarshal bom: %v", err)
	}

	if len(bom.Vulnerabilities) != 1 {
		t.Fatalf("vulnerabilities = %d, want 1", len(bom.Vulnerabilities))
	}
	if len(bom.Vulnerabilities[0].Analysis) != 0 {
		t.Errorf("a live advisory carries an analysis block: %s", bom.Vulnerabilities[0].Analysis)
	}
	// The control for the ratings rule too: dropping ratings from everything would
	// satisfy the withdrawn assertion above while stripping severity from every real
	// finding in the document.
	if len(bom.Vulnerabilities[0].Ratings) == 0 {
		t.Error("a live advisory lost its severity rating")
	}
}
