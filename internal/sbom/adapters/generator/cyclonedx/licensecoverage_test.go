package cyclonedx_test

import (
	"encoding/json"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	licensedomain "github.com/eitanity/kanonarion/internal/license/domain"
	"github.com/eitanity/kanonarion/internal/sbom/adapters/generator/cyclonedx"
)

// componentLicences is the slice of a generated document these tests read: the
// licence clause each component carries.
type componentLicences struct {
	Components []struct {
		Name     string `json:"name"`
		Licenses []struct {
			Expression string `json:"expression"`
			License    struct {
				ID string `json:"id"`
			} `json:"license"`
		} `json:"licenses"`
	} `json:"components"`
}

// clauseOf returns the licence clause the document states for one component.
func clauseOf(t *testing.T, bom componentLicences, name string) string {
	t.Helper()
	for _, c := range bom.Components {
		if c.Name != name || len(c.Licenses) == 0 {
			continue
		}
		if c.Licenses[0].Expression != "" {
			return c.Licenses[0].Expression
		}
		return c.Licenses[0].License.ID
	}
	t.Fatalf("no licence clause for component %q in %+v", name, bom.Components)
	return ""
}

// TestGenerate_AComponentsClauseIsTheLicenceCoveringItsCode is the SBOM leg of
// the coverage fix. github.com/alecthomas/chroma/v2 is a Go syntax-highlighting
// library whose root COPYING carries the library's MIT grant and the SIL Open
// Font Licence of a font it embeds; the document must not assert that the
// component is licensed OFL-1.1.
func TestGenerate_AComponentsClauseIsTheLicenceCoveringItsCode(t *testing.T) {
	coord := mustCoord(t, "github.com/alecthomas/chroma/v2", "v2.27.0")
	walk := makeWalk(t, []coordinate.ModuleCoordinate{coord})
	licenses := map[coordinate.ModuleCoordinate]licensedomain.LicenseRecord{
		coord: {
			PrimarySPDX:     "OFL-1.1",
			Expression:      "MIT AND OFL-1.1",
			ExpressionBasis: "split: is licensed under",
			ExtractedAt:     mustTime("2026-03-02T11:00:00Z"),
			LicenseFiles: []licensedomain.LicenseFileEntry{{
				Path:       "COPYING",
				SPDX:       "OFL-1.1",
				Confidence: 0.98,
				AltMatches: []licensedomain.AltMatch{{SPDX: "MIT", Confidence: 0.98}},
			}},
		},
	}

	rec, err := cyclonedx.New(testPipelineVersion).Generate(t.Context(), walk, licenses, makeGenReq())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var bom componentLicences
	if err := json.Unmarshal(rec.Content, &bom); err != nil {
		t.Fatalf("unmarshal bom: %v", err)
	}
	if got := clauseOf(t, bom, "github.com/alecthomas/chroma/v2"); got != "MIT" {
		t.Errorf("licence clause = %q, want MIT — the bundled font's licence is not this "+
			"component's licensing", got)
	}
}

// TestGenerate_AnOrdinaryComponentsClauseIsUnchanged is the control: the
// overwhelming majority of components carry one root licence over their code,
// and the clause the document states for them may not move.
func TestGenerate_AnOrdinaryComponentsClauseIsUnchanged(t *testing.T) {
	coord := mustCoord(t, "github.com/example/foo", "v1.0.0")
	walk := makeWalk(t, []coordinate.ModuleCoordinate{coord})
	licenses := map[coordinate.ModuleCoordinate]licensedomain.LicenseRecord{
		coord: {
			PrimarySPDX: "MIT",
			Expression:  "MIT",
			ExtractedAt: mustTime("2026-03-02T11:00:00Z"),
			LicenseFiles: []licensedomain.LicenseFileEntry{
				{Path: "LICENSE", SPDX: "MIT", Confidence: 0.99},
			},
		},
	}

	rec, err := cyclonedx.New(testPipelineVersion).Generate(t.Context(), walk, licenses, makeGenReq())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var bom componentLicences
	if err := json.Unmarshal(rec.Content, &bom); err != nil {
		t.Fatalf("unmarshal bom: %v", err)
	}
	if got := clauseOf(t, bom, "github.com/example/foo"); got != "MIT" {
		t.Errorf("licence clause = %q, want MIT", got)
	}
}
