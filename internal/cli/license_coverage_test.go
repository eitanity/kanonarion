package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	domain "github.com/eitanity/kanonarion/internal/license/domain"
)

// chromaRecord is github.com/alecthomas/chroma/v2 as the ledger holds it: one
// root COPYING whose most-covered match is the SIL Open Font Licence of a font
// the library embeds, with the library's own MIT grant recorded as an
// alternative match at the identical confidence.
func chromaRecord(t *testing.T) domain.LicenseRecord {
	t.Helper()
	coord, err := coordinate.NewModuleCoordinate("github.com/alecthomas/chroma/v2", "v2.27.0")
	if err != nil {
		t.Fatal(err)
	}
	return domain.LicenseRecord{
		Coordinate:      coord,
		OverallStatus:   domain.LicenseStatusMultiple,
		PrimarySPDX:     "OFL-1.1",
		Expression:      "MIT AND OFL-1.1",
		ExpressionBasis: "split: is licensed under",
		LicenseFiles: []domain.LicenseFileEntry{{
			Path:       "COPYING",
			SPDX:       "OFL-1.1",
			Confidence: 0.977983777520278,
			AltMatches: []domain.AltMatch{{SPDX: "MIT", Confidence: 0.977983777520278}},
		}},
	}
}

// TestPrintLicenseRecord_EmbeddedFontLicenceIsNotHandedToAConsumer is the
// wrong answer this fix exists for, on the rendered surface: a Go
// syntax-highlighting library reported as OFL-1.1, with a font's share-alike
// condition in the obligations a consumer is told they owe.
func TestPrintLicenseRecord_EmbeddedFontLicenceIsNotHandedToAConsumer(t *testing.T) {
	var buf bytes.Buffer
	if err := printLicenseRecord(chromaRecord(t), false, false, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "Multiple — MIT\n") {
		t.Errorf("the header does not report the library's own licence:\n%s", out)
	}
	if strings.Contains(out, "OFL-1.1)") || strings.Contains(out, "MIT AND OFL-1.1") {
		t.Errorf("the font licence is still published as a licence of this module:\n%s", out)
	}
	rows := obligationRowsUnder(t, out, "obligations (MIT")
	if rows["same-license"] != "none" {
		t.Errorf("a consumer is still handed the font's share-alike condition:\n%s", out)
	}
	if !strings.Contains(out, "COPYING: OFL-1.1 (98%) — covers a bundled component") {
		t.Errorf("the record does not say what the font licence covers:\n%s", out)
	}
	if !strings.Contains(out, "basis: coverage:") {
		t.Errorf("the expression changed with no recorded reason:\n%s", out)
	}
}

// TestLicenseJSON_EmbeddedFontLicenceIsNotHandedToAConsumer is the same
// instance on the surface a machine reads. It is asserted separately because a
// fix whose text was right while --json kept the old answer has shipped here
// before.
func TestLicenseJSON_EmbeddedFontLicenceIsNotHandedToAConsumer(t *testing.T) {
	var buf bytes.Buffer
	if err := printLicenseRecord(chromaRecord(t), false, true, &buf); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Primary     string         `json:"primary_spdx"`
		Expression  string         `json:"expression"`
		Basis       string         `json:"expression_basis"`
		Binding     map[string]any `json:"binding_obligations"`
		Reading     string         `json:"obligations_reading"`
		Obligations struct {
			SameLicense string `json:"same_license"`
		} `json:"obligations"`
		Files []struct {
			Path     string `json:"path"`
			SPDX     string `json:"spdx"`
			Coverage string `json:"coverage"`
		} `json:"license_files"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Primary != "MIT" || doc.Expression != "MIT" {
		t.Errorf("primary_spdx=%q expression=%q, want MIT for both", doc.Primary, doc.Expression)
	}
	if !strings.Contains(doc.Basis, "coverage:") || !strings.Contains(doc.Basis, "OFL-1.1") {
		t.Errorf("expression_basis = %q, must say coverage took part and name what it set aside", doc.Basis)
	}
	if doc.Obligations.SameLicense != "none" {
		t.Errorf("obligations.same_license = %q, want none — the weak share-alike was the font's",
			doc.Obligations.SameLicense)
	}
	if len(doc.Binding) != 0 || doc.Reading != "" {
		t.Errorf("binding_obligations=%v obligations_reading=%q, want absent: there is no conjunction left",
			doc.Binding, doc.Reading)
	}
	if len(doc.Files) != 1 || doc.Files[0].Coverage != "BundledComponent" {
		t.Errorf("license_files = %+v, want COPYING carrying BundledComponent", doc.Files)
	}
}

// TestLicenseJSON_CoverageIsEmittedAlways pins the rule the acceptance is
// explicit about: the field is present for every entry, including the ordinary
// code licence. An omitempty here would make "governs the code" indistinguishable
// from "this build does not derive coverage".
func TestLicenseJSON_CoverageIsEmittedAlways(t *testing.T) {
	coord, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	rec := domain.LicenseRecord{
		Coordinate:    coord,
		OverallStatus: domain.LicenseStatusDetected,
		PrimarySPDX:   "MIT",
		Expression:    "MIT",
		LicenseFiles: []domain.LicenseFileEntry{
			{Path: "LICENSE", SPDX: "MIT", Confidence: 0.99},
			{Path: "NOTICE", SPDX: "", Confidence: 0},
		},
	}
	var buf bytes.Buffer
	if err := printLicenseRecord(rec, false, true, &buf); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Expression string           `json:"expression"`
		Primary    string           `json:"primary_spdx"`
		Files      []map[string]any `json:"license_files"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Expression != "MIT" || doc.Primary != "MIT" {
		t.Errorf("an ordinary record moved: expression=%q primary=%q", doc.Expression, doc.Primary)
	}
	want := map[string]string{"LICENSE": "ModuleCode", "NOTICE": "AttributionOnly"}
	for _, f := range doc.Files {
		got, present := f["coverage"]
		if !present {
			t.Fatalf("license_files[%v] carries no coverage key", f["path"])
		}
		if got != want[f["path"].(string)] {
			t.Errorf("license_files[%v].coverage = %v, want %v", f["path"], got, want[f["path"].(string)])
		}
	}
}
