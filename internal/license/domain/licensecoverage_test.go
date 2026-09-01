package domain_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/license/domain"
)

// coverageRecord builds a record around a set of licence files, with the
// expression and primary a pre-coverage pipeline would have derived. The tests
// below then ask what the coverage reading makes of it.
func coverageRecord(t *testing.T, expr, basis, primary string, files ...domain.LicenseFileEntry) domain.LicenseRecord {
	t.Helper()
	coord, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("building coordinate: %v", err)
	}
	rec := domain.LicenseRecord{
		SchemaVersion:   domain.LicenseSchemaVersion,
		Ecosystem:       fetchdomain.EcosystemGo,
		Coordinate:      coord,
		PrimarySPDX:     primary,
		Expression:      expr,
		ExpressionBasis: basis,
		LicenseFiles:    files,
		OverallStatus:   domain.LicenseStatusMultiple,
	}
	domain.SetLicenseCoverage(&rec)
	return rec
}

func coverageOf(t *testing.T, r domain.LicenseRecord, path string) domain.LicenseCoverage {
	t.Helper()
	for _, f := range r.LicenseFiles {
		if f.Path == path {
			return f.Coverage
		}
	}
	t.Fatalf("no licence file at %q", path)
	return domain.CoverageNotDetermined
}

// -- the two defects the fix answers --

// TestReadCoverage_EmbeddedFontLicenceIsNotThePrimary is the chroma instance.
// One root COPYING carries the module's MIT grant and the SIL Open Font Licence
// of a font it embeds, at the identical confidence. The font licence covered
// more of the file, so it won the primary and put a share-alike obligation on
// every consumer of a Go syntax-highlighting library.
func TestReadCoverage_EmbeddedFontLicenceIsNotThePrimary(t *testing.T) {
	rec := coverageRecord(t, "MIT AND OFL-1.1", "split: is licensed under", "OFL-1.1",
		domain.LicenseFileEntry{
			Path:       "COPYING",
			SPDX:       "OFL-1.1",
			Confidence: 0.977983777520278,
			AltMatches: []domain.AltMatch{{SPDX: "MIT", Confidence: 0.977983777520278}},
		},
	)
	got := domain.ReadCoverage(rec)
	if got.Expression != "MIT" {
		t.Errorf("expression = %q, want MIT", got.Expression)
	}
	if got.PrimarySPDX != "MIT" {
		t.Errorf("primary = %q, want MIT — the font licence must never hold it", got.PrimarySPDX)
	}
	if len(got.SetAside) != 1 || got.SetAside[0].SPDX != "OFL-1.1" ||
		got.SetAside[0].Coverage != domain.CoverageBundledComponent {
		t.Errorf("set aside = %+v, want OFL-1.1 as a bundled component", got.SetAside)
	}
	if c := coverageOf(t, rec, "COPYING"); c != domain.CoverageBundledComponent {
		t.Errorf("COPYING coverage = %v, want BundledComponent", c)
	}
	// The basis must say coverage took part, and must keep the reading it
	// displaced: an expression that changed with no recorded reason is what
	// ExpressionBasis exists to prevent.
	for _, want := range []string{"coverage:", "OFL-1.1", "split: is licensed under"} {
		if !strings.Contains(got.Basis, want) {
			t.Errorf("basis %q does not mention %q", got.Basis, want)
		}
	}
}

// TestReadCoverage_DocumentationLicenceIsNotConjoined is the go-digest and
// docker/go-metrics instance: a root LICENSE for the code beside a root
// LICENSE.docs for the documentation, conjoined into a claim that a consumer
// must satisfy both to use the module.
func TestReadCoverage_DocumentationLicenceIsNotConjoined(t *testing.T) {
	rec := coverageRecord(t, "Apache-2.0 AND CC-BY-SA-4.0", domain.BasisSeparateGrants, "Apache-2.0",
		domain.LicenseFileEntry{Path: "LICENSE", SPDX: "Apache-2.0", Confidence: 1},
		domain.LicenseFileEntry{Path: "LICENSE.docs", SPDX: "CC-BY-SA-4.0", Confidence: 0.8221667854597291},
	)
	got := domain.ReadCoverage(rec)
	if got.Expression != "Apache-2.0" {
		t.Errorf("expression = %q, want Apache-2.0", got.Expression)
	}
	if got.PrimarySPDX != "Apache-2.0" {
		t.Errorf("primary = %q, want Apache-2.0", got.PrimarySPDX)
	}
	if c := coverageOf(t, rec, "LICENSE"); c != domain.CoverageModuleCode {
		t.Errorf("LICENSE coverage = %v, want ModuleCode", c)
	}
	if c := coverageOf(t, rec, "LICENSE.docs"); c != domain.CoverageDocumentation {
		t.Errorf("LICENSE.docs coverage = %v, want Documentation", c)
	}
	// The conjunction is gone, so nothing downstream may still read it as one.
	if arms := domain.ConjunctionArms(got.Expression); len(arms) != 0 {
		t.Errorf("arms = %v, want none", arms)
	}
}

// TestReadCoverage_DocsLicenceIsNotDecidedByItsName is the guard on the signal
// itself. The identifiers and confidences are go-digest's; only the file names
// are ordinary. A rule keyed on "LICENSE.docs" would answer differently here,
// and this fix must not.
func TestReadCoverage_DocsLicenceIsNotDecidedByItsName(t *testing.T) {
	rec := coverageRecord(t, "Apache-2.0 AND CC-BY-SA-4.0", domain.BasisSeparateGrants, "Apache-2.0",
		domain.LicenseFileEntry{Path: "LICENSE", SPDX: "Apache-2.0", Confidence: 1},
		domain.LicenseFileEntry{Path: "COPYING", SPDX: "CC-BY-SA-4.0", Confidence: 0.82},
	)
	if got := domain.ReadCoverage(rec).Expression; got != "Apache-2.0" {
		t.Errorf("expression = %q, want Apache-2.0 — the instrument decides, not the file name", got)
	}
	if c := coverageOf(t, rec, "COPYING"); c != domain.CoverageDocumentation {
		t.Errorf("COPYING coverage = %v, want Documentation", c)
	}
}

// -- the negative controls --

// TestReadCoverage_CC0IsACodeLicence is the control the ticket made explicit
// and the one an over-broad fix fails. CC0-1.0 is a Creative Commons instrument
// and a legitimate licence for Go source; zeebo/blake3 ships it as LICENSE and
// dchest/uniuri as COPYING — the same file name that carries chroma's font
// licence, which is the whole point.
func TestReadCoverage_CC0IsACodeLicence(t *testing.T) {
	for _, path := range []string{"LICENSE", "COPYING"} {
		rec := coverageRecord(t, "CC0-1.0", "", "CC0-1.0",
			domain.LicenseFileEntry{Path: path, SPDX: "CC0-1.0", Confidence: 0.99},
		)
		got := domain.ReadCoverage(rec)
		if got.Expression != "CC0-1.0" || got.PrimarySPDX != "CC0-1.0" || len(got.SetAside) != 0 {
			t.Errorf("%s: %+v, want CC0-1.0 untouched", path, got)
		}
		if c := coverageOf(t, rec, path); c != domain.CoverageModuleCode {
			t.Errorf("%s coverage = %v, want ModuleCode", path, c)
		}
	}
}

// TestReadCoverage_CC0BesideACodeLicenceStaysCode guards the same control in
// the shape the defect lives in: a conjunction. A CC0-1.0 arm beside an
// Apache-2.0 arm is two code grants, not a code grant and a content grant.
func TestReadCoverage_CC0BesideACodeLicenceStaysCode(t *testing.T) {
	rec := coverageRecord(t, "Apache-2.0 AND CC0-1.0", domain.BasisSeparateGrants, "Apache-2.0",
		domain.LicenseFileEntry{Path: "LICENSE", SPDX: "Apache-2.0", Confidence: 1},
		domain.LicenseFileEntry{Path: "LICENSE.cc0", SPDX: "CC0-1.0", Confidence: 0.99},
	)
	got := domain.ReadCoverage(rec)
	if got.Expression != "Apache-2.0 AND CC0-1.0" {
		t.Errorf("expression = %q, want the conjunction untouched", got.Expression)
	}
	if len(got.SetAside) != 0 {
		t.Errorf("set aside %+v, want none", got.SetAside)
	}
}

// TestReadCoverage_GenuineFontPackageKeepsItsElection is the second control.
// codeberg.org/go-fonts/liberation elects between BSD-3-Clause and OFL-1.1, and
// its OFL-1.1 covers the fonts the module IS. An election is the module's own
// statement that either grant governs the whole work, so neither arm is set
// aside and neither file's coverage is demoted.
func TestReadCoverage_GenuineFontPackageKeepsItsElection(t *testing.T) {
	rec := coverageRecord(t, "BSD-3-Clause OR OFL-1.1",
		"election: one file per licence (LICENSE, LICENSE-SIL)", "BSD-3-Clause",
		domain.LicenseFileEntry{Path: "LICENSE", SPDX: "BSD-3-Clause", Confidence: 1},
		domain.LicenseFileEntry{Path: "LICENSE-SIL", SPDX: "OFL-1.1", Confidence: 1},
	)
	got := domain.ReadCoverage(rec)
	if got.Expression != "BSD-3-Clause OR OFL-1.1" || got.PrimarySPDX != "BSD-3-Clause" {
		t.Errorf("%+v, want the election untouched", got)
	}
	if c := coverageOf(t, rec, "LICENSE-SIL"); c != domain.CoverageModuleCode {
		t.Errorf("LICENSE-SIL coverage = %v, want ModuleCode — the module elected it", c)
	}
}

// TestReadCoverage_OneRootLicenceNeverMoves is the control that matters most by
// volume: 1,809 of the maintainer's 1,828 records carry no conjunction at all,
// and not one of them may move.
func TestReadCoverage_OneRootLicenceNeverMoves(t *testing.T) {
	for _, spdx := range []string{"MIT", "Apache-2.0", "BSD-3-Clause", "MPL-2.0", "ISC", "GPL-3.0"} {
		rec := coverageRecord(t, spdx, "", spdx,
			domain.LicenseFileEntry{Path: "LICENSE", SPDX: spdx, Confidence: 1},
		)
		got := domain.ReadCoverage(rec)
		if got.Expression != spdx || got.PrimarySPDX != spdx || got.Basis != "" || len(got.SetAside) != 0 {
			t.Errorf("%s moved: %+v", spdx, got)
		}
		if c := coverageOf(t, rec, "LICENSE"); c != domain.CoverageModuleCode {
			t.Errorf("%s coverage = %v, want ModuleCode", spdx, c)
		}
	}
}

// TestReadCoverage_LoneNonCodeInstrumentIsUndetermined is the honesty case. A
// module whose ONLY grant is a font or content instrument may genuinely be
// licensed that way — the ajstarks modules the ticket refused to claim as
// instances are exactly this — so nothing is demoted and the record says the
// coverage was not determined rather than guessing either way.
func TestReadCoverage_LoneNonCodeInstrumentIsUndetermined(t *testing.T) {
	for _, spdx := range []string{"OFL-1.1", "CC-BY-4.0", "CC-BY-SA-4.0", "GFDL-1.3"} {
		rec := coverageRecord(t, spdx, "", spdx,
			domain.LicenseFileEntry{Path: "LICENSE", SPDX: spdx, Confidence: 0.98},
		)
		got := domain.ReadCoverage(rec)
		if got.Expression != spdx || got.PrimarySPDX != spdx {
			t.Errorf("%s moved: %+v", spdx, got)
		}
		if c := coverageOf(t, rec, "LICENSE"); c != domain.CoverageNotDetermined {
			t.Errorf("%s coverage = %v, want NotDetermined", spdx, c)
		}
	}
}

// TestReadCoverage_UnknownInstrumentIsNeverSetAside pins the default. An
// identifier the subject tables do not name cannot be classified, so it is left
// exactly as it was found — a new licence in the corpus must never be silently
// demoted out of a module's expression.
func TestReadCoverage_UnknownInstrumentIsNeverSetAside(t *testing.T) {
	rec := coverageRecord(t, "MIT AND SomeNewLicence-1.0", domain.BasisSeparateGrants, "MIT",
		domain.LicenseFileEntry{Path: "LICENSE", SPDX: "MIT", Confidence: 1},
		domain.LicenseFileEntry{Path: "LICENSE.other", SPDX: "SomeNewLicence-1.0", Confidence: 0.9},
	)
	got := domain.ReadCoverage(rec)
	if got.Expression != "MIT AND SomeNewLicence-1.0" || len(got.SetAside) != 0 {
		t.Errorf("%+v, want the conjunction untouched", got)
	}
	if c := coverageOf(t, rec, "LICENSE.other"); c != domain.CoverageNotDetermined {
		t.Errorf("unknown instrument coverage = %v, want NotDetermined", c)
	}
}

// TestReadCoverage_ConjunctionOfCodeLicencesIsUntouched covers the fifteen
// conjunctions in the maintainer's store that are not instances: yaml's
// Apache-2.0 AND MIT, thrift's Apache-2.0 AND BSD-3-Clause, and the three-armed
// sigs.k8s.io/yaml.
func TestReadCoverage_ConjunctionOfCodeLicencesIsUntouched(t *testing.T) {
	for _, expr := range []string{
		"Apache-2.0 AND MIT",
		"Apache-2.0 AND BSD-3-Clause",
		"Apache-2.0 AND BSD-3-Clause AND MIT",
	} {
		rec := coverageRecord(t, expr, domain.BasisSeparateGrants, "Apache-2.0",
			domain.LicenseFileEntry{Path: "LICENSE", SPDX: "Apache-2.0", Confidence: 1},
			domain.LicenseFileEntry{Path: "LICENSE.libyaml", SPDX: "MIT", Confidence: 1},
			domain.LicenseFileEntry{Path: "LICENSE.Golang", SPDX: "BSD-3-Clause", Confidence: 1},
		)
		got := domain.ReadCoverage(rec)
		if got.Expression != expr || got.Basis != domain.BasisSeparateGrants || len(got.SetAside) != 0 {
			t.Errorf("%q moved: %+v", expr, got)
		}
	}
}

// -- coverage of the entries that already stated what they relate to --

// TestSetLicenseCoverage_ReconcilesWithTheFactsAlreadyRecorded checks the field
// against the two an entry already carried. A third answer that disagreed with
// IsVendored or IsPerFile would leave a reader three ways to ask one question.
func TestSetLicenseCoverage_ReconcilesWithTheFactsAlreadyRecorded(t *testing.T) {
	rec := coverageRecord(t, "MIT", "", "MIT",
		domain.LicenseFileEntry{Path: "LICENSE", SPDX: "MIT", Confidence: 1},
		domain.LicenseFileEntry{Path: "NOTICE", SPDX: "Apache-2.0", Confidence: 1},
		domain.LicenseFileEntry{Path: "vendor/x/LICENSE", SPDX: "BSD-3-Clause", Confidence: 1, IsVendored: true},
		domain.LicenseFileEntry{Path: "cmd/tool/LICENSE", SPDX: "Apache-2.0", Confidence: 1},
		domain.LicenseFileEntry{Path: "main.go", SPDX: "MIT", Confidence: 1, IsPerFile: true},
		domain.LicenseFileEntry{Path: "LICENSE.unreadable", SPDX: "", Confidence: 0},
	)
	want := map[string]domain.LicenseCoverage{
		"LICENSE":            domain.CoverageModuleCode,
		"NOTICE":             domain.CoverageAttributionOnly,
		"vendor/x/LICENSE":   domain.CoverageBundledComponent,
		"cmd/tool/LICENSE":   domain.CoverageModuleCode,
		"main.go":            domain.CoverageModuleCode,
		"LICENSE.unreadable": domain.CoverageNotDetermined,
	}
	for path, w := range want {
		if got := coverageOf(t, rec, path); got != w {
			t.Errorf("%s coverage = %v, want %v", path, got, w)
		}
	}
}

// TestSetLicenseCoverage_NoticeIsNotAGrant pins the distinction the store makes
// visible: 85 entries in the maintainer's licence records are a NOTICE, and 21
// of them were matched to Apache-2.0 by the detector. Reporting those as
// "coverage not determined" would state a settled fact as a doubt.
func TestSetLicenseCoverage_NoticeIsNotAGrant(t *testing.T) {
	rec := coverageRecord(t, "Apache-2.0", "", "Apache-2.0",
		domain.LicenseFileEntry{Path: "LICENSE", SPDX: "Apache-2.0", Confidence: 1},
		domain.LicenseFileEntry{Path: "NOTICE", SPDX: "Apache-2.0", Confidence: 1},
	)
	if got := coverageOf(t, rec, "NOTICE"); got != domain.CoverageAttributionOnly {
		t.Errorf("NOTICE coverage = %v, want AttributionOnly", got)
	}
}

// -- properties the reading has to keep --

// TestReadCoverage_IsIdempotent proves an already corrected record is left
// alone. Extraction stores the corrected expression and the surfaces apply the
// same reading again on the way out; if the second pass moved anything, the two
// legs would disagree about the same record.
func TestReadCoverage_IsIdempotent(t *testing.T) {
	rec := coverageRecord(t, "MIT AND OFL-1.1", "split: is licensed under", "OFL-1.1",
		domain.LicenseFileEntry{
			Path:       "COPYING",
			SPDX:       "OFL-1.1",
			Confidence: 0.98,
			AltMatches: []domain.AltMatch{{SPDX: "MIT", Confidence: 0.98}},
		},
	)
	once := domain.ReadCoverage(rec)
	rec.Expression, rec.ExpressionBasis, rec.PrimarySPDX = once.Expression, once.Basis, once.PrimarySPDX
	domain.SetLicenseCoverage(&rec)
	twice := domain.ReadCoverage(rec)
	if twice.Expression != once.Expression || twice.PrimarySPDX != once.PrimarySPDX || twice.Basis != once.Basis {
		t.Errorf("second reading moved: %+v then %+v", once, twice)
	}
	if c := coverageOf(t, rec, "COPYING"); c != domain.CoverageBundledComponent {
		t.Errorf("COPYING coverage after re-derivation = %v, want BundledComponent", c)
	}
}

// TestLicenseCoverage_IsOutsideTheContentHash is the reason this change owes no
// pipeline bump. Coverage is derived on every load, so a record written before
// the field existed must still verify against the hash it was sealed with.
func TestLicenseCoverage_IsOutsideTheContentHash(t *testing.T) {
	rec := coverageRecord(t, "Apache-2.0 AND CC-BY-SA-4.0", domain.BasisSeparateGrants, "Apache-2.0",
		domain.LicenseFileEntry{Path: "LICENSE", SPDX: "Apache-2.0", Confidence: 1},
		domain.LicenseFileEntry{Path: "LICENSE.docs", SPDX: "CC-BY-SA-4.0", Confidence: 0.82},
	)
	rec.ExtractedAt = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	var h domain.LicenseRecordHasher
	sealed, err := h.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	raw, err := h.Marshal(sealed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(raw), "overage\":\"Module") || strings.Contains(string(raw), "AttributionOnly") {
		t.Fatalf("coverage reached the hashed shape: %s", raw)
	}
	back, err := h.Unmarshal(raw)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if err := h.VerifyContentHash(back); err != nil {
		t.Errorf("a record carrying derived coverage must still verify: %v", err)
	}
	// And the load recomputed it, so a record written before the field existed
	// answers the question too.
	if c := coverageOf(t, back, "LICENSE.docs"); c != domain.CoverageDocumentation {
		t.Errorf("coverage after a round trip = %v, want Documentation", c)
	}
}

func TestLicenseCoverageJSON(t *testing.T) {
	cases := []struct {
		c    domain.LicenseCoverage
		want string
	}{
		{domain.CoverageNotDetermined, `"NotDetermined"`},
		{domain.CoverageModuleCode, `"ModuleCode"`},
		{domain.CoverageDocumentation, `"Documentation"`},
		{domain.CoverageBundledComponent, `"BundledComponent"`},
		{domain.CoverageAttributionOnly, `"AttributionOnly"`},
	}
	for _, tc := range cases {
		b, err := json.Marshal(tc.c)
		if err != nil {
			t.Fatalf("json.Marshal(%v): %v", tc.c, err)
		}
		if got := string(b); got != tc.want {
			t.Errorf("json.Marshal(%v) = %s, want %s", tc.c, got, tc.want)
		}
		var back domain.LicenseCoverage
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatalf("json.Unmarshal(%s): %v", b, err)
		}
		if back != tc.c {
			t.Errorf("round trip of %v gave %v", tc.c, back)
		}
	}
	var c domain.LicenseCoverage
	if err := json.Unmarshal([]byte(`"moduleCode"`), &c); err == nil {
		t.Error("a name that is not a LicenseCoverage must be refused")
	}
	if err := json.Unmarshal([]byte(`1`), &c); err == nil {
		t.Error("an ordinal must be refused: the wire form is the name")
	}
}
