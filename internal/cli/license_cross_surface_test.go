package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"

	licapp "github.com/eitanity/kanonarion/internal/license/application"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
	licenseports "github.com/eitanity/kanonarion/internal/license/ports"
	sbomdomain "github.com/eitanity/kanonarion/internal/sbom/domain"
)

// One module, read through every surface that answers "what is this module
// licensed under". They must all give the same answer.
//
// The defect this guards was exactly a disagreement: a module whose own licence
// is BSD-3-Clause, bundling a Boost-licensed component under
// THIRD_PARTY_LICENSES, read as BSD-3-Clause on nine surfaces and as BSL-1.0 on
// license-compat — because license-compat answered from the effective set (root
// PLUS bundled components) while every other surface answers from the record's
// own expression. Bundled components are a real obligation, so the fix is not
// to drop them; it is that license-compat says whose licence each identifier is
// and reports the module's own alongside.
//
// inspect is not a separate derivation: runInspect delegates to runContext, so
// inspect and context share buildLicense and licenseSummaryLine. The test
// exercises the shared path once and says so rather than counting it twice.

// crossSurfaceRecord is the fixture: BSD-3-Clause root, BSL-1.0 bundled under
// THIRD_PARTY_LICENSES, MIT under a testdata corpus. Shaped after the module in
// the report.
func crossSurfaceRecord(t *testing.T) (licdomain.LicenseRecord, coordinate.ModuleCoordinate) {
	t.Helper()
	coord := coordinatetest.MustNew("example.com/numerics", "v0.16.0")
	rec := licdomain.LicenseRecord{
		Coordinate:    coord,
		PrimarySPDX:   "BSD-3-Clause",
		Expression:    "BSD-3-Clause",
		OverallStatus: licdomain.LicenseStatusDetected,
		LicenseFiles: []licdomain.LicenseFileEntry{
			{Path: "LICENSE", SPDX: "BSD-3-Clause", Confidence: 1},
			{Path: "THIRD_PARTY_LICENSES/Boost-LICENSE", SPDX: "BSL-1.0", Confidence: 1},
			{Path: "graph/formats/example/testdata/LICENSE", SPDX: "MIT", Confidence: 1},
		},
	}
	rec.EffectiveSet = licdomain.DeriveEffectiveLicenseSet(rec.LicenseFiles)
	// Guard the fixture itself: if the effective set stopped carrying the
	// bundled identifier the test would pass for the wrong reason.
	if !containsString(rec.EffectiveSet.AllSPDXs, "BSL-1.0") {
		t.Fatalf("fixture no longer models the bundled component: %+v", rec.EffectiveSet)
	}
	return rec, coord
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// TestModuleLicenceReadsIdenticallyOnEverySurface is the test that would have
// caught the defect.
func TestModuleLicenceReadsIdenticallyOnEverySurface(t *testing.T) {
	rec, coord := crossSurfaceRecord(t)
	const want = "BSD-3-Clause"

	// Each surface reports the module's own licence through the production
	// function it actually uses.
	surfaces := map[string]string{
		"license (text)":    licenceFromLicenseText(t, rec),
		"license (--json)":  licenceFromLicenseJSON(t, rec),
		"license-list":      licenceFromLicenseList(rec),
		"audit":             licenceFromAudit(rec),
		"sbom":              sbomdomain.LicenseClause(true, rec.PrimarySPDX, rec.Expression),
		"context / inspect": licenceFromContext(t, coord, rec),
		"license-compat":    licenceFromLicenseCompat(t, coord, rec),
	}

	for surface, got := range surfaces {
		if got != want {
			t.Errorf("%s reports the module's licence as %q, want %q — "+
				"every surface must answer this question the same way", surface, got, want)
		}
	}
}

// TestBundledComponentNeverPresentedAsTheModuleLicence: the bundled identifier
// must not reach any surface's "this module's licence" answer, and where
// license-compat does report it (as an obligation the module carries) it must
// be marked as the component's.
func TestBundledComponentNeverPresentedAsTheModuleLicence(t *testing.T) {
	rec, coord := crossSurfaceRecord(t)

	for surface, got := range map[string]string{
		"license (text)":    licenceFromLicenseText(t, rec),
		"license (--json)":  licenceFromLicenseJSON(t, rec),
		"license-list":      licenceFromLicenseList(rec),
		"audit":             licenceFromAudit(rec),
		"sbom":              sbomdomain.LicenseClause(true, rec.PrimarySPDX, rec.Expression),
		"context / inspect": licenceFromContext(t, coord, rec),
		"license-compat":    licenceFromLicenseCompat(t, coord, rec),
	} {
		if strings.Contains(got, "BSL-1.0") {
			t.Errorf("%s reports the bundled component's licence as the module's: %q", surface, got)
		}
		if strings.Contains(got, "MIT") {
			t.Errorf("%s reports a testdata corpus licence as the module's: %q", surface, got)
		}
	}
}

// -- per-surface readers, each using the surface's own production path --

func licenceFromLicenseText(t *testing.T, rec licdomain.LicenseRecord) string {
	t.Helper()
	var buf bytes.Buffer
	if err := printLicenseRecord(rec, false, false, &buf); err != nil {
		t.Fatalf("license text: %v", err)
	}
	// "<mod>@<ver>: <status> — <licence>"
	line := strings.SplitN(buf.String(), "\n", 2)[0]
	idx := strings.LastIndex(line, "— ")
	if idx < 0 {
		t.Fatalf("license text has no licence field: %q", line)
	}
	return strings.TrimSpace(line[idx+len("— "):])
}

func licenceFromLicenseJSON(t *testing.T, rec licdomain.LicenseRecord) string {
	t.Helper()
	var buf bytes.Buffer
	prev := jsonOut
	jsonOut = true
	defer func() { jsonOut = prev }()
	if err := printLicenseRecord(rec, false, true, &buf); err != nil {
		t.Fatalf("license json: %v", err)
	}
	var out struct {
		PrimarySPDX string `json:"PrimarySPDX"`
		Expression  string `json:"Expression"`
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("decoding license json: %v\n%s", err, buf.String())
	}
	if out.Expression != "" {
		return out.Expression
	}
	return out.PrimarySPDX
}

// licenceFromLicenseList mirrors runLicenseList's rule over the summary the
// store projects from the record. The summary is built here from the record's
// own fields, which is the projection the store performs.
func licenceFromLicenseList(rec licdomain.LicenseRecord) string {
	s := licenseports.LicenseSummary{
		PrimarySPDX:   rec.PrimarySPDX,
		Expression:    rec.Expression,
		OverallStatus: rec.OverallStatus,
	}
	license := s.PrimarySPDX
	if s.Expression != "" {
		license = s.Expression
	}
	return license
}

func licenceFromAudit(rec licdomain.LicenseRecord) string {
	display, _, _, _, _ := auditLicenceResolution(rec, true, nil, "", "")
	return display
}

func licenceFromContext(t *testing.T, coord coordinate.ModuleCoordinate, rec licdomain.LicenseRecord) string {
	t.Helper()
	fake := testfakes.NewFakeQueryLicense()
	fake.AddRecord(coord, licapp.PipelineVersion, rec)
	return licenseSummaryLine(buildLicense(context.Background(), coord, fake))
}

// licenceFromLicenseCompat reads the module's licence out of a compatibility
// report entry — the field a consumer is meant to use for that question. The
// module is put in a closure where it raises an entry (its bundled component is
// unmodelled against the target) so there is an entry to read.
func licenceFromLicenseCompat(t *testing.T, coord coordinate.ModuleCoordinate, rec licdomain.LicenseRecord) string {
	t.Helper()
	// A record whose bundled component is deliberately unmodelled, so the module
	// appears in the report at all.
	withUnmodelled := rec
	withUnmodelled.LicenseFiles = append(append([]licdomain.LicenseFileEntry(nil), rec.LicenseFiles...),
		licdomain.LicenseFileEntry{Path: "THIRD_PARTY_LICENSES/Docs-LICENSE", SPDX: "CC-BY-SA-4.0", Confidence: 1})
	withUnmodelled.EffectiveSet = licdomain.DeriveEffectiveLicenseSet(withUnmodelled.LicenseFiles)

	ctr, root := compatFromRecords(t, map[string]licdomain.LicenseRecord{
		coord.Path() + "@" + coord.Version(): withUnmodelled,
	})
	prev := jsonOut
	jsonOut = false
	defer func() { jsonOut = prev }()

	report, err := ctr.CheckCompatibility.CheckCompatibilityForWalk(
		context.Background(), "W1", root, "Apache-2.0", licdomain.NewLicenseOverrideSet(nil))
	if err != nil {
		t.Fatalf("license-compat: %v", err)
	}
	if len(report.Conflicts) == 0 {
		t.Fatal("license-compat raised no entry; nothing to read the module's licence from")
	}
	for _, c := range report.Conflicts {
		if c.ModulePath == coord.Path() {
			return c.ModuleExpression
		}
	}
	t.Fatalf("license-compat has no entry for %s", coord.Path())
	return ""
}
