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

// embeddedFontRecord is the second fixture, and it is the shape that broke the
// control above. github.com/alecthomas/chroma/v2 is a Go syntax-highlighting
// library whose one root COPYING carries the library's MIT grant and the SIL
// Open Font Licence of a Liberation font it embeds, at the identical
// confidence, with the font licence covering more of the file.
//
// The first fixture cannot stand in for it. There the bundled grant is under
// its own path, so it never entered the expression and every surface agreed
// without deciding anything. Here the bundled grant IS the record's stored
// primary, so agreeing requires each surface to read the record through what
// its licences cover — and the surfaces that did not were invisible while the
// only fixture was one where the question never arose.
func embeddedFontRecord(t *testing.T) (licdomain.LicenseRecord, coordinate.ModuleCoordinate) {
	t.Helper()
	coord := coordinatetest.MustNew("github.com/alecthomas/chroma/v2", "v2.27.0")
	rec := licdomain.LicenseRecord{
		Coordinate:      coord,
		PrimarySPDX:     "OFL-1.1",
		Expression:      "MIT AND OFL-1.1",
		ExpressionBasis: "split: is licensed under",
		OverallStatus:   licdomain.LicenseStatusMultiple,
		LicenseFiles: []licdomain.LicenseFileEntry{{
			Path:       "COPYING",
			SPDX:       "OFL-1.1",
			Confidence: 0.977983777520278,
			AltMatches: []licdomain.AltMatch{{SPDX: "MIT", Confidence: 0.977983777520278}},
		}},
	}
	rec.EffectiveSet = licdomain.DeriveEffectiveLicenseSet(rec.LicenseFiles)
	// Guard the fixture: the stored identity must still be the font's, or the
	// test would pass without the surfaces having to correct anything.
	if rec.PrimarySPDX != "OFL-1.1" || !strings.Contains(rec.Expression, "OFL-1.1") {
		t.Fatalf("fixture no longer models the embedded font licence: %+v", rec)
	}
	return rec, coord
}

// renderedLicenceOnEverySurface returns the licence each surface STATES as the
// module's own, read back out of what that surface actually printed, in both
// output modes.
//
// It is deliberately not a search for a forbidden identifier in the rendered
// bytes. A correct rendering of this fix prints the set-aside identifier on
// purpose — `license` lists the file it was found in, labelled with what it
// covers — so "OFL-1.1 does not appear" is a test that would fail on the right
// answer. What must not happen is the surface NAMING the module after it, and
// that is a specific field or phrase in each rendering, extracted here.
//
// Reading it back out of the rendering rather than off an intermediate value is
// what the two escaped failures needed. license-diff does not merely render its
// primary: it reasons from it and prints a conclusion — "No license changes:
// both sides declare OFL-1.1" — so the finding can be wrong while the field it
// came from looks right.
//
// Adding a surface here is the point: this list is the closed enumeration of
// every command that answers "what is this module licensed under", and a
// surface answering it while absent from this list is a surface nothing checks.
// license-list and license-diff were both absent, and both served the
// uncorrected answer for as long as they were.
//
// Three surfaces resolve one value that both their modes print (audit's display
// column, the SBOM's licence clause, the notice heading); they appear once and
// the key says so rather than pretending to two renderings.
func renderedLicenceOnEverySurface(t *testing.T, coord coordinate.ModuleCoordinate, rec licdomain.LicenseRecord) map[string]string {
	t.Helper()
	covered := licdomain.ReadCoverage(rec)
	return map[string]string{
		"license (text)":           licenceFromLicenseText(t, rec),
		"license (--json)":         licenceFromLicenseJSON(t, rec),
		"license-list (text)":      licenceFromRenderedLicenseList(t, rec, false),
		"license-list (--json)":    licenceFromRenderedLicenseList(t, rec, true),
		"license-diff (text)":      licenceFromRenderedLicenseDiff(t, rec),
		"license-diff (--json)":    licenceFromLicenseDiff(t, rec),
		"context / inspect (text)": licenceFromRenderedContextLine(t, coord, rec),
		"context / inspect (json)": licenceFromContext(t, coord, rec),
		"audit (both modes)":       licenceFromAudit(rec),
		"sbom (both modes)":        sbomdomain.LicenseClause(true, covered.PrimarySPDX, covered.Expression),
		"notice (both modes)":      licenceFromNotice(rec),
		"license-compat (both)":    licenceFromLicenseCompat(t, coord, rec),
	}
}

// licenceFromRenderedLicenseList runs the listing command and reads the licence
// back out of the row it printed.
//
// The row is built by the production projection, so what is faked is the SQL
// fetch and nothing else — handing the command a summary the test assembled
// would be the mirror that let this surface drift in the first place.
func licenceFromRenderedLicenseList(t *testing.T, rec licdomain.LicenseRecord, asJSON bool) string {
	t.Helper()
	fake := testfakes.NewFakeQueryLicense()
	fake.SetList([]licenseports.LicenseSummary{licenseports.WithLicenceIdentity(
		licenseports.LicenseSummary{
			ModulePath:      rec.Coordinate.Path(),
			ModuleVersion:   rec.Coordinate.Version(),
			PipelineVersion: licapp.PipelineVersion,
			OverallStatus:   rec.OverallStatus,
			ExtractedAt:     rec.ExtractedAt,
			ContentHash:     rec.ContentHash,
		}, rec)})
	prev := jsonOut
	jsonOut = asJSON
	defer func() { jsonOut = prev }()
	var stdout, stderr bytes.Buffer
	if err := runLicenseList(context.Background(), "", "", 0, 0, fake,
		licdomain.NewLicenseOverrideSet(nil), &stdout, &stderr); err != nil {
		t.Fatalf("license-list: %v", err)
	}
	out := stdout.String()
	if asJSON {
		var doc struct {
			Records []struct {
				License string `json:"license"`
			} `json:"records"`
		}
		if err := json.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatalf("decoding license-list json: %v\n%s", err, out)
		}
		if len(doc.Records) != 1 {
			t.Fatalf("license-list listed %d rows, want 1:\n%s", len(doc.Records), out)
		}
		return doc.Records[0].License
	}
	// "<module>@<version>  <status>  <licence>  <source>"
	fields := strings.Fields(out)
	if len(fields) < 4 {
		t.Fatalf("license-list row has no licence column: %q", out)
	}
	return strings.Join(fields[2:len(fields)-1], " ")
}

// licenceFromRenderedLicenseDiff reads the licence out of the CONCLUSION the
// diff prints. Both sides are the same record, so the diff must report no
// change and name that record's licence in the sentence it states.
func licenceFromRenderedLicenseDiff(t *testing.T, rec licdomain.LicenseRecord) string {
	t.Helper()
	var buf bytes.Buffer
	if err := printLicenseDiff(licdomain.DiffRecords(rec, rec), &buf); err != nil {
		t.Fatalf("license-diff text: %v", err)
	}
	out := buf.String()
	const marker = "both sides declare "
	idx := strings.Index(out, marker)
	if idx < 0 {
		t.Fatalf("license-diff printed no no-change conclusion to read:\n%s", out)
	}
	rest := out[idx+len(marker):]
	end := strings.Index(rest, " at status")
	if end < 0 {
		t.Fatalf("license-diff conclusion has no licence field:\n%s", out)
	}
	return rest[:end]
}

// licenceFromRenderedContextLine reads the licence out of the one-line summary
// `context` and `inspect` print for a module.
func licenceFromRenderedContextLine(t *testing.T, coord coordinate.ModuleCoordinate, rec licdomain.LicenseRecord) string {
	t.Helper()
	fake := testfakes.NewFakeQueryLicense()
	fake.AddRecord(coord, licapp.PipelineVersion, rec)
	line := licenseSummaryLine(buildLicense(context.Background(), coord, fake, nil))
	return strings.TrimSpace(strings.SplitN(line, " ", 2)[0])
}

// TestEverySurfaceRendersTheLicenceCoveringTheCode is the guard on the printed
// answer, in both modes, for every licence-reading command.
//
// It compares what each surface PRINTS, not the field it resolved. Both
// failures that escaped the earlier control were downstream of the field: a
// listing row assembled from the indexed columns, and a prose conclusion
// reasoned from a stale primary.
func TestEverySurfaceRendersTheLicenceCoveringTheCode(t *testing.T) {
	for _, tc := range []struct {
		name     string
		want     string
		makeFunc func(*testing.T) (licdomain.LicenseRecord, coordinate.ModuleCoordinate)
	}{
		{"bundled component under its own path", "BSD-3-Clause", crossSurfaceRecord},
		{"embedded font licence inside the root licence file", "MIT", embeddedFontRecord},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec, coord := tc.makeFunc(t)
			for surface, got := range renderedLicenceOnEverySurface(t, coord, rec) {
				if got != tc.want {
					t.Errorf("%s states the module's licence as %q, want %q — every surface "+
						"must PRINT the same answer, not merely resolve it", surface, got, tc.want)
				}
			}
		})
	}
}

// TestEmbeddedFontLicenceNeverPresentedAsTheModuleLicence is the same control
// for the second fixture: no surface may hand a consumer of a Go
// syntax-highlighting library the licence of the font it embeds.
func TestEmbeddedFontLicenceNeverPresentedAsTheModuleLicence(t *testing.T) {
	rec, coord := embeddedFontRecord(t)
	for surface, got := range renderedLicenceOnEverySurface(t, coord, rec) {
		if strings.Contains(got, "OFL-1.1") {
			t.Errorf("%s reports the embedded font's licence as the module's: %q", surface, got)
		}
	}
}

// TestBundledComponentNeverPresentedAsTheModuleLicence: the bundled identifier
// must not reach any surface's "this module's licence" answer, and where
// license-compat does report it (as an obligation the module carries) it must
// be marked as the component's.
func TestBundledComponentNeverPresentedAsTheModuleLicence(t *testing.T) {
	rec, coord := crossSurfaceRecord(t)

	for surface, got := range renderedLicenceOnEverySurface(t, coord, rec) {
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
	// The keys are the document's, not the record's Go field names: `expression`
	// matched by luck of case-folding while `PrimarySPDX` never matched
	// `primary_spdx`, so the fallback read empty on a record with no expression.
	var out struct {
		PrimarySPDX string `json:"primary_spdx"`
		Expression  string `json:"expression"`
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("decoding license json: %v\n%s", err, buf.String())
	}
	if out.Expression != "" {
		return out.Expression
	}
	return out.PrimarySPDX
}

// licenceFromLicenseDiff reads a side's licence out of the diff document, which
// is the field a consumer comparing two versions reads. Both sides are the same
// record, so the answer is that record's identity and the diff must report no
// change.
func licenceFromLicenseDiff(t *testing.T, rec licdomain.LicenseRecord) string {
	t.Helper()
	diff := licdomain.DiffRecords(rec, rec)
	if diff.SPDXChanged != nil {
		t.Errorf("license-diff reports a licence change between a record and itself: %+v", diff.SPDXChanged)
	}
	return toLicenseDiffJSON(diff).DeclaredA.PrimarySPDX
}

// licenceFromNotice reads the licence identity the attribution document
// publishes for the module. The document also reproduces every licence text the
// archive carries, which is a different question and deliberately not this one.
func licenceFromNotice(rec licdomain.LicenseRecord) string {
	spdx, expression := licdomain.NoticeIdentity(rec)
	if expression != "" {
		return expression
	}
	return spdx
}

func licenceFromAudit(rec licdomain.LicenseRecord) string {
	display, _, _, _, _ := auditLicenceResolution(rec, true, nil, "", "")
	return display
}

func licenceFromContext(t *testing.T, coord coordinate.ModuleCoordinate, rec licdomain.LicenseRecord) string {
	t.Helper()
	fake := testfakes.NewFakeQueryLicense()
	fake.AddRecord(coord, licapp.PipelineVersion, rec)
	return licenseSummaryLine(buildLicense(context.Background(), coord, fake, nil))
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
