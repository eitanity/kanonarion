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
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// These tests drive the REAL compatibility use case through the real renderer.
// A fixture report handed straight to the printer would prove only that the
// printer prints what it is given; the defect under test is in what the use
// case derives from a licence record, so the record is the input.

// originFakeLicenceStore satisfies the use case's licence-store dependency.
type originFakeLicenceStore struct {
	records map[string]licdomain.LicenseRecord // key = path@version
}

func (s *originFakeLicenceStore) GetLicenseRecord(_ context.Context, coord coordinate.ModuleCoordinate, _ string) (licdomain.LicenseRecord, bool, error) {
	rec, ok := s.records[coord.Path()+"@"+coord.Version()]
	return rec, ok, nil
}

// originFakeWalkStore serves one walk to the use case.
type originFakeWalkStore struct{ walk walkdomain.WalkRecord }

func (s *originFakeWalkStore) PutWalk(context.Context, walkdomain.WalkRecord) error { return nil }
func (s *originFakeWalkStore) GetWalk(context.Context, string) (walkdomain.WalkRecord, error) {
	return s.walk, nil
}

func (s *originFakeWalkStore) ListWalks(context.Context, walkports.WalkFilter) ([]walkports.WalkSummary, error) {
	return nil, nil
}

var _ walkports.WalkStore = (*originFakeWalkStore)(nil)

// compatFromRecords wires the real use case over the given records and returns
// a Container ready for licenseCompatWith, plus the root coordinate.
func compatFromRecords(t *testing.T, records map[string]licdomain.LicenseRecord) (*Container, coordinate.ModuleCoordinate) {
	t.Helper()
	root := coordinatetest.MustNew("example.com/root", "local")

	nodes := []walkdomain.GraphNode{{Coordinate: root}}
	for key := range records {
		at := strings.LastIndex(key, "@")
		nodes = append(nodes, walkdomain.GraphNode{Coordinate: coordinatetest.MustNew(key[:at], key[at+1:])})
	}
	walk := walkdomain.WalkRecord{ID: "W1", Graph: walkdomain.Graph{Nodes: nodes}}

	fqw := testfakes.NewFakeQueryWalks()
	fqw.SetSummaries([]walkports.WalkSummary{{ID: "W1", Target: root}})
	fqw.AddWalk(walk)

	return &Container{
		QueryWalks: fqw,
		CheckCompatibility: licapp.NewCheckCompatibilityUseCase(
			&originFakeLicenceStore{records: records},
			&originFakeWalkStore{walk: walk},
		),
	}, root
}

// runCompat runs licenseCompatWith in text or JSON mode and returns the output
// and the error (an *exitError for non-clean closures).
func runCompat(t *testing.T, ctr *Container, root coordinate.ModuleCoordinate, target string, asJSON bool) (string, error) {
	t.Helper()
	prev := jsonOut
	jsonOut = asJSON
	defer func() { jsonOut = prev }()
	var out bytes.Buffer
	err := licenseCompatWith(context.Background(), ctr, root, target, &out)
	return out.String(), err
}

// bundledComponentRecord models the shape at the heart of the report: a module
// whose OWN licence is permissive and which bundles a third-party component
// under a different licence, the way gonum bundles THIRD_PARTY_LICENSES.
func bundledComponentRecord(rootSPDX, componentSPDX string) licdomain.LicenseRecord {
	return licdomain.LicenseRecord{
		PrimarySPDX:   rootSPDX,
		Expression:    rootSPDX,
		OverallStatus: licdomain.LicenseStatusDetected,
		LicenseFiles: []licdomain.LicenseFileEntry{
			{Path: "LICENSE", SPDX: rootSPDX, Confidence: 1},
			{Path: "THIRD_PARTY_LICENSES/Vendored-LICENSE", SPDX: componentSPDX, Confidence: 1},
		},
	}
}

// withEffectiveSet returns rec with the derived effective set filled in, the
// way the store fills it on read.
func withEffectiveSet(rec licdomain.LicenseRecord) licdomain.LicenseRecord {
	rec.EffectiveSet = licdomain.DeriveEffectiveLicenseSet(rec.LicenseFiles)
	return rec
}

// A bundled component's licence must never be rendered as the module's own.
// Before the fix the row read "example.com/dep@v1.0.0  GPL-3.0-only" with
// nothing saying the identifier belonged to a vendored directory and nothing
// saying the module itself is BSD-3-Clause.
func TestLicenseCompat_BundledComponentNamesItsOrigin_Text(t *testing.T) {
	ctr, root := compatFromRecords(t, map[string]licdomain.LicenseRecord{
		"example.com/dep@v1.0.0": withEffectiveSet(bundledComponentRecord("BSD-3-Clause", "GPL-3.0-only")),
	})
	out, err := runCompat(t, ctr, root, "Apache-2.0", false)
	if err == nil {
		t.Fatal("a bundled GPL component is still a conflict; want a non-clean result")
	}
	if !strings.Contains(out, "THIRD_PARTY_LICENSES") {
		t.Errorf("text output does not name the component the identifier came from:\n%s", out)
	}
	if !strings.Contains(out, "bundled component") {
		t.Errorf("text output does not say the identifier belongs to a bundled component:\n%s", out)
	}
	if !strings.Contains(out, "BSD-3-Clause") {
		t.Errorf("text output does not report the module's own licence:\n%s", out)
	}
}

func TestLicenseCompat_BundledComponentNamesItsOrigin_JSON(t *testing.T) {
	ctr, root := compatFromRecords(t, map[string]licdomain.LicenseRecord{
		"example.com/dep@v1.0.0": withEffectiveSet(bundledComponentRecord("BSD-3-Clause", "GPL-3.0-only")),
	})
	out, err := runCompat(t, ctr, root, "Apache-2.0", true)
	if err == nil {
		t.Fatal("a bundled GPL component is still a conflict; want a non-clean result")
	}
	entry := soleConflictJSON(t, out)
	if got := entry["spdx_origin"]; got != "bundled_component" {
		t.Errorf("spdx_origin = %v, want bundled_component", got)
	}
	if got := entry["spdx_origin_path"]; got != "THIRD_PARTY_LICENSES" {
		t.Errorf("spdx_origin_path = %v, want THIRD_PARTY_LICENSES", got)
	}
	if got := entry["module_spdx"]; got != "BSD-3-Clause" {
		t.Errorf("module_spdx = %v, want BSD-3-Clause — a JSON consumer must be able to recover the module's actual licence", got)
	}
	if got := entry["dep_spdx"]; got != "GPL-3.0-only" {
		t.Errorf("dep_spdx = %v, want the evaluated identifier GPL-3.0-only", got)
	}
}

// A conjunction is reported whole, as sbom does, with the offending arm named.
// go-digest is the live case: "Apache-2.0 AND CC-BY-SA-4.0" was rendered as
// "CC-BY-SA-4.0" alone, which reads as the module's licence and is not.
func TestLicenseCompat_ConjunctiveExpressionReportedWhole_Text(t *testing.T) {
	rec := licdomain.LicenseRecord{
		PrimarySPDX:   "Apache-2.0",
		Expression:    "Apache-2.0 AND CC-BY-SA-4.0",
		OverallStatus: licdomain.LicenseStatusMultiple,
		LicenseFiles: []licdomain.LicenseFileEntry{
			{Path: "LICENSE", SPDX: "Apache-2.0", Confidence: 1},
			{Path: "LICENSE.docs", SPDX: "CC-BY-SA-4.0", Confidence: 1},
		},
	}
	ctr, root := compatFromRecords(t, map[string]licdomain.LicenseRecord{
		"example.com/dep@v1.0.0": withEffectiveSet(rec),
	})
	out, err := runCompat(t, ctr, root, "Apache-2.0", false)
	if err == nil {
		t.Fatal("CC-BY-SA-4.0 is unmodelled by decision; want a review item")
	}
	if !strings.Contains(out, "Apache-2.0 AND CC-BY-SA-4.0") {
		t.Errorf("the module's expression must be reported whole, never reduced to the offending arm:\n%s", out)
	}
	if !strings.Contains(out, "arm CC-BY-SA-4.0") {
		t.Errorf("the offending arm must be identified:\n%s", out)
	}
}

func TestLicenseCompat_ConjunctiveExpressionReportedWhole_JSON(t *testing.T) {
	rec := licdomain.LicenseRecord{
		PrimarySPDX:   "Apache-2.0",
		Expression:    "Apache-2.0 AND CC-BY-SA-4.0",
		OverallStatus: licdomain.LicenseStatusMultiple,
		LicenseFiles: []licdomain.LicenseFileEntry{
			{Path: "LICENSE", SPDX: "Apache-2.0", Confidence: 1},
			{Path: "LICENSE.docs", SPDX: "CC-BY-SA-4.0", Confidence: 1},
		},
	}
	ctr, root := compatFromRecords(t, map[string]licdomain.LicenseRecord{
		"example.com/dep@v1.0.0": withEffectiveSet(rec),
	})
	out, err := runCompat(t, ctr, root, "Apache-2.0", true)
	if err == nil {
		t.Fatal("CC-BY-SA-4.0 is unmodelled by decision; want a review item")
	}
	entry := soleConflictJSON(t, out)
	if got := entry["module_spdx"]; got != "Apache-2.0 AND CC-BY-SA-4.0" {
		t.Errorf("module_spdx = %v, want the whole expression", got)
	}
	if got := entry["dep_spdx"]; got != "CC-BY-SA-4.0" {
		t.Errorf("dep_spdx = %v, want the offending arm", got)
	}
	if got := entry["spdx_origin"]; got != "module_root" {
		t.Errorf("spdx_origin = %v: both arms are the module's own root licence", got)
	}
}

// A testdata directory is a test corpus, never linked code. A copyleft licence
// on a fixture must not raise a compatibility conflict.
func TestLicenseCompat_TestdataComponentRaisesNoConflict(t *testing.T) {
	rec := licdomain.LicenseRecord{
		PrimarySPDX:   "MIT",
		Expression:    "MIT",
		OverallStatus: licdomain.LicenseStatusDetected,
		LicenseFiles: []licdomain.LicenseFileEntry{
			{Path: "LICENSE", SPDX: "MIT", Confidence: 1},
			{Path: "graph/formats/example/testdata/LICENSE", SPDX: "GPL-3.0-only", Confidence: 1},
		},
	}
	ctr, root := compatFromRecords(t, map[string]licdomain.LicenseRecord{
		"example.com/dep@v1.0.0": withEffectiveSet(rec),
	})
	out, err := runCompat(t, ctr, root, "Apache-2.0", false)
	if err != nil {
		t.Fatalf("a GPL licence on a test corpus must not conflict with linked code; got %v\n%s", err, out)
	}
	if strings.Contains(out, "GPL-3.0-only") {
		t.Errorf("a testdata licence must not appear in the compatibility answer:\n%s", out)
	}
}

// A bundled component nested under testdata is excluded at any depth, the way
// the go tool ignores testdata at any depth — but a vendored component that
// merely has "testdata" in a longer segment name is not.
func TestLicenseCompat_TestdataExclusionIsSegmentExact(t *testing.T) {
	rec := licdomain.LicenseRecord{
		PrimarySPDX:   "MIT",
		Expression:    "MIT",
		OverallStatus: licdomain.LicenseStatusDetected,
		LicenseFiles: []licdomain.LicenseFileEntry{
			{Path: "LICENSE", SPDX: "MIT", Confidence: 1},
			{Path: "vendor/testdataloader/LICENSE", SPDX: "GPL-3.0-only", Confidence: 1},
		},
	}
	ctr, root := compatFromRecords(t, map[string]licdomain.LicenseRecord{
		"example.com/dep@v1.0.0": withEffectiveSet(rec),
	})
	out, err := runCompat(t, ctr, root, "Apache-2.0", false)
	if err == nil {
		t.Fatalf("vendor/testdataloader is a vendored library, not a test corpus — it must still conflict:\n%s", out)
	}
	if !strings.Contains(out, "vendor/testdataloader") {
		t.Errorf("the component that raised the conflict must be named:\n%s", out)
	}
}

// The reported false review item, end to end: a module whose own licence is
// BSD-3-Clause and which bundles a Boost-licensed component is compatible with
// an Apache-2.0 target and raises nothing at all.
func TestLicenseCompat_BundledPermissiveComponentIsNotAReviewItem(t *testing.T) {
	ctr, root := compatFromRecords(t, map[string]licdomain.LicenseRecord{
		"example.com/dep@v1.0.0": withEffectiveSet(bundledComponentRecord("BSD-3-Clause", "BSL-1.0")),
	})
	out, err := runCompat(t, ctr, root, "Apache-2.0", false)
	if err != nil {
		t.Fatalf("BSL-1.0 is permissive: want a clean closure, got %v\n%s", err, out)
	}
	if strings.Contains(out, "BSL-1.0") {
		t.Errorf("a permissive bundled licence must raise no row:\n%s", out)
	}
}

// One identifier the dataset does not model is ONE gap, whatever the module
// count. The per-module rows stay — they are still open items — but the
// coverage section says how many distinct identifiers are actually at issue.
func TestLicenseCompat_CoverageHolesReportedOncePerIdentifier(t *testing.T) {
	docsRec := func() licdomain.LicenseRecord {
		return withEffectiveSet(licdomain.LicenseRecord{
			PrimarySPDX:   "Apache-2.0",
			Expression:    "Apache-2.0 AND CC-BY-SA-4.0",
			OverallStatus: licdomain.LicenseStatusMultiple,
			LicenseFiles: []licdomain.LicenseFileEntry{
				{Path: "LICENSE", SPDX: "Apache-2.0", Confidence: 1},
				{Path: "LICENSE.docs", SPDX: "CC-BY-SA-4.0", Confidence: 1},
			},
		})
	}
	records := map[string]licdomain.LicenseRecord{
		"example.com/a@v1.0.0": docsRec(),
		"example.com/b@v1.0.0": docsRec(),
		"example.com/c@v1.0.0": docsRec(),
	}

	out, err := runCompatFor(t, records, false)
	if err == nil {
		t.Fatal("three unmodelled pairs must still require review")
	}
	if !strings.Contains(out, "Dataset coverage — 1 licence identifier in this closure is not modelled") {
		t.Errorf("three modules carrying one unmodelled identifier is one dataset gap, not three:\n%s", out)
	}
	if !strings.Contains(out, "unmodelled by decision") {
		t.Errorf("CC-BY-SA-4.0 is unmodelled on purpose and the output must say so:\n%s", out)
	}

	jsonText, err := runCompatFor(t, records, true)
	if err == nil {
		t.Fatal("three unmodelled pairs must still require review")
	}
	var report struct {
		Conflicts     []map[string]any `json:"conflicts"`
		CoverageHoles []struct {
			SPDX       string `json:"spdx"`
			Modules    int    `json:"modules"`
			Deliberate bool   `json:"deliberate"`
			Reason     string `json:"reason"`
		} `json:"coverage_holes"`
		TargetModelled bool `json:"target_modelled"`
	}
	if err := json.Unmarshal([]byte(jsonText), &report); err != nil {
		t.Fatalf("decoding JSON report: %v\n%s", err, jsonText)
	}
	if len(report.Conflicts) != 3 {
		t.Errorf("want 3 per-module review items, got %d", len(report.Conflicts))
	}
	if len(report.CoverageHoles) != 1 {
		t.Fatalf("want 1 coverage hole, got %d: %+v", len(report.CoverageHoles), report.CoverageHoles)
	}
	hole := report.CoverageHoles[0]
	if hole.SPDX != "CC-BY-SA-4.0" || hole.Modules != 3 || !hole.Deliberate || hole.Reason == "" {
		t.Errorf("coverage hole = %+v, want CC-BY-SA-4.0 on 3 modules, deliberate with a reason", hole)
	}
	if !report.TargetModelled {
		t.Error("Apache-2.0 is modelled; target_modelled must be true")
	}
}

// runCompatFor is compatFromRecords + runCompat for the multi-module cases.
func runCompatFor(t *testing.T, records map[string]licdomain.LicenseRecord, asJSON bool) (string, error) {
	t.Helper()
	ctr, root := compatFromRecords(t, records)
	return runCompat(t, ctr, root, "Apache-2.0", asJSON)
}

// soleConflictJSON decodes a JSON report and returns its single conflict entry.
func soleConflictJSON(t *testing.T, out string) map[string]any {
	t.Helper()
	var report struct {
		Conflicts []map[string]any `json:"conflicts"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("decoding JSON report: %v\n%s", err, out)
	}
	if len(report.Conflicts) != 1 {
		t.Fatalf("want exactly 1 conflict, got %d:\n%s", len(report.Conflicts), out)
	}
	return report.Conflicts[0]
}
