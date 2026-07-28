package cli

import (
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	coordinatetest "github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

// A record that reports an advisory under a coverage gap owes a line in both
// sections of the scan report, and the findings line is the one that was being
// lost: routing on the collapsed status word tested coverage first and skipped
// the module, so the section a reader opens the report for never mentioned it.
//
// This is the normal shape of a metadata-only fallback — an advisory matched by
// coordinate on a module whose source could not be analysed — not an exotic one.
func TestBuildScanAffectedModules_ReportsAFindingAndItsCoverageGap(t *testing.T) {
	gap := coordinatetest.MustNew("github.com/gap/mod", "v1.0.0")
	analysed := coordinatetest.MustNew("github.com/clean/mod", "v1.0.0")
	failed := coordinatetest.MustNew("github.com/broken/mod", "v1.0.0")

	uc := testfakes.NewFakeQueryVuln()
	uc.AddRecord(gap, vuldomain.VulnerabilityRecord{
		Coordinate:        gap,
		OverallStatus:     vuldomain.StatusAffected,
		CoverageStatus:    vuldomain.CoverageUnscannable,
		FindingsStatus:    vuldomain.FindingsRecordAffected,
		UnscanReason:      vuldomain.UnscanReasonVersionNotInToolchain,
		UnscannableReason: "metadata-only",
		Findings:          []vuldomain.VulnerabilityFinding{{ID: "GO-2024-0001"}},
		ScannedAt:         time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	uc.AddRecord(analysed, vuldomain.VulnerabilityRecord{
		Coordinate:     analysed,
		OverallStatus:  vuldomain.StatusClean,
		CoverageStatus: vuldomain.CoverageAnalysed,
		FindingsStatus: vuldomain.FindingsRecordClean,
	})
	uc.AddRecord(failed, vuldomain.VulnerabilityRecord{
		Coordinate:     failed,
		OverallStatus:  vuldomain.StatusScanFailed,
		CoverageStatus: vuldomain.CoverageFailedScan,
		FindingsStatus: vuldomain.FindingsRecordClean,
		ErrorDetail:    "govulncheck exited 1",
	})

	run := vuldomain.WalkScanRun{
		PerModuleResults: map[coordinate.ModuleCoordinate]string{
			gap: "h1", analysed: "h2", failed: "h3",
		},
	}

	summary := buildScanAffectedModules(t.Context(), run, uc)

	if len(summary.affected) != 1 || summary.affected[0].Coordinate != gap.String() {
		t.Fatalf("affected = %+v, want the coordinate-matched module %s reported", summary.affected, gap)
	}
	if len(summary.affected[0].Findings) != 1 {
		t.Errorf("findings = %d, want the advisory carried into the report", len(summary.affected[0].Findings))
	}
	// The same module is also named as a coverage gap, so the reader is not left
	// believing the match was checked for reachability.
	coords := summary.unscannable.byReason[vuldomain.UnscanReasonVersionNotInToolchain]
	if len(coords) != 1 || coords[0] != gap.String() {
		t.Errorf("unscannable roll-up = %v, want %s named as a coverage gap too", coords, gap)
	}
	// A failed scan is still a fault, and an analysed all-clear still owes nothing.
	if len(summary.scanFailed) != 1 || summary.scanFailed[0].Coordinate != failed.String() {
		t.Errorf("scanFailed = %+v, want %s", summary.scanFailed, failed)
	}
	if len(summary.missing) != 0 || len(summary.readErrors) != 0 {
		t.Errorf("missing=%v readErrors=%v, want both empty", summary.missing, summary.readErrors)
	}
}

// The per-module progress line carries both answers too. Before, a coordinate
// match on an unanalysable module printed a bare "Affected" and said nothing about
// the coverage gap; gating the whole label on coverage instead would have hidden
// the match. Both belong on the line.
func TestVulnScanStatusLabel_CarriesTheFindingAndTheCoverageGap(t *testing.T) {
	label := vulnScanStatusLabel(vuldomain.VulnerabilityRecord{
		OverallStatus:  vuldomain.StatusAffected,
		CoverageStatus: vuldomain.CoverageUnscannable,
		FindingsStatus: vuldomain.FindingsRecordAffected,
		UnscanReason:   vuldomain.UnscanReasonVersionNotInToolchain,
	})
	if want := string(vuldomain.StatusAffected); len(label) < len(want) || label[:len(want)] != want {
		t.Errorf("label = %q, want it to lead with %q", label, want)
	}
	if label == string(vuldomain.StatusAffected) {
		t.Errorf("label = %q, want the coverage gap named beside the finding", label)
	}

	// A coverage gap that recorded prose but no reason code reports the prose,
	// never "no reason recorded" — the reason is on the record.
	label = vulnScanStatusLabel(vuldomain.VulnerabilityRecord{
		OverallStatus:     vuldomain.StatusClean,
		CoverageStatus:    vuldomain.CoverageUnscannable,
		FindingsStatus:    vuldomain.FindingsRecordClean,
		UnscannableReason: "metadata-only: module not fetched (shallow walk)",
	})
	if label != "metadata-only: module not fetched (shallow walk)" {
		t.Errorf("label = %q, want the recorded reason", label)
	}

	// An analysed module keeps reporting its summary word verbatim.
	if got := vulnScanStatusLabel(vuldomain.VulnerabilityRecord{
		OverallStatus:  vuldomain.StatusClean,
		CoverageStatus: vuldomain.CoverageAnalysed,
		FindingsStatus: vuldomain.FindingsRecordClean,
	}); got != string(vuldomain.StatusClean) {
		t.Errorf("label = %q, want %q", got, vuldomain.StatusClean)
	}
}
