package application_test

import (
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	coordinatetest "github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	"github.com/eitanity/kanonarion/internal/vuln/application"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
)

// The metadata-only fallback is the one producer whose two answers cannot both
// fit in the collapsed status word, and it is the producer that was throwing one
// of them away: an advisory match overwrote the coverage the fallback was called
// with, leaving the gap recorded only as prose.
//
// All three fields are asserted against the record the store received, not
// against the value returned to the caller, because it is the stored record every
// later reader ranks and reports from.
func TestScanModule_MetadataOnlyMatchStatesBothAxes(t *testing.T) {
	vulnStore := newFakeVulnStore()
	snap := vulntest.MustNew("osv", "v2")
	modCoord := coordinatetest.MustNew("github.com/vuln/mod", "v1.0.0")
	db := &fakeDatabase{
		snapshot:    snap,
		vulnerables: map[coordinate.ModuleCoordinate][]string{modCoord: {"GO-2024-0001"}},
	}

	uc := application.NewScanModuleUseCase(
		newFakeFacts(), newFakeBlob(), vulnStore, newFakeWalkStore(),
		&fakeScanner{results: map[string]domain.VulnerabilityRecord{}}, db, nil,
		fixedClock{t: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)}, "v1", "v1", slog.Default(),
	)
	if _, err := uc.Scan(t.Context(), application.ScanModuleParams{
		Coordinate: modCoord,
		WalkID:     "w1",
		Snapshot:   &snap,
	}); err != nil {
		t.Fatalf("Scan(): %v", err)
	}

	stored, ok := vulnStore.served(vulnStore.recordKey(modCoord, "v1", snap))
	if !ok {
		t.Fatal("no record was stored for the metadata-only scan")
	}
	// Unscannable: nothing was analysed, so no reachability was established.
	if stored.CoverageStatus != domain.CoverageUnscannable {
		t.Errorf("coverage_status = %q, want %q — only the coordinate was matched", stored.CoverageStatus, domain.CoverageUnscannable)
	}
	// Affected: the advisory applies to this version, whatever coverage says.
	if stored.FindingsStatus != domain.FindingsRecordAffected {
		t.Errorf("findings_status = %q, want %q", stored.FindingsStatus, domain.FindingsRecordAffected)
	}
	// And the summary keeps reporting the match, so no consumer reading the single
	// word loses the finding to the coverage gap beside it.
	if stored.OverallStatus != domain.StatusAffected {
		t.Errorf("overall_status = %q, want %q", stored.OverallStatus, domain.StatusAffected)
	}
	// The seal must not have contradicted what the producer stated.
	if err := (domain.VulnerabilityRecordHasher{}).VerifyContentHash(stored); err != nil {
		t.Errorf("VerifyContentHash(stored) = %v, want nil", err)
	}
}

// The no-match half of the same path. A coordinate matched against the advisory
// database with nothing applying is a real answer about findings, so the summary
// stays Clean — but it is not an answer about coverage, and recording Analysed
// here is what put 74 rows in the maintainer's store claiming a module had been
// analysed when its source was never read.
func TestScanModule_MetadataOnlyCleanIsStillACoverageGap(t *testing.T) {
	vulnStore := newFakeVulnStore()
	snap := vulntest.MustNew("osv", "v2")
	modCoord := coordinatetest.MustNew("github.com/clean/mod", "v1.0.0")

	uc := application.NewScanModuleUseCase(
		newFakeFacts(), newFakeBlob(), vulnStore, newFakeWalkStore(),
		&fakeScanner{results: map[string]domain.VulnerabilityRecord{}},
		&fakeDatabase{snapshot: snap}, nil,
		fixedClock{t: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)}, "v1", "v1", slog.Default(),
	)
	if _, err := uc.Scan(t.Context(), application.ScanModuleParams{
		Coordinate: modCoord,
		WalkID:     "w1",
		Snapshot:   &snap,
	}); err != nil {
		t.Fatalf("Scan(): %v", err)
	}

	stored, ok := vulnStore.served(vulnStore.recordKey(modCoord, "v1", snap))
	if !ok {
		t.Fatal("no record was stored for the metadata-only scan")
	}
	if stored.CoverageStatus != domain.CoverageUnscannable {
		t.Errorf("coverage_status = %q, want %q — no source was analysed", stored.CoverageStatus, domain.CoverageUnscannable)
	}
	if stored.FindingsStatus != domain.FindingsRecordClean {
		t.Errorf("findings_status = %q, want %q", stored.FindingsStatus, domain.FindingsRecordClean)
	}
	if stored.OverallStatus != domain.StatusClean {
		t.Errorf("overall_status = %q, want the caller's %q", stored.OverallStatus, domain.StatusClean)
	}
	// A record read through RecordAxes must not be reported as an all-clear: only
	// Analysed + Clean is one, and this is not that pair.
	if coverage, findings := domain.RecordAxes(stored); coverage == domain.CoverageAnalysed && findings == domain.FindingsRecordClean {
		t.Error("a module whose source was never read reads back as a full all-clear")
	}
}

// A source scan that matched an advisory by coordinate states the findings axis
// and lets the domain collapse the summary, instead of open-coding the word. That
// is the production caller of DetermineRecordOverallStatus: before this, the
// branch that derives the summary from stated axes was reachable only from tests.
func TestScanModule_CoordinateMatchOnAnAnalysedModuleStatesAnalysedAndAffected(t *testing.T) {
	ctx := t.Context()
	vulnStore := newFakeVulnStore()
	snap := vulntest.MustNew("osv", "v2")
	modCoord := coordinatetest.MustNew("github.com/scanned/mod", "v1.0.0")

	// The module must be fetched for the source path to run at all; an absent
	// artefact routes to the metadata-only fallback instead.
	facts, blobs := newFakeFacts(), newFakeBlob()
	if err := facts.PutFetchRecord(ctx, fetchtest.Sealed(t,
		fetchtest.Coordinate(modCoord), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip content"))); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}
	if err := blobs.Put(ctx, fetchtest.ZipIdentity(t, fetchtest.Record(t,
		fetchtest.Coordinate(modCoord), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip content"))),
		strings.NewReader("zip content")); err != nil {
		t.Fatalf("blobs.Put: %v", err)
	}

	uc := application.NewScanModuleUseCase(
		facts, blobs, vulnStore, newFakeWalkStore(),
		// The scanner analysed the module and reported nothing; the advisory is
		// matched afterwards by coordinate, which source analysis cannot do for the
		// module it is scanning as its own main module.
		&fakeScanner{results: map[string]domain.VulnerabilityRecord{
			modCoord.String(): {Coordinate: modCoord, OverallStatus: domain.StatusClean},
		}},
		&fakeDatabase{
			snapshot:    snap,
			vulnerables: map[coordinate.ModuleCoordinate][]string{modCoord: {"GO-2024-0001"}},
		}, nil,
		fixedClock{t: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)}, "v1", "v1", slog.Default(),
	)
	rec, err := uc.Scan(t.Context(), application.ScanModuleParams{
		Coordinate: modCoord,
		WalkID:     "w1",
		Snapshot:   &snap,
		Force:      true, // skip the metadata pre-filter so the source path runs
	})
	if err != nil {
		t.Fatalf("Scan(): %v", err)
	}
	if rec.CoverageStatus != domain.CoverageAnalysed {
		t.Errorf("coverage_status = %q, want %q — the module was analysed", rec.CoverageStatus, domain.CoverageAnalysed)
	}
	if rec.FindingsStatus != domain.FindingsRecordAffected {
		t.Errorf("findings_status = %q, want %q", rec.FindingsStatus, domain.FindingsRecordAffected)
	}
	if rec.OverallStatus != domain.StatusAffected {
		t.Errorf("overall_status = %q, want %q collapsed from the axes", rec.OverallStatus, domain.StatusAffected)
	}
}
