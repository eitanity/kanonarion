package application

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// TestTallyModuleResults_UnrecognisedStatusCountedNotDropped proves a per-module
// verdict outside the known set is counted (as failed) rather than silently
// dropped, so the coverage buckets still partition the module total that the
// coverage axis and the completion summary derive from. No such value exists
// today; this guards the invariant, not a live failure mode.
//
// Both routes in are covered: an unrecognised summary word, which the coverage
// projection maps to Failed, and an unrecognised stored coverage axis, which
// reaches the tally's own default arm.
func TestTallyModuleResults_UnrecognisedStatusCountedNotDropped(t *testing.T) {
	for _, tc := range []struct {
		name   string
		record domain.VulnerabilityRecord
	}{
		{"unrecognised summary word", domain.VulnerabilityRecord{
			OverallStatus: domain.VulnerabilityStatus("SomeFutureStatus"),
		}},
		{"unrecognised stored coverage axis", domain.VulnerabilityRecord{
			OverallStatus:  domain.StatusClean,
			CoverageStatus: domain.RecordCoverageStatus("SomeFutureCoverage"),
			FindingsStatus: domain.FindingsRecordClean,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			uc := &ScanWalkUseCase{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

			coord := coordinatetest.MustNew("example.com/mod", "v1.0.0")
			rec := tc.record
			rec.Coordinate = coord
			final := map[coordinate.ModuleCoordinate]moduleResult{
				coord: {coord: coord, record: rec},
			}
			run := &domain.WalkScanRun{PerModuleResults: map[coordinate.ModuleCoordinate]string{}}
			pc := 0

			counts := uc.tallyModuleResults(context.Background(), []coordinate.ModuleCoordinate{coord},
				final, run, ScanWalkParams{}, &domain.DatabaseSnapshot{}, &pc, 1)

			if total := counts.analysed + counts.unscannable + counts.failed; total != 1 {
				t.Fatalf("coverage buckets do not partition the module total: analysed=%d unscannable=%d failed=%d (want sum 1)",
					counts.analysed, counts.unscannable, counts.failed)
			}
			if counts.failed != 1 {
				t.Errorf("unrecognised value counted as failed=%d, want 1 (must degrade coverage, not vanish)", counts.failed)
			}
			if counts.analysed != 0 {
				t.Errorf("analysed=%d, want 0: an unrecognised value must never claim the module was read", counts.analysed)
			}
		})
	}
}

// A module that reports an advisory under a coverage gap counts on both tallies:
// it is a finding AND a module that was never analysed. Counting it as analysed
// on the strength of its summary word — which reads Affected — is how a run came
// to report full coverage of modules nothing was read in.
func TestTallyModuleResults_ACoordinateMatchIsNotCountedAsAnalysed(t *testing.T) {
	uc := &ScanWalkUseCase{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	coord := coordinatetest.MustNew("example.com/mod", "v1.0.0")
	final := map[coordinate.ModuleCoordinate]moduleResult{
		coord: {coord: coord, record: domain.VulnerabilityRecord{
			Coordinate:     coord,
			OverallStatus:  domain.StatusAffected,
			CoverageStatus: domain.CoverageUnscannable,
			FindingsStatus: domain.FindingsRecordAffected,
			UnscanReason:   domain.UnscanReasonVersionNotInToolchain,
			Findings:       []domain.VulnerabilityFinding{{ID: "GO-2024-0001"}},
		}},
	}
	run := &domain.WalkScanRun{PerModuleResults: map[coordinate.ModuleCoordinate]string{}}
	pc := 0

	counts := uc.tallyModuleResults(context.Background(), []coordinate.ModuleCoordinate{coord},
		final, run, ScanWalkParams{}, &domain.DatabaseSnapshot{}, &pc, 1)

	if counts.affected != 1 {
		t.Errorf("affected=%d, want 1: the advisory is reported", counts.affected)
	}
	if counts.unscannable != 1 {
		t.Errorf("unscannable=%d, want 1: the module was never analysed", counts.unscannable)
	}
	if counts.analysed != 0 {
		t.Errorf("analysed=%d, want 0", counts.analysed)
	}
	if counts.clean != 0 {
		t.Errorf("clean=%d, want 0: an all-clear is analysed AND reporting nothing", counts.clean)
	}
}
