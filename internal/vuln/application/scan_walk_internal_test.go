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

// TestTallyModuleResults_UnrecognisedStatusCountedNotDropped proves the tally's
// default arm: a per-module verdict outside the known status set is counted
// (as failed) rather than silently dropped, so affected+clean+unscannable+failed
// still equals the module total that the coverage axis and the completion
// summary derive from. No such status exists today; this guards the invariant,
// not a live failure mode.
func TestTallyModuleResults_UnrecognisedStatusCountedNotDropped(t *testing.T) {
	uc := &ScanWalkUseCase{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	coord := coordinatetest.MustNew("example.com/mod", "v1.0.0")
	final := map[coordinate.ModuleCoordinate]moduleResult{
		coord: {coord: coord, record: domain.VulnerabilityRecord{
			Coordinate:    coord,
			OverallStatus: domain.VulnerabilityStatus("SomeFutureStatus"),
		}},
	}
	run := &domain.WalkScanRun{PerModuleResults: map[coordinate.ModuleCoordinate]string{}}
	pc := 0

	counts := uc.tallyModuleResults(context.Background(), []coordinate.ModuleCoordinate{coord},
		final, run, ScanWalkParams{}, &domain.DatabaseSnapshot{}, &pc, 1)

	total := counts.affected + counts.clean + counts.unscannable + counts.failed
	if total != 1 {
		t.Fatalf("counts do not sum to the module total: affected=%d clean=%d unscannable=%d failed=%d (want sum 1)",
			counts.affected, counts.clean, counts.unscannable, counts.failed)
	}
	if counts.failed != 1 {
		t.Errorf("unrecognised status counted as failed=%d, want 1 (must degrade coverage, not vanish)", counts.failed)
	}
}
