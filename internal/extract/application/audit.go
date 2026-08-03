package application

import (
	"fmt"

	"github.com/eitanity/kanonarion/internal/audit"

	"github.com/eitanity/kanonarion/internal/extract/domain"
)

// emitRunCompleted appends one extraction_run_completed event for the run this
// orchestration persisted. A nil sink disables emission.
//
// Every run this reaches wrote a run record — the orchestrator persists exactly
// one, on every outcome including a cancelled one — so there is no cache branch
// to exclude here. A run that never got that far returned before this point.
func (uc *ExtractUseCase) emitRunCompleted(run domain.ExtractionRun) error {
	if uc.audit == nil {
		return nil
	}
	if err := uc.audit.RecordEvent(runCompletedEvent(run)); err != nil {
		return fmt.Errorf("recording extraction run audit event: %w", err)
	}
	return nil
}

// runCompletedEvent builds the assurance-log envelope for one persisted
// extraction run.
//
// The payload identifies the campaign — which walk, which stages, over how many
// modules, with what outcome, sealed under which hash — and carries no
// per-module detail. The stages' own events carry that; this one is what tells a
// reader those events belong to a single orchestrated run rather than to
// separate single-module re-extractions.
func runCompletedEvent(run domain.ExtractionRun) audit.Event {
	succeeded, failed, skipped := stageOutcomeCounts(run)
	return audit.Event{
		Type: audit.EventExtractionRunCompleted,
		Payload: map[string]any{
			"run_id":           run.ID,
			"walk_id":          run.WalkID,
			"requested_stages": append([]string(nil), run.RequestedStages...),
			"module_count":     len(run.PerModuleResults),
			"stages_succeeded": succeeded,
			"stages_failed":    failed,
			"stages_skipped":   skipped,
			"overall_status":   run.OverallStatus.String(),
			"content_hash":     run.ContentHash,
		},
	}
}

// stageOutcomeCounts tallies the per-module stage results the run recorded. The
// overall status says whether anything failed; these say how much, which is what
// separates a run where one module could not be analysed from one where nothing
// could.
func stageOutcomeCounts(run domain.ExtractionRun) (succeeded, failed, skipped int) {
	for _, modRes := range run.PerModuleResults {
		for _, stageRes := range modRes.Stages {
			switch stageRes.Status {
			case domain.StageSucceeded:
				succeeded++
			case domain.StageFailed:
				failed++
			case domain.StageSkipped:
				skipped++
			}
		}
	}
	return succeeded, failed, skipped
}
