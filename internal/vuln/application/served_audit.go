package application

import (
	"fmt"

	"github.com/eitanity/kanonarion/internal/audit"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// Surfaces published in the assurance log beside a served scan run. They name
// the command that asked, because "when did we last check" is a question about
// asking and the asker is the only part of a served answer that is new: the run,
// the walk and the snapshot are all already in the store, and a log that could
// not say which surface reached for them would report a re-serve without saying
// who wanted it.
const (
	ServeSurfaceVulnScan = "vuln-scan"
	ServeSurfaceAudit    = "audit"
	ServeSurfaceInspect  = "inspect"
)

// ServeReusableRun witnesses in the assurance log that a stored scan run was
// handed to a caller instead of being measured again.
//
// It is deliberately not part of ReusableRun. ReusableRun answers whether a
// stored run COULD serve; some callers ask that only to narrate the derivation
// and then let another path do the serving, and some ask it and discard the
// answer because --force was given. An event emitted from the question would
// date a serving that never happened, and could date two for one. This method is
// called from the one place a run is actually handed back.
//
// A nil audit sink disables emission, as everywhere else in this context. The
// append happens before the run is reported, so a failed append fails the
// serving: the alternative is an answer that left the tool with no trace, which
// is the gap this closes rather than a smaller version of it.
func (uc *ScanWalkUseCase) ServeReusableRun(run domain.WalkScanRun, surface string) error {
	if uc.audit == nil {
		return nil
	}
	if err := uc.audit.RecordEvent(scanServedEvent(run, surface)); err != nil {
		return fmt.Errorf("recording vuln scan served audit event: %w", err)
	}
	return nil
}

// scanServedEvent builds the assurance-log envelope for one stored scan run
// served from the store.
//
// The payload names the run served, the walk it answered for, the pipeline that
// derived it and the advisory database it was judged against — the four things
// that together say WHICH question this answer settles — plus the surface that
// asked for this serving. It carries none of the run's conclusions: the
// findings, the per-module statuses, the coverage and the counts belong to the
// run, and the scan id reaches them. Restating them here would put a second,
// unsealed copy of a sealed run in the log, one that no later correction to the
// run would ever reach.
//
// The surface is omitted when the caller named none, rather than recorded as an
// empty string: no surface was supplied, and an empty one would read as an
// anonymous caller instead of an unstated one.
func scanServedEvent(run domain.WalkScanRun, surface string) audit.Event {
	payload := map[string]any{
		"scan_id":          run.ID,
		"walk_id":          run.WalkID,
		"pipeline_version": run.PipelineVersion,
		"snapshot_source":  run.Snapshot.Source(),
		"snapshot_version": run.Snapshot.Version(),
	}
	if surface != "" {
		payload["surface"] = surface
	}
	return audit.Event{Type: audit.EventVulnScanServed, Payload: payload}
}
