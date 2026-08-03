package application

import (
	"fmt"
	"time"

	"github.com/eitanity/kanonarion/internal/audit"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

// Routes published in the assurance log beside a persisted advisory snapshot.
// They name the run that acquired it — the same snapshot arriving through a
// walk scan, an explicit refresh and a re-scan are three different events in an
// operator's account of when the advisory set changed, and a log that could not
// tell them apart would answer "when did we take this database on" with a
// timestamp and no story.
const (
	snapshotRouteModuleScan = "module_scan"
	snapshotRouteWalkScan   = "walk_scan"
	snapshotRouteRefresh    = "advisory_refresh"
	snapshotRouteRescan     = "walk_rescan"
)

// emitSnapshotRecorded appends one advisory_snapshot_recorded event for a
// snapshot this run persisted. A nil sink disables emission.
//
// Every call site reaches it only after PutDatabaseSnapshot returned, so a
// failed append reports that a persisted snapshot is unlogged rather than
// undoing the write. A run that reuses a stored snapshot never gets here: the
// database is asked for a body only when there is one to store, and reuse is
// not an acquisition — appending for it would date an arrival that already
// happened, possibly weeks earlier and possibly on another machine.
func emitSnapshotRecorded(sink ports.AuditSink, snapshot domain.DatabaseSnapshot, route string) error {
	if sink == nil {
		return nil
	}
	if err := sink.RecordEvent(snapshotRecordedEvent(snapshot, route)); err != nil {
		return fmt.Errorf("recording advisory snapshot audit event: %w", err)
	}
	return nil
}

// snapshotRecordedEvent builds the assurance-log envelope for one persisted
// advisory database snapshot.
//
// The payload identifies the acquisition — which database, that database's own
// generation of itself, when this store retrieved it, and the content identity
// of the bytes persisted — plus the route the run took to it. It states nothing
// about what the snapshot contains: not the advisories, not how many there are,
// and not any module's standing against them. Those are questions for the
// snapshot, which the content identity reaches; answering them here would make
// the log an unsealed summary of an advisory set that upstream can withdraw
// from and re-scope under the same version string.
//
// The content identity is omitted when the snapshot carries none — a snapshot
// fetched before the hash existed is unverifiable rather than invalid, and an
// empty identity would read as bytes that hashed to nothing.
func snapshotRecordedEvent(snapshot domain.DatabaseSnapshot, route string) audit.Event {
	payload := map[string]any{
		"snapshot_source":   snapshot.Source(),
		"snapshot_version":  snapshot.Version(),
		"retrieved_at":      snapshot.RetrievedAt().UTC().Format(time.RFC3339),
		"acquisition_route": route,
	}
	if h := snapshot.ContentHash(); h != "" {
		payload["content_hash"] = h
	}
	return audit.Event{Type: audit.EventAdvisorySnapshotRecorded, Payload: payload}
}
