package application

import (
	"fmt"

	"github.com/eitanity/kanonarion/internal/audit"

	domain2 "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/callgraph/ports"
)

// emitCallGraphExtracted appends one callgraph_extracted event for a generation
// this run persisted. A nil sink disables emission, and a record served from
// cache never reaches here: the event says a generation was WRITTEN, so emitting
// on a cache hit would report a write that did not happen.
//
// Both extraction use cases share it. They persist through the same port and
// differ only in what they read, which the event states rather than splits into
// two event types.
func emitCallGraphExtracted(sink ports.AuditSink, record domain2.CallGraphRecord) error {
	if sink == nil {
		return nil
	}
	if err := sink.RecordEvent(callGraphExtractedEvent(record)); err != nil {
		return fmt.Errorf("recording call graph extraction audit event: %w", err)
	}
	return nil
}

// callGraphExtractedEvent builds the assurance-log envelope for one persisted
// call graph generation.
//
// The payload identifies the write — which module, which bytes, which pipeline,
// at what fidelity, sealed under which hash — and carries no part of the graph
// itself. A reader that wants nodes and edges has the content hash to ask the
// ledger with; the assurance log records that the write happened, not what it
// contained.
func callGraphExtractedEvent(record domain2.CallGraphRecord) audit.Event {
	payload := map[string]any{
		"module":           record.Coordinate.Path(),
		"version":          record.Coordinate.Version(),
		"pipeline_version": record.PipelineVersion,
		"completeness":     record.Completeness.String(),
		"overall_status":   record.OverallStatus.String(),
		"analysis_source":  record.AnalysisSource.String(),
		"node_count":       record.NodeCount,
		"edge_count":       record.EdgeCount,
		"content_hash":     record.ContentHash,
	}
	// What the analysis actually read. A fetched artefact is named by its
	// identity; a working tree has none, so its digest is the only thing that
	// tells one checkout of a module path from another. Each is omitted when the
	// record carries none, which is the truth for the other kind of source.
	if record.ArtefactIdentity != "" {
		payload["artefact_identity"] = record.ArtefactIdentity
	}
	if record.WorktreeDigest != "" {
		payload["worktree_digest"] = record.WorktreeDigest
	}
	return audit.Event{Type: audit.EventCallGraphExtracted, Payload: payload}
}
