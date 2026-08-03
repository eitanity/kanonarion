package application

import (
	"fmt"

	"github.com/eitanity/kanonarion/internal/audit"

	domain2 "github.com/eitanity/kanonarion/internal/example/domain"
	"github.com/eitanity/kanonarion/internal/example/ports"
)

// emitExamplesExtracted appends one examples_extracted event for a generation
// this run persisted. A nil sink disables emission, and a record served from
// cache never reaches here: the event says a generation was WRITTEN, so emitting
// on a cache hit would report a write that did not happen.
func emitExamplesExtracted(sink ports.AuditSink, record domain2.ExampleRecord) error {
	if sink == nil {
		return nil
	}
	if err := sink.RecordEvent(examplesExtractedEvent(record)); err != nil {
		return fmt.Errorf("recording example extraction audit event: %w", err)
	}
	return nil
}

// examplesExtractedEvent builds the assurance-log envelope for one persisted
// example generation.
//
// The payload identifies the write — which module, which bytes, which pipeline,
// at what status, sealed under which hash — and carries no example bodies. A
// reader that wants them has the content hash to ask the ledger with; the
// assurance log records that the write happened, not what it contained.
func examplesExtractedEvent(record domain2.ExampleRecord) audit.Event {
	payload := map[string]any{
		"module":              record.Coordinate.Path(),
		"version":             record.Coordinate.Version(),
		"pipeline_version":    record.PipelineVersion,
		"overall_status":      record.OverallStatus.String(),
		"example_count":       len(record.Examples),
		"parse_failure_count": len(record.ParseFailures),
		"content_hash":        record.ContentHash,
	}
	// Which bytes the extraction read, and which measurement of them. Both are
	// omitted when the record carries neither, which is the truth for a record
	// derived from no fetched artefact — an empty identity would read as an
	// artefact that hashed to nothing.
	if record.ArtefactIdentity != "" {
		payload["artefact_identity"] = record.ArtefactIdentity
	}
	if record.SourceContentHash != "" {
		payload["source_content_hash"] = record.SourceContentHash
	}
	// A failed extraction states why on the record; the log states it too, so a
	// reader does not have to open the ledger to tell a status apart from its
	// reason.
	if record.FailureDetail != "" {
		payload["failure_detail"] = record.FailureDetail
	}
	return audit.Event{Type: audit.EventExamplesExtracted, Payload: payload}
}
