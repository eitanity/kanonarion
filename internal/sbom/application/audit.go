package application

import (
	"fmt"

	"github.com/eitanity/kanonarion/internal/audit"

	"github.com/eitanity/kanonarion/internal/sbom/domain"
	"github.com/eitanity/kanonarion/internal/sbom/ports"
)

// emitSBOMGenerated appends one sbom_generated event for a document this run
// produced and persisted. A nil sink disables emission.
//
// It is reached only after the record is in the store, so a failed append
// reports that a persisted document is unlogged rather than undoing the write.
// A package-scoped (--package) request persists nothing and so never reaches
// here: the event says a record was written, and emitting for an ephemeral
// document would put a record in the log that no store holds.
func emitSBOMGenerated(sink ports.AuditSink, record domain.SBOMRecord, callerSuppliedTimestamp bool) error {
	if sink == nil {
		return nil
	}
	if err := sink.RecordEvent(sbomGeneratedEvent(record, callerSuppliedTimestamp)); err != nil {
		return fmt.Errorf("recording sbom generated audit event: %w", err)
	}
	return nil
}

// emitSBOMServed appends one sbom_served event for a stored document this run
// handed back instead of generating. A nil sink disables emission.
//
// The append happens before the document is returned, so a failed append fails
// the serving: the alternative is a document that left the building with no
// trace, which is the gap this closes rather than a smaller version of it.
func emitSBOMServed(sink ports.AuditSink, record domain.SBOMRecord, requestedBy string) error {
	if sink == nil {
		return nil
	}
	if err := sink.RecordEvent(sbomServedEvent(record, requestedBy)); err != nil {
		return fmt.Errorf("recording sbom served audit event: %w", err)
	}
	return nil
}

// sbomGeneratedEvent builds the assurance-log envelope for one persisted SBOM
// document.
//
// The payload identifies the artefact — which walk it describes, in which
// format, under which pipeline version, and the hash of the bytes produced —
// and states whether the caller supplied the document's creation time, because
// a caller-supplied time bypasses the cache and is the one input that makes two
// otherwise identical requests produce different documents. It carries none of
// the document's own claims: the component list, the licences and the
// completeness statements are the DOCUMENT's, and the content hash is what
// reaches them. Restating them here would make the log an unsealed second copy
// of the artefact rather than a witness that the artefact was made.
func sbomGeneratedEvent(record domain.SBOMRecord, callerSuppliedTimestamp bool) audit.Event {
	return audit.Event{
		Type: audit.EventSBOMGenerated,
		Payload: map[string]any{
			"sbom_id":                   record.ID,
			"walk_id":                   record.WalkID,
			"format":                    string(record.Format),
			"pipeline_version":          record.PipelineVersion,
			"content_hash":              record.ContentHash,
			"caller_supplied_timestamp": callerSuppliedTimestamp,
		},
	}
}

// sbomServedEvent builds the envelope for one stored document served from cache.
//
// It names the record served under the same identifying fields as the
// generation event, so the two can be matched against each other, plus the
// identity that asked for THIS serving. The record's own operator is not that
// identity: it named whoever requested the original generation, which may have
// been another person on another day, and reporting it here would answer "who
// received this document" with the wrong name. An empty requester is left out
// rather than recorded as an empty string, since no identity was supplied and
// an empty one would read as an anonymous principal.
func sbomServedEvent(record domain.SBOMRecord, requestedBy string) audit.Event {
	payload := map[string]any{
		"sbom_id":          record.ID,
		"walk_id":          record.WalkID,
		"format":           string(record.Format),
		"pipeline_version": record.PipelineVersion,
		"content_hash":     record.ContentHash,
	}
	if requestedBy != "" {
		payload["requested_by"] = requestedBy
	}
	return audit.Event{Type: audit.EventSBOMServed, Payload: payload}
}
