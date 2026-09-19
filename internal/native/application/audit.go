package application

import (
	"fmt"

	"github.com/eitanity/kanonarion/internal/audit"

	"github.com/eitanity/kanonarion/internal/native/domain"
	"github.com/eitanity/kanonarion/internal/native/ports"
)

// emitNativeComponentsRecorded appends one native_components_recorded event for
// a measurement this run persisted.
//
// A nil sink disables emission. A record served from cache never reaches here:
// the event says a measurement was WRITTEN, so emitting on a cache hit would
// report a write that did not happen. A run that could not read the artefact at
// all returns before the write and so appends nothing — an absence is not an
// observation.
func emitNativeComponentsRecorded(sink ports.AuditSink, rec domain.Record) error {
	if sink == nil {
		return nil
	}
	if err := sink.RecordEvent(nativeComponentsRecordedEvent(rec)); err != nil {
		return fmt.Errorf("recording native components audit event: %w", err)
	}
	return nil
}

// nativeComponentsRecordedEvent builds the assurance-log envelope for one
// persisted native measurement.
//
// The payload identifies the write — which module, which bytes, at which
// detection generation, what was found, sealed under which hash — and carries no
// part of the measurement's claims. No component name, no version, no file and
// no declaration: those are the RECORD's, reachable through the content hash,
// and restating them here would make the log a second unsealed copy of the
// evidence rather than a witness that the evidence was written.
//
// The counts are the exception, and they are counts rather than contents for
// that reason: they say how much the write contained, which is a property of
// the write, while what it contained is a property of the record. They are
// emitted at zero, because a measurement that found nothing is a measurement.
//
// The generation is named by its two independent axes, exactly as the record and
// `native --json` name it: the detection logic and the recipe catalogue evolve
// apart, and the fingerprint the store keys on is their concatenation.
func nativeComponentsRecordedEvent(rec domain.Record) audit.Event {
	payload := map[string]any{
		"module":                   rec.Coordinate.Path(),
		"version":                  rec.Coordinate.Version(),
		"artefact_identity":        rec.ArtefactIdentity,
		"pipeline_version":         rec.PipelineVersion,
		"recipe_catalogue_version": rec.RecipeCatalogueVersion,
		"presence":                 string(rec.Presence),
		"component_count":          len(rec.Components),
		"source_count":             len(rec.Sources),
		"linked_library_count":     len(rec.LinkedLibraries),
		"content_hash":             rec.ContentHash,
	}
	return audit.Event{Type: audit.EventNativeComponentsRecorded, Payload: payload}
}
