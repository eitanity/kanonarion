package application

import (
	"context"
	"errors"
	"fmt"

	"github.com/eitanity/kanonarion/internal/audit"
	"github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

// ErrVerificationFailed marks a fact record that failed its integrity
// verification. Both the write side (Ingest, which refuses to persist) and the
// read side (ReadVerified, which refuses to present) wrap the underlying domain
// error with this sentinel, so a consumer can distinguish a tampered or
// unverifiable record — treat-as-unavailable, fail-closed — from a
// genuine absence or an infrastructure error.
var ErrVerificationFailed = errors.New("fact record failed verification")

// ValidateAndIngestUseCase is the verified-fact boundary:
// records cross into the store (Ingest) and back out to a consumer
// (ReadVerified) only if they satisfy the same integrity invariants, so an
// imported airgap-bundle record is held to exactly the bar a freshly extracted
// record is. Verification is fail-closed — a record that fails is never
// persisted and never presented; it is treated as unavailable, not as a
// confident fact.
//
// It is the consume-side seam for the airgap bundle: full signature/Merkle
// anchoring against bundled signing material is layered on by later consumer
// work, which extends domain.VerifyFactRecord; this use case wires the seam into
// the store on both directions.
type ValidateAndIngestUseCase struct {
	store ports.FactStore
	audit ports.AuditSink
}

// NewValidateAndIngestUseCase constructs the use case over the fact store.
func NewValidateAndIngestUseCase(store ports.FactStore) *ValidateAndIngestUseCase {
	return &ValidateAndIngestUseCase{store: store}
}

// WithAudit wires an assurance-log sink so ReadVerified emits a verification
// outcome per read: record_read_verified when the record passes re-verification,
// verification_failed with the rejection reason when it does not. The sink is
// optional (mirroring WithSigner on the fetch pipeline): a caller that supplies
// none simply logs nothing. Returns the receiver for chaining.
func (uc *ValidateAndIngestUseCase) WithAudit(sink ports.AuditSink) *ValidateAndIngestUseCase {
	uc.audit = sink
	return uc
}

// Ingest verifies a record's integrity invariants and, only if they hold,
// persists it. A record that fails verification is rejected fail-closed: the
// returned error wraps ErrVerificationFailed and nothing is written, so a
// tampered import cannot enter the store masquerading as a confident fact. An
// infrastructure failure from the store is returned without the sentinel.
func (uc *ValidateAndIngestUseCase) Ingest(ctx context.Context, record domain.FactRecord) error {
	if err := domain.VerifyFactRecord(record); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrVerificationFailed, record.Coordinate(), err)
	}
	if err := uc.store.PutFetchRecord(ctx, record); err != nil {
		return fmt.Errorf("ingesting record for %s: %w", record.Coordinate(), err)
	}
	return nil
}

// ReadVerified retrieves a record and re-verifies it before returning it
// (verify-on-read, fail-closed). The returned bool is true only for a record
// that is present AND passes verification:
// - absent: zero record, false, nil — a genuine absence;
// - present and verified: the record, true, nil;
// - present but failed verification: zero record, false, an error wrapping
// ErrVerificationFailed — treated-as-unavailable, never returned as found;
// - infrastructure failure: zero record, false, the store error.
//
// The caller treats any non-nil error as unavailable (non-zero exit per
// ); only (false, nil) means the record genuinely does not exist.
func (uc *ValidateAndIngestUseCase) ReadVerified(ctx context.Context, coord domain.ModuleCoordinate, pipelineVersion string) (domain.FactRecord, bool, error) {
	rec, found, err := uc.store.GetFetchRecord(ctx, coord, pipelineVersion)
	if err != nil {
		return domain.FactRecord{}, false, fmt.Errorf("reading record for %s: %w", coord, err)
	}
	if !found {
		return domain.FactRecord{}, false, nil
	}
	if verr := domain.VerifyFactRecord(rec); verr != nil {
		failed := fmt.Errorf("%w: %s: %w", ErrVerificationFailed, coord, verr)
		if aerr := uc.recordEvent(audit.EventVerificationFailed, coord, pipelineVersion, rec, verr); aerr != nil {
			// Fail-closed still holds: preserve the verification sentinel while
			// surfacing the assurance-log failure rather than swallowing it.
			return domain.FactRecord{}, false, errors.Join(failed, aerr)
		}
		return domain.FactRecord{}, false, failed
	}
	if aerr := uc.recordEvent(audit.EventRecordReadVerified, coord, pipelineVersion, rec, nil); aerr != nil {
		return domain.FactRecord{}, false, aerr
	}
	return rec, true, nil
}

// recordEvent appends the assurance-log event for a verified read. It emits the
// coordinate, pipeline version and the record's verification status; on the
// failure path it also carries the rejection reason. A nil sink is a no-op; an
// emit failure is returned so a successful read is never presented without its
// log entry, and a rejected read never loses the fact that it was rejected.
func (uc *ValidateAndIngestUseCase) recordEvent(
	t audit.EventType, coord domain.ModuleCoordinate, pipelineVersion string,
	rec domain.FactRecord, reason error,
) error {
	if uc.audit == nil {
		return nil
	}
	payload := map[string]any{
		"module":              coord.Path,
		"version":             coord.Version,
		"pipeline_version":    pipelineVersion,
		"verification_status": rec.VerificationStatus,
	}
	if reason != nil {
		payload["reason"] = reason.Error()
	}
	if err := uc.audit.RecordEvent(audit.Event{Type: t, Payload: payload}); err != nil {
		return fmt.Errorf("recording read-verification audit event for %s: %w", coord, err)
	}
	return nil
}
