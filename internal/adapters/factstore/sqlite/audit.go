package sqlite

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/eitanity/kanonarion/internal/audit"
	"github.com/eitanity/kanonarion/internal/coordinate"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
	"github.com/eitanity/kanonarion/internal/sqlitestore"
)

// auditTimeFormat matches the fact store's persisted measurement time.
//
// The log is what a ledger row is correlated AGAINST, so recording it at second
// precision would leave the correlation no better off — two writes within one
// second would still be indistinguishable on the side of the pair that is meant
// to explain the other. These timestamps are covered by no content hash, so
// widening them changes nothing that has to verify, and the second-precision
// lines already in the log stay readable by any RFC3339 parser.
const auditTimeFormat = "2006-01-02T15:04:05.000000000Z07:00"

// AuditLog writes an append-only JSONL file: one entry per fact-record write,
// plus the generic supply-chain events other contexts emit through RecordEvent.
// It is the durable assurance trail of what was written; it is not itself a
// verifier. The JSONL is line-oriented so it can be grepped or shipped to
// external tooling.
type AuditLog struct {
	mu   sync.Mutex
	path string
}

// NewAuditLog creates an AuditLog writing to path. On Linux, a best-effort
// attempt is made to set the append-only attribute via chattr +a (T9).
func NewAuditLog(path string) (*AuditLog, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("creating audit log dir: %w", err)
	}
	// Create the file if it does not exist so chattr has a target.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304 -- path constructed from operator-controlled store root
	if err != nil {
		return nil, fmt.Errorf("creating audit log: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("closing audit log after create: %w", err)
	}
	// Best-effort: set append-only filesystem attribute on Linux. Fails on non-ext4 and in CI.
	_ = exec.Command("chattr", "+a", path).Run() /* #nosec G204 -- chattr path is a fixed string */
	return &AuditLog{path: path}, nil
}

// auditEntry is the envelope for a fact-record write. The EventType field is
// purely additive (additive-only rule): existing readers ignore the
// unknown field, while the flat fact fields keep their historical layout so no
// JSONL consumer breaks. New event kinds use the generic eventEnvelope below
// rather than growing this struct — that is what makes event-type extension
// cheap: a new event is a new constant, never a schema migration.
type auditEntry struct {
	EventType          audit.EventType `json:"event_type"`
	Timestamp          string          `json:"timestamp"`
	ModulePath         string          `json:"module_path"`
	ModuleVersion      string          `json:"module_version"`
	PipelineVersion    string          `json:"pipeline_version"`
	VerificationStatus string          `json:"verification_status"`
	ContentHash        string          `json:"content_hash"`
	// AcquisitionMode names the path the recorded bytes arrived by (proxy,
	// modcache, local). It is additive and omitted when absent, so existing
	// readers are unaffected; without it a log entry could not say which mode
	// wrote a record, and a run that demoted a network-verified record to a
	// module-cache one was indistinguishable from an ordinary re-measurement.
	AcquisitionMode string `json:"acquisition_mode,omitempty"`

	// ArtefactIdentity is the h1 identity of the artefact the record describes.
	// It is the question the ledger is keyed on, and until it was logged the
	// audit trail could not answer it: the log recorded 44 writes of one
	// coordinate without being able to say whether they described one artefact
	// or 44. Without it the log cannot corroborate the store, which is exactly
	// the failure this ledger exists to fix, relocated one layer out.
	ArtefactIdentity string `json:"artefact_identity,omitempty"`

	// MeasurementKind says what the write did — acquired or revalidated — and is
	// additionally where "unchanged" is recorded. A cache hit writes no row at
	// all, so a run that checked and found nothing changed leaves no trace in
	// the store; the log is where that fact belongs.
	MeasurementKind string `json:"measurement_kind,omitempty"`
}

// eventEnvelope is the generic JSONL shape for every non-fact event. The
// discriminator plus a free-form payload is the whole contract: a gap ticket
// emits a new event by choosing a new audit.EventType and a payload map,
// touching neither this adapter nor any storage schema.
type eventEnvelope struct {
	EventType audit.EventType `json:"event_type"`
	Timestamp string          `json:"timestamp"`
	Payload   map[string]any  `json:"payload,omitempty"`
}

// Record appends an entry for r to the audit log.
func (a *AuditLog) Record(r domain2.FactRecord) error {
	// A malformed hash must not stop the write being logged: the log's job is to
	// say what was written, and losing the entry because the identity could not
	// be rendered would be the silence this log exists to prevent. The identity
	// is simply omitted, which reads as "not recorded" rather than as absent.
	identity, err := domain2.ArtefactIdentityOf(r)
	if err != nil {
		identity = domain2.ArtefactIdentity{}
	}
	entry := auditEntry{
		EventType:          audit.EventFactRecordWritten,
		Timestamp:          time.Now().UTC().Format(auditTimeFormat),
		ModulePath:         r.ModulePath,
		ModuleVersion:      r.ModuleVersion,
		PipelineVersion:    r.PipelineVersion,
		VerificationStatus: r.VerificationStatus,
		ContentHash:        r.ContentHash,
		AcquisitionMode:    r.AcquisitionMode,
		ArtefactIdentity:   identity.String(),
		MeasurementKind:    r.MeasurementKind,
	}
	line, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshalling audit entry: %w", err)
	}
	return a.appendLine(line)
}

// RecordEvent appends a generic audit event. This is the extension point the
// supply-chain gap tickets emit through; ships it unused
// so those tickets add no audit plumbing of their own.
func (a *AuditLog) RecordEvent(e audit.Event) error {
	if err := e.Validate(); err != nil {
		return fmt.Errorf("invalid audit event: %w", err)
	}
	line, err := json.Marshal(eventEnvelope{
		EventType: e.Type,
		Timestamp: time.Now().UTC().Format(auditTimeFormat),
		Payload:   e.Payload,
	})
	if err != nil {
		return fmt.Errorf("marshalling audit event: %w", err)
	}
	return a.appendLine(line)
}

// appendLine writes one JSONL record under the log mutex.
func (a *AuditLog) appendLine(line []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	f, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304 -- path constructed from operator-controlled store root
	if err != nil {
		return fmt.Errorf("opening audit log: %w", err)
	}

	_, writeErr := fmt.Fprintf(f, "%s\n", line)
	closeErr := f.Close()
	if writeErr != nil {
		return fmt.Errorf("writing audit entry: %w", writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("closing audit log: %w", closeErr)
	}
	return nil
}

// AuditingStore wraps a Store and appends to an AuditLog on every write.
// It implements ports.FactStore.
type AuditingStore struct {
	inner *Store
	audit *AuditLog
}

// NewAuditingStore constructs an AuditingStore. auditPath is the JSONL log path.
func NewAuditingStore(inner *Store, auditPath string) (*AuditingStore, error) {
	al, err := NewAuditLog(auditPath)
	if err != nil {
		return nil, err
	}
	return &AuditingStore{inner: inner, audit: al}, nil
}

// Close closes the underlying database.
func (s *AuditingStore) Close() error { return s.inner.Close() }

// InternalDB returns the underlying DB so it can be shared with other stores
// that operate on the same database file.
func (s *AuditingStore) InternalDB() sqlitestore.DB { return s.inner.InternalDB() }

// RecordEvent appends a generic audit event, satisfying the narrow audit
// sinks that other contexts (e.g. directive) depend on without
// importing this adapter's concrete types.
func (s *AuditingStore) RecordEvent(e audit.Event) error { return s.audit.RecordEvent(e) }

// PutFetchRecord appends the measurement and mirrors it into the audit log.
func (s *AuditingStore) PutFetchRecord(ctx context.Context, sealed domain2.SealedRecord) error {
	if err := s.inner.PutFetchRecord(ctx, sealed); err != nil {
		return err
	}
	return s.audit.Record(sealed.Record())
}

// GetFetchRecord delegates to the inner store.
func (s *AuditingStore) GetFetchRecord(ctx context.Context, coord coordinate.ModuleCoordinate, pv string) (domain2.CompositeRecord, bool, error) {
	return s.inner.GetFetchRecord(ctx, coord, pv)
}

// ListFetchRecords delegates to the inner store, carrying the optional
// ports.FactRecordLister capability through the audit decorator. A decorator
// that silently dropped it would make the write path unable to inherit
// validation legs whenever auditing was enabled — which is always, in
// production.
func (s *AuditingStore) ListFetchRecords(ctx context.Context, coord coordinate.ModuleCoordinate, pv string) ([]domain2.FactRecord, error) {
	return s.inner.ListFetchRecords(ctx, coord, pv)
}

// PutAttestation delegates to the inner store. Attestations are additive
// provenance, not fact writes, so they are not mirrored into the audit log.
func (s *AuditingStore) PutAttestation(ctx context.Context, r domain2.AttestationRecord) error {
	return s.inner.PutAttestation(ctx, r)
}

// ListAttestations delegates to the inner store.
func (s *AuditingStore) ListAttestations(ctx context.Context, coord coordinate.ModuleCoordinate, pv string) ([]domain2.AttestationRecord, error) {
	return s.inner.ListAttestations(ctx, coord, pv)
}

var (
	_ ports.FactStore        = (*AuditingStore)(nil)
	_ ports.FactRecordLister = (*AuditingStore)(nil)
	_ ports.AttestationStore = (*AuditingStore)(nil)
)
