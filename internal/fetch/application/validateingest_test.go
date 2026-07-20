package application_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/audit"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/fetch/application"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// validRecord returns a fact record with a valid canonical content hash set.
func validRecord(t *testing.T) domain2.FactRecord {
	t.Helper()
	r := domain2.NewFactRecord(domain2.FetchedModule{
		Coordinate:         coordinate.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.2.3"},
		ModuleHash:         domain2.ModuleHash{Algorithm: "h1", Value: "abc=="},
		GoModHash:          domain2.ModuleHash{Algorithm: "h1", Value: "def=="},
		VerificationStatus: domain2.Verified,
		FetchedAt:          time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		PipelineVersion:    "0.1.0",
		ContentLocation:    "sha256:deadbeef",
	})
	hashed, err := domain2.CanonicalHasher{}.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	return hashed
}

// boomFacts is a FactStore that fails every operation, to exercise the
// infrastructure-error path distinct from verification failure.
type boomFacts struct{ err error }

func (b boomFacts) PutFetchRecord(context.Context, domain2.FactRecord) error { return b.err }

func (b boomFacts) GetFetchRecord(context.Context, coordinate.ModuleCoordinate, string) (domain2.FactRecord, bool, error) {
	return domain2.FactRecord{}, false, b.err
}

func TestValidateAndIngest_Ingest_Valid(t *testing.T) {
	store := newFakeFacts()
	uc := application.NewValidateAndIngestUseCase(store)
	rec := validRecord(t)

	if err := uc.Ingest(context.Background(), rec); err != nil {
		t.Fatalf("Ingest of a valid record: %v", err)
	}

	got, found, err := store.GetFetchRecord(context.Background(), rec.Coordinate(), rec.PipelineVersion)
	if err != nil || !found {
		t.Fatalf("record not persisted: found=%v err=%v", found, err)
	}
	if got.ContentHash != rec.ContentHash {
		t.Errorf("persisted record differs: got %q want %q", got.ContentHash, rec.ContentHash)
	}
}

func TestValidateAndIngest_Ingest_TamperedRejectedFailClosed(t *testing.T) {
	store := newFakeFacts()
	uc := application.NewValidateAndIngestUseCase(store)
	rec := validRecord(t)
	rec.VerificationStatus = "tampered" // body mutated after hashing

	err := uc.Ingest(context.Background(), rec)
	if !errors.Is(err, application.ErrVerificationFailed) {
		t.Fatalf("want ErrVerificationFailed, got %v", err)
	}
	// Fail-closed: nothing reached the store.
	if _, found, _ := store.GetFetchRecord(context.Background(), rec.Coordinate(), rec.PipelineVersion); found {
		t.Fatal("tampered record was persisted; ingest is not fail-closed")
	}
}

func TestValidateAndIngest_Ingest_StoreError(t *testing.T) {
	sentinel := errors.New("disk full")
	uc := application.NewValidateAndIngestUseCase(boomFacts{err: sentinel})

	err := uc.Ingest(context.Background(), validRecord(t))
	if !errors.Is(err, sentinel) {
		t.Fatalf("want store error, got %v", err)
	}
	// A genuine infra error must NOT be reported as a verification failure.
	if errors.Is(err, application.ErrVerificationFailed) {
		t.Fatal("store error misreported as verification failure")
	}
}

func TestValidateAndIngest_ReadVerified_Valid(t *testing.T) {
	store := newFakeFacts()
	rec := validRecord(t)
	if err := store.PutFetchRecord(context.Background(), rec); err != nil {
		t.Fatalf("seed: %v", err)
	}
	uc := application.NewValidateAndIngestUseCase(store)

	got, found, err := uc.ReadVerified(context.Background(), rec.Coordinate(), rec.PipelineVersion)
	if err != nil || !found {
		t.Fatalf("ReadVerified valid record: found=%v err=%v", found, err)
	}
	if got.ContentHash != rec.ContentHash {
		t.Errorf("returned record differs: got %q want %q", got.ContentHash, rec.ContentHash)
	}
}

func TestValidateAndIngest_ReadVerified_Absent(t *testing.T) {
	uc := application.NewValidateAndIngestUseCase(newFakeFacts())

	rec, found, err := uc.ReadVerified(context.Background(), coordinate.ModuleCoordinate{Path: "x", Version: "v1"}, "0.1.0")
	if err != nil {
		t.Fatalf("absent read must not error: %v", err)
	}
	if found {
		t.Fatal("found=true for an absent record")
	}
	if rec != (domain2.FactRecord{}) {
		t.Error("absent read returned a non-zero record")
	}
}

func TestValidateAndIngest_ReadVerified_TamperedFailClosed(t *testing.T) {
	store := newFakeFacts()
	rec := validRecord(t)
	rec.VerificationStatus = "tampered-on-disk" // poisoned without re-hashing
	if err := store.PutFetchRecord(context.Background(), rec); err != nil {
		t.Fatalf("seed: %v", err)
	}
	uc := application.NewValidateAndIngestUseCase(store)

	got, found, err := uc.ReadVerified(context.Background(), rec.Coordinate(), rec.PipelineVersion)
	if !errors.Is(err, application.ErrVerificationFailed) {
		t.Fatalf("want ErrVerificationFailed, got %v", err)
	}
	// Treated-as-unavailable: never returned as found, never the record body.
	if found {
		t.Fatal("tampered record returned as found; read is not fail-closed")
	}
	if got != (domain2.FactRecord{}) {
		t.Error("tampered read leaked the record body")
	}
}

func TestValidateAndIngest_ReadVerified_AuditsCleanRead(t *testing.T) {
	store := newFakeFacts()
	rec := validRecord(t)
	if err := store.PutFetchRecord(context.Background(), rec); err != nil {
		t.Fatalf("seed: %v", err)
	}
	sink := newFakeAudit()
	uc := application.NewValidateAndIngestUseCase(store).WithAudit(sink)

	got, found, err := uc.ReadVerified(context.Background(), rec.Coordinate(), rec.PipelineVersion)
	if err != nil || !found {
		t.Fatalf("ReadVerified clean record: found=%v err=%v", found, err)
	}
	if got.ContentHash != rec.ContentHash {
		t.Errorf("returned record differs from seed")
	}
	ev := sink.only(t)
	if ev.Type != audit.EventRecordReadVerified {
		t.Fatalf("event type = %q, want %q", ev.Type, audit.EventRecordReadVerified)
	}
	if ev.Payload["module"] != rec.ModulePath || ev.Payload["version"] != rec.ModuleVersion {
		t.Errorf("payload coordinate = %v@%v, want %s", ev.Payload["module"], ev.Payload["version"], rec.Coordinate())
	}
	if _, hasReason := ev.Payload["reason"]; hasReason {
		t.Error("a clean verified read must not carry a rejection reason")
	}
}

func TestValidateAndIngest_ReadVerified_AuditsTamperedRead(t *testing.T) {
	store := newFakeFacts()
	rec := validRecord(t)
	rec.VerificationStatus = "tampered-on-disk" // poisoned without re-hashing
	if err := store.PutFetchRecord(context.Background(), rec); err != nil {
		t.Fatalf("seed: %v", err)
	}
	sink := newFakeAudit()
	uc := application.NewValidateAndIngestUseCase(store).WithAudit(sink)

	_, found, err := uc.ReadVerified(context.Background(), rec.Coordinate(), rec.PipelineVersion)
	if !errors.Is(err, application.ErrVerificationFailed) {
		t.Fatalf("want ErrVerificationFailed, got %v", err)
	}
	if found {
		t.Fatal("tampered record must not be served")
	}
	ev := sink.only(t)
	if ev.Type != audit.EventVerificationFailed {
		t.Fatalf("event type = %q, want %q", ev.Type, audit.EventVerificationFailed)
	}
	if r, ok := ev.Payload["reason"].(string); !ok || r == "" {
		t.Errorf("verification_failed payload must carry a non-empty reason, got %v", ev.Payload["reason"])
	}
}

func TestValidateAndIngest_ReadVerified_Absent_NoAudit(t *testing.T) {
	sink := newFakeAudit()
	uc := application.NewValidateAndIngestUseCase(newFakeFacts()).WithAudit(sink)

	_, found, err := uc.ReadVerified(context.Background(), coordinate.ModuleCoordinate{Path: "x", Version: "v1"}, "0.1.0")
	if err != nil || found {
		t.Fatalf("absent read: found=%v err=%v", found, err)
	}
	// A genuine absence is not a verification outcome — nothing is logged.
	sink.mu.Lock()
	n := len(sink.events)
	sink.mu.Unlock()
	if n != 0 {
		t.Fatalf("absent read must emit no audit event, got %d", n)
	}
}

func TestValidateAndIngest_ReadVerified_AuditFailureSurfaced(t *testing.T) {
	// Clean read but the assurance log is unwritable: the read fails rather than
	// serving a record it could not record.
	store := newFakeFacts()
	rec := validRecord(t)
	if err := store.PutFetchRecord(context.Background(), rec); err != nil {
		t.Fatalf("seed: %v", err)
	}
	sink := &fakeAudit{err: errors.New("log unwritable")}
	uc := application.NewValidateAndIngestUseCase(store).WithAudit(sink)

	_, found, err := uc.ReadVerified(context.Background(), rec.Coordinate(), rec.PipelineVersion)
	if err == nil {
		t.Fatal("expected error when the assurance log cannot be written")
	}
	if found {
		t.Fatal("a record whose verified-read could not be logged must not be served")
	}
}

func TestValidateAndIngest_ReadVerified_TamperedAuditFailureJoinsSentinel(t *testing.T) {
	// Even when the assurance log is unwritable, a tampered read must still
	// report ErrVerificationFailed so fail-closed handling is preserved.
	store := newFakeFacts()
	rec := validRecord(t)
	rec.VerificationStatus = "tampered-on-disk"
	if err := store.PutFetchRecord(context.Background(), rec); err != nil {
		t.Fatalf("seed: %v", err)
	}
	sink := &fakeAudit{err: errors.New("log unwritable")}
	uc := application.NewValidateAndIngestUseCase(store).WithAudit(sink)

	_, found, err := uc.ReadVerified(context.Background(), rec.Coordinate(), rec.PipelineVersion)
	if !errors.Is(err, application.ErrVerificationFailed) {
		t.Fatalf("want ErrVerificationFailed preserved, got %v", err)
	}
	if found {
		t.Fatal("tampered record must not be served")
	}
}

func TestValidateAndIngest_ReadVerified_StoreError(t *testing.T) {
	sentinel := errors.New("db closed")
	uc := application.NewValidateAndIngestUseCase(boomFacts{err: sentinel})

	_, found, err := uc.ReadVerified(context.Background(), coordinate.ModuleCoordinate{Path: "x", Version: "v1"}, "0.1.0")
	if !errors.Is(err, sentinel) {
		t.Fatalf("want store error, got %v", err)
	}
	if found {
		t.Fatal("found=true on store error")
	}
	if errors.Is(err, application.ErrVerificationFailed) {
		t.Fatal("store error misreported as verification failure")
	}
}
