package sqlite

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
	"github.com/eitanity/kanonarion/internal/extract/domain"
	"github.com/eitanity/kanonarion/internal/extract/ports"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

func sealedRun(t *testing.T, id string) domain.ExtractionRun {
	t.Helper()
	at := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	run, err := domain.ExtractionRunHasher{}.SetContentHash(domain.ExtractionRun{
		SchemaVersion: domain.ExtractionRunSchemaVersion, Ecosystem: fetchdomain.EcosystemGo,
		ID: id, WalkID: "walk-1", RequestedStages: []string{"license"},
		StartedAt: at, CompletedAt: at.Add(time.Second), OverallStatus: domain.ExtractionRunSucceeded,
	})
	if err != nil {
		t.Fatalf("sealing: %v", err)
	}
	return run
}

// installWidenedRun rewrites run's stored bytes as a build with one more
// top-level field would have written them, resealed over those bytes; mutate,
// when set, then alters them. It returns the new seal.
func installWidenedRun(t *testing.T, s *Store, run domain.ExtractionRun, mutate func([]byte) []byte) string {
	t.Helper()
	raw, err := domain.ExtractionRunHasher{}.Marshal(run)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	widened := append([]byte(`{"retired_field":"a shape this build never had",`), raw[1:]...)
	stamped := []byte(`"content_hash":"` + run.ContentHash + `"`)
	if bytes.Count(widened, stamped) != 1 {
		t.Fatalf("fixture has %d top-level seals, want 1", bytes.Count(widened, stamped))
	}
	sum := sha256.Sum256(bytes.Replace(widened, stamped, []byte(`"content_hash":""`), 1))
	seal := "sha256:" + hex.EncodeToString(sum[:])
	blob := bytes.Replace(widened, stamped, []byte(`"content_hash":"`+seal+`"`), 1)
	if mutate != nil {
		blob = mutate(blob)
	}
	if _, err := s.db.DB().Exec(`UPDATE extraction_runs SET raw_record = ? WHERE id = ?`, blob, run.ID); err != nil {
		t.Fatalf("installing the widened row: %v", err)
	}
	return seal
}

// A run this build cannot reproduce is NothingServable naming its seal, never
// ErrExtractionRunIntegrity; one byte altered is still the integrity failure.
func TestGetExtractionRun_DriftIsNothingServableTamperIsIntegrity(t *testing.T) {
	ctx := t.Context()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	var reported []recordseal.SetAsideRow
	s.ReportSetAside(func(rows []recordseal.SetAsideRow) { reported = append(reported, rows...) })

	drifted, good, altered := sealedRun(t, "run-drift"), sealedRun(t, "run-good"), sealedRun(t, "run-altered")
	for _, r := range []domain.ExtractionRun{drifted, good, altered} {
		if err := s.PutExtractionRun(ctx, r); err != nil {
			t.Fatalf("PutExtractionRun: %v", err)
		}
	}
	seal := installWidenedRun(t, s, drifted, nil)
	installWidenedRun(t, s, altered, func(b []byte) []byte {
		b[bytes.Index(b, []byte("a shape this build never had"))] = 'A'
		return b
	})

	_, err = s.GetExtractionRun(ctx, drifted.ID)
	var none *recordseal.NothingServable
	if !errors.As(err, &none) || errors.Is(err, ports.ErrExtractionRunIntegrity) {
		t.Fatalf("drifted run = %v, want *recordseal.NothingServable and not the integrity sentinel", err)
	}
	if len(none.Aside.Rows) != 1 || none.Aside.Rows[0].ContentHash != seal || none.Aside.Rows[0].ID != drifted.ID {
		t.Errorf("set aside = %+v, want %s named by %s", none.Aside.Rows, drifted.ID, seal)
	}
	if len(reported) != 1 || reported[0].ContentHash != seal {
		t.Errorf("reported = %+v, want the run named once", reported)
	}
	if _, err := s.GetExtractionRun(ctx, good.ID); err != nil {
		t.Errorf("readable run = %v", err)
	}
	if _, err := s.GetExtractionRun(ctx, altered.ID); !errors.Is(err, ports.ErrExtractionRunIntegrity) {
		t.Errorf("altered run = %v, want ErrExtractionRunIntegrity", err)
	}
	// The listing reads columns and never verifies, so every row stays listed.
	sums, err := s.ListExtractionRuns(ctx, ports.ExtractionRunFilter{})
	if err != nil || len(sums) != 3 {
		t.Errorf("ListExtractionRuns = %d rows, %v; want all three", len(sums), err)
	}
}
