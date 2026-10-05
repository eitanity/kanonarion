package sqlite_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/blobcodec"
	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
	"github.com/eitanity/kanonarion/internal/walk/adapters/walks/sqlite"
	"github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// installWidenedWalk rewrites rec's stored row as a build with one more
// top-level field would have written it, resealed over those bytes and filed
// under the new seal; mutate, when set, then alters the bytes. It returns the
// seal the row is filed under.
func installWidenedWalk(t *testing.T, s *sqlite.Store, rec domain.WalkRecord, mutate func([]byte) []byte) string {
	t.Helper()
	raw, err := domain.WalkRecordHasher{}.Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	widened := append([]byte(`{"retired_field":"a shape this build never had",`), raw[1:]...)
	stamped := []byte(`"content_hash":"` + rec.ContentHash + `"`)
	if bytes.Count(widened, stamped) != 1 {
		t.Fatalf("fixture has %d top-level seals, want 1", bytes.Count(widened, stamped))
	}
	sum := sha256.Sum256(bytes.Replace(widened, stamped, []byte(`"content_hash":""`), 1))
	seal := "sha256:" + hex.EncodeToString(sum[:])
	blob := bytes.Replace(widened, stamped, []byte(`"content_hash":"`+seal+`"`), 1)
	if mutate != nil {
		blob = mutate(blob)
	}
	if _, err := s.InternalDB().DB().Exec(`UPDATE walks SET serialised = ?, content_hash = ? WHERE id = ?`,
		blobcodec.Encode(blob), seal, rec.ID); err != nil {
		t.Fatalf("installing the widened row: %v", err)
	}
	return seal
}

// A walk this build cannot reproduce has no other generation to serve, so the
// read is NothingServable naming the walk and its seal, never ErrWalkIntegrity,
// and the reporter hears of it even when a caller swallows the refusal.
func TestGetWalk_DriftedWalkIsNothingServable(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()
	var reported []recordseal.SetAsideRow
	s.ReportSetAside(func(rows []recordseal.SetAsideRow) { reported = append(reported, rows...) })

	rec := buildWalkRecord("01HZTEST0000000000000DRFT1")
	other := buildWalkRecord("01HZTEST0000000000000GOOD1")
	for _, r := range []domain.WalkRecord{rec, other} {
		if err := s.PutWalk(ctx, r); err != nil {
			t.Fatalf("PutWalk: %v", err)
		}
	}
	seal := installWidenedWalk(t, s, rec, nil)

	_, err := s.GetWalk(ctx, rec.ID)
	var none *recordseal.NothingServable
	if !errors.As(err, &none) {
		t.Fatalf("GetWalk = %v, want *recordseal.NothingServable", err)
	}
	if errors.Is(err, walkports.ErrWalkIntegrity) || !errors.Is(err, recordseal.ErrGenerationDrift) {
		t.Errorf("GetWalk = %v, want drift and not the integrity sentinel", err)
	}
	if len(none.Aside.Rows) != 1 || none.Aside.Rows[0].ContentHash != seal || none.Aside.Rows[0].ID != rec.ID ||
		none.Aside.Rows[0].Kind != sqlite.RecordKind {
		t.Errorf("set aside = %+v, want walk %s named by %s", none.Aside.Rows, rec.ID, seal)
	}
	if len(reported) != 1 || reported[0].ContentHash != seal {
		t.Errorf("reported = %+v, want the walk named once", reported)
	}
	if _, err := s.GetWalk(ctx, other.ID); err != nil {
		t.Errorf("the readable walk = %v, want it served", err)
	}
}

// Tamper control: one byte altered after resealing is still ErrWalkIntegrity,
// and so are intact bytes filed under a seal they do not carry.
func TestGetWalk_AlteredWalkIsStillIntegrity(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()
	rec := buildWalkRecord("01HZTEST0000000000000ALTR1")
	if err := s.PutWalk(ctx, rec); err != nil {
		t.Fatalf("PutWalk: %v", err)
	}
	installWidenedWalk(t, s, rec, func(b []byte) []byte {
		b[bytes.Index(b, []byte("a shape this build never had"))] = 'A'
		return b
	})
	if _, err := s.GetWalk(ctx, rec.ID); !errors.Is(err, walkports.ErrWalkIntegrity) {
		t.Errorf("altered walk: GetWalk = %v, want ErrWalkIntegrity", err)
	}

	installWidenedWalk(t, s, rec, nil)
	if _, err := s.InternalDB().DB().Exec(`UPDATE walks SET content_hash = 'sha256:00' WHERE id = ?`, rec.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetWalk(ctx, rec.ID); !errors.Is(err, walkports.ErrWalkIntegrity) {
		t.Errorf("refiled walk: GetWalk = %v, want ErrWalkIntegrity", err)
	}
}
