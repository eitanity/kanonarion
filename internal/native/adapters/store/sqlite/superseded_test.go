package sqlite_test

import (
	"context"
	"errors"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	nativesqlite "github.com/eitanity/kanonarion/internal/native/adapters/store/sqlite"
	"github.com/eitanity/kanonarion/internal/native/ports"
)

// A record of a directory read under the published coordinate answers no read:
// the published record is served, the listing drops it unless every generation
// is asked for, then marks it, and it never makes the published row disputed.
// The control: with nothing superseded the two artefacts still conflict.
func TestStore_SupersededLocalRecordIsLeftOut(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	published := sqliteRecord(t, "zip:h1:published=")
	local := sqliteRecord(t, "zip:h1:directory=")
	if err := s.PutNativeRecord(ctx, published); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.PutNativeRecord(ctx, local); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, _, err := s.GetNativeRecord(ctx, published.Coordinate); !errors.Is(err, ports.ErrNativeConflict) {
		t.Fatalf("control: with no reader the two artefacts must conflict, got %v", err)
	}

	s.WithSupersededArtefacts(func(context.Context, coordinate.ModuleCoordinate) (map[string]bool, error) {
		return map[string]bool{"zip:h1:directory=": true}, nil
	})
	got, found, err := s.GetNativeRecord(ctx, published.Coordinate)
	if err != nil || !found || got.ArtefactIdentity != "zip:h1:published=" {
		t.Fatalf("GetNativeRecord = %s, %v, %v; want the published record", got.ArtefactIdentity, found, err)
	}
	rows, err := s.ListNativeRecords(ctx, ports.NativeFilter{})
	if err != nil || len(rows) != 1 || rows[0].ArtefactIdentity != "zip:h1:published=" || rows[0].Conflict != nil {
		t.Errorf("listing = %+v, %v; want the published row alone, undisputed", rows, err)
	}
	assertMarkedWhenEveryGenerationIsListed(t, s)
}

func assertMarkedWhenEveryGenerationIsListed(t *testing.T, s *nativesqlite.Store) {
	t.Helper()
	rows, err := s.ListNativeRecords(context.Background(), ports.NativeFilter{AllGenerations: true})
	if err != nil || len(rows) != 2 {
		t.Fatalf("listing every generation = %d rows, %v; want both", len(rows), err)
	}
	for _, r := range rows {
		if r.SupersededByIdentity != (r.ArtefactIdentity == "zip:h1:directory=") || r.Conflict != nil {
			t.Errorf("row %s superseded=%v conflict=%v", r.ArtefactIdentity, r.SupersededByIdentity, r.Conflict)
		}
	}
}
