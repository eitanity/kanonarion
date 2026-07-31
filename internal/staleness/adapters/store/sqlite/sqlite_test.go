package sqlite_test

import (
	"context"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/sqlitestore"
	stalesqlite "github.com/eitanity/kanonarion/internal/staleness/adapters/store/sqlite"
	"github.com/eitanity/kanonarion/internal/staleness/domain"
)

func newStore(t *testing.T) *stalesqlite.Store {
	t.Helper()
	db, err := sqlitestore.Open(":memory:", stalesqlite.Migrations())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if cerr := db.Close(); cerr != nil {
			t.Errorf("Close: %v", cerr)
		}
	})
	return stalesqlite.New(db)
}

func TestPutGet_RoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	want := domain.Record{
		ModulePath:        "github.com/minio/minio-go/v6",
		LatestVersion:     "v6.0.57",
		LatestPublishedAt: time.Date(2020, 12, 21, 10, 0, 0, 0, time.UTC),
		NewerMajor: domain.NewerMajor{
			Probed:      true,
			FromMajor:   7,
			Path:        "github.com/minio/minio-go/v7",
			Version:     "v7.2.1",
			PublishedAt: time.Date(2026, 1, 19, 8, 0, 0, 0, time.UTC),
		},
		LookedUpAt: time.Date(2026, 7, 31, 9, 14, 0, 0, time.UTC),
	}
	if err := s.PutStaleness(ctx, want); err != nil {
		t.Fatalf("PutStaleness: %v", err)
	}

	got, found, err := s.GetStaleness(ctx, want.ModulePath)
	if err != nil {
		t.Fatalf("GetStaleness: %v", err)
	}
	if !found {
		t.Fatal("expected the row to be found")
	}
	if got.LatestVersion != want.LatestVersion || !got.LatestPublishedAt.Equal(want.LatestPublishedAt) {
		t.Errorf("latest = %s/%v, want %s/%v", got.LatestVersion, got.LatestPublishedAt, want.LatestVersion, want.LatestPublishedAt)
	}
	if got.NewerMajor != want.NewerMajor {
		t.Errorf("NewerMajor = %+v, want %+v", got.NewerMajor, want.NewerMajor)
	}
	if !got.LookedUpAt.Equal(want.LookedUpAt) {
		t.Errorf("LookedUpAt = %v, want %v", got.LookedUpAt, want.LookedUpAt)
	}
}

func TestGet_MissIsNotAnError(t *testing.T) {
	_, found, err := newStore(t).GetStaleness(context.Background(), "example.com/never/stored")
	if err != nil {
		t.Fatalf("GetStaleness: %v", err)
	}
	if found {
		t.Error("expected no row")
	}
}

// "Probed, none found" and "not probed" must survive the round trip as
// different answers; collapsing them would let an unasked question read as a
// clean one.
func TestRoundTrip_DistinguishesUnprobedFromNegative(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	now := time.Date(2026, 7, 31, 9, 0, 0, 0, time.UTC)

	negative := domain.Record{
		ModulePath:    "example.com/negative",
		LatestVersion: "v1.0.0",
		NewerMajor:    domain.NewerMajor{Probed: true, FromMajor: 2},
		LookedUpAt:    now,
	}
	unprobed := domain.Record{
		ModulePath:    "example.com/unprobed",
		LatestVersion: "v1.0.0",
		LookedUpAt:    now,
	}
	for _, rec := range []domain.Record{negative, unprobed} {
		if err := s.PutStaleness(ctx, rec); err != nil {
			t.Fatalf("PutStaleness(%s): %v", rec.ModulePath, err)
		}
	}

	got, _, err := s.GetStaleness(ctx, "example.com/negative")
	if err != nil {
		t.Fatalf("GetStaleness: %v", err)
	}
	if !got.NewerMajor.Probed || got.NewerMajor.FromMajor != 2 || got.NewerMajor.Path != "" {
		t.Errorf("negative round-tripped as %+v", got.NewerMajor)
	}

	got, _, err = s.GetStaleness(ctx, "example.com/unprobed")
	if err != nil {
		t.Fatalf("GetStaleness: %v", err)
	}
	if got.NewerMajor.Probed {
		t.Errorf("unprobed round-tripped as probed: %+v", got.NewerMajor)
	}
}

// A module whose publication date the proxy did not supply must not acquire a
// fabricated 0001-01-01 on the way through the store.
func TestRoundTrip_AbsentPublicationDateStaysAbsent(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	if err := s.PutStaleness(ctx, domain.Record{
		ModulePath:    "example.com/nodate",
		LatestVersion: "v1.0.0",
		NewerMajor:    domain.NewerMajor{Probed: true, FromMajor: 2},
		LookedUpAt:    time.Date(2026, 7, 31, 9, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("PutStaleness: %v", err)
	}
	got, _, err := s.GetStaleness(ctx, "example.com/nodate")
	if err != nil {
		t.Fatalf("GetStaleness: %v", err)
	}
	if !got.LatestPublishedAt.IsZero() {
		t.Errorf("LatestPublishedAt = %v, want the zero time", got.LatestPublishedAt)
	}
}

func TestPut_OverwritesInPlace(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	base := domain.Record{
		ModulePath:    "example.com/mod",
		LatestVersion: "v1.0.0",
		NewerMajor:    domain.NewerMajor{Probed: true, FromMajor: 2},
		LookedUpAt:    time.Date(2026, 7, 31, 9, 0, 0, 0, time.UTC),
	}
	if err := s.PutStaleness(ctx, base); err != nil {
		t.Fatalf("PutStaleness: %v", err)
	}
	base.LatestVersion = "v1.1.0"
	base.LookedUpAt = base.LookedUpAt.Add(time.Hour)
	if err := s.PutStaleness(ctx, base); err != nil {
		t.Fatalf("PutStaleness (overwrite): %v", err)
	}
	got, found, err := s.GetStaleness(ctx, "example.com/mod")
	if err != nil || !found {
		t.Fatalf("GetStaleness: %v found=%v", err, found)
	}
	if got.LatestVersion != "v1.1.0" {
		t.Errorf("LatestVersion = %q, want the overwritten v1.1.0", got.LatestVersion)
	}
}

func TestPut_RefusesAnIncompleteRow(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	now := time.Date(2026, 7, 31, 9, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		rec  domain.Record
	}{
		{"no module path", domain.Record{LatestVersion: "v1.0.0", LookedUpAt: now}},
		{"no latest version", domain.Record{ModulePath: "example.com/mod", LookedUpAt: now}},
		{"no lookup time", domain.Record{ModulePath: "example.com/mod", LatestVersion: "v1.0.0"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := s.PutStaleness(ctx, tc.rec); err == nil {
				t.Error("expected the incomplete row to be refused")
			}
		})
	}
}
