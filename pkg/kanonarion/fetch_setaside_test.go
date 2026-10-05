package kanonarion_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	fetchsqlite "github.com/eitanity/kanonarion/internal/adapters/factstore/sqlite"
	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"

	"github.com/eitanity/kanonarion/pkg/kanonarion"
)

// The fetch store a library caller reads through names a measurement it set
// aside to that caller's reporter.
func TestOpen_FetchSetAsideReachesTheLibraryCaller(t *testing.T) {
	root := t.TempDir()
	_, cleanup, err := kanonarion.Open(root)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
	coord, _ := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
	r := fetchtest.Record(t, fetchtest.Coordinate(coord), fetchtest.PipelineVersion("0.4.0"),
		fetchtest.FetchedAt(time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)))
	db, err := sqlitestore.Open(filepath.Join(root, "mirror.db"), nil, sqlitestore.IntentCreate)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := fetchdomain.Rehydrate(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := fetchsqlite.New(db).PutFetchRecord(context.Background(), sealed); err != nil {
		t.Fatal(err)
	}
	fetchedAt, seal := fetchtest.Respelt(t, r)
	if _, err := db.DB().Exec(`UPDATE fetch_records SET fetched_at = ?, content_hash = ?`, fetchedAt, seal); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	var got []kanonarion.SetAsideRow
	queries, cleanup, err := kanonarion.Open(root, kanonarion.WithSetAsideReporter(func(rows []kanonarion.SetAsideRow) {
		got = append(got, rows...)
	}))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = cleanup() })

	_, _, err = queries.Fetch.ComposeFetchRecord(context.Background(), coord)
	if !errors.As(err, new(*kanonarion.NothingServable)) {
		t.Fatalf("ComposeFetchRecord = %v, want *kanonarion.NothingServable", err)
	}
	if len(got) != 1 || got[0].ContentHash != seal || got[0].ID != coord.String() {
		t.Errorf("reporter received %+v, want the record named by %s", got, seal)
	}
}
