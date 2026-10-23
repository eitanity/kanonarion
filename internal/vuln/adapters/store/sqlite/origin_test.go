package sqlite_test

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
	"github.com/eitanity/kanonarion/internal/vuln/adapters/store/sqlite"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
)

// A snapshot downloaded from a mirror reads back with its origin from both
// metadata reads; one downloaded from vuln.go.dev reads back with none.
func TestDatabaseSnapshot_OriginRoundTrips(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)
	const mirror = "https://mirror.example.com/go"

	plain := snap("vuln.go.dev", "2026-10-20T00:00:00Z")
	mirrored, err := snap("vuln.go.dev", "2026-10-21T00:27:29Z").WithOrigin(mirror)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []domain.DatabaseSnapshot{plain, mirrored} {
		if perr := store.PutDatabaseSnapshot(ctx, s, bytes.NewReader([]byte(s.Version()))); perr != nil {
			t.Fatalf("PutDatabaseSnapshot %s: %v", s.Version(), perr)
		}
	}

	list, err := store.ListDatabaseSnapshots(ctx)
	if err != nil {
		t.Fatal(err)
	}
	origins := map[string]string{}
	for _, s := range list {
		origins[s.Version()] = s.Origin()
	}
	if origins[plain.Version()] != "" || origins[mirrored.Version()] != mirror {
		t.Errorf("listed origins = %v", origins)
	}
	latest, ok, err := store.GetLatestDatabaseSnapshot(ctx)
	if err != nil || !ok {
		t.Fatalf("GetLatestDatabaseSnapshot: %v, %v", ok, err)
	}
	if latest.Origin() != origins[latest.Version()] {
		t.Errorf("latest %s carries origin %q, the list %q", latest.Version(), latest.Origin(), origins[latest.Version()])
	}
}

// The column reaches a store that already holds snapshots, and every existing
// row reads back as downloaded from vuln.go.dev, which is where it came from.
func TestMigration_AddsTheSnapshotOrigin(t *testing.T) {
	ctx := t.Context()
	var pre []sqlitestore.Migration
	for _, m := range sqlite.Migrations() {
		if m.Version < 17 {
			pre = append(pre, m)
		}
	}
	path := t.TempDir() + "/origin.db"
	db, err := sqlitestore.Open(path, pre, sqlitestore.IntentCreate)
	if err != nil {
		t.Fatal(err)
	}
	if _, eerr := db.DB().ExecContext(ctx, `
INSERT INTO vulnerability_snapshots (source, version, retrieved_at, content_hash, content)
VALUES ('vuln.go.dev', '2026-10-21T00:27:29Z', '2026-10-23T04:32:44Z', '', 'body')`); eerr != nil {
		t.Fatal(eerr)
	}
	if cerr := db.Close(); cerr != nil {
		t.Fatal(cerr)
	}

	migrated, err := sqlitestore.Open(path, sqlite.Migrations(), sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("applying the migration: %v", err)
	}
	t.Cleanup(func() { _ = migrated.Close() })
	store := sqlite.New(migrated)
	list, err := store.ListDatabaseSnapshots(ctx)
	if err != nil || len(list) != 1 || list[0].Origin() != "" {
		t.Fatalf("ListDatabaseSnapshots = %v, %v; want the one row with no origin", list, err)
	}
	rc, err := store.GetDatabaseSnapshot(ctx, list[0])
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "body" {
		t.Errorf("the migrated row's bytes = %q", body)
	}
	var keyed int
	if err := migrated.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM pragma_table_info('vulnerability_snapshots') WHERE pk > 0`).Scan(&keyed); err != nil || keyed != 3 {
		t.Errorf("primary key columns = %d, %v; want source, version and content_hash", keyed, err)
	}
}

// putSnap stores body as source@version retrieved at, sealed by the store.
func putSnap(t *testing.T, store *sqlite.Store, version string, at time.Time, body string, origin string) domain.DatabaseSnapshot {
	t.Helper()
	s := vulntest.MustSeal("vuln.go.dev", version, at, domain.HashSnapshotContent([]byte(body)))
	if origin != "" {
		var err error
		if s, err = s.WithOrigin(origin); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.PutDatabaseSnapshot(t.Context(), s, strings.NewReader(body)); err != nil {
		t.Fatalf("PutDatabaseSnapshot %q: %v", body, err)
	}
	return s
}

func readSnap(t *testing.T, store *sqlite.Store, s domain.DatabaseSnapshot) (string, error) {
	t.Helper()
	rc, err := store.GetDatabaseSnapshot(t.Context(), s)
	if err != nil {
		return "", err
	}
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(rc)
	return string(b), err
}

// A version re-published with different bytes is stored beside the first: a
// read naming the first's hash still gets, and verifies, the bytes a run was
// judged against, while a read by version alone and "latest" get the newer.
// The same bytes arriving again change nothing.
func TestDatabaseSnapshot_ARepublishedVersionIsStoredBeside(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)
	const v = "2026-10-21T00:27:29Z"
	t0 := time.Date(2026, 10, 23, 4, 32, 44, 0, time.UTC)
	first := putSnap(t, store, v, t0, "first bytes", "")
	second := putSnap(t, store, v, t0.Add(time.Hour), "second bytes", "")
	putSnap(t, store, v, t0.Add(2*time.Hour), "first bytes", "https://mirror.example.com")

	if got, err := readSnap(t, store, first); err != nil || got != "first bytes" {
		t.Errorf("the first run's snapshot = %q, %v; want its own bytes", got, err)
	}
	if got, err := readSnap(t, store, second); err != nil || got != "second bytes" {
		t.Errorf("the second snapshot = %q, %v", got, err)
	}
	byVersion := vulntest.MustNew("vuln.go.dev", v)
	if got, err := readSnap(t, store, byVersion); err != nil || got != "second bytes" {
		t.Errorf("a read by version = %q, %v; want the latest", got, err)
	}
	latest, _, err := store.GetLatestDatabaseSnapshot(ctx)
	if err != nil || latest.ContentHash() != second.ContentHash() {
		t.Errorf("latest = %s, %v; want the second", latest, err)
	}
	list, err := store.ListDatabaseSnapshots(ctx)
	if err != nil || len(list) != 2 {
		t.Fatalf("ListDatabaseSnapshots = %v, %v; want two rows", list, err)
	}
	for _, s := range list {
		if s.ContentHash() == first.ContentHash() && (!s.RetrievedAt().Equal(t0) || s.Origin() != "") {
			t.Errorf("the same bytes again changed the held row: %s origin %q", s, s.Origin())
		}
	}
}

// Held bytes that no longer match their hash are restored by the bytes the
// hash names, and only those.
func TestDatabaseSnapshot_TheSameBytesRestoreAnAlteredRow(t *testing.T) {
	store := newTestStore(t)
	const v = "2026-10-21T00:27:29Z"
	s := putSnap(t, store, v, time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC), "good bytes", "")
	if _, err := store.InternalDB().DB().ExecContext(t.Context(),
		`UPDATE vulnerability_snapshots SET content = 'altered' WHERE version = ?`, v); err != nil {
		t.Fatal(err)
	}
	if _, err := readSnap(t, store, s); !errors.Is(err, ports.ErrSnapshotIntegrity) {
		t.Fatalf("altered row read: %v", err)
	}
	putSnap(t, store, v, time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC), "good bytes", "")
	if got, err := readSnap(t, store, s); err != nil || got != "good bytes" {
		t.Errorf("after the same bytes arrived: %q, %v", got, err)
	}
}
