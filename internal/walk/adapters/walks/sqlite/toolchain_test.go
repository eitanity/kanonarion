package sqlite_test

import (
	"context"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/blobcodec"
	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
	"github.com/eitanity/kanonarion/internal/coordinate"
	walksqlite "github.com/eitanity/kanonarion/internal/walk/adapters/walks/sqlite"
	"github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// walkMigrationsBefore returns the walk migrations up to but excluding version,
// so a migration test opens at the schema that migration is about to change.
//
// It selects by version rather than by position because "all but the last" turns
// into a test of the newest migration the moment one is added, and does so
// silently.
func walkMigrationsBefore(t testing.TB, version int) []sqlitestore.Migration {
	t.Helper()
	var out []sqlitestore.Migration
	for _, m := range walksqlite.Migrations() {
		if m.Version < version {
			out = append(out, m)
		}
	}
	if len(out) != version-1 {
		t.Fatalf("walk module has %d migrations before version %d, want %d", len(out), version, version-1)
	}
	return out
}

// walkRecordUnderToolchain builds a walk of one target resolved by a named
// toolchain, which is what distinguishes two walks that agree on everything a
// read could previously see.
func walkRecordUnderToolchain(t testing.TB, id, goVersion string, startedAt time.Time) domain.WalkRecord {
	t.Helper()
	target := mustCoord("github.com/example/target", "v1.0.0")
	outcome := domain.WalkOutcome{
		Target: target,
		Graph: domain.Graph{
			Target:          target,
			ResolvedAt:      startedAt,
			PipelineVersion: "0.3.0",
			BuildEnv:        domain.BuildEnv{GOOS: "linux", GOARCH: "amd64", GoVersion: goVersion},
		},
		PerNodeResults: map[coordinate.ModuleCoordinate]domain.NodeResult{},
		StartedAt:      startedAt,
		CompletedAt:    startedAt.Add(time.Second),
		OverallStatus:  domain.WalkSucceeded,
	}
	rec := domain.NewWalkRecord(id, "test-operator", "0.3.0", domain.WalkScopeCode, domain.WalkDepthFull, outcome, domain.DefaultDepthPolicy(), "")
	var h domain.WalkRecordHasher
	rec, err := h.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	return rec
}

// TestListWalks_FiltersByToolchain is the lookup the stdlib answer depends on.
// Two walks of one target, one platform and one scope can still differ in the
// toolchain that resolved them, and the toolchain pins the standard library the
// walk records. Recency answering for both is how one project was reported both
// affected and clean.
func TestListWalks_FiltersByToolchain(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	base := time.Date(2026, 8, 14, 1, 0, 0, 0, time.UTC)
	wanted := walkRecordUnderToolchain(t, "01TOOLCHAIN00000000OLD001", "go1.26.5", base)
	newerOther := walkRecordUnderToolchain(t, "01TOOLCHAIN00000000NEW001", "go1.26.6", base.Add(time.Hour))
	for _, rec := range []domain.WalkRecord{wanted, newerOther} {
		if err := s.PutWalk(ctx, rec); err != nil {
			t.Fatalf("PutWalk %s: %v", rec.ID, err)
		}
	}

	asked := "go1.26.5"
	got, err := s.ListWalks(ctx, walkports.WalkFilter{Toolchain: &asked, Limit: 1})
	if err != nil {
		t.Fatalf("ListWalks: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("ListWalks returned %d walks, want 1", len(got))
	}
	if got[0].ID != wanted.ID {
		t.Errorf("ListWalks returned %s, want %s — the newer walk of another toolchain answered", got[0].ID, wanted.ID)
	}
	if got[0].GoVersion != "go1.26.5" || got[0].Toolchain() != "go1.26.5" {
		t.Errorf("summary toolchain = %q/%q, want go1.26.5", got[0].GoVersion, got[0].Toolchain())
	}
}

// TestListWalks_ExplicitToolchainNeverMatchesAnUnrecordedOne is the safety rule
// the platform axis already holds to: a walk that recorded no toolchain is not a
// walk for every toolchain, and the empty string is how a caller asks for those
// rows deliberately.
func TestListWalks_ExplicitToolchainNeverMatchesAnUnrecordedOne(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	// buildWalkRecord carries no BuildEnv, which is the pre-BuildEnv shape.
	frameless := buildWalkRecord("01TOOLCHAIN0000NOTOOLCH01")
	if err := s.PutWalk(ctx, frameless); err != nil {
		t.Fatalf("PutWalk: %v", err)
	}

	asked := "go1.26.5"
	got, err := s.ListWalks(ctx, walkports.WalkFilter{Toolchain: &asked})
	if err != nil {
		t.Fatalf("ListWalks: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("a toolchain-unrecorded walk answered a go1.26.5 filter: %+v", got)
	}

	unrecorded := ""
	got, err = s.ListWalks(ctx, walkports.WalkFilter{Toolchain: &unrecorded})
	if err != nil {
		t.Fatalf("ListWalks: %v", err)
	}
	if len(got) != 1 || got[0].ID != frameless.ID {
		t.Fatalf("an explicitly empty toolchain filter returned %+v, want the toolchain-unrecorded walk", got)
	}
	if got[0].Toolchain() != "unrecorded" {
		t.Errorf("toolchain-unrecorded summary rendered as %q, want unrecorded", got[0].Toolchain())
	}
}

// TestListWalks_LatestOnlyKeepsOneWalkPerToolchain: two walks under two
// toolchains are two builds, not two attempts at one. Collapsing them by clock
// makes the newer toolchain's standard library stand for the older one's, which
// is a wrong answer rather than an unfiltered one.
func TestListWalks_LatestOnlyKeepsOneWalkPerToolchain(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	base := time.Date(2026, 8, 14, 1, 0, 0, 0, time.UTC)
	older := walkRecordUnderToolchain(t, "01TOOLCHAIN0000LATEST0OLD", "go1.26.5", base)
	newer := walkRecordUnderToolchain(t, "01TOOLCHAIN0000LATEST0NEW", "go1.26.6", base.Add(time.Hour))
	// A second walk under the older toolchain: the partition must still keep one
	// per toolchain, not one per walk.
	olderAgain := walkRecordUnderToolchain(t, "01TOOLCHAIN0000LATEST0OL2", "go1.26.5", base.Add(2*time.Hour))
	for _, rec := range []domain.WalkRecord{older, newer, olderAgain} {
		if err := s.PutWalk(ctx, rec); err != nil {
			t.Fatalf("PutWalk %s: %v", rec.ID, err)
		}
	}

	got, err := s.ListWalks(ctx, walkports.WalkFilter{LatestOnly: true})
	if err != nil {
		t.Fatalf("ListWalks: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("latest-for-target returned %d candidates, want one per toolchain (2): %+v", len(got), got)
	}
	seen := map[string]string{}
	for _, s := range got {
		seen[s.GoVersion] = s.ID
	}
	if seen["go1.26.5"] != olderAgain.ID {
		t.Errorf("the go1.26.5 candidate is %s, want the later of the two go1.26.5 walks %s", seen["go1.26.5"], olderAgain.ID)
	}
	if seen["go1.26.6"] != newer.ID {
		t.Errorf("the go1.26.6 candidate is %s, want %s", seen["go1.26.6"], newer.ID)
	}
}

// walkRecordOnPlatform builds a walk of one target resolved FOR one platform
// under one toolchain, which is what a cross-compiled store holds two of.
func walkRecordOnPlatform(t testing.TB, id, goos, goarch, goVersion string, startedAt time.Time) domain.WalkRecord {
	t.Helper()
	rec := walkRecordUnderToolchain(t, id, goVersion, startedAt)
	rec.Graph.BuildEnv.GOOS, rec.Graph.BuildEnv.GOARCH = goos, goarch
	var h domain.WalkRecordHasher
	rec, err := h.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	return rec
}

// TestListWalks_LatestOnlyKeepsOneWalkPerPlatform: a walk resolved for another
// GOOS selected other files, so it is another build for the same reason another
// toolchain is. The filter has always matched on the platform and the partition
// did not, so one SQL statement disagreed with itself and a cross-compiled store
// collapsed its platforms by clock.
func TestListWalks_LatestOnlyKeepsOneWalkPerPlatform(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	base := time.Date(2026, 8, 14, 1, 0, 0, 0, time.UTC)
	linux := walkRecordOnPlatform(t, "01PLATFORM00000LATEST0LIN", "linux", "amd64", "go1.26.6", base)
	darwin := walkRecordOnPlatform(t, "01PLATFORM00000LATEST0DAR", "darwin", "arm64", "go1.26.6", base.Add(time.Hour))
	// A second linux walk, later than the darwin one: the partition must keep one
	// per platform, not one per walk.
	linuxAgain := walkRecordOnPlatform(t, "01PLATFORM00000LATEST0LI2", "linux", "amd64", "go1.26.6", base.Add(2*time.Hour))
	for _, rec := range []domain.WalkRecord{linux, darwin, linuxAgain} {
		if err := s.PutWalk(ctx, rec); err != nil {
			t.Fatalf("PutWalk %s: %v", rec.ID, err)
		}
	}

	got, err := s.ListWalks(ctx, walkports.WalkFilter{LatestOnly: true})
	if err != nil {
		t.Fatalf("ListWalks: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("latest-for-target returned %d candidates, want one per platform (2): %+v", len(got), got)
	}
	seen := map[string]string{}
	for _, sum := range got {
		seen[sum.GOOS+"/"+sum.GOARCH] = sum.ID
	}
	if seen["darwin/arm64"] != darwin.ID {
		t.Errorf("the darwin/arm64 candidate is %q, want %s — the later linux walk stood for it", seen["darwin/arm64"], darwin.ID)
	}
	if seen["linux/amd64"] != linuxAgain.ID {
		t.Errorf("the linux/amd64 candidate is %q, want the later of the two %s", seen["linux/amd64"], linuxAgain.ID)
	}
}

// TestMigration9_BackfillsTheToolchainFromTheSealedRecord proves the column is a
// projection of data already in the store rather than a field only new walks
// get. Leaving it empty would make every stored walk permanently invisible to a
// toolchain-filtered read, which is the read the column exists for.
//
// It also pins that the projection did not touch the seal: the back-fill reads
// the blob and writes a column, and both hashes must come back unchanged.
func TestMigration9_BackfillsTheToolchainFromTheSealedRecord(t *testing.T) {
	ctx := context.Background()

	all := walksqlite.Migrations()
	pre := walkMigrationsBefore(t, 9)

	dsn := "file:" + t.Name() + "?mode=memory&cache=shared"
	handle, err := sqlitestore.Open(dsn, pre, sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("opening at the pre-migration schema: %v", err)
	}
	defer func() {
		if cerr := handle.Close(); cerr != nil {
			t.Errorf("closing: %v", cerr)
		}
	}()

	rec := walkRecordUnderToolchain(t, "01TOOLCHAIN000BACKFILL001", "go1.26.5",
		time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC))
	var h domain.WalkRecordHasher
	identity, err := h.IdentityHash(rec)
	if err != nil {
		t.Fatalf("IdentityHash: %v", err)
	}
	raw, err := h.Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	// Written the way the previous build did: every column it had, and no
	// go_version.
	if _, err := handle.DB().ExecContext(ctx, `
INSERT INTO walks (id, target_path, target_version, started_at, completed_at,
    overall_status, pipeline_version, operator, content_hash,
    node_count, failure_count, scope, depth, project_dir, identity_hash,
    goos, goarch, serialised)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 'code', '', '', ?, 'linux', 'amd64', ?)`,
		rec.ID, rec.Target.Path(), rec.Target.Version(),
		rec.StartedAt.UTC().Format(time.RFC3339), rec.CompletedAt.UTC().Format(time.RFC3339),
		int(rec.OverallStatus), rec.PipelineVersion, rec.Operator, rec.ContentHash,
		identity, blobcodec.Encode(raw),
	); err != nil {
		t.Fatalf("inserting a pre-migration row: %v", err)
	}

	if err := sqlitestore.Apply(handle, all); err != nil {
		t.Fatalf("applying migration 9: %v", err)
	}

	var goVersion, storedHash, storedIdentity string
	if err := handle.DB().QueryRowContext(ctx,
		`SELECT go_version, content_hash, identity_hash FROM walks WHERE id = ?`, rec.ID).
		Scan(&goVersion, &storedHash, &storedIdentity); err != nil {
		t.Fatalf("reading the back-filled toolchain: %v", err)
	}
	if goVersion != "go1.26.5" {
		t.Errorf("back-filled toolchain = %q, want go1.26.5", goVersion)
	}
	if storedHash != rec.ContentHash {
		t.Errorf("content_hash after migration = %q, want %q", storedHash, rec.ContentHash)
	}
	if storedIdentity != identity {
		t.Errorf("identity_hash after migration = %q, want %q", storedIdentity, identity)
	}

	// The record still reads back and still verifies against its own seal.
	store := walksqlite.New(handle)
	back, err := store.GetWalk(ctx, rec.ID)
	if err != nil {
		t.Fatalf("GetWalk after migration: %v", err)
	}
	if back.ContentHash != rec.ContentHash {
		t.Errorf("ContentHash after migration = %q, want %q", back.ContentHash, rec.ContentHash)
	}

	// And the back-filled row is reachable by a toolchain-filtered lookup, which
	// is the whole point of back-filling rather than defaulting to empty.
	asked := "go1.26.5"
	got, err := store.ListWalks(ctx, walkports.WalkFilter{Toolchain: &asked})
	if err != nil {
		t.Fatalf("ListWalks: %v", err)
	}
	if len(got) != 1 || got[0].ID != rec.ID {
		t.Fatalf("the back-filled walk is invisible to a go1.26.5 lookup: %+v", got)
	}
}

// TestMigration9_DoesNotDeleteWalks: walk migrations 4 and 5 purge the table,
// and this one must not. The value it projects is already in the blob, so
// back-filling it is the entire point — a purge here would destroy the evidence
// the column exists to make selectable.
func TestMigration9_DoesNotDeleteWalks(t *testing.T) {
	ctx := context.Background()

	all := walksqlite.Migrations()
	pre := walkMigrationsBefore(t, 9)

	dsn := "file:" + t.Name() + "?mode=memory&cache=shared"
	handle, err := sqlitestore.Open(dsn, pre, sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("opening at the pre-migration schema: %v", err)
	}
	defer func() {
		if cerr := handle.Close(); cerr != nil {
			t.Errorf("closing: %v", cerr)
		}
	}()

	// Written through SQL rather than PutWalk: the store is open at the schema
	// this migration is about to change, and PutWalk writes the column it adds.
	rec := walkRecordUnderToolchain(t, "01TOOLCHAIN0000SURVIVE001", "go1.26.5",
		time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC))
	var h domain.WalkRecordHasher
	raw, err := h.Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if _, err := handle.DB().ExecContext(ctx, `
INSERT INTO walks (id, target_path, target_version, started_at, completed_at,
    overall_status, pipeline_version, operator, content_hash,
    node_count, failure_count, scope, depth, project_dir, identity_hash,
    goos, goarch, serialised)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 'code', '', '', '', 'linux', 'amd64', ?)`,
		rec.ID, rec.Target.Path(), rec.Target.Version(),
		rec.StartedAt.UTC().Format(time.RFC3339), rec.CompletedAt.UTC().Format(time.RFC3339),
		int(rec.OverallStatus), rec.PipelineVersion, rec.Operator, rec.ContentHash,
		blobcodec.Encode(raw),
	); err != nil {
		t.Fatalf("inserting a pre-migration row: %v", err)
	}

	if err := sqlitestore.Apply(handle, all); err != nil {
		t.Fatalf("applying migration 9: %v", err)
	}

	var count int
	if err := handle.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM walks`).Scan(&count); err != nil {
		t.Fatalf("counting walks: %v", err)
	}
	if count != 1 {
		t.Fatalf("migration 9 left %d walks, want the 1 it started with", count)
	}
}

// TestMigration9_UndecodableRowKeepsAnUnrecordedToolchain: one historical row
// this build cannot decode must not stop the store from opening. Its toolchain
// is genuinely unknown, and unrecorded is the honest answer.
func TestMigration9_UndecodableRowKeepsAnUnrecordedToolchain(t *testing.T) {
	ctx := context.Background()

	all := walksqlite.Migrations()
	pre := walkMigrationsBefore(t, 9)
	dsn := "file:" + t.Name() + "?mode=memory&cache=shared"
	handle, err := sqlitestore.Open(dsn, pre, sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("opening at the pre-migration schema: %v", err)
	}
	defer func() {
		if cerr := handle.Close(); cerr != nil {
			t.Errorf("closing: %v", cerr)
		}
	}()

	if _, err := handle.DB().ExecContext(ctx, `
INSERT INTO walks (id, target_path, target_version, started_at, completed_at,
    overall_status, pipeline_version, operator, content_hash,
    node_count, failure_count, scope, depth, project_dir, identity_hash,
    goos, goarch, serialised)
VALUES ('01TOOLCHAIN0000GARBAGE001', 'example.com/m', 'v1.0.0',
    '2026-07-01T00:00:00Z', '2026-07-01T00:00:01Z', 0, '0.3.0', 'op', 'deadbeef',
    0, 0, 'code', '', '', '', '', '', ?)`, []byte("not a walk record")); err != nil {
		t.Fatalf("inserting an undecodable row: %v", err)
	}

	if err := sqlitestore.Apply(handle, all); err != nil {
		t.Fatalf("migration 9 refused to apply over an undecodable row: %v", err)
	}

	var goVersion string
	if err := handle.DB().QueryRowContext(ctx,
		`SELECT go_version FROM walks WHERE id = '01TOOLCHAIN0000GARBAGE001'`).Scan(&goVersion); err != nil {
		t.Fatalf("reading the toolchain: %v", err)
	}
	if goVersion != "" {
		t.Errorf("undecodable row got toolchain %q, want the unrecorded one", goVersion)
	}
}
