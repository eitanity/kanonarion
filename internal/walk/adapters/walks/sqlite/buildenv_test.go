package sqlite_test

import (
	"context"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/blobcodec"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/sqlitestore"
	walksqlite "github.com/eitanity/kanonarion/internal/walk/adapters/walks/sqlite"
	"github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// buildWalkRecordForPlatform is buildWalkRecord with a build environment, which
// is what distinguishes two walks of ONE target taken for two platforms.
func buildWalkRecordForPlatform(t testing.TB, id, goos, goarch string, startedAt time.Time) domain.WalkRecord {
	t.Helper()
	target := mustCoord("github.com/example/target", "v1.0.0")
	outcome := domain.WalkOutcome{
		Target: target,
		Graph: domain.Graph{
			Target:          target,
			ResolvedAt:      startedAt,
			PipelineVersion: "0.3.0",
			BuildEnv:        domain.BuildEnv{GOOS: goos, GOARCH: goarch, GoVersion: "go1.26.4"},
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

// TestListWalks_FiltersByBuildEnv is the lookup every platform-sensitive command
// depends on: of two walks of one target that differ only in the platform they
// resolved for, return the one this environment asked about — even when the
// other is newer.
func TestListWalks_FiltersByBuildEnv(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	base := time.Date(2026, 8, 2, 5, 0, 0, 0, time.UTC)
	wanted := buildWalkRecordForPlatform(t, "01BUILDENV0000000DARWIN01", "darwin", "arm64", base)
	newerOther := buildWalkRecordForPlatform(t, "01BUILDENV00000000LINUX01", "linux", "amd64", base.Add(time.Hour))
	for _, rec := range []domain.WalkRecord{wanted, newerOther} {
		if err := s.PutWalk(ctx, rec); err != nil {
			t.Fatalf("PutWalk %s: %v", rec.ID, err)
		}
	}

	platform := walkports.BuildEnvFilter{GOOS: "darwin", GOARCH: "arm64"}
	got, err := s.ListWalks(ctx, walkports.WalkFilter{BuildEnv: &platform, Limit: 1})
	if err != nil {
		t.Fatalf("ListWalks: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("ListWalks returned %d walks, want 1", len(got))
	}
	if got[0].ID != wanted.ID {
		t.Errorf("ListWalks returned %s, want %s — the newer walk of another platform answered", got[0].ID, wanted.ID)
	}
	if got[0].BuildFrame() != "darwin/arm64" {
		t.Errorf("summary frame = %q, want darwin/arm64", got[0].BuildFrame())
	}
}

// TestListWalks_NilBuildEnvIsTheOnlyWayToSayAny pins the semantics the refusal
// depends on. Without the filter the newest walk answers whatever its platform;
// that is exactly the platform-blindness a filtered caller must not inherit.
func TestListWalks_NilBuildEnvIsTheOnlyWayToSayAny(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	base := time.Date(2026, 8, 2, 5, 0, 0, 0, time.UTC)
	darwin := buildWalkRecordForPlatform(t, "01BUILDENV0000000DARWIN02", "darwin", "arm64", base)
	linux := buildWalkRecordForPlatform(t, "01BUILDENV00000000LINUX02", "linux", "amd64", base.Add(time.Hour))
	for _, rec := range []domain.WalkRecord{darwin, linux} {
		if err := s.PutWalk(ctx, rec); err != nil {
			t.Fatalf("PutWalk %s: %v", rec.ID, err)
		}
	}

	got, err := s.ListWalks(ctx, walkports.WalkFilter{})
	if err != nil {
		t.Fatalf("ListWalks: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("a nil build-environment filter returned %d walks, want both", len(got))
	}
}

// TestListWalks_ExplicitPlatformNeverMatchesAnUnrecordedFrame is the safety
// rule. A walk that recorded no build environment is not a walk for every
// platform; a caller asking for linux/amd64 must not receive it.
func TestListWalks_ExplicitPlatformNeverMatchesAnUnrecordedFrame(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	// buildWalkRecord carries no BuildEnv, which is exactly the pre-BuildEnv shape.
	frameless := buildWalkRecord("01BUILDENV000000NOFRAME001")
	if err := s.PutWalk(ctx, frameless); err != nil {
		t.Fatalf("PutWalk: %v", err)
	}

	platform := walkports.BuildEnvFilter{GOOS: "linux", GOARCH: "amd64"}
	got, err := s.ListWalks(ctx, walkports.WalkFilter{BuildEnv: &platform})
	if err != nil {
		t.Fatalf("ListWalks: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("a frame-unrecorded walk answered a linux/amd64 filter: %+v", got)
	}

	// And the empty filter is how a caller deliberately asks for those rows.
	unrecorded := walkports.BuildEnvFilter{}
	got, err = s.ListWalks(ctx, walkports.WalkFilter{BuildEnv: &unrecorded})
	if err != nil {
		t.Fatalf("ListWalks: %v", err)
	}
	if len(got) != 1 || got[0].ID != frameless.ID {
		t.Fatalf("an explicitly empty filter returned %+v, want the frame-unrecorded walk", got)
	}
	// buildWalkRecord is rooted at a published coordinate, so no platform applies
	// to it — which is a different fact from a platform that was not recorded.
	if got[0].BuildFrame() != "not-platform-scoped" {
		t.Errorf("frameless module-rooted summary rendered as %q, want not-platform-scoped", got[0].BuildFrame())
	}
}

// TestMigration8_BackfillsTheFrameFromTheSealedRecord proves the columns are a
// projection of data already in the store, not a field only new walks get. A row
// written before the columns existed still has its platform in its blob, and
// leaving it empty would make every stored walk permanently invisible to the
// filtered reads the columns exist for.
func TestMigration8_BackfillsTheFrameFromTheSealedRecord(t *testing.T) {
	ctx := context.Background()

	// Open at the pre-BuildEnv schema: every walk migration BEFORE 8. It is
	// selected by version rather than by position so a later migration does not
	// silently turn this into a test of something else.
	all := walksqlite.Migrations()
	pre := walkMigrationsBefore(t, 8)

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

	// Write the row the way the previous build did: no goos/goarch columns.
	rec := buildWalkRecordForPlatform(t, "01BUILDENV0000BACKFILL001", "windows", "arm64",
		time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC))
	var h domain.WalkRecordHasher
	raw, err := h.Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if _, err := handle.DB().ExecContext(ctx, `
INSERT INTO walks (id, target_path, target_version, started_at, completed_at,
    overall_status, pipeline_version, operator, content_hash,
    node_count, failure_count, scope, depth, project_dir, identity_hash, serialised)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 'code', '', '', '', ?)`,
		rec.ID, rec.Target.Path(), rec.Target.Version(),
		rec.StartedAt.UTC().Format(time.RFC3339), rec.CompletedAt.UTC().Format(time.RFC3339),
		int(rec.OverallStatus), rec.PipelineVersion, rec.Operator, rec.ContentHash,
		blobcodec.Encode(raw),
	); err != nil {
		t.Fatalf("inserting a pre-migration row: %v", err)
	}

	// Apply the migration under test.
	if err := sqlitestore.Apply(handle, all); err != nil {
		t.Fatalf("applying migration 8: %v", err)
	}

	var goos, goarch string
	if err := handle.DB().QueryRowContext(ctx,
		`SELECT goos, goarch FROM walks WHERE id = ?`, rec.ID).Scan(&goos, &goarch); err != nil {
		t.Fatalf("reading the back-filled frame: %v", err)
	}
	if goos != "windows" || goarch != "arm64" {
		t.Errorf("back-filled frame = %s/%s, want windows/arm64", goos, goarch)
	}

	// The projection must not have disturbed the seal.
	store := walksqlite.New(handle)
	back, err := store.GetWalk(ctx, rec.ID)
	if err != nil {
		t.Fatalf("GetWalk after migration: %v", err)
	}
	if back.ContentHash != rec.ContentHash {
		t.Errorf("ContentHash after migration = %q, want %q", back.ContentHash, rec.ContentHash)
	}

	// And the back-filled row is now reachable by a platform-filtered lookup,
	// which is the whole point of back-filling rather than defaulting to empty.
	platform := walkports.BuildEnvFilter{GOOS: "windows", GOARCH: "arm64"}
	got, err := store.ListWalks(ctx, walkports.WalkFilter{BuildEnv: &platform})
	if err != nil {
		t.Fatalf("ListWalks: %v", err)
	}
	if len(got) != 1 || got[0].ID != rec.ID {
		t.Fatalf("the back-filled walk is invisible to a windows/arm64 lookup: %+v", got)
	}
}

// TestMigration8_UndecodableRowKeepsAnUnrecordedFrame: one historical row this
// build cannot decode must not stop the store from opening. Its frame is
// genuinely unknown, and "unrecorded" is the honest answer.
func TestMigration8_UndecodableRowKeepsAnUnrecordedFrame(t *testing.T) {
	ctx := context.Background()

	all := walksqlite.Migrations()
	pre := walkMigrationsBefore(t, 8)
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
    node_count, failure_count, scope, depth, project_dir, identity_hash, serialised)
VALUES ('01BUILDENV00000GARBAGE001', 'example.com/m', 'v1.0.0',
    '2026-07-01T00:00:00Z', '2026-07-01T00:00:01Z', 0, '0.3.0', 'op', 'deadbeef',
    0, 0, 'code', '', '', '', ?)`, []byte("not a walk record")); err != nil {
		t.Fatalf("inserting an undecodable row: %v", err)
	}

	if err := sqlitestore.Apply(handle, all); err != nil {
		t.Fatalf("migration 8 refused to apply over an undecodable row: %v", err)
	}

	var goos, goarch string
	if err := handle.DB().QueryRowContext(ctx,
		`SELECT goos, goarch FROM walks WHERE id = '01BUILDENV00000GARBAGE001'`).Scan(&goos, &goarch); err != nil {
		t.Fatalf("reading the frame: %v", err)
	}
	if goos != "" || goarch != "" {
		t.Errorf("undecodable row got frame %s/%s, want the unrecorded frame", goos, goarch)
	}
}
