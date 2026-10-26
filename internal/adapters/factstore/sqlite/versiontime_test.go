package sqlite_test

import (
	"context"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"code.eitanity.com/kanonarion/internal/adapters/factstore/sqlite"
	"code.eitanity.com/kanonarion/internal/adapters/sqlitestore"
	"code.eitanity.com/kanonarion/internal/coordinate/coordinatetest"
	domain2 "code.eitanity.com/kanonarion/internal/fetch/domain"
	"code.eitanity.com/kanonarion/internal/fetch/fetchtest"
)

// The version time survives the store at full precision, and a record without
// one reads back unknown and verifying, as every record before the column did.
func TestVersionTimeRoundTripsThroughTheStore(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	for path, want := range map[string]string{
		"golang.org/x/text":      "2026-09-08T16:29:55Z",
		"example.com/nanosecond": "2026-09-08T16:29:55.000000001Z",
		"example.com/unknown":    "",
	} {
		var opts []fetchtest.Option
		if want != "" {
			at, err := time.Parse(time.RFC3339Nano, want)
			if err != nil {
				t.Fatal(err)
			}
			opts = append(opts, fetchtest.VersionTime(at))
		}
		r := sampleRecord(t, path, "v0.42.0", "0.6.0", opts...)
		if err := s.PutFetchRecord(ctx, mustSeal(t, r)); err != nil {
			t.Fatalf("Put(%s): %v", path, err)
		}
		got, ok, err := s.GetFetchRecord(ctx, coordinatetest.MustNew(path, "v0.42.0"), "0.6.0")
		if err != nil || !ok {
			t.Fatalf("Get(%s): ok=%v err=%v", path, ok, err)
		}
		if string(got.VersionTime) != want {
			t.Errorf("%s: VersionTime = %q, want %q", path, got.VersionTime, want)
		}
	}
}

// fetch@v12 adds the column to a store at the previous schema: a record already
// there reads back unknown and verifying, a new one carries its time, and a
// build that predates the column meets the gate's refusal before it reads either.
func TestVersionTimeMigrationOnAPreviousSchemaStore(t *testing.T) {
	ctx := context.Background()
	all := sqlite.Migrations()
	last := all[len(all)-1]
	if last.Module != "fetch" || last.Version != 12 {
		t.Fatalf("last migration = %s@v%d, want fetch@v12", last.Module, last.Version)
	}
	previous := all[:len(all)-1]
	dsn := filepath.Join(t.TempDir(), "mirror.db")

	pre := mustSeal(t, sampleRecord(t, "golang.org/x/text", "v0.42.0", "0.6.0")).Record()
	seedPreviousSchemaRecord(t, dsn, previous, pre)

	s, err := sqlite.Open(dsn)
	if err != nil {
		t.Fatalf("migrating to fetch@v12: %v", err)
	}
	got, ok, err := s.GetFetchRecord(ctx, coordinatetest.MustNew(pre.ModulePath, pre.ModuleVersion), pre.PipelineVersion)
	if err != nil || !ok || got.VersionTime != "" || got.ContentHash != pre.ContentHash {
		t.Fatalf("pre-migration record after fetch@v12: ok=%v err=%v version_time=%q", ok, err, got.VersionTime)
	}
	at := time.Date(2026, 9, 8, 16, 29, 55, 0, time.UTC)
	timed := sampleRecord(t, "golang.org/x/net", "v0.45.0", "0.6.0", fetchtest.VersionTime(at))
	if err = s.PutFetchRecord(ctx, mustSeal(t, timed)); err != nil {
		t.Fatalf("Put after migration: %v", err)
	}
	got, ok, err = s.GetFetchRecord(ctx, coordinatetest.MustNew(timed.ModulePath, timed.ModuleVersion), timed.PipelineVersion)
	if err != nil || !ok || got.VersionTime != "2026-09-08T16:29:55Z" {
		t.Fatalf("record after fetch@v12: ok=%v err=%v version_time=%q", ok, err, got.VersionTime)
	}
	if err = s.Close(); err != nil {
		t.Fatalf("closing: %v", err)
	}

	assertUnknownToPrevious(t, dsn, previous, all[len(all)-1:])
}

// assertUnknownToPrevious checks that a build holding only previous names
// exactly added as the migrations it does not know.
func assertUnknownToPrevious(t *testing.T, dsn string, previous, added []sqlitestore.Migration) {
	t.Helper()
	handle, err := sqlitestore.Open(dsn, nil, sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("reopening: %v", err)
	}
	defer func() { _ = handle.Close() }()
	state, err := sqlitestore.ReadMigrationState(handle, previous)
	if err != nil {
		t.Fatalf("ReadMigrationState: %v", err)
	}
	var want []string
	for _, m := range added {
		want = append(want, sqlitestore.MigrationKey(m.Module, m.Version))
	}
	if !slices.Equal(state.Unknown, want) {
		t.Errorf("unknown to the previous build = %v, want %v", state.Unknown, want)
	}
}

// seedPreviousSchemaRecord leaves dsn as a build holding only previous would,
// with pre written through the columns that build knows.
func seedPreviousSchemaRecord(t *testing.T, dsn string, previous []sqlitestore.Migration, pre domain2.FactRecord) {
	t.Helper()
	ctx := context.Background()
	old, err := sqlitestore.Open(dsn, previous, sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("opening at the previous schema: %v", err)
	}
	if _, err = old.DB().ExecContext(ctx, `INSERT INTO fetch_records (
    module_path, module_version, pipeline_version, schema_version, ecosystem, module_hash, go_mod_hash,
    git_url, git_ref, git_commit_hash, verification_status, verification_detail,
    fetched_at, content_location, go_mod_location, content_hash, retracted, git_subdir)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		pre.ModulePath, pre.ModuleVersion, pre.PipelineVersion, pre.SchemaVersion, pre.Ecosystem,
		pre.ModuleHash, pre.GoModHash, pre.GitURL, pre.GitRef, pre.GitCommitHash,
		pre.VerificationStatus, pre.VerificationDetail, pre.FetchedAt.Format(time.RFC3339),
		pre.ContentLocation, pre.GoModLocation, pre.ContentHash, pre.Retracted, string(pre.GitSubdir)); err != nil {
		t.Fatalf("seeding a previous-schema record: %v", err)
	}
	if err = old.Close(); err != nil {
		t.Fatalf("closing: %v", err)
	}
}
