package sqlite_test

import (
	"context"
	"path/filepath"
	"slices"
	"testing"

	"code.eitanity.com/kanonarion/internal/adapters/factstore/sqlite"
	"code.eitanity.com/kanonarion/internal/adapters/sqlitestore"
	"code.eitanity.com/kanonarion/internal/coordinate/coordinatetest"
	domain2 "code.eitanity.com/kanonarion/internal/fetch/domain"
	"code.eitanity.com/kanonarion/internal/fetch/fetchtest"
)

// The directory the VCS leg hashed survives the store, and a record without one
// reads back verifying, as every record written before the column did.
func TestGitSubdirRoundTripsThroughTheStore(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	for _, subdir := range []string{"client/v3", domain2.RepoRoot, ""} {
		r := sampleRecord(t, "go.etcd.io/etcd/client/v3/x"+subdir, "v3.6.14", "0.6.0",
			fetchtest.GitReference(domain2.GitReference{URL: "https://github.com/etcd-io/etcd",
				Ref: "refs/tags/client/v3.6.14", CommitHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Subdir: subdir}))
		if err := s.PutFetchRecord(ctx, mustSeal(t, r)); err != nil {
			t.Fatalf("Put(%q): %v", subdir, err)
		}
		got, ok, err := s.GetFetchRecord(ctx, coordinatetest.MustNew(r.ModulePath, r.ModuleVersion), r.PipelineVersion)
		if err != nil || !ok {
			t.Fatalf("Get(%q): ok=%v err=%v", subdir, ok, err)
		}
		if string(got.GitSubdir) != subdir {
			t.Errorf("GitSubdir = %q, want %q", got.GitSubdir, subdir)
		}
	}
}

// fetch@v11 adds the column to a store at the previous schema, keeping the rows
// already there readable; and a build that predates it meets the store gate's
// refusal (an unknown migration) before it reads a record carrying the column.
func TestGitSubdirMigrationOnAPreviousSchemaStore(t *testing.T) {
	ctx := context.Background()
	all := sqlite.Migrations()
	at := slices.IndexFunc(all, func(m sqlitestore.Migration) bool { return m.Module == "fetch" && m.Version == 11 })
	if at < 0 {
		t.Fatal("no fetch@v11 migration")
	}
	previous := all[:at]
	dsn := filepath.Join(t.TempDir(), "mirror.db")

	// A store as the previous build leaves it, holding one record.
	old, err := sqlitestore.Open(dsn, previous, sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("opening at the previous schema: %v", err)
	}
	r := sampleRecord(t, "github.com/foo/bar", "v1.0.0", "0.5.0")
	sealed := mustSeal(t, r).Record()
	if _, err = old.DB().ExecContext(ctx, `INSERT INTO fetch_records (
    module_path, module_version, pipeline_version, schema_version, ecosystem, module_hash, go_mod_hash,
    git_url, git_ref, git_commit_hash, verification_status, verification_detail,
    fetched_at, content_location, go_mod_location, content_hash, retracted)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sealed.ModulePath, sealed.ModuleVersion, sealed.PipelineVersion, sealed.SchemaVersion, sealed.Ecosystem,
		sealed.ModuleHash, sealed.GoModHash, sealed.GitURL, sealed.GitRef, sealed.GitCommitHash,
		sealed.VerificationStatus, sealed.VerificationDetail, "2024-01-01T00:00:00Z",
		sealed.ContentLocation, sealed.GoModLocation, sealed.ContentHash, sealed.Retracted); err != nil {
		t.Fatalf("seeding a previous-schema record: %v", err)
	}
	if err = old.Close(); err != nil {
		t.Fatalf("closing: %v", err)
	}

	s, err := sqlite.Open(dsn)
	if err != nil {
		t.Fatalf("migrating to fetch@v11: %v", err)
	}
	got, ok, err := s.GetFetchRecord(ctx, coordinatetest.MustNew(r.ModulePath, r.ModuleVersion), r.PipelineVersion)
	if err != nil || !ok || got.GitSubdir != "" {
		t.Fatalf("pre-migration record after fetch@v11: ok=%v err=%v subdir=%q", ok, err, got.GitSubdir)
	}
	withDir := sampleRecord(t, "github.com/foo/bar/sub", "v1.0.0", "0.6.0",
		fetchtest.GitReference(domain2.GitReference{URL: "https://github.com/foo/bar", Subdir: "sub"}))
	if err = s.PutFetchRecord(ctx, mustSeal(t, withDir)); err != nil {
		t.Fatalf("Put after migration: %v", err)
	}
	if err = s.Close(); err != nil {
		t.Fatalf("closing: %v", err)
	}

	assertUnknownToPrevious(t, dsn, previous, all[at:])
}
