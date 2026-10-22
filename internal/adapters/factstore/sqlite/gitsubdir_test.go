package sqlite_test

import (
	"context"
	"path/filepath"
	"slices"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/factstore/sqlite"
	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
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
	last := all[len(all)-1]
	if last.Module != "fetch" || last.Version != 11 {
		t.Fatalf("last fetch migration = %s@v%d, want fetch@v11", last.Module, last.Version)
	}
	previous := all[:len(all)-1]
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

	handle, err := sqlitestore.Open(dsn, nil, sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("reopening: %v", err)
	}
	defer func() { _ = handle.Close() }()
	state, err := sqlitestore.ReadMigrationState(handle, previous)
	if err != nil {
		t.Fatalf("ReadMigrationState: %v", err)
	}
	if !slices.Equal(state.Unknown, []string{sqlitestore.MigrationKey("fetch", 11)}) {
		t.Errorf("unknown to the previous build = %v, want [fetch@v11]", state.Unknown)
	}
}
