package sqlite_test

import (
	"context"
	"testing"
	"time"

	"code.eitanity.com/kanonarion/internal/adapters/blobcodec"
	"code.eitanity.com/kanonarion/internal/adapters/sqlitestore"
	walksqlite "code.eitanity.com/kanonarion/internal/walk/adapters/walks/sqlite"
	"code.eitanity.com/kanonarion/internal/walk/domain"
	walkports "code.eitanity.com/kanonarion/internal/walk/ports"
)

// tinyGoWalkRecord is a linux/arm walk resolved under the pico TinyGo frame.
func tinyGoWalkRecord(t *testing.T, id string, startedAt time.Time) domain.WalkRecord {
	t.Helper()
	rec := buildWalkRecordForPlatform(t, id, "linux", "arm", startedAt)
	rec.Graph.BuildEnv.GOARM = "6"
	rec.Graph.BuildEnv.TinyGoTarget = "pico"
	rec.Graph.BuildEnv.TinyGoVersion = "0.42.0"
	rec.Graph.BuildEnv.TinyGoTags = []string{"tinygo", "pico"}
	rec, err := domain.WalkRecordHasher{}.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	return rec
}

// A standard linux/arm read must never select a pico walk, nor a pico read a
// standard one, whichever is newer.
func TestListWalks_TheTinyGoTargetIsPartOfThePlatform(t *testing.T) {
	s, standard, pico := storeWithStandardAndPico(t)
	ctx := context.Background()

	for _, tc := range []struct {
		filter walkports.BuildEnvFilter
		want   string
	}{
		{walkports.BuildEnvFilter{GOOS: "linux", GOARCH: "arm"}, standard.ID},
		{walkports.BuildEnvFilter{GOOS: "linux", GOARCH: "arm", TinyGoTarget: "pico"}, pico.ID},
		{walkports.BuildEnvFilter{TinyGoTarget: "pico"}, pico.ID},
	} {
		got, err := s.ListWalks(ctx, walkports.WalkFilter{BuildEnv: &tc.filter})
		if err != nil {
			t.Fatalf("ListWalks: %v", err)
		}
		if len(got) != 1 || got[0].ID != tc.want {
			t.Errorf("%s selected %v, want only %s", tc.filter, got, tc.want)
		}
	}

	back, err := s.GetWalk(ctx, pico.ID)
	if err != nil {
		t.Fatalf("GetWalk: %v", err)
	}
	if back.Graph.BuildEnv.TinyGoTarget != "pico" || len(back.Graph.BuildEnv.TinyGoTags) != 2 {
		t.Errorf("the stored record lost its frame: %+v", back.Graph.BuildEnv)
	}
}

// --latest keeps a TinyGo walk and a standard one apart, and the summary
// carries the TinyGo frame.
func TestListWalks_LatestPartitionsOnTheTinyGoTarget(t *testing.T) {
	s, _, pico := storeWithStandardAndPico(t)

	got, err := s.ListWalks(context.Background(), walkports.WalkFilter{LatestOnly: true})
	if err != nil {
		t.Fatalf("ListWalks: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("--latest collapsed a TinyGo walk and a standard one into %d rows", len(got))
	}
	for _, sum := range got {
		if sum.ID == pico.ID && (sum.TinyGoTarget != "pico" || sum.TinyGoVersion != "0.42.0" || sum.BuildFrame() != "tinygo/pico (linux/arm)") {
			t.Errorf("pico summary = %+v, frame %q", sum, sum.BuildFrame())
		}
	}
}

// The TinyGo version is matched exactly, the empty string naming walks that
// declared none.
func TestListWalks_FiltersByTinyGoVersion(t *testing.T) {
	s, _, _ := storeWithStandardAndPico(t)
	for _, tc := range []struct {
		version string
		want    int
	}{{"0.42.0", 1}, {"0.41.0", 0}, {"", 1}} {
		v := tc.version
		got, err := s.ListWalks(context.Background(), walkports.WalkFilter{TinyGoVersion: &v})
		if err != nil {
			t.Fatalf("ListWalks: %v", err)
		}
		if len(got) != tc.want {
			t.Errorf("TinyGoVersion %q selected %d walks, want %d", v, len(got), tc.want)
		}
	}
}

// storeWithStandardAndPico holds a linux/arm walk and a newer pico one.
func storeWithStandardAndPico(t *testing.T) (*walksqlite.Store, domain.WalkRecord, domain.WalkRecord) {
	t.Helper()
	s := openMemStore(t)
	base := time.Date(2026, 10, 17, 5, 0, 0, 0, time.UTC)
	standard := buildWalkRecordForPlatform(t, "01TINYGO000000000STANDARD", "linux", "arm", base)
	pico := tinyGoWalkRecord(t, "01TINYGO00000000000000PICO", base.Add(time.Hour))
	for _, rec := range []domain.WalkRecord{standard, pico} {
		if err := s.PutWalk(context.Background(), rec); err != nil {
			t.Fatalf("PutWalk %s: %v", rec.ID, err)
		}
	}
	return s, standard, pico
}

// A row written before migration 12 reads as "not a TinyGo walk", and still
// verifies against its seal.
func TestMigration12_AnExistingRowIsNotATinyGoWalk(t *testing.T) {
	ctx := context.Background()
	handle, err := sqlitestore.Open("file:"+t.Name()+"?mode=memory&cache=shared", walkMigrationsBefore(t, 12), sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("opening at the pre-migration schema: %v", err)
	}
	defer func() {
		if cerr := handle.Close(); cerr != nil {
			t.Errorf("closing: %v", cerr)
		}
	}()
	rec := buildWalkRecordForPlatform(t, "01TINYGO0000000PREMIGRATE", "linux", "arm", time.Date(2026, 10, 17, 5, 0, 0, 0, time.UTC))
	raw, err := domain.WalkRecordHasher{}.Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if _, eerr := handle.DB().ExecContext(ctx, `
INSERT INTO walks (id, target_path, target_version, started_at, completed_at,
    overall_status, pipeline_version, operator, content_hash,
    node_count, failure_count, scope, depth, project_dir, identity_hash,
    goos, goarch, go_version, serialised)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 'code', '', '', '', 'linux', 'arm', 'go1.26.4', ?)`,
		rec.ID, rec.Target.Path(), rec.Target.Version(),
		rec.StartedAt.UTC().Format(time.RFC3339), rec.CompletedAt.UTC().Format(time.RFC3339),
		int(rec.OverallStatus), rec.PipelineVersion, rec.Operator, rec.ContentHash,
		blobcodec.Encode(raw),
	); eerr != nil {
		t.Fatalf("inserting a pre-migration row: %v", eerr)
	}

	if aerr := sqlitestore.Apply(handle, walksqlite.Migrations()); aerr != nil {
		t.Fatalf("applying migration 12: %v", aerr)
	}

	store := walksqlite.New(handle)
	platform := walkports.BuildEnvFilter{GOOS: "linux", GOARCH: "arm"}
	got, err := store.ListWalks(ctx, walkports.WalkFilter{BuildEnv: &platform})
	if err != nil {
		t.Fatalf("ListWalks: %v", err)
	}
	if len(got) != 1 || got[0].TinyGoTarget != "" || got[0].TinyGoVersion != "" {
		t.Fatalf("after migration 12 the linux/arm read found %+v", got)
	}
	if _, gerr := store.GetWalk(ctx, rec.ID); gerr != nil {
		t.Errorf("GetWalk after migration: %v", gerr)
	}
}
