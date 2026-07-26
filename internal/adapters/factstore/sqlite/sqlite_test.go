package sqlite_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/factstore/sqlite"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
)

func openMemStore(t *testing.T) *sqlite.Store {
	t.Helper()
	s, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("s.Close: %v", err)
		}
	})
	return s
}

// mustSeal wraps a record in the SealedRecord the store accepts for writing.
// The store takes only sealed records, so a test that seeds one goes through
// here rather than reaching past the guard the ledger depends on.
func mustSeal(t testing.TB, r domain2.FactRecord) domain2.SealedRecord {
	t.Helper()
	sealed, err := domain2.Rehydrate(r)
	if err != nil {
		t.Fatalf("sealing record: %v", err)
	}
	return sealed
}

func sampleRecord(t testing.TB, path, version, pipelineVersion string, opts ...fetchtest.Option) domain2.FactRecord {
	return fetchtest.Record(t, append([]fetchtest.Option{
		fetchtest.Module(path, version),
		fetchtest.PipelineVersion(pipelineVersion),
		fetchtest.Content("sha256:deadbeef"),
		fetchtest.ModuleHash(fetchtest.H1("abc==")),
		fetchtest.GoModHash(fetchtest.H1("def==")),
		fetchtest.GitReference(domain2.GitReference{URL: "https://github.com/foo/bar", Ref: "refs/tags/" + version, CommitHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}),
		fetchtest.Status(domain2.Verified),
		fetchtest.FetchedAt(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)),
	}, opts...)...)
}

func TestPutGetFetchRecord_DigestsRoundTrip(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	r := sampleRecord(t, "github.com/foo/bar", "v2.0.0", "0.4.0", fetchtest.Digests(domain2.ArtifactDigests{
		SHA256: "2222222222222222222222222222222222222222222222222222222222222222",
		SHA384: "333333333333333333333333333333333333333333333333",
		SHA512: "5555555555555555555555555555555555555555555555555555555555555555",
	}))

	if err := s.PutFetchRecord(ctx, mustSeal(t, r)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, ok, err := s.GetFetchRecord(ctx, coordinatetest.MustNew(r.ModulePath, r.ModuleVersion), r.PipelineVersion)
	if err != nil || !ok {
		t.Fatalf("Get: ok=%v err=%v", ok, err)
	}
	if domain2.RecordDigests(got.FactRecord) != domain2.RecordDigests(r) {
		t.Errorf("digests did not round-trip: got %+v want %+v", domain2.RecordDigests(got.FactRecord), domain2.RecordDigests(r))
	}
}

func TestPutGetFetchRecord(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	r := sampleRecord(t, "github.com/foo/bar", "v1.0.0", "0.1.0")
	if err := s.PutFetchRecord(ctx, mustSeal(t, r)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, ok, err := s.GetFetchRecord(ctx, coordinatetest.MustNew(r.ModulePath, r.ModuleVersion), r.PipelineVersion)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok {
		t.Fatal("record not found")
	}
	if got.ModulePath != r.ModulePath || got.ModuleVersion != r.ModuleVersion {
		t.Errorf("got %+v, want path=%s ver=%s", got, r.ModulePath, r.ModuleVersion)
	}
	if got.FetchedAt != r.FetchedAt {
		t.Errorf("FetchedAt mismatch: %v vs %v", got.FetchedAt, r.FetchedAt)
	}
}

func TestGetFetchRecord_NotFound(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	_, ok, err := s.GetFetchRecord(ctx, coordinatetest.MustNew("x", "v1.0.0"), "0.1.0")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if ok {
		t.Error("expected not found")
	}
}

// TestPutFetchRecord_AppendsRatherThanOverwrites is the deliberate inversion of
// what this test used to assert. It used to check that a second write REPLACED
// the first — the behaviour that let the store contradict its own audit log,
// which recorded fifteen writes for a coordinate while the store kept one, and
// destroyed the evidence an investigation into a verification demotion needed.
//
// Both measurements now survive, and a reader gets the composition of them.
func TestPutFetchRecord_AppendsRatherThanOverwrites(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	first := sampleRecord(t, "github.com/foo/bar", "v1.0.0", "0.1.0")
	if err := s.PutFetchRecord(ctx, mustSeal(t, first)); err != nil {
		t.Fatalf("first Put: %v", err)
	}

	// A second measurement of the same artefact, differing in a hashed field, so
	// it is genuinely a different record. It shares an instant with the first —
	// a fixed clock, as a coarse one would produce — which the key must still
	// keep apart.
	second := sampleRecord(t, "github.com/foo/bar", "v1.0.0", "0.1.0", fetchtest.Detail("re-measured"))
	if err := s.PutFetchRecord(ctx, mustSeal(t, second)); err != nil {
		t.Fatalf("second Put: %v", err)
	}

	coord := coordinatetest.MustNew(first.ModulePath, first.ModuleVersion)
	held, err := s.ListFetchRecords(ctx, coord, first.PipelineVersion)
	if err != nil {
		t.Fatalf("ListFetchRecords: %v", err)
	}
	if len(held) != 2 {
		t.Fatalf("ledger holds %d measurements, want 2: the first was overwritten", len(held))
	}

	got, ok, err := s.GetFetchRecord(ctx, coord, first.PipelineVersion)
	if err != nil || !ok {
		t.Fatalf("Get: err=%v ok=%v", err, ok)
	}
	if got.MeasurementCount != 2 {
		t.Errorf("MeasurementCount = %d, want 2", got.MeasurementCount)
	}
}

// The same record written twice is one measurement, not two, so it is a no-op
// rather than either a duplicate row or an error. A retried write must not fail
// a run that already succeeded.
func TestPutFetchRecord_IdenticalRewriteIsANoOp(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	r := sampleRecord(t, "github.com/foo/bar", "v1.0.0", "0.1.0")
	for i := range 2 {
		if err := s.PutFetchRecord(ctx, mustSeal(t, r)); err != nil {
			t.Fatalf("Put %d: %v", i+1, err)
		}
	}

	held, err := s.ListFetchRecords(ctx,
		coordinatetest.MustNew(r.ModulePath, r.ModuleVersion), r.PipelineVersion)
	if err != nil {
		t.Fatalf("ListFetchRecords: %v", err)
	}
	if len(held) != 1 {
		t.Errorf("ledger holds %d measurements, want 1: an identical rewrite is the same measurement", len(held))
	}
}

// TestGetFetchRecord_IntegrityError is the deliberate inversion of what this
// test used to assert. It used to require (zero, false, nil) on a tampered
// content hash — a detected tamper reported as a plain absence, which the caller
// then treated as a cache miss and re-fetched, overwriting the very evidence
// that something had been tampered with. The loudest signal the store can
// produce was its quietest path.
//
// It is now an error, so the read fails closed and the operator sees it.
func TestGetFetchRecord_IntegrityError(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	r := sampleRecord(t, "github.com/foo/bar", "v1.0.0", "0.1.0")
	if err := s.PutFetchRecord(ctx, mustSeal(t, r)); err != nil {
		t.Fatal(err)
	}

	// Tamper with content_hash in DB
	db := s.InternalDB().DB()
	if _, err := db.Exec("UPDATE fetch_records SET content_hash = 'sha256:tampered'"); err != nil {
		t.Fatal(err)
	}

	_, ok, err := s.GetFetchRecord(ctx, coordinatetest.MustNew(r.ModulePath, r.ModuleVersion), r.PipelineVersion)
	if err == nil {
		t.Fatal("a tampered record was reported without error; a detected tamper must never read as absence")
	}
	if ok {
		t.Error("a tampered record must not be reported as found")
	}
}

// SealedRecord is meant to be self-evidencing: holding one proves its contents
// were hashed, because Seal and Rehydrate are the only ways to make one. The
// type system does not quite deliver that — SealedRecord is an exported struct,
// so any package can write domain2.SealedRecord{} and hold a value that sealed
// nothing. Stored, it becomes an all-empty row that every later read treats as a
// genuine measurement of the empty module at the empty version, with a content
// hash of "" that no verification can distinguish from a record whose fields
// really are empty. The write is refused instead.
func TestPutFetchRecord_RefusesTheZeroSealedRecord(t *testing.T) {
	s := openMemStore(t)

	fetchtest.AssertRefusesUnsealed(t, s)

	// The leg the shared assertion cannot cover: it has no reader, so whether the
	// refusal also left the ledger untouched is checked by the store that has one.
	var n int
	if qerr := s.InternalDB().DB().QueryRow("SELECT COUNT(*) FROM fetch_records").Scan(&n); qerr != nil {
		t.Fatalf("counting rows: %v", qerr)
	}
	if n != 0 {
		t.Errorf("the refused write left %d row(s) behind", n)
	}
}

// The guard has to hold under the decorator the production path actually uses.
// An audit entry for a record that was never stored would put a measurement in
// the log that no ledger row backs — the audit log's whole claim is that it
// mirrors the writes.
func TestAuditingStore_RefusesTheZeroSealedRecordAndLogsNothing(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	inner, err := sqlite.Open(filepath.Join(dir, "facts.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	store, err := sqlite.NewAuditingStore(inner, auditPath)
	if err != nil {
		t.Fatalf("NewAuditingStore: %v", err)
	}
	defer func() {
		if cerr := store.Close(); cerr != nil {
			t.Errorf("store.Close: %v", cerr)
		}
	}()

	fetchtest.AssertRefusesUnsealed(t, store)

	data, rerr := os.ReadFile(auditPath) //nolint:gosec // test-owned temp path
	if rerr != nil && !os.IsNotExist(rerr) {
		t.Fatalf("reading audit log: %v", rerr)
	}
	if len(data) != 0 {
		t.Errorf("the refused write was mirrored into the audit log: %s", data)
	}
}

func TestGetFetchRecord_Retracted(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	r := sampleRecord(t, "github.com/foo/bar", "v1.0.0", "0.1.0", fetchtest.Retracted(true))

	if err := s.PutFetchRecord(ctx, mustSeal(t, r)); err != nil {
		t.Fatal(err)
	}

	got, ok, err := s.GetFetchRecord(ctx, coordinatetest.MustNew(r.ModulePath, r.ModuleVersion), r.PipelineVersion)
	if err != nil || !ok {
		t.Fatalf("Get: err=%v ok=%v", err, ok)
	}
	if !got.Retracted {
		t.Error("expected Retracted=true")
	}
}
