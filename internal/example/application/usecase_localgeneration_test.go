package application_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/example/adapters/parser/goast"
	"github.com/eitanity/kanonarion/internal/example/application"
	domain2 "github.com/eitanity/kanonarion/internal/example/domain"
	"github.com/eitanity/kanonarion/internal/example/ports"
	"github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
)

// localGenerationPipeline is the fetch pipeline version local ingest writes
// under; it is not this stage's extraction version.
const localGenerationPipeline = "local-0.1.0"

// advancingClock moves on every read, which is what a clock does between two
// runs over one tree. A fixed clock would seal both extractions identically and
// the test would prove nothing: the store collapses byte-identical rows on its
// own.
type advancingClock struct{ t time.Time }

func (c *advancingClock) Now() time.Time {
	c.t = c.t.Add(time.Hour)
	return c.t
}

// ingestLocalTree files a working tree the way local ingest does: the zip in the
// blob store, and a fetch record naming it.
//
// Calling it again with a different handle is an EDIT. A changed tree re-zips to
// different bytes, so production writes a different artefact identity and a
// different fetch record; a test that changed the files while keeping the
// identity would be testing a state the pipeline cannot produce.
func ingestLocalTree(
	t *testing.T,
	facts *fakeFactStore,
	blobs *fakeBlobStore,
	coord coordinate.ModuleCoordinate,
	handle string,
	files map[string]string,
) {
	t.Helper()
	zipData := buildModuleZip(t, coord, files)
	rec := fetchtest.Record(t,
		fetchtest.Coordinate(coord),
		fetchtest.PipelineVersion(localGenerationPipeline),
		fetchtest.Content(handle),
		fetchtest.Status(domain.LocalSource),
	)
	if err := blobs.Put(context.Background(), fetchtest.ZipIdentity(t, rec), bytes.NewReader(zipData)); err != nil {
		t.Fatalf("Put blob: %v", err)
	}
	if err := facts.PutFetchRecord(context.Background(), fetchtest.Sealed(t,
		fetchtest.Coordinate(coord),
		fetchtest.PipelineVersion(localGenerationPipeline),
		fetchtest.Content(handle),
		fetchtest.Status(domain.LocalSource),
	)); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}
}

// localTreeFiles is a working tree carrying one example.
func localTreeFiles(extra string) map[string]string {
	files := map[string]string{
		"go.mod": "module example.com/project\n",
		"doc.go": "package project\n\nfunc Root() {}\n",
		"example_test.go": "package project_test\n\n" +
			"func ExampleRoot() {\n\t// Output:\n}\n",
	}
	if extra != "" {
		files["extra_test.go"] = extra
	}
	return files
}

// localExampleUseCase wires the stage over a local coordinate whose tree has
// already been ingested. The parser is the real one, so what the tests exercise
// is a genuine re-parse of the tree.
func localExampleUseCase(t *testing.T) (
	*application.ExtractExampleUseCase,
	*fakeExampleStore,
	*fakeFactStore,
	*fakeBlobStore,
	coordinate.ModuleCoordinate,
) {
	t.Helper()
	coord := mustCoord(t, "example.com/project", coordinate.LocalVersion)
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	store := &fakeExampleStore{}
	ingestLocalTree(t, facts, blobs, coord, "zip-one", localTreeFiles(""))

	uc := application.NewExtractExampleUseCase(application.Config{
		Facts:     facts,
		Blobs:     blobs,
		Examples:  store,
		Parser:    goast.New(),
		Clock:     &advancingClock{t: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)},
		Stopwatch: fakeStopwatch{},
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	return uc, store, facts, blobs, coord
}

// TestExecute_ReExtractingAnUnchangedLocalTreeAppendsNothing.
//
// A local coordinate is never served from cache: a local version pins no content
// and the working tree mutates, so the extraction runs again on every run. That
// is correct and this does not change it. What it stops is the SECOND question
// being skipped: the re-extraction came back stating what the ledger already
// states, and appending it again writes a full example set to say nothing new.
func TestExecute_ReExtractingAnUnchangedLocalTreeAppendsNothing(t *testing.T) {
	uc, store, _, blobs, coord := localExampleUseCase(t)

	first, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if first.Reused {
		t.Fatal("the first run reported a reuse; there was nothing to reuse")
	}

	second, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if blobs.gets != 2 {
		t.Fatalf("the zip was read %d times; a local tree must be re-read on every run", blobs.gets)
	}
	if !second.Reused {
		t.Error("the second run did not report that its measurement matched the stored generation")
	}
	if second.FromCache {
		t.Error("the second run reported a cache hit; the extraction did run")
	}
	if len(store.puts) != 1 {
		t.Errorf("%d generations were written for two reads of one unchanged tree, want 1", len(store.puts))
	}
	if second.Record.ContentHash != first.Record.ContentHash {
		t.Error("the second run served a different record from the one already held")
	}
}

// TestExecute_AChangedLocalTreeIsStillAppended is the control, and the half that
// matters most: a rule that suppressed a real re-extraction would leave the
// project's own examples permanently stale.
func TestExecute_AChangedLocalTreeIsStillAppended(t *testing.T) {
	uc, store, facts, blobs, coord := localExampleUseCase(t)

	if _, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord}); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// The tree was edited: a second example was written, so it re-zips to
	// different bytes and the parse now finds one more.
	ingestLocalTree(t, facts, blobs, coord, "zip-two", localTreeFiles(
		"package project_test\n\nfunc ExampleRoot_second() {\n\t// Output:\n}\n"))

	second, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if second.Reused {
		t.Error("a re-extraction of an edited tree was discarded as a repeat")
	}
	if len(second.Record.Examples) != 2 {
		t.Errorf("the served record holds %d examples, want 2: the new measurement was not served",
			len(second.Record.Examples))
	}
	if len(store.puts) != 2 {
		t.Errorf("%d generations were written for two different trees, want 2", len(store.puts))
	}
}

// TestExecute_ForceAppendsALocalGenerationEvenWhenIdentical. --force is how a
// caller re-measures because something OUTSIDE the tree changed — a toolchain
// that can now build a package, a loader failure that has gone away — and asks
// for the result to be recorded. Collapsing it into the held generation would
// leave that caller with no way to record a measurement at all.
func TestExecute_ForceAppendsALocalGenerationEvenWhenIdentical(t *testing.T) {
	uc, store, _, _, coord := localExampleUseCase(t)

	if _, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	forced, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord, Force: true})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if forced.Reused {
		t.Error("--force reported a reuse; it asks for the measurement to be recorded")
	}
	if len(store.puts) != 2 {
		t.Errorf("%d generations were written, want 2: --force records what it measured", len(store.puts))
	}
}

// TestExecute_AnUnreadableLedgerStillRecordsTheMeasurement is the fault seam.
//
// The lookup runs AFTER the extraction, so a store that cannot answer it must
// not cost the run its answer: the measurement is recorded, and the fault is
// stated rather than swallowed. Losing a measured example set to protect an
// optimisation would be the worse failure by far.
func TestExecute_AnUnreadableLedgerStillRecordsTheMeasurement(t *testing.T) {
	uc, store, _, _, coord := localExampleUseCase(t)
	store.getErr = errors.New("ledger unreadable")

	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Reused {
		t.Error("a store that could not answer was read as agreement")
	}
	if len(store.puts) != 1 {
		t.Errorf("%d generations were written, want 1: the measurement must still be recorded", len(store.puts))
	}
}

// plainExampleStore is a store that does not offer IdenticalGeneration: every
// store that existed before the capability, and any implementation that never
// adds it. It delegates rather than embeds, because embedding would promote the
// very method it exists to withhold.
type plainExampleStore struct{ inner *fakeExampleStore }

func (s plainExampleStore) PutExampleRecord(ctx context.Context, r domain2.ExampleRecord) error {
	return s.inner.PutExampleRecord(ctx, r)
}

func (s plainExampleStore) GetExampleRecord(
	ctx context.Context, coord coordinate.ModuleCoordinate, pv string,
) (domain2.ExampleRecord, bool, error) {
	return s.inner.GetExampleRecord(ctx, coord, pv)
}

func (s plainExampleStore) ListExampleRecords(ctx context.Context, f ports.ExampleFilter) ([]ports.ExampleSummary, error) {
	return s.inner.ListExampleRecords(ctx, f)
}

func (s plainExampleStore) FindBySymbol(
	ctx context.Context, symbol string, pv string, scope coordinate.ModuleSet,
) ([]ports.ExampleRef, error) {
	return s.inner.FindBySymbol(ctx, symbol, pv, scope)
}

func (s plainExampleStore) FindBySymbolInModule(
	ctx context.Context, coord coordinate.ModuleCoordinate, symbol string, pv string,
) ([]ports.ExampleRef, error) {
	return s.inner.FindBySymbolInModule(ctx, coord, symbol, pv)
}

// TestExecute_AStoreWithoutTheCapabilityStillRecordsEveryRun. The read is
// optional, so a store that does not offer it must behave exactly as every store
// did before it existed: a generation per run, and no error.
func TestExecute_AStoreWithoutTheCapabilityStillRecordsEveryRun(t *testing.T) {
	coord := mustCoord(t, "example.com/project", coordinate.LocalVersion)
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	inner := &fakeExampleStore{}
	ingestLocalTree(t, facts, blobs, coord, "zip-one", localTreeFiles(""))

	uc := application.NewExtractExampleUseCase(application.Config{
		Facts:     facts,
		Blobs:     blobs,
		Examples:  plainExampleStore{inner: inner},
		Parser:    goast.New(),
		Clock:     &advancingClock{t: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)},
		Stopwatch: fakeStopwatch{},
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	for i := range 2 {
		result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
		if err != nil {
			t.Fatalf("Execute %d: %v", i, err)
		}
		if result.Reused {
			t.Errorf("run %d reported a reuse; the store was never asked", i)
		}
	}
	if len(inner.puts) != 2 {
		t.Errorf("%d generations were written, want 2: a store that cannot answer appends every run", len(inner.puts))
	}
}
