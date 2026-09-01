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
	"github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	"github.com/eitanity/kanonarion/internal/gotoolchain"
	"github.com/eitanity/kanonarion/internal/iface/application"
	domain3 "github.com/eitanity/kanonarion/internal/iface/domain"
	"github.com/eitanity/kanonarion/internal/iface/ports"
)

// localGenerationPipeline is the fetch pipeline version local ingest writes
// under; it is not this stage's extraction version.
const localGenerationPipeline = "local-0.1.0"

// localExtractionTime is when the first extraction of the tree was taken. This
// stage's ExtractedAt comes from the EXTRACTOR's clock, not the use case's, so a
// second run is given a later one explicitly — see the tests below.
var localExtractionTime = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

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

// localInterfaceUseCase wires the stage over a local coordinate whose tree has
// already been ingested.
func localInterfaceUseCase(t *testing.T) (
	*application.ExtractInterfaceUseCase,
	*fakeInterfaceStore,
	*fakeExtractor,
	*fakeFactStore,
	*fakeBlobStore,
	coordinate.ModuleCoordinate,
) {
	t.Helper()
	coord := mustCoord(t, "example.com/project", coordinate.LocalVersion)
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	store := &fakeInterfaceStore{}
	ext := &fakeExtractor{record: domain3.InterfaceRecord{
		SchemaVersion: domain3.InterfaceSchemaVersion,
		Ecosystem:     domain.EcosystemGo,
		OverallStatus: domain3.InterfaceStatusExtracted,
		Packages: []domain3.PackageInterface{{
			ImportPath: "example.com/project",
			Name:       "project",
			Funcs:      []domain3.FuncDecl{{Name: "Root", Signature: "func Root()"}},
		}},
		ExtractedAt: localExtractionTime,
	}}
	ingestLocalTree(t, facts, blobs, coord, "zip-one", map[string]string{"go.mod": "module example.com/project\n"})

	uc := application.NewExtractInterfaceUseCase(application.Config{
		Facts:     facts,
		Blobs:     blobs,
		Store:     store,
		Extractor: ext,
		Clock:     fakeClock{t: localExtractionTime},
		Stopwatch: fakeStopwatch{},
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	return uc, store, ext, facts, blobs, coord
}

// TestExecute_ReExtractingAnUnchangedLocalTreeAppendsNothing.
//
// A local coordinate is never served from cache: a local version pins no content
// and the working tree mutates, so the extraction runs again on every run. That
// is correct and this does not change it. What it stops is the SECOND question
// being skipped: the re-extraction came back stating what the ledger already
// states, and appending it again writes a full package set to say nothing new.
func TestExecute_ReExtractingAnUnchangedLocalTreeAppendsNothing(t *testing.T) {
	uc, store, ext, _, _, coord := localInterfaceUseCase(t)

	first, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if first.Reused {
		t.Fatal("the first run reported a reuse; there was nothing to reuse")
	}

	// The next run reads the same tree an hour later. The clock is the
	// extractor's here, not the use case's, so the second measurement is given
	// its own time the way the real extractor stamps one.
	ext.record.ExtractedAt = localExtractionTime.Add(time.Hour)

	second, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if ext.calls != 2 {
		t.Fatalf("the extractor ran %d times; a local tree must be re-read on every run", ext.calls)
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
// project's own API permanently stale.
func TestExecute_AChangedLocalTreeIsStillAppended(t *testing.T) {
	uc, store, ext, facts, blobs, coord := localInterfaceUseCase(t)

	if _, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord}); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// The tree was edited: it re-zips to different bytes and the extraction now
	// reaches a function that did not exist before.
	ingestLocalTree(t, facts, blobs, coord, "zip-two", map[string]string{
		"go.mod": "module example.com/project\n",
		"add.go": "package project\n\nfunc Added() {}\n",
	})
	ext.record.ExtractedAt = localExtractionTime.Add(time.Hour)
	ext.record.Packages[0].Funcs = append(ext.record.Packages[0].Funcs,
		domain3.FuncDecl{Name: "Added", Signature: "func Added()"})

	second, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if second.Reused {
		t.Error("a re-extraction of an edited tree was discarded as a repeat")
	}
	if len(second.Record.Packages[0].Funcs) != 2 {
		t.Errorf("the served record exports %d functions, want 2: the new measurement was not served",
			len(second.Record.Packages[0].Funcs))
	}
	if len(store.puts) != 2 {
		t.Errorf("%d generations were written for two different trees, want 2", len(store.puts))
	}
}

// TestExecute_ADifferentToolchainIsANewMeasurement.
//
// This is the dimension licence and example do not have. The toolchain is inside
// the seal but has no column, so nothing in the prefilter separates two
// extractions of one tree built under two toolchains. Collapsing them would
// throw away the record of what the newer toolchain saw.
func TestExecute_ADifferentToolchainIsANewMeasurement(t *testing.T) {
	uc, store, ext, _, _, coord := localInterfaceUseCase(t)
	// The extractor stamps the toolchain onto the record it returns, which is
	// what the real one does; the method is what the failure branch reads.
	ext.toolchain = gotoolchain.Version("go1.24.0")
	ext.record.Toolchain = ext.toolchain

	if _, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord}); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// Same tree, same API, a newer Go.
	ext.toolchain = gotoolchain.Version("go1.25.0")
	ext.record.Toolchain = ext.toolchain
	ext.record.ExtractedAt = localExtractionTime.Add(time.Hour)

	second, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if second.Reused {
		t.Error("an extraction under a different toolchain was discarded as a repeat")
	}
	if len(store.puts) != 2 {
		t.Errorf("%d generations were written for two toolchains, want 2", len(store.puts))
	}
}

// TestExecute_ForceAppendsALocalGenerationEvenWhenIdentical. --force is how a
// caller re-measures because something OUTSIDE the tree changed and asks for the
// result to be recorded. Collapsing it into the held generation would leave that
// caller with no way to record a measurement at all.
func TestExecute_ForceAppendsALocalGenerationEvenWhenIdentical(t *testing.T) {
	uc, store, ext, _, _, coord := localInterfaceUseCase(t)

	if _, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	ext.record.ExtractedAt = localExtractionTime.Add(time.Hour)
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
// stated rather than swallowed. Losing a measured API to protect an optimisation
// would be the worse failure by far.
func TestExecute_AnUnreadableLedgerStillRecordsTheMeasurement(t *testing.T) {
	uc, store, _, _, _, coord := localInterfaceUseCase(t)
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

// plainInterfaceStore is a store that does not offer IdenticalGeneration: every
// store that existed before the capability, and any implementation that never
// adds it. It delegates rather than embeds, because embedding would promote the
// very method it exists to withhold.
type plainInterfaceStore struct{ inner *fakeInterfaceStore }

func (s plainInterfaceStore) PutInterfaceRecord(ctx context.Context, r domain3.InterfaceRecord) error {
	return s.inner.PutInterfaceRecord(ctx, r)
}

func (s plainInterfaceStore) GetInterfaceRecord(
	ctx context.Context, coord coordinate.ModuleCoordinate, pv string,
) (domain3.InterfaceRecord, bool, error) {
	return s.inner.GetInterfaceRecord(ctx, coord, pv)
}

func (s plainInterfaceStore) ListInterfaceRecords(ctx context.Context, f ports.InterfaceFilter) ([]ports.InterfaceSummary, error) {
	return s.inner.ListInterfaceRecords(ctx, f)
}

func (s plainInterfaceStore) FindSymbol(
	ctx context.Context, name string, pv string, scope coordinate.ModuleSet,
) ([]ports.SymbolRef, error) {
	return s.inner.FindSymbol(ctx, name, pv, scope)
}

// TestExecute_AStoreWithoutTheCapabilityStillRecordsEveryRun. The read is
// optional, so a store that does not offer it must behave exactly as every store
// did before it existed: a generation per run, and no error.
func TestExecute_AStoreWithoutTheCapabilityStillRecordsEveryRun(t *testing.T) {
	coord := mustCoord(t, "example.com/project", coordinate.LocalVersion)
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	inner := &fakeInterfaceStore{}
	ext := &fakeExtractor{record: domain3.InterfaceRecord{
		SchemaVersion: domain3.InterfaceSchemaVersion,
		Ecosystem:     domain.EcosystemGo,
		OverallStatus: domain3.InterfaceStatusExtracted,
		ExtractedAt:   localExtractionTime,
	}}
	ingestLocalTree(t, facts, blobs, coord, "zip-one", map[string]string{"go.mod": "module example.com/project\n"})

	uc := application.NewExtractInterfaceUseCase(application.Config{
		Facts:     facts,
		Blobs:     blobs,
		Store:     plainInterfaceStore{inner: inner},
		Extractor: ext,
		Clock:     fakeClock{t: localExtractionTime},
		Stopwatch: fakeStopwatch{},
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	for i := range 2 {
		ext.record.ExtractedAt = localExtractionTime.Add(time.Duration(i) * time.Hour)
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
