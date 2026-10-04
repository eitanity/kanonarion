package application_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// fakeToolchainLocator answers with one toolchain, or with the refusal a host
// that holds none produces.
type fakeToolchainLocator struct {
	src  ports.ToolchainSource
	err  error
	want string
}

func (l *fakeToolchainLocator) LocateToolchain(_ context.Context, goVersion string) (ports.ToolchainSource, error) {
	l.want = goVersion
	return l.src, l.err
}

// fakeStdlibAnalyser returns a fixed graph and records what it was asked.
type fakeStdlibAnalyser struct {
	record domain.CallGraphRecord
	err    error
	calls  int
	gotSrc ports.ToolchainSource
}

func (a *fakeStdlibAnalyser) AnalyseStdlib(
	_ context.Context, src ports.ToolchainSource, coord coordinate.ModuleCoordinate,
) (domain.CallGraphRecord, error) {
	a.calls++
	a.gotSrc = src
	rec := a.record
	rec.Coordinate = coord
	return rec, a.err
}

func (a *fakeStdlibAnalyser) AnalyserMetadata() ports.AnalyserMetadata {
	return ports.AnalyserMetadata{Algorithm: domain.AlgorithmCHA, Version: "0.0.0-test"}
}

type fakeCustody struct {
	custody ports.StdlibCustody
	found   bool
	err     error
}

func (c fakeCustody) StdlibCustody(context.Context, string) (ports.StdlibCustody, bool, error) {
	return c.custody, c.found, c.err
}

func stdlibTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// analysedStdlibRecord is what the analyser hands back: a real graph of the
// toolchain's own source, with the fields the analyser stamps.
func analysedStdlibRecord() domain.CallGraphRecord {
	return domain.CallGraphRecord{
		SchemaVersion:  domain.CallGraphSchemaVersion,
		Ecosystem:      fetchdomain.EcosystemGo,
		Algorithm:      domain.AlgorithmCHA,
		Completeness:   domain.CompletenessBuiltWithBodies,
		ArtifactKind:   domain.ArtifactLibrary,
		AnalysisSource: domain.AnalysisSourceToolchainSource,
		AnalysisRoot:   "/usr/local/go/src",
		WorktreeDigest: "analysed-sha256:abc",
		OverallStatus:  domain.CallGraphStatusExtracted,
		Nodes:          []domain.CallNode{{ID: "net/http.Get", Module: "stdlib", Package: "net/http", Symbol: "Get"}},
	}
}

func newStdlibUseCase(t *testing.T, store ports.CallGraphStore, locator ports.ToolchainSourceLocator,
	analyser ports.StdlibCallGraphAnalyser, custody ports.StdlibCustodyReader,
) *cgapp.ExtractStdlibCallGraphUseCase {
	t.Helper()
	return cgapp.NewExtractStdlibCallGraphUseCase(cgapp.StdlibConfig{
		Store: store, Analyser: analyser, Toolchains: locator, Custody: custody,
		Clock: fakeClock{t: time.Unix(1, 0).UTC()}, Stopwatch: fakeStopwatch{}, Logger: stdlibTestLogger(),
	})
}

// TestExtractStdlib_AnchorsToTheCustodyChain is the identity decision: the
// record names the published source tarball the custody ledger holds for this
// toolchain version, and the source tree it actually read is stated separately.
func TestExtractStdlib_AnchorsToTheCustodyChain(t *testing.T) {
	store := &fakeCallGraphStore{}
	analyser := &fakeStdlibAnalyser{record: analysedStdlibRecord()}
	locator := &fakeToolchainLocator{src: ports.ToolchainSource{
		GoRoot: "/usr/local/go", GoBinary: "/usr/local/go/bin/go", Version: "go1.26.5",
	}}
	custody := fakeCustody{found: true, custody: ports.StdlibCustody{
		ArtefactIdentity: "sha256:495be4bc", MeasurementHash: "sha256:ecff68b7", Verification: "VerifiedGoDevChecksum",
	}}

	uc := newStdlibUseCase(t, store, locator, analyser, custody)
	res, err := uc.Execute(t.Context(), cgapp.ExtractRequest{
		Coordinate: coordinatetest.MustNew(coordinate.StdlibPath, "v1.26.5"),
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if locator.want != "go1.26.5" {
		t.Errorf("the locator was asked for %q, want the toolchain the coordinate names", locator.want)
	}
	if analyser.gotSrc.GoBinary != "/usr/local/go/bin/go" {
		t.Errorf("the analyser was handed %q, want the located toolchain's own go command", analyser.gotSrc.GoBinary)
	}
	if res.Record.ArtefactIdentity != "sha256:495be4bc" {
		t.Errorf("artefact identity = %q, want the custody chain's published tarball", res.Record.ArtefactIdentity)
	}
	if res.Record.SourceContentHash != "sha256:ecff68b7" {
		t.Errorf("source content hash = %q, want the custody measurement's own seal", res.Record.SourceContentHash)
	}
	if res.Record.WorktreeDigest != "analysed-sha256:abc" {
		t.Errorf("the record lost the digest of the source tree it read: %q", res.Record.WorktreeDigest)
	}
	if res.Record.ContentHash == "" {
		t.Error("the record was stored unsealed")
	}
}

// TestExtractStdlib_WithoutCustodyNamesTheToolchainInstead: a toolchain version
// the custody ledger has never measured still produces a graph, and the record
// says what it can stand behind rather than a digest nothing computed.
func TestExtractStdlib_WithoutCustodyNamesTheToolchainInstead(t *testing.T) {
	store := &fakeCallGraphStore{}
	uc := newStdlibUseCase(t, store,
		&fakeToolchainLocator{src: ports.ToolchainSource{GoRoot: "/usr/local/go", Version: "go1.26.5"}},
		&fakeStdlibAnalyser{record: analysedStdlibRecord()}, fakeCustody{})

	res, err := uc.Execute(t.Context(), cgapp.ExtractRequest{
		Coordinate: coordinatetest.MustNew(coordinate.StdlibPath, "v1.26.5"),
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.Record.ArtefactIdentity != "toolchain:go1.26.5" {
		t.Errorf("artefact identity = %q, want the toolchain's own name spelled so it cannot read as a digest",
			res.Record.ArtefactIdentity)
	}
}

// TestExtractStdlib_RefusesWhenNoToolchainSuppliesIt: a graph of the standard
// library built by a different Go is a graph of a different standard library,
// so nothing is recorded.
func TestExtractStdlib_RefusesWhenNoToolchainSuppliesIt(t *testing.T) {
	store := &fakeCallGraphStore{}
	analyser := &fakeStdlibAnalyser{record: analysedStdlibRecord()}
	uc := newStdlibUseCase(t, store,
		&fakeToolchainLocator{err: ports.ErrToolchainSourceUnavailable}, analyser, fakeCustody{})

	_, err := uc.Execute(t.Context(), cgapp.ExtractRequest{
		Coordinate: coordinatetest.MustNew(coordinate.StdlibPath, "v1.99.0"),
	})
	if !errors.Is(err, ports.ErrToolchainSourceUnavailable) {
		t.Fatalf("err = %v, want %v", err, ports.ErrToolchainSourceUnavailable)
	}
	if analyser.calls != 0 {
		t.Error("the analyser ran without a toolchain to read")
	}
	if len(store.puts) != 0 {
		t.Error("a record was written for a standard library nothing analysed")
	}
}

// TestExtractStdlib_RefusesANonStdlibCoordinate keeps the three extraction
// paths apart: this one reads a toolchain and knows nothing about fetching.
func TestExtractStdlib_RefusesANonStdlibCoordinate(t *testing.T) {
	uc := newStdlibUseCase(t, &fakeCallGraphStore{},
		&fakeToolchainLocator{}, &fakeStdlibAnalyser{}, fakeCustody{})

	_, err := uc.Execute(t.Context(), cgapp.ExtractRequest{
		Coordinate: coordinatetest.MustNew("example.com/mod", "v1.0.0"),
	})
	if err == nil {
		t.Fatal("a module coordinate was accepted by the standard-library stage")
	}
}

// TestStdlibCoordinateFor converts the toolchain's own spelling into the
// coordinate every record and advisory keys on, in one place.
func TestStdlibCoordinateFor(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		wantErr  bool
	}{
		{in: "go1.26.5", want: "stdlib@v1.26.5"},
		{in: "1.26.5", want: "stdlib@v1.26.5"},
		{in: "v1.26.5", want: "stdlib@v1.26.5"},
		{in: "", wantErr: true},
		{in: "not-a-version", wantErr: true},
	} {
		got, err := cgapp.StdlibCoordinateFor(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("StdlibCoordinateFor(%q) = %s, want an error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("StdlibCoordinateFor(%q): %v", tc.in, err)
			continue
		}
		if got.String() != tc.want {
			t.Errorf("StdlibCoordinateFor(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

// storeWithoutGenerationReader is a call-graph store that offers no
// identical-generation read, which is what every store did before that
// capability existed. A run against one appends rather than losing the answer.
type storeWithoutGenerationReader struct{ ports.CallGraphStore }

// unservableStore holds records and refuses to SERVE them: the state a
// coordinate is in when no single stored generation answers it. The
// after-the-fact read still works, because the question "does the ledger
// already hold this measurement" is answerable when "which one answers" is not.
type unservableStore struct {
	*fakeCallGraphStore
	refusal error
}

func (s unservableStore) GetCallGraphRecord(
	context.Context, coordinate.ModuleCoordinate, string,
) (domain.CallGraphRecord, bool, error) {
	return domain.CallGraphRecord{}, false, s.refusal
}

// TestExtractStdlib_EmitsOneAuditEventPerPersistedGeneration: the assurance log
// anchors the graph every later answer is derived from, and only a write
// appends to it — a run served from the ledger appends nothing.
func TestExtractStdlib_EmitsOneAuditEventPerPersistedGeneration(t *testing.T) {
	store := &fakeCallGraphStore{}
	sink := &recordingSink{}
	uc := newStdlibUseCase(t, store,
		&fakeToolchainLocator{src: ports.ToolchainSource{GoRoot: "/usr/local/go", Version: "go1.26.5"}},
		&fakeStdlibAnalyser{record: analysedStdlibRecord()}, fakeCustody{}).WithAudit(sink)

	coord := coordinatetest.MustNew(coordinate.StdlibPath, "v1.26.5")
	if _, err := uc.Execute(t.Context(), cgapp.ExtractRequest{Coordinate: coord}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(sink.events) != 1 {
		t.Fatalf("appended %d events, want 1 per persisted generation", len(sink.events))
	}

	// Served from the ledger: nothing was written, so nothing is claimed.
	if _, err := uc.Execute(t.Context(), cgapp.ExtractRequest{Coordinate: coord}); err != nil {
		t.Fatalf("Execute (second): %v", err)
	}
	if len(sink.events) != 1 {
		t.Errorf("a run that wrote nothing appended %d events", len(sink.events))
	}
	if len(store.puts) != 1 {
		t.Errorf("the ledger grew to %d generations over two runs of one unchanged toolchain", len(store.puts))
	}
}

// TestExtractStdlib_AuditFaultStopsTheRun: the event is the record of the
// write, so a sink that refuses it leaves the run reporting a failure rather
// than a write nothing can see.
func TestExtractStdlib_AuditFaultStopsTheRun(t *testing.T) {
	sinkErr := errors.New("log closed")
	uc := newStdlibUseCase(t, &fakeCallGraphStore{},
		&fakeToolchainLocator{src: ports.ToolchainSource{GoRoot: "/usr/local/go", Version: "go1.26.5"}},
		&fakeStdlibAnalyser{record: analysedStdlibRecord()}, fakeCustody{}).
		WithAudit(&recordingSink{err: sinkErr})

	_, err := uc.Execute(t.Context(), cgapp.ExtractRequest{
		Coordinate: coordinatetest.MustNew(coordinate.StdlibPath, "v1.26.5"),
	})
	if !errors.Is(err, sinkErr) {
		t.Fatalf("err = %v, want the sink's own fault", err)
	}
}

// TestExtractStdlib_ServesAHeldGenerationAndForcePastIt: a released toolchain's
// source is fixed by its version, so the second run of one coordinate measures
// nothing new — unless the caller says to re-measure.
func TestExtractStdlib_ServesAHeldGenerationAndForcePastIt(t *testing.T) {
	store := &fakeCallGraphStore{}
	analyser := &fakeStdlibAnalyser{record: analysedStdlibRecord()}
	uc := newStdlibUseCase(t, store,
		&fakeToolchainLocator{src: ports.ToolchainSource{GoRoot: "/usr/local/go", Version: "go1.26.5"}},
		analyser, fakeCustody{})
	coord := coordinatetest.MustNew(coordinate.StdlibPath, "v1.26.5")

	if _, err := uc.Execute(t.Context(), cgapp.ExtractRequest{Coordinate: coord}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	res, err := uc.Execute(t.Context(), cgapp.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute (second): %v", err)
	}
	if !res.FromCache || analyser.calls != 1 {
		t.Errorf("the second run analysed again: FromCache=%v calls=%d", res.FromCache, analyser.calls)
	}

	// --force asks for a measurement regardless of what is held, and APPENDS it:
	// the same contract the fetched-module stage states, so the two paths cannot
	// drift into different ideas of what the flag means.
	forced, err := uc.Execute(t.Context(), cgapp.ExtractRequest{Coordinate: coord, Force: true})
	if err != nil {
		t.Fatalf("Execute (forced): %v", err)
	}
	if analyser.calls != 2 || forced.FromCache {
		t.Errorf("--force did not re-measure: calls=%d FromCache=%v", analyser.calls, forced.FromCache)
	}
	if len(store.puts) != 2 {
		t.Errorf("the forced measurement was not appended: %d puts", len(store.puts))
	}
}

// TestExtractStdlib_ReMeasuresWhatItCannotRead: a coordinate no single stored
// generation answers is a reason to refuse to SERVE, never a reason to refuse
// to measure.
func TestExtractStdlib_ReMeasuresWhatItCannotRead(t *testing.T) {
	for name, getErr := range map[string]error{
		"composition conflict": ports.ErrCallGraphConflict,
		"integrity failure":    ports.ErrCallGraphIntegrity,
	} {
		t.Run(name, func(t *testing.T) {
			store := &fakeCallGraphStore{}
			analyser := &fakeStdlibAnalyser{record: analysedStdlibRecord()}
			uc := newStdlibUseCase(t, unservableStore{fakeCallGraphStore: store, refusal: getErr},
				&fakeToolchainLocator{src: ports.ToolchainSource{GoRoot: "/usr/local/go", Version: "go1.26.5"}},
				analyser, fakeCustody{})

			if _, err := uc.Execute(t.Context(), cgapp.ExtractRequest{
				Coordinate: coordinatetest.MustNew(coordinate.StdlibPath, "v1.26.5"),
			}); err != nil {
				t.Fatalf("Execute: %v", err)
			}
			if analyser.calls != 1 || len(store.puts) != 1 {
				t.Errorf("an unreadable ledger stopped the measurement: calls=%d puts=%d", analyser.calls, len(store.puts))
			}
			// And a SECOND run, still unable to serve, re-measures and finds the
			// ledger already holds exactly this — so it appends nothing. That is the
			// gate a composition refusal must not be allowed to disable, or a
			// coordinate that cannot be composed grows a generation per run for ever.
			res, err := uc.Execute(t.Context(), cgapp.ExtractRequest{
				Coordinate: coordinatetest.MustNew(coordinate.StdlibPath, "v1.26.5"),
			})
			if err != nil {
				t.Fatalf("Execute (second): %v", err)
			}
			if !res.Reused || len(store.puts) != 1 {
				t.Errorf("the identical re-measurement was appended again: Reused=%v puts=%d", res.Reused, len(store.puts))
			}
		})
	}
}

// TestExtractStdlib_StoreFaultsStopTheRun: a store that cannot be read, or
// cannot be written, is infrastructure. Nothing about the standard library was
// established, so nothing is reported as if it had been.
func TestExtractStdlib_StoreFaultsStopTheRun(t *testing.T) {
	readFault := errors.New("database is locked")
	writeFault := errors.New("disk full")
	for name, store := range map[string]*fakeCallGraphStore{
		"read":  {getErr: readFault},
		"write": {putErr: writeFault},
	} {
		want := readFault
		if name == "write" {
			want = writeFault
			// A read fault that is neither a conflict nor an integrity failure must
			// stop the run; the conflict cases above are the ones that fall through.
			store.getErr = nil
		} else {
			store.getErr = fmt.Errorf("checking: %w", readFault)
		}
		t.Run(name, func(t *testing.T) {
			uc := newStdlibUseCase(t, store,
				&fakeToolchainLocator{src: ports.ToolchainSource{GoRoot: "/usr/local/go", Version: "go1.26.5"}},
				&fakeStdlibAnalyser{record: analysedStdlibRecord()}, fakeCustody{})
			_, err := uc.Execute(t.Context(), cgapp.ExtractRequest{
				Coordinate: coordinatetest.MustNew(coordinate.StdlibPath, "v1.26.5"),
			})
			if !errors.Is(err, want) {
				t.Fatalf("err = %v, want %v", err, want)
			}
		})
	}
}

// TestExtractStdlib_AnalyserFaultStopsTheRun: an analyser that could not run is
// not a standard library that could not be analysed.
func TestExtractStdlib_AnalyserFaultStopsTheRun(t *testing.T) {
	analyserErr := errors.New("toolchain vanished")
	store := &fakeCallGraphStore{}
	uc := newStdlibUseCase(t, store,
		&fakeToolchainLocator{src: ports.ToolchainSource{GoRoot: "/usr/local/go", Version: "go1.26.5"}},
		&fakeStdlibAnalyser{err: analyserErr}, fakeCustody{})

	_, err := uc.Execute(t.Context(), cgapp.ExtractRequest{
		Coordinate: coordinatetest.MustNew(coordinate.StdlibPath, "v1.26.5"),
	})
	if !errors.Is(err, analyserErr) {
		t.Fatalf("err = %v, want %v", err, analyserErr)
	}
	if len(store.puts) != 0 {
		t.Error("a record was written for an analysis that did not run")
	}
}

// TestExtractStdlib_CustodyFaultStopsTheRun, and a measurement that computed no
// digest anchors nothing: a custody row naming no bytes is not an anchor, so
// the record falls back to the toolchain's own name rather than to an empty
// identity the store would refuse.
func TestExtractStdlib_CustodyFaults(t *testing.T) {
	custodyErr := errors.New("stdlib ledger unreadable")
	uc := newStdlibUseCase(t, &fakeCallGraphStore{},
		&fakeToolchainLocator{src: ports.ToolchainSource{GoRoot: "/usr/local/go", Version: "go1.26.5"}},
		&fakeStdlibAnalyser{record: analysedStdlibRecord()}, fakeCustody{err: custodyErr})
	if _, err := uc.Execute(t.Context(), cgapp.ExtractRequest{
		Coordinate: coordinatetest.MustNew(coordinate.StdlibPath, "v1.26.5"),
	}); !errors.Is(err, custodyErr) {
		t.Fatalf("err = %v, want %v", err, custodyErr)
	}

	uc = newStdlibUseCase(t, &fakeCallGraphStore{},
		&fakeToolchainLocator{src: ports.ToolchainSource{GoRoot: "/usr/local/go", Version: "go1.26.5"}},
		&fakeStdlibAnalyser{record: analysedStdlibRecord()},
		fakeCustody{found: true, custody: ports.StdlibCustody{MeasurementHash: "sha256:seal"}})
	res, err := uc.Execute(t.Context(), cgapp.ExtractRequest{
		Coordinate: coordinatetest.MustNew(coordinate.StdlibPath, "v1.26.5"),
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.Record.ArtefactIdentity != "toolchain:go1.26.5" {
		t.Errorf("artefact identity = %q, want the toolchain's own name", res.Record.ArtefactIdentity)
	}
}

// TestExtractStdlib_AppendsWhereTheLedgerCannotBeAsked: a store that offers no
// identical-generation read, or one that faults on it, leaves the run holding a
// measurement — and appending it is always correct. The optimisation being
// unavailable must never lose the answer.
func TestExtractStdlib_AppendsWhereTheLedgerCannotBeAsked(t *testing.T) {
	plain := &fakeCallGraphStore{}
	uc := newStdlibUseCase(t, storeWithoutGenerationReader{CallGraphStore: plain},
		&fakeToolchainLocator{src: ports.ToolchainSource{GoRoot: "/usr/local/go", Version: "go1.26.5"}},
		&fakeStdlibAnalyser{record: analysedStdlibRecord()}, fakeCustody{})
	if _, err := uc.Execute(t.Context(), cgapp.ExtractRequest{
		Coordinate: coordinatetest.MustNew(coordinate.StdlibPath, "v1.26.5"),
	}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(plain.puts) != 1 {
		t.Errorf("a store with no generation read wrote %d records, want the measurement appended", len(plain.puts))
	}
}

// TestExtractStdlib_RefusesACoordinateNamingNoToolchainVersion: the version
// component of this coordinate IS a toolchain version, and one that resolves to
// none names no standard library to analyse.
func TestExtractStdlib_RefusesACoordinateNamingNoToolchainVersion(t *testing.T) {
	uc := newStdlibUseCase(t, &fakeCallGraphStore{}, &fakeToolchainLocator{}, &fakeStdlibAnalyser{}, fakeCustody{})
	_, err := uc.Execute(t.Context(), cgapp.ExtractRequest{Coordinate: coordinate.NewStdlibCoordinate()})
	if err == nil || !strings.Contains(err.Error(), "names no toolchain version") {
		t.Fatalf("err = %v, want a refusal naming the missing toolchain version", err)
	}
}

// failedStdlibRecord is a record of a run that could not analyse: an
// environment failure, which is never eligible to answer a later run.
func failedStdlibRecord(detail string) domain.CallGraphRecord {
	return domain.CallGraphRecord{
		SchemaVersion:  domain.CallGraphSchemaVersion,
		Ecosystem:      fetchdomain.EcosystemGo,
		Algorithm:      domain.AlgorithmCHA,
		Completeness:   domain.CompletenessFailed,
		AnalysisSource: domain.AnalysisSourceToolchainSource,
		AnalysisRoot:   "/usr/local/go/src",
		WorktreeDigest: "analysed-sha256:abc",
		OverallStatus:  domain.CallGraphStatusLoadFailed,
		FailureCause:   domain.FailureCauseEnvironment,
		FailureDetail:  detail,
	}
}

// seedStdlib puts a record in the ledger as a previous run left it, sealed the
// way the store would have sealed it.
func seedStdlib(t *testing.T, store *fakeCallGraphStore, rec domain.CallGraphRecord) domain.CallGraphRecord {
	t.Helper()
	rec.Coordinate = coordinatetest.MustNew(coordinate.StdlibPath, "v1.26.5")
	rec.PipelineVersion = cgapp.PipelineVersion
	rec.ArtefactIdentity = "sha256:495be4bc"
	rec.ExtractedAt = time.Unix(0, 0).UTC()
	sealed, err := domain.CallGraphRecordHasher{}.SetContentHash(rec)
	if err != nil {
		t.Fatalf("sealing the seeded record: %v", err)
	}
	if err := store.PutCallGraphRecord(t.Context(), sealed); err != nil {
		t.Fatalf("seeding: %v", err)
	}
	store.puts = nil // the seed is the ledger's history, not this run's writes
	return sealed
}

// TestExtractStdlib_AnIneligibleRecordIsReMeasuredAndNotAppendedTwice: a record
// of a run the environment cut short is never served back — that would make one
// bad run permanent — but a re-measurement that comes back saying exactly what
// it says is not a new fact either, so nothing is appended.
func TestExtractStdlib_AnIneligibleRecordIsReMeasuredAndNotAppendedTwice(t *testing.T) {
	store := &fakeCallGraphStore{}
	held := seedStdlib(t, store, failedStdlibRecord("no usable toolchain"))
	analyser := &fakeStdlibAnalyser{record: failedStdlibRecord("no usable toolchain")}
	uc := newStdlibUseCase(t, store,
		&fakeToolchainLocator{src: ports.ToolchainSource{GoRoot: "/usr/local/go", Version: "go1.26.5"}},
		analyser, fakeCustody{found: true, custody: ports.StdlibCustody{ArtefactIdentity: "sha256:495be4bc"}})

	res, err := uc.Execute(t.Context(), cgapp.ExtractRequest{
		Coordinate: coordinatetest.MustNew(coordinate.StdlibPath, "v1.26.5"),
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if analyser.calls != 1 {
		t.Fatalf("the failed record was served back instead of re-measured: calls=%d", analyser.calls)
	}
	if !res.Reused || res.Record.ContentHash != held.ContentHash {
		t.Errorf("the identical re-measurement was not recognised: Reused=%v hash=%s", res.Reused, res.Record.ContentHash)
	}
	if len(store.puts) != 0 {
		t.Errorf("a generation per run: %d appended", len(store.puts))
	}
}

// TestExtractStdlib_AReMeasurementThatDiffersIsAppended is the other side of
// it: the run found something the ledger does not say, so the ledger grows.
func TestExtractStdlib_AReMeasurementThatDiffersIsAppended(t *testing.T) {
	store := &fakeCallGraphStore{}
	seedStdlib(t, store, failedStdlibRecord("no usable toolchain"))
	uc := newStdlibUseCase(t, store,
		&fakeToolchainLocator{src: ports.ToolchainSource{GoRoot: "/usr/local/go", Version: "go1.26.5"}},
		&fakeStdlibAnalyser{record: analysedStdlibRecord()},
		fakeCustody{found: true, custody: ports.StdlibCustody{ArtefactIdentity: "sha256:495be4bc"}})

	res, err := uc.Execute(t.Context(), cgapp.ExtractRequest{
		Coordinate: coordinatetest.MustNew(coordinate.StdlibPath, "v1.26.5"),
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.Reused || len(store.puts) != 1 {
		t.Errorf("a graph the ledger did not hold was not appended: Reused=%v puts=%d", res.Reused, len(store.puts))
	}
}

// TestExtractStdlib_WithoutACustodyReader: the chain of custody is optional
// wiring, and a composition root that offers none still gets a graph.
func TestExtractStdlib_WithoutACustodyReader(t *testing.T) {
	store := &fakeCallGraphStore{}
	uc := cgapp.NewExtractStdlibCallGraphUseCase(cgapp.StdlibConfig{
		Store:    store,
		Analyser: &fakeStdlibAnalyser{record: analysedStdlibRecord()},
		Toolchains: &fakeToolchainLocator{
			src: ports.ToolchainSource{GoRoot: "/usr/local/go", Version: "go1.26.5"},
		},
		Clock: fakeClock{t: time.Unix(1, 0).UTC()}, Stopwatch: fakeStopwatch{}, Logger: stdlibTestLogger(),
	})

	res, err := uc.Execute(t.Context(), cgapp.ExtractRequest{
		Coordinate: coordinatetest.MustNew(coordinate.StdlibPath, "v1.26.5"),
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.Record.ArtefactIdentity != "toolchain:go1.26.5" {
		t.Errorf("artefact identity = %q", res.Record.ArtefactIdentity)
	}
}

// TestExtractStdlib_AppendsWhenTheHeldGenerationCannotBeRead: the run holds a
// measurement, so appending it is always correct. Refusing to record what was
// measured because an optimisation could not be checked would lose the answer.
func TestExtractStdlib_AppendsWhenTheHeldGenerationCannotBeRead(t *testing.T) {
	store := &fakeCallGraphStore{getErr: errors.New("index corrupt")}
	uc := newStdlibUseCase(t, unservableStore{fakeCallGraphStore: store, refusal: ports.ErrCallGraphConflict},
		&fakeToolchainLocator{src: ports.ToolchainSource{GoRoot: "/usr/local/go", Version: "go1.26.5"}},
		&fakeStdlibAnalyser{record: analysedStdlibRecord()}, fakeCustody{})

	if _, err := uc.Execute(t.Context(), cgapp.ExtractRequest{
		Coordinate: coordinatetest.MustNew(coordinate.StdlibPath, "v1.26.5"),
	}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(store.puts) != 1 {
		t.Errorf("the measurement was lost to an unreadable ledger: %d puts", len(store.puts))
	}
}
