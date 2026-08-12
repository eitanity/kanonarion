package cli

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	"golang.org/x/mod/sumdb/dirhash"
)

// useBlobs is a blob store that hands back the bytes it was seeded with, so a
// copy can actually succeed and the tally has a non-zero control to measure the
// failure counts against.
type useBlobs struct {
	mu    sync.Mutex
	blobs map[string][]byte
}

func newUseBlobs() *useBlobs { return &useBlobs{blobs: map[string][]byte{}} }

func (b *useBlobs) put(identity fetchports.BlobIdentity, data []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.blobs[identity.String()] = data
}

func (b *useBlobs) Put(_ context.Context, identity fetchports.BlobIdentity, r io.Reader) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err //nolint:wrapcheck // test fake
	}
	b.put(identity, data)
	return nil
}

func (b *useBlobs) Get(_ context.Context, identity fetchports.BlobIdentity) (io.ReadCloser, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	data, ok := b.blobs[identity.String()]
	if !ok {
		return nil, fmt.Errorf("blob not found: %s", identity)
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (b *useBlobs) GetPath(_ context.Context, identity fetchports.BlobIdentity) (string, error) {
	return "", fmt.Errorf("no path for %s", identity)
}

func (b *useBlobs) Exists(_ context.Context, identity fetchports.BlobIdentity) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.blobs[identity.String()]
	return ok, nil
}

// seedCopyableModule files a fact record and the matching zip blob for coord, so
// copyToModCache finds a record, finds the bytes, and the h1 it recomputes over
// them matches the one recorded.
func seedCopyableModule(t *testing.T, facts *pvFakeFacts, blobs *useBlobs, coord coordinate.ModuleCoordinate) {
	t.Helper()

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(coord.Path() + "@" + coord.Version() + "/doc.go")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("package doc\n")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	zipPath := filepath.Join(t.TempDir(), "module.zip")
	if err := os.WriteFile(zipPath, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	h1, err := dirhash.HashZip(zipPath, dirhash.Hash1)
	if err != nil {
		t.Fatal(err)
	}

	rec := fetchtest.Record(t,
		fetchtest.Coordinate(coord),
		fetchtest.ModuleHash(fetchtest.H1(strings.TrimPrefix(h1, "h1:"))),
	)
	if err := facts.PutFetchRecord(context.Background(), fetchtest.Sealed(t,
		fetchtest.Coordinate(coord),
		fetchtest.ModuleHash(fetchtest.H1(strings.TrimPrefix(h1, "h1:"))),
	)); err != nil {
		t.Fatal(err)
	}
	blobs.put(fetchtest.ZipIdentity(t, rec), buf.Bytes())
}

func runCopySelection(t *testing.T, selection []useCandidate, facts *pvFakeFacts, blobs *useBlobs) (useTally, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tally := copySelection(context.Background(), selection, facts, blobs, t.TempDir(), logger, &stdout, &stderr)
	writeUseSummary(tally, &stderr)
	return tally, stdout.String(), stderr.String()
}

// A project walk always selects its own local root and the standard library.
// Neither has a module zip anywhere in the store and neither ever will, so the
// lookup for them can only miss. Reporting that miss as a copy failure told the
// reader two modules were lost from a cache that was complete, and left a
// genuine loss looking exactly the same.
func TestCopySelection_ACoordinateWithNoArtefactIsNotACopyFailure(t *testing.T) {
	facts := newPVFakeFacts()
	blobs := newUseBlobs()
	good := coordinatetest.MustNew("example.com/dep", "v1.0.0")
	seedCopyableModule(t, facts, blobs, good)

	selection := []useCandidate{
		{coord: coordinatetest.MustNew("example.com/project", coordinate.LocalVersion), source: walkdomain.ResolutionLocalMainModule},
		{coord: good, source: walkdomain.ResolutionMVS},
		{coord: coordinatetest.MustNew(coordinate.StdlibPath, "v1.26.5"), source: walkdomain.ResolutionStdlib},
	}

	tally, stdout, stderr := runCopySelection(t, selection, facts, blobs)

	if len(tally.failed) != 0 {
		t.Fatalf("a coordinate with no artefact must not be a failure, got %d: %v", len(tally.failed), tally.failed)
	}
	if len(tally.noArtefact) != 2 || len(tally.copied) != 1 {
		t.Fatalf("want 1 copied and 2 with no artefact, got %d copied / %d absent", len(tally.copied), len(tally.noArtefact))
	}
	if err := useCopyExit(tally); err != nil {
		t.Fatalf("nothing failed, so the run must exit 0; got %v", err)
	}
	if strings.Contains(stderr, "did not reach the cache") {
		t.Fatalf("an expected absence must not be reported as a loss:\n%s", stderr)
	}
	if want := "copied 1 of 1 modules with a stored artefact"; !strings.Contains(stderr, want) {
		t.Fatalf("summary must state copied-of-copyable %q, got:\n%s", want, stderr)
	}
	if want := "2 of 3 selected have no artefact to copy (1 local main module, 1 Go standard library)"; !strings.Contains(stderr, want) {
		t.Fatalf("summary must name what had nothing to copy %q, got:\n%s", want, stderr)
	}
	if lines := strings.Count(stdout, "\n"); lines != 1 {
		t.Fatalf("stdout carries only the modules that landed; want 1 line, got %d:\n%s", lines, stdout)
	}
}

// A module that owns an artefact and does not reach the cache is the case the
// exit code exists for: the caller compiles against the cache next.
func TestCopySelection_AGenuineFailureIsCountedAndExitsPartial(t *testing.T) {
	facts := newPVFakeFacts()
	blobs := newUseBlobs()
	good := coordinatetest.MustNew("example.com/dep", "v1.0.0")
	seedCopyableModule(t, facts, blobs, good)
	lost := coordinatetest.MustNew("example.com/lost", "v2.0.0")

	selection := []useCandidate{
		{coord: good, source: walkdomain.ResolutionMVS},
		{coord: lost, source: walkdomain.ResolutionMVS},
	}

	tally, _, stderr := runCopySelection(t, selection, facts, blobs)

	if len(tally.failed) != 1 || len(tally.copied) != 1 {
		t.Fatalf("want 1 copied and 1 failed, got %d/%d", len(tally.copied), len(tally.failed))
	}
	err := useCopyExit(tally)
	code, ok := ExitCodeFromError(err)
	if !ok || code != ExitPartial {
		t.Fatalf("a partial cache must exit %d, got %v (%v)", ExitPartial, code, err)
	}
	if want := "1 of 2 modules with a stored artefact did not reach the cache"; err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("the exit must state how many were lost %q, got %v", want, err)
	}
	if !strings.Contains(stderr, "example.com/lost@v2.0.0 did not reach the cache") {
		t.Fatalf("the lost module must be named on stderr, not only in the log stream:\n%s", stderr)
	}
	if want := "copied 1 of 2 modules with a stored artefact"; !strings.Contains(stderr, want) {
		t.Fatalf("summary must state copied-of-copyable %q, got:\n%s", want, stderr)
	}
}

// Nothing landing at all is a different answer from some of it landing, and the
// exit code says so, following the coverage band vuln-scan already uses.
func TestCopySelection_NothingCopiedExitsFailed(t *testing.T) {
	facts := newPVFakeFacts()
	blobs := newUseBlobs()
	selection := []useCandidate{
		{coord: coordinatetest.MustNew("example.com/lost", "v2.0.0"), source: walkdomain.ResolutionMVS},
	}

	tally, _, _ := runCopySelection(t, selection, facts, blobs)
	code, ok := ExitCodeFromError(useCopyExit(tally))
	if !ok || code != ExitFailed {
		t.Fatalf("a cache that received nothing must exit %d, got %v", ExitFailed, code)
	}
}

// A selection with nothing to copy established no incompleteness — there was
// nothing owed — so it exits 0 rather than reporting a loss it did not have.
func TestCopySelection_NothingToCopyExitsZero(t *testing.T) {
	facts := newPVFakeFacts()
	blobs := newUseBlobs()
	selection := []useCandidate{
		{coord: coordinatetest.MustNew("example.com/project", coordinate.LocalVersion), source: walkdomain.ResolutionLocalMainModule},
	}

	tally, _, stderr := runCopySelection(t, selection, facts, blobs)
	if err := useCopyExit(tally); err != nil {
		t.Fatalf("nothing was owed, so the run must exit 0; got %v", err)
	}
	if want := "copied 0 of 0 modules with a stored artefact"; !strings.Contains(stderr, want) {
		t.Fatalf("want %q, got:\n%s", want, stderr)
	}
}

// The resolution source is only knowable from the walk, so the selection has to
// carry it — for the non-recursive form too, where the coordinate comes from the
// command line and a local root looks like any other argument.
func TestUseSelection_CarriesTheWalkNodesResolutionSource(t *testing.T) {
	root := coordinatetest.MustNew("example.com/project", coordinate.LocalVersion)
	dep := coordinatetest.MustNew("example.com/dep", "v1.0.0")
	walk := walkdomain.WalkRecord{Graph: walkdomain.Graph{Nodes: []walkdomain.GraphNode{
		{Coordinate: root, ResolutionSource: walkdomain.ResolutionLocalMainModule},
		{Coordinate: dep, ResolutionSource: walkdomain.ResolutionMVS},
	}}}

	recursive := useSelection(walk, root, true)
	if len(recursive) != 2 {
		t.Fatalf("recursive selects every node, got %d", len(recursive))
	}
	if recursive[0].source != walkdomain.ResolutionLocalMainModule {
		t.Fatalf("the root must carry its own source, got %q", recursive[0].source)
	}

	single := useSelection(walk, root, false)
	if len(single) != 1 || single[0].source != walkdomain.ResolutionLocalMainModule {
		t.Fatalf("the named target must carry the source the walk recorded, got %+v", single)
	}

	absent := coordinatetest.MustNew("example.com/elsewhere", "v3.0.0")
	fallback := useSelection(walk, absent, false)
	if len(fallback) != 1 || fallback[0].source != walkdomain.ResolutionTarget {
		t.Fatalf("a target the graph does not name falls back to a source that owes an artefact, got %+v", fallback)
	}
}

// The predicate is the class test, so it is pinned directly: an unrecognised
// source answers "owes an artefact" so a genuine miss is reported, never hidden.
func TestHasFetchedArtefact_OnlyTheThreeUnfetchedSourcesAreExempt(t *testing.T) {
	for _, s := range []walkdomain.ResolutionSource{
		walkdomain.ResolutionLocalMainModule,
		walkdomain.ResolutionLocalReplace,
		walkdomain.ResolutionStdlib,
	} {
		if s.HasFetchedArtefact() {
			t.Errorf("%q never has a fetched artefact", s)
		}
		if s.ArtefactAbsenceNoun() == "" {
			t.Errorf("%q must name what it is for the summary", s)
		}
	}
	for _, s := range []walkdomain.ResolutionSource{
		walkdomain.ResolutionTarget,
		walkdomain.ResolutionMVS,
		walkdomain.ResolutionReplace,
		walkdomain.ResolutionLocalAnalysed,
		walkdomain.ResolutionFetchFailed,
		walkdomain.ResolutionParseFailed,
		walkdomain.ResolutionSource("a source this build has never heard of"),
	} {
		if !s.HasFetchedArtefact() {
			t.Errorf("%q owes an artefact, so a miss for it is a failure", s)
		}
	}
}
