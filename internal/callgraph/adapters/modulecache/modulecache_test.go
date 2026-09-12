package modulecache_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/callgraph/adapters/modulecache"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
)

// factStore holds records keyed by coordinate, composing across pipeline
// versions the way the real store does.
type factStore struct {
	records map[string]fetchdomain.FactRecord
}

func (s *factStore) PutFetchRecord(_ context.Context, sealed fetchdomain.SealedRecord) error {
	r := sealed.Record()
	s.records[r.ModulePath+"@"+r.ModuleVersion] = r
	return nil
}

func (s *factStore) GetFetchRecord(ctx context.Context, coord coordinate.ModuleCoordinate, _ string) (fetchdomain.CompositeRecord, bool, error) {
	return s.ComposeFetchRecord(ctx, coord)
}

func (s *factStore) ComposeFetchRecord(_ context.Context, coord coordinate.ModuleCoordinate) (fetchdomain.CompositeRecord, bool, error) {
	held := make([]fetchdomain.FactRecord, 0, len(s.records))
	for _, r := range s.records {
		held = append(held, r)
	}
	//nolint:wrapcheck // test fake; the helper already names the coordinate
	return fetchtest.ComposeCoordinate(coord, held)
}

// blobStore serves blob content from memory.
type blobStore struct{ blobs map[string][]byte }

func (s *blobStore) Put(_ context.Context, identity fetchports.BlobIdentity, r io.Reader) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err //nolint:wrapcheck // test fake
	}
	s.blobs[identity.String()] = data
	return nil
}

func (s *blobStore) Get(_ context.Context, identity fetchports.BlobIdentity) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(s.blobs[identity.String()])), nil
}

func (s *blobStore) Exists(_ context.Context, identity fetchports.BlobIdentity) (bool, error) {
	_, ok := s.blobs[identity.String()]
	return ok, nil
}

// fetcher records what it was asked to acquire, and adds it to the store so a
// second look finds it — which is what makes the closure's ensure hook worth
// calling at all.
type fetcher struct {
	facts  *factStore
	blobs  *blobStore
	full   []string
	goMods []string
	// goModFor is the go.mod text a fetched coordinate is given, keyed by
	// "path@version"; absent means an empty require list.
	goModFor map[string]string
	t        *testing.T
}

func (f *fetcher) FetchModule(_ context.Context, coord coordinate.ModuleCoordinate) error {
	f.full = append(f.full, coord.String())
	store(f.t, f.facts, f.blobs, coord, f.goModFor[coord.String()], true)
	return nil
}

func (f *fetcher) FetchModuleGoMod(_ context.Context, coord coordinate.ModuleCoordinate) error {
	f.goMods = append(f.goMods, coord.String())
	store(f.t, f.facts, f.blobs, coord, f.goModFor[coord.String()], false)
	return nil
}

// store files a record for coord, with a zip when withZip, and puts the go.mod
// text in the blob store under the address the record names.
func store(t *testing.T, facts *factStore, blobs *blobStore, coord coordinate.ModuleCoordinate, goMod string, withZip bool) {
	t.Helper()
	if goMod == "" {
		goMod = "module " + coord.Path() + "\n\ngo 1.21\n"
	}
	handle := "blob:" + coord.String()
	opts := []fetchtest.Option{
		fetchtest.Module(coord.Path(), coord.Version()),
		fetchtest.PipelineVersion("0.1.0"),
		fetchtest.FetchedAt(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
	}
	if withZip {
		opts = append(opts,
			fetchtest.GoMod(handle+":mod"),
			fetchtest.Content(handle+":zip"),
			fetchtest.ModuleHash(fetchtest.H1(handle)))
	} else {
		opts = append(opts, fetchtest.GoModOnly(handle+":mod"))
	}
	rec := fetchtest.Record(t, opts...)
	facts.records[coord.String()] = rec
	blobs.blobs[fetchtest.GoModIdentity(t, rec).String()] = []byte(goMod)
	if withZip {
		blobs.blobs[fetchtest.ZipIdentity(t, rec).String()] = []byte("zip of " + coord.String())
	}
}

func coord(t *testing.T, path, version string) coordinate.ModuleCoordinate {
	t.Helper()
	c, err := coordinate.NewModuleCoordinate(path, version)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newFixture(t *testing.T) (*factStore, *blobStore, *fetcher) {
	t.Helper()
	facts := &factStore{records: map[string]fetchdomain.FactRecord{}}
	blobs := &blobStore{blobs: map[string][]byte{}}
	return facts, blobs, &fetcher{facts: facts, blobs: blobs, goModFor: map[string]string{}, t: t}
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// pruned is a go1.17+ main module requiring these coordinates: the toolchain
// reads its require block and nothing below it, which is the shape almost every
// analysed module has.
func pruned(requires ...coordinate.ModuleCoordinate) cgports.MainModule {
	return cgports.MainModule{GoVersion: "1.21", Requires: requires}
}

// prePruning is the same module declaring a version that predates module-graph
// pruning, so the toolchain loads the complete transitive requirement graph.
func prePruning(requires ...coordinate.ModuleCoordinate) cgports.MainModule {
	return cgports.MainModule{GoVersion: "1.16", Requires: requires}
}

func entry(dir, path, version, ext string) string {
	return filepath.Join(dir, "cache", "download", filepath.FromSlash(path), "@v", version+ext)
}

// TestMaterialise_PrunedMainModuleWritesItsRequirementSource is the common
// shape: a main module on go1.17 or later reads its own require block and
// nothing below it, so the source of those requirements is the whole of what the
// load needs and a deeper version is populated for nobody.
func TestMaterialise_PrunedMainModuleWritesItsRequirementSource(t *testing.T) {
	facts, blobs, f := newFixture(t)
	dep := coord(t, "example.com/dep", "v1.2.3")
	deeper := coord(t, "example.com/deeper", "v0.4.0")
	store(t, facts, blobs, dep, "module example.com/dep\n\ngo 1.21\n\nrequire example.com/deeper v0.4.0\n", true)
	store(t, facts, blobs, deeper, "", false)

	dir := t.TempDir()
	report := modulecache.New(facts, blobs, discardLogger()).WithFetcher(f).
		Materialise(context.Background(), dir, pruned(dep))

	if !report.Complete() {
		t.Fatalf("materialise reported %d/%d written: %s", report.Written, report.Requested, report.Failures)
	}
	for _, ext := range []string{".zip", ".mod", ".info", ".lock"} {
		if _, err := os.Stat(entry(dir, "example.com/dep", "v1.2.3", ext)); err != nil {
			t.Errorf("a requirement the build compiles is missing its %s: %v", ext, err)
		}
	}
	if _, err := os.Stat(entry(dir, "example.com/deeper", "v0.4.0", ".mod")); err == nil {
		t.Error("a version below a pruned graph was populated; no toolchain reads it, " +
			"and expanding there is what reached thousands of versions on a 38-module require block")
	}
}

// TestMaterialise_PrePruningMainModuleWritesItsBuildList is the other half of
// the rule. Before go1.17 the complete module graph is loaded and the require
// block states DIRECT requirements only, so the source the build compiles is
// what minimal version selection picks out of that graph — and the versions MVS
// supersedes on the way there need their go.mod and nothing more.
func TestMaterialise_PrePruningMainModuleWritesItsBuildList(t *testing.T) {
	facts, blobs, f := newFixture(t)
	dep := coord(t, "example.com/dep", "v1.2.3")
	other := coord(t, "example.com/other", "v2.0.0")
	oldDeeper := coord(t, "example.com/deeper", "v0.4.0")
	newDeeper := coord(t, "example.com/deeper", "v0.5.0")
	store(t, facts, blobs, dep, "module example.com/dep\n\ngo 1.21\n\nrequire example.com/deeper v0.4.0\n", true)
	store(t, facts, blobs, other, "module example.com/other\n\ngo 1.21\n\nrequire example.com/deeper v0.5.0\n", true)
	store(t, facts, blobs, oldDeeper, "", false)
	store(t, facts, blobs, newDeeper, "", true)

	dir := t.TempDir()
	report := modulecache.New(facts, blobs, discardLogger()).WithFetcher(f).
		Materialise(context.Background(), dir, prePruning(dep, other))

	if !report.Complete() {
		t.Fatalf("materialise reported %d/%d written: %s", report.Written, report.Requested, report.Failures)
	}
	// The selected version is compiled, so it needs its source.
	if _, err := os.Stat(entry(dir, "example.com/deeper", "v0.5.0", ".zip")); err != nil {
		t.Errorf("the version minimal version selection picks was not given its source: %v", err)
	}
	// The superseded one is read for version arithmetic and never compiled.
	if _, err := os.Stat(entry(dir, "example.com/deeper", "v0.4.0", ".mod")); err != nil {
		t.Errorf("a superseded version is missing the go.mod MVS reads: %v", err)
	}
	if _, err := os.Stat(entry(dir, "example.com/deeper", "v0.4.0", ".zip")); err == nil {
		t.Error("a superseded version was given a zip; nothing compiles it")
	}
}

// TestMaterialise_PrePruningRequirementIsExpanded: pruning stops at a
// requirement that predates it, and the toolchain then reads that requirement's
// full subgraph even though the main module's own is pruned.
func TestMaterialise_PrePruningRequirementIsExpanded(t *testing.T) {
	facts, blobs, f := newFixture(t)
	old := coord(t, "example.com/old", "v1.2.3")
	deeper := coord(t, "example.com/deeper", "v0.4.0")
	store(t, facts, blobs, old, "module example.com/old\n\ngo 1.16\n\nrequire example.com/deeper v0.4.0\n", true)
	store(t, facts, blobs, deeper, "", false)

	dir := t.TempDir()
	if report := modulecache.New(facts, blobs, discardLogger()).WithFetcher(f).
		Materialise(context.Background(), dir, pruned(old)); !report.Complete() {
		t.Fatalf("materialise reported %d/%d written: %s", report.Written, report.Requested, report.Failures)
	}
	if _, err := os.Stat(entry(dir, "example.com/deeper", "v0.4.0", ".mod")); err != nil {
		t.Errorf("the subgraph beneath a pre-pruning requirement was not populated: %v", err)
	}
}

// TestMaterialise_FetchesWhatTheStoreLacks is the case the whole path exists
// for: a walk fetches what the CONSUMER's build resolved, so a module's own
// requirement can be in the store at no version at all.
func TestMaterialise_FetchesWhatTheStoreLacks(t *testing.T) {
	facts, blobs, f := newFixture(t)
	dep := coord(t, "example.com/dep", "v1.2.3")
	f.goModFor[dep.String()] = "module example.com/dep\n\ngo 1.16\n\nrequire example.com/deeper v0.4.0\n"

	dir := t.TempDir()
	report := modulecache.New(facts, blobs, discardLogger()).WithFetcher(f).
		Materialise(context.Background(), dir, pruned(dep))

	if !report.Complete() {
		t.Fatalf("materialise reported %d/%d written: %s", report.Written, report.Requested, report.Failures)
	}
	if len(f.full) != 1 || f.full[0] != dep.String() {
		t.Errorf("full fetches = %v, want exactly the requirement whose source the build compiles", f.full)
	}
	if len(f.goMods) != 1 || f.goMods[0] != "example.com/deeper@v0.4.0" {
		t.Errorf("go.mod-only fetches = %v, want the version reached through the requirement's own file", f.goMods)
	}
}

// TestMaterialise_GoModOnlyRecordIsRefetchedForSource: a record written by a
// module-graph population carries requirement lines, not source, and a build
// cannot be type-checked from those.
func TestMaterialise_GoModOnlyRecordIsRefetchedForSource(t *testing.T) {
	facts, blobs, f := newFixture(t)
	dep := coord(t, "example.com/dep", "v1.2.3")
	store(t, facts, blobs, dep, "", false)

	report := modulecache.New(facts, blobs, discardLogger()).WithFetcher(f).
		Materialise(context.Background(), t.TempDir(), pruned(dep))

	if len(f.full) != 1 || f.full[0] != dep.String() {
		t.Errorf("full fetches = %v, want the go.mod-only requirement re-fetched for its source", f.full)
	}
	if !report.Complete() {
		t.Errorf("materialise reported %d/%d written: %s", report.Written, report.Requested, report.Failures)
	}
}

// TestMaterialise_HoleIsNamed: under GOPROXY=off a coordinate that cannot be
// obtained is the difference between a module that resolves and one that does
// not, so the report states written against requested and names the failure
// rather than leaving it to surface later as an unexplained load error.
func TestMaterialise_HoleIsNamed(t *testing.T) {
	facts, blobs, _ := newFixture(t)
	dep := coord(t, "example.com/dep", "v1.2.3")

	report := modulecache.New(facts, blobs, discardLogger()).
		Materialise(context.Background(), t.TempDir(), pruned(dep))

	if report.Complete() {
		t.Fatal("a requirement the store cannot supply was reported as a complete population")
	}
	if report.Written != 0 || report.Requested == 0 {
		t.Errorf("written/requested = %d/%d, want nothing written against something requested", report.Written, report.Requested)
	}
	if !strings.Contains(report.Failures, "example.com/dep@v1.2.3") {
		t.Errorf("failures = %q, want the coordinate named", report.Failures)
	}
	if !strings.Contains(report.Failures, "source") {
		t.Errorf("failures = %q, want the leg that failed named", report.Failures)
	}
}

// TestMaterialise_WithoutAFetcherStaysWithinTheStore: a materialiser with no
// fetcher populates what the store holds and reports the rest, rather than
// silently reaching for a network nothing wired.
func TestMaterialise_WithoutAFetcherStaysWithinTheStore(t *testing.T) {
	facts, blobs, _ := newFixture(t)
	held := coord(t, "example.com/dep", "v1.2.3")
	absent := coord(t, "example.com/absent", "v9.9.9")
	store(t, facts, blobs, held, "", true)

	dir := t.TempDir()
	report := modulecache.New(facts, blobs, discardLogger()).
		Materialise(context.Background(), dir, pruned(held, absent))

	if _, err := os.Stat(entry(dir, "example.com/dep", "v1.2.3", ".zip")); err != nil {
		t.Errorf("the requirement the store holds was not written: %v", err)
	}
	if !strings.Contains(report.Failures, "example.com/absent@v9.9.9") {
		t.Errorf("failures = %q, want the coordinate the store does not hold named", report.Failures)
	}
}

// TestMaterialise_NoRequirementsIsNoWork: a module resolving from the standard
// library alone has no closure, and the empty report is the truthful one.
func TestMaterialise_NoRequirementsIsNoWork(t *testing.T) {
	facts, blobs, f := newFixture(t)

	report := modulecache.New(facts, blobs, discardLogger()).WithFetcher(f).
		Materialise(context.Background(), t.TempDir(), cgports.MainModule{GoVersion: "1.21"})

	if !report.Complete() || report.Requested != 0 || report.Written != 0 {
		t.Errorf("report = %+v, want an empty complete population", report)
	}
	if len(f.full)+len(f.goMods) != 0 {
		t.Errorf("a module requiring nothing caused %d fetches", len(f.full)+len(f.goMods))
	}
}
