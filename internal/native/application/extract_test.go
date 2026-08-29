package application_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	nativegosource "github.com/eitanity/kanonarion/internal/native/adapters/gosource"
	"github.com/eitanity/kanonarion/internal/native/application"
	"github.com/eitanity/kanonarion/internal/native/domain"
	"github.com/eitanity/kanonarion/internal/native/ports"
)

// cgoWrapper is the Go file that makes a directory's C sources compiled: the
// preamble names the headers and `import "C"` is the declaration the go tool
// acts on.
const cgoWrapper = `package sqlite3

/*
#include "sqlite3-binding.h"
*/
import "C"

import "database/sql/driver"

var _ driver.Driver
`

const pureGo = "package sqlite\n\nimport \"modernc.org/libc\"\n\nvar _ = libc.Xexit\n"

const sqliteAmalgamation = "#define SQLITE_VERSION        \"3.38.0\"\n#define SQLITE_VERSION_NUMBER 3038000\n"

type harness struct {
	uc     *application.ExtractNativeUseCase
	native *fakeNativeStore
	coord  coordinate.ModuleCoordinate
}

func newHarness(t *testing.T, path, version string, files map[string]string) harness {
	t.Helper()
	return newHarnessWithZip(t, path, version, func(c coordinate.ModuleCoordinate) []byte {
		return buildZip(t, c, files)
	}, nativegosource.New())
}

func newHarnessWithZip(
	t *testing.T,
	path, version string,
	zipOf func(coordinate.ModuleCoordinate) []byte,
	source ports.GoSourceReader,
) harness {
	t.Helper()
	coord, err := coordinate.NewModuleCoordinate(path, version)
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	record := fetchtest.Record(t, fetchtest.Coordinate(coord), fetchtest.Content("zip-"+path+"@"+version))
	facts := &fakeFactStore{}
	if err := facts.PutFetchRecord(context.Background(), fetchtest.Sealed(t,
		fetchtest.Coordinate(coord), fetchtest.Content("zip-"+path+"@"+version))); err != nil {
		t.Fatalf("seeding fetch record: %v", err)
	}
	blobs := &fakeBlobStore{}
	if err := blobs.Put(context.Background(), fetchtest.ZipIdentity(t, record), bytesReader(zipOf(coord))); err != nil {
		t.Fatalf("seeding blob: %v", err)
	}
	native := &fakeNativeStore{}
	uc := application.NewExtractNativeUseCase(application.Config{
		Facts: facts, Blobs: blobs, Native: native, Source: source,
		Clock: fakeClock{t: time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC)}, Stopwatch: fakeStopwatch{},
	})
	return harness{uc: uc, native: native, coord: coord}
}

func (h harness) run(t *testing.T, force bool) application.ExtractResult {
	t.Helper()
	res, err := h.uc.Execute(context.Background(), application.ExtractRequest{Coordinate: h.coord, Force: force})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	return res
}

// The positive case: a module that ships an amalgamated library and compiles it
// through cgo records the component, its version and the declaration that
// established it.
func TestExecute_RecordsAnEmbeddedLibraryFromItsDeclaration(t *testing.T) {
	h := newHarness(t, "github.com/mattn/go-sqlite3", "v1.14.12", map[string]string{
		"sqlite3.go":        cgoWrapper,
		"sqlite3-binding.c": sqliteAmalgamation,
		"sqlite3-binding.h": sqliteAmalgamation,
		"LICENSE":           "MIT",
	})
	rec := h.run(t, false).Record

	if rec.Presence != domain.PresenceIdentified {
		t.Fatalf("presence = %q, want %q", rec.Presence, domain.PresenceIdentified)
	}
	if len(rec.Components) != 1 {
		t.Fatalf("components = %+v, want one", rec.Components)
	}
	c := rec.Components[0]
	if c.Name != "SQLite" || c.Version != "3.38.0" || c.Confidence != domain.ConfidenceDeclared {
		t.Errorf("component = %+v, want SQLite 3.38.0 declared", c)
	}
	if c.Evidence[0].File != "sqlite3-binding.c" {
		t.Errorf("evidence = %+v, want the amalgamated source first", c.Evidence)
	}
	if len(rec.Sources) != 2 {
		t.Errorf("sources = %+v, want both native files", rec.Sources)
	}
	// The record pins the artefact it read, so it inherits that artefact's
	// verification status instead of asserting one of its own.
	if rec.ArtefactIdentity == "" {
		t.Error("the record names no artefact")
	}
	if rec.ContentHash == "" || rec.SchemaVersion != domain.NativeSchemaVersion || rec.Ecosystem != domain.EcosystemGo {
		t.Errorf("record envelope is incomplete: %+v", rec)
	}
	if h.native.puts != 1 {
		t.Errorf("store writes = %d, want 1", h.native.puts)
	}
}

// The negative control, and the case that decides the design: a pure-Go
// transpilation ships .c files but imports "C" nowhere and keeps them under
// testdata. Flagging it would be wrong at the root.
func TestExecute_PureGoTranspilationIsNotFlagged(t *testing.T) {
	h := newHarness(t, "modernc.org/sqlite", "v1.53.0", map[string]string{
		"sqlite.go":                 pureGo,
		"lib/sqlite_linux_amd64.go": pureGo,
		"testdata/mptest.c":         sqliteAmalgamation,
		"testdata/tcl/atrc.c":       sqliteAmalgamation,
	})
	rec := h.run(t, false).Record

	if rec.Presence != domain.PresenceAbsent {
		t.Fatalf("presence = %q, want %q: this module links no C at all", rec.Presence, domain.PresenceAbsent)
	}
	if len(rec.Sources) != 0 || len(rec.Components) != 0 {
		t.Errorf("record = %+v, want nothing recorded", rec)
	}
}

// A module can carry C it never builds. Without an `import "C"` in the same
// package directory the go tool never hands those files to a C compiler.
func TestExecute_NativeSourceWithNoCgoPackageIsAbsent(t *testing.T) {
	h := newHarness(t, "example.com/carrier", "v1.0.0", map[string]string{
		"lib.go":     pureGo,
		"vendored.c": sqliteAmalgamation,
	})
	if got := h.run(t, false).Record.Presence; got != domain.PresenceAbsent {
		t.Errorf("presence = %q, want %q", got, domain.PresenceAbsent)
	}
}

// C compiled only for a test binary is not in a consumer's build.
func TestExecute_CgoDeclaredOnlyInATestFileIsAbsent(t *testing.T) {
	h := newHarness(t, "example.com/testonly", "v1.0.0", map[string]string{
		"lib.go":      pureGo,
		"lib_test.go": cgoWrapper,
		"helper.c":    "int helper(void) { return 0; }\n",
	})
	if got := h.run(t, false).Record.Presence; got != domain.PresenceAbsent {
		t.Errorf("presence = %q, want %q", got, domain.PresenceAbsent)
	}
}

// A directory the go tool ignores outright is not part of any build, however
// much cgo it declares.
func TestExecute_IgnoredDirectoriesAreOutOfScope(t *testing.T) {
	h := newHarness(t, "example.com/samples", "v1.0.0", map[string]string{
		"lib.go":                  pureGo,
		"_example/mod/wrapper.go": cgoWrapper,
		"_example/mod/mod.c":      sqliteAmalgamation,
		"testdata/fixture/f.go":   cgoWrapper,
		"testdata/fixture/f.c":    sqliteAmalgamation,
	})
	if got := h.run(t, false).Record.Presence; got != domain.PresenceAbsent {
		t.Errorf("presence = %q, want %q", got, domain.PresenceAbsent)
	}
}

// The third value: native source is compiled in and no recipe names it. That is
// a coverage gap a reader can act on, and it carries the file evidence.
func TestExecute_UnmatchedNativeSourceIsPresentAndUnidentified(t *testing.T) {
	h := newHarness(t, "example.com/wrapper", "v1.0.0", map[string]string{
		"lib.go":          cgoWrapper,
		"helpers.c":       "int helper(void) { return 0; }\n",
		"helpers.h":       "#define HELPERS_H\nint helper(void);\n",
		"docs/readme.md":  "not source",
		"testdata/skip.c": sqliteAmalgamation,
	})
	rec := h.run(t, false).Record

	if rec.Presence != domain.PresenceUnidentified {
		t.Fatalf("presence = %q, want %q", rec.Presence, domain.PresenceUnidentified)
	}
	if len(rec.Components) != 0 {
		t.Fatalf("components = %+v, want none", rec.Components)
	}
	files := []string{}
	for _, s := range rec.Sources {
		files = append(files, s.File)
		if s.SHA256 == "" || s.Bytes == 0 {
			t.Errorf("source %+v carries no file evidence", s)
		}
	}
	want := []string{"helpers.c", "helpers.h"}
	if len(files) != len(want) {
		t.Fatalf("sources = %v, want %v", files, want)
	}
	for i := range want {
		if files[i] != want[i] {
			t.Fatalf("sources = %v, want %v", files, want)
		}
	}
}

// Native sources are collected per package directory: a cgo package does not
// make its siblings' C files compiled.
func TestExecute_ScopeIsThePackageDirectory(t *testing.T) {
	h := newHarness(t, "example.com/multi", "v1.0.0", map[string]string{
		"cgo/wrap.go":  cgoWrapper,
		"cgo/impl.c":   "int impl(void){return 0;}\n",
		"pure/lib.go":  pureGo,
		"pure/stray.c": sqliteAmalgamation,
	})
	rec := h.run(t, false).Record

	if rec.Presence != domain.PresenceUnidentified {
		t.Fatalf("presence = %q, want %q", rec.Presence, domain.PresenceUnidentified)
	}
	if len(rec.Sources) != 1 || rec.Sources[0].File != "cgo/impl.c" {
		t.Fatalf("sources = %+v, want only the cgo package's own file", rec.Sources)
	}
}

// A held record is served rather than re-measured, and --force re-measures.
func TestExecute_ServesAHeldRecordAndForceRemeasures(t *testing.T) {
	h := newHarness(t, "github.com/mattn/go-sqlite3", "v1.14.12", map[string]string{
		"sqlite3.go":        cgoWrapper,
		"sqlite3-binding.c": sqliteAmalgamation,
	})
	first := h.run(t, false)
	if first.FromCache {
		t.Fatal("the first measurement reported a cache hit")
	}
	second := h.run(t, false)
	if !second.FromCache {
		t.Error("a held record was re-measured instead of served")
	}
	if h.native.puts != 1 {
		t.Errorf("store writes = %d, want 1: serving a held record must write nothing", h.native.puts)
	}
	forced := h.run(t, true)
	if forced.FromCache {
		t.Error("--force served a held record")
	}
	if h.native.puts != 2 {
		t.Errorf("store writes = %d, want 2 after --force", h.native.puts)
	}
	if forced.Record.ContentHash != first.Record.ContentHash {
		t.Errorf("re-measuring one artefact produced a different record: %q vs %q",
			forced.Record.ContentHash, first.Record.ContentHash)
	}
}

func TestExecute_RefusesAnUnfetchedModule(t *testing.T) {
	coord, err := coordinate.NewModuleCoordinate("example.com/absent", "v1.0.0")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	uc := application.NewExtractNativeUseCase(application.Config{
		Facts: &fakeFactStore{}, Blobs: &fakeBlobStore{}, Native: &fakeNativeStore{},
		Source: nativegosource.New(),
		Clock:  fakeClock{}, Stopwatch: fakeStopwatch{},
	})
	_, err = uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if !errors.Is(err, ports.ErrModuleNotFetched) {
		t.Fatalf("Execute error = %v, want ErrModuleNotFetched", err)
	}
}

// An artefact holding nothing under the module prefix is the wrong bytes, not a
// module with no native code. Reporting "absent" for it would be a silent wrong
// answer.
func TestExecute_RefusesAnArtefactThatIsNotThisModule(t *testing.T) {
	h := newHarnessWithZip(t, "example.com/mod", "v1.0.0", func(coordinate.ModuleCoordinate) []byte {
		return buildZipWithPrefix(t, "example.com/other@v9.9.9/", map[string]string{"lib.go": pureGo})
	}, nativegosource.New())

	_, err := h.uc.Execute(context.Background(), application.ExtractRequest{Coordinate: h.coord})
	if err == nil {
		t.Fatal("Execute accepted an artefact holding no entry for this module")
	}
}

// A Go file whose imports cannot be read is an error, not an empty import set:
// silently reading it as not-cgo would drop a whole native component.
func TestExecute_RefusesWhenImportsCannotBeRead(t *testing.T) {
	sentinel := errors.New("unparseable header")
	h := newHarnessWithZip(t, "example.com/mod", "v1.0.0", func(c coordinate.ModuleCoordinate) []byte {
		return buildZip(t, c, map[string]string{"lib.go": pureGo, "impl.c": sqliteAmalgamation})
	}, failingSourceReader{err: sentinel})

	_, err := h.uc.Execute(context.Background(), application.ExtractRequest{Coordinate: h.coord})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Execute error = %v, want the parse failure to surface", err)
	}
	if h.native.puts != 0 {
		t.Error("a failed measurement was persisted")
	}
}

// A store read that fails is not a cache miss: measuring on regardless would
// write a second record for a coordinate whose held records could not be read.
func TestExecute_SurfacesAStoreReadFailure(t *testing.T) {
	sentinel := errors.New("store unreadable")
	h := newHarness(t, "example.com/mod", "v1.0.0", map[string]string{"lib.go": pureGo})
	h.native.getErr = sentinel

	_, err := h.uc.Execute(context.Background(), application.ExtractRequest{Coordinate: h.coord})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Execute error = %v, want the store failure to surface", err)
	}
}

// A cancelled context stops the walk rather than producing a partial answer
// that reads as a complete one.
func TestExecute_RefusesACancelledContext(t *testing.T) {
	h := newHarness(t, "example.com/mod", "v1.0.0", map[string]string{
		"lib.go": cgoWrapper, "impl.c": sqliteAmalgamation,
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := h.uc.Execute(ctx, application.ExtractRequest{Coordinate: h.coord})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Execute error = %v, want context.Canceled", err)
	}
}

// cgoLinker is the shape the defect is about: a package declares cgo, compiles
// no native source of its own, and links a library the host provides.
const cgoLinker = `package cases

/*
#cgo LDFLAGS: -licui18n -licuuc
#include <unicode/ucol.h>
*/
import "C"
`

// cgoRuntimeLinker is the negative control for the system list: every cgo
// binary links the C runtime, and -ldl is nothing more than that.
const cgoRuntimeLinker = `package dlopen

/*
#cgo LDFLAGS: -ldl
#include <dlfcn.h>
*/
import "C"
`

// The defect this change closes. A module that declares cgo, compiles nothing
// of its own and links an external library used to answer "absent", which is
// the word reserved for nothing being there.
func TestExecute_ExternalLinkWithNoSourcesIsLinkedNotShipped(t *testing.T) {
	h := newHarness(t, "golang.org/x/text", "v0.17.0", map[string]string{
		"cases/icu.go": cgoLinker,
		"lib.go":       pureGo,
	})
	rec := h.run(t, false).Record

	if rec.Presence != domain.PresenceLinkedNotShipped {
		t.Fatalf("presence = %q, want %q", rec.Presence, domain.PresenceLinkedNotShipped)
	}
	if len(rec.Sources) != 0 || len(rec.Components) != 0 {
		t.Errorf("record = %+v, want no shipped source: the library is linked, not carried", rec)
	}
	if len(rec.LinkedLibraries) != 2 {
		t.Fatalf("linked = %+v, want both ICU libraries", rec.LinkedLibraries)
	}
	first := rec.LinkedLibraries[0]
	if first.Name != "icui18n" || first.Kind != domain.LinkedLibraryExternal {
		t.Errorf("linked[0] = %+v, want icui18n as external", first)
	}
	if first.File != "cases/icu.go" || first.Directive != "#cgo LDFLAGS: -licui18n -licuuc" {
		t.Errorf("linked[0] = %+v, want the verbatim directive and the file it sits in", first)
	}
	// No version may be invented for a library the artefact does not carry.
	for _, l := range rec.LinkedLibraries {
		for _, c := range rec.Components {
			if c.Name == l.Name {
				t.Errorf("a version was stated for the linked library %q: %+v", l.Name, c)
			}
		}
	}
}

// The negative control for the system list. A module whose only link is the C
// runtime has not been dragged into the new value; it is still absent, and the
// runtime link is still recorded so the reader can see why.
func TestExecute_CRuntimeOnlyStaysAbsent(t *testing.T) {
	h := newHarness(t, "github.com/coreos/go-systemd/v22", "v22.7.0", map[string]string{
		"internal/dlopen/dlopen.go": cgoRuntimeLinker,
		"lib.go":                    pureGo,
	})
	rec := h.run(t, false).Record

	if rec.Presence != domain.PresenceAbsent {
		t.Fatalf("presence = %q, want %q: -ldl is the C runtime every cgo binary links",
			rec.Presence, domain.PresenceAbsent)
	}
	if len(rec.LinkedLibraries) != 1 || rec.LinkedLibraries[0].Kind != domain.LinkedLibrarySystem {
		t.Errorf("linked = %+v, want -ldl recorded as system", rec.LinkedLibraries)
	}
}

// A module with no cgo at all links nothing, and stays absent with an empty
// collection rather than an unexplained one.
func TestExecute_NoCgoLinksNothing(t *testing.T) {
	h := newHarness(t, "modernc.org/sqlite", "v1.57.0", map[string]string{
		"sqlite.go":         pureGo,
		"testdata/mptest.c": sqliteAmalgamation,
	})
	rec := h.run(t, false).Record

	if rec.Presence != domain.PresenceAbsent {
		t.Fatalf("presence = %q, want %q", rec.Presence, domain.PresenceAbsent)
	}
	if len(rec.LinkedLibraries) != 0 {
		t.Errorf("linked = %+v, want none", rec.LinkedLibraries)
	}
}

// A module that ships its own sources AND links something else states both.
// Neither answer hides the other.
func TestExecute_ShippedSourcesAndAnExternalLinkAreBothRecorded(t *testing.T) {
	h := newHarness(t, "github.com/mattn/go-sqlite3", "v1.14.12", map[string]string{
		"sqlite3.go":            cgoWrapper,
		"sqlite3-binding.c":     sqliteAmalgamation,
		"sqlite3_opt_icu.go":    "package sqlite3\n\n/*\n#cgo LDFLAGS: -licuuc -licui18n\n*/\nimport \"C\"\n",
		"sqlite3_opt_math.go":   "package sqlite3\n\n/*\n#cgo LDFLAGS: -lm\n*/\nimport \"C\"\n",
		"sqlite3_libsqlite3.go": "package sqlite3\n\n/*\n#cgo linux LDFLAGS: -lsqlite3\n*/\nimport \"C\"\n",
	})
	rec := h.run(t, false).Record

	if rec.Presence != domain.PresenceIdentified {
		t.Fatalf("presence = %q, want %q: a link must not displace what the module ships",
			rec.Presence, domain.PresenceIdentified)
	}
	if len(rec.Components) != 1 || rec.Components[0].Version != "3.38.0" {
		t.Fatalf("components = %+v, want SQLite 3.38.0", rec.Components)
	}
	got := map[string]domain.LinkedLibraryKind{}
	for _, l := range rec.LinkedLibraries {
		got[l.Name] = l.Kind
	}
	want := map[string]domain.LinkedLibraryKind{
		"icuuc":   domain.LinkedLibraryExternal,
		"icui18n": domain.LinkedLibraryExternal,
		"sqlite3": domain.LinkedLibraryExternal,
		"m":       domain.LinkedLibrarySystem,
	}
	if len(got) != len(want) {
		t.Fatalf("linked = %+v, want %v", rec.LinkedLibraries, want)
	}
	for name, kind := range want {
		if got[name] != kind {
			t.Errorf("linked %q = %q, want %q", name, got[name], kind)
		}
	}
}

// A cgo file outside any build is outside this too: a directive under testdata
// or a _-prefixed directory names nothing a consumer's binary links.
func TestExecute_DirectivesInIgnoredDirectoriesAreOutOfScope(t *testing.T) {
	h := newHarness(t, "example.com/samples", "v1.0.0", map[string]string{
		"lib.go":                  pureGo,
		"_example/mod/wrapper.go": cgoLinker,
		"testdata/fixture/f.go":   cgoLinker,
		"lib_test.go":             cgoLinker,
	})
	rec := h.run(t, false).Record

	if rec.Presence != domain.PresenceAbsent {
		t.Fatalf("presence = %q, want %q", rec.Presence, domain.PresenceAbsent)
	}
	if len(rec.LinkedLibraries) != 0 {
		t.Errorf("linked = %+v, want none", rec.LinkedLibraries)
	}
}

// A preamble that cannot be read is an error, not an empty one. Reading it as
// linking nothing is exactly the silence this change removes.
func TestExecute_RefusesWhenThePreambleCannotBeRead(t *testing.T) {
	sentinel := errors.New("unreadable preamble")
	h := newHarnessWithZip(t, "example.com/mod", "v1.0.0", func(c coordinate.ModuleCoordinate) []byte {
		return buildZip(t, c, map[string]string{"icu.go": cgoLinker})
	}, failingPreambleReader{inner: nativegosource.New(), err: sentinel})

	_, err := h.uc.Execute(context.Background(), application.ExtractRequest{Coordinate: h.coord})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Execute error = %v, want the preamble failure to surface", err)
	}
	if h.native.puts != 0 {
		t.Error("a failed measurement was persisted")
	}
}

// Every generation whose measurement differs from the current one must be a
// DIFFERENT pipeline version, or a store holding one of its rows serves a stale
// answer as a cache hit. Both of these were live: 0.1.0 predates the
// LinkedLibraries collection, and 0.2.0 read no `#cgo pkg-config` directive, so
// a 0.2.0 row for a module that links only through pkg-config says "absent".
func TestPipelineVersion_MovesWhenTheMeasurementChanges(t *testing.T) {
	for _, superseded := range []string{"0.1.0", "0.2.0"} {
		if domain.PipelineVersion == superseded {
			t.Errorf("the measurement changed since %s; the pipeline version must move so those rows are never served",
				superseded)
		}
	}
}
