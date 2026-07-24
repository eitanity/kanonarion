package domain

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
)

func buildList(coords ...coordinate.ModuleCoordinate) map[coordinate.ModuleCoordinate]struct{} {
	m := make(map[coordinate.ModuleCoordinate]struct{}, len(coords))
	for _, c := range coords {
		m[c] = struct{}{}
	}
	return m
}

func TestSynthesiseGoMod_DeclaresModulePathAndGoVersion(t *testing.T) {
	got := SynthesiseGoMod(coordinate.ModuleCoordinate{Path: "github.com/boltdb/bolt", Version: "v1.3.1"}, "go1.26.5", nil, nil)
	want := "module github.com/boltdb/bolt\n\ngo 1.26.5\n"
	if got != want {
		t.Errorf("SynthesiseGoMod() = %q, want %q", got, want)
	}
}

func TestSynthesiseGoMod_AcceptsGoVersionWithOrWithoutPrefix(t *testing.T) {
	coord := coordinate.ModuleCoordinate{Path: "example.com/mod", Version: "v1.0.0"}
	withPrefix := SynthesiseGoMod(coord, "go1.26.5", nil, nil)
	without := SynthesiseGoMod(coord, "1.26.5", nil, nil)
	if withPrefix != without {
		t.Errorf("go version prefix changed the output:\n%q\nvs\n%q", withPrefix, without)
	}
}

// An unknown toolchain version must not be guessed: the go directive selects
// which files build constraints admit, so inventing one would silently change
// what is analysed.
func TestSynthesiseGoMod_OmitsGoDirectiveWhenVersionUnknown(t *testing.T) {
	got := SynthesiseGoMod(coordinate.ModuleCoordinate{Path: "example.com/mod", Version: "v1.0.0"}, "", nil, nil)
	if strings.Contains(got, "go ") {
		t.Errorf("expected no go directive when version is unknown, got:\n%s", got)
	}
	if got != "module example.com/mod\n" {
		t.Errorf("SynthesiseGoMod() = %q", got)
	}
}

func TestSynthesiseGoMod_RendersBuildListAsSortedRequires(t *testing.T) {
	got := SynthesiseGoMod(
		coordinate.ModuleCoordinate{Path: "example.com/mod", Version: "v1.0.0"},
		"go1.26.5",
		[]string{"github.com/zzz/last", "github.com/aaa/first/sub"},
		buildList(
			coordinate.ModuleCoordinate{Path: "github.com/zzz/last", Version: "v0.2.0"},
			coordinate.ModuleCoordinate{Path: "github.com/aaa/first", Version: "v1.4.0"},
		),
	)
	want := "module example.com/mod\n\ngo 1.26.5\n\nrequire (\n\tgithub.com/aaa/first v1.4.0\n\tgithub.com/zzz/last v0.2.0\n)\n"
	if got != want {
		t.Errorf("SynthesiseGoMod() =\n%s\nwant\n%s", got, want)
	}
}

// go.mod cannot express these, so a build list carrying them must not produce a
// file the toolchain rejects — which would turn a scannable module back into a
// coverage gap for a reason that has nothing to do with the module.
func TestSynthesiseGoMod_ExcludesRequiresGoModCannotExpress(t *testing.T) {
	self := coordinate.ModuleCoordinate{Path: "example.com/mod", Version: "v1.0.0"}
	imports := []string{
		"example.com/mod/inner", StdlibModulePath, "example.com/working-tree",
		"example.com/no-version", "example.com/kept",
	}
	got := SynthesiseGoMod(self, "go1.26.5", imports, buildList(
		self,
		coordinate.ModuleCoordinate{Path: StdlibModulePath, Version: "v1.26.5"},
		coordinate.ModuleCoordinate{Path: "example.com/working-tree", Version: coordinate.LocalVersion},
		coordinate.ModuleCoordinate{Path: "", Version: "v1.0.0"},
		coordinate.ModuleCoordinate{Path: "example.com/no-version", Version: ""},
		coordinate.ModuleCoordinate{Path: "example.com/kept", Version: "v0.1.0"},
	))
	if !strings.Contains(got, "example.com/kept v0.1.0") {
		t.Fatalf("expected the ordinary dependency to be required, got:\n%s", got)
	}
	for _, unwanted := range []string{
		"example.com/mod v1.0.0", StdlibModulePath, coordinate.LocalVersion,
		"example.com/no-version", "example.com/working-tree",
	} {
		if strings.Contains(got, unwanted) {
			t.Errorf("require block must not contain %q, got:\n%s", unwanted, got)
		}
	}
}

// The build list records the coordinate a replaced node stands in for alongside
// the node itself, so one path can arrive at two versions; go.mod admits one
// require per path.
func TestSynthesiseGoMod_DeduplicatesPathKeepingHighestVersion(t *testing.T) {
	got := SynthesiseGoMod(
		coordinate.ModuleCoordinate{Path: "example.com/mod", Version: "v1.0.0"},
		"go1.26.5",
		[]string{"github.com/davecgh/go-spew/spew"},
		buildList(
			coordinate.ModuleCoordinate{Path: "github.com/davecgh/go-spew", Version: "v1.1.1"},
			coordinate.ModuleCoordinate{Path: "github.com/davecgh/go-spew", Version: "v1.1.2"},
		),
	)
	if strings.Count(got, "github.com/davecgh/go-spew") != 1 {
		t.Errorf("expected exactly one require for a duplicated path, got:\n%s", got)
	}
	if !strings.Contains(got, "github.com/davecgh/go-spew v1.1.2") {
		t.Errorf("expected the highest version to win, got:\n%s", got)
	}
}

// The regression that made every synthesised scan depend on the whole graph
// resolving: requiring build-list entries the module never imports means the
// toolchain runs MVS across all of them, so an unrelated module demanding a
// version the store lacks fails a module that never referenced it.
func TestSynthesiseGoMod_RequiresOnlyImportedModules(t *testing.T) {
	got := SynthesiseGoMod(
		coordinate.ModuleCoordinate{Path: "github.com/aymerick/douceur", Version: "v0.2.0"},
		"go1.26.5",
		[]string{"github.com/gorilla/css/scanner"},
		buildList(
			coordinate.ModuleCoordinate{Path: "github.com/gorilla/css", Version: "v1.0.0"},
			coordinate.ModuleCoordinate{Path: "github.com/fsnotify/fsnotify", Version: "v1.4.9"},
		),
	)
	if !strings.Contains(got, "github.com/gorilla/css v1.0.0") {
		t.Errorf("the imported module must be required, got:\n%s", got)
	}
	if strings.Contains(got, "fsnotify") {
		t.Errorf("an unimported build-list entry must not be required, got:\n%s", got)
	}
}

// A package path is its module path plus an optional subdirectory and neither is
// recoverable from the string alone, so the longest matching module wins.
func TestSynthesiseGoMod_ResolvesImportToLongestMatchingModule(t *testing.T) {
	got := SynthesiseGoMod(
		coordinate.ModuleCoordinate{Path: "example.com/mod", Version: "v1.0.0"},
		"go1.26.5",
		[]string{"github.com/gorilla/css/scanner"},
		buildList(
			coordinate.ModuleCoordinate{Path: "github.com/gorilla", Version: "v0.1.0"},
			coordinate.ModuleCoordinate{Path: "github.com/gorilla/css", Version: "v1.0.0"},
		),
	)
	if !strings.Contains(got, "github.com/gorilla/css v1.0.0") {
		t.Errorf("expected the longest matching module, got:\n%s", got)
	}
	if strings.Contains(got, "github.com/gorilla v0.1.0") {
		t.Errorf("the shorter prefix must not win, got:\n%s", got)
	}
}

// Prefix matching must respect path element boundaries.
func TestSynthesiseGoMod_DoesNotMatchPartialPathElement(t *testing.T) {
	got := SynthesiseGoMod(
		coordinate.ModuleCoordinate{Path: "example.com/mod", Version: "v1.0.0"},
		"go1.26.5",
		[]string{"example.com/other-extra/pkg"},
		buildList(coordinate.ModuleCoordinate{Path: "example.com/other", Version: "v1.0.0"}),
	)
	if strings.Contains(got, "example.com/other") {
		t.Errorf("a partial path element must not match, got:\n%s", got)
	}
}

// An import no build-list entry provides yields no require. The package that
// imports it then fails to compile and the toolchain names it, which is the
// truthful outcome — there is no version to pin it to.
func TestSynthesiseGoMod_UnsatisfiedImportContributesNoRequire(t *testing.T) {
	got := SynthesiseGoMod(
		coordinate.ModuleCoordinate{Path: "github.com/aymerick/douceur", Version: "v0.2.0"},
		"go1.26.5",
		[]string{"github.com/PuerkitoBio/goquery"},
		buildList(coordinate.ModuleCoordinate{Path: "github.com/gorilla/css", Version: "v1.0.0"}),
	)
	if strings.Contains(got, "require") {
		t.Errorf("expected no require block when no import is satisfied, got:\n%s", got)
	}
}
