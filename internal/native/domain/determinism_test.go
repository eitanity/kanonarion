package domain_test

import (
	"math/rand"
	"testing"

	"github.com/eitanity/kanonarion/internal/native/domain"
)

// determinismShuffles is how many independent input orders this guard puts
// through the canonical form. A comparator that is not a total order decides a
// tied pair by whatever the sort happened to do with the input order, so the
// guard has to supply many input orders; one or two would pass by luck.
const determinismShuffles = 50

// TestHash_IsIndependentOfInputOrder is the determinism guard for the
// native-component record's content hash.
//
// The elements deliberately tie: a header and an amalgamated source declaring
// one version, two components of one name, and two files of identical size are
// exactly the shapes an artefact produces, and a zip's entry order is not a
// property of the artefact's contents.
func TestHash_IsIndependentOfInputOrder(t *testing.T) {
	t.Parallel()

	buildComponents := func() []domain.Component {
		return []domain.Component{
			{Name: "SQLite", Version: "3.38.0", Confidence: domain.ConfidenceDeclared, Evidence: []domain.Evidence{
				{File: "sqlite3-binding.c", Declaration: `#define SQLITE_VERSION "3.38.0"`},
				{File: "sqlite3-binding.h", Declaration: `#define SQLITE_VERSION "3.38.0"`},
				{File: "sqlite3-binding.h", Declaration: `#define SQLITE_VERSION  "3.38.0"`},
			}},
			{Name: "SQLite", Version: "3.45.1", Confidence: domain.ConfidenceDeclared, Evidence: []domain.Evidence{
				{File: "vendor/sqlite3.c", Declaration: `#define SQLITE_VERSION "3.45.1"`},
			}},
		}
	}
	buildSources := func() []domain.Source {
		return []domain.Source{
			{File: "sqlite3-binding.c", Bytes: 8469484, SHA256: "aa"},
			{File: "sqlite3-binding.h", Bytes: 615366, SHA256: "bb"},
			{File: "sqlite3ext.h", Bytes: 36970, SHA256: "cc"},
			{File: "sqlite3_opt_unlock_notify.c", Bytes: 1716, SHA256: "dd"},
			// Same path and size, different bytes: only the digest separates
			// them, so a comparator keyed on the path alone leaves them tied.
			{File: "dup.c", Bytes: 10, SHA256: "ee"},
			{File: "dup.c", Bytes: 10, SHA256: "ff"},
		}
	}

	// The linked entries tie on purpose: one library named by two per-platform
	// directives in one file, and one name carried by two files, are exactly
	// what a real preamble produces.
	buildLinked := func() []domain.LinkedLibrary {
		return []domain.LinkedLibrary{
			{Name: "icui18n", Kind: domain.LinkedLibraryExternal, File: "cases/icu.go",
				Directive: "#cgo LDFLAGS: -licui18n -licuuc"},
			{Name: "icui18n", Kind: domain.LinkedLibraryExternal, File: "collate/tools/colcmp/icu.go",
				Directive: "#cgo LDFLAGS: -licui18n -licuuc"},
			{Name: "pdf_oxide", Kind: domain.LinkedLibraryExternal, File: "cgo_dev.go",
				Directive: "#cgo linux,amd64 LDFLAGS: ${SRCDIR}/../target/release/libpdf_oxide.a"},
			{Name: "pdf_oxide", Kind: domain.LinkedLibraryExternal, File: "cgo_dev.go",
				Directive: "#cgo linux,arm64 LDFLAGS: ${SRCDIR}/../target/aarch64/release/libpdf_oxide.a"},
			{Name: "dl", Kind: domain.LinkedLibrarySystem, File: "cgo_dev.go",
				Directive: "#cgo linux,amd64 LDFLAGS: -ldl"},
		}
	}

	var want string
	for i := range determinismShuffles {
		components, sources, linked := buildComponents(), buildSources(), buildLinked()
		rng := rand.New(rand.NewSource(int64(i))) /* #nosec G404 -- a determinism guard needs a REPRODUCIBLE shuffle: the seed is the test's evidence, not a secret */
		rng.Shuffle(len(components), func(a, b int) { components[a], components[b] = components[b], components[a] })
		rng.Shuffle(len(sources), func(a, b int) { sources[a], sources[b] = sources[b], sources[a] })
		rng.Shuffle(len(linked), func(a, b int) { linked[a], linked[b] = linked[b], linked[a] })
		for _, c := range components {
			rng.Shuffle(len(c.Evidence), func(a, b int) { c.Evidence[a], c.Evidence[b] = c.Evidence[b], c.Evidence[a] })
		}

		domain.SortComponents(components)
		domain.SortSources(sources)
		domain.SortLinkedLibraries(linked)
		for _, c := range components {
			domain.SortEvidence(c.Evidence)
		}
		got := domain.Hash(
			"github.com/mattn/go-sqlite3@v1.14.12", "zip:h1:abc=",
			domain.PipelineVersion, domain.RecipeCatalogueVersion,
			domain.PresenceIdentified, components, sources, linked,
		)
		if i == 0 {
			want = got
			continue
		}
		if got != want {
			t.Fatalf("shuffle %d: hash %s, shuffle 0 gave %s: the canonical order is not a function of the set alone", i, got, want)
		}
	}
}

// TestHash_SeparatesWhatItDescribes fails when a field the record carries is
// outside the seal. A record whose hash does not move when its subject does is
// a seal over the wrong thing.
func TestHash_SeparatesWhatItDescribes(t *testing.T) {
	t.Parallel()

	type input struct {
		coordinate, artefact, pipeline, catalogue string
		presence                                  domain.Presence
		version, declaration, digest              string
		linked                                    []domain.LinkedLibrary
	}
	base := input{
		coordinate: "m@v1", artefact: "zip:h1:a=", pipeline: "0.2.0", catalogue: "1",
		presence: domain.PresenceIdentified, version: "3.38.0", declaration: "d", digest: "aa",
		linked: []domain.LinkedLibrary{{
			Name: "icui18n", Kind: domain.LinkedLibraryExternal,
			File: "icu.go", Directive: "#cgo LDFLAGS: -licui18n",
		}},
	}
	hash := func(in input) string {
		return domain.Hash(in.coordinate, in.artefact, in.pipeline, in.catalogue, in.presence,
			[]domain.Component{{Name: "SQLite", Version: in.version, Confidence: domain.ConfidenceDeclared,
				Evidence: []domain.Evidence{{File: "a.c", Declaration: in.declaration}}}},
			[]domain.Source{{File: "a.c", Bytes: 1, SHA256: in.digest}},
			in.linked)
	}
	with := func(mutate func(*input)) string {
		in := base
		mutate(&in)
		return hash(in)
	}
	changed := map[string]string{
		"coordinate":    with(func(in *input) { in.coordinate = "m@v2" }),
		"artefact":      with(func(in *input) { in.artefact = "zip:h1:b=" }),
		"pipeline":      with(func(in *input) { in.pipeline = "0.1.0" }),
		"catalogue":     with(func(in *input) { in.catalogue = "2" }),
		"presence":      with(func(in *input) { in.presence = domain.PresenceUnidentified }),
		"version":       with(func(in *input) { in.version = "3.45.1" }),
		"declaration":   with(func(in *input) { in.declaration = "e" }),
		"source digest": with(func(in *input) { in.digest = "bb" }),
		"linked library name": with(func(in *input) {
			in.linked = []domain.LinkedLibrary{{Name: "icuuc", Kind: domain.LinkedLibraryExternal,
				File: "icu.go", Directive: "#cgo LDFLAGS: -licui18n"}}
		}),
		"linked library kind": with(func(in *input) {
			in.linked = []domain.LinkedLibrary{{Name: "icui18n", Kind: domain.LinkedLibrarySystem,
				File: "icu.go", Directive: "#cgo LDFLAGS: -licui18n"}}
		}),
		"linked library file": with(func(in *input) {
			in.linked = []domain.LinkedLibrary{{Name: "icui18n", Kind: domain.LinkedLibraryExternal,
				File: "other.go", Directive: "#cgo LDFLAGS: -licui18n"}}
		}),
		"linked library directive": with(func(in *input) {
			in.linked = []domain.LinkedLibrary{{Name: "icui18n", Kind: domain.LinkedLibraryExternal,
				File: "icu.go", Directive: "#cgo darwin LDFLAGS: -licui18n"}}
		}),
		"linked library dropped": with(func(in *input) { in.linked = nil }),
	}
	for what, got := range changed {
		if got == hash(base) {
			t.Errorf("changing the %s left the content hash unchanged: it is outside the seal", what)
		}
	}
}

// assertOrders checks that less decides a pair differing in exactly one field,
// in both directions, and reports an element equal to itself. Over every field
// the element carries, that is what "total order" means: no two DISTINCT
// elements compare equal, so the sort has no tie to resolve.
func assertOrders[T any](t *testing.T, key string, less func(a, b T) bool, lower, upper T) {
	t.Helper()
	if !less(lower, upper) {
		t.Errorf("%s: the comparator does not order two elements differing only in this field", key)
	}
	if less(upper, lower) {
		t.Errorf("%s: the comparator is not antisymmetric", key)
	}
	if less(lower, lower) {
		t.Errorf("%s: the comparator reports an element less than itself", key)
	}
}

func TestComparatorsAreKeyedOnEveryField(t *testing.T) {
	t.Parallel()

	assertOrders(t, "component name", domain.ComponentLess,
		domain.Component{Name: "OpenSSL"}, domain.Component{Name: "SQLite"})
	assertOrders(t, "component version", domain.ComponentLess,
		domain.Component{Name: "SQLite", Version: "3.38.0"}, domain.Component{Name: "SQLite", Version: "3.45.1"})
	assertOrders(t, "component confidence", domain.ComponentLess,
		domain.Component{Name: "SQLite"}, domain.Component{Name: "SQLite", Confidence: domain.ConfidenceDeclared})

	assertOrders(t, "evidence file", domain.EvidenceLess,
		domain.Evidence{File: "a.c"}, domain.Evidence{File: "b.c"})
	assertOrders(t, "evidence declaration", domain.EvidenceLess,
		domain.Evidence{File: "a.c", Declaration: "x"}, domain.Evidence{File: "a.c", Declaration: "y"})

	assertOrders(t, "source file", domain.SourceLess,
		domain.Source{File: "a.c"}, domain.Source{File: "b.c"})
	assertOrders(t, "source digest", domain.SourceLess,
		domain.Source{File: "a.c", SHA256: "aa"}, domain.Source{File: "a.c", SHA256: "bb"})
	assertOrders(t, "source bytes", domain.SourceLess,
		domain.Source{File: "a.c", SHA256: "aa", Bytes: 1}, domain.Source{File: "a.c", SHA256: "aa", Bytes: 2})

	assertOrders(t, "linked library name", domain.LinkedLibraryLess,
		domain.LinkedLibrary{Name: "icui18n"}, domain.LinkedLibrary{Name: "icuuc"})
	assertOrders(t, "linked library kind", domain.LinkedLibraryLess,
		domain.LinkedLibrary{Name: "m", Kind: domain.LinkedLibraryExternal},
		domain.LinkedLibrary{Name: "m", Kind: domain.LinkedLibrarySystem})
	assertOrders(t, "linked library file", domain.LinkedLibraryLess,
		domain.LinkedLibrary{Name: "m", Kind: domain.LinkedLibrarySystem, File: "a.go"},
		domain.LinkedLibrary{Name: "m", Kind: domain.LinkedLibrarySystem, File: "b.go"})
	assertOrders(t, "linked library directive", domain.LinkedLibraryLess,
		domain.LinkedLibrary{Name: "m", Kind: domain.LinkedLibrarySystem, File: "a.go", Directive: "#cgo LDFLAGS: -lm"},
		domain.LinkedLibrary{Name: "m", Kind: domain.LinkedLibrarySystem, File: "a.go", Directive: "#cgo darwin LDFLAGS: -lm"})
}
