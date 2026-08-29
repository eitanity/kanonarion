package domain_test

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/native/domain"
)

// sqliteAmalgamation is the shape the real declaration takes in
// github.com/mattn/go-sqlite3's sqlite3-binding.c, neighbours included: the
// macros either side are exactly what a looser match would misread.
const sqliteAmalgamation = `
/******** Begin file sqlite3.h *********/
#define SQLITE_VERSION        "3.38.0"
#define SQLITE_VERSION_NUMBER 3038000
#define SQLITE_SOURCE_ID      "2022-02-22 18:58:40 40fa792d359f84c3b9e9d6623743e1a59826274e221df1bde8f47086968a1bab"
`

func TestDetector_IdentifiesSQLiteFromItsDeclaration(t *testing.T) {
	d := domain.NewDetector()
	d.Add("sqlite3-binding.c", []byte(sqliteAmalgamation))
	components, sources, _ := d.Result()

	if len(components) != 1 {
		t.Fatalf("components = %d, want 1: %+v", len(components), components)
	}
	c := components[0]
	if c.Name != "SQLite" || c.Version != "3.38.0" {
		t.Errorf("component = %s %s, want SQLite 3.38.0", c.Name, c.Version)
	}
	if c.Confidence != domain.ConfidenceDeclared {
		t.Errorf("confidence = %q, want %q", c.Confidence, domain.ConfidenceDeclared)
	}
	if len(c.Evidence) != 1 {
		t.Fatalf("evidence = %d, want 1", len(c.Evidence))
	}
	if c.Evidence[0].File != "sqlite3-binding.c" {
		t.Errorf("evidence file = %q, want sqlite3-binding.c", c.Evidence[0].File)
	}
	// The declaration is recorded verbatim so a reader can check the claim
	// against the artefact rather than trusting the tool's paraphrase.
	if want := `#define SQLITE_VERSION        "3.38.0"`; c.Evidence[0].Declaration != want {
		t.Errorf("declaration = %q, want %q", c.Evidence[0].Declaration, want)
	}
	if len(sources) != 1 || sources[0].File != "sqlite3-binding.c" {
		t.Fatalf("sources = %+v, want the one file that was added", sources)
	}
	if sources[0].Bytes != int64(len(sqliteAmalgamation)) {
		t.Errorf("source bytes = %d, want %d", sources[0].Bytes, len(sqliteAmalgamation))
	}
	if len(sources[0].SHA256) != 64 {
		t.Errorf("source sha256 = %q, want a bare 64-character hex digest", sources[0].SHA256)
	}
	if got := domain.PresenceOf(components, sources, nil); got != domain.PresenceIdentified {
		t.Errorf("presence = %q, want %q", got, domain.PresenceIdentified)
	}
}

// One library declaring its version in both a header and an amalgamated source
// is one component carrying both pieces of evidence, not two components.
func TestDetector_OneVersionInTwoFilesIsOneComponent(t *testing.T) {
	d := domain.NewDetector()
	d.Add("sqlite3-binding.h", []byte(`#define SQLITE_VERSION "3.38.0"`))
	d.Add("sqlite3-binding.c", []byte(`#define SQLITE_VERSION "3.38.0"`))
	components, _, _ := d.Result()

	if len(components) != 1 {
		t.Fatalf("components = %d, want 1: %+v", len(components), components)
	}
	if len(components[0].Evidence) != 2 {
		t.Fatalf("evidence = %+v, want both files", components[0].Evidence)
	}
	if components[0].Evidence[0].File != "sqlite3-binding.c" {
		t.Errorf("evidence is not in canonical order: %+v", components[0].Evidence)
	}
}

// Sources that disagree are both recorded. Choosing one would report a version
// the artefact does not unambiguously declare.
func TestDetector_DisagreeingDeclarationsAreBothRecorded(t *testing.T) {
	d := domain.NewDetector()
	d.Add("vendor/sqlite3.c", []byte(`#define SQLITE_VERSION "3.38.0"`))
	d.Add("vendor/sqlite3.h", []byte(`#define SQLITE_VERSION "3.45.1"`))
	components, _, _ := d.Result()

	if len(components) != 2 {
		t.Fatalf("components = %+v, want both declared versions", components)
	}
	if components[0].Version != "3.38.0" || components[1].Version != "3.45.1" {
		t.Errorf("versions = %q, %q, want 3.38.0 then 3.45.1", components[0].Version, components[1].Version)
	}
}

// Presence with nothing a recipe names is a recordable value carrying the file
// evidence, not an omission and not an absence.
func TestDetector_UnmatchedFilesArePresentAndUnidentified(t *testing.T) {
	d := domain.NewDetector()
	d.Add("input/flb_input.h", []byte("#define FLB_INPUT_H\nint flb_input(void);\n"))
	d.Add("output/flb_output.h", []byte("#define FLB_OUTPUT_H\n"))
	components, sources, _ := d.Result()

	if len(components) != 0 {
		t.Fatalf("components = %+v, want none: no recipe names these", components)
	}
	if len(sources) != 2 {
		t.Fatalf("sources = %+v, want both files listed as evidence", sources)
	}
	if got := domain.PresenceOf(components, sources, nil); got != domain.PresenceUnidentified {
		t.Errorf("presence = %q, want %q", got, domain.PresenceUnidentified)
	}
}

func TestPresenceOf_NoSourcesIsAbsent(t *testing.T) {
	if got := domain.PresenceOf(nil, nil, nil); got != domain.PresenceAbsent {
		t.Errorf("presence = %q, want %q", got, domain.PresenceAbsent)
	}
}

// The defect this value exists for: an artefact that compiles nothing of its
// own but links a library from outside the module is not empty of native code,
// and calling it absent puts a coverage gap under the word for an absence.
func TestPresenceOf_ExternalLinkWithNoSourcesIsLinkedNotShipped(t *testing.T) {
	linked := []domain.LinkedLibrary{{
		Name: "icui18n", Kind: domain.LinkedLibraryExternal,
		Directive: "#cgo LDFLAGS: -licui18n -licuuc", File: "cases/icu.go",
	}}
	if got := domain.PresenceOf(nil, nil, linked); got != domain.PresenceLinkedNotShipped {
		t.Errorf("presence = %q, want %q", got, domain.PresenceLinkedNotShipped)
	}
}

// The negative control for the system list. Every cgo binary links the C
// runtime, so a module whose only link is -ldl has not been dragged into the
// new value.
func TestPresenceOf_SystemOnlyLinkStaysAbsent(t *testing.T) {
	linked := []domain.LinkedLibrary{{
		Name: "dl", Kind: domain.LinkedLibrarySystem,
		Directive: "#cgo LDFLAGS: -ldl", File: "internal/dlopen/dlopen.go",
	}}
	if got := domain.PresenceOf(nil, nil, linked); got != domain.PresenceAbsent {
		t.Errorf("presence = %q, want %q: the C runtime must not earn the new value", got, domain.PresenceAbsent)
	}
}

// A module that ships its own sources keeps its present_ answer, and what else
// it links is recorded beside it rather than replacing it.
func TestPresenceOf_ShippedSourcesOutrankAnExternalLink(t *testing.T) {
	sources := []domain.Source{{File: "sqlite3-binding.c", Bytes: 1, SHA256: "aa"}}
	components := []domain.Component{{Name: "SQLite", Version: "3.38.0", Confidence: domain.ConfidenceDeclared}}
	linked := []domain.LinkedLibrary{{Name: "icui18n", Kind: domain.LinkedLibraryExternal}}
	if got := domain.PresenceOf(components, sources, linked); got != domain.PresenceIdentified {
		t.Errorf("presence = %q, want %q", got, domain.PresenceIdentified)
	}
	if got := domain.PresenceOf(nil, sources, linked); got != domain.PresenceUnidentified {
		t.Errorf("presence = %q, want %q", got, domain.PresenceUnidentified)
	}
}

// The declaration forms a recipe accepts and rejects. Each rejection is a place
// a looser match would state a version the source does not declare.
func TestDetector_DeclarationForms(t *testing.T) {
	cases := []struct {
		name    string
		src     string
		version string
	}{
		{"plain", `#define SQLITE_VERSION "3.38.0"`, "3.38.0"},
		{"indented and spaced", "   #   define   SQLITE_VERSION   \"3.38.0\"", "3.38.0"},
		{"trailing block comment", `#define SQLITE_VERSION "3.38.0" /* the amalgamation */`, "3.38.0"},
		{"trailing line comment", `#define SQLITE_VERSION "3.38.0" // pinned`, "3.38.0"},
		{"carriage return", "#define SQLITE_VERSION \"3.38.0\"\r\n", "3.38.0"},

		{"numeric sibling", `#define SQLITE_VERSION_NUMBER 3038000`, ""},
		{"string sibling", `#define SQLITE_VERSION_STRING "3.38.0"`, ""},
		{"no space after define", `#defineSQLITE_VERSION "3.38.0"`, ""},
		{"not a define", `const char *SQLITE_VERSION = "3.38.0";`, ""},
		{"undef", `#undef SQLITE_VERSION`, ""},
		{"macro reference, not a literal", `#define SQLITE_VERSION SQLITE_VER`, ""},
		{"concatenation", `#define SQLITE_VERSION "3.38" ".0"`, ""},
		{"empty literal", `#define SQLITE_VERSION ""`, ""},
		{"unterminated literal", `#define SQLITE_VERSION "3.38.0`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := domain.NewDetector()
			d.Add("f.c", []byte(tc.src))
			components, _, _ := d.Result()
			if tc.version == "" {
				if len(components) != 0 {
					t.Fatalf("components = %+v, want none for %q", components, tc.src)
				}
				return
			}
			if len(components) != 1 || components[0].Version != tc.version {
				t.Fatalf("components = %+v, want version %q", components, tc.version)
			}
		})
	}
}

func TestRecipes_CatalogueIsNamed(t *testing.T) {
	recipes := domain.Recipes()
	if len(recipes) == 0 {
		t.Fatal("the catalogue is empty: nothing could ever be identified")
	}
	for _, r := range recipes {
		if r.Component == "" || r.Macro == "" {
			t.Errorf("recipe %+v names no component or no declaration", r)
		}
	}
	if domain.RecipeCatalogueVersion == "" {
		t.Error("the catalogue must be versioned: a record keyed on it re-measures when a recipe is added")
	}
	if !strings.Contains(domain.PipelineFingerprint(), domain.RecipeCatalogueVersion) {
		t.Errorf("PipelineFingerprint() = %q, must fold in the catalogue version so a new recipe re-measures",
			domain.PipelineFingerprint())
	}
}
