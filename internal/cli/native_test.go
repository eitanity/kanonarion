package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	nativedomain "github.com/eitanity/kanonarion/internal/native/domain"
)

func nativeCoord(t *testing.T, path, version string) coordinate.ModuleCoordinate {
	t.Helper()
	c, err := coordinate.NewModuleCoordinate(path, version)
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	return c
}

func nativeRec(t *testing.T, presence nativedomain.Presence, components []nativedomain.Component, sources []nativedomain.Source) nativedomain.Record {
	t.Helper()
	return nativeRecWithLinks(t, presence, components, sources, nil)
}

func nativeRecWithLinks(
	t *testing.T,
	presence nativedomain.Presence,
	components []nativedomain.Component,
	sources []nativedomain.Source,
	linked []nativedomain.LinkedLibrary,
) nativedomain.Record {
	t.Helper()
	return nativedomain.Record{
		SchemaVersion:          nativedomain.NativeSchemaVersion,
		Ecosystem:              nativedomain.EcosystemGo,
		Coordinate:             nativeCoord(t, "github.com/mattn/go-sqlite3", "v1.14.12"),
		ArtefactIdentity:       "zip:h1:abc=",
		PipelineVersion:        nativedomain.PipelineVersion,
		RecipeCatalogueVersion: nativedomain.RecipeCatalogueVersion,
		Presence:               presence,
		Components:             components,
		Sources:                sources,
		LinkedLibraries:        linked,
		ExtractedAt:            time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC),
		ContentHash:            "sha256:deadbeef",
	}
}

func identifiedRecord(t *testing.T) nativedomain.Record {
	t.Helper()
	return nativeRec(t, nativedomain.PresenceIdentified,
		[]nativedomain.Component{{
			Name: "SQLite", Version: "3.38.0", Confidence: nativedomain.ConfidenceDeclared,
			Evidence: []nativedomain.Evidence{
				{File: "sqlite3-binding.c", Declaration: `#define SQLITE_VERSION "3.38.0"`},
				{File: "sqlite3-binding.h", Declaration: `#define SQLITE_VERSION "3.38.0"`},
			},
		}},
		[]nativedomain.Source{
			{File: "sqlite3-binding.c", Bytes: 8469484, SHA256: "aa"},
			{File: "sqlite3-binding.h", Bytes: 615366, SHA256: "bb"},
		})
}

func TestPrintNativeTable_NamesTheComponentAndItsEvidence(t *testing.T) {
	var buf bytes.Buffer
	if err := printNativeTable(&buf, toNativeSection(identifiedRecord(t), false)); err != nil {
		t.Fatalf("printNativeTable: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"github.com/mattn/go-sqlite3@v1.14.12",
		"zip:h1:abc=",
		"present_identified",
		"SQLite",
		"3.38.0",
		"declared",
		`sqlite3-binding.c: #define SQLITE_VERSION "3.38.0"`,
		"Native sources compiled into the binary (2)",
		"8469484",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not contain %q:\n%s", want, out)
		}
	}
}

// The unidentified case must never read as an absence: the files are listed and
// the statement says a recipe is missing, not that nothing is there.
func TestPrintNativeTable_UnidentifiedShowsItsFileEvidence(t *testing.T) {
	rec := nativeRec(t, nativedomain.PresenceUnidentified, nil,
		[]nativedomain.Source{{File: "helpers.c", Bytes: 12, SHA256: "cc"}})

	var buf bytes.Buffer
	if err := printNativeTable(&buf, toNativeSection(rec, false)); err != nil {
		t.Fatalf("printNativeTable: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"present_unidentified",
		"no recipe names the library they belong to",
		"helpers.c",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not contain %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Components") {
		t.Errorf("an unidentified record rendered a components table:\n%s", out)
	}
}

func TestPrintNativeTable_AbsenceIsStated(t *testing.T) {
	var buf bytes.Buffer
	if err := printNativeTable(&buf, toNativeSection(nativeRec(t, nativedomain.PresenceAbsent, nil, nil), true)); err != nil {
		t.Fatalf("printNativeTable: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "no native source is compiled into a binary") {
		t.Errorf("absence is not stated:\n%s", out)
	}
}

// The four presence values render as four distinct statements, so no consumer
// of the text surface can collapse a coverage gap into an absence.
func TestNativeStatement_DistinguishesEveryPresence(t *testing.T) {
	seen := map[string]nativedomain.Presence{}
	for _, p := range []nativedomain.Presence{
		nativedomain.PresenceAbsent, nativedomain.PresenceLinkedNotShipped,
		nativedomain.PresenceIdentified, nativedomain.PresenceUnidentified,
	} {
		statement := nativeStatement(nativeRec(t, p, nil, nil))
		if statement == "" {
			t.Fatalf("presence %q has no statement", p)
		}
		if other, dup := seen[statement]; dup {
			t.Errorf("presence %q and %q render the same statement %q", p, other, statement)
		}
		seen[statement] = p
	}
	// An unrecognised value must say so rather than borrow another rung's words.
	if got := nativeStatement(nativeRec(t, "invented", nil, nil)); !strings.Contains(got, "invented") {
		t.Errorf("an unrecognised presence rendered as %q", got)
	}
}

func TestToNativeSection_EmitsArraysNotNull(t *testing.T) {
	raw, err := json.Marshal(toNativeSection(nativeRec(t, nativedomain.PresenceAbsent, nil, nil), false))
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	out := string(raw)
	for _, want := range []string{`"components":[]`, `"sources":[]`, `"linked_libraries":[]`} {
		if !strings.Contains(out, want) {
			t.Errorf("JSON does not contain %q: %s", want, out)
		}
	}
}

func TestToNativeSection_CarriesTheRecordEnvelope(t *testing.T) {
	s := toNativeSection(identifiedRecord(t), true)
	if s.SchemaVersion != nativedomain.NativeSchemaVersion || s.Ecosystem != nativedomain.EcosystemGo {
		t.Errorf("section envelope = %+v", s)
	}
	if s.PipelineVersion != nativedomain.PipelineVersion || s.RecipeCatalogueVersion != nativedomain.RecipeCatalogueVersion {
		t.Errorf("the generation is not stated: %+v", s)
	}
	if !s.FromCache {
		t.Error("a served record must say it was served")
	}
	if s.ContentHash != "sha256:deadbeef" || s.ExtractedAt != "2026-08-25T00:00:00Z" {
		t.Errorf("seal and timestamp = %q, %q", s.ContentHash, s.ExtractedAt)
	}
	if len(s.Components) != 1 || len(s.Components[0].Evidence) != 2 {
		t.Fatalf("components = %+v", s.Components)
	}
}

// linkedNotShippedRecord is the answer the new value exists for: nothing native
// is in these bytes, and something native still reaches the binary.
func linkedNotShippedRecord(t *testing.T) nativedomain.Record {
	t.Helper()
	return nativeRecWithLinks(t, nativedomain.PresenceLinkedNotShipped, nil, nil,
		[]nativedomain.LinkedLibrary{
			{Name: "icui18n", Kind: nativedomain.LinkedLibraryExternal,
				Directive: "#cgo LDFLAGS: -licui18n -licuuc", File: "cases/icu.go"},
			{Name: "icuuc", Kind: nativedomain.LinkedLibraryExternal,
				Directive: "#cgo LDFLAGS: -licui18n -licuuc", File: "cases/icu.go"},
		})
}

// The statement must say what happened without implying the library was
// measured: it names how many are linked, and says no version could be read.
func TestPrintNativeTable_LinkedNotShippedNamesWhatIsLinked(t *testing.T) {
	var buf bytes.Buffer
	if err := printNativeTable(&buf, toNativeSection(linkedNotShippedRecord(t), false)); err != nil {
		t.Fatalf("printNativeTable: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"linked_not_shipped",
		"2 external native libraries it links but does not ship",
		"no version could be read",
		"Linked libraries named by cgo directives (2)",
		"icui18n",
		"external",
		"cases/icu.go",
		"#cgo LDFLAGS: -licui18n -licuuc",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not contain %q:\n%s", want, out)
		}
	}
	// It must not read as an absence, and it must state no version.
	if strings.Contains(out, "no native source is compiled into a binary from this module's own artefact") {
		t.Errorf("the linked case rendered the absence statement:\n%s", out)
	}
	if strings.Contains(out, "Components") {
		t.Errorf("a version was rendered for a library that was never read:\n%s", out)
	}
}

// One library named by five per-platform directives is one library. Counting
// directives would overstate what is linked.
func TestNativeStatement_CountsDistinctExternalLibraries(t *testing.T) {
	rec := nativeRecWithLinks(t, nativedomain.PresenceLinkedNotShipped, nil, nil,
		[]nativedomain.LinkedLibrary{
			{Name: "pdf_oxide", Kind: nativedomain.LinkedLibraryExternal,
				Directive: "#cgo linux,amd64 LDFLAGS: libpdf_oxide.a", File: "cgo_dev.go"},
			{Name: "pdf_oxide", Kind: nativedomain.LinkedLibraryExternal,
				Directive: "#cgo linux,arm64 LDFLAGS: libpdf_oxide.a", File: "cgo_dev.go"},
			{Name: "m", Kind: nativedomain.LinkedLibrarySystem,
				Directive: "#cgo linux,amd64 LDFLAGS: -lm", File: "cgo_dev.go"},
		})
	got := nativeStatement(rec)
	if !strings.Contains(got, "1 external native library ") {
		t.Errorf("statement = %q, want one distinct external library, with the C runtime excluded", got)
	}
}

// A module that ships its own sources also states what else it links, so
// neither answer hides the other.
func TestPrintNativeTable_ShippedSourcesStillListWhatIsLinked(t *testing.T) {
	rec := nativeRecWithLinks(t, nativedomain.PresenceIdentified,
		identifiedRecord(t).Components, identifiedRecord(t).Sources,
		[]nativedomain.LinkedLibrary{{
			Name: "m", Kind: nativedomain.LinkedLibrarySystem,
			Directive: "#cgo LDFLAGS: -lm", File: "sqlite3_opt_fts5.go",
		}})

	var buf bytes.Buffer
	if err := printNativeTable(&buf, toNativeSection(rec, false)); err != nil {
		t.Fatalf("printNativeTable: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"present_identified", "SQLite", "Native sources compiled into the binary (2)", "system"} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not contain %q:\n%s", want, out)
		}
	}
}

func TestToNativeSection_CarriesTheLinkedLibraries(t *testing.T) {
	s := toNativeSection(linkedNotShippedRecord(t), false)
	if len(s.LinkedLibraries) != 2 {
		t.Fatalf("linked libraries = %+v, want two", s.LinkedLibraries)
	}
	first := s.LinkedLibraries[0]
	if first.Name != "icui18n" || first.Kind != "external" ||
		first.File != "cases/icu.go" || first.Directive != "#cgo LDFLAGS: -licui18n -licuuc" {
		t.Errorf("linked[0] = %+v", first)
	}
}
