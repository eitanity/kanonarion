package sqlite_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	nativesqlite "github.com/eitanity/kanonarion/internal/native/adapters/store/sqlite"
	"github.com/eitanity/kanonarion/internal/native/domain"
	"github.com/eitanity/kanonarion/internal/native/ports"
)

func openTestStore(t *testing.T) *nativesqlite.Store {
	t.Helper()
	db, err := sqlitestore.Open(":memory:", nativesqlite.Migrations(), sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if cerr := db.Close(); cerr != nil {
			t.Errorf("Close: %v", cerr)
		}
	})
	return nativesqlite.New(db)
}

func coord(t *testing.T, path, version string) coordinate.ModuleCoordinate {
	t.Helper()
	c, err := coordinate.NewModuleCoordinate(path, version)
	if err != nil {
		t.Fatalf("NewModuleCoordinate(%q, %q): %v", path, version, err)
	}
	return c
}

func sqliteRecord(t *testing.T, artefact string) domain.Record {
	t.Helper()
	components := []domain.Component{{
		Name: "SQLite", Version: "3.38.0", Confidence: domain.ConfidenceDeclared,
		Evidence: []domain.Evidence{{File: "sqlite3-binding.c", Declaration: `#define SQLITE_VERSION "3.38.0"`}},
	}}
	sources := []domain.Source{{File: "sqlite3-binding.c", Bytes: 8469484, SHA256: "aa"}}
	linked := []domain.LinkedLibrary{{
		Name: "icui18n", Kind: domain.LinkedLibraryExternal,
		Directive: "#cgo LDFLAGS: -licuuc -licui18n", File: "sqlite3_opt_icu.go",
	}}
	c := coord(t, "github.com/mattn/go-sqlite3", "v1.14.12")
	return domain.Record{
		SchemaVersion:          domain.NativeSchemaVersion,
		Ecosystem:              domain.EcosystemGo,
		Coordinate:             c,
		ArtefactIdentity:       artefact,
		PipelineVersion:        domain.PipelineVersion,
		RecipeCatalogueVersion: domain.RecipeCatalogueVersion,
		Presence:               domain.PresenceIdentified,
		Components:             components,
		Sources:                sources,
		LinkedLibraries:        linked,
		ExtractedAt:            time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC),
		ContentHash: domain.Hash(c.String(), artefact, domain.PipelineVersion,
			domain.RecipeCatalogueVersion, domain.PresenceIdentified, components, sources, linked),
	}
}

func TestStore_RoundTrip(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	want := sqliteRecord(t, "zip:h1:TJ1bhYJPV44phC+IMu1u2K/i5RriLTPe+yc68XDJ1Z0=")

	if err := s.PutNativeRecord(ctx, want); err != nil {
		t.Fatalf("PutNativeRecord: %v", err)
	}
	got, found, err := s.GetNativeRecord(ctx, want.Coordinate)
	if err != nil {
		t.Fatalf("GetNativeRecord: %v", err)
	}
	if !found {
		t.Fatal("GetNativeRecord found nothing after a successful put")
	}
	if got.ContentHash != want.ContentHash {
		t.Errorf("content hash = %q, want %q", got.ContentHash, want.ContentHash)
	}
	if got.Presence != domain.PresenceIdentified {
		t.Errorf("presence = %q, want %q", got.Presence, domain.PresenceIdentified)
	}
	if len(got.Components) != 1 || got.Components[0].Version != "3.38.0" {
		t.Fatalf("components = %+v, want SQLite 3.38.0", got.Components)
	}
	// The new collection survives the round trip, or a record would come back
	// saying the module links nothing when it links ICU.
	if len(got.LinkedLibraries) != 1 || got.LinkedLibraries[0].Name != "icui18n" ||
		got.LinkedLibraries[0].Kind != domain.LinkedLibraryExternal {
		t.Fatalf("linked libraries = %+v, want the ICU link", got.LinkedLibraries)
	}
	if got.Components[0].Evidence[0].Declaration != want.Components[0].Evidence[0].Declaration {
		t.Errorf("the declaration did not survive the round trip: %+v", got.Components[0].Evidence)
	}
	if len(got.Sources) != 1 || got.Sources[0].Bytes != 8469484 {
		t.Errorf("sources = %+v, want the file evidence to survive", got.Sources)
	}
	if got.Coordinate != want.Coordinate {
		t.Errorf("coordinate = %s, want %s", got.Coordinate, want.Coordinate)
	}
}

// Absence reads as "not examined". A caller must never be able to mistake it
// for "no native component", so it is a false found rather than a zero record
// that looks like a measurement.
func TestStore_UnexaminedModuleIsNotFound(t *testing.T) {
	s := openTestStore(t)
	_, found, err := s.GetNativeRecord(context.Background(), coord(t, "example.com/mod", "v1.0.0"))
	if err != nil {
		t.Fatalf("GetNativeRecord: %v", err)
	}
	if found {
		t.Error("a module that was never examined reads as found")
	}
}

// Re-measuring one artefact writes the same answer: the measurement is a
// function of the bytes at a fixed generation.
func TestStore_RemeasuringOneArtefactIsIdempotent(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	rec := sqliteRecord(t, "zip:h1:a=")

	for range 3 {
		if err := s.PutNativeRecord(ctx, rec); err != nil {
			t.Fatalf("PutNativeRecord: %v", err)
		}
	}
	got, found, err := s.GetNativeRecord(ctx, rec.Coordinate)
	if err != nil || !found {
		t.Fatalf("GetNativeRecord: %v (found=%t)", err, found)
	}
	if got.ContentHash != rec.ContentHash {
		t.Errorf("content hash = %q, want %q", got.ContentHash, rec.ContentHash)
	}
}

// Two records naming different artefacts for one pinned version is a
// contradiction about what that version's bytes are. Serving either would
// report a component read out of an artefact the caller may not have, and hide
// that the store holds another.
func TestStore_RefusesToPickBetweenTwoArtefacts(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	first := sqliteRecord(t, "zip:h1:a=")
	second := sqliteRecord(t, "zip:h1:b=")

	if err := s.PutNativeRecord(ctx, first); err != nil {
		t.Fatalf("PutNativeRecord(first): %v", err)
	}
	if err := s.PutNativeRecord(ctx, second); err != nil {
		t.Fatalf("PutNativeRecord(second): %v", err)
	}
	_, found, err := s.GetNativeRecord(ctx, first.Coordinate)
	if !errors.Is(err, ports.ErrNativeConflict) {
		t.Fatalf("GetNativeRecord error = %v, want ErrNativeConflict", err)
	}
	if found {
		t.Error("a refused composition must not also report a record")
	}
	for _, want := range []string{"zip:h1:a=", "zip:h1:b="} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not name %q: %v", want, err)
		}
	}
}

// A record that cannot say which bytes it describes is unfalsifiable, and would
// share a key with every other record that named none.
func TestStore_RefusesARecordNamingNoArtefact(t *testing.T) {
	s := openTestStore(t)
	rec := sqliteRecord(t, "")
	err := s.PutNativeRecord(context.Background(), rec)
	if !errors.Is(err, fetchdomain.ErrZeroIdentity) {
		t.Fatalf("PutNativeRecord error = %v, want ErrZeroIdentity", err)
	}
}

func TestStore_RefusesAForeignEcosystem(t *testing.T) {
	s := openTestStore(t)
	rec := sqliteRecord(t, "zip:h1:a=")
	rec.Ecosystem = "npm"
	err := s.PutNativeRecord(context.Background(), rec)
	if !errors.Is(err, domain.ErrUnsupportedEcosystem) {
		t.Fatalf("PutNativeRecord error = %v, want ErrUnsupportedEcosystem", err)
	}
}

// TestRefusesZeroCoordinate pins the value-object rule at this store, on both
// legs.
func TestRefusesZeroCoordinate(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	coordinatetest.AssertRefusesZeroCoordinate(t, "PutNativeRecord", func() error {
		return s.PutNativeRecord(ctx, domain.Record{})
	})
	coordinatetest.AssertRefusesZeroCoordinate(t, "GetNativeRecord", func() error {
		_, _, err := s.GetNativeRecord(ctx, coordinate.ModuleCoordinate{})
		if err != nil {
			return fmt.Errorf("GetNativeRecord: %w", err)
		}
		return nil
	})
}
