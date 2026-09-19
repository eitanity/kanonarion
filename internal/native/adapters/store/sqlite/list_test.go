package sqlite_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/blobcodec"
	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
	nativesqlite "github.com/eitanity/kanonarion/internal/native/adapters/store/sqlite"
	"github.com/eitanity/kanonarion/internal/native/domain"
	"github.com/eitanity/kanonarion/internal/native/ports"
)

// openTestStoreDB is openTestStore with the handle kept, for the two facts this
// file has to set up behind the store's back: a record at a generation the
// build no longer produces, and two records describing different artefacts for
// one pinned version. Neither can be written through PutNativeRecord, which
// stamps the current generation on everything it stores.
func openTestStoreDB(t *testing.T) (*nativesqlite.Store, sqlitestore.DB) {
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
	return nativesqlite.New(db), db
}

// putAt writes a record under an explicit generation and artefact identity,
// bypassing the current-generation stamp PutNativeRecord applies.
func putAt(t *testing.T, db sqlitestore.DB, rec domain.Record, generation, artefact string) {
	t.Helper()
	rec.ArtefactIdentity = artefact
	raw := mustMarshal(t, rec)
	const q = `INSERT INTO native_records (
        module_path, module_version, pipeline_fingerprint, artefact_identity,
        presence, component_count, source_count, extracted_at, content_hash, serialised
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	if _, err := db.DB().ExecContext(context.Background(), q,
		rec.Coordinate.Path(), rec.Coordinate.Version(), generation, artefact,
		string(rec.Presence), len(rec.Components), len(rec.Sources),
		rec.ExtractedAt.UTC().Format(time.RFC3339), rec.ContentHash, raw,
	); err != nil {
		t.Fatalf("inserting record at generation %s: %v", generation, err)
	}
}

// linkedRecord is a module that compiles no native source of its own and links
// two external libraries plus the C runtime, twice over between them: the
// listing must report two libraries, not four entries.
func linkedRecord(t *testing.T, path, version string, taken time.Time) domain.Record {
	t.Helper()
	c := coord(t, path, version)
	linked := []domain.LinkedLibrary{
		{Name: "icuuc", Kind: domain.LinkedLibraryExternal, Directive: "#cgo LDFLAGS: -licuuc", File: "a.go"},
		{Name: "icuuc", Kind: domain.LinkedLibraryExternal, Directive: "#cgo linux LDFLAGS: -licuuc", File: "b.go"},
		{Name: "c", Kind: domain.LinkedLibrarySystem, Directive: "#cgo LDFLAGS: -lc", File: "a.go"},
		{Name: "libxml-2.0", Kind: domain.LinkedLibraryExternal, Directive: "#cgo pkg-config: libxml-2.0", File: "a.go"},
	}
	return domain.Record{
		SchemaVersion:          domain.NativeSchemaVersion,
		Ecosystem:              domain.EcosystemGo,
		Coordinate:             c,
		ArtefactIdentity:       "zip:h1:linked-" + version,
		PipelineVersion:        domain.PipelineVersion,
		RecipeCatalogueVersion: domain.RecipeCatalogueVersion,
		Presence:               domain.PresenceLinkedNotShipped,
		Components:             []domain.Component{},
		Sources:                []domain.Source{},
		LinkedLibraries:        linked,
		ExtractedAt:            taken,
		ContentHash: domain.Hash(c.String(), "zip:h1:linked-"+version, domain.PipelineVersion,
			domain.RecipeCatalogueVersion, domain.PresenceLinkedNotShipped,
			[]domain.Component{}, []domain.Source{}, linked),
	}
}

// absentRecord is a module measured and found to compile and link nothing.
func absentRecord(t *testing.T, path, version string, taken time.Time) domain.Record {
	t.Helper()
	c := coord(t, path, version)
	return domain.Record{
		SchemaVersion:          domain.NativeSchemaVersion,
		Ecosystem:              domain.EcosystemGo,
		Coordinate:             c,
		ArtefactIdentity:       "zip:h1:absent-" + version,
		PipelineVersion:        domain.PipelineVersion,
		RecipeCatalogueVersion: domain.RecipeCatalogueVersion,
		Presence:               domain.PresenceAbsent,
		Components:             []domain.Component{},
		Sources:                []domain.Source{},
		LinkedLibraries:        []domain.LinkedLibrary{},
		ExtractedAt:            taken,
		ContentHash: domain.Hash(c.String(), "zip:h1:absent-"+version, domain.PipelineVersion,
			domain.RecipeCatalogueVersion, domain.PresenceAbsent,
			[]domain.Component{}, []domain.Source{}, []domain.LinkedLibrary{}),
	}
}

func seedListStore(t *testing.T) *nativesqlite.Store {
	t.Helper()
	s := openTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	for _, rec := range []domain.Record{
		sqliteRecord(t, "zip:h1:sqlite"),
		linkedRecord(t, "golang.org/x/text", "v0.17.0", base.Add(-1*time.Hour)),
		absentRecord(t, "example.com/plain", "v1.0.0", base.Add(-2*time.Hour)),
		absentRecord(t, "example.com/other", "v2.0.0", base.Add(-3*time.Hour)),
	} {
		if err := s.PutNativeRecord(ctx, rec); err != nil {
			t.Fatalf("PutNativeRecord: %v", err)
		}
	}
	return s
}

func TestListNativeRecords_UnfilteredIsEveryRecordAtThisGeneration(t *testing.T) {
	s := seedListStore(t)

	got, err := s.ListNativeRecords(context.Background(), ports.NativeFilter{})
	if err != nil {
		t.Fatalf("ListNativeRecords: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("listed %d records, want 4", len(got))
	}
	// Newest measurement first, which is the ordering every listing on this
	// store uses.
	want := []string{
		"github.com/mattn/go-sqlite3@v1.14.12",
		"golang.org/x/text@v0.17.0",
		"example.com/plain@v1.0.0",
		"example.com/other@v2.0.0",
	}
	for i, w := range want {
		if got[i].Coordinate.String() != w {
			t.Errorf("row %d = %s, want %s", i, got[i].Coordinate, w)
		}
		if got[i].Generation != domain.PipelineFingerprint() {
			t.Errorf("row %d generation = %q, want %q", i, got[i].Generation, domain.PipelineFingerprint())
		}
	}
}

func TestListNativeRecords_NamesComponentsAndDistinctExternalLibraries(t *testing.T) {
	s := seedListStore(t)

	got, err := s.ListNativeRecords(context.Background(),
		ports.NativeFilter{Presence: []string{string(domain.PresenceLinkedNotShipped)}})
	if err != nil {
		t.Fatalf("ListNativeRecords: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("listed %d records, want 1", len(got))
	}
	// Two names from three external entries, and the C runtime left out: one
	// library named by two per-platform directives is one library, and every
	// cgo binary links libc.
	if want := []string{"icuuc", "libxml-2.0"}; !equalStrings(got[0].LinkedExternal, want) {
		t.Errorf("LinkedExternal = %v, want %v", got[0].LinkedExternal, want)
	}

	identified, err := s.ListNativeRecords(context.Background(),
		ports.NativeFilter{Presence: []string{string(domain.PresenceIdentified)}})
	if err != nil {
		t.Fatalf("ListNativeRecords: %v", err)
	}
	if len(identified) != 1 || len(identified[0].Components) != 1 {
		t.Fatalf("identified rows = %d, want 1 with 1 component", len(identified))
	}
	if identified[0].Components[0].Name != "SQLite" || identified[0].Components[0].Version != "3.38.0" {
		t.Errorf("component = %+v, want SQLite 3.38.0", identified[0].Components[0])
	}
	if identified[0].SourceCount != 1 {
		t.Errorf("SourceCount = %d, want 1", identified[0].SourceCount)
	}
}

func TestListNativeRecords_PresenceFilterTakesSeveralValues(t *testing.T) {
	s := seedListStore(t)

	got, err := s.ListNativeRecords(context.Background(), ports.NativeFilter{
		Presence: []string{string(domain.PresenceLinkedNotShipped), string(domain.PresenceIdentified)},
	})
	if err != nil {
		t.Fatalf("ListNativeRecords: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("listed %d records, want 2", len(got))
	}
	for _, s := range got {
		if s.Presence == domain.PresenceAbsent {
			t.Errorf("%s is absent and matched a filter that named neither absence", s.Coordinate)
		}
	}
}

func TestListNativeRecords_SupersededGenerationIsHiddenUntilAskedFor(t *testing.T) {
	s, db := openTestStoreDB(t)
	ctx := context.Background()
	base := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	if err := s.PutNativeRecord(ctx, absentRecord(t, "example.com/plain", "v1.0.0", base)); err != nil {
		t.Fatalf("PutNativeRecord: %v", err)
	}
	// The same module, measured by detection logic this build has replaced.
	putAt(t, db, linkedRecord(t, "example.com/plain", "v1.0.0", base.Add(-time.Hour)),
		"0.1.0+recipes.1", "zip:h1:old")

	held, err := s.ListNativeRecords(ctx, ports.NativeFilter{})
	if err != nil {
		t.Fatalf("ListNativeRecords: %v", err)
	}
	if len(held) != 1 {
		t.Fatalf("default listing returned %d records, want 1: a superseded generation must not pad the count", len(held))
	}
	if held[0].Presence != domain.PresenceAbsent {
		t.Errorf("presence = %q, want the servable record's %q", held[0].Presence, domain.PresenceAbsent)
	}

	all, err := s.ListNativeRecords(ctx, ports.NativeFilter{AllGenerations: true})
	if err != nil {
		t.Fatalf("ListNativeRecords(all): %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("--all-generations returned %d records, want 2", len(all))
	}
	generations := map[string]bool{}
	for _, s := range all {
		generations[s.Generation] = true
	}
	if !generations["0.1.0+recipes.1"] || !generations[domain.PipelineFingerprint()] {
		t.Errorf("generations listed = %v, want both", generations)
	}
}

func TestListNativeRecords_PagesEveryRowExactlyOnce(t *testing.T) {
	s := seedListStore(t)
	ctx := context.Background()

	full, err := s.ListNativeRecords(ctx, ports.NativeFilter{})
	if err != nil {
		t.Fatalf("ListNativeRecords: %v", err)
	}

	var paged []string
	for offset := 0; ; offset += 2 {
		page, perr := s.ListNativeRecords(ctx, ports.NativeFilter{Limit: 2, Offset: offset})
		if perr != nil {
			t.Fatalf("ListNativeRecords(offset %d): %v", offset, perr)
		}
		if len(page) == 0 {
			break
		}
		for _, row := range page {
			paged = append(paged, row.Coordinate.String())
		}
	}
	if len(paged) != len(full) {
		t.Fatalf("paged %d rows, unpaged listing holds %d", len(paged), len(full))
	}
	for i := range full {
		if paged[i] != full[i].Coordinate.String() {
			t.Errorf("paged row %d = %s, unpaged = %s", i, paged[i], full[i].Coordinate)
		}
	}
}

func TestListNativeRecords_OffsetWithoutLimitStillPages(t *testing.T) {
	s := seedListStore(t)

	got, err := s.ListNativeRecords(context.Background(), ports.NativeFilter{Offset: 3})
	if err != nil {
		t.Fatalf("ListNativeRecords: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("listed %d records, want 1: an offset with no limit must still skip", len(got))
	}
}

func TestListNativeRecords_DisputedCoordinateIsMarkedOnEveryRow(t *testing.T) {
	s, db := openTestStoreDB(t)
	ctx := context.Background()
	base := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	rec := absentRecord(t, "example.com/two", "v1.0.0", base)
	// Two records for one pinned version, describing different bytes. The
	// single-module read refuses to pick; the listing must not present them as
	// two independent answers.
	putAt(t, db, rec, domain.PipelineFingerprint(), "zip:h1:first")
	putAt(t, db, linkedRecord(t, "example.com/two", "v1.0.0", base), domain.PipelineFingerprint(), "zip:h1:second")

	got, err := s.ListNativeRecords(ctx, ports.NativeFilter{})
	if err != nil {
		t.Fatalf("ListNativeRecords: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("listed %d records, want 2", len(got))
	}
	for i, row := range got {
		if row.Conflict == nil {
			t.Errorf("row %d carries no conflict, though the store holds two records for %s", i, row.Coordinate)
			continue
		}
		if !errors.Is(row.Conflict, ports.ErrNativeConflict) {
			t.Errorf("row %d conflict = %v, want ErrNativeConflict", i, row.Conflict)
		}
	}

	// A presence filter narrows the rows, never the dispute: the two records
	// disagree about the presence itself, so a filter that returns one of them
	// must still say the other exists.
	filtered, ferr := s.ListNativeRecords(ctx, ports.NativeFilter{Presence: []string{string(domain.PresenceAbsent)}})
	if ferr != nil {
		t.Fatalf("ListNativeRecords(filtered): %v", ferr)
	}
	if len(filtered) != 1 {
		t.Fatalf("filtered listing returned %d records, want 1", len(filtered))
	}
	if filtered[0].Conflict == nil {
		t.Error("a filtered row lost the conflict its coordinate is in")
	}
}

func TestListNativeRecords_EmptyStoreListsNothingWithoutError(t *testing.T) {
	s := openTestStore(t)

	got, err := s.ListNativeRecords(context.Background(), ports.NativeFilter{})
	if err != nil {
		t.Fatalf("ListNativeRecords: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("listed %d records over an empty store", len(got))
	}
	if got == nil {
		t.Error("an empty listing returned nil rather than an empty slice")
	}
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// mustMarshal encodes a record the way the store does, so a hand-inserted row
// decodes through the same path a stored one does.
func mustMarshal(t *testing.T, rec domain.Record) []byte {
	t.Helper()
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshalling record: %v", err)
	}
	return blobcodec.Encode(raw)
}

// A stored record whose coordinate does not match the row it was filed under is
// refused rather than listed. The columns are the index; the record is the
// claim, and listing it under a name it does not make would attribute a
// measurement to the wrong module.
func TestListNativeRecords_RefusesARecordFiledUnderAnotherCoordinate(t *testing.T) {
	s, db := openTestStoreDB(t)
	rec := absentRecord(t, "example.com/real", "v1.0.0", time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC))
	raw := mustMarshal(t, rec)
	const q = `INSERT INTO native_records (
        module_path, module_version, pipeline_fingerprint, artefact_identity,
        presence, component_count, source_count, extracted_at, content_hash, serialised
    ) VALUES (?, ?, ?, ?, ?, 0, 0, ?, ?, ?)`
	if _, err := db.DB().ExecContext(context.Background(), q,
		"example.com/filed-as", "v9.9.9", domain.PipelineFingerprint(), "zip:h1:x",
		string(domain.PresenceAbsent), rec.ExtractedAt.Format(time.RFC3339), rec.ContentHash, raw,
	); err != nil {
		t.Fatalf("inserting mismatched record: %v", err)
	}

	if _, err := s.ListNativeRecords(context.Background(), ports.NativeFilter{}); err == nil {
		t.Fatal("ListNativeRecords listed a record filed under a coordinate it does not describe")
	}
}

// A record naming an ecosystem this build does not record is refused on the way
// out, exactly as the single-record read refuses it.
func TestListNativeRecords_RefusesAForeignEcosystem(t *testing.T) {
	s, db := openTestStoreDB(t)
	rec := absentRecord(t, "example.com/real", "v1.0.0", time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC))
	rec.Ecosystem = "npm"
	putAt(t, db, rec, domain.PipelineFingerprint(), "zip:h1:npm")

	_, err := s.ListNativeRecords(context.Background(), ports.NativeFilter{})
	if !errors.Is(err, domain.ErrUnsupportedEcosystem) {
		t.Fatalf("ListNativeRecords error = %v, want ErrUnsupportedEcosystem", err)
	}
}
