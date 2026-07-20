package sqlite_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	examplesqlite "github.com/eitanity/kanonarion/internal/example/adapters/store/sqlite"
	domain2 "github.com/eitanity/kanonarion/internal/example/domain"
	"github.com/eitanity/kanonarion/internal/example/ports"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

func openTestStore(t *testing.T) *examplesqlite.Store {
	t.Helper()
	s, err := examplesqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return s
}

func mustCoord(t *testing.T, path, version string) coordinate.ModuleCoordinate {
	t.Helper()
	c, err := coordinate.NewModuleCoordinate(path, version)
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	return c
}

func buildRecord(t *testing.T, coord coordinate.ModuleCoordinate, count int, status domain2.ExampleStatus) domain2.ExampleRecord {
	t.Helper()
	var examples []domain2.ExampleEntry
	for i := 0; i < count; i++ {
		examples = append(examples, domain2.ExampleEntry{
			Name:             fmt.Sprintf("ExampleFoo%d", i),
			Package:          "mod_test",
			AssociatedSymbol: fmt.Sprintf("Foo%d", i),
			Body:             "{}",
			Validates:        i%2 == 0,
		})
	}
	r := domain2.ExampleRecord{
		SchemaVersion:   domain2.ExampleSchemaVersion,
		Ecosystem:       fetchdomain.EcosystemGo,
		Coordinate:      coord,
		Examples:        examples,
		OverallStatus:   status,
		ExtractedAt:     time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		PipelineVersion: "0.1.0",
	}
	var h domain2.ExampleRecordHasher
	r, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	return r
}

func TestPutAndGet(t *testing.T) {
	s := openTestStore(t)
	coord := mustCoord(t, "example.com/mod", "v1.0.0")
	r := buildRecord(t, coord, 2, domain2.ExampleStatusFound)

	if err := s.PutExampleRecord(context.Background(), r); err != nil {
		t.Fatalf("PutExampleRecord: %v", err)
	}

	got, found, err := s.GetExampleRecord(context.Background(), coord, "0.1.0")
	if err != nil {
		t.Fatalf("GetExampleRecord: %v", err)
	}
	if !found {
		t.Fatal("expected record to be found")
	}
	if got.OverallStatus != domain2.ExampleStatusFound {
		t.Errorf("OverallStatus: got %v, want Found", got.OverallStatus)
	}
	if len(got.Examples) != 2 {
		t.Errorf("expected 2 examples, got %d", len(got.Examples))
	}
	if got.ContentHash != r.ContentHash {
		t.Errorf("ContentHash mismatch: got %q, want %q", got.ContentHash, r.ContentHash)
	}
}

func TestGet_NotFound(t *testing.T) {
	s := openTestStore(t)
	coord := mustCoord(t, "example.com/absent", "v1.0.0")

	_, found, err := s.GetExampleRecord(context.Background(), coord, "0.1.0")
	if err != nil {
		t.Fatalf("GetExampleRecord: %v", err)
	}
	if found {
		t.Error("expected not found for absent record")
	}
}

func TestPut_Idempotent(t *testing.T) {
	s := openTestStore(t)
	coord := mustCoord(t, "example.com/idem", "v1.0.0")
	r := buildRecord(t, coord, 1, domain2.ExampleStatusFound)

	if err := s.PutExampleRecord(context.Background(), r); err != nil {
		t.Fatalf("first put: %v", err)
	}
	if err := s.PutExampleRecord(context.Background(), r); err != nil {
		t.Fatalf("second put: %v", err)
	}

	_, found, err := s.GetExampleRecord(context.Background(), coord, "0.1.0")
	if err != nil {
		t.Fatalf("GetExampleRecord: %v", err)
	}
	if !found {
		t.Fatal("expected record to be found")
	}
}

func TestListExampleRecords(t *testing.T) {
	s := openTestStore(t)

	c1 := mustCoord(t, "example.com/a", "v1.0.0")
	c2 := mustCoord(t, "example.com/b", "v1.0.0")

	if err := s.PutExampleRecord(context.Background(), buildRecord(t, c1, 3, domain2.ExampleStatusFound)); err != nil {
		t.Fatalf("put c1: %v", err)
	}
	if err := s.PutExampleRecord(context.Background(), buildRecord(t, c2, 0, domain2.ExampleStatusNone)); err != nil {
		t.Fatalf("put c2: %v", err)
	}

	t.Run("all", func(t *testing.T) {
		sums, err := s.ListExampleRecords(context.Background(), ports.ExampleFilter{})
		if err != nil {
			t.Fatalf("ListExampleRecords: %v", err)
		}
		if len(sums) != 2 {
			t.Errorf("expected 2 summaries, got %d", len(sums))
		}
	})

	t.Run("limit", func(t *testing.T) {
		sums, err := s.ListExampleRecords(context.Background(), ports.ExampleFilter{Limit: 1})
		if err != nil {
			t.Fatalf("ListExampleRecords: %v", err)
		}
		if len(sums) != 1 {
			t.Errorf("expected 1 summary with Limit=1, got %d", len(sums))
		}
	})

	t.Run("offset", func(t *testing.T) {
		sums, err := s.ListExampleRecords(context.Background(), ports.ExampleFilter{Offset: 1})
		if err != nil {
			t.Fatalf("ListExampleRecords: %v", err)
		}
		if len(sums) != 1 {
			t.Errorf("expected 1 summary with Offset=1, got %d", len(sums))
		}
	})
}

func TestGet_IntegrityError(t *testing.T) {
	s := openTestStore(t)
	coord := mustCoord(t, "example.com/mod", "v1.0.0")
	r := buildRecord(t, coord, 1, domain2.ExampleStatusFound)

	if err := s.PutExampleRecord(context.Background(), r); err != nil {
		t.Fatalf("PutExampleRecord: %v", err)
	}

	// Tamper with the database to cause integrity error
	db := s.InternalDB().DB()
	// Change the content_hash in the database but keep the serialised blob as is.
	// When GetExampleRecord reads it, it will unmarshal the blob, then re-compute the hash
	// from the unmarshalled record, and compare it with the content_hash field IN THE RECORD.
	// Wait, the content_hash is ALSO inside the serialised blob.
	// Let's update the serialised blob to have a different content_hash than what it should have.

	r.ContentHash = "sha256:invalid"
	var h domain2.ExampleRecordHasher
	blob, _ := h.Marshal(r)
	if _, err := db.Exec("UPDATE example_records SET serialised = ?", blob); err != nil {
		t.Fatalf("failed to tamper with db: %v", err)
	}

	_, _, err := s.GetExampleRecord(context.Background(), coord, "0.1.0")
	if err == nil {
		t.Fatal("expected error due to tampered hash")
	}
	if !errors.Is(err, ports.ErrExampleIntegrity) {
		t.Errorf("expected ErrExampleIntegrity, got %v", err)
	}
}

func TestFindBySymbol(t *testing.T) {
	s := openTestStore(t)

	coord := mustCoord(t, "example.com/mod", "v1.0.0")
	r := buildRecord(t, coord, 3, domain2.ExampleStatusFound)
	// buildRecord creates ExampleFoo0, ExampleFoo1, ExampleFoo2 with symbols Foo0, Foo1, Foo2.
	if err := s.PutExampleRecord(context.Background(), r); err != nil {
		t.Fatalf("PutExampleRecord: %v", err)
	}

	refs, err := s.FindBySymbol(context.Background(), "Foo0", "0.1.0")
	if err != nil {
		t.Fatalf("FindBySymbol: %v", err)
	}
	if len(refs) != 1 {
		t.Fatalf("expected 1 ref for Foo0, got %d", len(refs))
	}
	if refs[0].ExampleName != "ExampleFoo0" {
		t.Errorf("ExampleName: got %q, want ExampleFoo0", refs[0].ExampleName)
	}
	if !refs[0].Validates {
		t.Error("ExampleFoo0 should have Validates=true (index 0 is even)")
	}

	// Symbol not in index.
	refs, err = s.FindBySymbol(context.Background(), "Absent", "0.1.0")
	if err != nil {
		t.Fatalf("FindBySymbol Absent: %v", err)
	}
	if len(refs) != 0 {
		t.Errorf("expected 0 refs for Absent, got %d", len(refs))
	}
}

func TestFindBySymbolInModule_Scoped(t *testing.T) {
	s := openTestStore(t)

	coordA := mustCoord(t, "example.com/mod-a", "v1.0.0")
	coordB := mustCoord(t, "example.com/mod-b", "v1.0.0")

	// Both modules have an example for the same symbol.
	makeRecord := func(coord coordinate.ModuleCoordinate, name string) domain2.ExampleRecord {
		r := domain2.ExampleRecord{
			SchemaVersion: domain2.ExampleSchemaVersion,
			Ecosystem:     fetchdomain.EcosystemGo,
			Coordinate:    coord,
			Examples: []domain2.ExampleEntry{
				{Name: "ExampleMarshal", Package: "pkg_test", AssociatedSymbol: "Marshal", Body: "{}"},
			},
			OverallStatus:   domain2.ExampleStatusFound,
			ExtractedAt:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			PipelineVersion: "0.1.0",
		}
		_ = name
		var h domain2.ExampleRecordHasher
		r, err := h.SetContentHash(r)
		if err != nil {
			t.Fatalf("SetContentHash: %v", err)
		}
		return r
	}
	if err := s.PutExampleRecord(context.Background(), makeRecord(coordA, "a")); err != nil {
		t.Fatal(err)
	}
	if err := s.PutExampleRecord(context.Background(), makeRecord(coordB, "b")); err != nil {
		t.Fatal(err)
	}

	// Global find returns both.
	all, err := s.FindBySymbol(context.Background(), "Marshal", "0.1.0")
	if err != nil {
		t.Fatalf("FindBySymbol: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 refs globally, got %d", len(all))
	}

	// Scoped find returns only mod-a's example.
	refs, err := s.FindBySymbolInModule(context.Background(), coordA, "Marshal", "0.1.0")
	if err != nil {
		t.Fatalf("FindBySymbolInModule: %v", err)
	}
	if len(refs) != 1 {
		t.Fatalf("expected 1 scoped ref for mod-a, got %d", len(refs))
	}
	if refs[0].ModulePath != coordA.Path {
		t.Errorf("ModulePath: got %q, want %q", refs[0].ModulePath, coordA.Path)
	}
	if refs[0].ExampleName != "ExampleMarshal" {
		t.Errorf("ExampleName: got %q", refs[0].ExampleName)
	}
}

func TestFindBySymbolInModule_NotFound(t *testing.T) {
	s := openTestStore(t)
	coord := mustCoord(t, "example.com/mod", "v1.0.0")
	r := buildRecord(t, coord, 1, domain2.ExampleStatusFound)
	if err := s.PutExampleRecord(context.Background(), r); err != nil {
		t.Fatal(err)
	}

	// Scoped to a version that has no data.
	coordOther := mustCoord(t, "example.com/mod", "v9.9.9")
	refs, err := s.FindBySymbolInModule(context.Background(), coordOther, "Foo0", "0.1.0")
	if err != nil {
		t.Fatalf("FindBySymbolInModule: %v", err)
	}
	if len(refs) != 0 {
		t.Errorf("expected 0 refs, got %d", len(refs))
	}
}

func TestFindBySymbolInModule_PackageQualified(t *testing.T) {
	s := openTestStore(t)
	coord := mustCoord(t, "example.com/mod", "v1.0.0")
	r := buildRecord(t, coord, 1, domain2.ExampleStatusFound)
	if err := s.PutExampleRecord(context.Background(), r); err != nil {
		t.Fatal(err)
	}

	// "mod.Foo0" should strip the package prefix and match "Foo0".
	refs, err := s.FindBySymbolInModule(context.Background(), coord, "mod.Foo0", "0.1.0")
	if err != nil {
		t.Fatalf("FindBySymbolInModule: %v", err)
	}
	if len(refs) != 1 {
		t.Fatalf("expected 1 ref after package-prefix stripping, got %d", len(refs))
	}
}

func TestMigrateIdempotent(t *testing.T) {
	s1, err := examplesqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	s2, err := examplesqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	if err := s2.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
