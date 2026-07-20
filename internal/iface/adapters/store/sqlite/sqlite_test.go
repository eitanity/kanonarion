package sqlite_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/iface/adapters/store/sqlite"
	domain2 "github.com/eitanity/kanonarion/internal/iface/domain"
	"github.com/eitanity/kanonarion/internal/iface/ports"
)

func openStore(t *testing.T) *sqlite.Store {
	t.Helper()
	s, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func makeRecord(t *testing.T) domain2.InterfaceRecord {
	t.Helper()
	coord, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	r := domain2.InterfaceRecord{
		SchemaVersion: domain2.InterfaceSchemaVersion,
		Ecosystem:     fetchdomain.EcosystemGo,
		Coordinate:    coord,
		Packages: []domain2.PackageInterface{
			{
				ImportPath: "example.com/mod",
				Name:       "mod",
				Types: []domain2.TypeDecl{
					{
						Name:      "Client",
						Kind:      domain2.TypeKindStruct,
						Signature: "type Client struct{}",
						Methods: []domain2.MethodDecl{
							{Name: "Do", Signature: "func (c *Client) Do() error", PtrReceiver: true},
						},
					},
				},
				Funcs:  []domain2.FuncDecl{{Name: "New", Signature: "func New() *Client"}},
				Consts: []domain2.ValueDecl{{Name: "Version", Type: "string"}},
				Vars:   []domain2.ValueDecl{{Name: "ErrClosed", Type: "error"}},
			},
		},
		OverallStatus:   domain2.InterfaceStatusExtracted,
		ExtractedAt:     time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
		PipelineVersion: "0.1.0",
	}
	var h domain2.InterfaceRecordHasher
	r, err = h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	return r
}

func TestStore_PutGet_RoundTrip(t *testing.T) {
	s := openStore(t)
	r := makeRecord(t)

	if err := s.PutInterfaceRecord(context.Background(), r); err != nil {
		t.Fatalf("PutInterfaceRecord: %v", err)
	}

	got, found, err := s.GetInterfaceRecord(context.Background(), r.Coordinate, r.PipelineVersion)
	if err != nil {
		t.Fatalf("GetInterfaceRecord: %v", err)
	}
	if !found {
		t.Fatal("record not found after put")
	}
	if got.ContentHash != r.ContentHash {
		t.Errorf("ContentHash: %q vs %q", got.ContentHash, r.ContentHash)
	}
	if len(got.Packages) != len(r.Packages) {
		t.Errorf("Packages len: %d vs %d", len(got.Packages), len(r.Packages))
	}
}

func TestStore_GetNotFound(t *testing.T) {
	s := openStore(t)
	coord, _ := coordinate.NewModuleCoordinate("example.com/missing", "v1.0.0")
	_, found, err := s.GetInterfaceRecord(context.Background(), coord, "0.1.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Error("expected not found")
	}
}

func TestStore_Put_Idempotent(t *testing.T) {
	s := openStore(t)
	r := makeRecord(t)

	if err := s.PutInterfaceRecord(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if err := s.PutInterfaceRecord(context.Background(), r); err != nil {
		t.Fatalf("second put failed: %v", err)
	}

	_, found, err := s.GetInterfaceRecord(context.Background(), r.Coordinate, r.PipelineVersion)
	if err != nil || !found {
		t.Errorf("get after double-put: found=%v err=%v", found, err)
	}
}

func TestStore_ListInterfaceRecords(t *testing.T) {
	s := openStore(t)
	r := makeRecord(t)

	if err := s.PutInterfaceRecord(context.Background(), r); err != nil {
		t.Fatal(err)
	}

	sums, err := s.ListInterfaceRecords(context.Background(), ports.InterfaceFilter{Limit: 10})
	if err != nil {
		t.Fatalf("ListInterfaceRecords: %v", err)
	}
	if len(sums) != 1 {
		t.Fatalf("expected 1 summary, got %d", len(sums))
	}
	if sums[0].ModulePath != r.Coordinate.Path {
		t.Errorf("ModulePath: %q", sums[0].ModulePath)
	}
	if sums[0].PackageCount != len(r.Packages) {
		t.Errorf("PackageCount: %d vs %d", sums[0].PackageCount, len(r.Packages))
	}

	t.Run("offset", func(t *testing.T) {
		sums, err := s.ListInterfaceRecords(context.Background(), ports.InterfaceFilter{Offset: 1})
		if err != nil {
			t.Fatalf("ListInterfaceRecords: %v", err)
		}
		if len(sums) != 0 {
			t.Errorf("expected 0 summaries with Offset=1, got %d", len(sums))
		}
	})
}

func TestStore_GetInterfaceRecord_IntegrityError(t *testing.T) {
	s := openStore(t)
	r := makeRecord(t)
	if err := s.PutInterfaceRecord(context.Background(), r); err != nil {
		t.Fatalf("PutInterfaceRecord: %v", err)
	}

	db := s.InternalDB().DB()
	r.ContentHash = "sha256:invalid"
	var h domain2.InterfaceRecordHasher
	blob, _ := h.Marshal(r)
	if _, err := db.Exec("UPDATE interface_records SET serialised = ?", blob); err != nil {
		t.Fatalf("failed to tamper with db: %v", err)
	}

	_, _, err := s.GetInterfaceRecord(context.Background(), r.Coordinate, r.PipelineVersion)
	if !errors.Is(err, ports.ErrInterfaceIntegrity) {
		t.Errorf("expected ErrInterfaceIntegrity, got %v", err)
	}
}

func TestStore_FindSymbol(t *testing.T) {
	s := openStore(t)
	r := makeRecord(t)

	if err := s.PutInterfaceRecord(context.Background(), r); err != nil {
		t.Fatal(err)
	}

	// Find a type symbol.
	refs, err := s.FindSymbol(context.Background(), "Client", r.PipelineVersion)
	if err != nil {
		t.Fatalf("FindSymbol: %v", err)
	}
	if len(refs) != 1 {
		t.Fatalf("expected 1 ref for Client, got %d", len(refs))
	}
	if refs[0].SymbolKind != "type" {
		t.Errorf("SymbolKind: %q, want type", refs[0].SymbolKind)
	}
	if refs[0].ParentType != "" {
		t.Errorf("ParentType: %q, want empty", refs[0].ParentType)
	}
	if refs[0].PackagePath != "example.com/mod" {
		t.Errorf("PackagePath: %q, want example.com/mod", refs[0].PackagePath)
	}
	if refs[0].Signature == "" {
		t.Error("Signature is empty for type symbol")
	}
}

func TestStore_FindSymbol_Method(t *testing.T) {
	s := openStore(t)
	r := makeRecord(t)

	if err := s.PutInterfaceRecord(context.Background(), r); err != nil {
		t.Fatal(err)
	}

	refs, err := s.FindSymbol(context.Background(), "Do", r.PipelineVersion)
	if err != nil {
		t.Fatalf("FindSymbol: %v", err)
	}
	if len(refs) != 1 {
		t.Fatalf("expected 1 ref for Do, got %d", len(refs))
	}
	if refs[0].SymbolKind != "method" {
		t.Errorf("SymbolKind: %q, want method", refs[0].SymbolKind)
	}
	if refs[0].ParentType != "Client" {
		t.Errorf("ParentType: %q, want Client", refs[0].ParentType)
	}
	if refs[0].Signature != "func (c *Client) Do() error" {
		t.Errorf("Signature: %q, want method signature", refs[0].Signature)
	}
}

func TestStore_FindSymbol_Func_Signature(t *testing.T) {
	s := openStore(t)
	r := makeRecord(t)

	if err := s.PutInterfaceRecord(context.Background(), r); err != nil {
		t.Fatal(err)
	}

	refs, err := s.FindSymbol(context.Background(), "New", r.PipelineVersion)
	if err != nil {
		t.Fatalf("FindSymbol: %v", err)
	}
	if len(refs) != 1 {
		t.Fatalf("expected 1 ref for New, got %d", len(refs))
	}
	if refs[0].Signature != "func New() *Client" {
		t.Errorf("Signature: %q, want func New() *Client", refs[0].Signature)
	}
}

func TestStore_FindSymbol_MultiPackage_Disambiguates(t *testing.T) {
	s := openStore(t)

	// Two packages in the same module both export "Marshal".
	coord, _ := coordinate.NewModuleCoordinate("example.com/multi", "v1.0.0")
	r := domain2.InterfaceRecord{
		SchemaVersion: domain2.InterfaceSchemaVersion,
		Ecosystem:     fetchdomain.EcosystemGo,
		Coordinate:    coord,
		Packages: []domain2.PackageInterface{
			{
				ImportPath: "example.com/multi/json",
				Name:       "json",
				Funcs: []domain2.FuncDecl{
					{Name: "Marshal", Signature: "func Marshal(v any) ([]byte, error)"},
				},
			},
			{
				ImportPath: "example.com/multi/xml",
				Name:       "xml",
				Funcs: []domain2.FuncDecl{
					{Name: "Marshal", Signature: "func Marshal(v any) ([]byte, error)"},
				},
			},
		},
		OverallStatus:   domain2.InterfaceStatusExtracted,
		ExtractedAt:     time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
		PipelineVersion: "0.1.0",
	}
	var h domain2.InterfaceRecordHasher
	r, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}

	if err := s.PutInterfaceRecord(context.Background(), r); err != nil {
		t.Fatal(err)
	}

	refs, err := s.FindSymbol(context.Background(), "Marshal", r.PipelineVersion)
	if err != nil {
		t.Fatalf("FindSymbol: %v", err)
	}
	if len(refs) != 2 {
		t.Fatalf("expected 2 distinct refs (one per package), got %d", len(refs))
	}

	// Each ref must have its own PackagePath so callers can disambiguate.
	paths := map[string]bool{}
	for _, ref := range refs {
		if ref.PackagePath == "" {
			t.Error("PackagePath must not be empty")
		}
		paths[ref.PackagePath] = true
		if ref.Signature == "" {
			t.Errorf("Signature empty for ref in %s", ref.PackagePath)
		}
	}
	if len(paths) != 2 {
		t.Errorf("expected 2 distinct PackagePaths, got %v", paths)
	}
}

func TestStore_FindSymbol_NotFound(t *testing.T) {
	s := openStore(t)
	refs, err := s.FindSymbol(context.Background(), "NoSuchSymbol", "0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 0 {
		t.Errorf("expected 0 refs, got %d", len(refs))
	}
}

func TestStore_Put_RebuildIndex(t *testing.T) {
	s := openStore(t)
	r := makeRecord(t)

	if err := s.PutInterfaceRecord(context.Background(), r); err != nil {
		t.Fatal(err)
	}

	// Put again (simulates a re-extraction) — index must not double-count.
	if err := s.PutInterfaceRecord(context.Background(), r); err != nil {
		t.Fatal(err)
	}

	refs, err := s.FindSymbol(context.Background(), "Client", r.PipelineVersion)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 {
		t.Errorf("expected exactly 1 symbol ref after double-put, got %d", len(refs))
	}
}
