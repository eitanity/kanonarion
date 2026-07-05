package domain_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	domain2 "github.com/eitanity/kanonarion/internal/iface/domain"
)

func makeTestRecord(t *testing.T) domain2.InterfaceRecord {
	t.Helper()
	coord, err := fetchdomain.NewModuleCoordinate("example.com/mod", "v1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	return domain2.InterfaceRecord{
		SchemaVersion: domain2.InterfaceSchemaVersion,
		Ecosystem:     fetchdomain.EcosystemGo,
		Coordinate:    coord,
		Packages: []domain2.PackageInterface{
			{
				ImportPath: "example.com/mod",
				Name:       "mod",
				Doc:        "Package mod does things.",
				Types: []domain2.TypeDecl{
					{
						Name:      "Client",
						Kind:      domain2.TypeKindStruct,
						Signature: "type Client struct{ ... }",
						Doc:       "Client calls the API.",
						Fields: []domain2.FieldDecl{
							{Name: "Timeout", Type: "time.Duration"},
						},
						Methods: []domain2.MethodDecl{
							{Name: "Do", Signature: "func (c *Client) Do(req *Request) (*Response, error)", PtrReceiver: true},
						},
					},
				},
				Funcs: []domain2.FuncDecl{
					{Name: "New", Signature: "func New() *Client"},
				},
				Consts: []domain2.ValueDecl{{Name: "DefaultTimeout", Type: "time.Duration"}},
				Vars:   []domain2.ValueDecl{{Name: "ErrClosed", Type: "error"}},
			},
		},
		OverallStatus:   domain2.InterfaceStatusExtracted,
		ExtractedAt:     time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC),
		PipelineVersion: "0.1.0",
	}
}

func TestHasher_RoundTrip(t *testing.T) {
	var h domain2.InterfaceRecordHasher

	r := makeTestRecord(t)
	r, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if r.ContentHash == "" {
		t.Fatal("ContentHash is empty after SetContentHash")
	}

	blob, err := h.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	got, err := h.Unmarshal(blob)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if got.ContentHash != r.ContentHash {
		t.Errorf("ContentHash mismatch after round-trip: %q vs %q", got.ContentHash, r.ContentHash)
	}
	if got.Coordinate.Path != r.Coordinate.Path {
		t.Errorf("Coordinate.Path: %q vs %q", got.Coordinate.Path, r.Coordinate.Path)
	}
	if len(got.Packages) != len(r.Packages) {
		t.Fatalf("Packages length: %d vs %d", len(got.Packages), len(r.Packages))
	}
	if got.Packages[0].Name != r.Packages[0].Name {
		t.Errorf("Package.Name: %q vs %q", got.Packages[0].Name, r.Packages[0].Name)
	}
}

func TestHasher_VerifyContentHash_Valid(t *testing.T) {
	var h domain2.InterfaceRecordHasher
	r := makeTestRecord(t)
	r, err := h.SetContentHash(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.VerifyContentHash(r); err != nil {
		t.Errorf("VerifyContentHash on valid record: %v", err)
	}
}

func TestHasher_VerifyContentHash_Tampered(t *testing.T) {
	var h domain2.InterfaceRecordHasher
	r := makeTestRecord(t)
	r, _ = h.SetContentHash(r)

	r.Packages[0].Name = "tampered"
	if err := h.VerifyContentHash(r); err == nil {
		t.Error("expected error on tampered record, got nil")
	}
}

func TestHasher_Deterministic(t *testing.T) {
	var h domain2.InterfaceRecordHasher
	r1 := makeTestRecord(t)
	r2 := makeTestRecord(t)

	r1, _ = h.SetContentHash(r1)
	r2, _ = h.SetContentHash(r2)

	if r1.ContentHash != r2.ContentHash {
		t.Errorf("hashes differ across identical records: %q vs %q", r1.ContentHash, r2.ContentHash)
	}
}

func TestHasher_VerifyBlobHash(t *testing.T) {
	var h domain2.InterfaceRecordHasher
	r := makeTestRecord(t)
	r, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	blob, err := h.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	if err := h.VerifyBlobHash(blob, r.ContentHash); err != nil {
		t.Errorf("VerifyBlobHash on valid blob: %v", err)
	}

	if err := h.VerifyBlobHash(blob, "sha256:badhash"); err == nil {
		t.Error("VerifyBlobHash should fail on wrong storedHash")
	}

	tampered := make([]byte, len(blob))
	copy(tampered, blob)
	tampered[len(tampered)-2] ^= 0xff
	if err := h.VerifyBlobHash(tampered, r.ContentHash); err == nil {
		t.Error("VerifyBlobHash should fail on tampered blob")
	}

	if err := h.VerifyBlobHash([]byte(`{"no_hash_field":"x"}`), r.ContentHash); err == nil {
		t.Error("VerifyBlobHash should fail when content_hash field is absent")
	}
}

func TestHasher_EmptyRecord(t *testing.T) {
	var h domain2.InterfaceRecordHasher
	coord, _ := fetchdomain.NewModuleCoordinate("example.com/m", "v0.0.1")
	r := domain2.InterfaceRecord{
		SchemaVersion:   domain2.InterfaceSchemaVersion,
		Ecosystem:       fetchdomain.EcosystemGo,
		Coordinate:      coord,
		OverallStatus:   domain2.InterfaceStatusExtractionFailed,
		FailureDetail:   "zip corrupted",
		ExtractedAt:     time.Now().UTC(),
		PipelineVersion: "0.1.0",
	}
	r, err := h.SetContentHash(r)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := h.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	got, err := h.Unmarshal(blob)
	if err != nil {
		t.Fatal(err)
	}
	if got.FailureDetail != r.FailureDetail {
		t.Errorf("FailureDetail: %q vs %q", got.FailureDetail, r.FailureDetail)
	}
}

func TestHasher_EcosystemPresentAfterRoundTrip(t *testing.T) {
	var h domain2.InterfaceRecordHasher
	r, err := h.SetContentHash(makeTestRecord(t))
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	blob, err := h.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(blob), `"ecosystem":"go"`) {
		t.Errorf("canonical JSON missing ecosystem field: %s", blob)
	}
	got, err := h.Unmarshal(blob)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.Ecosystem != fetchdomain.EcosystemGo {
		t.Errorf("Ecosystem after round-trip = %q, want %q", got.Ecosystem, fetchdomain.EcosystemGo)
	}
}

func TestHasher_RejectsForeignEcosystem(t *testing.T) {
	var h domain2.InterfaceRecordHasher
	r := makeTestRecord(t)
	r.Ecosystem = "npm"
	hashed, _ := h.SetContentHash(r)
	blob, err := h.Marshal(hashed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if _, err := h.Unmarshal(blob); !errors.Is(err, fetchdomain.ErrUnsupportedEcosystem) {
		t.Errorf("expected ErrUnsupportedEcosystem, got %v", err)
	}
}
