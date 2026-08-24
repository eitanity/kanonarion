package domain_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	domain2 "github.com/eitanity/kanonarion/internal/iface/domain"
)

func makeTestRecord(t *testing.T) domain2.InterfaceRecord {
	t.Helper()
	coord, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.2.3")
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
						// TypeParams exercises the generic-type-parameter round-trip.
						TypeParams: []domain2.TypeParam{{Name: "T", Constraint: "any"}},
					},
				},
				Funcs: []domain2.FuncDecl{
					// TypeParams exercises the generic-func-parameter round-trip.
					{Name: "New", Signature: "func New[T any]() *Client[T]", TypeParams: []domain2.TypeParam{{Name: "T", Constraint: "any"}}},
				},
				Consts: []domain2.ValueDecl{{Name: "DefaultTimeout", Type: "time.Duration"}},
				Vars:   []domain2.ValueDecl{{Name: "ErrClosed", Type: "error"}},
				ParseFailures: []domain2.ParseFailure{
					{File: "broken.go", Error: "syntax error"},
				},
			},
			// A second package, with a different ImportPath, exercises the
			// cross-package sort comparator in marshalCanonical.
			{
				ImportPath: "example.com/mod/sub",
				Name:       "sub",
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
	if got.Coordinate.Path() != r.Coordinate.Path() {
		t.Errorf("Coordinate.Path: %q vs %q", got.Coordinate.Path(), r.Coordinate.Path())
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

func TestHasher_EmptyRecord(t *testing.T) {
	var h domain2.InterfaceRecordHasher
	coord, _ := coordinate.NewModuleCoordinate("example.com/m", "v0.0.1")
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

func TestHasher_Unmarshal_InvalidJSON(t *testing.T) {
	var h domain2.InterfaceRecordHasher
	if _, err := h.Unmarshal([]byte("not json")); err == nil {
		t.Error("Unmarshal() error = nil, want a JSON syntax error")
	}
}

func TestHasher_Unmarshal_MalformedExtractedAt(t *testing.T) {
	var h domain2.InterfaceRecordHasher
	hashed, err := h.SetContentHash(makeTestRecord(t))
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	blob, err := h.Marshal(hashed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	tampered := strings.Replace(string(blob), `"extracted_at":"2026-01-15T10:00:00Z"`, `"extracted_at":"not-a-time"`, 1)
	if _, err := h.Unmarshal([]byte(tampered)); err == nil {
		t.Error("Unmarshal() error = nil, want a parse error for malformed extracted_at")
	}
}

func TestHasher_Unmarshal_MalformedCoordinate(t *testing.T) {
	var h domain2.InterfaceRecordHasher
	hashed, err := h.SetContentHash(makeTestRecord(t))
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	blob, err := h.Marshal(hashed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	tampered := strings.Replace(string(blob), `"path":"example.com/mod"`, `"path":""`, 1)
	if _, err := h.Unmarshal([]byte(tampered)); err == nil {
		t.Error("Unmarshal() error = nil, want a parse error for an invalid coordinate")
	}
}

// TestBuildFrame_AbsentOnRecordsThatNameNone keeps every generation written
// before extraction evaluated build constraints verifiable: the new field is
// omitted from the canonical bytes when the frame is zero, so a stored record's
// hash does not move under it.
func TestBuildFrame_AbsentOnRecordsThatNameNone(t *testing.T) {
	h := domain2.InterfaceRecordHasher{}
	r := recordWithFrame(t, domain2.BuildFrame{})

	data, err := h.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(data), "build_frame") {
		t.Errorf("canonical bytes carry build_frame for a record that names none: %s", data)
	}

	sealed, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if err := h.VerifyContentHash(sealed); err != nil {
		t.Errorf("VerifyContentHash: %v", err)
	}
}

// TestBuildFrame_RoundTripsAndChangesTheSeal states the other half: a record
// that names a frame carries it through the store, and two records measured on
// different platforms are different records rather than one.
func TestBuildFrame_RoundTripsAndChangesTheSeal(t *testing.T) {
	h := domain2.InterfaceRecordHasher{}
	linux := recordWithFrame(t, domain2.BuildFrame{GOOS: "linux", GOARCH: "amd64", CgoEnabled: true})
	windows := recordWithFrame(t, domain2.BuildFrame{GOOS: "windows", GOARCH: "amd64", CgoEnabled: true})

	sealedLinux, err := h.SetContentHash(linux)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	sealedWindows, err := h.SetContentHash(windows)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if sealedLinux.ContentHash == sealedWindows.ContentHash {
		t.Error("two frames produced one content hash: the frame is not inside the seal")
	}
	if domain2.APIDigest(sealedLinux) == domain2.APIDigest(sealedWindows) {
		t.Error("two frames produced one public API digest")
	}

	data, err := h.Marshal(sealedLinux)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	back, err := h.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if back.BuildFrame != linux.BuildFrame {
		t.Errorf("BuildFrame round-tripped as %v, want %v", back.BuildFrame, linux.BuildFrame)
	}
	if !back.Packages[1].OutOfFrame || back.Packages[0].OutOfFrame {
		t.Errorf("OutOfFrame did not round-trip: %v", back.Packages)
	}
	if err := h.VerifyContentHash(back); err != nil {
		t.Errorf("VerifyContentHash after round trip: %v", err)
	}
}

func recordWithFrame(t *testing.T, frame domain2.BuildFrame) domain2.InterfaceRecord {
	t.Helper()
	c, err := coordinate.NewModuleCoordinate("example.com/m", "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	return domain2.InterfaceRecord{
		SchemaVersion: domain2.InterfaceSchemaVersion,
		Ecosystem:     fetchdomain.EcosystemGo,
		Coordinate:    c,
		BuildFrame:    frame,
		Packages: []domain2.PackageInterface{
			{ImportPath: "example.com/m", Name: "m", Funcs: []domain2.FuncDecl{{Name: "F", Signature: "func F()"}}},
			{ImportPath: "example.com/m/plan9", Name: "plan9", OutOfFrame: true},
		},
		OverallStatus:   domain2.InterfaceStatusExtracted,
		ExtractedAt:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		PipelineVersion: "0.4.0",
	}
}
