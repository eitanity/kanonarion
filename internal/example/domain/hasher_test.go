package domain_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	domain2 "github.com/eitanity/kanonarion/internal/example/domain"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

func buildExampleRecord(t *testing.T) domain2.ExampleRecord {
	t.Helper()
	coord := mustCoord(t, "example.com/mod", "v1.0.0")
	return domain2.ExampleRecord{
		SchemaVersion: domain2.ExampleSchemaVersion,
		Ecosystem:     fetchdomain.EcosystemGo,
		Coordinate:    coord,
		Examples: []domain2.ExampleEntry{
			// Multiple entries to exercise sort comparison branches:
			// same package+symbol, different name (branch 3 in marshalCanonicalExample).
			{
				Name:             "ExampleFoo",
				Package:          "mod_test",
				AssociatedSymbol: "Foo",
				Body:             "{\n\tfmt.Println(\"hello\")\n}",
				Output:           "hello",
				Imports:          []string{"fmt"},
				Doc:              "ExampleFoo shows Foo usage.",
				Position:         domain2.SourcePosition{File: "foo_test.go", Line: 10},
				Validates:        true,
			},
			{
				Name:             "ExampleFoo_second",
				Package:          "mod_test",
				AssociatedSymbol: "Foo",
				SubExample:       "second",
				Body:             "{\n\tfmt.Println(\"hi\")\n}",
				Imports:          []string{"fmt"},
				Position:         domain2.SourcePosition{File: "foo_test.go", Line: 20},
			},
			// Different symbol in same package (branch 2).
			{
				Name:             "ExampleBar",
				Package:          "mod_test",
				AssociatedSymbol: "Bar",
				Body:             "{}",
				Position:         domain2.SourcePosition{File: "bar_test.go", Line: 5},
			},
			// Different package (branch 1).
			{
				Name:             "ExampleBaz",
				Package:          "sub_test",
				AssociatedSymbol: "Baz",
				Body:             "{}",
				Position:         domain2.SourcePosition{File: "sub/baz_test.go", Line: 1},
			},
		},
		ParseFailures: []domain2.ParseFailure{
			// Two entries with different File to exercise the sort comparator
			// in marshalCanonicalExample.
			{File: "broken_test.go", Error: "syntax error"},
			{File: "another_test.go", Error: "unexpected EOF"},
		},
		OverallStatus:   domain2.ExampleStatusFound,
		ExtractedAt:     time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		PipelineVersion: "0.1.0",
	}
}

func TestSetAndVerifyContentHash(t *testing.T) {
	var h domain2.ExampleRecordHasher
	r := buildExampleRecord(t)

	r, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if r.ContentHash == "" {
		t.Fatal("ContentHash must not be empty after SetContentHash")
	}
	if err := h.VerifyContentHash(r); err != nil {
		t.Fatalf("VerifyContentHash: %v", err)
	}
}

func TestVerifyContentHash_Tampered(t *testing.T) {
	var h domain2.ExampleRecordHasher
	r := buildExampleRecord(t)
	r, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}

	r.Examples[0].Body = "tampered"
	if err := h.VerifyContentHash(r); err == nil {
		t.Fatal("VerifyContentHash should fail for tampered record")
	}
}

func TestMarshalUnmarshal_RoundTrip(t *testing.T) {
	var h domain2.ExampleRecordHasher
	r := buildExampleRecord(t)
	r, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}

	data, err := h.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	got, err := h.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if got.ContentHash != r.ContentHash {
		t.Errorf("ContentHash: got %q, want %q", got.ContentHash, r.ContentHash)
	}
	if got.OverallStatus != r.OverallStatus {
		t.Errorf("OverallStatus: got %v, want %v", got.OverallStatus, r.OverallStatus)
	}
	if len(got.Examples) != len(r.Examples) {
		t.Fatalf("Examples length: got %d, want %d", len(got.Examples), len(r.Examples))
	}
	if len(got.ParseFailures) != len(r.ParseFailures) {
		t.Fatalf("ParseFailures length: got %d, want %d", len(got.ParseFailures), len(r.ParseFailures))
	}
	// Find ExampleFoo by name (the unmarshalled record is sorted).
	var foo *domain2.ExampleEntry
	for i := range got.Examples {
		if got.Examples[i].Name == "ExampleFoo" {
			foo = &got.Examples[i]
			break
		}
	}
	if foo == nil {
		t.Fatal("ExampleFoo not found in unmarshalled record")
	} else if !foo.Validates {
		t.Error("ExampleFoo.Validates: got false, want true")
	}
}

func TestUnmarshal_BadJSON(t *testing.T) {
	var h domain2.ExampleRecordHasher
	_, err := h.Unmarshal([]byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestUnmarshal_BadExtractedAt(t *testing.T) {
	var h domain2.ExampleRecordHasher
	data := []byte(`{"extracted_at":"not-a-date","coordinate":{"path":"example.com/m","version":"v1.0.0"}}`)
	_, err := h.Unmarshal(data)
	if err == nil {
		t.Fatal("expected error for invalid extracted_at")
	}
}

func TestUnmarshal_BadCoordinate(t *testing.T) {
	var h domain2.ExampleRecordHasher
	// Empty path is invalid for a ModuleCoordinate.
	data := []byte(`{"extracted_at":"2025-01-01T00:00:00Z","coordinate":{"path":"","version":"v1.0.0"}}`)
	_, err := h.Unmarshal(data)
	if err == nil {
		t.Fatal("expected error for invalid coordinate")
	}
}

func TestSetContentHash_Deterministic(t *testing.T) {
	var h domain2.ExampleRecordHasher
	r1 := buildExampleRecord(t)
	r2 := buildExampleRecord(t)

	r1, err := h.SetContentHash(r1)
	if err != nil {
		t.Fatalf("SetContentHash r1: %v", err)
	}
	r2, err = h.SetContentHash(r2)
	if err != nil {
		t.Fatalf("SetContentHash r2: %v", err)
	}

	if r1.ContentHash != r2.ContentHash {
		t.Errorf("hashes differ for identical records: %q vs %q", r1.ContentHash, r2.ContentHash)
	}
}

func TestHasher_EcosystemPresentAfterRoundTrip(t *testing.T) {
	var h domain2.ExampleRecordHasher
	r, err := h.SetContentHash(buildExampleRecord(t))
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
	var h domain2.ExampleRecordHasher
	r := buildExampleRecord(t)
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

func TestHasher_Unmarshal_MalformedExtractedAt(t *testing.T) {
	var h domain2.ExampleRecordHasher
	r := buildExampleRecord(t)
	hashed, _ := h.SetContentHash(r)
	blob, err := h.Marshal(hashed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	tampered := strings.Replace(string(blob), `"extracted_at":"2025-01-01T00:00:00Z"`, `"extracted_at":"not-a-time"`, 1)
	if _, err := h.Unmarshal([]byte(tampered)); err == nil {
		t.Error("Unmarshal() error = nil, want a parse error for malformed extracted_at")
	}
}

func TestHasher_Unmarshal_MalformedCoordinate(t *testing.T) {
	var h domain2.ExampleRecordHasher
	r := buildExampleRecord(t)
	hashed, _ := h.SetContentHash(r)
	blob, err := h.Marshal(hashed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	tampered := strings.Replace(string(blob), `"path":"example.com/mod"`, `"path":""`, 1)
	if _, err := h.Unmarshal([]byte(tampered)); err == nil {
		t.Error("Unmarshal() error = nil, want a parse error for an invalid coordinate")
	}
}
