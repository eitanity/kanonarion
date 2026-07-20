package domain_test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
)

func sampleRecord() domain2.FactRecord {
	return domain2.FactRecord{
		SchemaVersion:      "1",
		Ecosystem:          domain2.EcosystemGo,
		ModulePath:         "github.com/gorilla/mux",
		ModuleVersion:      "v1.8.1",
		ModuleHash:         "h1:abc==",
		GoModHash:          "h1:def==",
		GitURL:             "https://github.com/gorilla/mux",
		GitRef:             "refs/tags/v1.8.1",
		GitCommitHash:      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		VerificationStatus: "Verified",
		VerificationDetail: "",
		FetchedAt:          time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		PipelineVersion:    "0.1.0",
		ContentLocation:    "sha256:deadbeef",
	}
}

func TestCanonicalHasher_SetAndVerify(t *testing.T) {
	h := domain2.CanonicalHasher{}
	r := sampleRecord()

	r2, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if r2.ContentHash == "" {
		t.Fatal("ContentHash not set")
	}

	if err := h.VerifyContentHash(r2); err != nil {
		t.Errorf("VerifyContentHash: %v", err)
	}
}

func TestCanonicalHasher_Deterministic(t *testing.T) {
	h := domain2.CanonicalHasher{}
	r1, _ := h.SetContentHash(sampleRecord())
	r2, _ := h.SetContentHash(sampleRecord())
	if r1.ContentHash != r2.ContentHash {
		t.Errorf("non-deterministic: %q vs %q", r1.ContentHash, r2.ContentHash)
	}
}

func TestCanonicalHasher_TamperDetection(t *testing.T) {
	h := domain2.CanonicalHasher{}
	r, _ := h.SetContentHash(sampleRecord())
	r.ModuleHash = "h1:tampered=="
	if err := h.VerifyContentHash(r); err == nil {
		t.Error("expected tamper detection, got nil error")
	}
}

func TestCanonicalHasher_MarshalUnmarshal(t *testing.T) {
	h := domain2.CanonicalHasher{}
	r := sampleRecord()
	r, _ = h.SetContentHash(r)

	data, err := h.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	r2, err := h.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if r2.ContentHash != r.ContentHash {
		t.Errorf("expected hash %q, got %q", r.ContentHash, r2.ContentHash)
	}
	if !r2.FetchedAt.Equal(r.FetchedAt) {
		t.Errorf("expected time %v, got %v", r.FetchedAt, r2.FetchedAt)
	}
	if r2.ModulePath != r.ModulePath {
		t.Errorf("expected path %q, got %q", r.ModulePath, r2.ModulePath)
	}
	if r2.Ecosystem != domain2.EcosystemGo {
		t.Errorf("expected ecosystem %q, got %q", domain2.EcosystemGo, r2.Ecosystem)
	}
}

func TestCanonicalHasher_EcosystemPresentAfterRoundTrip(t *testing.T) {
	h := domain2.CanonicalHasher{}
	r, _ := h.SetContentHash(sampleRecord())

	data, err := h.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !bytes.Contains(data, []byte(`"ecosystem":"go"`)) {
		t.Errorf("canonical JSON missing ecosystem field: %s", data)
	}

	r2, err := h.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if r2.Ecosystem != domain2.EcosystemGo {
		t.Errorf("expected ecosystem %q after round-trip, got %q", domain2.EcosystemGo, r2.Ecosystem)
	}
}

func TestCanonicalHasher_RejectsForeignEcosystem(t *testing.T) {
	h := domain2.CanonicalHasher{}
	r, _ := h.SetContentHash(sampleRecord())
	r.Ecosystem = "npm"
	data, err := h.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if _, err := h.Unmarshal(data); !errors.Is(err, domain2.ErrUnsupportedEcosystem) {
		t.Errorf("expected ErrUnsupportedEcosystem for npm, got %v", err)
	}
}

func TestCanonicalHasher_RejectsAbsentEcosystem(t *testing.T) {
	h := domain2.CanonicalHasher{}
	// A record serialised without the ecosystem field (e.g. a legacy blob).
	if _, err := h.Unmarshal([]byte(`{"schema_version":"3","module_path":"x","module_version":"v1.0.0","fetched_at":"2024-01-01T00:00:00Z"}`)); !errors.Is(err, domain2.ErrUnsupportedEcosystem) {
		t.Errorf("expected ErrUnsupportedEcosystem for absent field, got %v", err)
	}
}

func TestCanonicalHasher_Unmarshal_InvalidJSON(t *testing.T) {
	h := domain2.CanonicalHasher{}
	if _, err := h.Unmarshal([]byte("not json")); err == nil {
		t.Error("Unmarshal() error = nil, want a JSON syntax error")
	}
}

func TestCanonicalHasher_Unmarshal_MalformedFetchedAt(t *testing.T) {
	h := domain2.CanonicalHasher{}
	r, err := h.SetContentHash(sampleRecord())
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	data, err := h.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	tampered := bytes.Replace(data, []byte(`"fetched_at":"2024-01-01T00:00:00Z"`), []byte(`"fetched_at":"not-a-time"`), 1)
	if _, err := h.Unmarshal(tampered); err == nil {
		t.Error("Unmarshal() error = nil, want a parse error for malformed fetched_at")
	}
}
