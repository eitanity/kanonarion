package domain_test

import (
	"errors"
	"strings"
	"testing"

	domain2 "github.com/eitanity/kanonarion/internal/callgraph/domain"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

func TestHasherRoundTrip(t *testing.T) {
	var h domain2.CallGraphRecordHasher
	r := makeTestRecord()

	hashed, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if hashed.ContentHash == "" {
		t.Fatal("ContentHash is empty after SetContentHash")
	}
	if !isValidHash(hashed.ContentHash) {
		t.Errorf("ContentHash %q does not start with sha256:", hashed.ContentHash)
	}

	if err := h.VerifyContentHash(hashed); err != nil {
		t.Errorf("VerifyContentHash: %v", err)
	}

	blob, err := h.Marshal(hashed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	restored, err := h.Unmarshal(blob)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if restored.ContentHash != hashed.ContentHash {
		t.Errorf("ContentHash mismatch after round-trip: got %q, want %q", restored.ContentHash, hashed.ContentHash)
	}
	if restored.Coordinate.Path != hashed.Coordinate.Path {
		t.Errorf("Coordinate.Path mismatch: got %q, want %q", restored.Coordinate.Path, hashed.Coordinate.Path)
	}
	if len(restored.Nodes) != len(hashed.Nodes) {
		t.Errorf("node count mismatch: got %d, want %d", len(restored.Nodes), len(hashed.Nodes))
	}
	if len(restored.Edges) != len(hashed.Edges) {
		t.Errorf("edge count mismatch: got %d, want %d", len(restored.Edges), len(hashed.Edges))
	}
}

func TestHasherVerifyDetectsTampering(t *testing.T) {
	var h domain2.CallGraphRecordHasher
	r := makeTestRecord()

	hashed, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}

	hashed.Nodes = append(hashed.Nodes, domain2.CallNode{ID: "tampered"})
	if err := h.VerifyContentHash(hashed); err == nil {
		t.Error("VerifyContentHash should have returned an error for tampered record")
	}
}

func TestHasherDeterministic(t *testing.T) {
	var h domain2.CallGraphRecordHasher
	r := makeTestRecord()

	h1, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash first: %v", err)
	}
	h2, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash second: %v", err)
	}
	if h1.ContentHash != h2.ContentHash {
		t.Errorf("hashing is non-deterministic: %q vs %q", h1.ContentHash, h2.ContentHash)
	}
}

func TestHasherUnmarshalErrors(t *testing.T) {
	var h domain2.CallGraphRecordHasher

	if _, err := h.Unmarshal([]byte("not json")); err == nil {
		t.Error("Unmarshal should fail on invalid JSON")
	}

	// Valid JSON but invalid extracted_at format.
	badTime := []byte(`{"schema_version":"1","algorithm":"CHA","content_hash":"","coordinate":{"path":"ex.com/m","version":"v1.0.0"},"overall_status":0,"pipeline_version":"0.1.0","edge_count":0,"edges":null,"failure_detail":"","node_count":0,"nodes":null,"extracted_at":"not-a-time"}`)
	if _, err := h.Unmarshal(badTime); err == nil {
		t.Error("Unmarshal should fail on invalid extracted_at")
	}

	// Invalid module coordinate.
	badCoord := []byte(`{"schema_version":"1","algorithm":"CHA","content_hash":"","coordinate":{"path":"","version":""},"overall_status":0,"pipeline_version":"0.1.0","edge_count":0,"edges":null,"failure_detail":"","node_count":0,"nodes":null,"extracted_at":"2025-01-01T00:00:00Z"}`)
	if _, err := h.Unmarshal(badCoord); err == nil {
		t.Error("Unmarshal should fail on invalid coordinate")
	}
}

func TestHasherMarshalRoundTrip_ManyNodes(t *testing.T) {
	var h domain2.CallGraphRecordHasher
	r := makeTestRecord()

	// Add multiple nodes and edges to exercise the sorting and marshalling paths.
	r.Nodes = append(r.Nodes,
		domain2.CallNode{
			ID: "example.com/mod.Beta", Module: "example.com/mod",
			Package: "example.com/mod", Symbol: "Beta",
			Receiver: "*BetaType", IsExternal: false, IsExportedAPI: false,
			Position: domain2.SourcePosition{File: "b.go", Line: 7},
		},
		domain2.CallNode{
			ID: "external.pkg.Ext", Module: "", Package: "external.pkg",
			Symbol: "Ext", IsExternal: true,
		},
	)
	r.Edges = append(r.Edges,
		domain2.CallEdge{
			FromID:     "example.com/mod.Beta",
			ToID:       "external.pkg.Ext",
			CallSite:   domain2.SourcePosition{File: "b.go", Line: 9},
			Confidence: domain2.ConfidenceUnknown,
		},
	)

	hashed, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	blob, err := h.Marshal(hashed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	restored, err := h.Unmarshal(blob)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(restored.Nodes) != len(r.Nodes) {
		t.Errorf("node count: got %d, want %d", len(restored.Nodes), len(r.Nodes))
	}
	if len(restored.Edges) != len(r.Edges) {
		t.Errorf("edge count: got %d, want %d", len(restored.Edges), len(r.Edges))
	}
	if err := h.VerifyContentHash(restored); err != nil {
		t.Errorf("VerifyContentHash after round-trip: %v", err)
	}
}

func TestSortEdgeTieBreaking(t *testing.T) {
	coord, _ := fetchdomain.NewModuleCoordinate("example.com/mod", "v1.0.0")
	r := domain2.CallGraphRecord{
		Coordinate: coord,
		Edges: []domain2.CallEdge{
			{FromID: "A", ToID: "B", CallSite: domain2.SourcePosition{File: "z.go", Line: 1}},
			{FromID: "A", ToID: "B", CallSite: domain2.SourcePosition{File: "a.go", Line: 5}},
			{FromID: "A", ToID: "B", CallSite: domain2.SourcePosition{File: "a.go", Line: 2}},
		},
	}
	r.Sort()
	if r.Edges[0].CallSite.File != "a.go" || r.Edges[0].CallSite.Line != 2 {
		t.Errorf("first edge after sort = %+v, want a.go:2", r.Edges[0])
	}
	if r.Edges[2].CallSite.File != "z.go" {
		t.Errorf("last edge after sort = %+v, want z.go:1", r.Edges[2])
	}
}

func TestSortEdgeSameFromDifferentTo(t *testing.T) {
	coord, _ := fetchdomain.NewModuleCoordinate("example.com/mod", "v1.0.0")
	r := domain2.CallGraphRecord{
		Coordinate: coord,
		Edges: []domain2.CallEdge{
			{FromID: "A", ToID: "Z", CallSite: domain2.SourcePosition{File: "a.go", Line: 1}},
			{FromID: "A", ToID: "B", CallSite: domain2.SourcePosition{File: "a.go", Line: 2}},
		},
	}
	r.Sort()
	if r.Edges[0].ToID != "B" {
		t.Errorf("first edge ToID = %q, want B", r.Edges[0].ToID)
	}
}

// TestMarshalCanonical_AllEdgeSortBranches exercises all four comparison
// branches in the marshalCanonical edge sort by creating edges that differ
// only in FromID, ToID, File, and Line respectively.
func TestMarshalCanonical_AllEdgeSortBranches(t *testing.T) {
	var h domain2.CallGraphRecordHasher
	coord, _ := fetchdomain.NewModuleCoordinate("example.com/mod", "v1.0.0")
	r := domain2.CallGraphRecord{
		SchemaVersion:   domain2.CallGraphSchemaVersion,
		Ecosystem:       fetchdomain.EcosystemGo,
		Coordinate:      coord,
		Algorithm:       domain2.AlgorithmCHA,
		OverallStatus:   domain2.CallGraphStatusExtracted,
		PipelineVersion: "0.1.0",
		ExtractedAt:     makeTestRecord().ExtractedAt,
		Edges: []domain2.CallEdge{
			// Different FromID — exercises branch 1.
			{FromID: "Z", ToID: "B", CallSite: domain2.SourcePosition{File: "z.go", Line: 1}, Confidence: domain2.ConfidenceDirect},
			{FromID: "A", ToID: "B", CallSite: domain2.SourcePosition{File: "a.go", Line: 1}, Confidence: domain2.ConfidenceDirect},
			// Same FromID, different ToID — exercises branch 2.
			{FromID: "A", ToID: "Z", CallSite: domain2.SourcePosition{File: "a.go", Line: 1}, Confidence: domain2.ConfidenceDirect},
			// Same FromID and ToID, different file — exercises branch 3.
			{FromID: "A", ToID: "Z", CallSite: domain2.SourcePosition{File: "z.go", Line: 1}, Confidence: domain2.ConfidenceDirect},
			// Same FromID, ToID, and file, different line — exercises branch 4.
			{FromID: "A", ToID: "Z", CallSite: domain2.SourcePosition{File: "z.go", Line: 9}, Confidence: domain2.ConfidenceDirect},
		},
	}
	hashed, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	blob, err := h.Marshal(hashed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	restored, err := h.Unmarshal(blob)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(restored.Edges) != len(r.Edges) {
		t.Errorf("edge count after round-trip: got %d, want %d", len(restored.Edges), len(r.Edges))
	}
}

func TestHasherVerifyBlobHash(t *testing.T) {
	var h domain2.CallGraphRecordHasher
	r := makeTestRecord()

	hashed, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	blob, err := h.Marshal(hashed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	if err := h.VerifyBlobHash(blob, hashed.ContentHash); err != nil {
		t.Errorf("VerifyBlobHash on valid blob: %v", err)
	}

	if err := h.VerifyBlobHash(blob, "sha256:badhash"); err == nil {
		t.Error("VerifyBlobHash should fail on wrong storedHash")
	}

	tampered := make([]byte, len(blob))
	copy(tampered, blob)
	tampered[len(tampered)-2] ^= 0xff
	if err := h.VerifyBlobHash(tampered, hashed.ContentHash); err == nil {
		t.Error("VerifyBlobHash should fail on tampered blob")
	}

	if err := h.VerifyBlobHash([]byte(`{"no_hash_field":"x"}`), hashed.ContentHash); err == nil {
		t.Error("VerifyBlobHash should fail when content_hash field is absent")
	}
}

func TestHasher_EcosystemPresentAfterRoundTrip(t *testing.T) {
	var h domain2.CallGraphRecordHasher
	hashed, err := h.SetContentHash(makeTestRecord())
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	blob, err := h.Marshal(hashed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(blob), `"ecosystem":"go"`) {
		t.Errorf("canonical JSON missing ecosystem field: %s", blob)
	}
	restored, err := h.Unmarshal(blob)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if restored.Ecosystem != fetchdomain.EcosystemGo {
		t.Errorf("Ecosystem after round-trip = %q, want %q", restored.Ecosystem, fetchdomain.EcosystemGo)
	}
}

func TestHasher_RejectsForeignEcosystem(t *testing.T) {
	var h domain2.CallGraphRecordHasher
	r := makeTestRecord()
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

func isValidHash(h string) bool {
	return len(h) > 7 && h[:7] == "sha256:"
}
