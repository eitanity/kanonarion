package domain_test

import (
	"fmt"
	"testing"
	"time"

	domain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// makeLargeRecord builds a record with n nodes and n edges to simulate a
// large module like x/tools.
func makeLargeRecord(n int) domain.CallGraphRecord {
	coord, _ := fetchdomain.NewModuleCoordinate("example.com/mod", "v1.0.0")
	nodes := make([]domain.CallNode, n)
	edges := make([]domain.CallEdge, n)
	for i := range nodes {
		id := fmt.Sprintf("example.com/mod.Func%d", i)
		nodes[i] = domain.CallNode{
			ID:            id,
			Module:        "example.com/mod",
			Package:       "example.com/mod",
			Symbol:        fmt.Sprintf("Func%d", i),
			IsExportedAPI: i%2 == 0,
			Position:      domain.SourcePosition{File: fmt.Sprintf("f%d.go", i), Line: i + 1},
		}
		toID := fmt.Sprintf("example.com/mod.Func%d", (i+1)%n)
		edges[i] = domain.CallEdge{
			FromID:     id,
			ToID:       toID,
			CallSite:   domain.SourcePosition{File: fmt.Sprintf("f%d.go", i), Line: i + 2},
			Confidence: domain.ConfidenceDirect,
		}
	}
	return domain.CallGraphRecord{
		SchemaVersion:   domain.CallGraphSchemaVersion,
		Coordinate:      coord,
		Algorithm:       domain.AlgorithmCHA,
		Nodes:           nodes,
		Edges:           edges,
		OverallStatus:   domain.CallGraphStatusExtracted,
		NodeCount:       n,
		EdgeCount:       n,
		ExtractedAt:     time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		PipelineVersion: "0.1.0",
	}
}

// BenchmarkVerifyBlobHash benchmarks the fast in-place blob verification path
// introduced in, which avoids deserialisation and re-serialisation.
func BenchmarkVerifyBlobHash(b *testing.B) {
	for _, n := range []int{10, 100, 1000} {
		r := makeLargeRecord(n)
		var h domain.CallGraphRecordHasher
		hashed, err := h.SetContentHash(r)
		if err != nil {
			b.Fatalf("SetContentHash: %v", err)
		}
		blob, err := h.Marshal(hashed)
		if err != nil {
			b.Fatalf("Marshal: %v", err)
		}
		storedHash := hashed.ContentHash
		b.Run(fmt.Sprintf("nodes=%d/blob_bytes=%d", n, len(blob)), func(b *testing.B) {
			b.SetBytes(int64(len(blob)))
			b.ResetTimer()
			for range b.N {
				if err := h.VerifyBlobHash(blob, storedHash); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkVerifyContentHash benchmarks the old path that unmarshals and
// re-serialises the full record for comparison.
func BenchmarkVerifyContentHash(b *testing.B) {
	for _, n := range []int{10, 100, 1000} {
		r := makeLargeRecord(n)
		var h domain.CallGraphRecordHasher
		hashed, err := h.SetContentHash(r)
		if err != nil {
			b.Fatalf("SetContentHash: %v", err)
		}
		blob, err := h.Marshal(hashed)
		if err != nil {
			b.Fatalf("Marshal: %v", err)
		}
		b.Run(fmt.Sprintf("nodes=%d/blob_bytes=%d", n, len(blob)), func(b *testing.B) {
			b.SetBytes(int64(len(blob)))
			b.ResetTimer()
			for range b.N {
				restored, err := h.Unmarshal(blob)
				if err != nil {
					b.Fatal(err)
				}
				if err := h.VerifyContentHash(restored); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
