package application

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/extract/domain"
	"github.com/eitanity/kanonarion/internal/extract/ports"

	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// slowExtractor simulates a real extraction stage with a fixed per-call delay.
type slowExtractor struct {
	delay time.Duration
}

func (s *slowExtractor) Extract(_ context.Context, _ coordinate.ModuleCoordinate, stage string, _ bool) (ports.StageResult, error) {
	time.Sleep(s.delay)
	return ports.StageResult{Status: domain.StageSucceeded, RecordID: "rec-" + stage}, nil
}

func buildBenchWalk(n int) walkdomain.WalkRecord {
	nodes := make([]walkdomain.GraphNode, n)
	for i := range n {
		c, _ := coordinate.NewModuleCoordinate(fmt.Sprintf("github.com/pkg/m%d", i), "v1.0.0")
		nodes[i] = walkdomain.GraphNode{Coordinate: c}
	}
	return walkdomain.WalkRecord{
		ID:    fmt.Sprintf("bench-walk-%d", n),
		Graph: walkdomain.Graph{Nodes: nodes},
	}
}

// BenchmarkExtract_Sequential_vs_Parallel measures the speedup from the worker
// pool. Each stage sleeps 20 ms to model subprocess/parsing overhead.
// Sequential wall time ≈ N×stages×20 ms; parallel ≈ ceil(N/W)×stages×20 ms.
func BenchmarkExtract_Sequential_vs_Parallel(b *testing.B) {
	const stageDelay = 20 * time.Millisecond
	stages := []string{"license", "interface"}

	for _, n := range []int{4, 8, 16} {
		walk := buildBenchWalk(n)
		ws := &mockWalkStore{walks: map[string]walkdomain.WalkRecord{walk.ID: walk}}

		b.Run(fmt.Sprintf("modules=%d/workers=1", n), func(b *testing.B) {
			rs := &mockExtractionStore{runs: make(map[string]domain.ExtractionRun)}
			uc := NewExtractUseCase(Config{
				Runs:      rs,
				Walks:     ws,
				Extractor: &slowExtractor{delay: stageDelay},
				Clock:     fakeClock{t: testClockTime},
				Stopwatch: fakeStopwatch{},
				Workers:   1,
			})
			req := ExtractRequest{WalkID: walk.ID, Stages: stages}
			b.ResetTimer()
			for range b.N {
				if _, err := uc.Execute(context.Background(), req); err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run(fmt.Sprintf("modules=%d/workers=parallel", n), func(b *testing.B) {
			rs := &mockExtractionStore{runs: make(map[string]domain.ExtractionRun)}
			uc := NewExtractUseCase(Config{
				Runs:      rs,
				Walks:     ws,
				Extractor: &slowExtractor{delay: stageDelay},
				Clock:     fakeClock{t: testClockTime},
				Stopwatch: fakeStopwatch{},
				Workers:   0, // runtime.NumCPU()
			})
			req := ExtractRequest{WalkID: walk.ID, Stages: stages}
			b.ResetTimer()
			for range b.N {
				if _, err := uc.Execute(context.Background(), req); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
