package application_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/vuln/application"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// slowScanner simulates govulncheck with a fixed delay.
type slowScanner struct {
	delay time.Duration
}

func (s *slowScanner) Scan(_ context.Context, req ports.ScanRequest) (domain.VulnerabilityRecord, error) {
	time.Sleep(s.delay)
	return domain.VulnerabilityRecord{
		Coordinate:       req.Coordinate,
		OverallStatus:    domain.StatusClean,
		DatabaseSnapshot: req.Snapshot,
	}, nil
}

func (s *slowScanner) ScanProject(_ context.Context, _ string, _ domain.DatabaseSnapshot, _ string) (domain.ProjectScanResult, error) {
	time.Sleep(s.delay)
	return domain.ProjectScanResult{Status: domain.StatusClean}, nil
}

// ScanTargetModule reports a fault so the benchmark keeps measuring the
// isolated per-module pool it exists to measure, rather than collapsing to one
// target-rooted scan.
func (s *slowScanner) ScanTargetModule(_ context.Context, _ ports.TargetScanRequest) (domain.ProjectScanResult, error) {
	return domain.ProjectScanResult{
		Status:            domain.StatusUnscannable,
		UnscannableReason: "slow-fake: target-rooted scanning not benchmarked",
	}, nil
}

func (s *slowScanner) Preflight(_ context.Context) error { return nil }

func (s *slowScanner) ScannerMetadata() ports.ScannerMetadata {
	return ports.ScannerMetadata{Name: "slow-fake", Version: "v0"}
}

func buildBenchScanWalk(n int) (walkdomain.WalkRecord, []coordinate.ModuleCoordinate) {
	nodes := make([]walkdomain.GraphNode, n)
	coords := make([]coordinate.ModuleCoordinate, n)
	for i := range n {
		c := coordinate.ModuleCoordinate{Path: fmt.Sprintf("github.com/pkg/m%d", i), Version: "v1.0.0"}
		nodes[i] = walkdomain.GraphNode{Coordinate: c}
		coords[i] = c
	}
	id := fmt.Sprintf("bench-scan-walk-%d", n)
	return walkdomain.WalkRecord{ID: id, Graph: walkdomain.Graph{Nodes: nodes}}, coords
}

// BenchmarkVulnScan_Sequential_vs_Parallel measures the worker-pool speedup.
// Each scan sleeps 100 ms to model govulncheck subprocess overhead. Force=true
// bypasses the cache so every iteration invokes the scanner.
// Sequential wall time ≈ N×100 ms; parallel (4 workers) ≈ ceil(N/4)×100 ms.
func BenchmarkVulnScan_Sequential_vs_Parallel(b *testing.B) {
	const scanDelay = 100 * time.Millisecond
	ctx := context.Background()
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := fixedClock{t: now}
	snap := domain.DatabaseSnapshot{Source: "bench", Version: "v1"}
	silentLogger := slog.New(slog.NewTextHandler(io.Discard, nil))

	for _, n := range []int{4, 8, 16} {
		walk, coords := buildBenchScanWalk(n)

		// Mark all modules as potentially vulnerable so the slow scanner is invoked.
		vulnerables := make(map[coordinate.ModuleCoordinate][]string, n)
		for _, c := range coords {
			vulnerables[c] = []string{"GO-BENCH-VULN"}
		}

		ws := newFakeWalkStore()
		if err := ws.PutWalk(ctx, walk); err != nil {
			b.Fatal(err)
		}
		blobs := newFakeBlob()
		facts := newFakeFacts()
		for _, c := range coords {
			h, _ := blobs.Put(ctx, strings.NewReader("zip"))
			if err := facts.PutFetchRecord(ctx, fetchdomain.FactRecord{
				ModulePath: c.Path, ModuleVersion: c.Version, PipelineVersion: "v1", ContentLocation: string(h),
			}); err != nil {
				b.Fatal(err)
			}
		}
		db := &fakeDatabase{snapshot: snap, vulnerables: vulnerables}

		b.Run(fmt.Sprintf("modules=%d/workers=1", n), func(b *testing.B) {
			vulnStore := newFakeVulnStore()
			_ = vulnStore.PutDatabaseSnapshot(ctx, snap, strings.NewReader(""))
			moduleUC := application.NewScanModuleUseCase(
				facts, blobs, vulnStore, ws, &slowScanner{delay: scanDelay},
				db, nil, clock, "v1", "v1", silentLogger,
			)
			walkUC := application.NewScanWalkUseCase(
				ws, vulnStore, moduleUC, nil, clock, "v1", silentLogger,
			)
			params := application.ScanWalkParams{
				WalkID:   walk.ID,
				Snapshot: &snap,
				Force:    true, // bypass cache so slowScanner fires every iteration
				Workers:  1,
			}
			b.ResetTimer()
			for range b.N {
				if _, err := walkUC.Scan(ctx, params); err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run(fmt.Sprintf("modules=%d/workers=parallel", n), func(b *testing.B) {
			vulnStore := newFakeVulnStore()
			_ = vulnStore.PutDatabaseSnapshot(ctx, snap, strings.NewReader(""))
			moduleUC := application.NewScanModuleUseCase(
				facts, blobs, vulnStore, ws, &slowScanner{delay: scanDelay},
				db, nil, clock, "v1", "v1", silentLogger,
			)
			walkUC := application.NewScanWalkUseCase(
				ws, vulnStore, moduleUC, nil, clock, "v1", silentLogger,
			)
			params := application.ScanWalkParams{
				WalkID:   walk.ID,
				Snapshot: &snap,
				Force:    true,
				Workers:  0, // min(NumCPU, 4)
			}
			b.ResetTimer()
			for range b.N {
				if _, err := walkUC.Scan(ctx, params); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
