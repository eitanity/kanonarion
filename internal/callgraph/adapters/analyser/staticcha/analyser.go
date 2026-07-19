package staticcha

import (
	"context"
	"fmt"
	"go/token"
	"log/slog"
	"os"
	"runtime"
	"strings"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/packages"
)

const analyserVersion = "0.1.0"

// Analyser implements cgports.CallGraphAnalyser using CHA.
type Analyser struct {
	pipelineVersion string
	goBinary        string
	logger          *slog.Logger
}

// New constructs an Analyser.
func New(pipelineVersion string, goBinary string, logger *slog.Logger) *Analyser {
	return &Analyser{pipelineVersion: pipelineVersion, goBinary: goBinary, logger: logger}
}

// AnalyserMetadata returns the algorithm and version of this implementation.
func (a *Analyser) AnalyserMetadata() cgports.AnalyserMetadata {
	return cgports.AnalyserMetadata{
		Algorithm: domain.AlgorithmCHA,
		Version:   analyserVersion,
	}
}

func (a *Analyser) logMem(ctx context.Context, phase string) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	a.logger.DebugContext(ctx, "callgraph_memory_telemetry",
		slog.String("phase", phase),
		slog.Uint64("alloc_mb", m.Alloc/1024/1024),
		slog.Uint64("total_alloc_mb", m.TotalAlloc/1024/1024),
		slog.Uint64("sys_mb", m.Sys/1024/1024),
		slog.Uint64("heap_alloc_mb", m.HeapAlloc/1024/1024),
		slog.Uint64("heap_objects", m.HeapObjects),
		slog.Int("num_gc", int(m.NumGC)),
	)
}

// Analyse extracts the call graph from a module zip using CHA.
func (a *Analyser) Analyse(ctx context.Context, zipPath string, coord fetchdomain.ModuleCoordinate) (domain.CallGraphRecord, error) {
	a.logMem(ctx, "start")
	tempDir, err := os.MkdirTemp("", "kanonarion-cg-*")
	if err != nil {
		return domain.CallGraphRecord{}, fmt.Errorf("creating temp dir: %w", err)
	}
	defer func() {
		if rerr := os.RemoveAll(tempDir); rerr != nil {
			a.logger.WarnContext(ctx, "callgraph_temp_cleanup_failed",
				slog.String("error", rerr.Error()),
				slog.String("dir", tempDir),
			)
		}
	}()

	modulePrefix := coord.Path + "@" + coord.Version + "/"
	if err := extractModuleZip(zipPath, modulePrefix, tempDir); err != nil {
		return a.failRecord(coord, domain.CallGraphStatusLoadFailed, domain.CompletenessFailed,
			"extracting module zip: "+err.Error()), nil
	}

	if ctx.Err() != nil {
		return a.failRecord(coord, domain.CallGraphStatusCancelled, domain.CompletenessUnknown, "cancelled before load"), nil
	}

	return a.analyseDir(ctx, tempDir, coord)
}

// AnalyseDir runs the same CHA pipeline as Analyse but against an on-disk Go
// module working tree instead of a fetched module zip. It is used for
// local-analysis ingestion so kanonarion can answer
// callers/callees for its own internal packages. coord.Path must be the
// module path declared in the directory's go.mod; coord.Version is a
// synthetic local version (e.g. "v0.0.0").
func (a *Analyser) AnalyseDir(ctx context.Context, dir string, coord fetchdomain.ModuleCoordinate) (domain.CallGraphRecord, error) {
	a.logMem(ctx, "start")
	// Cancellation is observed inside analyseDir (packages.Load honours ctx,
	// plus explicit ctx.Err checkpoints), so no pre-check is needed here.
	return a.analyseDir(ctx, dir, coord)
}

// analyseDir holds the shared post-extraction analysis pipeline: load
// packages from dir, build SSA, run CHA, and walk the graph into a
// CallGraphRecord. dir is either an extracted-zip temp dir (Analyse) or a
// local working tree (AnalyseDir).
func (a *Analyser) analyseDir(ctx context.Context, tempDir string, coord fetchdomain.ModuleCoordinate) (domain.CallGraphRecord, error) {
	fset := token.NewFileSet()

	envCleanup, err := a.setupGoEnv(ctx, tempDir)
	if err != nil {
		return a.failRecord(coord, domain.CallGraphStatusLoadFailed, domain.CompletenessFailed, err.Error()), nil
	}
	defer envCleanup()

	// New Architecture: Multi-pass load to bypass go/packages memory limitations.
	// Step 1: Discover ALL packages in the transitive dependency graph (metadata only).
	// This ensures we know about every package that might be imported.
	cfgMeta := &packages.Config{
		Mode:    packages.NeedName | packages.NeedImports | packages.NeedDeps,
		Dir:     tempDir,
		Context: ctx,
		Tests:   false,
	}

	pkgsMeta, err := packages.Load(cfgMeta, "./...")
	if err != nil {
		return a.failRecord(coord, domain.CallGraphStatusLoadFailed, domain.CompletenessFailed, "meta load: "+err.Error()), nil
	}
	a.logMem(ctx, "meta_loaded")

	if len(pkgsMeta) == 0 {
		return a.failRecord(coord, domain.CallGraphStatusLoadFailed, domain.CompletenessFailed, "no packages found"), nil
	}

	// New Architecture: Streaming SSA Construction.
	// We load and process target packages in small batches to keep peak memory low.
	var targetPkgPaths []string
	packages.Visit(pkgsMeta, nil, func(p *packages.Package) {
		isTarget := p.PkgPath == coord.Path || strings.HasPrefix(p.PkgPath, coord.Path+"/")
		if isTarget {
			targetPkgPaths = append(targetPkgPaths, p.PkgPath)
		}
	})

	prog, targetSSAPkgs, allLoadErrs, failedPkgs, err := a.loadAndBuildSSA(ctx, fset, tempDir, coord, targetPkgPaths)
	if err != nil {
		return a.failRecord(coord, domain.CallGraphStatusLoadFailed, domain.CompletenessFailed, err.Error()), nil
	}

	// Step 4: Final Cleanup and Call Graph Construction
	runtime.GC()
	a.logMem(ctx, "all_batches_processed")

	if len(targetSSAPkgs) == 0 {
		detail := "no packages successfully loaded"
		if len(allLoadErrs) > 0 {
			detail = joinFirst(allLoadErrs, 3)
		}
		return a.failRecord(coord, domain.CallGraphStatusLoadFailed, domain.CompletenessMetadataOnly, detail), nil
	}

	if ctx.Err() != nil {
		return a.failRecord(coord, domain.CallGraphStatusCancelled, domain.CompletenessUnknown, "cancelled after streaming load"), nil
	}

	a.logger.InfoContext(ctx, "callgraph_streaming_load_completed",
		slog.Int("target_pkg_count", len(targetSSAPkgs)),
		slog.Int("load_errors", len(allLoadErrs)),
	)

	// Step 3: Call Graph Construction (CHA)
	a.logMem(ctx, "pre_cha")
	cg := cha.CallGraph(prog)
	a.logMem(ctx, "post_cha")

	// Ensure GC can reclaim memory before starting walk
	runtime.GC()

	// Pre-filter to the caller nodes walkGraph records — module functions plus
	// dependency functions built with real bodies — to save memory during walk.
	recordedCallers := recordedCallerNodes(cg, coord)

	// Ensure GC can reclaim memory before starting walk
	runtime.GC()

	nodes, edges, overallStatus := a.walkGraph(ctx, cg, recordedCallers, coord, fset, tempDir)

	// Attach body-level capability facts. These are properties of a
	// function's own body — unsafe.Pointer conversions, assembly/linkname
	// leaves — that the call graph and package sink map cannot witness. Scan
	// only the packages that appear as graph nodes so the extra syntax load is
	// bounded by the graph rather than the full dependency set.
	a.attachBodyFacts(ctx, nodes, tempDir)

	// Recover client-side interface-dispatch edges CHA drops when the sole
	// implementer's body was never built into SSA (type-only dep / unbuilt
	// package). Runs after body facts so those only scan built module bodies;
	// devirtualized leaf targets carry no onward edges.
	nodes, edges = a.devirtualizeSingleImplementer(ctx, prog, coord, fset, tempDir, nodes, edges)

	// A failed package (or any load error) means the graph is incomplete;
	// never report Extracted when some target package did not resolve. Keeping
	// FailedPackages and the Partial status in lock-step is what lets the query
	// layer trust FailedPackages as the completeness signal.
	if (len(allLoadErrs) > 0 || len(failedPkgs) > 0) && overallStatus == domain.CallGraphStatusExtracted {
		overallStatus = domain.CallGraphStatusPartial
	}

	rec := domain.CallGraphRecord{
		SchemaVersion: domain.CallGraphSchemaVersion,
		Ecosystem:     fetchdomain.EcosystemGo,
		Coordinate:    coord,
		Algorithm:     domain.AlgorithmCHA,
		// Reaching here means at least one target package was built into SSA with
		// bodies. Per-package build failures are carried in FailedPackages (and
		// force Partial below); the module-level fidelity is still bodies-built.
		Completeness:    domain.CompletenessBuiltWithBodies,
		Nodes:           nodes,
		Edges:           edges,
		OverallStatus:   overallStatus,
		NodeCount:       len(nodes),
		EdgeCount:       len(edges),
		PipelineVersion: a.pipelineVersion,
	}
	if len(allLoadErrs) > 0 {
		rec.FailureDetail = joinFirst(allLoadErrs, 3)
	}
	// FailedPackages scopes the incompleteness to the exact packages that did
	// not typecheck, so callers/callees/reachability verdicts over this Partial
	// graph can be caveated per package rather than by node/edge totals.
	rec.FailedPackages = failedPkgs
	rec.Sort()
	return rec, nil
}

// failRecord builds a no-graph record for a fatal extraction outcome. completeness
// is the fidelity the module reached before failing: FAILED when nothing usable
// loaded, METADATA_ONLY when package metadata loaded but no SSA was built, and
// Unknown for a transient outcome (cancellation) that makes no fidelity claim.
func (a *Analyser) failRecord(coord fetchdomain.ModuleCoordinate, status domain.CallGraphStatus, completeness domain.CompletenessLevel, detail string) domain.CallGraphRecord {
	return domain.CallGraphRecord{
		SchemaVersion:   domain.CallGraphSchemaVersion,
		Ecosystem:       fetchdomain.EcosystemGo,
		Coordinate:      coord,
		Algorithm:       domain.AlgorithmCHA,
		Completeness:    completeness,
		OverallStatus:   status,
		FailureDetail:   detail,
		PipelineVersion: a.pipelineVersion,
	}
}

func joinFirst(ss []string, n int) string {
	if len(ss) > n {
		ss = ss[:n]
	}
	return strings.Join(ss, "; ")
}

// Ensure Analyser implements cgports.CallGraphAnalyser at compile time.
var _ cgports.CallGraphAnalyser = (*Analyser)(nil)
