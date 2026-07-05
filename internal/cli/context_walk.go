package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

func runContextWalk(ctx context.Context, f contextFlags, stdout, stderr io.Writer) error {
	logger := buildLogger(logLevel, stderr)

	dbPath := filepath.Join(storeRoot, "mirror.db")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return fmt.Errorf("store not found at %s: run a kanonarion command to initialise it", dbPath)
	}

	ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() { _ = cleanup() }()

	rec, err := ctr.QueryWalks.GetWalk(ctx, f.walkID)
	if err != nil {
		if errors.Is(err, walkports.ErrWalkNotFound) {
			return fmt.Errorf("walk %s not found", f.walkID)
		}
		return fmt.Errorf("loading walk %s: %w", f.walkID, err)
	}

	vulnBatch, err := loadVulnBatchCtx(ctx, ctr.QueryScanRuns, ctr.QueryWalks)
	if err != nil {
		return fmt.Errorf("loading vuln batch context: %w", err)
	}

	compact := f.compact && !f.full

	// Build the filtered node list for --direct-only / --affected-only / --modules.
	nodes, err := filterContextWalkNodes(ctx, rec.Graph.Nodes, rec.Target, f, ctr.QueryVuln, ctr.QueryScanRuns, vulnBatch)
	if err != nil {
		return err
	}

	// --size-only with --walk-id: accumulate per-module JSON sizes.
	if f.sizeOnly {
		return runContextWalkSizeOnly(ctx, f, nodes, compact, ctr.QueryVuln, vulnBatch, ctr.QueryFetch, ctr.QueryLicense, ctr.QueryInterface, ctr.QueryCallGraph, ctr.QueryExamples, ctr.QueryWalks, stdout)
	}

	if !jsonOut && !f.stream {
		for _, node := range nodes {
			if err := ctx.Err(); err != nil {
				return fmt.Errorf("context cancelled: %w", err)
			}
			coord := node.Coordinate
			vulns := buildVulnerabilitiesFromBatch(ctx, coord, ctr.QueryVuln, vulnBatch)
			var cmdWalkID string
			if vulns.Status == sectionStatusNotRun {
				cmdWalkID = f.walkID
			}
			out := contextOutput{
				Module:          contextModuleInfo{Path: coord.Path, Version: coord.Version},
				Verification:    buildVerification(ctx, coord, ctr.QueryFetch),
				Provenance:      buildProvenance(coord),
				Dependencies:    buildDependencies(ctx, coord, ctr.QueryWalks),
				License:         buildLicense(ctx, coord, ctr.QueryLicense),
				Interface:       buildInterface(ctx, coord, ctr.QueryInterface, compact, f.packageFilter),
				CallGraph:       buildCallGraph(ctx, coord, ctr.QueryCallGraph, f.entryPointsFull, f.packageFilter),
				Examples:        buildExamples(ctx, coord, ctr.QueryExamples, compact, f.packageFilter),
				Vulnerabilities: vulns,
				Commands:        buildCommandsWithWalk(coord, cmdWalkID),
			}
			if err := printContextText(out, compact, stdout); err != nil {
				return err
			}
			// Add a separator between modules in text output
			if _, err := fmt.Fprintln(stdout, "\n---"); err != nil {
				return fmt.Errorf("writing separator: %w", err)
			}
		}
		return nil
	}

	enc := json.NewEncoder(stdout)
	for _, node := range nodes {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("context cancelled: %w", err)
		}
		coord := node.Coordinate
		vulns := buildVulnerabilitiesFromBatch(ctx, coord, ctr.QueryVuln, vulnBatch)
		var cmdWalkID string
		if vulns.Status == sectionStatusNotRun {
			cmdWalkID = f.walkID
		}
		out := contextOutput{
			Module:          contextModuleInfo{Path: coord.Path, Version: coord.Version},
			Verification:    buildVerification(ctx, coord, ctr.QueryFetch),
			Dependencies:    buildDependencies(ctx, coord, ctr.QueryWalks),
			License:         buildLicense(ctx, coord, ctr.QueryLicense),
			Interface:       buildInterface(ctx, coord, ctr.QueryInterface, compact, f.packageFilter),
			CallGraph:       buildCallGraph(ctx, coord, ctr.QueryCallGraph, f.entryPointsFull, f.packageFilter),
			Examples:        buildExamples(ctx, coord, ctr.QueryExamples, compact, f.packageFilter),
			Vulnerabilities: vulns,
			Commands:        buildCommandsWithWalk(coord, cmdWalkID),
		}
		if err := enc.Encode(out); err != nil {
			return fmt.Errorf("encoding context for %s@%s: %w", coord.Path, coord.Version, err)
		}
	}
	return nil
}

// filterContextWalkNodes applies --direct-only, --affected-only, and --modules
// filters to the graph node list for context --walk-id mode.
func filterContextWalkNodes(
	ctx context.Context,
	nodes []walkdomain.GraphNode,
	root fetchdomain.ModuleCoordinate,
	f contextFlags,
	vulnUC QueryVulnUseCase,
	runsUC QueryScanRunsUseCase,
	vulnBatch *vulnBatchCtx,
) ([]walkdomain.GraphNode, error) {
	// Build coordinate allow-set from --modules file.
	var allowSet map[string]struct{}
	if f.modulesFile != "" {
		data, err := os.ReadFile(filepath.Clean(f.modulesFile))
		if err != nil {
			return nil, fmt.Errorf("reading --modules file %q: %w", f.modulesFile, err)
		}
		allowSet = make(map[string]struct{})
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				allowSet[line] = struct{}{}
			}
		}
	}

	// Pre-compute the affected module set from the most recent scan run for this
	// walk. Resolving from PerModuleResults (always populated after a scan) avoids
	// silently dropping modules that are Affected in the scan but lack an extracted
	// VulnerabilityRecord in the store.
	var affectedSet map[fetchdomain.ModuleCoordinate]struct{}
	if f.affectedOnly && f.walkID != "" {
		var err error
		affectedSet, err = buildAffectedSetForWalk(ctx, runsUC, vulnUC, f.walkID, vulnBatch)
		if err != nil {
			return nil, err
		}
	}

	var out []walkdomain.GraphNode
	for _, node := range nodes {
		if f.directOnly && !node.DirectDependency {
			continue
		}
		if allowSet != nil {
			if _, ok := allowSet[node.Coordinate.String()]; !ok {
				continue
			}
		}
		if f.affectedOnly {
			if affectedSet != nil {
				if _, ok := affectedSet[node.Coordinate]; !ok {
					continue
				}
			} else {
				// Fallback when no walk ID is available: use batch context.
				vulns := buildVulnerabilitiesFromBatch(ctx, node.Coordinate, vulnUC, vulnBatch)
				if vulns.Status != string(vuldomain.StatusAffected) {
					continue
				}
			}
		}
		out = append(out, node)
	}
	return out, nil
}

// buildAffectedSetForWalk returns the set of module coordinates that are
// Affected in the most recent scan run for the given walk. It resolves module
// status from the scan run's PerModuleResults so that modules affected at the
// scan level are included even when no VulnerabilityRecord was extracted.
func buildAffectedSetForWalk(ctx context.Context, runsUC QueryScanRunsUseCase, vulnUC QueryVulnUseCase, walkID string, batch *vulnBatchCtx) (map[fetchdomain.ModuleCoordinate]struct{}, error) {

	// Prefer the in-memory batch to avoid an extra DB round-trip.
	runs := batch.runs[walkID]
	if len(runs) == 0 {
		var err error
		runs, err = runsUC.ListRunsForWalk(ctx, walkID)
		if err != nil {
			return nil, fmt.Errorf("listing scan runs for walk %s: %w", walkID, err)
		}
	}
	if len(runs) == 0 {
		return map[fetchdomain.ModuleCoordinate]struct{}{}, nil
	}

	// runs[0] is the most recent (ListWalkScanRuns returns DESC by started_at).
	run := runs[0]
	affected := make(map[fetchdomain.ModuleCoordinate]struct{}, len(run.PerModuleResults))
	for coord := range run.PerModuleResults {
		// Use the walk-scoped lookup (snapshot-agnostic) so snapshot mismatches
		// don't hide records that were stored under a different snapshot.
		rec, found, err := vulnUC.GetLatestRecordForWalk(ctx, coord, vulnPipelineVersion, run.WalkID)
		if err != nil || !found {
			// Include conservatively: the module was part of this scan run but its
			// record is unavailable — we cannot confirm it is Clean.
			affected[coord] = struct{}{}
			continue
		}
		if rec.OverallStatus == vuldomain.StatusAffected {
			affected[coord] = struct{}{}
		}
	}
	return affected, nil
}

type walkModuleSize struct {
	Module          string `json:"module"`
	EstimatedTokens int    `json:"estimated_tokens"`
	ByteCount       int    `json:"byte_count"`
}

// runContextWalkSizeOnly accumulates JSON sizes for each filtered node and
// prints a total + per-module breakdown without writing context output.
func runContextWalkSizeOnly(
	ctx context.Context,
	f contextFlags,
	nodes []walkdomain.GraphNode,
	compact bool,
	vulnUC QueryVulnUseCase,
	vulnBatch *vulnBatchCtx,
	fetchUC QueryFetchUseCase,
	licUC QueryLicenseUseCase,
	ifaceUC QueryInterfaceUseCase,
	cgUC QueryCallGraphUseCase,
	exUC QueryExamplesUseCase,
	walkUC QueryWalksUseCase,
	stdout io.Writer,
) error {
	var totalBytes int
	sizes := make([]walkModuleSize, 0, len(nodes))

	for _, node := range nodes {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("context cancelled: %w", err)
		}
		coord := node.Coordinate
		vulns := buildVulnerabilitiesFromBatch(ctx, coord, vulnUC, vulnBatch)
		var cmdWalkID string
		if vulns.Status == sectionStatusNotRun {
			cmdWalkID = f.walkID
		}
		out := contextOutput{
			Module:          contextModuleInfo{Path: coord.Path, Version: coord.Version},
			Verification:    buildVerification(ctx, coord, fetchUC),
			Provenance:      buildProvenance(coord),
			Dependencies:    buildDependencies(ctx, coord, walkUC),
			License:         buildLicense(ctx, coord, licUC),
			Interface:       buildInterface(ctx, coord, ifaceUC, compact, f.packageFilter),
			CallGraph:       buildCallGraph(ctx, coord, cgUC, f.entryPointsFull, f.packageFilter),
			Examples:        buildExamples(ctx, coord, exUC, compact, f.packageFilter),
			Vulnerabilities: vulns,
			Commands:        buildCommandsWithWalk(coord, cmdWalkID),
		}
		raw, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return fmt.Errorf("encoding context for %s: %w", coord, err)
		}
		byteCount := len(raw) + 1
		totalBytes += byteCount
		sizes = append(sizes, walkModuleSize{
			Module:          coord.String(),
			EstimatedTokens: byteCount / 4,
			ByteCount:       byteCount,
		})
	}

	if jsonOut {
		type sizeReport struct {
			EstimatedTokens int              `json:"estimated_tokens"`
			ByteCount       int              `json:"byte_count"`
			ModuleCount     int              `json:"module_count"`
			Modules         []walkModuleSize `json:"modules"`
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(sizeReport{
			EstimatedTokens: totalBytes / 4,
			ByteCount:       totalBytes,
			ModuleCount:     len(sizes),
			Modules:         sizes,
		}); err != nil {
			return fmt.Errorf("encoding size report: %w", err)
		}
		return nil
	}

	if _, err := fmt.Fprintf(stdout, "Total: ~%d tokens (%d bytes) across %d modules\n\nPer-module breakdown:\n",
		totalBytes/4, totalBytes, len(sizes)); err != nil {
		return fmt.Errorf("writing size summary: %w", err)
	}
	for _, m := range sizes {
		if _, err := fmt.Fprintf(stdout, "  %s: ~%d tokens (%d bytes)\n", m.Module, m.EstimatedTokens, m.ByteCount); err != nil {
			return fmt.Errorf("writing size entry: %w", err)
		}
	}
	return nil
}
