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

	"github.com/eitanity/kanonarion/internal/coordinate"

	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// contextWalkRecord loads the walk `context --walk-id` was pointed at, and is
// the seam the miss is exercisable through: the command builds its own
// container, so without it the one branch that answers a mistyped id could only
// be reached with a live store.
func contextWalkRecord(ctx context.Context, uc QueryWalksUseCase, walkID string, stderr io.Writer,
) (walkdomain.WalkRecord, error) {
	rec, err := uc.GetWalk(ctx, walkID)
	if err != nil {
		if errors.Is(err, walkports.ErrWalkNotFound) {
			return walkdomain.WalkRecord{}, walkIDMiss(ctx, uc, walkID, stderr)
		}
		return walkdomain.WalkRecord{}, fmt.Errorf("loading walk %s: %w", walkID, err)
	}
	return rec, nil
}

func runContextWalk(ctx context.Context, f contextFlags, stdout, stderr io.Writer) error {
	refused := append(contextLocalOnlyFlags(f), contextGoModOnlyFlags(f)...)
	refused = append(refused, contextTestScopeFlag(f)...)
	if err := refuseInapplicableFlags("context --walk-id", refused); err != nil {
		return err
	}

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

	rec, err := contextWalkRecord(ctx, ctr.QueryWalks, f.walkID, stderr)
	if err != nil {
		return err
	}

	vulnBatch, err := loadVulnBatchCtx(ctx, ctr.QueryScanRuns, ctr.QueryWalks)
	if err != nil {
		return fmt.Errorf("loading vuln batch context: %w", err)
	}
	// The report is about this walk, so every module's verdict is read in this
	// walk's frame and from this walk's runs, and its dependency section is
	// resolved out of this walk's graph.
	vulnBatch.anchorTo(ctx, f.walkID)
	basis := walkAsBasis(rec)

	compact := f.compact && !f.full

	// Build the filtered node list for --direct-only / --affected-only / --modules.
	nodes, err := filterContextWalkNodes(ctx, rec.Graph.Nodes, rec.Target, f, ctr.QueryVuln, ctr.QueryScanRuns, vulnBatch)
	if err != nil {
		return err
	}

	// --size-only with --walk-id: accumulate per-module JSON sizes.
	if f.sizeOnly {
		return runContextWalkSizeOnly(ctx, f, nodes, compact, ctr.QueryVuln, vulnBatch, ctr.QueryFetch, ctr.QueryLicense, ctr.StdlibCustody, ctr.QueryInterface, ctr.QueryCallGraph, ctr.QueryExamples, ctr.QueryWalks, basis, stdout)
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
				Module:          contextModuleInfo{Path: coord.Path(), Version: coord.Version()},
				Verification:    buildVerification(ctx, coord, ctr.QueryFetch),
				Provenance:      buildProvenance(coord),
				Dependencies:    buildDependencies(ctx, coord, ctr.QueryWalks, basis),
				License:         buildLicense(ctx, coord, ctr.QueryLicense, ctr.StdlibCustody),
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

	// --json frames the documents as one array so the whole answer parses as a
	// single document; --stream keeps the newline-delimited stream for a caller
	// that reads one module at a time. Asking for both is asking for the stream.
	arr := jsonArrayWriter{out: stdout}
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
			Module:          contextModuleInfo{Path: coord.Path(), Version: coord.Version()},
			Verification:    buildVerification(ctx, coord, ctr.QueryFetch),
			Dependencies:    buildDependencies(ctx, coord, ctr.QueryWalks, basis),
			License:         buildLicense(ctx, coord, ctr.QueryLicense, ctr.StdlibCustody),
			Interface:       buildInterface(ctx, coord, ctr.QueryInterface, compact, f.packageFilter),
			CallGraph:       buildCallGraph(ctx, coord, ctr.QueryCallGraph, f.entryPointsFull, f.packageFilter),
			Examples:        buildExamples(ctx, coord, ctr.QueryExamples, compact, f.packageFilter),
			Vulnerabilities: vulns,
			Commands:        buildCommandsWithWalk(coord, cmdWalkID),
		}
		if f.stream {
			if err := enc.Encode(out); err != nil {
				return fmt.Errorf("encoding context for %s@%s: %w", coord.Path(), coord.Version(), err)
			}
			continue
		}
		if err := arr.write(out); err != nil {
			return fmt.Errorf("encoding context for %s@%s: %w", coord.Path(), coord.Version(), err)
		}
	}
	if f.stream {
		return nil
	}
	// An empty selection — every node filtered out — still answers with [].
	return arr.close()
}

// filterContextWalkNodes applies --direct-only, --affected-only, and --modules
// filters to the graph node list for context --walk-id mode.
func filterContextWalkNodes(
	ctx context.Context,
	nodes []walkdomain.GraphNode,
	_ coordinate.ModuleCoordinate,
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
		for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
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
	var affectedSet map[coordinate.ModuleCoordinate]struct{}
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
func buildAffectedSetForWalk(ctx context.Context, runsUC QueryScanRunsUseCase, vulnUC QueryVulnUseCase, walkID string, batch *vulnBatchCtx) (map[coordinate.ModuleCoordinate]struct{}, error) {

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
		return map[coordinate.ModuleCoordinate]struct{}{}, nil
	}

	// runs[0] is the most recent (ListWalkScanRuns returns DESC by started_at).
	return affectedSetForRun(ctx, vulnUC, runs[0], batch.frameFor(ctx, walkID))
}

// affectedSetForRun resolves the set of module coordinates that are Affected in
// a single scan run, reading each module's per-module verdict from its
// VulnerabilityRecord.
//
// A store read error is a fault, not a verdict: it is propagated, never
// fabricated into an Affected entry. A not-found record is a coverage gap (the
// run lists the coordinate but nothing backs a verdict): it is no evidence of
// Affected, so it is skipped. Only a real StatusAffected record adds a
// coordinate.
func affectedSetForRun(ctx context.Context, vulnUC QueryVulnUseCase, run vuldomain.WalkScanRun, anchor vulnFrameAnchor) (map[coordinate.ModuleCoordinate]struct{}, error) {
	affected := make(map[coordinate.ModuleCoordinate]struct{}, len(run.PerModuleResults))
	for coord := range run.PerModuleResults {
		// Walk-scoped (snapshot-agnostic) so a snapshot mismatch does not hide a
		// record, and selected in the walk's own frame so another project's scan
		// of a shared dependency cannot decide whether this walk is affected.
		rec, found, err := recordInWalkFrame(ctx, vulnUC, coord, anchor)
		if err != nil {
			return nil, fmt.Errorf("reading verdict for %s in walk %s: %w", coord, run.WalkID, err)
		}
		if !found {
			continue
		}
		// A findings question, asked of the findings axis: a module whose coordinate
		// matched an advisory is affected whether or not its source could be
		// analysed, and the collapsed word reports only one of those two facts.
		if _, findings := vuldomain.RecordAxes(rec); findings == vuldomain.FindingsRecordAffected {
			affected[coord] = struct{}{}
		}
	}
	return affected, nil
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
	stdlibCustody StdlibCustodyReader,
	ifaceUC QueryInterfaceUseCase,
	cgUC QueryCallGraphUseCase,
	exUC QueryExamplesUseCase,
	walkUC QueryWalksUseCase,
	basis basisWalk,
	stdout io.Writer,
) error {
	var report contextSizeReport

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
			Module:          contextModuleInfo{Path: coord.Path(), Version: coord.Version()},
			Verification:    buildVerification(ctx, coord, fetchUC),
			Provenance:      buildProvenance(coord),
			Dependencies:    buildDependencies(ctx, coord, walkUC, basis),
			License:         buildLicense(ctx, coord, licUC, stdlibCustody),
			Interface:       buildInterface(ctx, coord, ifaceUC, compact, f.packageFilter),
			CallGraph:       buildCallGraph(ctx, coord, cgUC, f.entryPointsFull, f.packageFilter),
			Examples:        buildExamples(ctx, coord, exUC, compact, f.packageFilter),
			Vulnerabilities: vulns,
			Commands:        buildCommandsWithWalk(coord, cmdWalkID),
		}
		if err := report.add(coord.String(), out); err != nil {
			return err
		}
	}

	return report.write(jsonOut, stdout)
}
