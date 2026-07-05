package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// runContextGoMod resolves the dependency scope's module set (default code, or
// --tool / --project) and emits a context entry for each one, sharing a single
// DB connection across the loop. The module set matches what `inspect` populates
// for the same scope, so a bare `inspect` followed by a bare `context` composes:
// every module enumerated here was walked, extracted, and vuln-scanned by the
// inspect side. Output is NDJSON when --json is set; otherwise text blocks
// separated by a blank line, each prefixed with a "==> <module>" header line.
func runContextGoMod(ctx context.Context, f contextFlags, scope depScope, stdout, stderr io.Writer) error {
	logger := buildLogger(logLevel, stderr)

	coords, err := resolveScopeModules(f.gomodPath, scope)
	if err != nil {
		return fmt.Errorf("resolving %s scope: %w", scope, err)
	}
	if len(coords) == 0 {
		_, _ = fmt.Fprintf(stdout, "no %s dependencies found in %s\n", scope, f.gomodPath)
		return nil
	}

	dbPath := filepath.Join(storeRoot, "mirror.db")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return fmt.Errorf("store not found at %s: run a kanonarion command to initialise it", dbPath)
	}

	ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() { _ = cleanup() }()

	vulnBatch, err := loadVulnBatchCtx(ctx, ctr.QueryScanRuns, ctr.QueryWalks)
	if err != nil {
		return fmt.Errorf("loading vuln batch context: %w", err)
	}

	compact := f.compact && !f.full

	var errs []error
	for _, coordStr := range coords {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("context cancelled: %w", err)
		}

		coord, err := parseCoordinate(coordStr)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", coordStr, err))
			continue
		}

		vulns := buildVulnerabilitiesFromBatch(ctx, coord, ctr.QueryVuln, vulnBatch)
		var cmdWalkID string
		if vulns.Status == sectionStatusNotRun {
			if walks, werr := ctr.QueryWalks.ListWalks(ctx, walkports.WalkFilter{Target: &coord, Limit: 1}); werr == nil && len(walks) > 0 {
				cmdWalkID = walks[0].ID
			}
		}

		out := contextOutput{
			Module:          contextModuleInfo{Path: coord.Path, Version: coord.Version},
			Commands:        buildCommandsWithWalk(coord, cmdWalkID),
			Verification:    buildVerification(ctx, coord, ctr.QueryFetch),
			Provenance:      buildProvenance(coord),
			Dependencies:    buildDependencies(ctx, coord, ctr.QueryWalks),
			License:         buildLicense(ctx, coord, ctr.QueryLicense),
			Interface:       buildInterface(ctx, coord, ctr.QueryInterface, compact, f.packageFilter),
			CallGraph:       buildCallGraph(ctx, coord, ctr.QueryCallGraph, f.entryPointsFull, f.packageFilter),
			Examples:        buildExamples(ctx, coord, ctr.QueryExamples, compact, f.packageFilter),
			Vulnerabilities: vulns,
		}

		if jsonOut {
			line, merr := json.Marshal(out)
			if merr != nil {
				errs = append(errs, fmt.Errorf("%s: encoding: %w", coordStr, merr))
				continue
			}
			if _, werr := fmt.Fprintf(stdout, "%s\n", line); werr != nil {
				return fmt.Errorf("writing output: %w", werr)
			}
		} else {
			_, _ = fmt.Fprintf(stdout, "==> %s\n", coordStr)
			if perr := printContextText(out, compact, stdout); perr != nil {
				errs = append(errs, fmt.Errorf("%s: %w", coordStr, perr))
				continue
			}
			_, _ = fmt.Fprintln(stdout)
		}
	}

	if len(errs) > 0 {
		for _, e := range errs {
			_, _ = fmt.Fprintf(stderr, "error: %v\n", e)
		}
		return fmt.Errorf("%d module(s) failed", len(errs))
	}
	return nil
}
