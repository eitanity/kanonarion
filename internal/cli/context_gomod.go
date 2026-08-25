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
//
// --stream selects the NDJSON stream without --json, exactly as it does on the
// --walk-id path: both emit one document per module, and a caller that wants
// the stream but not --json's effect on the rest of its invocation asks for it
// the same way here.
func runContextGoMod(ctx context.Context, f contextFlags, scope depScope, stdout, stderr io.Writer) error {
	if err := refuseInapplicableFlags("context --gomod",
		append(contextWalkOnlyFlags(f), contextLocalOnlyFlags(f)...)); err != nil {
		return err
	}
	ndjson := jsonOut || f.stream

	logger := buildLogger(logLevel, stderr)

	coords, err := resolveScopeModules(f.gomodPath, scope)
	if err != nil {
		return fmt.Errorf("resolving %s scope: %w", scope, err)
	}
	if len(coords) == 0 {
		if f.sizeOnly {
			// --size-only asks a size question, so an empty scope answers it with a
			// zero-module report rather than the NDJSON empty stream: empty and
			// populated size answers decode into the same type.
			var report contextSizeReport
			return report.write(jsonOut, stdout)
		}
		// NDJSON: an empty stream is how "nothing matched" is spelled, so under
		// --json (or --stream) emit zero stdout bytes. The prose stays on the
		// text path only.
		if !ndjson {
			_, _ = fmt.Fprintf(stdout, "no %s dependencies found in %s\n", scope, f.gomodPath)
		}
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
	// The go.mod names the build, so its own latest project walk is the frame
	// these verdicts are read in. A project with no walk yet is left unanchored
	// rather than refused: context is a survey, and every section it prints
	// states its own basis.
	//
	// The anchor is stated on stderr, and it states its own limit: the walk was
	// found by the module path this manifest declares, and a survey does not
	// re-resolve the manifest to check that the walk still describes it. An
	// anchored batch prints no per-module walk basis — the caller is held to name
	// the build it pinned to — so without this line the pin is invisible, and an
	// invisible pin to a walk taken before the last go.mod edit reads as a
	// statement about the tree in front of the reader.
	var basis basisWalk
	if choice, werr := latestWalkForGoMod(ctx, ctr.QueryWalks, f.gomodPath); werr == nil {
		vulnBatch.anchorTo(ctx, choice.summary.ID)
		// The same walk the verdicts are read in answers the dependency section,
		// so every document in the stream reports one build.
		basis = resolveBasisWalk(ctx, ctr.QueryWalks, choice.summary.ID)
		_, _ = fmt.Fprintf(stderr, "notice: vulnerability verdicts read in walk %q (frame %s)%s%s\n",
			choice.summary.ID, choice.summary.BuildFrame(), choice.stalenessNote(), choice.statementClause())
	}

	compact := f.compact && !f.full

	// --size-only asks how much this scope's context would cost before pulling
	// it. Answering with the context itself — 7.9 MB of the very document the
	// caller was budgeting against — is the one answer the flag exists to avoid,
	// so nothing but the report is written.
	var report contextSizeReport

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
			// The id only fills in a suggested `vuln-scan <walk-id>` command line,
			// exactly as in the single-coordinate path; no answer is read from this
			// walk, so no selection rule applies to it. See the same lookup in
			// runContext for why.
			if walks, werr := ctr.QueryWalks.ListWalks(ctx, walkports.WalkFilter{Target: &coord, Limit: 1}); werr == nil && len(walks) > 0 {
				cmdWalkID = walks[0].ID
			}
		}

		out := contextOutput{
			Module:          contextModuleInfo{Path: coord.Path(), Version: coord.Version()},
			Commands:        buildCommandsWithWalk(coord, cmdWalkID),
			Verification:    buildVerification(ctx, coord, ctr.QueryFetch),
			Provenance:      buildProvenance(coord),
			Dependencies:    buildDependencies(ctx, coord, ctr.QueryWalks, basis),
			License:         buildLicense(ctx, coord, ctr.QueryLicense, ctr.StdlibCustody),
			Interface:       buildInterface(ctx, coord, ctr.QueryInterface, compact, f.packageFilter),
			CallGraph:       buildCallGraph(ctx, coord, ctr.QueryCallGraph, f.entryPointsFull, f.packageFilter),
			Examples:        buildExamples(ctx, coord, ctr.QueryExamples, compact, f.packageFilter),
			Vulnerabilities: vulns,
		}

		switch {
		case f.sizeOnly:
			if serr := report.add(coordStr, out); serr != nil {
				errs = append(errs, serr)
				continue
			}
		case ndjson:
			line, merr := json.Marshal(out)
			if merr != nil {
				errs = append(errs, fmt.Errorf("%s: encoding: %w", coordStr, merr))
				continue
			}
			if _, werr := fmt.Fprintf(stdout, "%s\n", line); werr != nil {
				return fmt.Errorf("writing output: %w", werr)
			}
		default:
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

	if f.sizeOnly {
		return report.write(jsonOut, stdout)
	}
	return nil
}
