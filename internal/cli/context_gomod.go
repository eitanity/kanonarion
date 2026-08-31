package cli

import (
	"context"
	"encoding/json"
	"errors"
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
// inspect side. Output is one JSON object when --json is set — the per-module
// documents in its modules array, the scope that selected them and the walk
// their verdicts were read in beside them; otherwise text blocks separated by a
// blank line, each prefixed with a "==> <module>" header line.
//
// --stream selects the newline-delimited stream instead, exactly as it does on
// the --walk-id path: both emit one document per line, and a caller that wants
// the stream but not --json's effect on the rest of its invocation asks for it
// the same way here. Asking for both is asking for the stream.
func runContextGoMod(ctx context.Context, f contextFlags, scope depScope, stdout, stderr io.Writer) error {
	if err := refuseInapplicableFlags("context --gomod",
		append(contextWalkOnlyFlags(f), contextLocalOnlyFlags(f)...)); err != nil {
		return err
	}
	// The complete scope has no test partition to narrow, so the flag is refused
	// against it rather than parsed and dropped: accepting it would emit
	// byte-identical output and report the narrowing as honoured.
	if f.excludeTests && scope == scopeComplete {
		return refuseTestScopeOnCompleteScope("context --gomod")
	}
	// --json frames the documents as the modules array of one envelope, so the
	// whole answer parses as a single document and the run's own facts have
	// somewhere to sit; --stream keeps the newline-delimited stream of per-module
	// documents for a caller that reads one module at a time.
	stream := f.stream
	array := jsonOut && !stream

	logger := buildLogger(logLevel, stderr)

	coords, res, err := resolveScopeModules(f.gomodPath, scope, f.excludeTests)
	if err != nil {
		return fmt.Errorf("resolving %s scope: %w", scope, err)
	}
	// The scope the document set was selected by, stated before the documents,
	// on the channel the vulnerability frame is stated on. An empty scope states
	// it too: which set came back empty is the whole answer there.
	if nerr := writeDepScopeNotice(stderr, res, len(coords), true); nerr != nil {
		return nerr
	}
	scopeField := newScopeJSON(res)
	// The same three facts the notice above states, as the envelope's fields.
	// Built here, from the same resolution and the same count, so the sentence
	// and the document cannot disagree.
	envelope := newEnvelopeScope(res, len(coords), true)
	if len(coords) == 0 {
		return writeEmptyContextScope(f, scope, envelope, array, stream, stdout)
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
	// The go.mod and the scope together name the build, so the latest project
	// walk OF THAT SCOPE is the frame these verdicts are read in. The scope is
	// passed rather than left to recency because --tool and --project already
	// chose the module set printed below: anchoring their verdicts to whichever
	// scope was walked last reports one build's dependencies against another
	// build's scan.
	//
	// A project with no walk of that scope is left unanchored rather than
	// refused: context is a survey, and every section it prints states its own
	// basis. But the miss is stated, because an unanchored survey and an anchored
	// one differ only in a line that is now absent, and a reader who asked for
	// --tool needs to be told which walk to take.
	//
	// The anchor is stated on stderr, and it states its own limit: the walk was
	// found by the module path this manifest declares, and a survey does not
	// re-resolve the manifest to check that the walk still describes it. An
	// anchored batch prints no per-module walk basis — the caller is held to name
	// the build it pinned to — so without this line the pin is invisible, and an
	// invisible pin to a walk taken before the last go.mod edit reads as a
	// statement about the tree in front of the reader.
	var basis basisWalk
	var rooting *contextRooting
	choice, werr := latestWalkForGoMod(ctx, ctr.QueryWalks, f.gomodPath, scope)
	switch {
	case werr != nil:
		rooting = contextRootingUnanchored(werr.Error(), f.gomodPath)
		_, _ = fmt.Fprintf(stderr, "notice: no walk anchors these vulnerability verdicts: %v\n", werr)
	default:
		vulnBatch.anchorTo(ctx, choice.summary.ID)
		// The same walk the verdicts are read in answers the dependency section,
		// so every document in the stream reports one build.
		basis = resolveBasisWalk(ctx, ctr.QueryWalks, choice.summary.ID)
		// The same statement as fields: which walk, chosen rather than named, out
		// of how many, against which manifest and under which toolchain.
		rooting = contextRootingForChoice(choice, f.gomodPath)
		_, _ = fmt.Fprintf(stderr, "notice: vulnerability verdicts read in walk %q (%s, frame %s)%s\n",
			choice.summary.ID, walkScopeLabel(choice.summary.Scope), choice.summary.BuildFrame(),
			choice.basisNotes())
	}

	compact := f.compact && !f.full

	// --size-only asks how much this scope's context would cost before pulling
	// it. Answering with the context itself — 7.9 MB of the very document the
	// caller was budgeting against — is the one answer the flag exists to avoid,
	// so nothing but the report is written.
	var report contextSizeReport

	arr := jsonEnvelopeWriter{out: stdout,
		head: contextEnvelopeHead{envelopeScope: envelope, Rooting: rooting}}

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
			DependencyScope: scopeField,
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

		if eerr := emitContextDocument(coordStr, out, f.sizeOnly, array, stream, compact, &arr, &report, stdout); eerr != nil {
			if errors.Is(eerr, errContextOutputWrite) {
				return eerr
			}
			errs = append(errs, fmt.Errorf("%s: %w", coordStr, eerr))
			continue
		}
	}

	// The envelope is closed before the failures are reported, so a run that lost
	// modules still leaves a parseable document behind holding the ones it got.
	// --size-only wrote no element and answers with its own report below, so
	// there is no envelope to close there.
	if array && !f.sizeOnly {
		if cerr := arr.close(); cerr != nil {
			return cerr
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

// writeEmptyContextScope answers a scope that resolved no modules, in the shape
// the caller asked for.
//
// --size-only asks a size question, so it answers with a zero-module report
// rather than an empty answer of another shape: empty and populated size
// answers decode into the same type. Under --json the empty answer is the same
// envelope with an empty modules array, for the same reason — and it is the one
// answer where the envelope earns its keep on its own, because which scope came
// back empty is the whole of what the run has to say. On the stream an empty
// stream is how "nothing matched" is spelled, so --stream writes zero bytes. The
// prose stays on the text path.
func writeEmptyContextScope(f contextFlags, scope depScope, envelope envelopeScope, array, stream bool, stdout io.Writer) error {
	if f.sizeOnly {
		var report contextSizeReport
		return report.write(jsonOut, stdout)
	}
	if array {
		// No walk was selected: the run stopped at the empty scope, before the
		// build it would have read verdicts in was chosen.
		empty := jsonEnvelopeWriter{out: stdout, head: contextEnvelopeHead{envelopeScope: envelope}}
		return empty.close()
	}
	if !stream {
		_, _ = fmt.Fprintf(stdout, "no %s dependencies found in %s\n", scope, f.gomodPath)
	}
	return nil
}

// emitContextDocument renders one module's document in the form the caller
// asked for: into the size report, into the envelope's modules array, onto the
// newline-delimited stream, or as a text block.
//
// A failure to write is wrapped in errContextOutputWrite, which the caller
// reads as fatal; anything else is that one module's failure and is collected.
func emitContextDocument(coordStr string, out contextOutput, sizeOnly, array, stream, compact bool,
	arr *jsonEnvelopeWriter, report *contextSizeReport, stdout io.Writer) error {
	switch {
	case sizeOnly:
		return report.add(coordStr, out)
	case array:
		return arr.write(out)
	case stream:
		line, merr := json.Marshal(out)
		if merr != nil {
			return fmt.Errorf("encoding: %w", merr)
		}
		if _, werr := fmt.Fprintf(stdout, "%s\n", line); werr != nil {
			return fmt.Errorf("%w: %w", errContextOutputWrite, werr)
		}
		return nil
	default:
		_, _ = fmt.Fprintf(stdout, "==> %s\n", coordStr)
		if perr := printContextText(out, compact, stdout); perr != nil {
			return perr
		}
		_, _ = fmt.Fprintln(stdout)
		return nil
	}
}
