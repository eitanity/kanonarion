package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/example/application"
	"github.com/eitanity/kanonarion/internal/example/domain"
	"github.com/eitanity/kanonarion/internal/example/ports"
	"github.com/spf13/cobra"
)

type exampleFlags struct {
	force   bool
	history bool
}

// exampleRefJSON is the curated snake_case shape of a stored example
// reference, returned by examples-find.
type exampleRefJSON struct {
	ModulePath       string `json:"module_path"`
	ModuleVersion    string `json:"module_version"`
	PipelineVersion  string `json:"pipeline_version"`
	Package          string `json:"package"`
	AssociatedSymbol string `json:"associated_symbol"`
	ExampleName      string `json:"example_name"`
	Validates        bool   `json:"validates"`
}

// -- examples command --

func newExamplesCmd(stdout, stderr io.Writer) *cobra.Command {
	var f exampleFlags

	cmd := &cobra.Command{
		Use: "examples <module>@<version>",
		Annotations: map[string]string{
			annotationStoreIntent: StoreIntentCreate,
			annotationNetworkUse:  NetworkNever,
		},
		Short: "Harvest and list Example* functions for a Go module",
		Example: `  kanonarion examples github.com/spf13/cobra@v1.8.1
  kanonarion examples github.com/spf13/cobra@v1.8.1 --json
  kanonarion examples github.com/spf13/cobra@v1.8.1 --force`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return usageErr(cmd)
			}
			if len(args) > 1 {
				return fmt.Errorf("accepts 1 arg, received %d", len(args))
			}
			return runExamplesExtract(cmd.Context(), args[0], f, stdout, stderr)
		},
	}

	cmd.Flags().BoolVar(&f.force, "force", false, "re-extract even if cached")
	cmd.Flags().BoolVar(&f.history, "history", false, "show every stored generation for the module instead of extracting")

	return cmd
}

func runExamplesExtract(ctx context.Context, arg string, f exampleFlags, stdout, stderr io.Writer) (retErr error) {
	logger := buildLogger(logLevel, stderr)

	coord, err := parseCoordinate(arg)
	if err != nil {
		return fmt.Errorf("invalid coordinate %q: %w", arg, err)
	}

	ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer releaseStore(cleanup)

	if f.history {
		return runExamplesHistory(ctx, coord, ctr.QueryExamples, stdout)
	}

	result, err := ctr.ExtractExample.Execute(ctx, application.ExtractRequest{
		Coordinate: coord,
		Force:      f.force,
	})
	if err != nil {
		return fmt.Errorf("extracting examples: %w", err)
	}

	if err := printExampleRecord(result.Record, result.FromCache || result.Reused, jsonOut, stdout); err != nil {
		return err
	}
	// The record is stored; the refusal says the examples in some files were
	// never read, which only a newer build of this binary can do.
	defer func() {
		if retErr == nil {
			retErr = analyserLimitExit(result.Record.Coordinate.String()+": "+result.Record.OverallStatus.String(), result.Record.AnalyserLimit)
		}
	}()
	if result.Reused {
		// Said plainly, because the two are different facts and the distinction is
		// the one a reader chasing a stale answer needs: the extraction DID run,
		// and it came back saying what the ledger already said.
		if _, err := fmt.Fprintln(stderr,
			"re-extracted and found identical to the generation already recorded; no new generation was written"); err != nil {
			return fmt.Errorf("writing re-extraction note: %w", err)
		}
	}
	return nil
}

// runExamplesHistory prints every generation the ledger holds for a coordinate,
// oldest first, and marks the one composition serves.
//
// The served record is marked rather than printed alone, because the point of
// the ledger is that the two are different things: what was found now, and what
// was found before and on the strength of which bytes.
func runExamplesHistory(ctx context.Context, coord coordinate.ModuleCoordinate, uc QueryExamplesUseCase, stdout io.Writer) error {
	recs, err := uc.ExampleHistory(ctx, coord, application.PipelineVersion)
	if err != nil {
		return fmt.Errorf("reading example history: %w", err)
	}
	if len(recs) == 0 {
		if _, werr := fmt.Fprintf(stdout, "no example records for %s\n", coord); werr != nil {
			return fmt.Errorf("writing output: %w", werr)
		}
		return nil
	}

	// A conflict is reported, not hidden: the history view is precisely where an
	// operator goes to see why the composed read refused to pick.
	servedHash := ""
	served, found, gerr := uc.GetExampleRecord(ctx, coord, application.PipelineVersion)
	switch {
	case gerr != nil:
		if _, werr := fmt.Fprintf(stdout, "composed answer: unavailable — %v\n\n", gerr); werr != nil {
			return fmt.Errorf("writing output: %w", werr)
		}
	case found:
		servedHash = served.ContentHash
	}

	if _, werr := fmt.Fprintf(stdout, "%d generation(s) for %s at pipeline %s:\n",
		len(recs), coord, application.PipelineVersion); werr != nil {
		return fmt.Errorf("writing output: %w", werr)
	}
	for _, r := range recs {
		marker := " "
		if r.ContentHash != "" && r.ContentHash == servedHash {
			marker = "*"
		}
		artefact := r.ArtefactIdentity
		if artefact == "" {
			artefact = "(no artefact recorded)"
		}
		unread := ""
		if r.AnalyserLimit != nil {
			unread = fmt.Sprintf(", %d file(s) not analysed (%s)", len(r.AnalyserLimit.Files), r.AnalyserLimit.Limit.Clause())
		}
		if _, werr := fmt.Fprintf(stdout,
			"%s %s  %-16s %d example(s), %d parse failure(s)%s\n    artefact: %s\n    record:   %s\n",
			marker, r.ExtractedAt.UTC().Format(time.RFC3339), r.OverallStatus.String(),
			len(r.Examples), len(r.ParseFailures), unread, artefact, r.ContentHash); werr != nil {
			return fmt.Errorf("writing output: %w", werr)
		}
	}
	if _, werr := fmt.Fprintln(stdout,
		"\n* served by the composed read (completed extraction, then fewest parse failures, then most recent)"); werr != nil {
		return fmt.Errorf("writing output: %w", werr)
	}
	return nil
}

func printExampleRecord(r domain.ExampleRecord, fromCache bool, jsonOut bool, stdout io.Writer) error {
	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		// The record's own keys, unchanged, plus the generations the read set
		// aside; absent when there are none.
		doc := struct {
			domain.ExampleRecord
			SetAside []setAsideJSON `json:"set_aside,omitempty"`
		}{r, storeSetAside.take().json()}
		if err := enc.Encode(doc); err != nil {
			return fmt.Errorf("encoding JSON: %w", err)
		}
		return nil
	}

	cached := ""
	if fromCache {
		cached = " (cached)"
	}
	if _, err := fmt.Fprintf(stdout, "%s@%s: %s — %d example(s)%s\n",
		r.Coordinate.Path(), r.Coordinate.Version(),
		r.OverallStatus.String(), len(r.Examples),
		cached,
	); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	if r.FailureDetail != "" {
		if _, err := fmt.Fprintf(stdout, "  failure: %s\n", r.FailureDetail); err != nil {
			return fmt.Errorf("writing failure detail: %w", err)
		}
	}
	if err := writeAnalyserLimit(stdout, "  ", r.AnalyserLimit, "kanonarion examples "+r.Coordinate.String()); err != nil {
		return err
	}
	for _, e := range r.Examples {
		validates := ""
		if e.Validates {
			validates = " [validated]"
		}
		if _, err := fmt.Fprintf(stdout, "  %s (%s) → %s%s\n",
			e.Name, e.Package, e.AssociatedSymbol, validates,
		); err != nil {
			return fmt.Errorf("writing example entry: %w", err)
		}
	}
	for _, pf := range r.ParseFailures {
		if _, err := fmt.Fprintf(stdout, "  [parse failure] %s: %s\n", pf.File, pf.Error); err != nil {
			return fmt.Errorf("writing parse failure: %w", err)
		}
	}
	return nil
}

// -- examples-show command --

func newExamplesShowCmd(stdout, stderr io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use: "examples-show <module>@<version> <example-name>",
		Annotations: map[string]string{
			annotationStoreIntent: StoreIntentRead,
			annotationNetworkUse:  NetworkNever,
		},
		Short: "Show a specific Example* function from the harvested record",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 2 {
				return usageErr(cmd)
			}
			logger := buildLogger(logLevel, stderr)
			ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
			if err != nil {
				return fmt.Errorf("initialising store: %w", err)
			}
			defer releaseStore(cleanup)
			return runExamplesShow(cmd.Context(), args[0], args[1], jsonOut, ctr.QueryExamples, stdout, stderr)
		},
	}

	return cmd
}

func runExamplesShow(ctx context.Context, moduleArg, exampleName string, jsonOut bool, uc QueryExamplesUseCase, stdout, stderr io.Writer) error {
	coord, err := parseCoordinate(moduleArg)
	if err != nil {
		return fmt.Errorf("invalid coordinate %q: %w", moduleArg, err)
	}

	r, found, err := uc.GetExampleRecord(ctx, coord, application.PipelineVersion)
	if err != nil {
		return fmt.Errorf("getting example record: %w", err)
	}
	if !found {
		return exampleRecordMiss(ctx, uc, coord, jsonOut, stderr)
	}

	for _, e := range r.Examples {
		if e.Name != exampleName {
			continue
		}
		if jsonOut {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(e); err != nil {
				return fmt.Errorf("encoding JSON: %w", err)
			}
			return nil
		}
		if _, err := fmt.Fprintf(stdout, "// %s — %s (%s)\n", e.Name, e.AssociatedSymbol, e.Package); err != nil {
			return fmt.Errorf("writing header: %w", err)
		}
		if e.Doc != "" {
			if _, err := fmt.Fprintf(stdout, "// %s\n", e.Doc); err != nil {
				return fmt.Errorf("writing doc: %w", err)
			}
		}
		if _, err := fmt.Fprintf(stdout, "func %s() %s\n", e.Name, e.Body); err != nil {
			return fmt.Errorf("writing body: %w", err)
		}
		return nil
	}

	msg := fmt.Sprintf("example %q not found in record for %s", exampleName, coord)
	// The example may be in a file this record never read; saying only "not
	// found" would deny one nobody looked for.
	if u := r.AnalyserLimit; u != nil {
		msg += "; " + u.Summary()
		if u.Limit.Binds() {
			msg += ". " + u.Limit.Remedy()
		}
	}
	return &exitError{code: ExitNotFound, msg: msg}
}

// -- examples-find command --

func newExamplesFindCmd(stdout, stderr io.Writer) *cobra.Command {
	var scopeFlags buildScopeFlags

	cmd := &cobra.Command{
		Use: "examples-find <symbol>",
		Annotations: map[string]string{
			annotationStoreIntent: StoreIntentRead,
			annotationNetworkUse:  NetworkNever,
		},
		Short: "Find all examples for a symbol across the store",
		Example: `  kanonarion examples-find Client.Do
  kanonarion examples-find Marshal
  kanonarion examples-find Marshal --json
  kanonarion examples-find Marshal --gomod ./go.mod`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageErr(cmd)
			}
			if berr := scopeFlags.bind(cmd); berr != nil {
				return berr
			}
			logger := buildLogger(logLevel, stderr)
			ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
			if err != nil {
				return fmt.Errorf("initialising store: %w", err)
			}
			defer releaseStore(cleanup)
			sc, serr := scopeFlags.resolve(cmd.Context(), ctr.QueryWalks)
			if serr != nil {
				return serr
			}
			return runExamplesFind(cmd.Context(), args[0], jsonOut, ctr.QueryExamples, stdout, sc)
		},
	}

	registerBuildScopeFlags(cmd, &scopeFlags)

	return cmd
}

func runExamplesFind(ctx context.Context, symbol string, jsonOut bool, uc QueryExamplesUseCase, stdout io.Writer, sc buildScope) error {
	// A conflict is carried, not returned: the refs the store COULD resolve are
	// rendered first and the command fails afterwards, so one module whose records
	// composition refused to pick between does not delete every other module's
	// answer. See ports.ErrExampleConflict.
	refs, err := uc.FindBySymbol(ctx, symbol, application.PipelineVersion, sc.modules)
	var conflictErr error
	switch {
	case errors.Is(err, ports.ErrExampleConflict):
		conflictErr = err
	case err != nil:
		return fmt.Errorf("finding examples for %q: %w", symbol, err)
	}

	if !jsonOut {
		if nerr := writeScopeNotice(stdout, sc); nerr != nil {
			return nerr
		}
	}

	if jsonOut {
		out := make([]exampleRefJSON, 0, len(refs))
		for _, r := range refs {
			out = append(out, exampleRefJSON{
				ModulePath:       r.ModulePath,
				ModuleVersion:    r.ModuleVersion,
				PipelineVersion:  r.PipelineVersion,
				Package:          r.Package,
				AssociatedSymbol: r.AssociatedSymbol,
				ExampleName:      r.ExampleName,
				Validates:        r.Validates,
			})
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			return fmt.Errorf("encoding JSON: %w", err)
		}
		return conflictErr
	}

	if len(refs) == 0 {
		if _, err := fmt.Fprintf(stdout, "no examples found for symbol %q\n", symbol); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		return conflictErr
	}
	for _, ref := range refs {
		validates := ""
		if ref.Validates {
			validates = " [validated]"
		}
		if _, err := fmt.Fprintf(stdout, "%-60s %s%s\n",
			ref.ModulePath+"@"+ref.ModuleVersion,
			ref.ExampleName, validates,
		); err != nil {
			return fmt.Errorf("writing ref: %w", err)
		}
	}
	return conflictErr
}

// exampleRecordMiss answers the two commands that name a module whose example
// record the store does not hold. Both already carried the remedy — run
// `kanonarion examples` — and it is kept beside the corpus statement rather than
// replaced by it: a caller whose module has never been harvested needs it
// whether or not other modules have been.
//
// The survey read is on the miss branch. A module whose record was found never
// reaches here, which is what keeps the count off the path these commands take
// on almost every call.
func exampleRecordMiss(ctx context.Context, uc QueryExamplesUseCase, coord coordinate.ModuleCoordinate,
	jsonOut bool, stderr io.Writer,
) error {
	all, err := uc.ListExampleRecords(ctx, ports.ExampleFilter{})
	if err != nil {
		return fmt.Errorf("counting example records for the not-found notice: %w", err)
	}
	scope := listZeroScope{
		subject:     "example record",
		filterName:  "module coordinate",
		filterValue: coord.String(),
		field:       "module coordinate",
		matchKind:   matchExact,
		considered:  len(all),
		produce:     "kanonarion examples " + coord.String(),
		listAll:     "kanonarion examples-list",
		keepProduce: true,
	}
	if len(all) > 0 {
		scope.example = all[0].ModulePath + "@" + all[0].ModuleVersion
	}
	if jsonOut {
		if werr := writeListZeroNoticeJSON(stderr, scope); werr != nil {
			return werr
		}
	}
	return &exitError{code: ExitNotFound, msg: listZeroLine(scope)}
}

// examplesListZeroScope lifts the paging and re-asks the store, so a zero says
// whether the store holds no example record at all or the page starts past the
// last one. This listing takes no filter — a module argument routes to the
// single-module rendering, which fails with ExitNotFound — so the filter cause
// cannot arise and the notice never claims it did. Reached only when the
// listing came back empty.
func examplesListZeroScope(ctx context.Context, offset int, gen listGeneration, uc QueryExamplesUseCase) (listZeroScope, error) {
	all, err := uc.ListExampleRecords(ctx, ports.ExampleFilter{PipelineVersion: gen.filterVersion()})
	if err != nil {
		return listZeroScope{}, fmt.Errorf("counting example records for the zero-result notice: %w", err)
	}
	scope := listZeroScope{
		subject:    "example record",
		considered: len(all),
		produce:    "kanonarion examples <module>@<version>",
		listAll:    "kanonarion examples-list",
	}
	// An empty corpus is not something a page can start past, so a zero over it
	// keeps the store-empty statement and its produce-a-record remedy.
	if len(all) > 0 && offset > 0 && offset >= len(all) {
		scope.pagedPast = fmt.Sprintf("--offset %d starts past the last one", offset)
	}
	return scope, nil
}

// -- examples-list command --

func newExamplesListCmd(stdout, stderr io.Writer) *cobra.Command {
	var limit, offset int
	var allGenerations bool

	cmd := &cobra.Command{
		Use: "examples-list [<module>@<version>]",
		Annotations: map[string]string{
			annotationStoreIntent: StoreIntentRead,
			annotationNetworkUse:  NetworkNever,
		},
		Short: "List example records, or examples within a specific module",
		Long: `examples-list reads back the records 'kanonarion examples' writes, one row per
module coordinate. Given a module coordinate it lists that module's examples
instead.

By default only records at the pipeline version this build serves are listed,
one row per coordinate. A record from an earlier pipeline version answers no
query, so listing it beside the others would pad the count of what is known.
--all-generations includes them and marks each one.`,
		Example: `  kanonarion examples-list
  kanonarion examples-list --all-generations --limit 0
  kanonarion examples-list github.com/charmbracelet/lipgloss@v1.1.0`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 1 {
				return fmt.Errorf("accepts at most 1 argument, received %d", len(args))
			}
			logger := buildLogger(logLevel, stderr)
			ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
			if err != nil {
				return fmt.Errorf("initialising store: %w", err)
			}
			defer releaseStore(cleanup)
			if len(args) == 1 {
				return runExamplesListForModule(cmd.Context(), args[0], ctr.QueryExamples, stdout, stderr)
			}
			return runExamplesList(cmd.Context(), limit, offset, allGenerations, ctr.QueryExamples, stdout, stderr)
		},
	}

	cmd.Flags().IntVar(&limit, "limit", 50, "maximum number of records to return without a module arg (0 = unlimited)")
	cmd.Flags().IntVar(&offset, "offset", 0, "skip this many records")
	cmd.Flags().BoolVar(&allGenerations, "all-generations", false,
		"also list records extracted at a superseded pipeline version, which this build does not serve")

	return cmd
}

func runExamplesListForModule(ctx context.Context, moduleArg string, uc QueryExamplesUseCase, stdout, stderr io.Writer) error {
	coord, err := parseCoordinate(moduleArg)
	if err != nil {
		return fmt.Errorf("invalid coordinate %q: %w", moduleArg, err)
	}

	r, found, err := uc.GetExampleRecord(ctx, coord, application.PipelineVersion)
	if err != nil {
		return fmt.Errorf("getting example record: %w", err)
	}
	if !found {
		return exampleRecordMiss(ctx, uc, coord, jsonOut, stderr)
	}
	// On stderr: both outputs below are bare lists with no room for the fact.
	if err := writeAnalyserLimit(stderr, "", r.AnalyserLimit, "kanonarion examples "+r.Coordinate.String()); err != nil {
		return err
	}
	if jsonOut {
		out := make([]exampleRefJSON, 0, len(r.Examples))
		for _, e := range r.Examples {
			out = append(out, exampleRefJSON{
				ModulePath:       r.Coordinate.Path(),
				ModuleVersion:    r.Coordinate.Version(),
				PipelineVersion:  r.PipelineVersion,
				Package:          e.Package,
				AssociatedSymbol: e.AssociatedSymbol,
				ExampleName:      e.Name,
				Validates:        e.Validates,
			})
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			return fmt.Errorf("encoding JSON: %w", err)
		}
		return nil
	}
	if len(r.Examples) == 0 {
		if _, err := fmt.Fprintf(stdout, "no examples found in %s\n", moduleArg); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		return nil
	}
	for _, e := range r.Examples {
		validates := ""
		if e.Validates {
			validates = " [validated]"
		}
		if _, err := fmt.Fprintf(stdout, "%-45s %s → %s%s\n",
			e.Name, e.Package, e.AssociatedSymbol, validates,
		); err != nil {
			return fmt.Errorf("writing example entry: %w", err)
		}
	}
	return nil
}

// examplesListGeneration is examples-list's generation contract.
func examplesListGeneration(allGenerations bool) listGeneration {
	return pipelineGeneration("example records", application.PipelineVersion, allGenerations,
		"kanonarion examples <module>@<version>")
}

// examplesListEntry is one row of `examples-list --json`.
type examplesListEntry struct {
	Module  string `json:"module"`
	Version string `json:"version"`
	Status  string `json:"status"`
	// PipelineVersion and Superseded are emitted on every row, false included:
	// a consumer reading only the true ones could not tell a servable record
	// from one the pair was never computed for.
	PipelineVersion string `json:"pipeline_version"`
	Superseded      bool   `json:"superseded"`
	ExampleCount    int    `json:"example_count"`
	Conflict        string `json:"conflict,omitempty"`
}

func runExamplesList(ctx context.Context, limit, offset int, allGenerations bool, uc QueryExamplesUseCase, stdout, stderr io.Writer) error {
	gen := examplesListGeneration(allGenerations)
	// One row more than will be printed, so the extra row answers whether the
	// limit bit without a second read.
	sums, err := uc.ListExampleRecords(ctx, ports.ExampleFilter{
		PipelineVersion: gen.filterVersion(),
		Limit:           truncationFetchLimit(limit),
		Offset:          offset,
	})
	if err != nil {
		return fmt.Errorf("listing example records: %w", err)
	}
	sums, truncated := truncateList(sums, limit)
	trunc := listTruncation{limit: limit, subject: gen.subject, truncated: truncated, offset: offset}
	if jsonOut {
		out := make([]examplesListEntry, 0, len(sums))
		var jsonConflicts []error
		for _, s := range sums {
			if s.Conflict != nil {
				jsonConflicts = append(jsonConflicts, s.Conflict)
				out = append(out, examplesListEntry{
					Module: s.ModulePath, Version: s.ModuleVersion,
					Status: "Conflict", Conflict: s.Conflict.Error(),
					PipelineVersion: s.PipelineVersion, Superseded: gen.superseded(s.PipelineVersion),
				})
				continue
			}
			out = append(out, examplesListEntry{
				Module:          s.ModulePath,
				Version:         s.ModuleVersion,
				Status:          s.OverallStatus.String(),
				PipelineVersion: s.PipelineVersion,
				Superseded:      gen.superseded(s.PipelineVersion),
				ExampleCount:    s.ExampleCount,
			})
		}
		var zero *listZeroScope
		if len(out) == 0 {
			scope, serr := examplesListZeroScope(ctx, offset, gen, uc)
			if serr != nil {
				return serr
			}
			zero = &scope
		}
		if derr := writeListDocumentWith(stdout, out, trunc, zero, listDocumentFacts{
			generation: gen.statement(),
		}); derr != nil {
			return derr
		}
		return examplesListConflictErr(jsonConflicts)
	}
	if len(sums) == 0 {
		scope, serr := examplesListZeroScope(ctx, offset, gen, uc)
		if serr != nil {
			return serr
		}
		return writeListZeroNotice(stdout, scope)
	}
	var conflicts []error
	superseded := 0
	for _, s := range sums {
		mark := gen.mark(s.PipelineVersion)
		if mark != "" {
			superseded++
		}
		if s.Conflict != nil {
			conflicts = append(conflicts, s.Conflict)
			if _, err := fmt.Fprintf(stdout, "%-50s %-12s %s%s\n",
				s.ModulePath+"@"+s.ModuleVersion, "CONFLICT",
				"run 'kanonarion examples "+s.ModulePath+"@"+s.ModuleVersion+" --history'", mark); err != nil {
				return fmt.Errorf("writing output: %w", err)
			}
			continue
		}
		if _, err := fmt.Fprintf(stdout, "%-50s %-12s %d example(s)%s\n",
			s.ModulePath+"@"+s.ModuleVersion,
			s.OverallStatus.String(),
			s.ExampleCount,
			mark,
		); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	}
	if gerr := gen.writeNotice(stdout, superseded, len(sums)); gerr != nil {
		return gerr
	}
	if terr := writeListTruncationNotice(stdout, trunc); terr != nil {
		return terr
	}
	// Every module is listed first, then the command fails. A module in dispute
	// must not be reported as a clean run.
	return examplesListConflictErr(conflicts)
}

// examplesListConflictErr fails the run when the listed rows held a disputed
// coordinate. It sees only the rows being listed, so a disagreement inside a
// generation this build does not serve is reported only under --all-generations.
func examplesListConflictErr(conflicts []error) error {
	if len(conflicts) == 0 {
		return nil
	}
	return fmt.Errorf("%d module(s) hold conflicting example records: %w",
		len(conflicts), errors.Join(conflicts...))
}
