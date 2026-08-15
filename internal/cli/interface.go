package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	ifaceapp "github.com/eitanity/kanonarion/internal/iface/application"
	"github.com/eitanity/kanonarion/internal/iface/domain"
	"github.com/eitanity/kanonarion/internal/iface/ports"
	"github.com/spf13/cobra"
)

type ifaceFlags struct {
	force   bool
	history bool
}

// -- interface command --

func newInterfaceCmd(stdout, stderr io.Writer) *cobra.Command {
	var f ifaceFlags

	cmd := &cobra.Command{
		Use:   "interface <module>@<version>",
		Short: "Extract and summarise the public API of a Go module",
		Example: `  kanonarion interface github.com/spf13/cobra@v1.8.1
  kanonarion interface github.com/spf13/cobra@v1.8.1 --json
  kanonarion interface github.com/spf13/cobra@v1.8.1 --force`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return usageErr(cmd)
			}
			if len(args) > 1 {
				return fmt.Errorf("accepts 1 arg, received %d", len(args))
			}
			return runInterfaceExtract(cmd.Context(), args[0], f, stdout, stderr)
		},
	}

	cmd.Flags().BoolVar(&f.force, "force", false, "re-extract even if cached")
	cmd.Flags().BoolVar(&f.history, "history", false, "show every stored generation for the module instead of extracting")

	return cmd
}

func runInterfaceExtract(ctx context.Context, arg string, f ifaceFlags, stdout, stderr io.Writer) error {
	logger := buildLogger(logLevel, stderr)

	coord, err := parseCoordinate(arg)
	if err != nil {
		return fmt.Errorf("invalid coordinate %q: %w", arg, err)
	}

	ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() { _ = cleanup() }()

	if f.history {
		return runInterfaceHistory(ctx, coord, ctr.QueryInterface, stdout)
	}

	result, err := ctr.ExtractInterface.Execute(ctx, ifaceapp.ExtractRequest{
		Coordinate: coord,
		Force:      f.force,
	})
	if err != nil {
		return fmt.Errorf("extracting interface: %w", err)
	}

	return printInterfaceRecord(result.Record, result.FromCache, jsonOut, stdout)
}

// runInterfaceHistory prints every generation the ledger holds for a coordinate,
// oldest first, and marks the one composition serves.
//
// For this domain the history view is also where a reported non-determination is
// examined: the two records that disagree are both listed, with the digest of
// what each of them says the API is.
func runInterfaceHistory(ctx context.Context, coord coordinate.ModuleCoordinate, uc QueryInterfaceUseCase, stdout io.Writer) error {
	recs, err := uc.InterfaceHistory(ctx, coord, ifaceapp.PipelineVersion)
	if err != nil {
		return fmt.Errorf("reading interface history: %w", err)
	}
	if len(recs) == 0 {
		// The history is read at the serving pipeline version, so a coordinate
		// whose generations are all superseded has an empty history and a full
		// ledger. Saying "no records" would deny records that are still here.
		line := fmt.Sprintf("no interface records for %s", coord)
		if all, lerr := uc.ListInterfaceRecords(ctx, ports.InterfaceFilter{}); lerr == nil {
			if pipelines, superseded := supersededInterfacePipelines(coord, all); superseded {
				line = supersededInterfaceLine(coord, pipelines)
			}
		}
		if _, werr := fmt.Fprintf(stdout, "%s\n", line); werr != nil {
			return fmt.Errorf("writing output: %w", werr)
		}
		return nil
	}

	// A conflict is reported, not hidden: the history view is precisely where an
	// operator goes to see why the composed read refused to pick.
	servedHash := ""
	served, found, gerr := uc.GetInterfaceRecord(ctx, coord, ifaceapp.PipelineVersion)
	switch {
	case gerr != nil:
		if _, werr := fmt.Fprintf(stdout, "composed answer: unavailable — %v\n\n", gerr); werr != nil {
			return fmt.Errorf("writing output: %w", werr)
		}
	case found:
		servedHash = served.ContentHash
	}

	if _, werr := fmt.Fprintf(stdout, "%d generation(s) for %s at pipeline %s:\n",
		len(recs), coord, ifaceapp.PipelineVersion); werr != nil {
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
		if _, werr := fmt.Fprintf(stdout,
			"%s %s  %-16s %d package(s)\n    artefact: %s\n    api:      %s\n    record:   %s\n",
			marker, r.ExtractedAt.UTC().Format(time.RFC3339), r.OverallStatus.String(),
			len(r.Packages), artefact, domain.APIDigest(r), r.ContentHash); werr != nil {
			return fmt.Errorf("writing output: %w", werr)
		}
	}
	if _, werr := fmt.Fprintln(stdout,
		"\n* served by the composed read (a complete extraction outranks a Partial one, then most recent)"); werr != nil {
		return fmt.Errorf("writing output: %w", werr)
	}
	return nil
}

func printInterfaceRecord(r domain.InterfaceRecord, fromCache bool, jsonOut bool, stdout io.Writer) error {
	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(toInterfaceRecordJSON(r)); err != nil {
			return fmt.Errorf("encoding JSON: %w", err)
		}
		return nil
	}

	cached := ""
	if fromCache {
		cached = " (cached)"
	}
	if _, err := fmt.Fprintf(stdout, "%s@%s: %s — %d package(s)%s\n",
		r.Coordinate.Path(), r.Coordinate.Version(),
		r.OverallStatus.String(), len(r.Packages), cached,
	); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	if r.FailureDetail != "" {
		if _, err := fmt.Fprintf(stdout, "  failure: %s\n", r.FailureDetail); err != nil {
			return fmt.Errorf("writing failure detail: %w", err)
		}
	}
	for _, pkg := range r.Packages {
		if _, err := fmt.Fprintf(stdout, "  %-60s %dT %dF %dC %dV\n",
			pkg.ImportPath,
			len(pkg.Types), len(pkg.Funcs), len(pkg.Consts), len(pkg.Vars),
		); err != nil {
			return fmt.Errorf("writing package line: %w", err)
		}
	}
	return nil
}

// -- interface-show command --

func newInterfaceShowCmd(stdout, stderr io.Writer) *cobra.Command {
	var pkgFilter, symbolFilter string

	cmd := &cobra.Command{
		Use:   "interface-show <module>@<version>",
		Short: "Show the full interface record for a module",
		Example: `  kanonarion interface-show github.com/spf13/cobra@v1.8.1
  kanonarion interface-show github.com/spf13/cobra@v1.8.1 --package github.com/spf13/cobra
  kanonarion interface-show github.com/spf13/cobra@v1.8.1 --symbol Command`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageErr(cmd)
			}
			return runInterfaceShow(cmd.Context(), args[0], pkgFilter, symbolFilter, jsonOut, stdout, stderr)
		},
	}

	cmd.Flags().StringVar(&pkgFilter, "package", "", "filter to a specific import path")
	cmd.Flags().StringVar(&symbolFilter, "symbol", "", "filter to a specific symbol name")

	return cmd
}

func runInterfaceShow(ctx context.Context, moduleArg, pkgFilter, symbolFilter string, jsonOut bool, stdout, stderr io.Writer) error {
	coord, err := parseCoordinate(moduleArg)
	if err != nil {
		return fmt.Errorf("invalid coordinate %q: %w", moduleArg, err)
	}

	logger := buildLogger(logLevel, stderr)
	ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() { _ = cleanup() }()

	r, found, err := ctr.QueryInterface.GetInterfaceRecord(ctx, coord, ifaceapp.PipelineVersion)
	if err != nil {
		return fmt.Errorf("getting interface record: %w", err)
	}
	if !found {
		return interfaceRecordMiss(ctx, ctr.QueryInterface, coord, jsonOut, stderr)
	}

	// Promotion is resolved against the whole record, before any filter: a type
	// printed alone still reports what its embeddings make callable on it.
	idx := newPromotionIndex(r)

	// Apply filters.
	if pkgFilter != "" || symbolFilter != "" {
		r = filterRecord(r, pkgFilter, symbolFilter)
	}

	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(toInterfaceRecordJSON(r)); err != nil {
			return fmt.Errorf("encoding JSON: %w", err)
		}
		return nil
	}

	return printRecordText(r, idx, stdout)
}

func filterRecord(r domain.InterfaceRecord, pkgFilter, symbolFilter string) domain.InterfaceRecord {
	var pkgs []domain.PackageInterface
	for _, pkg := range r.Packages {
		if pkgFilter != "" && pkg.ImportPath != pkgFilter {
			continue
		}
		if symbolFilter != "" {
			pkg = filterPackageSymbol(pkg, symbolFilter)
		}
		pkgs = append(pkgs, pkg)
	}
	r.Packages = pkgs
	return r
}

func filterPackageSymbol(pkg domain.PackageInterface, sym string) domain.PackageInterface {
	var types []domain.TypeDecl
	for _, t := range pkg.Types {
		if strings.EqualFold(t.Name, sym) {
			types = append(types, t)
		}
	}
	var funcs []domain.FuncDecl
	for _, f := range pkg.Funcs {
		if strings.EqualFold(f.Name, sym) {
			funcs = append(funcs, f)
		}
	}
	var consts []domain.ValueDecl
	for _, c := range pkg.Consts {
		if strings.EqualFold(c.Name, sym) {
			consts = append(consts, c)
		}
	}
	var vars []domain.ValueDecl
	for _, v := range pkg.Vars {
		if strings.EqualFold(v.Name, sym) {
			vars = append(vars, v)
		}
	}
	pkg.Types = types
	pkg.Funcs = funcs
	pkg.Consts = consts
	pkg.Vars = vars
	return pkg
}

// -- symbol-find command --

func newSymbolFindCmd(stdout, stderr io.Writer) *cobra.Command {
	var scopeFlags buildScopeFlags

	cmd := &cobra.Command{
		Use:   "symbol-find <name>",
		Short: "Find all modules that export a symbol with the given name",
		Example: `  kanonarion symbol-find Client
  kanonarion symbol-find Marshal
  kanonarion symbol-find Marshal --json
  kanonarion symbol-find Marshal --gomod ./go.mod`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageErr(cmd)
			}
			scopeFlags.bind(cmd)
			return runSymbolFind(cmd.Context(), args[0], scopeFlags, jsonOut, stdout, stderr)
		},
	}

	registerBuildScopeFlags(cmd, &scopeFlags)

	return cmd
}

func runSymbolFind(ctx context.Context, symbolName string, scopeFlags buildScopeFlags, jsonOut bool, stdout, stderr io.Writer) error {
	logger := buildLogger(logLevel, stderr)
	ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() { _ = cleanup() }()

	sc, err := scopeFlags.resolve(ctx, ctr.QueryWalks)
	if err != nil {
		return err
	}

	// A conflict is carried, not returned: the refs the store COULD resolve are
	// rendered first and the command fails afterwards, so one module whose records
	// composition refused to pick between does not delete every other module's
	// answer. See ports.ErrInterfaceConflict.
	refs, err := ctr.QueryInterface.FindSymbol(ctx, symbolName, ifaceapp.PipelineVersion, sc.modules)
	var conflictErr error
	switch {
	case errors.Is(err, ports.ErrInterfaceConflict):
		conflictErr = err
	case err != nil:
		return fmt.Errorf("finding symbol %q: %w", symbolName, err)
	}

	// An empty result over an empty interface store is "nothing analysed",
	// not "analysed, no such export" — the two must be distinguishable
	// symbol-find takes a bare name with no module to
	// classify, so the absence test is whether any interface record exists.
	if len(refs) == 0 {
		recs, lerr := ctr.QueryInterface.ListInterfaceRecords(ctx, ports.InterfaceFilter{})
		if lerr != nil {
			return fmt.Errorf("listing analysed modules: %w", lerr)
		}
		if len(recs) == 0 {
			return fmt.Errorf(
				"symbol %q cannot be resolved: the interface store is empty, nothing "+
					"has been analysed. Analyse a module first, e.g.:\n"+
					"  kanonarion interface <module>@<version>\n"+
					"  kanonarion local .   # for this project's own symbols",
				symbolName)
		}
		// A store full of records this build refuses to serve is not a store
		// that answers "no such export". The index is keyed on the pipeline
		// version, so the lookup read nothing at all.
		if line, superseded := supersededInterfaceStoreLine(recs); superseded {
			return fmt.Errorf("symbol %q cannot be resolved: %s", symbolName, line)
		}
		// Under a scope, "no exports" is also reachable because every module that
		// exports the symbol sits outside the named build. That is a statement
		// about the build, not about the symbol, and the two must not print the
		// same line — so say which one it is before the empty list is rendered.
		if sc.modules.IsRestricted() {
			unscoped, uerr := ctr.QueryInterface.FindSymbol(ctx, symbolName, ifaceapp.PipelineVersion, coordinate.ModuleSet{})
			if uerr != nil && !errors.Is(uerr, ports.ErrInterfaceConflict) {
				return fmt.Errorf("finding symbol %q across all versions: %w", symbolName, uerr)
			}
			if len(unscoped) > 0 {
				if _, werr := fmt.Fprintf(stderr,
					"notice: %d export(s) of %q exist in the store, all outside %s\n",
					len(unscoped), symbolName, sc.source); werr != nil {
					return fmt.Errorf("writing scope notice: %w", werr)
				}
			}
		}
	}

	if !jsonOut {
		if err := writeScopeNotice(stdout, sc); err != nil {
			return err
		}
	}

	if jsonOut {
		if refs == nil {
			refs = []ports.SymbolRef{}
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(refs); err != nil {
			return fmt.Errorf("encoding JSON: %w", err)
		}
		return conflictErr
	}

	if perr := printSymbolRefs(symbolName, refs, stdout); perr != nil {
		return perr
	}
	return conflictErr
}

func printSymbolRefs(symbolName string, refs []ports.SymbolRef, stdout io.Writer) error {
	if len(refs) == 0 {
		if _, err := fmt.Fprintf(stdout, "no exports found for symbol %q\n", symbolName); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		return nil
	}
	for _, ref := range refs {
		parent := ""
		if ref.ParentType != "" {
			parent = ref.ParentType + "."
		}
		if _, err := fmt.Fprintf(stdout, "%-55s %-10s %s  %s%s\n",
			ref.ModulePath+"@"+ref.ModuleVersion,
			ref.SymbolKind,
			ref.PackagePath,
			parent, ref.SymbolName,
		); err != nil {
			return fmt.Errorf("writing ref: %w", err)
		}
		if ref.Signature != "" {
			if _, err := fmt.Fprintf(stdout, "    %s\n", ref.Signature); err != nil {
				return fmt.Errorf("writing signature: %w", err)
			}
		}
	}
	return nil
}

// -- interface-list command --

type packageSummary struct {
	ImportPath string
	Types      int
	Funcs      int
	Consts     int
	Vars       int
}

func newInterfaceListCmd(stdout, stderr io.Writer) *cobra.Command {
	var limit, offset int

	cmd := &cobra.Command{
		Use:   "interface-list [<module>@<version>]",
		Short: "List interface records, or packages within a specific module",
		Example: `  kanonarion interface-list
  kanonarion interface-list github.com/spf13/cobra@v1.8.1
  kanonarion interface-list github.com/spf13/cobra@v1.8.1 --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 1 {
				return fmt.Errorf("accepts at most 1 argument, received %d", len(args))
			}
			if len(args) == 1 {
				return runInterfaceListForModule(cmd.Context(), args[0], jsonOut, stdout, stderr)
			}
			return runInterfaceList(cmd.Context(), limit, offset, stdout, stderr)
		},
	}

	cmd.Flags().IntVar(&limit, "limit", 50, "maximum number of records to return without a module arg (0 = unlimited)")
	cmd.Flags().IntVar(&offset, "offset", 0, "skip this many records")

	return cmd
}

func runInterfaceListForModule(ctx context.Context, moduleArg string, jsonOut bool, stdout, stderr io.Writer) error {
	coord, err := parseCoordinate(moduleArg)
	if err != nil {
		return fmt.Errorf("invalid coordinate %q: %w", moduleArg, err)
	}

	logger := buildLogger(logLevel, stderr)
	ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() { _ = cleanup() }()

	r, found, err := ctr.QueryInterface.GetInterfaceRecord(ctx, coord, ifaceapp.PipelineVersion)
	if err != nil {
		return fmt.Errorf("getting interface record: %w", err)
	}
	if !found {
		return interfaceRecordMiss(ctx, ctr.QueryInterface, coord, jsonOut, stderr)
	}

	if jsonOut {
		summaries := make([]packageSummary, 0, len(r.Packages))
		for _, pkg := range r.Packages {
			summaries = append(summaries, packageSummary{
				ImportPath: pkg.ImportPath,
				Types:      len(pkg.Types),
				Funcs:      len(pkg.Funcs),
				Consts:     len(pkg.Consts),
				Vars:       len(pkg.Vars),
			})
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(summaries); err != nil {
			return fmt.Errorf("encoding JSON: %w", err)
		}
		return nil
	}

	for _, pkg := range r.Packages {
		if _, err := fmt.Fprintf(stdout, "%-60s %dT %dF %dC %dV\n",
			pkg.ImportPath,
			len(pkg.Types), len(pkg.Funcs), len(pkg.Consts), len(pkg.Vars),
		); err != nil {
			return fmt.Errorf("writing package line: %w", err)
		}
	}
	return nil
}

func runInterfaceList(ctx context.Context, limit, offset int, stdout, stderr io.Writer) error {
	logger := buildLogger(logLevel, stderr)
	ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() { _ = cleanup() }()

	return interfaceListWith(ctx, limit, offset, ctr.QueryInterface, stdout, stderr)
}

// interfaceListWith holds the collapsed listing over an injected use case, so
// the row cap it applies is exercisable without a live store.
func interfaceListWith(ctx context.Context, limit, offset int, uc QueryInterfaceUseCase, stdout, stderr io.Writer) error {
	// One row more than will be printed: the extra row answers whether the limit
	// bit, and costs one row rather than a second read.
	sums, err := uc.ListInterfaceRecords(ctx, ports.InterfaceFilter{Limit: truncationFetchLimit(limit), Offset: offset})
	if err != nil {
		return fmt.Errorf("listing interface records: %w", err)
	}
	// The scope is measured only when the page came back empty: it is the read
	// the notice is built from, and a listing that returned rows never pays it.
	var zero listZeroScope
	if len(sums) == 0 {
		zero, err = interfaceListZeroScope(ctx, offset, uc)
		if err != nil {
			return err
		}
	}
	return printInterfaceList(sums, jsonOut, limit, offset, zero, stdout, stderr)
}

// interfaceListZeroScope lifts the paging and re-asks the store, so a zero says
// whether the store holds no interface record at all or the page simply starts
// past the last one. This listing takes no filter — a module argument routes to
// interface-list's single-module rendering, which fails with ExitNotFound — so
// the filter cause cannot arise and the notice never claims it did.
func interfaceListZeroScope(ctx context.Context, offset int, uc QueryInterfaceUseCase) (listZeroScope, error) {
	all, err := uc.ListInterfaceRecords(ctx, ports.InterfaceFilter{})
	if err != nil {
		return listZeroScope{}, fmt.Errorf("counting interface records for the zero-result notice: %w", err)
	}
	scope := listZeroScope{
		subject:    "interface record",
		considered: len(all),
		produce:    "kanonarion interface <module>@<version>",
		listAll:    "kanonarion interface-list",
	}
	// An offset past the end empties the page while the store holds records, and
	// the two are the same zero rows from the caller's side.
	// An empty corpus is not something a page can start past, so a zero over it
	// keeps the store-empty statement and its produce-a-record remedy.
	if len(all) > 0 && offset > 0 && offset >= len(all) {
		scope.pagedPast = fmt.Sprintf("--offset %d starts past the last one", offset)
	}
	return scope, nil
}

// interfaceRecordMiss answers the two commands that name a module whose
// interface record the store does not hold, on the same terms as the example
// pair beside it: the remedy they already carried is kept, and the corpus they
// searched is stated next to it. The survey read is on the miss branch, so a
// module whose record is there pays nothing for it.
func interfaceRecordMiss(ctx context.Context, uc QueryInterfaceUseCase, coord coordinate.ModuleCoordinate,
	jsonOut bool, stderr io.Writer,
) error {
	all, err := uc.ListInterfaceRecords(ctx, ports.InterfaceFilter{})
	if err != nil {
		return fmt.Errorf("counting interface records for the not-found notice: %w", err)
	}
	// The listing is unfiltered by pipeline version, so it can tell a
	// coordinate that was never extracted from one whose every record this
	// build refuses to serve. The second is not a coordinate to check.
	if pipelines, superseded := supersededInterfacePipelines(coord, all); superseded {
		return &exitError{code: ExitNotFound, msg: supersededInterfaceLine(coord, pipelines)}
	}
	scope := listZeroScope{
		subject:     "interface record",
		filterName:  "module coordinate",
		filterValue: coord.String(),
		field:       "module coordinate",
		matchKind:   matchExact,
		considered:  len(all),
		produce:     "kanonarion interface " + coord.String(),
		listAll:     "kanonarion interface-list",
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

// printInterfaceList renders the collapsed list.
//
// A module whose records composition refused to pick between is printed on its
// own row and the command fails afterwards: every module is listed first, so one
// module in dispute does not delete the answers for all the others, and the run
// still does not read as clean.
func printInterfaceList(sums []ports.InterfaceSummary, jsonOut bool, limit, offset int, zero listZeroScope, stdout, stderr io.Writer) error {
	sums, truncated := truncateList(sums, limit)
	trunc := listTruncation{limit: limit, subject: "interface records", truncated: truncated, offset: offset}
	if jsonOut {
		type interfaceListEntry struct {
			Module  string `json:"module"`
			Version string `json:"version"`
			Status  string `json:"status"`
			// PipelineVersion is the extraction logic that produced the record,
			// and Superseded says this build does not serve it. Without the
			// pair a consumer reads a listed record as an available one and
			// finds every query about it empty. Both halves are emitted on
			// every row: the half that says "this one IS servable" is false,
			// and omitting it left the servable rows looking like rows the
			// pair was never computed for.
			PipelineVersion string `json:"pipeline_version"`
			Superseded      bool   `json:"superseded"`
			PackageCount    int    `json:"package_count"`
			Conflict        string `json:"conflict,omitempty"`
		}
		entries := make([]interfaceListEntry, 0, len(sums))
		var jsonConflicts []error
		for _, s := range sums {
			if s.Conflict != nil {
				jsonConflicts = append(jsonConflicts, s.Conflict)
				entries = append(entries, interfaceListEntry{
					Module: s.ModulePath, Version: s.ModuleVersion,
					Status: "Conflict", Conflict: s.Conflict.Error(),
					PipelineVersion: s.PipelineVersion,
					Superseded:      s.PipelineVersion != ifaceapp.PipelineVersion,
				})
				continue
			}
			entries = append(entries, interfaceListEntry{
				Module:          s.ModulePath,
				Version:         s.ModuleVersion,
				Status:          s.OverallStatus.String(),
				PipelineVersion: s.PipelineVersion,
				Superseded:      s.PipelineVersion != ifaceapp.PipelineVersion,
				PackageCount:    s.PackageCount,
			})
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(entries); err != nil {
			return fmt.Errorf("encoding JSON: %w", err)
		}
		if len(entries) > 0 {
			if terr := writeListTruncationJSON(stderr, trunc); terr != nil {
				return terr
			}
		} else if zerr := writeListZeroNoticeJSON(stderr, zero); zerr != nil {
			return zerr
		}
		if len(jsonConflicts) > 0 {
			return fmt.Errorf("%d module(s) hold conflicting interface records: %w",
				len(jsonConflicts), errors.Join(jsonConflicts...))
		}
		return nil
	}
	if len(sums) == 0 {
		return writeListZeroNotice(stdout, zero)
	}
	var conflicts []error
	supersededRows := 0
	for _, s := range sums {
		if s.Conflict != nil {
			conflicts = append(conflicts, s.Conflict)
			if _, err := fmt.Fprintf(stdout, "%-50s %-12s %s\n",
				s.ModulePath+"@"+s.ModuleVersion, "CONFLICT",
				"run: kanonarion interface "+s.ModulePath+"@"+s.ModuleVersion+" --history"); err != nil {
				return fmt.Errorf("writing output: %w", err)
			}
			continue
		}
		superseded := ""
		if s.PipelineVersion != ifaceapp.PipelineVersion {
			superseded = "  [superseded pipeline " + s.PipelineVersion + "]"
			supersededRows++
		}
		if _, err := fmt.Fprintf(stdout, "%-50s %-12s %d package(s)%s\n",
			s.ModulePath+"@"+s.ModuleVersion,
			s.OverallStatus.String(),
			s.PackageCount,
			superseded,
		); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	}
	// A listed record this build will not serve is still a listed record; the
	// row says so, and the footer says how many and what to do, so an operator
	// does not read the listing as an inventory of answerable modules.
	if supersededRows > 0 {
		if _, err := fmt.Fprintf(stdout,
			"%d of %d listed record(s) were produced by superseded extraction logic; this build "+
				"serves pipeline %s and answers no query from them. Re-extract one:\n"+
				"  kanonarion interface <module>@<version>\n",
			supersededRows, len(sums), ifaceapp.PipelineVersion); err != nil {
			return fmt.Errorf("writing superseded notice: %w", err)
		}
	}
	if terr := writeListTruncationNotice(stdout, trunc); terr != nil {
		return terr
	}
	// Every module is listed first, then the command fails. A module whose
	// records disagree must not be reported as a clean run.
	if len(conflicts) > 0 {
		return fmt.Errorf("%d module(s) hold conflicting interface records: %w",
			len(conflicts), errors.Join(conflicts...))
	}
	return nil
}
