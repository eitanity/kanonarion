package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	ifaceapp "github.com/eitanity/kanonarion/internal/iface/application"
	"github.com/eitanity/kanonarion/internal/iface/domain"
	"github.com/eitanity/kanonarion/internal/iface/ports"
	"github.com/spf13/cobra"
)

type ifaceFlags struct {
	force bool
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

	result, err := ctr.ExtractInterface.Execute(ctx, ifaceapp.ExtractRequest{
		Coordinate: coord,
		Force:      f.force,
	})
	if err != nil {
		return fmt.Errorf("extracting interface: %w", err)
	}

	return printInterfaceRecord(result.Record, result.FromCache, jsonOut, stdout)
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
		r.Coordinate.Path, r.Coordinate.Version,
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
		return fmt.Errorf("no interface record for %s — run 'kanonarion interface' first", coord)
	}

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

	return printRecordText(r, stdout)
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

func printRecordText(r domain.InterfaceRecord, stdout io.Writer) error {
	for _, pkg := range r.Packages {
		if _, err := fmt.Fprintf(stdout, "\npackage %s // %s\n", pkg.Name, pkg.ImportPath); err != nil {
			return fmt.Errorf("writing package header: %w", err)
		}
		for _, t := range pkg.Types {
			if _, err := fmt.Fprintf(stdout, "  type %s (%s)\n", t.Name, t.Kind.String()); err != nil {
				return fmt.Errorf("writing type: %w", err)
			}
			for _, m := range t.Methods {
				if _, err := fmt.Fprintf(stdout, "    func %s\n", m.Signature); err != nil {
					return fmt.Errorf("writing method: %w", err)
				}
			}
		}
		for _, f := range pkg.Funcs {
			if _, err := fmt.Fprintf(stdout, "  %s\n", f.Signature); err != nil {
				return fmt.Errorf("writing func: %w", err)
			}
		}
		for _, c := range pkg.Consts {
			if _, err := fmt.Fprintf(stdout, "  const %s %s\n", c.Name, c.Type); err != nil {
				return fmt.Errorf("writing const: %w", err)
			}
		}
		for _, v := range pkg.Vars {
			if _, err := fmt.Fprintf(stdout, "  var %s %s\n", v.Name, v.Type); err != nil {
				return fmt.Errorf("writing var: %w", err)
			}
		}
		for _, pf := range pkg.ParseFailures {
			if _, err := fmt.Fprintf(stdout, "  [parse failure] %s: %s\n", pf.File, pf.Error); err != nil {
				return fmt.Errorf("writing parse failure: %w", err)
			}
		}
	}
	return nil
}

// -- symbol-find command --

func newSymbolFindCmd(stdout, stderr io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "symbol-find <name>",
		Short: "Find all modules that export a symbol with the given name",
		Example: `  kanonarion symbol-find Client
  kanonarion symbol-find Marshal
  kanonarion symbol-find Marshal --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageErr(cmd)
			}
			return runSymbolFind(cmd.Context(), args[0], jsonOut, stdout, stderr)
		},
	}

	return cmd
}

func runSymbolFind(ctx context.Context, symbolName string, jsonOut bool, stdout, stderr io.Writer) error {
	logger := buildLogger(logLevel, stderr)
	ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() { _ = cleanup() }()

	refs, err := ctr.QueryInterface.FindSymbol(ctx, symbolName, ifaceapp.PipelineVersion)
	if err != nil {
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
		return nil
	}

	return printSymbolRefs(symbolName, refs, stdout)
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
	var limit int

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
			return runInterfaceList(cmd.Context(), limit, stdout, stderr)
		},
	}

	cmd.Flags().IntVar(&limit, "limit", 50, "maximum number of records to return without a module arg (0 = unlimited)")

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
		return fmt.Errorf("no interface record for %s — run 'kanonarion interface %s' first", coord, moduleArg)
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

func runInterfaceList(ctx context.Context, limit int, stdout, stderr io.Writer) error {
	logger := buildLogger(logLevel, stderr)
	ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() { _ = cleanup() }()

	sums, err := ctr.QueryInterface.ListInterfaceRecords(ctx, ports.InterfaceFilter{Limit: limit})
	if err != nil {
		return fmt.Errorf("listing interface records: %w", err)
	}
	if jsonOut {
		type interfaceListEntry struct {
			Module       string `json:"module"`
			Version      string `json:"version"`
			Status       string `json:"status"`
			PackageCount int    `json:"package_count"`
		}
		entries := make([]interfaceListEntry, 0, len(sums))
		for _, s := range sums {
			entries = append(entries, interfaceListEntry{
				Module:       s.ModulePath,
				Version:      s.ModuleVersion,
				Status:       s.OverallStatus.String(),
				PackageCount: s.PackageCount,
			})
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(entries); err != nil {
			return fmt.Errorf("encoding JSON: %w", err)
		}
		return nil
	}
	if len(sums) == 0 {
		if _, err := fmt.Fprintln(stdout, "no interface records found"); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		return nil
	}
	for _, s := range sums {
		if _, err := fmt.Fprintf(stdout, "%-50s %-12s %d package(s)\n",
			s.ModulePath+"@"+s.ModuleVersion,
			s.OverallStatus.String(),
			s.PackageCount,
		); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	}
	return nil
}
