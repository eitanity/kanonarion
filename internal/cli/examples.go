package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/eitanity/kanonarion/internal/example/application"
	"github.com/eitanity/kanonarion/internal/example/domain"
	"github.com/eitanity/kanonarion/internal/example/ports"
	"github.com/spf13/cobra"
)

type exampleFlags struct {
	force bool
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
		Use:   "examples <module>@<version>",
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

	return cmd
}

func runExamplesExtract(ctx context.Context, arg string, f exampleFlags, stdout, stderr io.Writer) error {
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

	result, err := ctr.ExtractExample.Execute(ctx, application.ExtractRequest{
		Coordinate: coord,
		Force:      f.force,
	})
	if err != nil {
		return fmt.Errorf("extracting examples: %w", err)
	}

	return printExampleRecord(result.Record, result.FromCache, jsonOut, stdout)
}

func printExampleRecord(r domain.ExampleRecord, fromCache bool, jsonOut bool, stdout io.Writer) error {
	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(r); err != nil {
			return fmt.Errorf("encoding JSON: %w", err)
		}
		return nil
	}

	cached := ""
	if fromCache {
		cached = " (cached)"
	}
	if _, err := fmt.Fprintf(stdout, "%s@%s: %s — %d example(s)%s\n",
		r.Coordinate.Path, r.Coordinate.Version,
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
		Use:   "examples-show <module>@<version> <example-name>",
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
			defer func() { _ = cleanup() }()
			return runExamplesShow(cmd.Context(), args[0], args[1], jsonOut, ctr.QueryExamples, stdout)
		},
	}

	return cmd
}

func runExamplesShow(ctx context.Context, moduleArg, exampleName string, jsonOut bool, uc QueryExamplesUseCase, stdout io.Writer) error {
	coord, err := parseCoordinate(moduleArg)
	if err != nil {
		return fmt.Errorf("invalid coordinate %q: %w", moduleArg, err)
	}

	r, found, err := uc.GetExampleRecord(ctx, coord, application.PipelineVersion)
	if err != nil {
		return fmt.Errorf("getting example record: %w", err)
	}
	if !found {
		return fmt.Errorf("no example record for %s — run 'kanonarion examples' first", coord)
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

	return fmt.Errorf("example %q not found in record for %s", exampleName, coord)
}

// -- examples-find command --

func newExamplesFindCmd(stdout, stderr io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "examples-find <symbol>",
		Short: "Find all examples for a symbol across the store",
		Example: `  kanonarion examples-find Client.Do
  kanonarion examples-find Marshal
  kanonarion examples-find Marshal --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageErr(cmd)
			}
			logger := buildLogger(logLevel, stderr)
			ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
			if err != nil {
				return fmt.Errorf("initialising store: %w", err)
			}
			defer func() { _ = cleanup() }()
			return runExamplesFind(cmd.Context(), args[0], jsonOut, ctr.QueryExamples, stdout)
		},
	}

	return cmd
}

func runExamplesFind(ctx context.Context, symbol string, jsonOut bool, uc QueryExamplesUseCase, stdout io.Writer) error {
	refs, err := uc.FindBySymbol(ctx, symbol, application.PipelineVersion)
	if err != nil {
		return fmt.Errorf("finding examples for %q: %w", symbol, err)
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
		return nil
	}

	if len(refs) == 0 {
		if _, err := fmt.Fprintf(stdout, "no examples found for symbol %q\n", symbol); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		return nil
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
	return nil
}

// -- examples-list command --

func newExamplesListCmd(stdout, stderr io.Writer) *cobra.Command {
	var limit int

	cmd := &cobra.Command{
		Use:   "examples-list [<module>@<version>]",
		Short: "List example records, or examples within a specific module",
		Example: `  kanonarion examples-list
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
			defer func() { _ = cleanup() }()
			if len(args) == 1 {
				return runExamplesListForModule(cmd.Context(), args[0], ctr.QueryExamples, stdout)
			}
			return runExamplesList(cmd.Context(), limit, ctr.QueryExamples, stdout)
		},
	}

	cmd.Flags().IntVar(&limit, "limit", 50, "maximum number of records to return without a module arg (0 = unlimited)")

	return cmd
}

func runExamplesListForModule(ctx context.Context, moduleArg string, uc QueryExamplesUseCase, stdout io.Writer) error {
	coord, err := parseCoordinate(moduleArg)
	if err != nil {
		return fmt.Errorf("invalid coordinate %q: %w", moduleArg, err)
	}

	r, found, err := uc.GetExampleRecord(ctx, coord, application.PipelineVersion)
	if err != nil {
		return fmt.Errorf("getting example record: %w", err)
	}
	if !found {
		return fmt.Errorf("no example record for %s — run 'kanonarion examples %s' first", coord, moduleArg)
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

func runExamplesList(ctx context.Context, limit int, uc QueryExamplesUseCase, stdout io.Writer) error {
	sums, err := uc.ListExampleRecords(ctx, ports.ExampleFilter{Limit: limit})
	if err != nil {
		return fmt.Errorf("listing example records: %w", err)
	}
	if jsonOut {
		type entry struct {
			Module       string `json:"module"`
			Version      string `json:"version"`
			Status       string `json:"status"`
			ExampleCount int    `json:"example_count"`
		}
		out := make([]entry, 0, len(sums))
		for _, s := range sums {
			out = append(out, entry{s.ModulePath, s.ModuleVersion, s.OverallStatus.String(), s.ExampleCount})
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			return fmt.Errorf("encoding JSON: %w", err)
		}
		return nil
	}
	if len(sums) == 0 {
		if _, err := fmt.Fprintln(stdout, "no example records found"); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		return nil
	}
	for _, s := range sums {
		if _, err := fmt.Fprintf(stdout, "%-50s %-12s %d example(s)\n",
			s.ModulePath+"@"+s.ModuleVersion,
			s.OverallStatus.String(),
			s.ExampleCount,
		); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	}
	return nil
}
