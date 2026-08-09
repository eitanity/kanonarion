package cli

import (
	"context"
	"fmt"
	"io"
	"path/filepath"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/spf13/cobra"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
)

type localFlags struct {
	goBinary string
}

func newLocalCmd(stdout, stderr io.Writer) *cobra.Command {
	var f localFlags

	cmd := &cobra.Command{
		Use:   "local [dir]",
		Short: "Ingest the local working tree's call graph so callers/callees resolve internal symbols",
		Long: `Analyse the Go module rooted at [dir] (default ".") and persist its
call graph into the store. Unlike 'callgraph <module@version>', which only
sees fetched external modules, 'local' ingests the project's own internal
packages so 'callers'/'callees' can answer questions about them.

After running 'local', query internal symbols directly, e.g.:
  kanonarion callers '<module-path>/internal/cli.runScanRescan'`,
		Example: `  kanonarion local
  kanonarion local .
  kanonarion local /path/to/project`,
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := "."
			if len(args) == 1 {
				dir = args[0]
			} else if len(args) > 1 {
				return fmt.Errorf("accepts at most 1 arg, received %d", len(args))
			}
			return runLocalCallGraph(cmd.Context(), dir, f, stdout, stderr)
		},
	}

	cmd.Flags().StringVar(&f.goBinary, "go-binary", "", "path to 'go' binary if not in PATH")

	return cmd
}

func runLocalCallGraph(ctx context.Context, dir string, f localFlags, stdout, stderr io.Writer) error {
	logger := buildLogger(logLevel, stderr)

	abs, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("resolving path %q: %w", dir, err)
	}

	gomodPath := filepath.Join(abs, "go.mod")
	modulePath, err := readGoModulePath(gomodPath)
	if err != nil {
		return fmt.Errorf("reading module path: %w", err)
	}

	// coordinate.LocalVersion, not a synthetic semver. Nothing published this
	// tree, so there is no version to name, and a placeholder like "v0.0.0" is a
	// version column stating something untrue: it reads as a real release, it is
	// invisible to every query that filters on version, and it smuggles "this came
	// from a working tree" into a field that means something else. LocalVersion is
	// the marker the project walk already uses for exactly this, and the record's
	// AnalysisSource now carries what the placeholder was standing in for.
	coord, err := coordinate.NewLocalCoordinate(modulePath)
	if err != nil {
		return fmt.Errorf("constructing local coordinate: %w", err)
	}

	ctr, cleanup, err := NewContainer(storeRoot, "", f.goBinary, false, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() { _ = cleanup() }()

	result, err := ctr.ExtractLocalCallGraph.Execute(ctx, cgapp.LocalExtractRequest{
		Dir:        abs,
		Coordinate: coord,
	})
	if err != nil {
		return fmt.Errorf("extracting local call graph: %w", err)
	}

	if err := printCallGraphSummary(result.Record, result.FromCache, jsonOut, stdout); err != nil {
		return err
	}
	return callGraphExtractionExit(result.Record)
}
