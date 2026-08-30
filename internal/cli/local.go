package cli

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/spf13/cobra"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
)

type localFlags struct {
	goBinary string
	force    bool
}

func newLocalCmd(stdout, stderr io.Writer) *cobra.Command {
	var f localFlags

	cmd := &cobra.Command{
		Use: "local [dir]",
		Annotations: map[string]string{
			annotationStoreIntent: StoreIntentCreate,
			annotationNetworkUse:  NetworkNever,
		},
		Short: "Ingest the local working tree's call graph so callers/callees resolve internal symbols",
		Long: `Analyse the Go module rooted at [dir] (default ".") and persist its
call graph into the store. Unlike 'callgraph <module@version>', which only
sees fetched external modules, 'local' ingests the project's own internal
packages so 'callers'/'callees' can answer questions about them.

A tree that has not changed since the last run is not analysed again: the
record already held is served, and the derivation line says so. --force
re-measures anyway, which is what to use when something outside the tree
changed — a different toolchain. A record left incomplete because this host's
module cache was cold is never served, so warming the cache and re-running
without the flag re-analyses.

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
	cmd.Flags().BoolVar(&f.force, "force", false, "re-analyse even if the tree is unchanged since the stored record")

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
		Force:      f.force,
	})
	if err != nil {
		return fmt.Errorf("extracting local call graph: %w", err)
	}

	if err := printCallGraphSummary(result.Record, result.FromCache, jsonOut, abs, stdout); err != nil {
		return err
	}
	// The derivation goes to stderr, in both modes and for the same reason.
	//
	// It is a statement ABOUT the answer rather than part of it, which is where
	// every other command puts one — 'audit' writes its walk and scan derivation
	// to stderr — and one concept arriving on two streams depending on which
	// command produced it is a contract a reader cannot learn once.
	//
	// Under --json it matters more, not less. stdout is a document a consumer
	// parses, so the statement cannot go there without either corrupting the
	// stream or being folded into the record — and folding it in would change the
	// record's shape for a narration change, which is a pipeline bump owed for
	// nothing. On stderr it costs the document nothing and stays stated: without
	// it a JSON consumer has no way at all to tell a served graph from a fresh
	// measurement, which is the one distinction this line exists to preserve.
	if err := writeDerivation(stderr, localDerivationLine(result)); err != nil {
		return err
	}
	return callGraphExtractionExit(result.Record)
}

// localDerivationLine states where this run's answer came from: the tree it read,
// or a record it found it had already taken of that same tree.
//
// A reader cannot otherwise tell a fresh measurement from a stored one, and the
// two carry different weight in exactly the cases the distinction matters —
// deciding whether a query is answering about the code in front of you. The
// reuse line names the record's date so the statement is checkable, and names
// --force because a reader who wants the measurement taken again needs to be
// told how, in the place they learn it was not.
func localDerivationLine(result cgapp.ExtractResult) string {
	if !result.FromCache {
		return "call graph: derived by this run"
	}
	return fmt.Sprintf(
		"call graph: re-read the working tree and found it identical to the tree analysed %s; that record was reused (--force to re-measure)",
		result.Record.ExtractedAt.UTC().Format(time.RFC3339))
}
