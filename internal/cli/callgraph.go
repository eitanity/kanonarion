package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/spf13/cobra"
)

type cgFlags struct {
	goBinary     string
	force        bool
	fromModcache string
}

func newCallGraphCmd(stdout, stderr io.Writer) *cobra.Command {
	var f cgFlags
	var localShim bool

	cmd := &cobra.Command{
		Use:   "callgraph <module>@<version>",
		Short: "Extract and summarise the call graph of a Go module",
		Example: `  kanonarion callgraph github.com/spf13/cobra@v1.8.1
  kanonarion callgraph github.com/spf13/cobra@v1.8.1 --json
  kanonarion callgraph github.com/spf13/cobra@v1.8.1 --force`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if localShim {
				// Direct, never execute: 'callgraph' analyses fetched
				// (consumer-mode) modules; the local working tree is
				// author-mode and has its own command.
				return errors.New(
					"the 'callgraph' command analyses fetched modules; to analyse the " +
						"local working tree use the 'local' command:\n  kanonarion local <dir>")
			}
			if len(args) == 0 {
				return usageErr(cmd)
			}
			if len(args) > 1 {
				return fmt.Errorf("accepts 1 arg, received %d", len(args))
			}
			// A module fetched via --from-modcache is stored under a
			// "modcache:zip:" blob handle, not a content-addressed one; the
			// call-graph extractor needs the same modcache-aware blob store
			// that fetched it, or blob resolution fails.
			if f.fromModcache != "" {
				gomodPath, gerr := resolveGoModPath("")
				if gerr != nil {
					return fmt.Errorf("--from-modcache: locating go.mod: %w", gerr)
				}
				if merr := resolveModcacheMode(f.fromModcache, gomodPath); merr != nil {
					return merr
				}
			}
			return runCallGraphExtract(cmd.Context(), args[0], f, stdout, stderr)
		},
	}

	cmd.Flags().StringVar(&f.goBinary, "go-binary", "", "path to 'go' binary if not in PATH")
	cmd.Flags().BoolVar(&f.force, "force", false, "re-extract even if cached")
	cmd.Flags().BoolVar(&localShim, "local", false, "")
	_ = cmd.Flags().MarkHidden("local")
	registerFromModcacheFlag(cmd, &f.fromModcache)

	return cmd
}

func runCallGraphExtract(ctx context.Context, arg string, f cgFlags, stdout, stderr io.Writer) error {
	logger := buildLogger(logLevel, stderr)

	coord, err := parseCoordinate(arg)
	if err != nil {
		return fmt.Errorf("invalid coordinate %q: %w", arg, err)
	}

	ctr, cleanup, err := NewContainer(storeRoot, "", f.goBinary, false, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() { _ = cleanup() }()

	result, err := ctr.ExtractCallGraph.Execute(ctx, cgapp.ExtractRequest{
		Coordinate: coord,
		Force:      f.force,
	})
	if err != nil {
		return fmt.Errorf("extracting call graph: %w", err)
	}

	return printCallGraphSummary(result.Record, result.FromCache, jsonOut, stdout)
}

func printCallGraphSummary(r domain.CallGraphRecord, fromCache bool, jsonOut bool, stdout io.Writer) error {
	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(toCallGraphJSON(r)); err != nil {
			return fmt.Errorf("encoding JSON: %w", err)
		}
		return nil
	}

	cached := ""
	if fromCache {
		cached = " (cached)"
	}
	if _, err := fmt.Fprintf(stdout, "%s@%s: %s — %d nodes, %d edges [%s]%s\n",
		r.Coordinate.Path, r.Coordinate.Version,
		r.OverallStatus.String(),
		r.NodeCount, r.EdgeCount,
		string(r.Algorithm),
		cached,
	); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	if r.FailureDetail != "" {
		if _, err := fmt.Fprintf(stdout, "  failure: %s\n", r.FailureDetail); err != nil {
			return fmt.Errorf("writing failure detail: %w", err)
		}
	}
	if err := writeFailedPackages(stdout, r); err != nil {
		return err
	}
	if err := writeExclusionInfo(stdout, r); err != nil {
		return err
	}
	return nil
}

// writeFailedPackages lists the packages that failed to typecheck (Partial
// graphs only). It scopes the graph's incompleteness to exact packages so a
// reader never infers completeness from the node/edge totals on the line above.
func writeFailedPackages(stdout io.Writer, r domain.CallGraphRecord) error {
	if len(r.FailedPackages) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(stdout, "  failed packages (%d): %s\n",
		len(r.FailedPackages), strings.Join(r.FailedPackages, ", ")); err != nil {
		return fmt.Errorf("writing failed packages: %w", err)
	}
	return nil
}

// writeExclusionInfo prints the exclusion reason (when the module was skipped)
// and the callgraph.exclude policy that was active when the record was
// computed. No output when no exclusion policy was in force.
func writeExclusionInfo(stdout io.Writer, r domain.CallGraphRecord) error {
	if r.ExclusionReason != "" {
		if _, err := fmt.Fprintf(stdout, "  excluded: %s\n", r.ExclusionReason); err != nil {
			return fmt.Errorf("writing exclusion reason: %w", err)
		}
	}
	if len(r.ExclusionList) > 0 {
		if _, err := fmt.Fprintf(stdout, "  exclusion list (active at extraction): %s\n",
			strings.Join(r.ExclusionList, ", ")); err != nil {
			return fmt.Errorf("writing exclusion list: %w", err)
		}
	}
	return nil
}
