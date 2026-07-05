package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// provenanceOutput is the JSON payload of the provenance command. It reuses
// the context section's fork-heuristic shape so consumers see one vocabulary
// across both surfaces.
type provenanceOutput struct {
	Module        string               `json:"module"`
	Version       string               `json:"version,omitempty"`
	ForkHeuristic contextForkHeuristic `json:"fork_heuristic"`
}

func newProvenanceCmd(stdout, _ io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "provenance <module[@version]>",
		Short: "Show fork/copy provenance facts for a module path (name-path heuristic)",
		Long: `Run the cheap-tier name-path fork heuristic over a module path: when the
path shares its trailing name element with a catalogued canonical module
under a different owner or host, report a caveated fork inference.

The result is an inference, never a verdict — "path suggests a fork of
<canonical> — verify". Confirming or refuting it requires comparing the
module's VCS origin or content with the canonical's.

The heuristic is a pure function of the path; no store record is needed and
the version, when given, is echoed but does not influence the result.`,
		Example: `  kanonarion provenance github.com/someuser/cobra
  kanonarion provenance github.com/someuser/cobra@v1.0.0 --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path, version, _ := strings.Cut(args[0], "@")
			if path == "" {
				return usageErr(cmd)
			}
			return runProvenance(path, version, stdout)
		},
	}
	return cmd
}

func runProvenance(path, version string, stdout io.Writer) error {
	fp := fetchdomain.InferForkProvenance(path)
	out := provenanceOutput{
		Module:  path,
		Version: version,
		ForkHeuristic: contextForkHeuristic{
			Status:           fp.Status.String(),
			CatalogueVersion: fp.CatalogueVersion,
		},
	}
	for _, ind := range fp.Indicators {
		out.ForkHeuristic.ForkIndicators = append(out.ForkHeuristic.ForkIndicators, contextForkIndicator{
			Canonical: ind.Canonical,
			Statement: ind.Statement,
		})
	}

	if jsonOut {
		raw, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return fmt.Errorf("encoding provenance: %w", err)
		}
		if _, err := fmt.Fprintf(stdout, "%s\n", raw); err != nil {
			return fmt.Errorf("writing provenance: %w", err)
		}
		return nil
	}

	w := &errWriter{w: stdout}
	header := out.Module
	if out.Version != "" {
		header += "@" + out.Version
	}
	w.printf("%s\n", header)
	switch out.ForkHeuristic.Status {
	case forkStatusPathMatch:
		w.printf("  Fork Heuristic: %s (catalogue %s)\n", out.ForkHeuristic.Status, out.ForkHeuristic.CatalogueVersion)
		for _, ind := range out.ForkHeuristic.ForkIndicators {
			w.printf("    %s\n", ind.Statement)
		}
	default:
		w.printf("  Fork Heuristic: no fork indicators (catalogue %s)\n", out.ForkHeuristic.CatalogueVersion)
	}
	if w.err != nil {
		return fmt.Errorf("writing provenance: %w", w.err)
	}
	return nil
}
