package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	licapp "github.com/eitanity/kanonarion/internal/license/application"
	"github.com/eitanity/kanonarion/internal/license/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
	"github.com/spf13/cobra"
)

// newLicenseCompatCmd returns the license-compat command, which evaluates a
// module's dependency closure against a target distribution license using the
// compatibility engine.
func newLicenseCompatCmd(stdout, stderr io.Writer) *cobra.Command {
	var targetSPDX string

	cmd := &cobra.Command{
		Use:   "license-compat <module>@<version>",
		Short: "Report license conflicts in a module's dependency closure",
		Long: `Evaluates whether the dependency closure of <module>@<version> is
redistributable under --target.

Exit codes:
  0  clean — no conflicts, no unknown pairs
  1  conflicts — one or more deps are incompatible with the target license
  2  unknown pairs — one or more dep licenses are not in the modelled dataset
     (requires human review; these are never silently "compatible")`,
		Example: `  kanonarion license-compat github.com/spf13/cobra@v1.8.1 --target Apache-2.0
  kanonarion license-compat github.com/spf13/cobra@v1.8.1 --target Apache-2.0 --json
  kanonarion license-compat example.com/project@local`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return usageErr(cmd)
			}
			if len(args) > 1 {
				return fmt.Errorf("accepts 1 arg, received %d", len(args))
			}
			return runLicenseCompat(cmd.Context(), args[0], targetSPDX, stdout, stderr)
		},
	}

	cmd.Flags().StringVar(&targetSPDX, "target", "", "target distribution license SPDX id (e.g. Apache-2.0); omitted: use the root's own analysed licence record as the target")

	return cmd
}

func runLicenseCompat(ctx context.Context, arg, targetSPDX string, stdout, stderr io.Writer) error {
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

	return licenseCompatWith(ctx, ctr, coord, targetSPDX, stdout)
}

// licenseCompatWith holds the license-compat logic over an injected Container:
// it resolves the root walk, runs the closure compatibility check, maps the
// intent-aware diagnostics (unanalysed root vs. no-SPDX root) and the
// clean/conflict/unknown verdict to exit codes, and renders the report. Split
// from runLicenseCompat so the exit-code and diagnostic decisions are testable
// without a live store.
func licenseCompatWith(ctx context.Context, ctr *Container, coord fetchdomain.ModuleCoordinate, targetSPDX string, stdout io.Writer) error {
	// Require an existing walk record for the root module.
	target := coord
	summaries, err := ctr.QueryWalks.ListWalks(ctx, walkports.WalkFilter{Target: &target, Limit: 1})
	if err != nil {
		return fmt.Errorf("listing walks: %w", err)
	}
	if len(summaries) == 0 {
		// return error once via exitError; main prints it. No fmt.Fprintf here.
		return &exitError{
			code: ExitNotFound,
			msg:  fmt.Sprintf("no walk record found for %s — run 'kanonarion walk %s' first", coord, coord),
		}
	}
	walkID := summaries[0].ID

	report, err := ctr.CheckCompatibility.CheckCompatibilityForWalk(ctx, walkID, coord, targetSPDX)
	if err != nil {
		// Implicit-target resolution failures get intent-aware diagnostics
		// say what is missing and which command produces it.
		switch {
		case errors.Is(err, licapp.ErrRootLicenceNotAnalysed):
			hint := fmt.Sprintf("run 'kanonarion license %s' first, or pass --target", coord)
			if coord.IsLocal() {
				hint = "run 'kanonarion walk --gomod ./go.mod --analyse-root' then 'kanonarion extract <walk-id>' to analyse the project's own licence, or pass --target"
			}
			return &exitError{
				code: ExitNotFound,
				msg:  fmt.Sprintf("no licence record for root %s — %s", coord, hint),
			}
		case errors.Is(err, licapp.ErrRootLicenceNoSPDX):
			return &exitError{
				code: ExitFailed,
				msg:  fmt.Sprintf("root %s has a licence record but no SPDX identity (proprietary/unclassified roots are valid, just not usable as an implicit target) — pass --target explicitly", coord),
			}
		}
		return fmt.Errorf("checking compatibility: %w", err)
	}

	if jsonOut {
		if err := printCompatReportJSON(report, stdout); err != nil {
			return err
		}
	} else {
		printCompatReportText(report, coord, stdout)
	}

	return compatExitCode(report)
}

func printCompatReportJSON(report domain.ClosureCompatibilityReport, stdout io.Writer) error {
	type conflictJSON struct {
		Module  string `json:"module"`
		Version string `json:"version"`
		DepSPDX string `json:"dep_spdx"`
		Target  string `json:"target_spdx"`
		Verdict string `json:"verdict"`
		Kind    string `json:"kind"`
	}
	type reportJSON struct {
		TargetSPDX  string         `json:"target_spdx"`
		DataVersion string         `json:"data_version"`
		Clean       bool           `json:"clean"`
		Conflicts   []conflictJSON `json:"conflicts"`
	}

	out := reportJSON{
		TargetSPDX:  report.TargetSPDX,
		DataVersion: report.DataVersion,
		Clean:       report.Clean,
		Conflicts:   make([]conflictJSON, 0, len(report.Conflicts)),
	}
	for _, c := range report.Conflicts {
		out.Conflicts = append(out.Conflicts, conflictJSON{
			Module:  c.ModulePath,
			Version: c.ModuleVersion,
			DepSPDX: c.DepSPDX,
			Target:  c.TargetSPDX,
			Verdict: c.Verdict.String(),
			Kind:    c.Kind.String(),
		})
	}

	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return fmt.Errorf("encoding JSON: %w", err)
	}
	return nil
}

func printCompatReportText(report domain.ClosureCompatibilityReport, root fetchdomain.ModuleCoordinate, stdout io.Writer) {
	if report.Clean {
		_, _ = fmt.Fprintf(stdout, "%s: closure is compatible with %s (data v%s)\n",
			root, report.TargetSPDX, report.DataVersion)
		return
	}

	var incompatible, unknown []domain.CompatibilityConflict
	for _, c := range report.Conflicts {
		if c.Verdict == domain.VerdictUnknownPair {
			unknown = append(unknown, c)
		} else {
			incompatible = append(incompatible, c)
		}
	}

	_, _ = fmt.Fprintf(stdout, "%s vs %s (data v%s):\n", root, report.TargetSPDX, report.DataVersion)

	if len(incompatible) > 0 {
		_, _ = fmt.Fprintf(stdout, "\nIncompatible (%d):\n", len(incompatible))
		for _, c := range incompatible {
			depSPDX := c.DepSPDX
			if depSPDX == "" {
				depSPDX = "(no license)"
			}
			_, _ = fmt.Fprintf(stdout, "  %-55s %s [%s]\n",
				c.ModulePath+"@"+c.ModuleVersion, depSPDX, c.Kind.String())
		}
	}

	if len(unknown) > 0 {
		_, _ = fmt.Fprintf(stdout, "\nRequires review — unmodelled license pair (%d):\n", len(unknown))
		hasNoRecord := false
		for _, c := range unknown {
			depSPDX := c.DepSPDX
			if depSPDX == "" {
				depSPDX = "(no license detected)"
				hasNoRecord = true
			}
			_, _ = fmt.Fprintf(stdout, "  %-55s %s\n",
				c.ModulePath+"@"+c.ModuleVersion, depSPDX)
		}
		// hint so the user knows whether extraction is the next step.
		if hasNoRecord {
			_, _ = fmt.Fprintf(stdout, "\nTip: some deps show no license. Run 'kanonarion extract <walk-id>' to\n")
			_, _ = fmt.Fprintf(stdout, "     populate missing records, then re-run license-compat.\n")
		}
	}
}

// compatExitCode returns an exitError for non-clean reports. ExitPartial (1)
// for confirmed incompatible pairs, ExitFailed (2) for unknown pairs.
func compatExitCode(report domain.ClosureCompatibilityReport) error {
	if report.Clean {
		return nil
	}
	hasIncompat := false
	hasUnknown := false
	for _, c := range report.Conflicts {
		switch c.Verdict {
		case domain.VerdictIncompatible:
			hasIncompat = true
		case domain.VerdictUnknownPair:
			hasUnknown = true
		}
	}
	// Unknown pairs take priority: they require human review, which is a
	// stronger signal than a confirmed incompatibility.
	if hasUnknown {
		return &exitError{code: ExitFailed, msg: "closure has unmodelled license pairs requiring review"}
	}
	if hasIncompat {
		return &exitError{code: ExitPartial, msg: "closure has license conflicts"}
	}
	return nil
}
