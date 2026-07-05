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
	"github.com/spf13/cobra"
)

// -- license-diff command --

func newLicenseDiffCmd(stdout, stderr io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "license-diff <module>@<versionA> <module>@<versionB>",
		Short: "Report license changes between two versions of a module",
		Long: `license-diff compares two stored license records and reports SPDX changes,
status changes, added/removed license files, and copyright-holder changes.

A meaningful relicensing from a permissive license to a copyleft license
(the Redis, Terraform, HashiCorp, Sentry pattern) is visibly flagged.

Both records must already be extracted — run 'kanonarion license' first.`,
		Example: `  kanonarion license-diff github.com/redis/go-redis@v8.11.5 github.com/redis/go-redis@v9.0.0
  kanonarion license-diff github.com/hashicorp/terraform@v1.4.0 github.com/hashicorp/terraform@v1.5.0 --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 2 {
				return usageErr(cmd)
			}
			return runLicenseDiff(cmd.Context(), args[0], args[1], stdout, stderr)
		},
	}
	return cmd
}

func runLicenseDiff(ctx context.Context, argA, argB string, stdout, stderr io.Writer) error {
	coordA, err := parseCoordinate(argA)
	if err != nil {
		return fmt.Errorf("invalid coordinate %q: %w", argA, err)
	}
	coordB, err := parseCoordinate(argB)
	if err != nil {
		return fmt.Errorf("invalid coordinate %q: %w", argB, err)
	}

	logger := buildLogger(logLevel, stderr)
	ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() { _ = cleanup() }()

	return licenseDiffWith(ctx, ctr, coordA, coordB, stdout)
}

// licenseDiffWith holds the license-diff logic over an injected Container: it
// runs the diff, maps a missing record to ExitNotFound (absence is surfaced,
// never reported as "no change"), and selects JSON vs text rendering. Split
// from runLicenseDiff so the not-found contract and render selection are
// testable without a live store.
func licenseDiffWith(ctx context.Context, ctr *Container, coordA, coordB fetchdomain.ModuleCoordinate, stdout io.Writer) error {
	diff, err := ctr.DiffLicense.Diff(ctx, coordA, coordB)
	if err != nil {
		var notFound *licapp.ErrLicenseRecordNotFound
		if errors.As(err, &notFound) {
			return &exitError{code: ExitNotFound, msg: notFound.Error()}
		}
		return fmt.Errorf("diffing license records: %w", err)
	}

	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if encErr := enc.Encode(toLicenseDiffJSON(diff)); encErr != nil {
			return fmt.Errorf("encoding JSON: %w", encErr)
		}
		return nil
	}

	return printLicenseDiff(diff, stdout)
}

// -- text output --

func printLicenseDiff(diff domain.LicenseDiff, stdout io.Writer) error {
	a := diff.RecordA.Coordinate
	b := diff.RecordB.Coordinate

	if _, err := fmt.Fprintf(stdout, "Diff:  %s@%s → %s@%s\n", a.Path, a.Version, b.Path, b.Version); err != nil {
		return fmt.Errorf("writing header: %w", err)
	}

	if !diff.HasChanges() && diff.Escalation == nil {
		if _, err := fmt.Fprintln(stdout, "No license changes."); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		return nil
	}

	if diff.Escalation != nil {
		if _, err := fmt.Fprintf(stdout, "\n[ESCALATION] %s → %s (permissive to %s copyleft)\n",
			diff.RecordA.PrimarySPDX, diff.RecordB.PrimarySPDX, diff.Escalation.To.String()); err != nil {
			return fmt.Errorf("writing escalation: %w", err)
		}
	}

	if diff.SPDXChanged != nil {
		from := diff.SPDXChanged.From
		if from == "" {
			from = "(none)"
		}
		to := diff.SPDXChanged.To
		if to == "" {
			to = "(none)"
		}
		if _, err := fmt.Fprintf(stdout, "\nSPDX:  %s → %s\n", from, to); err != nil {
			return fmt.Errorf("writing SPDX change: %w", err)
		}
	}

	if diff.StatusChanged != nil {
		if _, err := fmt.Fprintf(stdout, "Status: %s → %s\n",
			diff.StatusChanged.From.String(), diff.StatusChanged.To.String()); err != nil {
			return fmt.Errorf("writing status change: %w", err)
		}
	}

	if len(diff.FilesAdded) > 0 {
		if _, err := fmt.Fprintf(stdout, "\nFiles added (%d):\n", len(diff.FilesAdded)); err != nil {
			return fmt.Errorf("writing files added header: %w", err)
		}
		for _, f := range diff.FilesAdded {
			if _, err := fmt.Fprintf(stdout, "  + %s  [%s]\n", f.Path, f.SPDX); err != nil {
				return fmt.Errorf("writing file entry: %w", err)
			}
		}
	}

	if len(diff.FilesRemoved) > 0 {
		if _, err := fmt.Fprintf(stdout, "\nFiles removed (%d):\n", len(diff.FilesRemoved)); err != nil {
			return fmt.Errorf("writing files removed header: %w", err)
		}
		for _, f := range diff.FilesRemoved {
			if _, err := fmt.Fprintf(stdout, "  - %s  [%s]\n", f.Path, f.SPDX); err != nil {
				return fmt.Errorf("writing file entry: %w", err)
			}
		}
	}

	if len(diff.CopyrightAdded) > 0 {
		if _, err := fmt.Fprintf(stdout, "\nCopyright added (%d):\n", len(diff.CopyrightAdded)); err != nil {
			return fmt.Errorf("writing copyright added header: %w", err)
		}
		for _, s := range diff.CopyrightAdded {
			if _, err := fmt.Fprintf(stdout, "  + %s\n", s.Verbatim); err != nil {
				return fmt.Errorf("writing copyright statement: %w", err)
			}
		}
	}

	if len(diff.CopyrightRemoved) > 0 {
		if _, err := fmt.Fprintf(stdout, "\nCopyright removed (%d):\n", len(diff.CopyrightRemoved)); err != nil {
			return fmt.Errorf("writing copyright removed header: %w", err)
		}
		for _, s := range diff.CopyrightRemoved {
			if _, err := fmt.Fprintf(stdout, "  - %s\n", s.Verbatim); err != nil {
				return fmt.Errorf("writing copyright statement: %w", err)
			}
		}
	}

	return nil
}

// -- JSON output --

type licenseDiffJSON struct {
	ModuleA          string             `json:"module_a"`
	ModuleB          string             `json:"module_b"`
	SPDXChanged      *spdxChangeJSON    `json:"spdx_changed,omitempty"`
	StatusChanged    *statusChangeJSON  `json:"status_changed,omitempty"`
	FilesAdded       []licFileDeltaJSON `json:"files_added"`
	FilesRemoved     []licFileDeltaJSON `json:"files_removed"`
	CopyrightAdded   []string           `json:"copyright_added"`
	CopyrightRemoved []string           `json:"copyright_removed"`
	Escalation       *escalationJSON    `json:"escalation,omitempty"`
}

type spdxChangeJSON struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type statusChangeJSON struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type licFileDeltaJSON struct {
	Path string `json:"path"`
	SPDX string `json:"spdx"`
}

type escalationJSON struct {
	From string `json:"from"`
	To   string `json:"to"`
}

func toLicenseDiffJSON(diff domain.LicenseDiff) licenseDiffJSON {
	a := diff.RecordA.Coordinate
	b := diff.RecordB.Coordinate

	out := licenseDiffJSON{
		ModuleA:          a.Path + "@" + a.Version,
		ModuleB:          b.Path + "@" + b.Version,
		FilesAdded:       make([]licFileDeltaJSON, 0, len(diff.FilesAdded)),
		FilesRemoved:     make([]licFileDeltaJSON, 0, len(diff.FilesRemoved)),
		CopyrightAdded:   make([]string, 0, len(diff.CopyrightAdded)),
		CopyrightRemoved: make([]string, 0, len(diff.CopyrightRemoved)),
	}

	if diff.SPDXChanged != nil {
		out.SPDXChanged = &spdxChangeJSON{From: diff.SPDXChanged.From, To: diff.SPDXChanged.To}
	}
	if diff.StatusChanged != nil {
		out.StatusChanged = &statusChangeJSON{
			From: diff.StatusChanged.From.String(),
			To:   diff.StatusChanged.To.String(),
		}
	}
	for _, f := range diff.FilesAdded {
		out.FilesAdded = append(out.FilesAdded, licFileDeltaJSON{Path: f.Path, SPDX: f.SPDX})
	}
	for _, f := range diff.FilesRemoved {
		out.FilesRemoved = append(out.FilesRemoved, licFileDeltaJSON{Path: f.Path, SPDX: f.SPDX})
	}
	for _, s := range diff.CopyrightAdded {
		out.CopyrightAdded = append(out.CopyrightAdded, s.Verbatim)
	}
	for _, s := range diff.CopyrightRemoved {
		out.CopyrightRemoved = append(out.CopyrightRemoved, s.Verbatim)
	}
	if diff.Escalation != nil {
		out.Escalation = &escalationJSON{
			From: diff.Escalation.From.String(),
			To:   diff.Escalation.To.String(),
		}
	}

	return out
}
