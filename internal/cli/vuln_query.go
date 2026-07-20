package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	vulnapp "github.com/eitanity/kanonarion/internal/vuln/application"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/spf13/cobra"
)

// vulnPipelineVersion is the vuln scan pipeline version the read-side query
// commands pin to. It mirrors the version the container scans under so a query
// resolves the records the scanner wrote — keeping reader and writer on a
// single source of truth instead of duplicating the literal at each call site.
const vulnPipelineVersion = vulnapp.PipelineVersion

func newVulnShowCmd(stdout, _ io.Writer) *cobra.Command {
	var walkID string
	var history bool

	cmd := &cobra.Command{
		Use:   "vuln-show <module>@<version>",
		Short: "Show the vulnerability record for a module",
		Long: `Show the vulnerability record for a module.

When --walk-id is omitted, vuln-show returns the most recent scan for the
module across all walks. Pass --walk-id to pin to a specific walk.

Use --history to list every stored scan record for the module across all
walks and snapshots, newest first. This shows when a finding first appeared
or was absent because the vulnerability database snapshot predated it.`,
		Example: `  kanonarion vuln-show github.com/gin-gonic/gin@v1.6.2
  kanonarion vuln-show github.com/gin-gonic/gin@v1.6.2 --json
  kanonarion vuln-show github.com/gin-gonic/gin@v1.6.2 --history
  kanonarion vuln-show github.com/gin-gonic/gin@v1.6.2 --history --json
  kanonarion vuln-show github.com/gin-gonic/gin@v1.6.2 --walk-id 01KQDBVW092ER1HNXZ60X27CMD
  kanonarion vuln-show github.com/gin-gonic/gin@v1.6.2 --walk-id 01KQDBVW092ER1HNXZ60X27CMD --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := buildLogger(logLevel, stdout)
			ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
			if err != nil {
				return fmt.Errorf("initialising store: %w", err)
			}
			defer func() { _ = cleanup() }()
			return runVulnShow(cmd.Context(), args[0], walkID, jsonOut, history, ctr.QueryVuln, stdout)
		},
	}

	cmd.Flags().BoolVar(&history, "history", false, "list all scan records across walks and snapshots")
	cmd.Flags().StringVar(&walkID, "walk-id", "", "walk ID the scan was performed under (optional; defaults to most recent scan)")

	return cmd
}

func runVulnShow(ctx context.Context, arg, walkID string, jsonOut, history bool, uc QueryVulnUseCase, stdout io.Writer) error {
	coord, err := parseCoordinate(arg)
	if err != nil {
		return fmt.Errorf("invalid coordinate %q: %w", arg, err)
	}

	if history {
		return runVulnShowHistory(ctx, coord, jsonOut, uc, stdout)
	}

	var rec vuldomain.VulnerabilityRecord
	if walkID == "" {
		r, ok, err := uc.GetLatestRecord(ctx, coord, vulnPipelineVersion)
		if err != nil {
			return fmt.Errorf("getting vulnerability record: %w", err)
		}
		if !ok {
			return fmt.Errorf("no vulnerability record for %s — run: kanonarion vuln-scan <walk-id>", coord)
		}
		rec = r
	} else {
		r, ok, err := uc.GetLatestRecordForWalk(ctx, coord, vulnPipelineVersion, walkID)
		if err != nil {
			return fmt.Errorf("getting vulnerability record: %w", err)
		}
		if !ok {
			any, _, aerr := uc.GetLatestRecord(ctx, coord, vulnPipelineVersion)
			if aerr == nil && any.OverallStatus == vuldomain.StatusScanFailed {
				msg := fmt.Sprintf("scan for %s failed", coord)
				if any.ErrorDetail != "" {
					msg += ": " + any.ErrorDetail
				}
				return fmt.Errorf("%s — re-run: kanonarion vuln-scan %s", msg, walkID)
			}
			return fmt.Errorf("no vulnerability record for %s in walk %s — run: kanonarion vuln-scan %s", coord, walkID, walkID)
		}
		rec = r
	}

	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rec); err != nil {
			return fmt.Errorf("encoding vulnerability record: %w", err)
		}
		return nil
	}

	printVulnRecord(stdout, rec)
	return nil
}

func runVulnShowHistory(ctx context.Context, coord coordinate.ModuleCoordinate, jsonOut bool, uc QueryVulnUseCase, stdout io.Writer) error {
	recs, err := uc.ListRecordsForModule(ctx, coord, vulnPipelineVersion)
	if err != nil {
		return fmt.Errorf("listing vulnerability history: %w", err)
	}
	if len(recs) == 0 {
		return fmt.Errorf("no vulnerability records for %s — run 'kanonarion vuln-scan' first", coord)
	}

	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(recs); err != nil {
			return fmt.Errorf("encoding vulnerability history: %w", err)
		}
		return nil
	}

	_, _ = fmt.Fprintf(stdout, "%s@%s — %d scan record(s)\n\n", coord.Path, coord.Version, len(recs))
	for _, rec := range recs {
		findingIDs := make([]string, 0, len(rec.Findings))
		for _, f := range rec.Findings {
			findingIDs = append(findingIDs, f.ID)
		}
		findingSummary := "no findings"
		if len(findingIDs) > 0 {
			findingSummary = strings.Join(findingIDs, "  ")
		}
		_, _ = fmt.Fprintf(stdout, "  %s  walk=%-26s  snap=%-24s  %-8s  %s\n",
			rec.ScannedAt.UTC().Format(time.RFC3339),
			rec.WalkID,
			rec.DatabaseSnapshot.Version,
			rec.OverallStatus,
			findingSummary,
		)
	}
	return nil
}

func newVulnByIDCmd(stdout, _ io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vuln-by-id <finding-id>",
		Short: "Find all modules affected by a specific vulnerability ID",
		Example: `  kanonarion vuln-by-id GO-2023-1234
  kanonarion vuln-by-id CVE-2023-12345 --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := buildLogger(logLevel, stdout)
			ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
			if err != nil {
				return fmt.Errorf("initialising store: %w", err)
			}
			defer func() { _ = cleanup() }()
			return runVulnByID(cmd.Context(), args[0], jsonOut, ctr.QueryVuln, stdout)
		},
	}

	return cmd
}

func runVulnByID(ctx context.Context, findingID string, jsonOut bool, uc QueryVulnUseCase, stdout io.Writer) error {
	records, err := uc.ListRecordsByFindingID(ctx, findingID)
	if err != nil {
		return fmt.Errorf("querying by finding ID: %w", err)
	}
	if jsonOut {
		// emit a JSON array ("[]" when empty), never plain text.
		if records == nil {
			records = []vuldomain.VulnerabilityRecord{}
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(records); err != nil {
			return fmt.Errorf("encoding vulnerability records: %w", err)
		}
		return nil
	}

	if len(records) == 0 {
		_, _ = fmt.Fprintf(stdout, "no modules affected by %s\n", findingID)
		return nil
	}

	for _, rec := range records {
		_, _ = fmt.Fprintf(stdout, "%-60s %s\n",
			rec.Coordinate.Path+"@"+rec.Coordinate.Version,
			rec.OverallStatus)
	}
	return nil
}
