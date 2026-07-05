package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
	"github.com/spf13/cobra"
)

func newWalkListCmd(stdout, stderr io.Writer) *cobra.Command {
	var f commonWalkFlags
	var target string
	var since string
	var statusStr string
	var scopeStr string
	var tool bool
	var limit int
	var walkID string
	var latest bool
	var latestSuccess bool

	cmd := &cobra.Command{
		Use:   "walk-list",
		Short: "List stored walk records",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if tool && scopeStr != "" {
				return fmt.Errorf("cannot combine --tool and --scope")
			}
			if tool {
				scopeStr = "tool"
			}
			if latestSuccess {
				if statusStr != "" && statusStr != "succeeded" {
					return fmt.Errorf("--latest-success implies --status succeeded; cannot combine with --status %s", statusStr)
				}
				statusStr = "succeeded"
				limit = 1
			}
			logger := buildLogger(logLevel, stderr)
			ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
			if err != nil {
				return fmt.Errorf("initialising store: %w", err)
			}
			defer func() { _ = cleanup() }()
			return runWalkList(cmd.Context(), f, target, since, statusStr, scopeStr, walkID, limit, latest, latestSuccess, ctr.QueryWalks, stdout, stderr)
		},
	}
	cmd.Flags().StringVar(&target, "target", "", "filter by target module@version")
	cmd.Flags().StringVar(&since, "since", "", "filter by start time (RFC3339)")
	cmd.Flags().StringVar(&statusStr, "status", "", "filter by overall status (succeeded|partial|failed|cancelled)")
	cmd.Flags().StringVar(&scopeStr, "scope", "", "filter by walk scope (production|tool)")
	cmd.Flags().BoolVar(&tool, "tool", false, "shorthand for --scope tool")
	cmd.Flags().IntVar(&limit, "limit", 20, "maximum number of results to return (0 = unlimited)")
	cmd.Flags().StringVar(&walkID, "walk-id", "", "fetch a single walk summary by ID")
	cmd.Flags().BoolVar(&latest, "latest", false, "return only the latest unique (target, scope) combination")
	cmd.Flags().BoolVar(&latestSuccess, "latest-success", false, "return only the single most recent succeeded walk (as a JSON object, not an array)")
	return cmd
}
func runWalkList(
	ctx context.Context,
	f commonWalkFlags,
	targetArg, sinceArg, statusArg, scopeArg, walkID string,
	limit int,
	latest bool,
	latestSuccess bool,
	uc QueryWalksUseCase,
	stdout, _ io.Writer,
) error {
	if walkID != "" {
		rec, rerr := uc.GetWalk(ctx, walkID)
		if rerr != nil {
			if isWalkNotFound(rerr) {
				return fmt.Errorf("walk %s not found", walkID)
			}
			return fmt.Errorf("loading walk %s: %w", walkID, rerr)
		}
		summary := walkports.WalkSummary{
			ID:            rec.ID,
			Target:        rec.Target,
			Scope:         rec.Scope,
			Depth:         rec.Depth,
			StartedAt:     rec.StartedAt,
			CompletedAt:   rec.CompletedAt,
			OverallStatus: rec.OverallStatus,
			NodeCount:     len(rec.Graph.Nodes),
			FailureCount:  countFailures(rec),
		}
		if jsonOut {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			if encErr := enc.Encode(summary); encErr != nil {
				return fmt.Errorf("encoding JSON: %w", encErr)
			}
			return nil
		}
		if _, pErr := fmt.Fprintf(stdout, "%s  %s  %s  %s  scope=%s  depth=%s  nodes=%d failures=%d\n",
			summary.ID, summary.Target.String(), summary.StartedAt.UTC().Format(time.RFC3339),
			summary.OverallStatus.String(), string(summary.Scope), string(summary.Depth), summary.NodeCount, summary.FailureCount,
		); pErr != nil {
			return fmt.Errorf("writing output: %w", pErr)
		}
		return nil
	}
	filter := walkports.WalkFilter{Limit: limit, LatestOnly: latest}

	if targetArg != "" {
		coord, cerr := parseCoordinate(targetArg)
		if cerr != nil {
			return fmt.Errorf("invalid target coordinate %q: %w", targetArg, cerr)
		}
		filter.Target = &coord
	}
	if sinceArg != "" {
		t, perr := time.Parse(time.RFC3339, sinceArg)
		if perr != nil {
			return fmt.Errorf("parsing --since %q: %w", sinceArg, perr)
		}
		filter.Since = &t
	}
	if statusArg != "" {
		st, perr := parseWalkStatus(statusArg)
		if perr != nil {
			return fmt.Errorf("parsing --status %q: %w", statusArg, perr)
		}
		filter.OverallStatus = &st
	}
	if scopeArg != "" {
		sc, perr := parseWalkScope(scopeArg)
		if perr != nil {
			return fmt.Errorf("parsing --scope %q: %w", scopeArg, perr)
		}
		filter.Scope = &sc
	}

	summaries, err := uc.ListWalks(ctx, filter)
	if err != nil {
		return fmt.Errorf("listing walks: %w", err)
	}

	if latestSuccess {
		if len(summaries) == 0 {
			return fmt.Errorf("no succeeded walk found")
		}
		s := summaries[0]
		if jsonOut {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			if encErr := enc.Encode(s); encErr != nil {
				return fmt.Errorf("encoding JSON: %w", encErr)
			}
			return nil
		}
		if _, pErr := fmt.Fprintf(stdout, "%s  %s  %s  %s  scope=%s  depth=%s  nodes=%d failures=%d\n",
			s.ID, s.Target.String(), s.StartedAt.UTC().Format(time.RFC3339),
			s.OverallStatus.String(), string(s.Scope), string(s.Depth), s.NodeCount, s.FailureCount,
		); pErr != nil {
			return fmt.Errorf("writing output: %w", pErr)
		}
		return nil
	}

	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if encErr := enc.Encode(summaries); encErr != nil {
			return fmt.Errorf("encoding JSON: %w", encErr)
		}
		return nil
	}

	if len(summaries) == 0 {
		if _, pErr := fmt.Fprintln(stdout, "no walk records found"); pErr != nil {
			return fmt.Errorf("writing output: %w", pErr)
		}
		return nil
	}
	for _, s := range summaries {
		if _, pErr := fmt.Fprintf(stdout, "%s  %s  %s  %s  scope=%s  depth=%s  nodes=%d failures=%d\n",
			s.ID, s.Target.String(), s.StartedAt.UTC().Format(time.RFC3339),
			s.OverallStatus.String(), string(s.Scope), string(s.Depth), s.NodeCount, s.FailureCount,
		); pErr != nil {
			return fmt.Errorf("writing output: %w", pErr)
		}
	}
	return nil
}
func parseWalkStatus(s string) (domain.WalkStatus, error) {
	switch strings.ToLower(s) {
	case "succeeded":
		return domain.WalkSucceeded, nil
	case "partial":
		return domain.WalkPartial, nil
	case "failed":
		return domain.WalkFailed, nil
	case "cancelled":
		return domain.WalkCancelled, nil
	default:
		return 0, fmt.Errorf("unknown status %q; want succeeded|partial|failed|cancelled", s)
	}
}
func parseWalkScope(s string) (domain.WalkScope, error) {
	switch strings.ToLower(s) {
	case "code":
		return domain.WalkScopeCode, nil
	case "tool":
		return domain.WalkScopeTool, nil
	case "complete":
		return domain.WalkScopeComplete, nil
	default:
		return "", fmt.Errorf("unknown scope %q; want code|tool|complete", s)
	}
}
func countFailures(rec domain.WalkRecord) int {
	n := 0
	for _, r := range rec.PerNodeResults {
		if r.Status != domain.NodeSucceeded {
			n++
		}
	}
	return n
}
