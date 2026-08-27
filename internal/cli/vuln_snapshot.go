package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"

	"github.com/spf13/cobra"
)

func newVulnSnapshotListCmd(stdout, stderr io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:         "vuln-snapshot-list",
		Annotations: map[string]string{annotationStoreIntent: StoreIntentRead},
		Short:       "List stored vulnerability database snapshots",
		RunE: func(cmd *cobra.Command, _ []string) error {
			logger := buildLogger(logLevel, stderr)
			ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
			if err != nil {
				return fmt.Errorf("initialising store: %w", err)
			}
			defer func() { _ = cleanup() }()
			return runSnapshotList(cmd.Context(), jsonOut, ctr.QueryScanRuns, stdout, stderr)
		},
	}

	return cmd
}

func runSnapshotList(ctx context.Context, jsonOut bool, uc QueryScanRunsUseCase, stdout, stderr io.Writer) error {
	snapshots, err := uc.ListSnapshots(ctx)
	if err != nil {
		return fmt.Errorf("listing snapshots: %w", err)
	}
	// The empty case is answered on the caller's own channel: under --json an
	// empty array on stdout, never a human sentence that fails to parse, with
	// the statement of scope alongside it on stderr. Only the text path gets
	// the prose.
	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if snapshots == nil {
			snapshots = []vuldomain.DatabaseSnapshot{}
		}
		if err := enc.Encode(snapshots); err != nil {
			return fmt.Errorf("encoding snapshots: %w", err)
		}
		if len(snapshots) == 0 {
			return writeListZeroNoticeJSON(stderr, snapshotListZeroScope(snapshots))
		}
		return nil
	}

	if len(snapshots) == 0 {
		return writeListZeroNotice(stdout, snapshotListZeroScope(snapshots))
	}

	for _, s := range snapshots {
		_, _ = fmt.Fprintf(stdout, "%-30s %-20s %s\n",
			s.Source(), s.Version(), s.RetrievedAt().UTC().Format("2006-01-02T15:04:05Z"))
	}
	return nil
}

// snapshotListZeroScope states what vuln-snapshot-list looked at when it found
// nothing.
//
// This listing takes no filter and no offset, so it has exactly one cause it
// can have — the store holds no snapshot — and it says that one rather than
// borrowing the filter and paging clauses its neighbours need. It also needs no
// second read to say it: the corpus IS the result, so the count is the length
// of what already came back, and reaching for a survey read here would be
// asking the store for a number it just handed over.
func snapshotListZeroScope(snapshots []vuldomain.DatabaseSnapshot) listZeroScope {
	return listZeroScope{
		subject:    "vulnerability database snapshot",
		considered: len(snapshots),
		// A snapshot is pinned by the scan that judged a walk against it; there
		// is no command whose job is to fetch one on its own.
		produce: "kanonarion vuln-scan <walk-id>",
		listAll: "kanonarion vuln-snapshot-list",
	}
}

func newVulnSnapshotShowCmd(stdout, stderr io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:         "vuln-snapshot-show <source> <version>",
		Annotations: map[string]string{annotationStoreIntent: StoreIntentRead},
		Short:       "Show metadata for a specific vulnerability database snapshot",
		Example: `  kanonarion vuln-snapshot-show govulndb v2024-01-01T00-00-00
  kanonarion vuln-snapshot-show govulndb v2024-01-01T00-00-00 --json`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := buildLogger(logLevel, stderr)
			ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
			if err != nil {
				return fmt.Errorf("initialising store: %w", err)
			}
			defer func() { _ = cleanup() }()
			return runSnapshotShow(cmd.Context(), args[0], args[1], jsonOut, ctr.QueryScanRuns, stdout, stderr)
		},
	}

	return cmd
}

func runSnapshotShow(ctx context.Context, source, version string, jsonOut bool, uc QueryScanRunsUseCase, stdout, stderr io.Writer) error {
	snapshots, err := uc.ListSnapshots(ctx)
	if err != nil {
		return fmt.Errorf("listing snapshots: %w", err)
	}

	for _, s := range snapshots {
		if s.Source() == source && s.Version() == version {
			if jsonOut {
				enc := json.NewEncoder(stdout)
				enc.SetIndent("", "  ")
				if err := enc.Encode(s); err != nil {
					return fmt.Errorf("encoding snapshot: %w", err)
				}
				return nil
			}
			_, _ = fmt.Fprintf(stdout, "Source:       %s\n", s.Source())
			_, _ = fmt.Fprintf(stdout, "Version:      %s\n", s.Version())
			_, _ = fmt.Fprintf(stdout, "Retrieved at: %s\n", s.RetrievedAt().UTC().Format(time.RFC3339))
			_, _ = fmt.Fprintf(stdout, "Content hash: %s\n", s.ContentHash())
			return nil
		}
	}
	return snapshotMiss(snapshots, source, version, jsonOut, stderr)
}

// snapshotMiss answers a snapshot named by source and version that the store
// does not hold, for `vuln-snapshot-show` and for the `--snapshot-source` /
// `--snapshot-version` pin on `vuln-scan-rescan`.
//
// The corpus was already read to answer the question, so saying how big it was
// costs nothing: a flat "snapshot not found" reads as "none have ever been
// pinned" over a store holding a dozen, and the remedy for those two is not the
// same one. Both surfaces say it the same way — the pin is the same lookup the
// show command makes, and a caller who has seen one has seen both.
func snapshotMiss(snapshots []vuldomain.DatabaseSnapshot, source, version string,
	jsonOut bool, stderr io.Writer,
) error {
	scope := listZeroScope{
		subject:     "vulnerability database snapshot",
		filterName:  "source and version",
		filterValue: source + "@" + version,
		field:       "source and version",
		matchKind:   matchExact,
		considered:  len(snapshots),
		produce:     "kanonarion vuln-scan <walk-id>",
		listAll:     "kanonarion vuln-snapshot-list",
	}
	if len(snapshots) > 0 {
		scope.example = snapshots[0].Source() + "@" + snapshots[0].Version()
	}
	if jsonOut {
		if werr := writeListZeroNoticeJSON(stderr, scope); werr != nil {
			return werr
		}
	}
	return &exitError{code: ExitNotFound, msg: listZeroLine(scope)}
}
