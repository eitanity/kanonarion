package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/spf13/cobra"
)

// A scan run names the walk it analysed, and nothing ties the two rows
// together: a migration that purged walks left runs behind, and their findings
// survive while the statement of what was scanned — at which versions, from
// which root — does not. Such a run is still evidence that a scan happened, so
// it is listed; what it must never do is render a walk id that reads as a live
// reference.
//
// The two phrasings share the leading clause so one grep finds every surface.
const unresolvableInputsShort = "inputs unresolvable: walk absent from this store"

// unresolvableInputsNote names the walk, for surfaces where the id is not
// already on the line the note joins.
func unresolvableInputsNote(walkID string) string {
	return fmt.Sprintf("inputs unresolvable: walk %s absent from this store", walkID)
}

func newVulnScanListCmd(stdout, stderr io.Writer) *cobra.Command {
	var limit, offset int

	cmd := &cobra.Command{
		Use:   "vuln-scan-list [walk-id]",
		Short: "List walk scan runs",
		Example: `  kanonarion vuln-scan-list
  kanonarion vuln-scan-list 01KQDBVW092ER1HNXZ60X27CMD`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var walkID string
			if len(args) == 1 {
				walkID = args[0]
			}
			logger := buildLogger(logLevel, stderr)
			ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
			if err != nil {
				return fmt.Errorf("initialising store: %w", err)
			}
			defer func() { _ = cleanup() }()
			return runScanList(cmd.Context(), walkID, limit, offset, ctr.QueryScanRuns, stdout, stderr)
		},
	}

	cmd.Flags().IntVar(&limit, "limit", 20, "maximum number of results to return (0 = unlimited)")
	cmd.Flags().IntVar(&offset, "offset", 0, "skip this many results")

	return cmd
}

func runScanList(ctx context.Context, walkID string, limit, offset int, uc QueryScanRunsUseCase, stdout, stderr io.Writer) error {
	var (
		runs []vuldomain.WalkScanRun
		err  error
	)
	if walkID == "" {
		runs, err = uc.ListAllRuns(ctx)
	} else {
		runs, err = uc.ListRunsForWalk(ctx, walkID)
	}
	// This command surveys the store, so a row it cannot verify is part of the
	// answer rather than a reason to withhold it. Any other error still aborts.
	unreadable, survivable := unreadableRunReport(err)
	if err != nil && !survivable {
		return fmt.Errorf("listing scan runs: %w", err)
	}
	// This listing already holds every run, so the extra row the other listings
	// over-fetch for is free here: the cap is applied in memory and what it
	// dropped is known exactly.
	// The port hands this listing its whole population — there is no filter to
	// carry an offset into — so the page is taken here, on the same ordering the
	// unpaged listing prints, before the cap is applied.
	runs = skipList(runs, offset)
	runs, truncated := truncateList(runs, limit)
	trunc := listTruncation{limit: limit, subject: "scan runs", truncated: truncated, offset: offset}
	// Derived after the limit is applied: the probe only has to classify the runs
	// this invocation will print, and it is one indexed read over their walks.
	unresolved, uerr := uc.UnresolvedWalks(ctx, runs)
	if uerr != nil {
		return fmt.Errorf("listing scan runs: %w", uerr)
	}
	if jsonOut {
		type entry struct {
			ID          string `json:"id"`
			WalkID      string `json:"walk_id"`
			Status      string `json:"status"`
			CompletedAt string `json:"completed_at"`
			Reason      string `json:"reason,omitempty"`
			// InputsUnresolvable states, when present, that the walk this run
			// names is gone. Absent on a run whose walk resolves, so an existing
			// consumer sees no change.
			InputsUnresolvable string `json:"inputs_unresolvable,omitempty"`
		}
		out := make([]entry, 0, len(runs)+len(unreadable))
		for _, r := range runs {
			e := entry{ID: r.ID, WalkID: r.WalkID, Status: string(r.OverallStatus), CompletedAt: isoTime(r.CompletedAt)}
			if unresolved[r.WalkID] {
				e.InputsUnresolvable = unresolvableInputsNote(r.WalkID)
			}
			out = append(out, e)
		}
		// The unreadable rows join the same array rather than a section of their
		// own: a caller that reads this output as "the runs in the store" must
		// not be able to miss them, and one that filters on status still can.
		for _, u := range unreadable {
			out = append(out, entry{ID: u.ID, Status: scanRunStatusUnreadable, Reason: u.Reason})
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			return fmt.Errorf("encoding JSON: %w", err)
		}
		if len(out) == 0 {
			scope, serr := scanListZeroScope(ctx, walkID, offset, uc)
			if serr != nil {
				return serr
			}
			return writeListZeroNoticeJSON(stderr, scope)
		}
		return writeListTruncationJSON(stderr, trunc)
	}
	if len(runs) == 0 && len(unreadable) == 0 {
		scope, serr := scanListZeroScope(ctx, walkID, offset, uc)
		if serr != nil {
			return serr
		}
		return writeListZeroNotice(stdout, scope)
	}
	for _, r := range runs {
		line := fmt.Sprintf("%-26s  walk=%-26s  status=%-12s  %s",
			r.ID, r.WalkID, string(r.OverallStatus), r.CompletedAt.UTC().Format("2006-01-02T15:04:05Z"))
		if unresolved[r.WalkID] {
			line += "  " + unresolvableInputsShort
		}
		_, _ = fmt.Fprintln(stdout, line)
	}
	writeUnreadableRuns(stdout, unreadable)
	return writeListTruncationNotice(stdout, trunc)
}

// scanListZeroScope lifts the walk-id filter and re-asks the store, so a zero
// distinguishes "that walk has no scan run" from "nothing has been scanned".
// Reached only when the listing came back empty.
func scanListZeroScope(ctx context.Context, walkID string, offset int, uc QueryScanRunsUseCase) (listZeroScope, error) {
	all, err := uc.ListAllRuns(ctx)
	// A store that cannot be surveyed still answers the question the listing was
	// asked; what it cannot do is size the corpus, and a count of zero would
	// assert exactly the thing it failed to measure.
	if _, survivable := unreadableRunReport(err); err != nil && !survivable {
		return listZeroScope{}, fmt.Errorf("counting scan runs for the zero-result notice: %w", err)
	}
	scope := listZeroScope{
		subject:     "scan run",
		filterName:  "walk id",
		filterValue: walkID,
		field:       "walk id each run was recorded against",
		matchKind:   matchExact,
		considered:  len(all),
		produce:     "kanonarion vuln-scan <walk-id>",
		listAll:     "kanonarion vuln-scan-list",
	}
	if len(all) > 0 {
		scope.example = all[0].WalkID
	}
	// An offset past the end empties the page without the filter having anything
	// to do with it, and the two look identical from the rows alone.
	// An empty corpus is not something a page can start past, so a zero over it
	// keeps the store-empty statement and its produce-a-record remedy.
	if walkID == "" && len(all) > 0 && offset > 0 && offset >= len(all) {
		scope.pagedPast = fmt.Sprintf("--offset %d starts past the last one", offset)
	}
	return scope, nil
}

// scanRunMiss answers a `vuln-scan-show` that named a run the store does not
// hold. `scan run not found: X` reads the same over an empty store and over
// fifteen runs, and the two have different remedies: one caller has never
// scanned anything, the other has mistyped an id the store could show them.
//
// The corpus is every run in the store, not the runs of any one walk: a run id
// is not keyed on a walk, so the caller's walk is not what excluded it. The
// survey read is on the miss branch, where a found run never goes.
func scanRunMiss(ctx context.Context, uc QueryScanRunsUseCase, runID string, jsonOut bool, stderr io.Writer) error {
	all, err := uc.ListAllRuns(ctx)
	// A store with unreadable rows can still be counted; one that cannot be read
	// at all has nothing honest to say, and a zero substituted for a failed count
	// would assert exactly the thing it failed to measure.
	if _, survivable := unreadableRunReport(err); err != nil && !survivable {
		return fmt.Errorf("counting scan runs for the not-found notice: %w", err)
	}
	scope := listZeroScope{
		subject:     "scan run",
		filterName:  "run id",
		filterValue: runID,
		field:       "run id",
		matchKind:   matchExact,
		considered:  len(all),
		produce:     "kanonarion vuln-scan <walk-id>",
		listAll:     "kanonarion vuln-scan-list --limit 0",
	}
	if len(all) > 0 {
		scope.example = all[0].ID
	}
	if jsonOut {
		if werr := writeListZeroNoticeJSON(stderr, scope); werr != nil {
			return werr
		}
	}
	return &exitError{code: ExitNotFound, msg: listZeroLine(scope)}
}

func newVulnScanShowCmd(stdout, stderr io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vuln-scan-show <run-id>",
		Short: "Show details of a walk scan run",
		Example: `  kanonarion vuln-scan-show 01KQDBVW092ER1HNXZ60X27CMD
  kanonarion vuln-scan-show 01KQDBVW092ER1HNXZ60X27CMD --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := buildLogger(logLevel, stderr)
			ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
			if err != nil {
				return fmt.Errorf("initialising store: %w", err)
			}
			defer func() { _ = cleanup() }()
			return runScanShow(cmd.Context(), args[0], jsonOut, ctr.QueryScanRuns, ctr.QueryVuln, stdout, stderr)
		},
	}

	return cmd
}

type scanAffectedModule struct {
	Coordinate string `json:"coordinate"`
	Status     string `json:"status"`
	// Findings carry the rung behind each reachability answer. This command's
	// text surface prints finding IDs only, so --json is the sole place a
	// consumer reads a verdict from a scan run, and a negative published without
	// the rung is a negative published without what was searched to reach it.
	Findings []vulnFindingJSON `json:"findings,omitempty"`
}

type scanShowJSON struct {
	ID               string                                 `json:"id"`
	WalkID           string                                 `json:"walk_id"`
	Snapshot         vuldomain.DatabaseSnapshot             `json:"snapshot"`
	PerModuleResults map[coordinate.ModuleCoordinate]string `json:"per_module_results"`
	StartedAt        time.Time                              `json:"started_at"`
	CompletedAt      time.Time                              `json:"completed_at"`
	OverallStatus    vuldomain.WalkScanStatus               `json:"overall_status"`
	PipelineVersion  string                                 `json:"pipeline_version"`
	Operator         string                                 `json:"operator"`
	ContentHash      string                                 `json:"content_hash"`
	AffectedModules  []scanAffectedModule                   `json:"affected_modules,omitempty"`
	// WithdrawnModules are modules whose every matched advisory has been retracted
	// upstream. They are their own list rather than an omission: a module that once
	// reported a finding and now does not owes the reader the reason, and leaving it
	// out of the report reads as never-affected.
	WithdrawnModules []scanAffectedModule `json:"withdrawn_modules,omitempty"`
	ScanFailures     []scanRecordFault    `json:"scan_failures,omitempty"`
	ReadErrors       []scanRecordFault    `json:"read_errors,omitempty"`
	MissingRecords   []string             `json:"missing_records,omitempty"`
	// InputsUnresolvable states, when present, that the walk this run names is
	// gone: the findings below stand, but what was scanned cannot be recovered
	// from this store. Absent on a run whose walk resolves.
	InputsUnresolvable string `json:"inputs_unresolvable,omitempty"`
}

// scanRecordFault is a coordinate whose VulnerabilityRecord could not be read,
// paired with the store error. A read error is not absence: reporting the module
// as unscanned when the store could not be read is the misattribution
// audit.go's vulnAuditStatus removes, and it must not reappear here.
type scanRecordFault struct {
	Coordinate string `json:"coordinate"`
	Error      string `json:"error"`
}

// scanShowSummary is the per-module read-back of a scan run for display: the
// modules with findings, the Unscannable roll-up, and the two ways a module in
// PerModuleResults can fail to produce a summary line of its own — a store read
// error (a fault) and a record that was never persisted (a coverage gap).
//
// Neither may leave the module out of the summary silently. The header prints a
// module count from len(PerModuleResults), so a coordinate that resolves to no
// section would make the output claim more modules than it accounts for — the
// "appears in no roll-up" defect fixed one function above this one.
type scanShowSummary struct {
	affected    []scanAffectedModule
	withdrawn   []scanAffectedModule
	unscannable *unscannableRollup
	readErrors  []scanRecordFault
	missing     []string
	scanFailed  []scanRecordFault
}

func runScanShow(ctx context.Context, runID string, jsonOut bool, ucRuns QueryScanRunsUseCase, ucVuln QueryVulnUseCase, stdout, stderr io.Writer) error {
	run, found, err := ucRuns.GetRun(ctx, runID)
	// vuln-scan-list names the rows it could not verify, and this is the command
	// an operator runs next against one of those names. Refusing here would send
	// them from a listing that reports the fault to the one tool that will not
	// discuss it, which is the same dead end one step along.
	if unreadable, survivable := unreadableRunReport(err); survivable {
		return writeUnreadableRun(stdout, runID, unreadable, jsonOut)
	}
	if err != nil {
		return fmt.Errorf("getting scan run: %w", err)
	}
	if !found {
		return scanRunMiss(ctx, ucRuns, runID, jsonOut, stderr)
	}

	walkPresent, perr := ucRuns.WalkPresent(ctx, run.WalkID)
	if perr != nil {
		return fmt.Errorf("getting scan run: %w", perr)
	}

	summary := buildScanAffectedModules(ctx, run, ucVuln)
	affected := summary.affected
	unscannable := summary.unscannable

	if jsonOut {
		out := scanShowJSON{
			ID:               run.ID,
			WalkID:           run.WalkID,
			Snapshot:         run.Snapshot,
			PerModuleResults: run.PerModuleResults,
			StartedAt:        run.StartedAt,
			CompletedAt:      run.CompletedAt,
			OverallStatus:    run.OverallStatus,
			PipelineVersion:  run.PipelineVersion,
			Operator:         run.Operator,
			ContentHash:      run.ContentHash,
			AffectedModules:  affected,
			WithdrawnModules: summary.withdrawn,
			ScanFailures:     summary.scanFailed,
			ReadErrors:       summary.readErrors,
			MissingRecords:   summary.missing,
		}
		if !walkPresent {
			out.InputsUnresolvable = unresolvableInputsNote(run.WalkID)
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			return fmt.Errorf("encoding scan run: %w", err)
		}
		return nil
	}

	_, _ = fmt.Fprintf(stdout, "ID:          %s\n", run.ID)
	if walkPresent {
		_, _ = fmt.Fprintf(stdout, "Walk ID:     %s\n", run.WalkID)
	} else {
		// Stated on the line the reference is rendered on, so a reader cannot take
		// the id for a resolvable one without also reading that it is not.
		_, _ = fmt.Fprintf(stdout, "Walk ID:     %s (%s)\n", run.WalkID, unresolvableInputsShort)
	}
	_, _ = fmt.Fprintf(stdout, "Status:      %s\n", run.OverallStatus)
	_, _ = fmt.Fprintf(stdout, "Operator:    %s\n", run.Operator)
	_, _ = fmt.Fprintf(stdout, "Started:     %s\n", run.StartedAt.UTC().Format(time.RFC3339))
	_, _ = fmt.Fprintf(stdout, "Completed:   %s\n", run.CompletedAt.UTC().Format(time.RFC3339))
	_, _ = fmt.Fprintf(stdout, "Snapshot:    %s@%s\n", run.Snapshot.Source(), run.Snapshot.Version())
	_, _ = fmt.Fprintf(stdout, "Advisories:  %s\n", advisoryCountLine(run.Snapshot))
	_, _ = fmt.Fprintf(stdout, "Modules:     %d\n", len(run.PerModuleResults))
	// One line per reason rather than one for the out-of-toolchain set alone, so
	// a Partial run is explained whichever reason produced it and no Unscannable
	// module is absent from the detail view.
	for _, section := range unscannable.sections() {
		line := fmt.Sprintf("%s: %d", section.display.heading, len(section.coords))
		if section.display.hint != "" {
			line += " — " + section.display.hint
		}
		_, _ = fmt.Fprintf(stdout, "%s\n", line)
	}
	// The two ways a counted module produces no line above: a store read error
	// (a fault) and a record that was never persisted (a coverage gap). Each gets
	// its own heading in the unscannableRollup section shape rather than a silent
	// skip, so the module count over the header is always accounted for.
	writeScanFailures(summary.scanFailed, stdout)
	writeScanRecordFaults(summary.readErrors, stdout)
	writeMissingScanRecords(summary.missing, stdout)
	writeScanModuleFindings(stdout, "Affected modules", affected)
	// Printed after the affected list and separately from it: a reader scanning for
	// what to act on sees the affected set alone, and a reader asking why a module
	// stopped being listed finds it named here with the retraction date rather than
	// having to notice its absence.
	writeScanModuleFindings(stdout, "Withdrawn advisories, not counted as findings", summary.withdrawn)
	return nil
}

// writeScanModuleFindings prints one findings section: a heading with the module
// count, then one line per module naming its finding IDs. A withdrawn advisory
// carries its retraction date, which is the whole reason it is listed apart from
// the affected set.
func writeScanModuleFindings(stdout io.Writer, heading string, modules []scanAffectedModule) {
	if len(modules) == 0 {
		return
	}
	_, _ = fmt.Fprintf(stdout, "\n%s (%d):\n", heading, len(modules))
	for _, m := range modules {
		findingIDs := make([]string, 0, len(m.Findings))
		for _, f := range m.Findings {
			id := f.ID
			if f.IsWithdrawn() {
				id += " (withdrawn " + f.WithdrawnAt.UTC().Format(time.RFC3339) + ")"
			}
			findingIDs = append(findingIDs, id)
		}
		_, _ = fmt.Fprintf(stdout, "  %s  %s\n", m.Coordinate, strings.Join(findingIDs, "  "))
	}
}

// buildScanAffectedModules looks up VulnerabilityRecords for each module in
// the scan run and returns entries where findings were present.
// It also returns, as a second value, every Unscannable module collected by
// reason, so the detail view carries the same categories the scan output does.
// Previously only the out-of-toolchain reason was collected and every other
// Unscannable record was dropped from the query output entirely.
//
// A store read error and a not-found record are also collected separately
// rather than collapsed into one silent skip: a read error is a fault (the
// store could not be read, so the module is neither scanned nor absent) and a
// not-found record is a coverage gap (the run claims a verdict no record
// backs). Both were dropped before, leaving the header's module count higher
// than the summary explained.
func buildScanAffectedModules(ctx context.Context, run vuldomain.WalkScanRun, uc QueryVulnUseCase) scanShowSummary {
	coords := make([]coordinate.ModuleCoordinate, 0, len(run.PerModuleResults))
	for coord := range run.PerModuleResults {
		coords = append(coords, coord)
	}
	sort.Slice(coords, func(i, j int) bool {
		if coords[i].Path() != coords[j].Path() {
			return coords[i].Path() < coords[j].Path()
		}
		return coords[i].Version() < coords[j].Version()
	})

	summary := scanShowSummary{unscannable: newUnscannableRollup()}
	for _, coord := range coords {
		rec, found, err := uc.GetRecord(ctx, coord, vulnPipelineVersion, run.Snapshot)
		if err != nil {
			summary.readErrors = append(summary.readErrors, scanRecordFault{
				Coordinate: coord.String(),
				Error:      err.Error(),
			})
			continue
		}
		if !found {
			summary.missing = append(summary.missing, coord.String())
			continue
		}
		// The two axes are reported independently, and a module can owe a line in
		// both sections. Routing on the collapsed word instead tested coverage
		// first and returned, so a record reporting an advisory under a coverage
		// gap — the metadata-only fallback's normal shape — had its findings
		// dropped from the report entirely: the one section the reader is looking
		// for. Coverage answers "was it analysed", findings answers "was anything
		// found", and neither may stand in for the other.
		coverage, findings := vuldomain.RecordAxes(rec)
		module := scanAffectedModule{
			Coordinate: coord.String(),
			Status:     string(rec.OverallStatus),
			Findings:   toVulnFindingsJSON(rec.Findings),
		}
		// The findings axis has three values and each owes its own section. A
		// withdrawn module is not affected, so it must not appear in the affected
		// list; it is also not silent, so it must not be absent from the report —
		// that absence is what let a retracted advisory read exactly like an
		// advisory that never applied.
		switch findings {
		case vuldomain.FindingsRecordAffected:
			summary.affected = append(summary.affected, module)
		case vuldomain.FindingsRecordWithdrawn:
			summary.withdrawn = append(summary.withdrawn, module)
		case vuldomain.FindingsRecordClean:
			// No advisory matched: nothing to name in either findings section.
		}
		// A coverage gap is reported whether or not an advisory matched, so a
		// finding that was never checked for reachability is not read as one that
		// was. A failed scan is a fault, reported like a read error rather than
		// dropped: the module was neither analysed nor declared out of scope, and a
		// bare skip left it counted in the header and named nowhere.
		switch coverage {
		case vuldomain.CoverageUnscannable:
			summary.unscannable.add(rec.UnscanReason, coord.String(), rec.UnscannableReason)
		case vuldomain.CoverageFailedScan:
			summary.scanFailed = append(summary.scanFailed, scanRecordFault{
				Coordinate: coord.String(),
				Error:      rec.ErrorDetail,
			})
		case vuldomain.CoverageAnalysed:
			// Analysed: the findings axis above is the whole answer, no caveat owed.
		}
	}
	return summary
}

// writeScanFailures prints the scan-failure section: modules whose scan itself
// failed (ScanFailed), each named with its recorded error detail. Same section
// shape as the read-error and Unscannable sections. A ScanFailed module is a
// fault, not a clean or out-of-scope module, so it is surfaced rather than
// dropped by the "no findings" path.
func writeScanFailures(faults []scanRecordFault, w io.Writer) {
	if len(faults) == 0 {
		return
	}
	_, _ = fmt.Fprintf(w, "Scan failed (%d): the scan of these modules failed — no verdict was reached\n", len(faults))
	for _, f := range faults {
		if f.Error == "" {
			_, _ = fmt.Fprintf(w, "  %s\n", f.Coordinate)
			continue
		}
		_, _ = fmt.Fprintf(w, "  %s: %s\n", f.Coordinate, f.Error)
	}
}

// writeScanRecordFaults prints the read-error section: a heading carrying the
// count and an explanation, then one line per coordinate naming the store
// error. It follows the unscannableRollup section shape — heading "(N):
// explanation" over an indented coordinate list — so the reader meets one
// format for "counted but carries no findings line", not a third.
//
// A read error is reported as a fault, never as absence: the reader must not be
// told a module is unscanned when the store could not be read.
func writeScanRecordFaults(faults []scanRecordFault, w io.Writer) {
	if len(faults) == 0 {
		return
	}
	_, _ = fmt.Fprintf(w, "Read errors (%d): the vulnerability store could not be read for these modules — neither scanned nor absent\n", len(faults))
	for _, f := range faults {
		_, _ = fmt.Fprintf(w, "  %s: %s\n", f.Coordinate, f.Error)
	}
}

// writeMissingScanRecords prints the coverage-gap section: modules the run
// reports a verdict for in PerModuleResults that no stored record backs. Same
// section shape as the read-error and Unscannable sections above it.
func writeMissingScanRecords(coords []string, w io.Writer) {
	if len(coords) == 0 {
		return
	}
	_, _ = fmt.Fprintf(w, "No scan record (%d): the run reports a verdict for these modules but no record backs it\n", len(coords))
	for _, c := range coords {
		_, _ = fmt.Fprintf(w, "  %s\n", c)
	}
}

// newVulnScanHistoryCmd returns the vuln-scan-history command.
func newVulnScanHistoryCmd(stdout, stderr io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vuln-scan-history <walk-id>",
		Short: "List every scan run for a walk in chronological order",
		Example: `  kanonarion vuln-scan-history 01KQDBVW092ER1HNXZ60X27CMD
  kanonarion vuln-scan-history 01KQDBVW092ER1HNXZ60X27CMD --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := buildLogger(logLevel, stderr)
			ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
			if err != nil {
				return fmt.Errorf("initialising store: %w", err)
			}
			defer func() { _ = cleanup() }()
			return runScanHistory(cmd.Context(), args[0], jsonOut, ctr.QueryScanRuns, stdout)
		},
	}

	return cmd
}

func runScanHistory(ctx context.Context, walkID string, jsonOut bool, uc QueryScanRunsUseCase, stdout io.Writer) error {
	runs, err := uc.ListRunsForWalk(ctx, walkID)
	// A history of a walk is a survey of the same rows vuln-scan-list surveys,
	// and reaches them through the same store seam, so it answers the same way:
	// every run it can read, plus the ones it cannot, named.
	unreadable, survivable := unreadableRunReport(err)
	if err != nil && !survivable {
		return fmt.Errorf("listing scan runs: %w", err)
	}
	// The walk is named by the caller here, so it is asked about directly rather
	// than derived from the runs: a walk that is gone owes the same statement
	// even when it has no readable run left to hang it on.
	walkPresent, perr := uc.WalkPresent(ctx, walkID)
	if perr != nil {
		return fmt.Errorf("listing scan runs: %w", perr)
	}
	// The empty case is answered on the caller's own channel: under --json an
	// empty array, never a human sentence that fails to parse. Only the text
	// path gets the prose.
	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if runs == nil {
			runs = []vuldomain.WalkScanRun{}
		}
		// The unreadable rows are reported on their own key rather than folded
		// into the run array, whose elements are whole WalkScanRuns: an entry
		// that is not one would have to be faked, and a fabricated run is a
		// worse answer than an omitted one. The key is absent when there are
		// none, so an existing consumer sees no change. The unresolvable-inputs
		// statement joins on the same terms and for the same reason: it is a fact
		// about the walk, not a field of any run.
		if len(unreadable) > 0 || !walkPresent {
			payload := struct {
				Runs               []vuldomain.WalkScanRun `json:"runs"`
				Unreadable         []unreadableRunEntry    `json:"unreadable,omitempty"`
				InputsUnresolvable string                  `json:"inputs_unresolvable,omitempty"`
			}{Runs: runs, Unreadable: unreadable}
			if !walkPresent {
				payload.InputsUnresolvable = unresolvableInputsNote(walkID)
			}
			if err := enc.Encode(payload); err != nil {
				return fmt.Errorf("encoding scan runs: %w", err)
			}
			return nil
		}
		if err := enc.Encode(runs); err != nil {
			return fmt.Errorf("encoding scan runs: %w", err)
		}
		return nil
	}

	if !walkPresent {
		_, _ = fmt.Fprintf(stdout, "%s\n", unresolvableInputsNote(walkID))
	}
	if len(runs) == 0 && len(unreadable) == 0 {
		_, _ = fmt.Fprintf(stdout, "no scan runs found for walk %s\n", walkID)
		return nil
	}

	_, _ = fmt.Fprintf(stdout, "%-26s  %-12s  %-30s  %s\n", "RUN ID", "STATUS", "SNAPSHOT", "COMPLETED")
	for _, r := range runs {
		snap := r.Snapshot.Source() + "@" + r.Snapshot.Version()
		_, _ = fmt.Fprintf(stdout, "%-26s  %-12s  %-30s  %s\n",
			r.ID,
			string(r.OverallStatus),
			snap,
			r.CompletedAt.UTC().Format("2006-01-02T15:04:05Z"),
		)
	}
	writeUnreadableRuns(stdout, unreadable)
	return nil
}

// newVulnScanDiffCmd returns the vuln-scan-diff command.
func newVulnScanDiffCmd(stdout, stderr io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vuln-scan-diff <run-id-a> <run-id-b>",
		Short: "Compare two scan runs of the same walk",
		Long: `vuln-scan-diff compares two WalkScanRuns of the same walk and reports:
  - findings present only in B (newly known vulnerabilities)
  - findings present only in A (resolved / no longer known)
  - findings present in both with changed reachability`,
		Example: `  kanonarion vuln-scan-diff vscan-01ABC vscan-01DEF
  kanonarion vuln-scan-diff vscan-01ABC vscan-01DEF --json`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := buildLogger(logLevel, stderr)
			ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
			if err != nil {
				return fmt.Errorf("initialising store: %w", err)
			}
			defer func() { _ = cleanup() }()
			return runScanDiff(cmd.Context(), args[0], args[1], jsonOut, ctr.DiffScanRuns, ctr.QueryScanRuns, stdout)
		},
	}

	return cmd
}

func runScanDiff(
	ctx context.Context, runIDA, runIDB string, jsonOut bool,
	ucDiff DiffScanRunsUseCase, ucRuns QueryScanRunsUseCase, stdout io.Writer,
) error {
	diff, err := ucDiff.Diff(ctx, runIDA, runIDB)
	if err != nil {
		return fmt.Errorf("computing scan diff: %w", err)
	}
	// A diff is a claim about two runs of one walk, so the walk it names carries
	// the same statement it does everywhere else.
	walkPresent, perr := ucRuns.WalkPresent(ctx, diff.RunA.WalkID)
	if perr != nil {
		return fmt.Errorf("computing scan diff: %w", perr)
	}

	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(toScanDiffJSON(diff)); err != nil {
			return fmt.Errorf("encoding scan diff: %w", err)
		}
		return nil
	}

	_, _ = fmt.Fprintf(stdout, "Diff: %s → %s\n", runIDA, runIDB)
	if walkPresent {
		_, _ = fmt.Fprintf(stdout, "Walk: %s\n\n", diff.RunA.WalkID)
	} else {
		_, _ = fmt.Fprintf(stdout, "Walk: %s (%s)\n\n", diff.RunA.WalkID, unresolvableInputsShort)
	}

	if len(diff.NewFindings) == 0 && len(diff.ResolvedFindings) == 0 && len(diff.WithdrawnFindings) == 0 &&
		len(diff.ReachabilityChanges) == 0 && len(diff.UnresolvedFindings) == 0 {
		// The populations are stated with the zero: two runs that agree on fifteen
		// affected modules and two runs that each found nothing are different
		// findings, and "No differences." alone reads the same for both.
		_, _ = fmt.Fprintf(stdout,
			"No differences: %s reports %d affected of %d module(s) analysed, %s reports %d of %d, and no finding, reachability or withdrawal moved between them\n",
			runIDA, diff.RunA.Counts.Affected, diff.RunA.Counts.Analysed,
			runIDB, diff.RunB.Counts.Affected, diff.RunB.Counts.Analysed)
		return nil
	}

	if len(diff.NewFindings) > 0 {
		_, _ = fmt.Fprintf(stdout, "NEW findings (%d):\n", len(diff.NewFindings))
		for _, d := range diff.NewFindings {
			_, _ = fmt.Fprintf(stdout, "  + %s  %s@%s  %s\n", d.Finding.ID, d.Coordinate.Path(), d.Coordinate.Version(), d.Finding.Summary)
		}
		_, _ = fmt.Fprintln(stdout)
	}

	// Withdrawn is printed before resolved, and separately from it, because it is the
	// attributed half of what used to be one bucket. "Resolved / no longer known"
	// collapsed "upstream fixed it", "we upgraded" and "the advisory was retracted"
	// into a single green label, and a review acted on the wrong one of the three.
	if len(diff.WithdrawnFindings) > 0 {
		_, _ = fmt.Fprintf(stdout, "WITHDRAWN advisories (%d) — retracted upstream, not fixed:\n", len(diff.WithdrawnFindings))
		for _, d := range diff.WithdrawnFindings {
			_, _ = fmt.Fprintf(stdout, "  ! %s  %s@%s  withdrawn %s  %s\n", d.Finding.ID,
				d.Coordinate.Path(), d.Coordinate.Version(),
				d.Finding.WithdrawnAt.UTC().Format(time.RFC3339), d.Finding.Summary)
		}
		_, _ = fmt.Fprintln(stdout)
	}

	if len(diff.ResolvedFindings) > 0 {
		_, _ = fmt.Fprintf(stdout, "RESOLVED findings (%d) — no longer reported, no reason recorded:\n", len(diff.ResolvedFindings))
		for _, d := range diff.ResolvedFindings {
			_, _ = fmt.Fprintf(stdout, "  - %s  %s@%s  %s\n", d.Finding.ID, d.Coordinate.Path(), d.Coordinate.Version(), d.Finding.Summary)
		}
		_, _ = fmt.Fprintln(stdout)
	}

	if len(diff.ReachabilityChanges) > 0 {
		_, _ = fmt.Fprintf(stdout, "REACHABILITY changes (%d):\n", len(diff.ReachabilityChanges))
		for _, c := range diff.ReachabilityChanges {
			was := "not reachable"
			if c.WasReachable {
				was = "reachable"
			}
			now := "not reachable"
			if c.IsReachable {
				now = "reachable"
			} else if soundness, _ := vuldomain.NegativeSoundness(c.Finding); soundness != vuldomain.SoundnessNotStated {
				// The transition an operator acts on is the one INTO a negative, and
				// the rung says how thorough the search behind that negative was. A
				// bare "not reachable" here reads as a resolution.
				now = "not reachable — " + soundness.String()
			}
			if !c.IsReachable && c.Finding.AdvisoryNamesNoSymbols {
				// The later run did not search and fail; there was no symbol for it to
				// search for. Rendering this as "not reachable" would read as a
				// resolution and invite the operator to stand down on a module that is
				// still affected at package level.
				now = "not determined at symbol level (advisory names no symbols)"
			}
			_, _ = fmt.Fprintf(stdout, "  ~ %s  %s@%s  %s → %s\n", c.Finding.ID, c.Coordinate.Path(), c.Coordinate.Version(), was, now)
		}
		_, _ = fmt.Fprintln(stdout)
	}

	if len(diff.UnresolvedFindings) > 0 {
		_, _ = fmt.Fprintf(stdout, "UNRESOLVED (%d) — completeness parity mismatch, verdict withheld:\n", len(diff.UnresolvedFindings))
		for _, u := range diff.UnresolvedFindings {
			_, _ = fmt.Fprintf(stdout, "  ? %s  %s@%s  would-be %s but %s\n",
				u.Finding.ID, u.Coordinate.Path(), u.Coordinate.Version(), u.Kind, u.Reason)
		}
	}

	return nil
}
