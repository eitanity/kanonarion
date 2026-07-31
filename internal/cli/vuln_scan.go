package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	application2 "github.com/eitanity/kanonarion/internal/vuln/application"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
	"github.com/spf13/cobra"
)

func newVulnScanCmd(stdout, stderr io.Writer) *cobra.Command {
	var f commonWalkFlags
	var force bool
	var fresh bool
	var enableReachability bool
	var callGraphWorkers int
	var goBinary string
	var operator string
	var moduleCoord string
	var binaryModePrePass bool
	var tool bool
	var project bool
	var gomod string
	var policyPath string
	var noVendor bool
	var noProgress bool

	cmd := &cobra.Command{
		Use:   "vuln-scan [walk-id]",
		Short: "Scan all modules in a walk for vulnerabilities",
		Example: `  kanonarion vuln-scan 01KQDBVW092ER1HNXZ60X27CMD
  kanonarion vuln-scan --module github.com/gin-gonic/gin@v1.6.2
  kanonarion vuln-scan --binary-pre-pass 01KQDBVW092ER1HNXZ60X27CMD
  kanonarion vuln-scan --tool
  kanonarion vuln-scan --tool --gomod ./go.mod`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			goModScope := gomod != "" || tool || project
			if goModScope {
				if len(args) > 0 {
					return fmt.Errorf("a go.mod scope scan (--gomod/--tool/--project) and a positional walk-id are mutually exclusive")
				}
				if moduleCoord != "" {
					return fmt.Errorf("a go.mod scope scan and --module are mutually exclusive")
				}
				scope, serr := scopeFromFlags(tool, project)
				if serr != nil {
					return serr
				}
				gomodPath, err := resolveGoModPath(gomod)
				if err != nil {
					return err
				}
				return runVulnScanScope(cmd.Context(), gomodPath, scope, force, fresh, enableReachability, callGraphWorkers, jsonOut, goBinary, operator, policyPath, noVendor, noProgress, stdout, stderr)
			}
			if moduleCoord != "" && len(args) > 0 {
				return fmt.Errorf("--module and a positional walk-id are mutually exclusive")
			}
			if moduleCoord == "" && len(args) == 0 {
				return fmt.Errorf("provide either a walk-id argument, --module <module@version>, --gomod, --tool, or --project")
			}
			if moduleCoord != "" {
				return runVulnScanByModule(cmd.Context(), moduleCoord, f, force, fresh, enableReachability, callGraphWorkers, jsonOut, goBinary, operator, policyPath, noProgress, stdout, stderr)
			}
			return runVulnScan(cmd.Context(), args[0], force, fresh, enableReachability, callGraphWorkers, binaryModePrePass, jsonOut, goBinary, operator, "", policyPath, noVendor, noProgress, stdout, stderr)
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "force re-scan even if results exist")
	cmd.Flags().BoolVar(&fresh, "fresh", false, "fetch fresh vulnerability database snapshot from network")
	cmd.Flags().BoolVar(&enableReachability, "reachability", false, "enable call-graph reachability analysis")
	cmd.Flags().IntVar(&callGraphWorkers, "callgraph-workers", 1, "max concurrent on-demand callgraph subprocesses (SSA-heavy; keep low)")
	cmd.Flags().BoolVar(&binaryModePrePass, "binary-pre-pass", false, "fast binary-mode pre-pass; source mode only for affected modules")
	cmd.Flags().StringVar(&goBinary, "go-binary", "", "path to 'go' binary if not in PATH")
	cmd.Flags().StringVar(&operator, "operator", os.Getenv("USER"), "operator identifier (defaults to $USER)")
	cmd.Flags().StringVar(&moduleCoord, "module", "", "look up the latest walk ROOTED AT <module@version> (its own target, not a walk that merely contains it as a dependency) and scan it")
	cmd.Flags().BoolVar(&tool, "tool", false, "scan the tooling supply chain: the latest tool-scoped project walk (requires prior walk --tool)")
	cmd.Flags().BoolVar(&project, "project", false, "scan the complete set: the latest complete-scope project walk (requires prior walk --project)")
	cmd.Flags().StringVar(&gomod, "gomod", "", "scan the latest project walk for this go.mod's scope (default: search upward from cwd); default scope is code")
	cmd.Flags().StringVar(&policyPath, "policy", "", "path to depth policy YAML (default: search upward for .kanonarion/policy.yaml)")
	cmd.Flags().BoolVar(&noVendor, "no-vendor", false,
		"analyse the fetched artefacts even when the project is vendored (default: analyse vendor/, the source the project compiles)")
	registerNoProgressFlag(cmd, &noProgress)

	return cmd
}

// runVulnScanScope finds the latest succeeded project walk for the requested
// dependency scope (the single record produced by `walk --gomod [--tool|--project]`)
// and scans it. The project walk is rooted at the local main module, so its
// closure is the scope's full set in one record — one scan, not one per module.
func runVulnScanScope(ctx context.Context, gomodPath string, scope depScope, force, fresh, enableReachability bool, callGraphWorkers int, jsonOut bool, goBinary, operator, policyPath string, noVendor, noProgress bool, stdout, stderr io.Writer) error {
	modulePath, err := readGoModulePath(gomodPath)
	if err != nil {
		return err
	}

	logger := buildLogger(logLevel, stderr)
	ctr, cleanup, err := NewContainer(storeRoot, "", goBinary, false, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() {
		if cerr := cleanup(); cerr != nil {
			logger.Warn("vuln-scan: store cleanup failed", "error", cerr)
		}
	}()

	coord, err := coordinate.NewModuleCoordinate(modulePath, coordinate.LocalVersion)
	if err != nil {
		return fmt.Errorf("building project coordinate: %w", err)
	}
	walkScope := walkScopeFor(scope)
	succeeded := walkdomain.WalkSucceeded
	walks, err := ctr.QueryWalks.ListWalks(ctx, walkports.WalkFilter{
		Target:        &coord,
		Scope:         &walkScope,
		OverallStatus: &succeeded,
		Limit:         1,
	})
	if err != nil {
		return fmt.Errorf("listing %s project walks for %s: %w", scope, modulePath, err)
	}
	if len(walks) == 0 {
		return fmt.Errorf("no succeeded %s project walk for %s — run: kanonarion walk --gomod %s%s",
			scope, modulePath, gomodPath, scopeWalkFlagHint(scope))
	}

	_, _ = fmt.Fprintf(progressWriter(stderr, noProgress), "scanning %s project walk %s\n", scope, walks[0].ID)
	return runVulnScan(ctx, walks[0].ID, force, fresh, enableReachability, callGraphWorkers, false, jsonOut, goBinary, operator, filepath.Dir(gomodPath), policyPath, noVendor, noProgress, stdout, stderr)
}

// scopeWalkFlagHint returns the `walk` flag that produces a walk of the given
// scope, for use in "run walk first" diagnostics.
func scopeWalkFlagHint(scope depScope) string {
	switch scope {
	case scopeTool:
		return " --tool"
	case scopeComplete:
		return " --project"
	default:
		return ""
	}
}

// vcsHostScopedScan is a scan use case that accepts a per-run VCS forge
// allowlist. It is asserted rather than added to ScanWalkUseCase so the narrow
// CLI interface (and the fakes that satisfy it) stay unchanged; the assertion
// only has to succeed when a policy actually enforces a list.
type vcsHostScopedScan interface {
	WithVCSHosts(fetchdomain.VCSHostAllowlist) *application2.ScanWalkUseCase
}

// applyScanVCSHosts binds the operator's fetch-stage VCS forge allowlist to a
// scan's pre-fetch.
//
// A vuln-scan that finds a module missing from the fact store fetches it, and
// that fetch cross-verifies against a forge. Without this, which allowlist
// applied depended on whether walk or vuln-scan reached the coordinate first.
// Resolution goes through loadPolicy — the same path walk, fetch and audit use
// — so both sources reach it: the depth policy file and the store config's
// fetch_policy block, with the policy file winning where both speak.
//
// An enforcing policy that cannot be applied fails the scan. Continuing would
// cross-verify against forges the operator excluded and record the result as if
// their policy had been honoured.
func applyScanVCSHosts(ctx context.Context, scan ScanWalkUseCase, policyPath string, stderr io.Writer) error {
	hosts, err := resolveFetchVCSHosts(ctx, policyPath, stderr)
	if err != nil {
		return err
	}
	if !hosts.IsEnforcing() {
		return nil
	}
	vc, ok := scan.(vcsHostScopedScan)
	if !ok {
		return fmt.Errorf(
			"policy sets allowed_vcs_hosts but the scan cannot apply it: %T does not implement WithVCSHosts", scan)
	}
	vc.WithVCSHosts(hosts)
	return nil
}

func runVulnScan(ctx context.Context, walkID string, force, fresh, enableReachability bool, callGraphWorkers int, binaryModePrePass, jsonOut bool, goBinary, operator, projectDir, policyPath string, noVendor, noProgress bool, stdout, stderr io.Writer) error {
	logger := buildLogger(logLevel, stderr)

	if goBinary != "" {
		goDir := filepath.Dir(goBinary)
		binDir, err := os.MkdirTemp("", "kanonarion-bin-*")
		if err == nil {
			goSymlink := filepath.Join(binDir, "go")
			_ = os.Symlink(goBinary, goSymlink)
			goDir = binDir
			defer func() { _ = os.RemoveAll(binDir) }()
		}

		currentPath := os.Getenv("PATH")
		newPath := goDir + string(os.PathListSeparator) + currentPath
		if err := os.Setenv("PATH", newPath); err != nil {
			return fmt.Errorf("setting PATH: %w", err)
		}
		if err := os.Unsetenv("GOROOT"); err != nil {
			return fmt.Errorf("unsetting GOROOT: %w", err)
		}
	}

	ctr, cleanup, err := NewContainer(storeRoot, "", goBinary, false, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() {
		if cerr := cleanup(); cerr != nil {
			logger.Warn("vuln-scan: store cleanup failed", "error", cerr)
		}
	}()

	// Progress preamble goes to stderr so stdout is a clean data channel —
	// under --json, callers pipe stdout straight into jq and a preamble line
	// breaks parsing.
	// Before any fetch: an unusable policy must stop the run here.
	if err := applyScanVCSHosts(ctx, ctr.ScanWalk, policyPath, stderr); err != nil {
		return err
	}

	// The narration stream, which --no-progress silences. Only the per-module
	// lines and this preamble travel on it: the scan's warnings and its result
	// keep their own writers, so a silenced run still says what went wrong. A
	// walk of any size emits one of these lines per module — 321 on a project
	// scan — and that stream is the reason the flag exists.
	progressOut := progressWriter(stderr, noProgress)
	_, _ = fmt.Fprintf(progressOut, "Scanning walk %s...\n", walkID)

	var affected, withdrawn []vulnScanAffected
	var failedCoords []string
	unscannable := newUnscannableRollup()

	run, err := ctr.ScanWalk.Scan(ctx, application2.ScanWalkParams{
		WalkID:             walkID,
		Force:              force,
		Fresh:              fresh,
		EnableReachability: enableReachability,
		CallGraphWorkers:   callGraphWorkers,
		BinaryModePrePass:  binaryModePrePass,
		Operator:           operator,
		ProjectDir:         projectDir,
		NoVendor:           noVendor,
		Progress: func(coord coordinate.ModuleCoordinate, record vuldomain.VulnerabilityRecord, current, total int) {
			// Only the line is suppressed; the bucketing below always runs, because
			// the roll-ups it feeds are the result, printed to stdout.
			writeVulnScanProgress(record, coord, current, total, progressOut)
			// Bucketed by axis, not by the collapsed word, so a module can appear in
			// both roll-ups. A metadata-only record that matched an advisory is both
			// a finding and a coverage gap; routing on the single word put it in the
			// affected list and silently left it out of the coverage roll-up, which
			// is where the reader learns the match was never checked for
			// reachability.
			coverage, findings := vuldomain.RecordAxes(record)
			// Three findings values, three destinations. A withdrawn module is not
			// affected and must leave the affected roll-up; it is also not silent and
			// must not thereby leave the report.
			switch findings {
			case vuldomain.FindingsRecordAffected:
				affected = append(affected, vulnScanAffected{coord: coord.Path() + "@" + coord.Version(), record: record})
			case vuldomain.FindingsRecordWithdrawn:
				withdrawn = append(withdrawn, vulnScanAffected{coord: coord.Path() + "@" + coord.Version(), record: record})
			case vuldomain.FindingsRecordClean:
				// No advisory matched: neither findings roll-up names it.
			}
			// Every Unscannable is bucketed, not just the out-of-toolchain one:
			// the same advisory matching ran for all of them, so a record that
			// appeared in no roll-up was being hidden from the reader on the
			// strength of its reason code alone.
			switch coverage {
			case vuldomain.CoverageFailedScan:
				failedCoords = append(failedCoords, coord.Path()+"@"+coord.Version())
			case vuldomain.CoverageUnscannable:
				unscannable.add(record.UnscanReason, coord.Path()+"@"+coord.Version(), record.UnscannableReason)
			case vuldomain.CoverageAnalysed:
				// Analysed: the findings bucket above is the whole answer.
			}
		},
	})
	if err != nil {
		return fmt.Errorf("vuln scan failed: %w", err)
	}

	return printVulnScanResult(run, affected, withdrawn, failedCoords, unscannable, jsonOut, stdout)
}

// reachabilityLocalHint is the intent-aware direction shown for modules that are
// metadata-only because their isolated build resolved a version outside the
// project's build. It points at the command that answers the project-rooted
// reachability question; it directs, it does not run anything.
const reachabilityLocalHint = "for project-rooted reachability, run: kanonarion reachability --local <project-dir>"

// vulnScanStatusLabel returns the human display label for a per-module scan
// line. Every Unscannable reason resolves through the display table rather than
// falling through to the raw status string: the same advisory matching ran for
// all of them, so telling the reader nothing for one module and explaining
// another is a difference in presentation that no difference in analysis backs.
// The stored status and JSON stay Unscannable; only the human label changes.
// Whether the module was analysed is asked of the coverage axis: a metadata-only
// record that matched an advisory summarises as Affected, so gating on the word
// printed a bare "Affected" and told the reader nothing about the module never
// having been analysed. When both axes have something to say the line carries
// both, findings first — the coverage caveat qualifies the finding, it does not
// replace it.
func vulnScanStatusLabel(record vuldomain.VulnerabilityRecord) string {
	coverage, findings := vuldomain.RecordAxes(record)
	if coverage != vuldomain.CoverageUnscannable {
		return string(record.OverallStatus)
	}
	label := unscanLabelFor(record)
	// Both findings words that report a matched advisory keep it in front of the
	// coverage caveat. A withdrawn match under a coverage gap is still something the
	// module was found to carry, and dropping to the bare coverage label would be
	// the same silence that hid an Affected match before it.
	switch findings {
	case vuldomain.FindingsRecordAffected:
		return string(vuldomain.StatusAffected) + " — " + label
	case vuldomain.FindingsRecordWithdrawn:
		return string(vuldomain.StatusWithdrawn) + " — " + label
	case vuldomain.FindingsRecordClean:
		return label
	}
	return label
}

// writeVulnScanProgress writes one per-module progress line (and, for a scan
// fault, its reason) to w, which must be stderr. It is the single place the
// progress callback writes so tests can verify the routing without going
// through NewContainer.
//
// An Unscannable module contributes only its status line here. The explanation,
// the direction, and the scanner's free-text reason are properties of the reason
// code, byte-identical for every module carrying it, so they are printed once in
// the end-of-run roll-up instead of once per module. A scan fault keeps its
// per-module reason: that text is the one genuinely per-module signal in the
// stream, and it was the text being buried by the repeated boilerplate.
func writeVulnScanProgress(record vuldomain.VulnerabilityRecord, coord coordinate.ModuleCoordinate, current, total int, w io.Writer) {
	status := vulnScanStatusLabel(record)
	if record.Reused {
		// A reused record was served from the cache, not freshly scanned; label
		// it so the line does not read as a fresh scan that never happened.
		status += " (reused — same snapshot)"
	}
	_, _ = fmt.Fprintf(w, "  [%d/%d] %s@%s — %s\n", current, total, coord.Path(), coord.Version(), status)
	coverage, _ := vuldomain.RecordAxes(record)
	if coverage == vuldomain.CoverageFailedScan && record.ErrorDetail != "" {
		_, _ = fmt.Fprintf(w, "      reason: %s\n", record.ErrorDetail)
	}
}

// vulnScanAffected holds the display coordinate and record for a module that
// was found to have vulnerabilities during a walk scan.
type vulnScanAffected struct {
	coord  string
	record vuldomain.VulnerabilityRecord
}

// scanCompletionSummary renders both scan axes for the "Scan completed" line,
// printing each only when it says something: coverage names the unanalysed count
// unless it is Complete, findings names the affected count unless it is Clean.
// The two answer different questions, so neither suppresses the other —
// a run that is both Partial and Affected reports both.
func scanCompletionSummary(run vuldomain.WalkScanRun) string {
	unanalysed := run.Counts.Unscannable + run.Counts.Failed
	var coverage string
	switch run.CoverageStatus {
	case vuldomain.CoveragePartial:
		coverage = fmt.Sprintf("Partial coverage (%d of %d unanalysed)", unanalysed, run.Counts.Total)
	case vuldomain.CoverageFailed:
		coverage = fmt.Sprintf("Failed coverage (%d of %d unanalysed)", unanalysed, run.Counts.Total)
	default:
		coverage = "Complete"
	}
	findings := "Clean"
	if run.FindingsStatus == vuldomain.FindingsAffected {
		findings = fmt.Sprintf("Affected (%d)", run.Counts.Affected)
	}
	return coverage + ", " + findings
}

// printVulnScanResult writes the scan result to stdout. Progress output has
// already been written to stderr by the Progress callback. This function owns
// only the final result channel: JSON under --json, or a findings summary
// followed by the status line in text mode.
func printVulnScanResult(run vuldomain.WalkScanRun, affected, withdrawn []vulnScanAffected, failedCoords []string, unscannable *unscannableRollup, jsonOut bool, stdout io.Writer) error {
	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(run); err != nil {
			return fmt.Errorf("encoding JSON output: %w", err)
		}
		return nil
	}

	// Findings summary — only Affected modules appear on stdout.
	if len(affected) > 0 {
		_, _ = fmt.Fprintf(stdout, "Findings (%d affected):\n", len(affected))
		for _, a := range affected {
			_, _ = fmt.Fprintf(stdout, "  %s\n", a.coord)
			for _, f := range a.record.Findings {
				aliases := ""
				if len(f.Aliases) > 0 {
					aliases = " (" + strings.Join(f.Aliases, ", ") + ")"
				}
				fixedIn := ""
				if f.FixedIn != "" {
					fixedIn = ", fixed in " + f.FixedIn
				}
				reachability := reachabilityLabel(f, " [not reachable in call graph]")
				_, _ = fmt.Fprintf(stdout, "    %s%s%s%s: %s\n", f.ID, aliases, fixedIn, reachability, f.Summary)
			}
		}
	}

	// Its own section, after the findings and outside the affected count. A module
	// whose advisory was retracted has a history the reader needs — it was reported
	// affected until the retraction became readable — and naming it only on the
	// progress line, which scrolls past, is the silence the retraction exists to
	// break. It carries no fix or reachability line: neither applies to an advisory
	// that no longer stands, and printing them would invite acting on them.
	if len(withdrawn) > 0 {
		_, _ = fmt.Fprintf(stdout, "Withdrawn advisories (%d, not counted as findings):\n", len(withdrawn))
		for _, a := range withdrawn {
			_, _ = fmt.Fprintf(stdout, "  %s\n", a.coord)
			for _, f := range a.record.Findings {
				if !f.IsWithdrawn() {
					continue
				}
				_, _ = fmt.Fprintf(stdout, "    %s: retracted upstream %s — %s\n",
					f.ID, f.WithdrawnAt.UTC().Format(time.RFC3339), f.Summary)
			}
		}
	}

	_, _ = fmt.Fprintf(stdout, "Scan completed: %s  Run ID: %s\n", scanCompletionSummary(run), run.ID)
	// Listed whenever any module failed, not only on a Partial run. A run is
	// Affected as soon as one module has findings and Failed when every module
	// failed, so gating on Partial dropped the failed list from the summary in
	// exactly the two runs where a scan fault matters most — the same "appears in
	// no roll-up" defect the Unscannable sections below fix.
	if len(failedCoords) > 0 {
		_, _ = fmt.Fprintf(stdout, "Failed modules (%d):\n", len(failedCoords))
		for _, c := range failedCoords {
			_, _ = fmt.Fprintf(stdout, "  %s\n", c)
		}
	}
	// A Partial run is often caused only by out-of-toolchain modules, which are
	// expected, not failures. One section per reason names every Unscannable
	// module, so the counts are readable without scrolling the progress stream
	// and no record is left out of the summary for want of a display mapping.
	// Sections stay separate rather than merged because the direction line
	// belongs to one reason only.
	writeUnscannableRollup(unscannable, stdout)

	return nil
}

// writeUnscannableRollup prints one section per Unscannable reason present in
// the run: a heading carrying the count and the reason's explanation, the
// distinct scanner reasons behind it, the coordinates, and the reason's
// direction line where one exists.
//
// This section is where the once-per-reason text lives. The per-module stream
// carries only the varying part — the status label and the progress counter —
// so the explanation, the scanner detail and the direction each appear once per
// run however many modules carry the reason.
func writeUnscannableRollup(rollup *unscannableRollup, w io.Writer) {
	if rollup == nil || rollup.empty() {
		return
	}
	for _, section := range rollup.sections() {
		// A fanned-out project fault is one condition, not one per module. State
		// it once with the count of modules it took down and print no coordinate
		// list: N coordinates under a heading reads as N findings, which is the
		// opposite of what a single operator-side input fault is.
		if section.display.oneFault {
			_, _ = fmt.Fprintf(w, "%s; all %d modules unscannable\n", section.display.heading, len(section.coords))
			for _, d := range section.detailsToPrint() {
				_, _ = fmt.Fprintf(w, "  reason: %s\n", d.text)
			}
			continue
		}
		heading := fmt.Sprintf("%s (%d):", section.display.heading, len(section.coords))
		if section.display.explanation != "" {
			heading += " " + section.display.explanation
		}
		_, _ = fmt.Fprintf(w, "%s\n", heading)
		// The scanner's free text is printed only where the reason has no curated
		// explanation. Where one exists it says the same thing in fewer words, and
		// printing both restores the redundancy this roll-up exists to remove.
		//
		// Detail and direction precede the coordinates. They belong to the heading
		// and are read with it; printing the direction past a hundred coordinates
		// orphans it from the explanation it answers.
		for _, d := range section.detailsToPrint() {
			// The count is given only when this text covers part of the section.
			// Where one text covers every coordinate the heading has already stated
			// the number, and repeating it three words later says nothing new.
			if d.count < len(section.coords) {
				_, _ = fmt.Fprintf(w, "  reason: %s (%s)\n", d.text, pluralModules(d.count))
			} else {
				_, _ = fmt.Fprintf(w, "  reason: %s\n", d.text)
			}
		}
		if section.display.hint != "" {
			_, _ = fmt.Fprintf(w, "  → %s\n", section.display.hint)
		}
		for _, c := range section.coords {
			_, _ = fmt.Fprintf(w, "  %s\n", c)
		}
	}
}

// pluralModules renders a module count for a roll-up detail line. A section
// whose modules split across several scanner messages needs the count on each,
// and "1 modules" in that list reads as a defect in the tool rather than a
// property of the run.
func pluralModules(n int) string {
	if n == 1 {
		return "1 module"
	}
	return fmt.Sprintf("%d modules", n)
}

func runVulnScanByModule(ctx context.Context, moduleCoord string, f commonWalkFlags, force, fresh, enableReachability bool, callGraphWorkers int, jsonOut bool, goBinary, operator, policyPath string, noProgress bool, stdout, stderr io.Writer) error {
	logger := buildLogger(logLevel, stderr)

	coord, err := parseCoordinate(moduleCoord)
	if err != nil {
		return fmt.Errorf("invalid module coordinate %q: %w", moduleCoord, err)
	}

	ctr, cleanup, err := NewContainer(storeRoot, f.goproxy, goBinary, false, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() {
		if cerr := cleanup(); cerr != nil {
			logger.Warn("vuln-scan: walk store cleanup failed", "error", cerr)
		}
	}()

	summaries, err := ctr.QueryWalks.ListWalks(ctx, walkports.WalkFilter{
		Target: &coord,
		Limit:  1,
	})
	if err != nil {
		return fmt.Errorf("listing walks for %s: %w", moduleCoord, err)
	}
	if len(summaries) == 0 {
		// The filter is Target, so this searched walks ROOTED AT the coordinate, not
		// walks that contain it — and a module is contained by every walk of every
		// project that depends on it. Saying "no walk found" asserted the wider fact
		// from the narrower search, and reads as "this module has never been walked"
		// for a coordinate sitting in a walk that was scanned minutes earlier. The
		// message states what was searched and names the two ways forward.
		return fmt.Errorf("no walk is rooted at %s (searched walks whose target is that coordinate; "+
			"a walk that merely contains it as a dependency is not one). Either walk it as its own target:\n"+
			"  kanonarion walk %s\n"+
			"or scan the walk that already contains it, by ID:\n"+
			"  kanonarion vuln-scan <walk-id>", moduleCoord, moduleCoord)
	}

	walkID := summaries[0].ID
	logger.Debug("vuln-scan: resolved module to walk", "module", moduleCoord, "walk_id", walkID)
	return runVulnScan(ctx, walkID, force, fresh, enableReachability, callGraphWorkers, false, jsonOut, goBinary, operator, "", policyPath, false, noProgress, stdout, stderr)
}

// newVulnScanRescanCmd returns the vuln-scan-rescan command.
func newVulnScanRescanCmd(stdout, stderr io.Writer) *cobra.Command {
	var enableReachability bool
	var goBinary string
	var operator string
	var snapshotSource string
	var snapshotVersion string
	var policyPath string

	cmd := &cobra.Command{
		Use:     "vuln-scan-rescan <walk-id>",
		Aliases: []string{"vuln-scan-regate"}, // deprecated: renamed from regate
		Short:   "Re-scan an existing walk against a fresh vulnerability database snapshot",
		Long: `vuln-scan-rescan re-runs the vulnerability scanner for every module in an existing
walk against a fresh (or explicitly pinned) database snapshot. It always
bypasses the per-module cache so the new snapshot is actually consulted.
Prior scan runs are preserved unchanged; a new WalkScanRun is appended.`,
		Example: `  kanonarion vuln-scan-rescan 01KQDBVW092ER1HNXZ60X27CMD
  kanonarion vuln-scan-rescan 01KQDBVW092ER1HNXZ60X27CMD --reachability`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if cmd.CalledAs() == "vuln-scan-regate" {
				_, _ = fmt.Fprintln(stderr, "warning: 'vuln-scan-regate' is deprecated; use 'vuln-scan-rescan' instead")
			}
			return runScanRescan(cmd.Context(), args[0], enableReachability, goBinary, operator, snapshotSource, snapshotVersion, policyPath, stdout, stderr)
		},
	}

	cmd.Flags().BoolVar(&enableReachability, "reachability", false, "enable call-graph reachability analysis")
	cmd.Flags().StringVar(&goBinary, "go-binary", "", "path to 'go' binary if not in PATH")
	cmd.Flags().StringVar(&operator, "operator", os.Getenv("USER"), "operator identifier (defaults to $USER)")
	cmd.Flags().StringVar(&snapshotSource, "snapshot-source", "", "pin to a specific snapshot source (requires --snapshot-version)")
	cmd.Flags().StringVar(&snapshotVersion, "snapshot-version", "", "pin to a specific snapshot version (requires --snapshot-source)")
	cmd.Flags().StringVar(&policyPath, "policy", "", "path to depth policy YAML (default: search upward for .kanonarion/policy.yaml)")

	return cmd
}

// vcsHostScopedRescan is the rescan counterpart of vcsHostScopedScan.
type vcsHostScopedRescan interface {
	WithVCSHosts(fetchdomain.VCSHostAllowlist) *application2.RescanWalkUseCase
}

// applyRescanVCSHosts binds the operator's VCS forge allowlist to a rescan's
// pre-fetch, failing when an enforcing policy cannot be applied.
func applyRescanVCSHosts(ctx context.Context, rescan RescanWalkUseCase, policyPath string, stderr io.Writer) error {
	hosts, err := resolveFetchVCSHosts(ctx, policyPath, stderr)
	if err != nil {
		return err
	}
	if !hosts.IsEnforcing() {
		return nil
	}
	vc, ok := rescan.(vcsHostScopedRescan)
	if !ok {
		return fmt.Errorf(
			"policy sets allowed_vcs_hosts but the rescan cannot apply it: %T does not implement WithVCSHosts", rescan)
	}
	vc.WithVCSHosts(hosts)
	return nil
}

func runScanRescan(ctx context.Context, walkID string, enableReachability bool, goBinary, operator, snapshotSource, snapshotVersion, policyPath string, stdout, stderr io.Writer) error {
	logger := buildLogger(logLevel, stderr)

	if goBinary != "" {
		goDir := filepath.Dir(goBinary)
		binDir, err := os.MkdirTemp("", "kanonarion-bin-*")
		if err == nil {
			goSymlink := filepath.Join(binDir, "go")
			_ = os.Symlink(goBinary, goSymlink)
			goDir = binDir
			defer func() { _ = os.RemoveAll(binDir) }()
		}

		currentPath := os.Getenv("PATH")
		newPath := goDir + string(os.PathListSeparator) + currentPath
		if err := os.Setenv("PATH", newPath); err != nil {
			return fmt.Errorf("setting PATH: %w", err)
		}
		if err := os.Unsetenv("GOROOT"); err != nil {
			return fmt.Errorf("unsetting GOROOT: %w", err)
		}
	}

	if (snapshotSource == "") != (snapshotVersion == "") {
		return fmt.Errorf("--snapshot-source and --snapshot-version must be provided together")
	}

	ctr, cleanup, err := NewContainer(storeRoot, "", goBinary, false, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() {
		if cerr := cleanup(); cerr != nil {
			logger.Warn("vuln-scan-rescan: store cleanup failed", "error", cerr)
		}
	}()

	req := application2.RescanRequest{
		WalkID:             walkID,
		EnableReachability: enableReachability,
		Operator:           operator,
	}

	if snapshotSource != "" {
		snap, found, err := resolveSnapshot(ctx, ctr.QueryScanRuns, snapshotSource, snapshotVersion)
		if err != nil {
			return err
		}
		if !found {
			return &exitError{code: ExitNotFound, msg: fmt.Sprintf("snapshot not found: %s@%s", snapshotSource, snapshotVersion)}
		}
		req.Snapshot = &snap
	}

	_, _ = fmt.Fprintf(stdout, "Re-scanning walk %s...\n", walkID)
	// A rescan re-runs the same pipeline and may pre-fetch, so it is bound by
	// the same policy as a scan. Omitting it here would restore the divergence
	// one command over.
	if err := applyRescanVCSHosts(ctx, ctr.RescanWalk, policyPath, stderr); err != nil {
		return err
	}

	run, err := ctr.RescanWalk.Rescan(ctx, req)
	if err != nil {
		return fmt.Errorf("vuln-scan-rescan failed: %w", err)
	}

	_, _ = fmt.Fprintf(stdout, "Re-scan completed: %s\n", scanCompletionSummary(run))
	_, _ = fmt.Fprintf(stdout, "Run ID: %s\n", run.ID)
	_, _ = fmt.Fprintf(stdout, "Snapshot: %s@%s\n", run.Snapshot.Source(), run.Snapshot.Version())
	return nil
}

// resolveSnapshot looks up a stored snapshot by source and version.
func resolveSnapshot(ctx context.Context, uc QueryScanRunsUseCase, source, version string) (vuldomain.DatabaseSnapshot, bool, error) {
	snapshots, err := uc.ListSnapshots(ctx)
	if err != nil {
		return vuldomain.DatabaseSnapshot{}, false, fmt.Errorf("listing snapshots: %w", err)
	}
	for _, s := range snapshots {
		if s.Source() == source && s.Version() == version {
			return s, true, nil
		}
	}
	return vuldomain.DatabaseSnapshot{}, false, nil
}
