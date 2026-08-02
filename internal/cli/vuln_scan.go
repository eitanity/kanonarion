package cli

import (
	"context"
	"encoding/json"
	"errors"
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
		Long: `Scan every module in a walk against the advisory database.

Beside the result, on stderr, vuln-scan states the toolchain axis: the Go
toolchain version the walk was built by, the advisory snapshot it was judged
against, and either that no toolchain advisory covers it or the ones that do.
The advisory database keys the toolchain (cmd/go, the compiler, the linker)
separately from stdlib and no project imports it, so no module scan can reach
it. It is reported on its own and counted in no roll-up.`,
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
			return runVulnScan(cmd.Context(), args[0], force, fresh, enableReachability, callGraphWorkers, binaryModePrePass, jsonOut, goBinary, operator, "", policyPath, noVendor, noProgress, true, stdout, stderr)
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "force re-scan even if results exist")
	cmd.Flags().BoolVar(&fresh, "fresh", false, "refresh the vulnerability advisory database: download a new snapshot only if an advisory listed for a module in this walk has changed")
	cmd.Flags().BoolVar(&enableReachability, "reachability", false, "enable call-graph reachability analysis")
	cmd.Flags().IntVar(&callGraphWorkers, "callgraph-workers", 1, "max concurrent on-demand callgraph subprocesses (SSA-heavy; keep low)")
	cmd.Flags().BoolVar(&binaryModePrePass, "binary-pre-pass", false, "fast binary-mode pre-pass; source mode only for affected modules")
	cmd.Flags().StringVar(&goBinary, "go-binary", "", "path to 'go' binary if not in PATH")
	cmd.Flags().StringVar(&operator, "operator", os.Getenv("USER"), "operator identifier (defaults to $USER)")
	cmd.Flags().StringVar(&moduleCoord, "module", "", "look up the latest walk ROOTED AT <module@version> (its own target, not a walk that merely contains it as a dependency) and scan it; such a walk records no target platform, and the scan says so")
	cmd.Flags().BoolVar(&tool, "tool", false, "scan the tooling supply chain: the latest tool-scoped project walk for this GOOS/GOARCH (requires prior walk --tool)")
	cmd.Flags().BoolVar(&project, "project", false, "scan the complete set: the latest complete-scope project walk for this GOOS/GOARCH (requires prior walk --project)")
	cmd.Flags().StringVar(&gomod, "gomod", "", "scan the latest project walk for this go.mod's scope and this GOOS/GOARCH (default: search upward from cwd); default scope is code")
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
	// Build constraints select files per platform and govulncheck's reachability
	// follows those files, so a scan run in this environment must read a walk
	// resolved for this environment. Without the axis the newest walk answered,
	// whichever platform produced it.
	platform := currentBuildEnvFilter(ctx, goBinary, filepath.Dir(gomodPath), logger)
	selected, err := selectProjectWalkToScan(ctx, ctr.QueryWalks, coord, scope, platform, gomodPath)
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(progressWriter(stderr, noProgress), "scanning %s project walk %s (%s)\n", scope, selected.ID, selected.BuildFrame())
	return runVulnScan(ctx, selected.ID, force, fresh, enableReachability, callGraphWorkers, false, jsonOut, goBinary, operator, filepath.Dir(gomodPath), policyPath, noVendor, noProgress, true, stdout, stderr)
}

// selectProjectWalkToScan returns the succeeded project walk of the requested
// scope that was resolved for platform, or a refusal naming that platform and
// the command that produces such a walk.
//
// The platform is part of the question, not a preference: it is never relaxed
// to "some other platform's walk of the same project" on a miss, because a
// reachability answer computed over another platform's file set is not a weaker
// answer to this question, it is an answer to a different one.
func selectProjectWalkToScan(
	ctx context.Context,
	qw QueryWalksUseCase,
	coord coordinate.ModuleCoordinate,
	scope depScope,
	platform walkports.BuildEnvFilter,
	gomodPath string,
) (walkports.WalkSummary, error) {
	walkScope := walkScopeFor(scope)
	succeeded := walkdomain.WalkSucceeded
	walks, err := qw.ListWalks(ctx, walkports.WalkFilter{
		Target:        &coord,
		Scope:         &walkScope,
		OverallStatus: &succeeded,
		BuildEnv:      &platform,
		Limit:         1,
	})
	if err != nil {
		return walkports.WalkSummary{}, fmt.Errorf("listing %s project walks for %s: %w", scope, coord.Path(), err)
	}
	if len(walks) == 0 {
		return walkports.WalkSummary{}, fmt.Errorf("no succeeded %s project walk for %s on %s — run: kanonarion walk --gomod %s%s",
			scope, coord.Path(), platform, gomodPath, scopeWalkFlagHint(scope))
	}
	return walks[0], nil
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

// narrateRun controls whether this run states the things it says about itself
// as a whole — that a stored run was served, and what the toolchain axis says.
// It is false only for `audit`, which narrates the derivation and the toolchain
// axis in statements of its own and would otherwise say each of them twice.
func runVulnScan(ctx context.Context, walkID string, force, fresh, enableReachability bool, callGraphWorkers int, binaryModePrePass, jsonOut bool, goBinary, operator, projectDir, policyPath string, noVendor, noProgress, narrateRun bool, stdout, stderr io.Writer) error {
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

	// --fresh refreshes the advisory database and nothing else. It happens before
	// the reuse question below, which is asked against whatever database the
	// refresh settled on.
	if fresh {
		refresh, rerr := ctr.ScanWalk.RefreshSnapshot(ctx, walkID)
		if _, werr := fmt.Fprintf(stderr, "%s\n", advisoryRefreshLine(refresh, rerr)); werr != nil {
			return fmt.Errorf("writing output: %w", werr)
		}
		if rerr != nil {
			return fmt.Errorf("refreshing the advisory database: %w", rerr)
		}
	}

	// A scan of the same walk against the same advisory snapshot has already
	// answered this question. Re-running govulncheck over the whole build list
	// would reproduce the stored verdicts at the cost of the run — the dominant
	// cost of the command — so the stored run is served instead, and the report
	// says so rather than letting a served answer read as a fresh measurement.
	// --force is the way to insist on measuring; a --fresh that downloaded a new
	// database re-scans on its own, because the stored run no longer answers
	// against it.
	if !force {
		if prior, ok, rerr := ctr.ScanWalk.ReusableRun(ctx, walkID); rerr != nil {
			return fmt.Errorf("checking for a reusable scan run: %w", rerr)
		} else if ok {
			return serveStoredScanRun(ctx, prior, ctr, jsonOut, narrateRun, stdout, stderr)
		}
	}

	_, _ = fmt.Fprintf(progressOut, "Scanning walk %s...\n", walkID)

	rollups := newVulnScanRollups()

	run, err := ctr.ScanWalk.Scan(ctx, application2.ScanWalkParams{
		WalkID: walkID,
		Force:  force,
		// The refresh above already settled which database this run is judged
		// against, and stored it; the scan resolves that stored snapshot. Passing
		// the flag on would check the database a second time in one invocation.
		Fresh:              false,
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
			rollups.add(coord, record)
		},
	})
	if err != nil {
		return fmt.Errorf("vuln scan failed: %w", err)
	}

	// The toolchain axis goes to stderr, beside the result and never inside it:
	// stdout is the data channel a --json caller pipes into jq, and the toolchain
	// is not one of the modules this run scanned.
	if narrateRun {
		if terr := reportToolchainAxis(ctx, ctr, run, stderr); terr != nil {
			return terr
		}
	}

	if perr := printVulnScanResult(run, rollups.affected, rollups.withdrawn, rollups.failed, rollups.unscannable, jsonOut, stdout); perr != nil {
		return perr
	}
	return vulnScanCoverageExit(run)
}

// advisoryRefreshLine renders what a --fresh refresh established, in one line.
//
// Every outcome is said in its own words, and each says the basis it rests on
// rather than only its conclusion. Two of them are claims that the stored answer
// is still current, and a claim of currency with no stated basis is the thing
// this whole report exists to avoid: "unchanged" is a statement about the
// database's generation, while "unchanged for this walk" is a statement about a
// measured comparison over a named number of modules, and a reader has to be
// able to tell which one they were given.
//
// err is the refresh's own failure; when it is set the refresh value is unused.
func advisoryRefreshLine(r application2.SnapshotRefresh, err error) string {
	if err != nil {
		return fmt.Sprintf("advisory database: refresh failed (%v); the stored database is unchanged and this run is judged against it", err)
	}
	source, version := r.Snapshot.Source(), r.Snapshot.Version()
	switch {
	case r.StampErr != nil:
		return fmt.Sprintf("advisory database: %s published generation unreadable (%v); downloaded the database, now at %s",
			source, r.StampErr, version)
	case r.IndexErr != nil:
		return fmt.Sprintf("advisory database: %s advanced %s -> %s, but the advisories could not be compared (%v); downloaded the new database",
			source, r.PriorVersion, r.PublishedVersion, r.IndexErr)
	case r.Outcome == application2.RefreshUnchanged:
		return fmt.Sprintf("advisory database: checked %s and found it unchanged at %s; nothing was downloaded and the stored snapshot was kept",
			source, version)
	case r.Outcome == application2.RefreshIndexUnchanged:
		return fmt.Sprintf(
			"advisory database: %s advanced %s -> %s; the advisories listed for all %d modules in this walk are identical between the two, so the run judged against %s remains current for this walk; nothing was downloaded",
			source, r.PriorVersion, r.PublishedVersion, r.ModulesCompared, r.PriorVersion)
	case r.PriorVersion == "":
		return fmt.Sprintf("advisory database: no snapshot was stored; downloaded %s@%s", source, version)
	default:
		return fmt.Sprintf("advisory database: %s advanced %s -> %s and the advisories changed for a module in this walk; downloaded the new database",
			source, r.PriorVersion, version)
	}
}

// vulnScanRollups buckets per-module scan verdicts into the sections the report
// prints. It is filled identically whether the verdicts came from a scan running
// now or from the records a stored run wrote, so a served report is assembled by
// the same code as a measured one and cannot drift from it.
type vulnScanRollups struct {
	affected    []vulnScanAffected
	withdrawn   []vulnScanAffected
	failed      []string
	unscannable *unscannableRollup
}

func newVulnScanRollups() *vulnScanRollups {
	return &vulnScanRollups{unscannable: newUnscannableRollup()}
}

// add buckets one module's record.
//
// Bucketed by axis, not by the collapsed word, so a module can appear in both
// roll-ups. A metadata-only record that matched an advisory is both a finding
// and a coverage gap; routing on the single word put it in the affected list and
// silently left it out of the coverage roll-up, which is where the reader learns
// the match was never checked for reachability.
func (r *vulnScanRollups) add(coord coordinate.ModuleCoordinate, record vuldomain.VulnerabilityRecord) {
	coverage, findings := vuldomain.RecordAxes(record)
	// Three findings values, three destinations. A withdrawn module is not
	// affected and must leave the affected roll-up; it is also not silent and
	// must not thereby leave the report.
	switch findings {
	case vuldomain.FindingsRecordAffected:
		r.affected = append(r.affected, vulnScanAffected{coord: coord.Path() + "@" + coord.Version(), record: record})
	case vuldomain.FindingsRecordWithdrawn:
		r.withdrawn = append(r.withdrawn, vulnScanAffected{coord: coord.Path() + "@" + coord.Version(), record: record})
	case vuldomain.FindingsRecordClean:
		// No advisory matched: neither findings roll-up names it.
	}
	// Every Unscannable is bucketed, not just the out-of-toolchain one: the same
	// advisory matching ran for all of them, so a record that appeared in no
	// roll-up was being hidden from the reader on the strength of its reason code
	// alone.
	switch coverage {
	case vuldomain.CoverageFailedScan:
		r.failed = append(r.failed, coord.Path()+"@"+coord.Version())
	case vuldomain.CoverageUnscannable:
		r.unscannable.add(record.UnscanReason, coord.Path()+"@"+coord.Version(), record.UnscannableReason)
	case vuldomain.CoverageAnalysed:
		// Analysed: the findings bucket above is the whole answer.
	}
}

// serveStoredScanRun reports a scan run that already exists instead of
// re-deriving it, and states on stderr that it did.
//
// The statement goes to stderr for the same reason the verification-coverage
// aggregate does: stdout is the data channel a --json caller pipes into jq, and
// the provenance of the answer is a report about the run, not part of it. The
// run's own JSON is unchanged and already carries its id, its dates and its
// snapshot, so a machine reader can see the answer's age without a new field.
//
// The roll-ups are rebuilt from the records THAT RUN wrote, so the report is the
// one that run produced rather than a fresh summary over whatever each module's
// latest verdict has since become.
func serveStoredScanRun(ctx context.Context, run vuldomain.WalkScanRun, ctr *Container, jsonOut, announce bool, stdout, stderr io.Writer) error {
	recs, err := ctr.QueryVuln.ListRecordsForRun(ctx, run.ID)
	if err != nil {
		return fmt.Errorf("reading the reused scan run's records: %w", err)
	}

	rollups := newVulnScanRollups()
	for _, rec := range recs {
		rollups.add(rec.Coordinate, rec)
	}

	if announce {
		if _, werr := fmt.Fprintf(stderr,
			"reusing scan run %s of %s against snapshot %s@%s; nothing was re-scanned (--force to re-measure)\n",
			run.ID, run.CompletedAt.UTC().Format(time.RFC3339),
			run.Snapshot.Source(), run.Snapshot.Version(),
		); werr != nil {
			return fmt.Errorf("writing output: %w", werr)
		}
	}

	// The toolchain judgment is derived on a served report exactly as on a
	// measured one: it is read from the stored snapshot the run names, so reuse
	// costs it nothing and cannot silently drop it.
	if announce {
		if terr := reportToolchainAxis(ctx, ctr, run, stderr); terr != nil {
			return terr
		}
	}

	if perr := printVulnScanResult(run, rollups.affected, rollups.withdrawn, rollups.failed, rollups.unscannable, jsonOut, stdout); perr != nil {
		return perr
	}
	return vulnScanCoverageExit(run)
}

// vulnScanCoverageExit maps the run's COVERAGE axis onto the process exit code.
//
// The exit code has to carry the same statement the headline does. A scan that
// left part of the build list unanalysed — including, in the worst case, a scan
// whose target could not be loaded and which therefore measured nothing at all —
// exited 0, which is the one signal an automation caller reads without parsing
// prose, and it said the work completed.
//
// ExitPartial and ExitFailed, not ExitPolicy: this is the "did the work
// complete" question the 0/1/2/3 band answers, not a gate firing on real
// findings. And the gate is on coverage alone. A complete run that found
// vulnerabilities has completed its work and reports them; whether that should
// fail a build is a policy question this command is not the one to answer.
func vulnScanCoverageExit(run vuldomain.WalkScanRun) error {
	unanalysed := run.Counts.Unscannable + run.Counts.Failed
	switch run.CoverageStatus {
	case vuldomain.CoverageFailed:
		return &exitError{code: ExitFailed, msg: fmt.Sprintf(
			"no module in the walk was analysed (%d of %d unanalysed); the scan established nothing",
			unanalysed, run.Counts.Total)}
	case vuldomain.CoveragePartial:
		return &exitError{code: ExitPartial, msg: fmt.Sprintf(
			"%d of %d modules were not analysed; the scan's coverage is incomplete",
			unanalysed, run.Counts.Total)}
	case vuldomain.CoverageComplete:
		return nil
	default:
		// A coverage value this binary does not know is not a statement that the
		// run completed. It degrades to Partial rather than to OK, for the same
		// reason the tally counts an unrecognised per-module coverage as failed.
		return &exitError{code: ExitPartial, msg: fmt.Sprintf(
			"the run reports an unrecognised coverage status %q; its completeness cannot be established",
			run.CoverageStatus)}
	}
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

	// Deliberately NOT platform-filtered, unlike the project-scope entry. A walk
	// rooted at a published coordinate is resolved through the module path, which
	// records no build environment at all — measured on the real store: of 92
	// walks, the 20 with no frame are exactly the module-rooted ones, and both
	// sites that write a BuildEnv sit under the project resolver. Filtering here
	// would refuse every module-rooted walk there is, forever, so the frame is
	// stated rather than required.
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
	// A module-rooted walk carries no frame, so this is "unrecorded" in practice.
	// It is stated anyway: the reader must be able to tell an unstated frame from
	// a missing one, and a scan of a frameless walk is a real caveat on its
	// reachability answer.
	_, _ = fmt.Fprintf(progressWriter(stderr, noProgress), "scanning walk %s rooted at %s (frame %s)\n",
		walkID, moduleCoord, summaries[0].BuildFrame())
	logger.Debug("vuln-scan: resolved module to walk", "module", moduleCoord, "walk_id", walkID, "build_frame", summaries[0].BuildFrame())
	return runVulnScan(ctx, walkID, force, fresh, enableReachability, callGraphWorkers, false, jsonOut, goBinary, operator, "", policyPath, false, noProgress, true, stdout, stderr)
}

// newVulnScanRescanCmd returns the vuln-scan-rescan command.
func newVulnScanRescanCmd(stdout, stderr io.Writer) *cobra.Command {
	var enableReachability bool
	var goBinary string
	var operator string
	var snapshotSource string
	var snapshotVersion string
	var policyPath string
	var noProgress bool

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
			return runScanRescan(cmd.Context(), args[0], enableReachability, goBinary, operator, snapshotSource, snapshotVersion, policyPath, noProgress, stdout, stderr)
		},
	}

	cmd.Flags().BoolVar(&enableReachability, "reachability", false, "enable call-graph reachability analysis")
	cmd.Flags().StringVar(&goBinary, "go-binary", "", "path to 'go' binary if not in PATH")
	cmd.Flags().StringVar(&operator, "operator", os.Getenv("USER"), "operator identifier (defaults to $USER)")
	cmd.Flags().StringVar(&snapshotSource, "snapshot-source", "", "pin to a specific snapshot source (requires --snapshot-version)")
	cmd.Flags().StringVar(&snapshotVersion, "snapshot-version", "", "pin to a specific snapshot version (requires --snapshot-source)")
	cmd.Flags().StringVar(&policyPath, "policy", "", "path to depth policy YAML (default: search upward for .kanonarion/policy.yaml)")
	registerNoProgressFlag(cmd, &noProgress)

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

func runScanRescan(ctx context.Context, walkID string, enableReachability bool, goBinary, operator, snapshotSource, snapshotVersion, policyPath string, noProgress bool, stdout, stderr io.Writer) error {
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

	return rescanWith(ctx, ctr.RescanWalk, req, policyPath, noProgress, stdout, stderr)
}

// rescanWith drives an already-resolved re-scan and owns the command's output
// contract: the narration and the per-module progress stream go to stderr, the
// result to stdout.
//
// It is split from runScanRescan so that contract can be tested without a store
// or a scanner — the store construction above is the only reason the command was
// otherwise untestable, and the routing is the part that keeps regressing.
func rescanWith(
	ctx context.Context,
	rescan RescanWalkUseCase,
	req application2.RescanRequest,
	policyPath string,
	noProgress bool,
	stdout, stderr io.Writer,
) error {
	// The narration stream. `Re-scanning walk ...` is said while the run is in
	// flight, which makes it narration and not a result: stdout is the data
	// channel, and this is the one scan command that was writing commentary onto
	// it. Run ID and Snapshot below are results and stay where they are.
	progressOut := progressWriter(stderr, noProgress)
	_, _ = fmt.Fprintf(progressOut, "Re-scanning walk %s...\n", req.WalkID)

	// A re-scan forces every module in the walk through the scanner. It is the
	// most expensive run the CLI offers and it said nothing until it finished;
	// the per-module line is the same one `vuln-scan` writes, from the same
	// writer, so the two commands read alike and one flag silences both.
	req.Progress = func(coord coordinate.ModuleCoordinate, record vuldomain.VulnerabilityRecord, current, total int) {
		writeVulnScanProgress(record, coord, current, total, progressOut)
	}

	// A rescan re-runs the same pipeline and may pre-fetch, so it is bound by
	// the same policy as a scan. Omitting it here would restore the divergence
	// one command over.
	if err := applyRescanVCSHosts(ctx, rescan, policyPath, stderr); err != nil {
		return err
	}

	run, err := rescan.Rescan(ctx, req)
	if err != nil {
		// A frame the re-scan cannot reproduce is the one failure here that has a
		// route out, and the route is a different command — so it is named. The
		// remedy is built in this layer because the invocations are a CLI contract:
		// every line the tool prints is pushed through the CLI's own parser by
		// TestReachabilityRemedies_EveryLineIsAcceptedByTheParser.
		var frame *application2.FrameNotReproducibleError
		if errors.As(err, &frame) {
			// ExitConfig, not ExitFailed: nothing was scanned and nothing failed to
			// scan. The precondition for answering the question at all — a machine
			// that can reach the project's tree — was not met, which is the class
			// this code names.
			return &exitError{code: ExitConfig, msg: fmt.Sprintf(
				"vuln-scan-rescan refused: %v. %s", err, remedyRescanProject(frame.ProjectDir))}
		}
		return fmt.Errorf("vuln-scan-rescan failed: %w", err)
	}

	_, _ = fmt.Fprintf(stdout, "Re-scan completed: %s\n", scanCompletionSummary(run))
	_, _ = fmt.Fprintf(stdout, "Run ID: %s\n", run.ID)
	_, _ = fmt.Fprintf(stdout, "Snapshot: %s@%s\n", run.Snapshot.Source(), run.Snapshot.Version())
	// The re-scan reports the same two axes and owes the same exit code. A
	// re-derivation that could not analyse part of the build list has not
	// completed its work either, and a caller branching on the code alone must
	// not read the two runs on different terms.
	return vulnScanCoverageExit(run)
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
