package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

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
				return runVulnScanScope(cmd.Context(), gomodPath, scope, force, fresh, enableReachability, callGraphWorkers, jsonOut, goBinary, operator, stdout, stderr)
			}
			if moduleCoord != "" && len(args) > 0 {
				return fmt.Errorf("--module and a positional walk-id are mutually exclusive")
			}
			if moduleCoord == "" && len(args) == 0 {
				return fmt.Errorf("provide either a walk-id argument, --module <module@version>, --gomod, --tool, or --project")
			}
			if moduleCoord != "" {
				return runVulnScanByModule(cmd.Context(), moduleCoord, f, force, fresh, enableReachability, callGraphWorkers, jsonOut, goBinary, operator, stdout, stderr)
			}
			return runVulnScan(cmd.Context(), args[0], f, force, fresh, enableReachability, callGraphWorkers, binaryModePrePass, jsonOut, goBinary, operator, "", stdout, stderr)
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "force re-scan even if results exist")
	cmd.Flags().BoolVar(&fresh, "fresh", false, "fetch fresh vulnerability database snapshot from network")
	cmd.Flags().BoolVar(&enableReachability, "reachability", false, "enable call-graph reachability analysis")
	cmd.Flags().IntVar(&callGraphWorkers, "callgraph-workers", 1, "max concurrent on-demand callgraph subprocesses (SSA-heavy; keep low)")
	cmd.Flags().BoolVar(&binaryModePrePass, "binary-pre-pass", false, "fast binary-mode pre-pass; source mode only for affected modules")
	cmd.Flags().StringVar(&goBinary, "go-binary", "", "path to 'go' binary if not in PATH")
	cmd.Flags().StringVar(&operator, "operator", os.Getenv("USER"), "operator identifier (defaults to $USER)")
	cmd.Flags().StringVar(&moduleCoord, "module", "", "look up the latest walk for <module@version> and scan it")
	cmd.Flags().BoolVar(&tool, "tool", false, "scan the tooling supply chain: the latest tool-scoped project walk (requires prior walk --tool)")
	cmd.Flags().BoolVar(&project, "project", false, "scan the complete set: the latest complete-scope project walk (requires prior walk --project)")
	cmd.Flags().StringVar(&gomod, "gomod", "", "scan the latest project walk for this go.mod's scope (default: search upward from cwd); default scope is code")

	return cmd
}

// runVulnScanScope finds the latest succeeded project walk for the requested
// dependency scope (the single record produced by `walk --gomod [--tool|--project]`)
// and scans it. The project walk is rooted at the local main module, so its
// closure is the scope's full set in one record — one scan, not one per module.
func runVulnScanScope(ctx context.Context, gomodPath string, scope depScope, force, fresh, enableReachability bool, callGraphWorkers int, jsonOut bool, goBinary, operator string, stdout, stderr io.Writer) error {
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

	coord, err := fetchdomain.NewModuleCoordinate(modulePath, fetchdomain.LocalVersion)
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

	_, _ = fmt.Fprintf(stderr, "scanning %s project walk %s\n", scope, walks[0].ID)
	return runVulnScan(ctx, walks[0].ID, commonWalkFlags{}, force, fresh, enableReachability, callGraphWorkers, false, jsonOut, goBinary, operator, filepath.Dir(gomodPath), stdout, stderr)
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

func runVulnScan(ctx context.Context, walkID string, f commonWalkFlags, force, fresh, enableReachability bool, callGraphWorkers int, binaryModePrePass, jsonOut bool, goBinary, operator, projectDir string, stdout, stderr io.Writer) error {
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
	_, _ = fmt.Fprintf(stderr, "Scanning walk %s...\n", walkID)

	var affected []vulnScanAffected
	var failedCoords []string
	var metadataOnlyCoords []string

	run, err := ctr.ScanWalk.Scan(ctx, application2.ScanWalkParams{
		WalkID:             walkID,
		Force:              force,
		Fresh:              fresh,
		EnableReachability: enableReachability,
		CallGraphWorkers:   callGraphWorkers,
		BinaryModePrePass:  binaryModePrePass,
		Operator:           operator,
		ProjectDir:         projectDir,
		Progress: func(coord fetchdomain.ModuleCoordinate, record vuldomain.VulnerabilityRecord, current, total int) {
			writeVulnScanProgress(record, coord, current, total, stderr)
			switch {
			case record.OverallStatus == vuldomain.StatusScanFailed:
				failedCoords = append(failedCoords, coord.Path+"@"+coord.Version)
			case record.OverallStatus == vuldomain.StatusAffected:
				affected = append(affected, vulnScanAffected{coord: coord.Path + "@" + coord.Version, record: record})
			case record.OverallStatus == vuldomain.StatusUnscannable && record.UnscanReason.ExpectedOutOfToolchain():
				metadataOnlyCoords = append(metadataOnlyCoords, coord.Path+"@"+coord.Version)
			}
		},
	})
	if err != nil {
		return fmt.Errorf("vuln scan failed: %w", err)
	}

	return printVulnScanResult(run, affected, failedCoords, metadataOnlyCoords, jsonOut, stdout)
}

// reachabilityLocalHint is the intent-aware direction shown for modules that are
// metadata-only because their isolated build resolved a version outside the
// project's build. It points at the command that answers the project-rooted
// reachability question; it directs, it does not run anything.
const reachabilityLocalHint = "for project-rooted reachability, run: kanonarion reachability --local <project-dir>"

// vulnScanStatusLabel returns the human display label for a per-module scan
// line. An out-of-toolchain coverage gap reads as an informational metadata-only
// outcome rather than a bare "Unscannable": the version resolved when the module
// is scanned in isolation is simply not the one the project builds, so this is
// expected, not a fault. The stored status and JSON stay Unscannable; only the
// human label changes.
func vulnScanStatusLabel(record vuldomain.VulnerabilityRecord) string {
	if record.OverallStatus == vuldomain.StatusUnscannable && record.UnscanReason.ExpectedOutOfToolchain() {
		return "Metadata-only (version not in project build)"
	}
	return string(record.OverallStatus)
}

// writeVulnScanProgress writes one per-module progress line (and optional
// reason) to w, which must be stderr. It is the single place the progress
// callback writes so tests can verify the routing without going through
// NewContainer.
func writeVulnScanProgress(record vuldomain.VulnerabilityRecord, coord fetchdomain.ModuleCoordinate, current, total int, w io.Writer) {
	status := vulnScanStatusLabel(record)
	if record.Reused {
		// A reused record was served from the cache, not freshly scanned; label
		// it so the line does not read as a fresh scan that never happened.
		status += " (reused — same snapshot)"
	}
	_, _ = fmt.Fprintf(w, "  [%d/%d] %s@%s — %s\n", current, total, coord.Path, coord.Version, status)
	switch record.OverallStatus {
	case vuldomain.StatusScanFailed:
		if record.ErrorDetail != "" {
			_, _ = fmt.Fprintf(w, "      reason: %s\n", record.ErrorDetail)
		}
	case vuldomain.StatusUnscannable:
		if record.UnscanReason.ExpectedOutOfToolchain() {
			// Expected: name the cause plainly and direct to the whole-build
			// analysis instead of leaving an alarming bare reason.
			_, _ = fmt.Fprintf(w, "      metadata-only: scanned in isolation the module resolves a dependency version the project's build never selected; advisories matched, reachability not computed here\n")
			_, _ = fmt.Fprintf(w, "      → %s\n", reachabilityLocalHint)
		} else if record.UnscannableReason != "" {
			_, _ = fmt.Fprintf(w, "      reason: %s\n", record.UnscannableReason)
		}
	}
}

// vulnScanAffected holds the display coordinate and record for a module that
// was found to have vulnerabilities during a walk scan.
type vulnScanAffected struct {
	coord  string
	record vuldomain.VulnerabilityRecord
}

// printVulnScanResult writes the scan result to stdout. Progress output has
// already been written to stderr by the Progress callback. This function owns
// only the final result channel: JSON under --json, or a findings summary
// followed by the status line in text mode.
func printVulnScanResult(run vuldomain.WalkScanRun, affected []vulnScanAffected, failedCoords, metadataOnlyCoords []string, jsonOut bool, stdout io.Writer) error {
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
				reachability := ""
				if f.Reachable != nil {
					if f.Reachable.IsReachable {
						reachability = " [reachable]"
					} else {
						reachability = " [not reachable in call graph]"
					}
				}
				_, _ = fmt.Fprintf(stdout, "    %s%s%s%s: %s\n", f.ID, aliases, fixedIn, reachability, f.Summary)
			}
		}
	}

	_, _ = fmt.Fprintf(stdout, "Scan completed: %s  Run ID: %s\n", run.OverallStatus, run.ID)
	if run.OverallStatus == vuldomain.WalkStatusPartial && len(failedCoords) > 0 {
		_, _ = fmt.Fprintf(stdout, "Failed modules (%d):\n", len(failedCoords))
		for _, c := range failedCoords {
			_, _ = fmt.Fprintf(stdout, "  %s\n", c)
		}
	}
	// A Partial run is often caused only by out-of-toolchain modules, which are
	// expected, not failures. Name them and direct to the whole-build analysis so
	// the Partial status does not read as a fault with no explanation.
	if len(metadataOnlyCoords) > 0 {
		_, _ = fmt.Fprintf(stdout, "Metadata-only — version not in project build (%d):\n", len(metadataOnlyCoords))
		for _, c := range metadataOnlyCoords {
			_, _ = fmt.Fprintf(stdout, "  %s\n", c)
		}
		_, _ = fmt.Fprintf(stdout, "  → %s\n", reachabilityLocalHint)
	}

	return nil
}

func runVulnScanByModule(ctx context.Context, moduleCoord string, f commonWalkFlags, force, fresh, enableReachability bool, callGraphWorkers int, jsonOut bool, goBinary, operator string, stdout, stderr io.Writer) error {
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
		return fmt.Errorf("no walk found for %s", moduleCoord)
	}

	walkID := summaries[0].ID
	logger.Debug("vuln-scan: resolved module to walk", "module", moduleCoord, "walk_id", walkID)
	return runVulnScan(ctx, walkID, f, force, fresh, enableReachability, callGraphWorkers, false, jsonOut, goBinary, operator, "", stdout, stderr)
}

// newVulnScanRescanCmd returns the vuln-scan-rescan command.
func newVulnScanRescanCmd(stdout, stderr io.Writer) *cobra.Command {
	var f commonWalkFlags
	var enableReachability bool
	var goBinary string
	var operator string
	var snapshotSource string
	var snapshotVersion string

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
			return runScanRescan(cmd.Context(), args[0], f, enableReachability, goBinary, operator, snapshotSource, snapshotVersion, stdout, stderr)
		},
	}

	cmd.Flags().BoolVar(&enableReachability, "reachability", false, "enable call-graph reachability analysis")
	cmd.Flags().StringVar(&goBinary, "go-binary", "", "path to 'go' binary if not in PATH")
	cmd.Flags().StringVar(&operator, "operator", os.Getenv("USER"), "operator identifier (defaults to $USER)")
	cmd.Flags().StringVar(&snapshotSource, "snapshot-source", "", "pin to a specific snapshot source (requires --snapshot-version)")
	cmd.Flags().StringVar(&snapshotVersion, "snapshot-version", "", "pin to a specific snapshot version (requires --snapshot-source)")

	return cmd
}

func runScanRescan(ctx context.Context, walkID string, f commonWalkFlags, enableReachability bool, goBinary, operator, snapshotSource, snapshotVersion string, stdout, stderr io.Writer) error {
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
			return fmt.Errorf("snapshot not found: %s@%s", snapshotSource, snapshotVersion)
		}
		req.Snapshot = &snap
	}

	_, _ = fmt.Fprintf(stdout, "Re-scanning walk %s...\n", walkID)
	run, err := ctr.RescanWalk.Rescan(ctx, req)
	if err != nil {
		return fmt.Errorf("vuln-scan-rescan failed: %w", err)
	}

	_, _ = fmt.Fprintf(stdout, "Re-scan completed with status: %s\n", run.OverallStatus)
	_, _ = fmt.Fprintf(stdout, "Run ID: %s\n", run.ID)
	_, _ = fmt.Fprintf(stdout, "Snapshot: %s@%s\n", run.Snapshot.Source, run.Snapshot.Version)
	return nil
}

// resolveSnapshot looks up a stored snapshot by source and version.
func resolveSnapshot(ctx context.Context, uc QueryScanRunsUseCase, source, version string) (vuldomain.DatabaseSnapshot, bool, error) {
	snapshots, err := uc.ListSnapshots(ctx)
	if err != nil {
		return vuldomain.DatabaseSnapshot{}, false, fmt.Errorf("listing snapshots: %w", err)
	}
	for _, s := range snapshots {
		if s.Source == source && s.Version == version {
			return s, true, nil
		}
	}
	return vuldomain.DatabaseSnapshot{}, false, nil
}
