package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	proxyadapter "github.com/eitanity/kanonarion/internal/adapters/proxy/direct"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	vendports "github.com/eitanity/kanonarion/internal/vendortree/ports"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	domain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

type inspectFlags struct {
	goproxy         string
	goBinary        string
	gomodPath       string
	tool            bool
	project         bool
	force           bool
	fresh           bool
	reachable       bool
	skipVCS         bool
	sizeOnly        bool
	full            bool
	noProgress      bool
	stdlibFromGoMod bool
}

func newInspectCmd(stdout, stderr io.Writer) *cobra.Command {
	var f inspectFlags

	cmd := &cobra.Command{
		Use:   "inspect [<module>@<version>]",
		Short: "Run the full pipeline (walk → extract → vuln-scan → context); no args: code deps of ./go.mod",
		Long: `Run the full pipeline (walk → extract → vuln-scan → context) for a module.

With no arguments, inspect defaults to --gomod ./go.mod and runs the pipeline
over the project's own code dependencies, printing a summary instead of
per-module context. The dependency scope is consistent with every go.mod
command: default = code, --tool = tooling, --project = complete (code +
tooling).`,
		Example: `  kanonarion inspect github.com/spf13/cobra@v1.8.1
  kanonarion inspect modernc.org/sqlite@latest --reachability
  kanonarion inspect
  kanonarion inspect --gomod ./go.mod
  kanonarion inspect --tool
  kanonarion inspect --project`,
		Args: cobra.RangeArgs(0, 1),
		RunE: func(cmd *cobra.Command, args []string) error {
			scope, serr := scopeFromFlags(f.tool, f.project)
			if serr != nil {
				return serr
			}
			if (f.tool || f.project) && len(args) > 0 {
				return fmt.Errorf("--tool and --project apply to a go.mod scan, not a positional module argument")
			}
			// With no positional module, default to a go.mod scan; --gomod
			// defaults to ./go.mod via resolveGoModPath.
			if f.gomodPath != "" || len(args) == 0 {
				if len(args) != 0 {
					return fmt.Errorf("--gomod and a module argument are mutually exclusive")
				}
				resolved, rerr := resolveGoModPath(f.gomodPath)
				if rerr != nil {
					return rerr
				}
				f.gomodPath = resolved
				return runInspectGoMod(cmd.Context(), f, scope, stdout, stderr)
			}
			return runInspect(cmd.Context(), args[0], f, stdout, stderr)
		},
	}

	cmd.Flags().StringVar(&f.goproxy, "goproxy", "", "override GOPROXY (default: $GOPROXY or proxy.golang.org)")
	cmd.Flags().StringVar(&f.goBinary, "go-binary", "", "path to 'go' binary if not in PATH")
	cmd.Flags().BoolVar(&f.force, "force", false, "re-fetch and re-extract even if cached records exist")
	cmd.Flags().BoolVar(&f.fresh, "fresh", false, "fetch fresh vulnerability database snapshot from network")
	cmd.Flags().BoolVar(&f.reachable, "reachability", false, "enable call-graph reachability analysis during vuln-scan")
	cmd.Flags().BoolVar(&f.skipVCS, "skip-vcs-verify", false, "skip git cross-verification; sumdb verification still runs")
	cmd.Flags().BoolVar(&f.sizeOnly, "size-only", false, "print estimated token count and byte size of the context, then exit")
	cmd.Flags().BoolVar(&f.full, "full", false, "include full doc comments and complete example bodies (overrides --compact)")
	cmd.Flags().StringVar(&f.gomodPath, "gomod", "", "path to a go.mod file; run the pipeline over the project's code dependencies and print a summary (default: ./go.mod)")
	cmd.Flags().BoolVar(&f.tool, "tool", false, "scope to the tooling supply chain (the go.mod tool directives' closure)")
	cmd.Flags().BoolVar(&f.project, "project", false, "scope to the complete set: the project's code AND tooling")
	cmd.Flags().BoolVar(&f.noProgress, "no-progress", false, "suppress the stderr fetch-progress heartbeat (default: heartbeat on for long runs)")
	registerStdlibFromGoModFlag(cmd, &f.stdlibFromGoMod)

	return cmd
}

func runInspect(ctx context.Context, arg string, f inspectFlags, stdout, stderr io.Writer) error {
	wf := commonWalkFlags{
		goproxy: f.goproxy,
	}

	logger := buildLogger(logLevel, stderr)
	ctr, cleanup, err := NewContainer(storeRoot, f.goproxy, f.goBinary, f.skipVCS, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() { _ = cleanup() }()

	// Step 1: walk
	if _, err := fmt.Fprintf(stderr, "==> inspect: walking %s\n", arg); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	progress := newWalkProgressReporter(stderr, f.noProgress, activeConfig, logLevel)
	if err := runWalk(ctx, arg, wf, f.force, true, 0, "", "", f.skipVCS, domain.WalkScopeCode, domain.WalkDepthFull, "", progress, ctr.ExecuteWalk, io.Discard, stderr); err != nil {
		return fmt.Errorf("walk: %w", err)
	}

	// Resolve the coordinate (handles @latest) to look up the walk ID.
	coord, err := resolveCoordForInspect(ctx, arg, storeRoot, f.goproxy, stderr)
	if err != nil {
		return err
	}

	// Step 2: find the walk ID for this coordinate.
	walkID, err := latestWalkIDForCoord(ctx, ctr.QueryWalks, coord)
	if err != nil {
		return fmt.Errorf("finding walk ID: %w", err)
	}

	// Step 3: extract
	if _, err := fmt.Fprintf(stderr, "==> inspect: extracting walk %s\n", walkID); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	ef := extractFlags{
		goBinary: f.goBinary,
		stages:   []string{"license", "interface", "callgraph", "example"},
		force:    f.force,
	}
	if err := runExtract(ctx, walkID, ef, io.Discard, stderr); err != nil {
		return fmt.Errorf("extract: %w", err)
	}

	// Step 4: vuln-scan
	if _, err := fmt.Fprintf(stderr, "==> inspect: scanning vulnerabilities for walk %s\n", walkID); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	if err := runVulnScan(ctx, walkID, commonWalkFlags{}, f.force, f.fresh, f.reachable, 1, false, false, f.goBinary, os.Getenv("USER"), "", io.Discard, stderr); err != nil {
		return fmt.Errorf("vuln-scan: %w", err)
	}

	// Step 5: context
	if _, err := fmt.Fprintf(stderr, "==> inspect: building context for %s\n", coord.String()); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	cf := contextFlags{
		compact:  !f.full,
		sizeOnly: f.sizeOnly,
		full:     f.full,
	}
	return runContext(ctx, coord.String(), cf, stdout, stderr)
}

// resolveCoordForInspect parses the module arg, resolving @latest if needed.
func resolveCoordForInspect(ctx context.Context, arg, _, goproxy string, stderr io.Writer) (fetchdomain.ModuleCoordinate, error) {
	path, version, err := parseModuleArg(arg)
	if err != nil {
		return fetchdomain.ModuleCoordinate{}, fmt.Errorf("invalid argument %q: %w", arg, err)
	}
	if version == "latest" {
		proxy, err := proxyadapter.New(goproxy, false)
		if err != nil {
			return fetchdomain.ModuleCoordinate{}, fmt.Errorf("creating proxy: %w", err)
		}
		return resolveLatest(ctx, path, proxy, stderr)
	}
	coord, err := fetchdomain.NewModuleCoordinate(path, version)
	if err != nil {
		return fetchdomain.ModuleCoordinate{}, fmt.Errorf("invalid coordinate %q: %w", arg, err)
	}
	return coord, nil
}

// inspectSummary is the aggregate result of an inspect --gomod run.
type inspectSummary struct {
	ModuleCount     int                `json:"module_count"`
	NodeFails       int                `json:"node_fails,omitempty"`
	ExtractFails    int                `json:"extract_fails,omitempty"`
	ScanFails       int                `json:"scan_fails,omitempty"`
	OverallStatus   string             `json:"overall_status"`
	AffectedCount   int                `json:"affected_count"`
	SnapshotVersion string             `json:"snapshot_version,omitempty"`
	WalkIDs         []string           `json:"walk_ids"`
	Directives      *directivesSection `json:"directives,omitempty"`
	GoDebug         *godebugSection    `json:"godebug,omitempty"`
	Vendor          *vendorSection     `json:"vendor,omitempty"`
}

// inspectSummaryStatus derives the aggregate status for inspect's summary.
// Any failed stage — walk, extract, or vuln-scan — means part of the
// dependency set was not analysed, so the result must surface as partial
// rather than a confident AllClean: an unscanned set presented as clean is
// the absence-as-answer defect class.
func inspectSummaryStatus(nodeFails, extractFails, scanFails, affectedCount int) string {
	switch {
	case nodeFails > 0 || extractFails > 0 || scanFails > 0:
		return string(vuldomain.WalkStatusPartial)
	case affectedCount > 0:
		return string(vuldomain.WalkStatusAffected)
	}
	return string(vuldomain.WalkStatusAllClean)
}

// runInspectGoMod runs the full pipeline for the local project using a single
// project-rooted walk. The walk resolves Go's pruned module graph (the same
// validated build inputs every other go.mod command uses), then extract and
// vuln-scan operate on that one walk record.
func runInspectGoMod(ctx context.Context, f inspectFlags, scope depScope, stdout, stderr io.Writer) error {
	// For code and tool scopes, check whether the scope is empty before
	// spinning up the project walk. An empty import closure is valid but
	// produces no dependency analysis; surface it early and clearly.
	if scope != scopeComplete {
		coords, cerr := resolveScopeModules(f.gomodPath, scope)
		if cerr == nil && len(coords) == 0 {
			_, _ = fmt.Fprintf(stdout, "no %s dependencies found in %s\n", scope, f.gomodPath)
			return nil
		}
	}

	logger := buildLogger(logLevel, stderr)
	ctr, cleanup, err := NewContainer(storeRoot, f.goproxy, f.goBinary, f.skipVCS, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() { _ = cleanup() }()

	modulePath, err := readGoModulePath(f.gomodPath)
	if err != nil {
		return err
	}

	wf := commonWalkFlags{goproxy: f.goproxy}
	_, _ = fmt.Fprintf(stderr, "==> inspect --gomod: walking project %s\n", f.gomodPath)

	var nodeFails int
	progress := newWalkProgressReporter(stderr, f.noProgress, activeConfig, logLevel)
	if werr := runWalkProject(ctx, f.gomodPath, wf, f.force, true, 0, "", "", f.skipVCS, scope, domain.WalkDepthFull, "", false, f.stdlibFromGoMod, progress, ctr.ExecuteWalk, io.Discard, stderr); werr != nil {
		_, _ = fmt.Fprintf(stderr, "walk: %v\n", werr)
		nodeFails = 1
	}

	// Look up the project walk record for its ID and node counts.
	localCoord := fetchdomain.ModuleCoordinate{Path: modulePath, Version: fetchdomain.LocalVersion}
	walkScope := domain.WalkScope(scope)
	walks, qerr := ctr.QueryWalks.ListWalks(ctx, walkports.WalkFilter{Target: &localCoord, Scope: &walkScope, Limit: 1})
	if qerr != nil {
		return fmt.Errorf("querying project walk: %w", qerr)
	}

	var walkID string
	var moduleCount int
	if len(walks) > 0 {
		walkID = walks[0].ID
		moduleCount = walks[0].NodeCount
		if walks[0].FailureCount > 0 && nodeFails == 0 {
			nodeFails = walks[0].FailureCount
		}
	}

	var extractFails, scanFails int
	if walkID != "" {
		_, _ = fmt.Fprintf(stderr, "==> inspect --gomod: extracting walk %s\n", walkID)
		ef := extractFlags{
			goBinary: f.goBinary,
			stages:   []string{"license", "interface", "callgraph", "example"},
			force:    f.force,
		}
		if eerr := runExtract(ctx, walkID, ef, io.Discard, stderr); eerr != nil {
			_, _ = fmt.Fprintf(stderr, "extract: %v\n", eerr)
			extractFails = 1
		}

		_, _ = fmt.Fprintf(stderr, "==> inspect --gomod: vuln-scanning walk %s\n", walkID)
		if verr := runVulnScan(ctx, walkID, commonWalkFlags{}, f.force, f.fresh, f.reachable, 1, false, false, f.goBinary, os.Getenv("USER"), filepath.Dir(f.gomodPath), io.Discard, stderr); verr != nil {
			_, _ = fmt.Fprintf(stderr, "vuln-scan: %v\n", verr)
			scanFails = 1
		}
	}

	var affectedCount int
	var snapshotVersion string
	if walkID != "" {
		runs, rerr := ctr.QueryScanRuns.ListRunsForWalk(ctx, walkID)
		if rerr == nil && len(runs) > 0 {
			if runs[0].OverallStatus == vuldomain.WalkStatusAffected {
				affectedCount = 1
			}
			snapshotVersion = runs[0].Snapshot.Version
		}
	}

	walkIDs := []string{}
	if walkID != "" {
		walkIDs = []string{walkID}
	}

	overallStatus := inspectSummaryStatus(nodeFails, extractFails, scanFails, affectedCount)

	if jsonOut {
		var directives *directivesSection
		if rec, derr := ctr.ExtractDirectives.Extract(ctx, f.gomodPath, activeConfig.DirectivePolicy); derr == nil {
			s := toDirectivesSection(rec)
			directives = &s
		} else {
			_, _ = fmt.Fprintf(stderr, "==> inspect: directive scan skipped: %v\n", derr)
		}
		var godebug *godebugSection
		if rec, derr := ctr.ExtractGoDebug.Extract(ctx, f.gomodPath, activeConfig.GoDebugPolicy); derr == nil {
			s := toGoDebugSection(rec)
			godebug = &s
		} else {
			_, _ = fmt.Fprintf(stderr, "==> inspect: godebug scan skipped: %v\n", derr)
		}
		var vendor *vendorSection
		if rec, derr := ctr.ExtractVendor.Extract(ctx, f.gomodPath, activeConfig.VendorPolicy.VendorOnly, activeConfig.VendorPolicy); derr == nil {
			s := toVendorSection(rec)
			vendor = &s
		} else if !errors.Is(derr, vendports.ErrNotVendored) {
			_, _ = fmt.Fprintf(stderr, "==> inspect: vendor scan skipped: %v\n", derr)
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(inspectSummary{
			ModuleCount:     moduleCount,
			NodeFails:       nodeFails,
			ExtractFails:    extractFails,
			ScanFails:       scanFails,
			OverallStatus:   overallStatus,
			AffectedCount:   affectedCount,
			SnapshotVersion: snapshotVersion,
			WalkIDs:         walkIDs,
			Directives:      directives,
			GoDebug:         godebug,
			Vendor:          vendor,
		}); err != nil {
			return fmt.Errorf("encoding summary: %w", err)
		}
		return nil
	}

	_, _ = fmt.Fprintf(stdout, "Status:   %s\n", overallStatus)
	_, _ = fmt.Fprintf(stdout, "Modules:  %d (%d failed)\n", moduleCount, nodeFails)
	_, _ = fmt.Fprintf(stdout, "Affected: %d\n", affectedCount)
	if extractFails > 0 {
		_, _ = fmt.Fprintf(stdout, "Extract fails: %d\n", extractFails)
	}
	if scanFails > 0 {
		_, _ = fmt.Fprintf(stdout, "Scan fails: %d (vulnerability status unknown)\n", scanFails)
	}
	if snapshotVersion != "" {
		_, _ = fmt.Fprintf(stdout, "Snapshot: %s\n", snapshotVersion)
	}
	if walkID != "" {
		_, _ = fmt.Fprintf(stdout, "Walk ID:  %s\n", walkID)
		_, _ = fmt.Fprintf(stdout, "\nTo get module context: kanonarion context --gomod %s\n", f.gomodPath)
	}
	return nil
}

// latestWalkIDForCoord returns the ID of the most recent walk for the given coordinate.
func latestWalkIDForCoord(ctx context.Context, uc QueryWalksUseCase, coord fetchdomain.ModuleCoordinate) (string, error) {
	walks, err := uc.ListWalks(ctx, walkports.WalkFilter{Target: &coord, Limit: 1})
	if err != nil {
		return "", fmt.Errorf("listing walks for %s: %w", coord, err)
	}
	if len(walks) == 0 {
		return "", fmt.Errorf("no walk found for %s after walk step", coord)
	}
	return walks[0].ID, nil
}

// latestWalkIDForCoordScope returns the ID of the most recent walk for the given
// coordinate and scope.
func latestWalkIDForCoordScope(ctx context.Context, uc QueryWalksUseCase, coord fetchdomain.ModuleCoordinate, scope domain.WalkScope) (string, error) {
	walks, err := uc.ListWalks(ctx, walkports.WalkFilter{Target: &coord, Scope: &scope, Limit: 1})
	if err != nil {
		return "", fmt.Errorf("listing walks for %s: %w", coord, err)
	}
	if len(walks) == 0 {
		return "", fmt.Errorf("no walk found for %s after walk step", coord)
	}
	return walks[0].ID, nil
}
