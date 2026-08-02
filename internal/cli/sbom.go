package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/spf13/cobra"

	extractapp "github.com/eitanity/kanonarion/internal/extract/application"

	"github.com/eitanity/kanonarion/internal/sbom/application"
	"github.com/eitanity/kanonarion/internal/sbom/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

func newSBOMCmd(stdout, stderr io.Writer) *cobra.Command {
	var scanRunID string
	var format string
	var output string
	var force bool
	var operator string
	var logJSON bool
	var packagePattern string
	var stdlibFromGoMod bool
	var mainVersion string
	var mainLicense string
	var fromModcache string
	var policyPath string
	var noProgress bool

	cmd := &cobra.Command{
		Use:   "sbom [<walk-id>]",
		Short: "Generate a Software Bill of Materials for a walk",
		Long: `Generate a Software Bill of Materials (CycloneDX) for a walk.

Exit codes:
  0  SBOM generated with complete licence data
  1  SBOM generated, but one or more modules have no licence record — the
     document IS written; a licence-less SBOM must never pass as complete
  4  the walk, scan run or package scope named does not exist
  20 bad invocation (missing walk id and --package, unparseable coordinate, ...)`,
		Example: `  kanonarion sbom 01KQDBVW092ER1HNXZ60X27CMD
  kanonarion sbom 01KQDBVW092ER1HNXZ60X27CMD --scan vscan-01KQDBVW092ER1HNXZ60X27CMD-1234
  kanonarion sbom 01KQDBVW092ER1HNXZ60X27CMD --output sbom.json
  kanonarion sbom 01KQDBVW092ER1HNXZ60X27CMD --package ./cmd/kanonarion
  kanonarion sbom --package ./cmd/kanonarion`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			walkID := ""
			if len(args) > 0 {
				walkID = args[0]
			}
			if walkID == "" && packagePattern == "" {
				return fmt.Errorf("a walk ID argument or --package is required")
			}
			if fromModcache != "" {
				gomodPath, gerr := resolveGoModPath("")
				if gerr != nil {
					return fmt.Errorf("--from-modcache: locating go.mod: %w", gerr)
				}
				if merr := resolveModcacheMode(fromModcache, gomodPath); merr != nil {
					return merr
				}
			}
			var scanRunPtr *string
			if scanRunID != "" {
				scanRunPtr = &scanRunID
			}
			logger := buildLogger(logLevel, stderr)
			return runSBOMGenerate(cmd.Context(), walkID, storeRoot, packagePattern, scanRunPtr, format, output, force, stdlibFromGoMod, noProgress, mainVersion, mainLicense, operator, policyPath, logger, stdout, stderr)
		},
	}

	cmd.Flags().StringVar(&scanRunID, "scan", "", "include vulnerabilities from this scan run ID")
	cmd.Flags().StringVar(&format, "format", "cyclonedx-1.6", "SBOM format (cyclonedx-1.6)")
	cmd.Flags().StringVar(&output, "output", "", "write SBOM content to this file (default: stdout)")
	cmd.Flags().BoolVar(&force, "force", false, "re-generate even if cached")
	cmd.Flags().StringVar(&operator, "operator", "", "operator identifier (defaults to $USER)")
	cmd.Flags().BoolVar(&logJSON, "log-json", false, "emit logs as JSON")
	cmd.Flags().StringVar(&packagePattern, "package", "", "Go package pattern (e.g. ./cmd/kanonarion); scopes components to that binary's import closure")
	cmd.Flags().StringVar(&policyPath, "policy", "", "path to depth policy YAML (default: search for .kanonarion/policy.yaml)")
	cmd.Flags().StringVar(&mainVersion, "main-version", "", "version to stamp on the SBOM subject (metadata.component) instead of the synthetic \"local\"; use a release tag (e.g. v0.1.1) so the subject is a resolvable coordinate")
	cmd.Flags().StringVar(&mainLicense, "main-license", "", "SPDX id/expression (e.g. Apache-2.0) to attach to the SBOM subject, which has no fetched licence record of its own")
	registerStdlibFromGoModFlag(cmd, &stdlibFromGoMod)
	registerFromModcacheFlag(cmd, &fromModcache)
	registerAllowVerificationDowngradeFlag(cmd)
	registerNoProgressFlag(cmd, &noProgress)
	return cmd
}

func newSBOMShowCmd(stdout, stderr io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "sbom-show <sbom-id>",
		Short:   "Print a stored SBOM record",
		Example: `  kanonarion sbom-show sbom-abc123`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSBOMShow(cmd.Context(), args[0], storeRoot, jsonOut, stdout, stderr)
		},
	}

	return cmd
}

func newSBOMListCmd(stdout, stderr io.Writer) *cobra.Command {
	var walkID string

	cmd := &cobra.Command{
		Use:     "sbom-list",
		Short:   "List SBOM records in the store",
		Example: `  kanonarion sbom-list --walk 01KQDBVW092ER1HNXZ60X27CMD`,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSBOMList(cmd.Context(), storeRoot, walkID, jsonOut, stdout, stderr)
		},
	}

	cmd.Flags().StringVar(&walkID, "walk", "", "filter by walk ID")
	return cmd
}

func runSBOMGenerate(
	ctx context.Context,
	walkID, storeRoot string,
	packagePattern string,
	scanRunID *string,
	format, output string,
	force bool,
	stdlibFromGoMod bool,
	noProgress bool,
	mainVersion, mainLicense string,
	operator string,
	policyPath string,
	logger *slog.Logger,
	stdout, stderr io.Writer,
) error {
	// --package builds (or reuses) a project walk, so a local go.sum can anchor
	// each fetched module's integrity on the normal path. Resolve it
	// before the container so the fetch use case is wired with the verifier.
	if packagePattern != "" {
		if gomodPath, gerr := resolveGoModPath(""); gerr == nil {
			resolveProjectGoSum(gomodPath)
		}
	}
	ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() { _ = cleanup() }()

	return sbomGenerateWith(ctx, ctr, walkID, packagePattern, scanRunID, format, output, force, stdlibFromGoMod, noProgress, mainVersion, mainLicense, operator, policyPath, stdout, stderr)
}

// sbomGenerateWith holds the sbom-generate logic over an injected Container:
// it builds the package allow-list, resolves or builds the project walk when
// needed, generates the SBOM, and writes it to a file or stdout, failing
// non-zero when licence data is incomplete rather than letting a degraded SBOM
// pass. Split from runSBOMGenerate so the output and incomplete-licence branches
// are testable without a live store.
func sbomGenerateWith(
	ctx context.Context,
	ctr *Container,
	walkID, packagePattern string,
	scanRunID *string,
	format, output string,
	force bool,
	stdlibFromGoMod bool,
	noProgress bool,
	mainVersion, mainLicense string,
	operator string,
	policyPath string,
	stdout, stderr io.Writer,
) error {
	var err error
	var allowList []coordinate.ModuleCoordinate
	if packagePattern != "" {
		var aerr error
		allowList, aerr = buildPackageAllowList(packagePattern)
		if aerr != nil {
			return aerr
		}
		if walkID == "" {
			walkID, err = ensureProjectWalkForSBOM(ctx, ctr, force, stdlibFromGoMod, noProgress, policyPath, stderr)
			if err != nil {
				return err
			}
		}
	}

	req := application.SBOMRequest{
		WalkID:               walkID,
		WalkScanRunID:        scanRunID,
		Format:               domain.SBOMFormat(format),
		Force:                force,
		Operator:             operator,
		AllowList:            allowList,
		MainComponentVersion: mainVersion,
		MainComponentLicense: mainLicense,
	}

	record, err := ctr.GenerateSBOM.Generate(ctx, req)
	if err != nil {
		return fmt.Errorf("generating sbom: %w", err)
	}

	if output != "" {
		if err := writeArtefactFile("SBOM", output, record.Content, stdout); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(stdout, "ID:           %s\n", record.ID)
		_, _ = fmt.Fprintf(stdout, "Content-Hash: %s\n", record.ContentHash)
	} else if _, err := stdout.Write(record.Content); err != nil {
		return fmt.Errorf("writing sbom to stdout: %w", err)
	}

	// A licence-less SBOM must never pass as complete. Surface the gap as a
	// non-zero exit on every output path: the message travels on stderr via
	// main, never on stdout where it would corrupt the SBOM bytes, and is
	// never dropped as it was on the bare stdout path. The artifact is still
	// emitted (as audit prints its table before blocking) so the gap can be
	// inspected; absence of licence data is surfaced, never presented clean.
	if record.LicensesIncomplete {
		return &exitError{code: ExitPartial, msg: "sbom generated with incomplete licence data: one or more modules have no licence record"}
	}
	return nil
}

func runSBOMShow(ctx context.Context, id, storeRoot string, jsonOut bool, stdout, stderr io.Writer) error {
	logger := buildLogger(logLevel, stderr)
	ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() { _ = cleanup() }()

	record, err := ctr.QuerySBOM.GetSBOMRecord(ctx, id)
	if err != nil {
		return fmt.Errorf("retrieving sbom %q: %w", id, err)
	}

	if jsonOut {
		type meta struct {
			ID                 string  `json:"id"`
			Ecosystem          string  `json:"ecosystem"`
			WalkID             string  `json:"walk_id"`
			WalkScanRunID      *string `json:"walk_scan_run_id,omitempty"`
			Format             string  `json:"format"`
			PipelineVersion    string  `json:"pipeline_version"`
			GeneratedAt        string  `json:"generated_at"`
			ContentHash        string  `json:"content_hash"`
			Operator           string  `json:"operator"`
			LicensesIncomplete bool    `json:"licenses_incomplete"`
		}
		m := meta{
			ID:                 record.ID,
			Ecosystem:          record.Ecosystem,
			WalkID:             record.WalkID,
			WalkScanRunID:      record.WalkScanRunID,
			Format:             string(record.Format),
			PipelineVersion:    record.PipelineVersion,
			GeneratedAt:        record.GeneratedAt.Format("2006-01-02T15:04:05Z"),
			ContentHash:        record.ContentHash,
			Operator:           record.Operator,
			LicensesIncomplete: record.LicensesIncomplete,
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(m); err != nil {
			return fmt.Errorf("encoding sbom metadata: %w", err)
		}
		return nil
	}

	if _, err := stdout.Write(record.Content); err != nil {
		return fmt.Errorf("writing sbom content: %w", err)
	}
	return nil
}

func runSBOMList(ctx context.Context, storeRoot, walkID string, jsonOut bool, stdout, stderr io.Writer) error {
	logger := buildLogger(logLevel, stderr)
	ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() { _ = cleanup() }()

	records, err := ctr.QuerySBOM.ListSBOMRecords(ctx, walkID)
	if err != nil {
		return fmt.Errorf("listing sbom records: %w", err)
	}

	if jsonOut {
		type row struct {
			ID              string  `json:"id"`
			Ecosystem       string  `json:"ecosystem"`
			WalkID          string  `json:"walk_id"`
			WalkScanRunID   *string `json:"walk_scan_run_id,omitempty"`
			Format          string  `json:"format"`
			PipelineVersion string  `json:"pipeline_version"`
			GeneratedAt     string  `json:"generated_at"`
			ContentHash     string  `json:"content_hash"`
		}
		rows := make([]row, len(records))
		for i, r := range records {
			rows[i] = row{
				ID:              r.ID,
				Ecosystem:       r.Ecosystem,
				WalkID:          r.WalkID,
				WalkScanRunID:   r.WalkScanRunID,
				Format:          string(r.Format),
				PipelineVersion: r.PipelineVersion,
				GeneratedAt:     r.GeneratedAt.Format("2006-01-02T15:04:05Z"),
				ContentHash:     r.ContentHash,
			}
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rows); err != nil {
			return fmt.Errorf("encoding sbom list: %w", err)
		}
		return nil
	}

	if len(records) == 0 {
		_, _ = fmt.Fprintln(stdout, "No SBOM records found.")
		return nil
	}
	for _, r := range records {
		scanRun := "-"
		if r.WalkScanRunID != nil {
			scanRun = *r.WalkScanRunID
		}
		_, _ = fmt.Fprintf(stdout, "%s  walk=%-26s  scan=%-26s  format=%-14s  %s\n",
			r.ID, r.WalkID, scanRun, string(r.Format),
			r.GeneratedAt.Format("2006-01-02T15:04:05Z"))
	}
	return nil
}

// buildPackageAllowList resolves the module coordinates for the binary's import
// closure via go list -deps and returns them as a parsed AllowList.
func buildPackageAllowList(packagePattern string) ([]coordinate.ModuleCoordinate, error) {
	coordStrs, err := readPackageModules(packagePattern)
	if err != nil {
		return nil, fmt.Errorf("resolving package modules for %q: %w", packagePattern, err)
	}
	allowList := make([]coordinate.ModuleCoordinate, 0, len(coordStrs))
	for _, s := range coordStrs {
		coord, cerr := parseCoordinate(s)
		if cerr != nil {
			return nil, fmt.Errorf("invalid coordinate %q: %w", s, cerr)
		}
		allowList = append(allowList, coord)
	}
	return allowList, nil
}

// errNoProjectWalk marks the absence of a reusable succeeded project walk. It
// is a signal, not a failure: sbom --package treats it as "cold store, build
// the prerequisites" rather than surfacing it to the caller.
var errNoProjectWalk = errors.New("no succeeded project walk found")

// ensureProjectWalkForSBOM returns the project walk ID to generate a --package
// SBOM from. Without --force it reuses the latest succeeded project walk when
// one exists (no redundant re-walk or re-extract). When none exists (a cold
// store) or --force is set, it builds the prerequisites itself, unattended: a
// project-rooted walk over the current go.mod for the default code scope,
// equivalent to 'walk --gomod ./go.mod', then a licence-extraction stage over
// that walk, equivalent to 'extract <walk-id> --stages license'. So a bare
// 'sbom --package' on a clean store yields a fully-licenced artifact.
func ensureProjectWalkForSBOM(ctx context.Context, ctr *Container, force, stdlibFromGoMod, noProgress bool, policyPath string, stderr io.Writer) (string, error) {
	gomodPath, err := resolveGoModPath("")
	if err != nil {
		return "", fmt.Errorf("locating go.mod for project walk: %w", err)
	}
	modulePath, err := readGoModulePath(gomodPath)
	if err != nil {
		return "", fmt.Errorf("reading module path for project walk: %w", err)
	}

	// Reuse is gated on the platform, not just the target. A walk resolved for
	// another GOOS/GOARCH holds another closure, and an SBOM built over it would
	// inventory components this build never selects. A miss is not a refusal
	// here: the cold-store path below builds a walk in this environment, which
	// is the answer a refusal would have asked the operator to produce by hand.
	platform := currentBuildEnvFilter(ctx, "", filepath.Dir(gomodPath), buildLogger(logLevel, stderr))
	walkID, reuse, err := projectWalkToReuse(ctx, ctr.QueryWalks, modulePath, force, platform)
	if err != nil {
		return "", err
	}
	if reuse {
		_, _ = fmt.Fprintf(progressWriter(stderr, noProgress), "==> sbom: reusing project walk %s (%s)\n", walkID, platform)
		return walkID, nil
	}

	// Cold store (or --force): build the project walk for the default code
	// scope, matching 'walk --gomod ./go.mod'. allowPartial is true so an
	// unfetchable node does not abort the SBOM; the SBOM records what resolved.
	progress := newWalkProgressReporter(stderr, noProgress, activeConfig, logLevel)
	_, _ = fmt.Fprintf(progressWriter(stderr, noProgress), "==> sbom: building project walk for %s\n", modulePath)
	walkResult, werr := runWalkProject(ctx, gomodPath, force, true, 0, "", policyPath, false, scopeCode, walkdomain.WalkDepthFull, "", false, stdlibFromGoMod, progress, ctr.ExecuteWalk, nil, io.Discard, stderr)
	if werr != nil {
		return "", fmt.Errorf("building project walk: %w", werr)
	}

	// A go.sum verification failure surfaces as a fetch-failed node. Fail the
	// SBOM rather than emitting one that silently omits the unverifiable module:
	// --from-modcache mode fails on any such node (go.sum is the sole anchor),
	// and the normal network path fails on a go.sum-mismatch node.
	localCoord, cErr := coordinate.NewLocalCoordinate(modulePath)
	if cErr != nil {
		return "", fmt.Errorf("project coordinate for %s: %w", modulePath, cErr)
	}
	// The walk this run just executed or reused, taken from its own result. The
	// latest-for-target lookup this replaces carries no build-environment axis,
	// so a cross-compiled run could gate, licence and inventory another
	// platform's walk whenever that one was newer.
	if walkResult.Record.ID == "" {
		return "", fmt.Errorf("project walk produced no record for %s", modulePath)
	}
	walkID = walkResult.Record.ID
	walkRec, gerr := ctr.QueryWalks.GetWalk(ctx, walkID)
	if gerr != nil {
		return "", fmt.Errorf("loading project walk %s: %w", walkID, gerr)
	}
	if gateErr := modcacheWalkGate(walkRec, localCoord); gateErr != nil {
		return "", gateErr
	}
	if gateErr := goSumWalkGate(walkRec, localCoord); gateErr != nil {
		return "", gateErr
	}

	return extractLicencesForProjectWalk(ctx, ctr.Extract, walkID, force, stderr)
}

// projectWalkToReuse decides whether an existing project walk can be reused.
// With --force it never reuses (reuse=false, build). Otherwise it reuses the
// latest succeeded project walk when one exists; a cold store (errNoProjectWalk)
// also returns reuse=false so the caller builds. Any other lookup error is
// propagated. Extracted so the reuse/build decision is testable without a live
// walk pipeline.
func projectWalkToReuse(ctx context.Context, qw QueryWalksUseCase, modulePath string, force bool, platform walkports.BuildEnvFilter) (walkID string, reuse bool, err error) {
	if force {
		return "", false, nil
	}
	walkID, err = findLatestProjectWalk(ctx, qw, modulePath, platform)
	if err == nil {
		return walkID, true, nil
	}
	if errors.Is(err, errNoProjectWalk) {
		return "", false, nil
	}
	return "", false, err
}

// extractLicencesForProjectWalk runs the licence extraction stage over walkID —
// the walk the caller just executed or reused — and returns it. A partial walk
// is accepted, so a walk with some unfetchable nodes still yields a licensed
// SBOM for the nodes that resolved.
func extractLicencesForProjectWalk(ctx context.Context, ex ExtractUseCase, walkID string, force bool, stderr io.Writer) (string, error) {
	_, _ = fmt.Fprintf(stderr, "==> sbom: extracting licences for walk %s\n", walkID)
	if _, err := ex.Execute(ctx, extractapp.ExtractRequest{
		WalkID: walkID,
		Stages: []string{"license"},
		Force:  force,
	}); err != nil {
		return "", fmt.Errorf("extracting licences for walk %s: %w", walkID, err)
	}
	return walkID, nil
}

// findLatestProjectWalk looks up the latest succeeded project walk whose target
// is modulePath@local. Any scope (code/tool/complete) qualifies: --package
// derives its own binary import closure and filters the walk's components to it,
// and every project scope's set contains the binary's modules. Returns
// errNoProjectWalk when no succeeded walk exists.
func findLatestProjectWalk(ctx context.Context, qw QueryWalksUseCase, modulePath string, platform walkports.BuildEnvFilter) (string, error) {
	coord, err := coordinate.NewModuleCoordinate(modulePath, coordinate.LocalVersion)
	if err != nil {
		return "", fmt.Errorf("building project coordinate: %w", err)
	}
	succeeded := walkdomain.WalkSucceeded
	walks, err := qw.ListWalks(ctx, walkports.WalkFilter{
		Target:        &coord,
		OverallStatus: &succeeded,
		BuildEnv:      &platform,
		Limit:         1,
	})
	if err != nil {
		return "", fmt.Errorf("listing project walks for %s: %w", modulePath, err)
	}
	if len(walks) == 0 {
		return "", fmt.Errorf("%w for %s on %s", errNoProjectWalk, modulePath, platform)
	}
	return walks[0].ID, nil
}
