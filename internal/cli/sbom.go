package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	extractapp "github.com/eitanity/kanonarion/internal/extract/application"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
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

	cmd := &cobra.Command{
		Use:   "sbom [<walk-id>]",
		Short: "Generate a Software Bill of Materials for a walk",
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
			var scanRunPtr *string
			if scanRunID != "" {
				scanRunPtr = &scanRunID
			}
			logger := buildLogger(logLevel, stderr)
			return runSBOMGenerate(cmd.Context(), walkID, storeRoot, packagePattern, scanRunPtr, format, output, force, operator, logger, stdout, stderr)
		},
	}

	cmd.Flags().StringVar(&scanRunID, "scan", "", "include vulnerabilities from this scan run ID")
	cmd.Flags().StringVar(&format, "format", "cyclonedx-1.5", "SBOM format (cyclonedx-1.5)")
	cmd.Flags().StringVar(&output, "output", "", "write SBOM content to this file (default: stdout)")
	cmd.Flags().BoolVar(&force, "force", false, "re-generate even if cached")
	cmd.Flags().StringVar(&operator, "operator", "", "operator identifier (defaults to $USER)")
	cmd.Flags().BoolVar(&logJSON, "log-json", false, "emit logs as JSON")
	cmd.Flags().StringVar(&packagePattern, "package", "", "Go package pattern (e.g. ./cmd/kanonarion); scopes components to that binary's import closure")
	return cmd
}

func newSBOMShowCmd(stdout, stderr io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "sbom-show <sbom-id>",
		Short:   "Print a stored SBOM record",
		Example: `  kanonarion sbom-show sbom-abc123`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSBOMShow(cmd.Context(), args[0], storeRoot, jsonOut, stdout)
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
			return runSBOMList(cmd.Context(), storeRoot, walkID, jsonOut, stdout)
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
	operator string,
	logger *slog.Logger,
	stdout, stderr io.Writer,
) error {
	ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() { _ = cleanup() }()

	return sbomGenerateWith(ctx, ctr, walkID, packagePattern, scanRunID, format, output, force, operator, stdout, stderr)
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
	operator string,
	stdout, stderr io.Writer,
) error {
	var err error
	var allowList []fetchdomain.ModuleCoordinate
	if packagePattern != "" {
		var aerr error
		allowList, aerr = buildPackageAllowList(packagePattern)
		if aerr != nil {
			return aerr
		}
		if walkID == "" {
			walkID, err = ensureProjectWalkForSBOM(ctx, ctr, force, stderr)
			if err != nil {
				return err
			}
		}
	}

	req := application.SBOMRequest{
		WalkID:        walkID,
		WalkScanRunID: scanRunID,
		Format:        domain.SBOMFormat(format),
		Force:         force,
		Operator:      operator,
		AllowList:     allowList,
	}

	record, err := ctr.GenerateSBOM.Generate(ctx, req)
	if err != nil {
		return fmt.Errorf("generating sbom: %w", err)
	}

	if output != "" {
		if err := os.WriteFile(output, record.Content, 0o600); err != nil {
			return fmt.Errorf("writing sbom to %q: %w", output, err)
		}
		_, _ = fmt.Fprintf(stdout, "SBOM written to %s\n", output)
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

func runSBOMShow(ctx context.Context, id, storeRoot string, jsonOut bool, stdout io.Writer) error {
	logger := buildLogger(logLevel, stdout)
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

func runSBOMList(ctx context.Context, storeRoot, walkID string, jsonOut bool, stdout io.Writer) error {
	logger := buildLogger(logLevel, stdout)
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
func buildPackageAllowList(packagePattern string) ([]fetchdomain.ModuleCoordinate, error) {
	coordStrs, err := readPackageModules(packagePattern)
	if err != nil {
		return nil, fmt.Errorf("resolving package modules for %q: %w", packagePattern, err)
	}
	allowList := make([]fetchdomain.ModuleCoordinate, 0, len(coordStrs))
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
func ensureProjectWalkForSBOM(ctx context.Context, ctr *Container, force bool, stderr io.Writer) (string, error) {
	gomodPath, err := resolveGoModPath("")
	if err != nil {
		return "", fmt.Errorf("locating go.mod for project walk: %w", err)
	}
	modulePath, err := readGoModulePath(gomodPath)
	if err != nil {
		return "", fmt.Errorf("reading module path for project walk: %w", err)
	}

	walkID, reuse, err := projectWalkToReuse(ctx, ctr.QueryWalks, modulePath, force)
	if err != nil {
		return "", err
	}
	if reuse {
		return walkID, nil
	}

	// Cold store (or --force): build the project walk for the default code
	// scope, matching 'walk --gomod ./go.mod'. allowPartial is true so an
	// unfetchable node does not abort the SBOM; the SBOM records what resolved.
	progress := newWalkProgressReporter(stderr, false, activeConfig, logLevel)
	_, _ = fmt.Fprintf(stderr, "==> sbom: building project walk for %s\n", modulePath)
	if werr := runWalkProject(ctx, gomodPath, commonWalkFlags{}, force, true, 0, "", "", false, scopeCode, walkdomain.WalkDepthFull, "", false, progress, ctr.ExecuteWalk, io.Discard, stderr); werr != nil {
		return "", fmt.Errorf("building project walk: %w", werr)
	}

	return extractLicencesForProjectWalk(ctx, ctr.QueryWalks, ctr.Extract, modulePath, force, stderr)
}

// projectWalkToReuse decides whether an existing project walk can be reused.
// With --force it never reuses (reuse=false, build). Otherwise it reuses the
// latest succeeded project walk when one exists; a cold store (errNoProjectWalk)
// also returns reuse=false so the caller builds. Any other lookup error is
// propagated. Extracted so the reuse/build decision is testable without a live
// walk pipeline.
func projectWalkToReuse(ctx context.Context, qw QueryWalksUseCase, modulePath string, force bool) (walkID string, reuse bool, err error) {
	if force {
		return "", false, nil
	}
	walkID, err = findLatestProjectWalk(ctx, qw, modulePath)
	if err == nil {
		return walkID, true, nil
	}
	if errors.Is(err, errNoProjectWalk) {
		return "", false, nil
	}
	return "", false, err
}

// extractLicencesForProjectWalk runs the licence extraction stage over the
// freshly built project walk and returns its ID. It looks the walk up by target
// and code scope (accepting a partial walk, which a strictly-succeeded lookup
// would miss) so that a walk with some unfetchable nodes still yields a licensed
// SBOM for the nodes that resolved.
func extractLicencesForProjectWalk(ctx context.Context, qw QueryWalksUseCase, ex ExtractUseCase, modulePath string, force bool, stderr io.Writer) (string, error) {
	walkID, err := latestProjectWalkByScope(ctx, qw, modulePath, walkdomain.WalkScopeCode)
	if err != nil {
		return "", err
	}
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
func findLatestProjectWalk(ctx context.Context, qw QueryWalksUseCase, modulePath string) (string, error) {
	coord, err := fetchdomain.NewModuleCoordinate(modulePath, fetchdomain.LocalVersion)
	if err != nil {
		return "", fmt.Errorf("building project coordinate: %w", err)
	}
	succeeded := walkdomain.WalkSucceeded
	walks, err := qw.ListWalks(ctx, walkports.WalkFilter{
		Target:        &coord,
		OverallStatus: &succeeded,
		Limit:         1,
	})
	if err != nil {
		return "", fmt.Errorf("listing project walks for %s: %w", modulePath, err)
	}
	if len(walks) == 0 {
		return "", fmt.Errorf("%w for %s", errNoProjectWalk, modulePath)
	}
	return walks[0].ID, nil
}

// latestProjectWalkByScope returns the latest project walk rooted at
// modulePath@local for the given scope, regardless of overall status. Used
// straight after building a walk, where a partial result is still usable and a
// succeeded-only lookup would find nothing.
func latestProjectWalkByScope(ctx context.Context, qw QueryWalksUseCase, modulePath string, scope walkdomain.WalkScope) (string, error) {
	coord, err := fetchdomain.NewModuleCoordinate(modulePath, fetchdomain.LocalVersion)
	if err != nil {
		return "", fmt.Errorf("building project coordinate: %w", err)
	}
	walks, err := qw.ListWalks(ctx, walkports.WalkFilter{
		Target: &coord,
		Scope:  &scope,
		Limit:  1,
	})
	if err != nil {
		return "", fmt.Errorf("listing project walks for %s: %w", modulePath, err)
	}
	if len(walks) == 0 {
		return "", fmt.Errorf("project walk produced no record for %s", modulePath)
	}
	return walks[0].ID, nil
}
