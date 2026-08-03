package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/spf13/cobra"

	extractapp "github.com/eitanity/kanonarion/internal/extract/application"

	"github.com/eitanity/kanonarion/internal/sbom/application"
	"github.com/eitanity/kanonarion/internal/sbom/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// sbomFlags holds every flag the sbom command registers. They live in one
// struct, rather than in a local variable each, so that a flag the command
// parses but never acts on is visible per field.
type sbomFlags struct {
	format          string
	output          string
	force           bool
	operator        string
	packagePattern  string
	stdlibFromGoMod bool
	mainVersion     string
	mainLicense     string
	fromModcache    string
	policyPath      string
	noProgress      bool
	generatedAt     string
}

func newSBOMCmd(stdout, stderr io.Writer) *cobra.Command {
	var f sbomFlags

	cmd := &cobra.Command{
		Use:   "sbom [<walk-id>]",
		Short: "Generate a Software Bill of Materials for a walk",
		Long: `Generate a Software Bill of Materials (CycloneDX) for a walk.

The document is an inventory: components, their identity, hashes, licences and
dependency graph. It carries no vulnerability list. Vulnerability and
reachability answers come from 'kanonarion vuln-show' and
'kanonarion reachability', which state the frame and the advisory snapshot the
answer was measured against.

Exit codes:
  0  SBOM generated, every component carrying a licence identity
  1  SBOM generated, but one or more components carry no licence identity —
     no licence record was found, or the record found identified no SPDX
     licence. The document IS written and names them; a licence-less SBOM
     must never pass as complete
  4  the walk or package scope named does not exist
  20 bad invocation (missing walk id and --package, unparseable coordinate,
     unparseable --generated-at, ...)`,
		Example: `  kanonarion sbom 01KQDBVW092ER1HNXZ60X27CMD
  kanonarion sbom 01KQDBVW092ER1HNXZ60X27CMD --output sbom.json
  kanonarion sbom 01KQDBVW092ER1HNXZ60X27CMD --package ./cmd/kanonarion
  kanonarion sbom --package ./cmd/kanonarion`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			walkID := ""
			if len(args) > 0 {
				walkID = args[0]
			}
			if walkID == "" && f.packagePattern == "" {
				return fmt.Errorf("a walk ID argument or --package is required")
			}
			docTime, terr := parseGeneratedAt(f.generatedAt)
			if terr != nil {
				return terr
			}
			logger := buildLogger(logLevel, stderr)
			return runSBOMGenerate(cmd.Context(), walkID, storeRoot, f, docTime, logger, stdout, stderr)
		},
	}

	cmd.Flags().StringVar(&f.format, "format", "cyclonedx-1.6", "SBOM format (cyclonedx-1.6)")
	cmd.Flags().StringVar(&f.output, "output", "", "write SBOM content to this file (default: stdout)")
	cmd.Flags().BoolVar(&f.force, "force", false, "re-generate even if cached")
	cmd.Flags().StringVar(&f.operator, "operator", "", "operator identifier (defaults to $USER)")
	cmd.Flags().StringVar(&f.packagePattern, "package", "", "Go package pattern (e.g. ./cmd/kanonarion); scopes components to that binary's import closure")
	cmd.Flags().StringVar(&f.policyPath, "policy", "", "path to depth policy YAML (default: search for .kanonarion/policy.yaml)")
	cmd.Flags().StringVar(&f.mainVersion, "main-version", "", "version to stamp on the SBOM subject (metadata.component) instead of the synthetic \"local\"; use a release tag (e.g. v0.1.1) so the subject is a resolvable coordinate")
	cmd.Flags().StringVar(&f.mainLicense, "main-license", "", "SPDX id/expression (e.g. Apache-2.0) to attach to the SBOM subject, which has no fetched licence record of its own")
	cmd.Flags().StringVar(&f.generatedAt, "generated-at", "", "RFC3339 time this document is being created (e.g. 2026-01-31T09:00:00Z); becomes metadata.timestamp. Omitted, the document is stamped with the newest licence extraction time among its inputs and says so")
	registerStdlibFromGoModFlag(cmd, &f.stdlibFromGoMod)
	registerFromModcacheFlag(cmd, &f.fromModcache)
	registerAllowVerificationDowngradeFlag(cmd)
	registerNoProgressFlag(cmd, &f.noProgress)
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
	f sbomFlags,
	generatedAt time.Time,
	logger *slog.Logger,
	stdout, stderr io.Writer,
) error {
	// A module fetched via --from-modcache is stored under a "modcache:zip:"
	// blob handle, not a content-addressed one; every stage that reads those
	// blobs needs the same modcache-aware store that fetched them. Resolved on
	// the path that consumes it, so the flag is answered for where the work
	// happens rather than in the constructor.
	if f.fromModcache != "" {
		gomodPath, gerr := resolveGoModPath("")
		if gerr != nil {
			return fmt.Errorf("--from-modcache: locating go.mod: %w", gerr)
		}
		if merr := resolveModcacheMode(f.fromModcache, gomodPath); merr != nil {
			return merr
		}
	}
	// --package builds (or reuses) a project walk, so a local go.sum can anchor
	// each fetched module's integrity on the normal path. Resolve it
	// before the container so the fetch use case is wired with the verifier.
	if f.packagePattern != "" {
		if gomodPath, gerr := resolveGoModPath(""); gerr == nil {
			resolveProjectGoSum(gomodPath)
		}
	}
	ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() { _ = cleanup() }()

	return sbomGenerateWith(ctx, ctr, walkID, f, generatedAt, stdout, stderr)
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
	walkID string,
	f sbomFlags,
	generatedAt time.Time,
	stdout, stderr io.Writer,
) error {
	// --stdlib-from-gomod shapes the project walk this command builds when it
	// has none. Named a walk, there is nothing left for it to shape: the walk
	// exists, its stdlib node is already pinned one way or the other, and the
	// document is generated from what that walk recorded. Refuse it by name
	// rather than accept it and emit a byte-identical document.
	if walkID != "" && f.stdlibFromGoMod {
		if err := refuseInapplicableFlags("sbom <walk-id>", []inapplicableFlag{
			{flag: "--stdlib-from-gomod", where: "sbom --package, which builds the walk"},
		}); err != nil {
			return err
		}
	}

	var err error
	var allowList []coordinate.ModuleCoordinate
	if f.packagePattern != "" {
		var aerr error
		allowList, aerr = buildPackageAllowList(f.packagePattern)
		if aerr != nil {
			return aerr
		}
		if walkID == "" {
			walkID, err = ensureProjectWalkForSBOM(ctx, ctr, f.force, f.stdlibFromGoMod, f.noProgress, f.policyPath, stderr)
			if err != nil {
				return err
			}
		}
	}

	req := application.SBOMRequest{
		WalkID:               walkID,
		GeneratedAt:          generatedAt,
		Format:               domain.SBOMFormat(f.format),
		Force:                f.force,
		Operator:             f.operator,
		AllowList:            allowList,
		MainComponentVersion: f.mainVersion,
		MainComponentLicense: f.mainLicense,
	}

	record, err := ctr.GenerateSBOM.Generate(ctx, req)
	if err != nil {
		return fmt.Errorf("generating sbom: %w", err)
	}

	if f.output != "" {
		if err := writeArtefactFile("SBOM", f.output, record.Content, stdout); err != nil {
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
	//
	// The components are named from the document that was just written rather
	// than from the record, so the message describes the artefact a consumer
	// will hold, and says the same thing whether the document was generated now
	// or served from the cache.
	if record.LicensesIncomplete {
		return &exitError{
			code: ExitPartial,
			msg:  "sbom generated with undetermined licences: " + undeterminedLicenceSummary(record.Content),
		}
	}
	return nil
}

// parseGeneratedAt reads the --generated-at flag. An empty value is not an
// error: it means the caller supplied no creation time, and the document falls
// back to a derived timestamp it labels as derived.
func parseGeneratedAt(v string) (time.Time, error) {
	if v == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, fmt.Errorf("--generated-at %q: expected an RFC3339 time such as 2026-01-31T09:00:00Z: %w", v, err)
	}
	return t, nil
}

// undeterminedLicenceSummary names the components of a generated document that
// carry no licence identity, so the operator learns which they are without
// opening the artefact.
//
// It reads the document rather than the record because the document is the thing
// being judged and is present on every path, cached included. A document this
// process cannot re-read is reported as such: the exit code has already been
// decided by the record, and a parse failure here must not turn a stated gap
// into a silent one.
func undeterminedLicenceSummary(content []byte) string {
	var doc struct {
		Components []struct {
			Name     string            `json:"name"`
			Version  string            `json:"version"`
			Licenses []json.RawMessage `json:"licenses"`
		} `json:"components"`
		Metadata struct {
			Component struct {
				Name     string            `json:"name"`
				Version  string            `json:"version"`
				Licenses []json.RawMessage `json:"licenses"`
			} `json:"component"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(content, &doc); err != nil {
		return "one or more components carry no licence identity (the generated document could not be re-read to name them: " + err.Error() + ")"
	}
	// The subject is deduplicated against the component list: a walk rooted at a
	// module carries that module as both, and counting it twice would put the
	// message at odds with the count the document itself states.
	var names []string
	seen := make(map[string]struct{}, len(doc.Components))
	add := func(coord, suffix string) {
		if _, dup := seen[coord]; dup {
			return
		}
		seen[coord] = struct{}{}
		names = append(names, coord+suffix)
	}
	if m := doc.Metadata.Component; m.Name != "" && len(m.Licenses) == 0 {
		add(m.Name+"@"+m.Version, " (the document's subject)")
	}
	for _, c := range doc.Components {
		if len(c.Licenses) == 0 {
			add(c.Name+"@"+c.Version, "")
		}
	}
	if len(names) == 0 {
		return "one or more components carry no licence identity"
	}
	return fmt.Sprintf("%d component(s) with no licence identity: %s", len(names), strings.Join(names, ", "))
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
			ID                 string `json:"id"`
			Ecosystem          string `json:"ecosystem"`
			WalkID             string `json:"walk_id"`
			Format             string `json:"format"`
			PipelineVersion    string `json:"pipeline_version"`
			GeneratedAt        string `json:"generated_at"`
			ContentHash        string `json:"content_hash"`
			Operator           string `json:"operator"`
			LicensesIncomplete bool   `json:"licenses_incomplete"`
		}
		m := meta{
			ID:                 record.ID,
			Ecosystem:          record.Ecosystem,
			WalkID:             record.WalkID,
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
			ID              string `json:"id"`
			Ecosystem       string `json:"ecosystem"`
			WalkID          string `json:"walk_id"`
			Format          string `json:"format"`
			PipelineVersion string `json:"pipeline_version"`
			GeneratedAt     string `json:"generated_at"`
			ContentHash     string `json:"content_hash"`
		}
		rows := make([]row, len(records))
		for i, r := range records {
			rows[i] = row{
				ID:              r.ID,
				Ecosystem:       r.Ecosystem,
				WalkID:          r.WalkID,
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
		_, _ = fmt.Fprintf(stdout, "%s  walk=%-26s  format=%-14s  %s\n",
			r.ID, r.WalkID, string(r.Format),
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
