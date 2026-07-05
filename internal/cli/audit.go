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

	"github.com/spf13/cobra"

	proxyadapter "github.com/eitanity/kanonarion/internal/adapters/proxy/direct"
	fetchapp "github.com/eitanity/kanonarion/internal/fetch/application"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	licapp "github.com/eitanity/kanonarion/internal/license/application"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

type auditFlags struct {
	gomodPath     string
	goproxy       string
	force         bool
	fresh         bool
	tool          bool
	project       bool
	skipVCSVerify bool
}

func newAuditCmd(stdout, stderr io.Writer) *cobra.Command {
	var f auditFlags

	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Audit direct dependencies from a go.mod file",
		Long: `Audit fetches, scans, and reports on every dependency in a go.mod's scope.

For each module, audit shows:
  - Coordinate and whether it is the latest published version
  - Verification status (from the fetch record)
  - License (SPDX identifier)
  - Vulnerability status

This collapses the walk → vuln-scan → license-list workflow into a single call.

The dependency scope is consistent with every go.mod command: the default is the
project's own build dependencies (the code your packages import, incl. tests);
--tool audits the tooling supply chain; --project audits the complete set (code
+ tooling).`,
		Example: `  kanonarion audit
  kanonarion audit --gomod ./go.mod
  kanonarion audit --gomod ./go.mod --json
  kanonarion audit --gomod ./go.mod --tool
  kanonarion audit --gomod ./go.mod --project --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAudit(cmd.Context(), f, stdout, stderr)
		},
	}

	cmd.Flags().StringVar(&f.gomodPath, "gomod", "", "path to go.mod file (default: ./go.mod)")
	cmd.Flags().StringVar(&f.goproxy, "goproxy", "", "override GOPROXY (default: $GOPROXY or proxy.golang.org)")
	cmd.Flags().BoolVar(&f.force, "force", false, "re-fetch and re-scan even if cached records exist")
	cmd.Flags().BoolVar(&f.fresh, "fresh", false, "fetch fresh vulnerability database snapshot from network")
	cmd.Flags().BoolVar(&f.tool, "tool", false, "scope to the tooling supply chain (the go.mod tool directives' closure)")
	cmd.Flags().BoolVar(&f.project, "project", false, "scope to the complete set: the project's code AND tooling")
	cmd.Flags().BoolVar(&f.skipVCSVerify, "skip-vcs-verify", false, "skip git cross-verification; sumdb verification still runs")

	return cmd
}

type auditModuleResult struct {
	Coordinate    string `json:"coordinate"`
	Scope         string `json:"scope,omitempty"`
	Verification  string `json:"verification"`
	License       string `json:"license"`
	LicenseStatus string `json:"license_status"`
	VulnStatus    string `json:"vuln_status"`
	VulnFindings  int    `json:"vuln_findings"`
	// VulnReason carries the diagnostic for a non-clean, non-affected status
	// (ScanFailed → ErrorDetail, Unscannable → UnscannableReason). Absent for
	// Clean/Affected. Without it a ScanFailed row is an "absence-as-answer".
	VulnReason      string `json:"vuln_reason,omitempty"`
	LicenseCategory string `json:"license_category,omitempty"`
	LicenseSource   string `json:"license_source,omitempty"`
	PolicyOutcome   string `json:"policy_outcome,omitempty"`
	// LicenseResolved is false when no SPDX could be determined for this
	// module (no record, or status None/Multiple/ExtractionFailed/
	// Cancelled, with no override). When false the policy_outcome is NOT a
	// clean verdict — it is governed by the scope's unknown_license policy
	// and the result is uncertain.
	LicenseResolved bool `json:"license_resolved"`
	// LicenseUncertainty is a machine-readable reason when
	// LicenseResolved is false: no_record | none | multiple |
	// extraction_failed | cancelled | not_run.
	LicenseUncertainty string `json:"license_uncertainty,omitempty"`
	// PolicyBlocking is true when this uncertain result is a hard
	// compliance failure (scope unknown_license = block); `audit` exits
	// non-zero when any result is blocking.
	PolicyBlocking bool   `json:"policy_blocking,omitempty"`
	IsLatest       bool   `json:"is_latest"`
	LatestVersion  string `json:"latest_version,omitempty"`
	DaysBehind     int    `json:"days_behind,omitempty"`
	// Direct is true when this module is a direct dependency in the audited
	// go.mod. The report covers the whole scoped build list, so transitive
	// modules (Direct=false) appear alongside direct ones and the
	// compliance picture spans the full closure, not just the require lines.
	Direct bool `json:"direct"`
}

func runAudit(ctx context.Context, f auditFlags, stdout, stderr io.Writer) error {
	gomodPath, err := resolveGoModPath(f.gomodPath)
	if err != nil {
		return err
	}
	f.gomodPath = gomodPath

	scope, err := scopeFromFlags(f.tool, f.project)
	if err != nil {
		return err
	}
	coords, err := resolveScopeModules(f.gomodPath, scope)
	if err != nil {
		return fmt.Errorf("resolving %s scope: %w", scope, err)
	}
	if len(coords) == 0 {
		_, _ = fmt.Fprintf(stdout, "no %s dependencies found in %s\n", scope, f.gomodPath)
		return nil
	}

	logger := buildLogger(logLevel, stderr)
	ctr, cleanup, err := NewContainer(storeRoot, f.goproxy, "", f.skipVCSVerify, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() { _ = cleanup() }()

	proxy, err := proxyadapter.New(f.goproxy, false)
	if err != nil {
		return fmt.Errorf("creating proxy adapter: %w", err)
	}

	results, err := auditScope(ctx, coords, scope, f, proxy, ctr, stderr)
	if err != nil {
		return err
	}

	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(results); err != nil {
			return fmt.Errorf("encoding results: %w", err)
		}
		return auditBlockingErr(results)
	}

	if err := printAuditTable(stdout, results); err != nil {
		return err
	}
	return auditBlockingErr(results)
}

// walkScopeFor maps a CLI depScope to the walk-record WalkScope tag. The string
// values are identical, so this is a direct conversion documented for clarity.
func walkScopeFor(s depScope) walkdomain.WalkScope { return walkdomain.WalkScope(s) }

// auditScope performs a single project walk rooted at the local module and
// derives one auditModuleResult per dependency by iterating that walk's graph
// nodes. Licence extraction and vuln scanning each run once over the project
// walk, so the same per-module facts are produced once from a shared graph
// rather than redundantly per dependency. The project walk it leaves behind is
// the record `sbom --package` auto-discovers, so a completed audit is a valid
// precursor to it.
//
// coords is the resolved dependency scope, used only to report the pre-walk
// count; the authoritative module set is the walk's graph.
func auditScope(
	ctx context.Context,
	coords []string,
	scope depScope,
	f auditFlags,
	proxy *proxyadapter.Proxy,
	ctr *Container,
	stderr io.Writer,
) ([]auditModuleResult, error) {
	modulePath, err := readGoModulePath(f.gomodPath)
	if err != nil {
		return nil, err
	}

	wf := commonWalkFlags{goproxy: f.goproxy}
	_, _ = fmt.Fprintf(stderr, "==> audit: walking project %s (%d %s dependencies)\n", f.gomodPath, len(coords), scope)

	progress := newWalkProgressReporter(stderr, false, activeConfig, logLevel)
	if werr := runWalkProject(ctx, f.gomodPath, wf, f.force, true, 0, "", "", f.skipVCSVerify, scope, walkdomain.WalkDepthFull, "", false, progress, ctr.ExecuteWalk, io.Discard, stderr); werr != nil {
		// A partial walk is tolerated (allowPartial=true above): individual
		// unfetchable nodes surface as "(not fetched)" rows. Only a hard walk
		// failure or cancellation leaves no usable record.
		_, _ = fmt.Fprintf(stderr, "walk: %v\n", werr)
	}

	// The project walk's target is the local main module; find its record.
	localCoord := fetchdomain.ModuleCoordinate{Path: modulePath, Version: fetchdomain.LocalVersion}
	walkScope := walkdomain.WalkScope(scope)
	walks, qerr := ctr.QueryWalks.ListWalks(ctx, walkports.WalkFilter{Target: &localCoord, Scope: &walkScope, Limit: 1})
	if qerr != nil {
		return nil, fmt.Errorf("querying project walk: %w", qerr)
	}
	if len(walks) == 0 {
		return nil, fmt.Errorf("project walk produced no record for %s", localCoord)
	}
	walkID := walks[0].ID

	rec, gerr := ctr.QueryWalks.GetWalk(ctx, walkID)
	if gerr != nil {
		return nil, fmt.Errorf("loading project walk %s: %w", walkID, gerr)
	}

	_, _ = fmt.Fprintf(stderr, "==> audit: extracting licenses for walk %s\n", walkID)
	ef := extractFlags{stages: []string{"license"}, force: f.force}
	if eerr := runExtract(ctx, walkID, ef, io.Discard, stderr); eerr != nil {
		_, _ = fmt.Fprintf(stderr, "extract: %v\n", eerr)
	}

	_, _ = fmt.Fprintf(stderr, "==> audit: scanning vulnerabilities for walk %s\n", walkID)
	if verr := runVulnScan(ctx, walkID, commonWalkFlags{}, f.force, f.fresh, false, 1, false, false, "", os.Getenv("USER"), filepath.Dir(f.gomodPath), io.Discard, stderr); verr != nil {
		_, _ = fmt.Fprintf(stderr, "vuln-scan: %v\n", verr)
	}

	overrides, err := ctr.LicenseOverrides.LoadOverrides(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading license overrides: %w", err)
	}

	// Iterate the walk's dependency nodes (every graph node bar the local root):
	// the dependency set is a structural subset of the project walk. Nodes are
	// already sorted (Graph.Sort), so row order is deterministic.
	depNodes := auditDependencyNodes(rec, localCoord)
	results := make([]auditModuleResult, 0, len(depNodes))
	for _, node := range depNodes {
		res, rerr := buildAuditResult(ctx, node.Coordinate.String(), walkID, string(walkScope), overrides, proxy, ctr)
		if rerr != nil {
			return nil, rerr
		}
		res.Direct = node.DirectDependency
		results = append(results, res)
	}
	return results, nil
}

// auditDependencyNodes returns the dependency nodes of a project walk: every
// graph node except the local root (the main module the walk is rooted at).
// Order follows the graph's own node order (already sorted by Graph.Sort), so
// audit rows are deterministic. Both direct and transitive dependencies are
// returned; the scope restriction was applied when the walk was built, so the
// graph already holds exactly the audited module set plus the root.
func auditDependencyNodes(rec walkdomain.WalkRecord, local fetchdomain.ModuleCoordinate) []walkdomain.GraphNode {
	nodes := make([]walkdomain.GraphNode, 0, len(rec.Graph.Nodes))
	for _, node := range rec.Graph.Nodes {
		if node.Coordinate == local {
			continue
		}
		nodes = append(nodes, node)
	}
	return nodes
}

func buildAuditResult(ctx context.Context, coordStr, walkID, scope string, overrides licdomain.LicenseOverrideSet, proxy *proxyadapter.Proxy, ctr *Container) (auditModuleResult, error) {
	coord, err := parseCoordinate(coordStr)
	if err != nil {
		return auditModuleResult{}, fmt.Errorf("invalid coordinate %q: %w", coordStr, err)
	}

	res := auditModuleResult{
		Coordinate:    coordStr,
		Verification:  "(walk failed)",
		License:       "(not run)",
		LicenseStatus: "(not run)",
		VulnStatus:    "(not run)",
		IsLatest:      true,
	}

	if info, lerr := proxy.LatestInfo(ctx, coord.Path); lerr == nil && info.Version != coord.Version {
		res.IsLatest = false
		res.LatestVersion = info.Version
		if !info.Time.IsZero() {
			res.DaysBehind = int(time.Since(info.Time).Hours() / 24)
		}
	}

	if walkID == "" {
		return res, nil
	}

	if frec, found, ferr := ctr.QueryFetch.GetFetchRecord(ctx, coord, fetchapp.PipelineVersion); ferr == nil && found {
		res.Verification = frec.VerificationStatus
	} else if !found {
		res.Verification = "(not fetched)"
	}

	// resolvedSPDX is the SPDX identifier the policy is evaluated against:
	// the detected primary license, overridden by any license_overrides entry
	// for this module path. Empty when nothing was detected.
	var resolvedSPDX string
	// uncertaintyReason records *why* no SPDX was resolved, for the
	// machine-readable license_uncertainty field. Empty once an SPDX is
	// resolved (by the scanner or an override).
	uncertaintyReason := "no_record"
	if lrec, found, lerr := ctr.QueryLicense.GetLicenseRecord(ctx, coord, licapp.PipelineVersion); lerr == nil && found {
		res.License = lrec.PrimarySPDX
		res.LicenseStatus = lrec.OverallStatus.String()
		resolvedSPDX = lrec.PrimarySPDX
		switch lrec.OverallStatus {
		case licdomain.LicenseStatusNone:
			res.License = "(none)"
			uncertaintyReason = "none"
		case licdomain.LicenseStatusMultiple:
			uncertaintyReason = "multiple"
		case licdomain.LicenseStatusExtractionFailed:
			uncertaintyReason = "extraction_failed"
		case licdomain.LicenseStatusCancelled:
			uncertaintyReason = "cancelled"
		}
	} else if !found {
		res.License = "(not run)"
		res.LicenseStatus = "(not run)"
		uncertaintyReason = "no_record"
	}
	// Overrides are consulted after the scanner result and can correct both
	// unknown and positive results; a version-pinned entry beats a
	// module-level one (resolution lives in license/domain).
	if ov, ok := overrides.Resolve(coord); ok {
		resolvedSPDX = ov.SPDX
		res.License = ov.SPDX
		res.LicenseSource = "override"
	} else if res.LicenseStatus != "(not run)" {
		res.LicenseSource = "scanner"
	}

	eval := activeConfig.LicensePolicy.EvaluateLicense(resolvedSPDX, scope)
	res.LicenseCategory = eval.Category
	res.PolicyOutcome = string(eval.Outcome)
	res.LicenseResolved = !eval.Uncertain
	res.PolicyBlocking = eval.Blocking
	if eval.Uncertain {
		res.LicenseUncertainty = uncertaintyReason
	}

	if vrec, found, verr := ctr.QueryVuln.GetLatestRecordForWalk(ctx, coord, vulnPipelineVersion, walkID); verr == nil && found {
		res.VulnStatus = string(vrec.OverallStatus)
		res.VulnFindings = len(vrec.Findings)
		switch vrec.OverallStatus {
		case vulndomain.StatusScanFailed:
			res.VulnReason = vrec.ErrorDetail
		case vulndomain.StatusUnscannable:
			res.VulnReason = vrec.UnscannableReason
		}
	} else if !found {
		res.VulnStatus = "(not scanned)"
	}

	return res, nil
}

// auditBlockingErr returns a non-nil error when any result is a hard
// compliance failure — an undetermined license under a scope whose
// unknown_license policy is "block" — so `audit` exits non-zero for CI
// gating instead of silently passing uncertain dependencies.
// The full result table/JSON is still emitted before this is returned.
func auditBlockingErr(results []auditModuleResult) error {
	var blocked []string
	for _, r := range results {
		if r.PolicyBlocking {
			blocked = append(blocked, r.Coordinate)
		}
	}
	if len(blocked) == 0 {
		return nil
	}
	return &exitError{code: ExitConfig, msg: fmt.Sprintf(
		"license policy: %d dependency(ies) with an undetermined license blocked by policy (unknown_license=block): %s",
		len(blocked), strings.Join(blocked, ", "))}
}

func printAuditTable(stdout io.Writer, results []auditModuleResult) error {
	const colWidth = 55
	showScope := false
	for _, r := range results {
		if r.Scope != "" {
			showScope = true
			break
		}
	}
	for _, r := range results {
		vuln := r.VulnStatus
		if r.VulnFindings > 0 {
			vuln = fmt.Sprintf("%s (%d findings)", r.VulnStatus, r.VulnFindings)
		} else if r.VulnReason != "" {
			// The reason (govulncheck stderr) is multi-line and too wide for
			// the table; direct the reader to vuln-show, which renders it.
			vuln = fmt.Sprintf("%s (see vuln-show)", r.VulnStatus)
		}
		license := r.License
		if r.LicenseSource == "override" {
			license = fmt.Sprintf("%s (override)", r.License)
		} else if r.LicenseStatus != "(not run)" && r.LicenseStatus != "Detected" {
			license = fmt.Sprintf("%s [%s]", r.License, r.LicenseStatus)
		}
		coord := r.Coordinate
		if len(coord) < colWidth {
			coord = fmt.Sprintf("%-*s", colWidth, coord)
		}
		staleness := "current"
		if !r.IsLatest {
			if r.DaysBehind == 0 {
				staleness = fmt.Sprintf("latest: %s (today)", r.LatestVersion)
			} else {
				staleness = fmt.Sprintf("latest: %s (%d days ago)", r.LatestVersion, r.DaysBehind)
			}
		}
		policy := r.PolicyOutcome
		if r.LicenseCategory != "" {
			policy = fmt.Sprintf("%s [%s]", r.PolicyOutcome, r.LicenseCategory)
		}
		// Never let an undetermined license read as a clean verdict: make
		// the uncertainty (and any hard block) explicit in the table.
		if !r.LicenseResolved {
			marker := "UNCERTAIN"
			if r.PolicyBlocking {
				marker = "BLOCKED"
			}
			policy = fmt.Sprintf("%s [%s: %s]", r.PolicyOutcome, marker, r.LicenseUncertainty)
		}
		var err error
		if showScope {
			_, err = fmt.Fprintf(stdout, "%s  %-10s  %-22s  %-30s  %-20s  %-22s  %s\n",
				coord, r.Scope, r.Verification, license, staleness, vuln, policy,
			)
		} else {
			_, err = fmt.Fprintf(stdout, "%s  %-22s  %-30s  %-20s  %-22s  %s\n",
				coord, r.Verification, license, staleness, vuln, policy,
			)
		}
		if err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	}
	return nil
}
