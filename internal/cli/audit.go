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

	"github.com/spf13/cobra"

	proxyadapter "github.com/eitanity/kanonarion/internal/adapters/proxy/direct"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"

	licapp "github.com/eitanity/kanonarion/internal/license/application"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

type auditFlags struct {
	gomodPath       string
	goproxy         string
	force           bool
	fresh           bool
	tool            bool
	project         bool
	skipVCSVerify   bool
	stdlibFromGoMod bool
	fromModcache    string
	policyPath      string
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
	cmd.Flags().StringVar(&f.policyPath, "policy", "", "path to depth policy YAML (default: search for .kanonarion/policy.yaml)")
	registerStdlibFromGoModFlag(cmd, &f.stdlibFromGoMod)
	registerFromModcacheFlag(cmd, &f.fromModcache)
	registerAllowVerificationDowngradeFlag(cmd)

	return cmd
}

type auditModuleResult struct {
	Coordinate    string `json:"coordinate"`
	Scope         string `json:"scope,omitempty"`
	Verification  string `json:"verification"`
	License       string `json:"license"`
	LicenseStatus string `json:"license_status"`
	VulnStatus    string `json:"vuln_status"`
	// VulnFindings counts every advisory the record carries, retracted ones
	// included. Its meaning is deliberately unchanged: narrowing it to live
	// advisories would have altered the number under an existing field name, with
	// the same type and no signal, so a consumer parsing this JSON would silently
	// read a different fact than the one it was written against.
	VulnFindings int `json:"vuln_findings"`
	// VulnWithdrawn counts the retracted subset of VulnFindings; live advisories are
	// the difference. It is a new field, so a consumer that has never heard of it
	// reads exactly what it read before, and one that has can tell a retraction from
	// a finding — which the single tally could not express.
	VulnWithdrawn int `json:"vuln_withdrawn,omitempty"`
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

	// coverage is this module's contribution to the run's verification-coverage
	// aggregate, captured from the same record read that filled Verification.
	// Taking it from the same read is what makes the aggregate equal the rows by
	// construction rather than by a second lookup that could disagree.
	//
	// Unexported deliberately: the aggregate is reported on stderr, and adding a
	// field here would change the documented `audit --json` array element for
	// every consumer to carry a per-row copy of a whole-graph figure.
	coverage fetchdomain.CoverageObservation
}

func runAudit(ctx context.Context, f auditFlags, stdout, stderr io.Writer) error {
	gomodPath, err := resolveGoModPath(f.gomodPath)
	if err != nil {
		return err
	}
	f.gomodPath = gomodPath

	if err := resolveModcacheMode(f.fromModcache, gomodPath); err != nil {
		return err
	}
	// On the normal network path, layer the project go.sum on as an always-on
	// offline integrity check. No-op in --from-modcache mode.
	resolveProjectGoSum(gomodPath)

	scope, err := scopeFromFlags(f.tool, f.project)
	if err != nil {
		return err
	}
	coords, err := resolveScopeModules(f.gomodPath, scope)
	if err != nil {
		return fmt.Errorf("resolving %s scope: %w", scope, err)
	}
	// An empty scope is a valid answer, not an error, and it is answered on
	// the caller's own channel: an empty array under --json, prose only on the
	// text path. Answered here, before the store and proxy are opened, because
	// there is nothing to audit either way.
	if len(coords) == 0 {
		if jsonOut {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode([]auditModuleResult{}); err != nil {
				return fmt.Errorf("encoding results: %w", err)
			}
			return nil
		}
		_, _ = fmt.Fprintf(stdout, "no %s dependencies found in %s\n", scope, f.gomodPath)
		return nil
	}

	logger := buildLogger(logLevel, stderr)
	ctr, cleanup, err := NewContainer(storeRoot, f.goproxy, "", f.skipVCSVerify, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() { _ = cleanup() }()

	// The staleness column consults the network proxy for each module's latest
	// version. In --from-modcache mode the run is fully offline, so the proxy is
	// left nil and staleness is reported as "current".
	var proxy *proxyadapter.Proxy
	if !modcacheMode {
		proxy, err = proxyadapter.New(f.goproxy, false)
		if err != nil {
			return fmt.Errorf("creating proxy adapter: %w", err)
		}
	}

	results, err := auditScope(ctx, coords, scope, f, proxy, ctr, stderr)
	if err != nil {
		return err
	}

	// The aggregate goes to stderr on both paths: a whole-graph collapse in
	// cross-verification is invisible in a populated status column, and stdout
	// is the data channel --json callers pipe into jq.
	if cerr := writeVerificationCoverage(stderr, auditVerificationCoverage(results)); cerr != nil {
		return cerr
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

	_, _ = fmt.Fprintf(stderr, "==> audit: walking project %s (%d %s dependencies)\n", f.gomodPath, len(coords), scope)

	progress := newWalkProgressReporter(stderr, false, activeConfig, logLevel)
	if werr := runWalkProject(ctx, f.gomodPath, f.force, true, 0, "", f.policyPath, f.skipVCSVerify, scope,
		walkdomain.WalkDepthFull, "", false, f.stdlibFromGoMod, progress, ctr.ExecuteWalk, nil, io.Discard, stderr); werr != nil {
		// A partial walk is tolerated (allowPartial=true above): individual
		// unfetchable nodes surface as "(not fetched)" rows. Only a hard walk
		// failure or cancellation leaves no usable record.
		_, _ = fmt.Fprintf(stderr, "walk: %v\n", werr)
	}

	// The project walk's target is the local main module; find its record.
	localCoord, cErr := coordinate.NewLocalCoordinate(modulePath)
	if cErr != nil {
		return nil, fmt.Errorf("project coordinate for %s: %w", modulePath, cErr)
	}
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

	// In --from-modcache mode a module that fails go.sum verification is a hard
	// error: stop before extract/scan and exit non-zero rather than reporting a
	// row for it.
	if gateErr := modcacheWalkGate(rec, localCoord); gateErr != nil {
		return nil, gateErr
	}
	// On the normal path, a local go.sum mismatch is tamper-evidence: fail hard
	// before extract/scan rather than reporting a row for the tampered module.
	if gateErr := goSumWalkGate(rec, localCoord); gateErr != nil {
		return nil, gateErr
	}

	_, _ = fmt.Fprintf(stderr, "==> audit: extracting licenses for walk %s\n", walkID)
	ef := extractFlags{stages: []string{"license"}, force: f.force}
	if eerr := runExtract(ctx, walkID, ef, io.Discard, stderr); eerr != nil {
		_, _ = fmt.Fprintf(stderr, "extract: %v\n", eerr)
	}

	_, _ = fmt.Fprintf(stderr, "==> audit: scanning vulnerabilities for walk %s\n", walkID)
	if verr := runVulnScan(ctx, walkID, f.force, f.fresh, false, 1, false, false, "", os.Getenv("USER"), filepath.Dir(f.gomodPath), f.policyPath, false, io.Discard, stderr); verr != nil {
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
		res, rerr := buildAuditResult(ctx, node, walkID, string(walkScope), overrides, proxy, ctr)
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
func auditDependencyNodes(rec walkdomain.WalkRecord, local coordinate.ModuleCoordinate) []walkdomain.GraphNode {
	nodes := make([]walkdomain.GraphNode, 0, len(rec.Graph.Nodes))
	for _, node := range rec.Graph.Nodes {
		if node.Coordinate == local {
			continue
		}
		nodes = append(nodes, node)
	}
	return nodes
}

func buildAuditResult(ctx context.Context, node walkdomain.GraphNode, walkID, scope string, overrides licdomain.LicenseOverrideSet, proxy *proxyadapter.Proxy, ctr *Container) (auditModuleResult, error) {
	coordStr := node.Coordinate.String()
	coord, err := parseCoordinate(coordStr)
	if err != nil {
		return auditModuleResult{}, fmt.Errorf("invalid coordinate %q: %w", coordStr, err)
	}

	// The standard library is toolchain-provided, not a proxy artefact: it has no
	// fetch/licence/vuln records to look up and no proxy "latest" to compare
	// against. Its custody chain (verification status, extracted licence) rides on
	// the graph node, so it is reported from there rather than the record stores.
	if node.ResolutionSource == walkdomain.ResolutionStdlib {
		return buildStdlibAuditResult(ctx, coord, node, scope, walkID, ctr), nil
	}

	res := auditModuleResult{
		Coordinate:    coordStr,
		Verification:  "(walk failed)",
		License:       "(not run)",
		LicenseStatus: "(not run)",
		VulnStatus:    "(not run)",
		IsLatest:      true,
	}

	if proxy != nil {
		if info, lerr := proxy.LatestInfo(ctx, coord.Path()); lerr == nil && info.Version != coord.Version() {
			res.IsLatest = false
			res.LatestVersion = info.Version
			if !info.Time.IsZero() {
				res.DaysBehind = int(time.Since(info.Time).Hours() / 24)
			}
		}
	}

	if walkID == "" {
		return res, nil
	}

	if frec, found, ferr := ctr.QueryFetch.ComposeFetchRecord(ctx, coord); ferr == nil && found {
		res.Verification = frec.VerificationStatus
		res.coverage = fetchdomain.CoverageObservation{
			Bucket:   fetchdomain.BucketForVerification(fetchdomain.VerificationStatus(frec.VerificationStatus)),
			Legs:     frec.Legs,
			Recorded: true,
		}
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

	vrec, found, verr := ctr.QueryVuln.GetLatestRecordForWalk(ctx, coord, vulnPipelineVersion, walkID)
	res.VulnStatus, res.VulnReason, res.VulnFindings, res.VulnWithdrawn = vulnAuditStatus(vrec, found, verr)

	return res, nil
}

// vulnAuditStatus renders the vulnerability columns of an audit row from a
// record lookup: the status, the reason prose, and the finding count.
//
// A read error is reported as a read error. Previously an errored lookup either
// fell into the not-found branch and rendered "(not scanned)" — telling the
// operator the module was never scanned when in truth the store could not be
// read — or, when a record came back alongside the error, left the column blank
// with nothing said at all. Absence and unreadability are different facts about
// a module, and only one of them is a reason to stop asking.
//
// A record returned alongside an error is not trusted: the error is the more
// reliable of the two signals, so the row names the failure rather than
// reporting a status derived from a value the store could not vouch for.
//
// Both audit paths share this so they cannot drift into disagreeing about the
// same condition, which is how one of them came to have no error branch at all.
// findings counts every advisory on the record and withdrawn counts the retracted
// subset of it, so the live count is the difference. Reporting only the total made
// the row read "Withdrawn (1 findings)" — a finding asserted and denied in one
// line — while narrowing the total instead would have changed what an existing
// field means without saying so.
func vulnAuditStatus(rec vulndomain.VulnerabilityRecord, found bool, err error) (status, reason string, findings, withdrawn int) {
	if err != nil {
		return "(scan record unreadable)", "reading vulnerability record: " + err.Error(), 0, 0
	}
	if !found {
		return "(not scanned)", "", 0, 0
	}
	// Which diagnostic explains the row is a coverage question, so it is asked of
	// the coverage axis. The collapsed word cannot answer it: a metadata-only
	// record that matched an advisory summarises as Affected, so its coverage gap
	// went unexplained here while the findings count reported the match.
	coverage, _ := vulndomain.RecordAxes(rec)
	switch coverage {
	case vulndomain.CoverageFailedScan:
		reason = rec.ErrorDetail
	case vulndomain.CoverageUnscannable:
		reason = rec.UnscannableReason
	case vulndomain.CoverageAnalysed:
		// Analysed: the status word stands on its own, no caveat to explain.
	}
	for _, f := range rec.Findings {
		if f.IsWithdrawn() {
			withdrawn++
		}
	}
	return string(rec.OverallStatus), reason, len(rec.Findings), withdrawn
}

// buildStdlibAuditResult reports the standard-library node's custody chain from
// the facts carried on the graph node: the go.dev/dl verification status and the
// licence extracted from the source tarball, with the licence policy evaluated
// against that SPDX. It still consults the vuln store — the stdlib node exists so
// standard-library advisories are scanned — but skips the fetch/licence record
// lookups and the proxy staleness check, which do not apply to a toolchain
// artefact. A nil Stdlib (an offline walk that could not acquire the chain)
// degrades to "(custody unavailable)" rather than an error.
func buildStdlibAuditResult(ctx context.Context, coord coordinate.ModuleCoordinate, node walkdomain.GraphNode, scope, walkID string, ctr *Container) auditModuleResult {
	res := auditModuleResult{
		Coordinate:    coord.String(),
		Verification:  "(custody unavailable)",
		License:       "(not run)",
		LicenseStatus: "(not run)",
		VulnStatus:    "(not scanned)",
		IsLatest:      true, // pinned to the build toolchain; no proxy "latest" applies
	}

	var resolvedSPDX string
	uncertaintyReason := "no_record"
	if node.Stdlib != nil {
		if node.Stdlib.VerificationStatus != "" {
			res.Verification = node.Stdlib.VerificationStatus
			// The stdlib's custody rides on the graph node, not a fetch record,
			// and it carries no validation legs — so it reports as measured for
			// the status buckets and as not-measured for the ledger, which is
			// exactly what it is.
			res.coverage = stdlibCoverageObservation(node)
		}
		res.LicenseSource = "stdlib-tarball"
		if node.Stdlib.LicenseSPDX != "" {
			res.License = node.Stdlib.LicenseSPDX
			res.LicenseStatus = "Detected"
			resolvedSPDX = node.Stdlib.LicenseSPDX
			uncertaintyReason = ""
		}
	}

	eval := activeConfig.LicensePolicy.EvaluateLicense(resolvedSPDX, scope)
	res.LicenseCategory = eval.Category
	res.PolicyOutcome = string(eval.Outcome)
	res.LicenseResolved = !eval.Uncertain
	res.PolicyBlocking = eval.Blocking
	if eval.Uncertain {
		res.LicenseUncertainty = uncertaintyReason
	}

	vrec, found, verr := ctr.QueryVuln.GetLatestRecordForWalk(ctx, coord, vulnPipelineVersion, walkID)
	res.VulnStatus, res.VulnReason, res.VulnFindings, res.VulnWithdrawn = vulnAuditStatus(vrec, found, verr)
	return res
}

// auditVerificationCoverage aggregates the run's own rows. It reads the
// observations captured alongside each row's Verification column rather than
// consulting the store again, so the acceptance the ticket asks for — that the
// counts equal the per-module statuses in the same run — holds by construction
// instead of by two reads agreeing.
func auditVerificationCoverage(results []auditModuleResult) fetchdomain.VerificationCoverage {
	obs := make([]fetchdomain.CoverageObservation, 0, len(results))
	for _, r := range results {
		obs = append(obs, r.coverage)
	}
	return fetchdomain.VerificationCoverageOf(obs)
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
		// live is the difference, because VulnFindings counts the retracted ones too.
		live := r.VulnFindings - r.VulnWithdrawn
		switch {
		case live > 0 && r.VulnWithdrawn > 0:
			vuln = fmt.Sprintf("%s (%d findings, %d retracted)", r.VulnStatus, live, r.VulnWithdrawn)
		case live > 0:
			vuln = fmt.Sprintf("%s (%d findings)", r.VulnStatus, live)
		case r.VulnWithdrawn > 0:
			// Named as retracted, never as findings: the count column sits beside a
			// Withdrawn status word, and "1 findings" there contradicts it.
			vuln = fmt.Sprintf("%s (%d retracted)", r.VulnStatus, r.VulnWithdrawn)
		case r.VulnReason != "":
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
