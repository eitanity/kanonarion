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
	configdomain "github.com/eitanity/kanonarion/internal/config/domain"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	staleapp "github.com/eitanity/kanonarion/internal/staleness/application"

	licapp "github.com/eitanity/kanonarion/internal/license/application"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
	vulnapp "github.com/eitanity/kanonarion/internal/vuln/application"
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
	noProgress      bool
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
+ tooling).

Exit codes:
  0  every dependency resolved and no licence-policy block
  5  the governance gate fired: dependencies with an undetermined licence are
     blocked by policy (unknown_license=block), or the licence gate could not
     be evaluated because the policy scope in force matches no license_policy
     rule — the table is still printed either way
  10 a walk node failed its integrity check
  20 bad invocation, unresolvable go.mod, or a policy file that could not be read`,
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
	cmd.Flags().BoolVar(&f.fresh, "fresh", false, "refresh the vulnerability advisory database: download a new snapshot only if an advisory listed for a module in this walk has changed")
	cmd.Flags().BoolVar(&f.tool, "tool", false, "scope to the tooling supply chain (the go.mod tool directives' closure)")
	cmd.Flags().BoolVar(&f.project, "project", false, "scope to the complete set: the project's code AND tooling")
	cmd.Flags().BoolVar(&f.skipVCSVerify, "skip-vcs-verify", false, "skip git cross-verification; sumdb verification still runs")
	cmd.Flags().StringVar(&f.policyPath, "policy", "", "path to depth policy YAML (default: search for .kanonarion/policy.yaml)")
	registerStdlibFromGoModFlag(cmd, &f.stdlibFromGoMod)
	registerFromModcacheFlag(cmd, &f.fromModcache)
	registerAllowVerificationDowngradeFlag(cmd)
	registerNoProgressFlag(cmd, &f.noProgress)

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
	// LicenseElectableArms names the arms of a dual-licence disjunction that
	// carry the reported policy_outcome — the licences a consumer may elect
	// between to obtain it. Information, not an open item: the outcome already
	// stands on the most favourable arm, and the row is not blocking for want
	// of a recorded election.
	LicenseElectableArms []string `json:"license_electable_arms,omitempty"`
	// PolicyBlocking is true when this result is a hard compliance failure:
	// an uncertain licence under scope unknown_license = block, or a policy
	// scope no rule covers (unevaluated); `audit` exits non-zero when any
	// result is blocking.
	PolicyBlocking bool `json:"policy_blocking,omitempty"`
	// PolicyUnevaluated is true when the policy scope in force matched no
	// license_policy rule: the gate evaluated nothing for this row, which is
	// reported and blocking — never an implicit allow.
	PolicyUnevaluated bool   `json:"policy_unevaluated,omitempty"`
	IsLatest          bool   `json:"is_latest"`
	LatestVersion     string `json:"latest_version,omitempty"`
	// LatestReleaseAgeDays is how long ago the LATEST release shipped, not how
	// far behind the pin is. It replaces the `days_behind` key, which named a
	// quantity the value never held: the number is the age of the newest release,
	// so an eighteen-month-old pin on an actively released module reported a
	// smaller figure than a current pin on a quiet one. See latestResult in
	// latest.go for why the genuine pin-to-latest distance is not emitted at all
	// rather than approximated.
	LatestReleaseAgeDays int `json:"latest_release_age_days,omitempty"`
	// NewerMajorModule/NewerMajorLatest are the SEPARATE major-line fact: a
	// module's next major version lives at a different path, so IsLatest — which
	// is about this path — can be true while a whole major line is available.
	// The two are never merged.
	NewerMajorModule string `json:"newer_major_module,omitempty"`
	NewerMajorLatest string `json:"newer_major_latest,omitempty"`
	// MajorProbed separates "probed, none newer" from "not probed" (offline
	// runs, or a probe whose request failed).
	MajorProbed bool `json:"major_probed"`
	// StalenessLookedUpAt is when the proxy was asked for this row's staleness.
	// A row served from the ledger carries the original lookup time.
	StalenessLookedUpAt time.Time `json:"staleness_looked_up_at,omitzero"`
	// Direct is true when this module is a direct dependency in the audited
	// go.mod. The report covers the whole scoped build list, so transitive
	// modules (Direct=false) appear alongside direct ones and the
	// compliance picture spans the full closure, not just the require lines.
	Direct bool `json:"direct"`

	// policyScope and policyRuleScopes carry the evaluation's scope facts for
	// the unevaluated diagnostic (which scope was in force, which scopes have
	// rules). Unexported: the JSON row already names the condition via
	// PolicyUnevaluated, and these feed the human-readable remedy only.
	policyScope      string
	policyRuleScopes []string

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
	var staleness *staleapp.Resolver
	if !modcacheMode {
		proxy, perr := proxyadapter.New(f.goproxy, false)
		if perr != nil {
			return fmt.Errorf("creating proxy adapter: %w", perr)
		}
		// The same ledger `latest` writes. Every successful lookup either
		// command makes is served to the other inside the TTL, which is the
		// whole point: the two commands were re-paying the same sweep minutes
		// apart.
		staleness = newAuditStalenessResolver(newProxyLatestResolver(proxy), ctr.StalenessLedger, activeConfig.Staleness.TTL)
	}

	results, derivation, err := auditScope(ctx, coords, scope, f, staleness, ctr, stderr)
	if err != nil {
		return err
	}

	// Where the answer came from, before the answer itself. On stderr for the
	// same reason the coverage aggregate is: a --json caller pipes stdout into
	// jq, and a statement about the run is not one of the run's rows.
	if derr := writeAuditDerivation(stderr, derivation); derr != nil {
		return derr
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

// auditDerivation records where an audit's two expensive answers came from: the
// walk that fixed the dependency set, and the vulnerability scan judged against
// it. It exists so the report can say which parts of the answer were measured by
// this invocation and which were served from records, because a reader cannot
// otherwise tell a fresh measurement from a stored one — and the two carry
// different weight in exactly the cases (release evidence, incident response)
// where the distinction decides what the answer is worth.
type auditDerivation struct {
	walkReused bool
	walkRecord walkdomain.WalkRecord
	scanReused bool
	scanRun    vulndomain.WalkScanRun
	// refreshed is set when --fresh made this run check the advisory database;
	// refresh is what that check established. Without the flag the run reads the
	// stored database and the derivation says nothing about a check it never made.
	refreshed bool
	refresh   vulnapp.SnapshotRefresh
	// refreshErr is the refresh's own failure, when the database could not be
	// brought up to date at all. The audit continues against the stored database;
	// the statement is what stops that reading as a checked one.
	refreshErr error
}

// writeAuditDerivation states the provenance of the run's two derived answers.
//
// Reuse is named with the record it served and the date that record was made, so
// the statement is checkable; a re-derivation names what it produced. The walk
// line says "re-resolved" even when reused, because that is what happened: the
// go.mod was resolved again and the resolution turned out to be identical to a
// stored one. Calling that "skipped" would claim less work than was done, and
// calling it "fresh" would claim a new record exists when none was written.
func writeAuditDerivation(w io.Writer, d auditDerivation) error {
	walkLine := fmt.Sprintf("walk %s: derived by this run", d.walkRecord.ID)
	if d.walkReused {
		walkLine = fmt.Sprintf("walk %s: re-resolved and found identical to the walk taken %s; that record was reused",
			d.walkRecord.ID, d.walkRecord.CompletedAt.UTC().Format(time.RFC3339))
	}

	scanLine := "vulnerability scan: derived by this run"
	if d.scanReused {
		scanLine = fmt.Sprintf("vulnerability scan: reused run %s of %s against snapshot %s@%s; nothing was re-scanned (--force to re-measure)",
			d.scanRun.ID, d.scanRun.CompletedAt.UTC().Format(time.RFC3339),
			d.scanRun.Snapshot.Source(), d.scanRun.Snapshot.Version())
	}

	lines := []string{walkLine}
	if d.refreshed {
		lines = append(lines, advisoryRefreshLine(d.refresh, d.refreshErr))
	}
	lines = append(lines, scanLine)

	if _, err := fmt.Fprintf(w, "derivation:\n  %s\n", strings.Join(lines, "\n  ")); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	return nil
}

// walkScopeFor maps a CLI depScope to the walk-record WalkScope tag. The string
// values are identical, so this is a direct conversion documented for clarity.
func walkScopeFor(s depScope) walkdomain.WalkScope { return walkdomain.WalkScope(s) }

// policyScopeForWalkScope translates a walk scope onto the policy scope whose
// license_policy rule governs it. The two vocabularies are distinct: walk
// scopes name dependency sets (code / tool / complete), policy scopes name
// rule domains (production / tool), and only "tool" appears in both. Passing a
// walk scope straight through meant the default scope ("code") matched no rule
// and every licence resolved to an implicit allow — the gate never fired on
// the command operators actually run. code and complete are production
// dependency sets (modules linked into, or spanning, the shipped binary), so
// both normalise to production. The translation lives here at the boundary
// deliberately: the shipped config's two-scope vocabulary is the intended one
// and must not grow walk-scope mirror rules.
func policyScopeForWalkScope(s walkdomain.WalkScope) string {
	switch s {
	case walkdomain.WalkScopeCode, walkdomain.WalkScopeComplete:
		return "production"
	case walkdomain.WalkScopeTool:
		return "tool"
	}
	// Unknown walk scope: pass through and let the policy engine's
	// unmatched-scope guard report the gate as unevaluated rather than
	// guessing a rule domain here.
	return string(s)
}

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
	staleness *staleapp.Resolver,
	ctr *Container,
	stderr io.Writer,
) ([]auditModuleResult, auditDerivation, error) {
	var derivation auditDerivation
	modulePath, err := readGoModulePath(f.gomodPath)
	if err != nil {
		return nil, derivation, err
	}

	// audit narrates three stages on stderr and drives a walk and a scan that
	// narrate per module beneath them. All of it is progress, and all of it goes
	// to progressOut, which --no-progress silences. The stage failures below keep
	// writing to stderr: a silenced audit still reports that the walk or the scan
	// went wrong, because those are not progress.
	progressOut := progressWriter(stderr, f.noProgress)
	_, _ = fmt.Fprintf(progressOut, "==> audit: walking project %s (%d %s dependencies)\n", f.gomodPath, len(coords), scope)

	progress := newWalkProgressReporter(stderr, f.noProgress, activeConfig, logLevel)
	walkResult, werr := runWalkProject(ctx, f.gomodPath, f.force, true, 0, "", f.policyPath, f.skipVCSVerify, scope,
		walkdomain.WalkDepthFull, "", false, f.stdlibFromGoMod, progress, ctr.ExecuteWalk, nil, io.Discard, stderr)
	if werr != nil {
		// A partial walk is tolerated (allowPartial=true above): individual
		// unfetchable nodes surface as "(not fetched)" rows. Only a hard walk
		// failure or cancellation leaves no usable record.
		_, _ = fmt.Fprintf(stderr, "walk: %v\n", werr)
	}
	derivation.walkReused = walkResult.Reused
	derivation.walkRecord = walkResult.Record

	// The project walk's target is the local main module; find its record.
	localCoord, cErr := coordinate.NewLocalCoordinate(modulePath)
	if cErr != nil {
		return nil, derivation, fmt.Errorf("project coordinate for %s: %w", modulePath, cErr)
	}
	walkScope := walkdomain.WalkScope(scope)
	walks, qerr := ctr.QueryWalks.ListWalks(ctx, walkports.WalkFilter{Target: &localCoord, Scope: &walkScope, Limit: 1})
	if qerr != nil {
		return nil, derivation, fmt.Errorf("querying project walk: %w", qerr)
	}
	if len(walks) == 0 {
		return nil, derivation, fmt.Errorf("project walk produced no record for %s", localCoord)
	}
	walkID := walks[0].ID

	rec, gerr := ctr.QueryWalks.GetWalk(ctx, walkID)
	if gerr != nil {
		return nil, derivation, fmt.Errorf("loading project walk %s: %w", walkID, gerr)
	}

	// In --from-modcache mode a module that fails go.sum verification is a hard
	// error: stop before extract/scan and exit non-zero rather than reporting a
	// row for it.
	if gateErr := modcacheWalkGate(rec, localCoord); gateErr != nil {
		return nil, derivation, gateErr
	}
	// On the normal path, a local go.sum mismatch is tamper-evidence: fail hard
	// before extract/scan rather than reporting a row for the tampered module.
	if gateErr := goSumWalkGate(rec, localCoord); gateErr != nil {
		return nil, derivation, gateErr
	}

	_, _ = fmt.Fprintf(progressOut, "==> audit: extracting licenses for walk %s\n", walkID)
	ef := extractFlags{stages: []string{"license"}, force: f.force, noProgress: f.noProgress}
	if eerr := runExtract(ctx, walkID, ef, io.Discard, stderr); eerr != nil {
		_, _ = fmt.Fprintf(stderr, "extract: %v\n", eerr)
	}

	// The refresh happens before the reuse question is asked, because it decides
	// what that question is asked against: a refresh that downloads a new
	// database makes the stored run unreusable, and one that keeps the stored
	// snapshot — because the database has not moved, or has not moved for
	// anything this walk is judged on — leaves it answering. A failed refresh is
	// reported and the audit continues against the stored database rather than
	// losing the whole report.
	if f.fresh {
		_, _ = fmt.Fprintf(progressOut, "==> audit: refreshing the advisory database\n")
		derivation.refreshed = true
		refresh, frerr := ctr.ScanWalk.RefreshSnapshot(ctx, walkID)
		if frerr != nil {
			derivation.refreshErr = frerr
		} else {
			derivation.refresh = refresh
		}
	}

	// Asked before the scan is driven so the derivation statement can name the
	// run that answered, and answered with the same lookup the scan itself makes:
	// audit narrates the whole derivation in one place, so runVulnScan is told not
	// to announce the reuse a second time.
	if prior, ok, rerr := ctr.ScanWalk.ReusableRun(ctx, walkID); rerr != nil {
		_, _ = fmt.Fprintf(stderr, "vuln-scan: %v\n", rerr)
	} else if ok && !f.force {
		derivation.scanReused = true
		derivation.scanRun = prior
	}

	// fresh=false: the refresh above already happened, and the snapshot it
	// settled on is the stored one the scan now resolves. Passing the flag on
	// would check the database a second time in the same invocation.
	_, _ = fmt.Fprintf(progressOut, "==> audit: scanning vulnerabilities for walk %s\n", walkID)
	if verr := runVulnScan(ctx, walkID, f.force, false, false, 1, false, false, "", os.Getenv("USER"), filepath.Dir(f.gomodPath), f.policyPath, false, f.noProgress, false, io.Discard, stderr); verr != nil {
		_, _ = fmt.Fprintf(stderr, "vuln-scan: %v\n", verr)
	}

	overrides, err := ctr.LicenseOverrides.LoadOverrides(ctx)
	if err != nil {
		return nil, derivation, fmt.Errorf("loading license overrides: %w", err)
	}

	// Iterate the walk's dependency nodes (every graph node bar the local root):
	// the dependency set is a structural subset of the project walk. Nodes are
	// already sorted (Graph.Sort), so row order is deterministic.
	depNodes := auditDependencyNodes(rec, localCoord)
	results := make([]auditModuleResult, 0, len(depNodes))
	// The walk scope names a dependency set; the licence policy speaks in
	// policy scopes. Translate once here so every row is evaluated under the
	// rule domain that governs it rather than under a scope no rule matches.
	policyScope := policyScopeForWalkScope(walkScope)
	for _, node := range depNodes {
		res, rerr := buildAuditResult(ctx, node, walkID, policyScope, overrides, staleness, ctr, stderr)
		if rerr != nil {
			return nil, derivation, rerr
		}
		res.Direct = node.DirectDependency
		results = append(results, res)
	}
	return results, derivation, nil
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

// buildAuditResult builds one audit row. policyScope is the licence-policy
// scope (production/tool) the row's licence is evaluated under — already
// translated from the walk scope by the caller.
func buildAuditResult(ctx context.Context, node walkdomain.GraphNode, walkID, policyScope string, overrides licdomain.LicenseOverrideSet, staleness *staleapp.Resolver, ctr *Container, stderr io.Writer) (auditModuleResult, error) {
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
		return buildStdlibAuditResult(ctx, coord, node, policyScope, walkID, ctr), nil
	}

	res := auditModuleResult{
		Coordinate:    coordStr,
		Verification:  "(walk failed)",
		License:       "(not run)",
		LicenseStatus: "(not run)",
		VulnStatus:    "(not run)",
		IsLatest:      true,
	}

	if staleness != nil {
		ans, lerr := staleness.Resolve(ctx, coord.Path(), coord.Version())
		if lerr != nil {
			// Reported, never swallowed: a module whose staleness could not be
			// resolved keeps MajorProbed false and IsLatest true-by-default, and
			// the reader is told which one it was.
			_, _ = fmt.Fprintf(stderr, "staleness %s: %v\n", coord.Path(), lerr)
		}
		if ans.LatestVersion != "" {
			res.StalenessLookedUpAt = ans.LookedUpAt
			// The release age is a fact about the release, so it is recorded
			// whether or not the pin is current; only LatestVersion, which names a
			// version the project is not on, is gated on the pin being behind.
			res.LatestReleaseAgeDays = latestReleaseAgeDays(ans.LatestPublishedAt)
			if ans.LatestVersion != coord.Version() {
				res.IsLatest = false
				res.LatestVersion = ans.LatestVersion
			}
			res.MajorProbed = ans.NewerMajor.Probed
			res.NewerMajorModule = ans.NewerMajor.Path
			res.NewerMajorLatest = ans.NewerMajor.Version
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

	lrec, lfound, lerr := ctr.QueryLicense.GetLicenseRecord(ctx, coord, licapp.PipelineVersion)
	var resolvedSPDX, uncertaintyReason string
	var arms []string
	res.License, res.LicenseStatus, resolvedSPDX, uncertaintyReason, arms = auditLicenceResolution(lrec, lfound, lerr, res.License, res.LicenseStatus)
	// Overrides are consulted after the scanner result and can correct both
	// unknown and positive results; a version-pinned entry beats a
	// module-level one (resolution lives in license/domain). An override also
	// settles a disjunction wholesale — the recorded election replaces the
	// arms, so the row is evaluated under that one licence.
	if ov, ok := overrides.Resolve(coord); ok {
		resolvedSPDX = ov.SPDX
		res.License = ov.SPDX
		res.LicenseSource = "override"
		arms = nil
	} else if res.LicenseStatus != "(not run)" {
		res.LicenseSource = "scanner"
	}

	eval := activeConfig.LicensePolicy.EvaluateLicense(resolvedSPDX, policyScope)
	if len(arms) > 0 {
		eval = activeConfig.LicensePolicy.EvaluateDisjunction(arms, policyScope)
	}
	applyPolicyEvaluation(&res, eval, uncertaintyReason)

	vrec, found, verr := ctr.QueryVuln.GetLatestRecordForWalk(ctx, coord, vulnPipelineVersion, walkID)
	res.VulnStatus, res.VulnReason, res.VulnFindings, res.VulnWithdrawn = vulnAuditStatus(vrec, found, verr)

	return res, nil
}

// auditLicenceResolution derives an audit row's licence columns from a licence
// record lookup: the display licence and status, the SPDX the policy is
// evaluated against, the machine-readable uncertainty reason (meaningful only
// when no SPDX resolves), and the electable arms when the record carries a
// resolved disjunction. displayIn/statusIn are the row's current placeholders,
// kept when the lookup errs.
//
// A Multiple status splits in two. When the record's expression is a pure OR of
// identified licences, the module offers the consumer a choice: the arms are
// returned and the caller evaluates the policy per arm, taking the most
// favourable — a choice between allowed licences is not an uncertainty, and
// routing it through the unknown-licence machinery ranked it below a determined
// strong-copyleft licence the same rule merely warns on. Recording the election
// as a license_overrides entry still settles the row, but its absence gates
// nothing.
//
// When the expression names a single identifier, that identifier is the
// resolution: a module whose one licence file bundles third-party texts is
// reported Multiple, and its derived expression is still its own licence.
//
// A Multiple whose expression yields neither (a conjunction, or candidates that
// could not be identified) resolves NO SPDX: detection did not settle on any
// licence identity, so it stays an open item and rides the unknown-licence
// machinery (uncertain, and blocking where the scope blocks unknowns) until an
// override settles it. Overrides are consulted by the caller after this.
func auditLicenceResolution(lrec licdomain.LicenseRecord, found bool, lerr error, displayIn, statusIn string) (display, status, resolvedSPDX, uncertaintyReason string, arms []string) {
	display, status = displayIn, statusIn
	uncertaintyReason = "no_record"
	switch {
	case lerr == nil && found:
		display = lrec.PrimarySPDX
		status = lrec.OverallStatus.String()
		resolvedSPDX = lrec.PrimarySPDX
		switch lrec.OverallStatus {
		case licdomain.LicenseStatusNone:
			display = "(none)"
			uncertaintyReason = "none"
		case licdomain.LicenseStatusMultiple:
			resolvedSPDX = ""
			uncertaintyReason = "multiple"
			arms = licdomain.DisjunctionArms(lrec.Expression)
			// The expression is the licence identity detection settled on, and
			// Multiple describes how it got there, not that it failed. A pure
			// disjunction is handed to the caller as arms; an expression naming
			// one identifier — the omnibus-attribution case, where a single
			// LICENSE file bundles third-party texts and the derived expression
			// is the module's own licence — resolves to that identifier.
			// Anything else (a conjunction, or candidates that named nothing)
			// resolves nothing and keeps riding the unknown-licence machinery.
			if len(arms) == 0 {
				resolvedSPDX = licdomain.SoleIdentifier(lrec.Expression)
			}
		case licdomain.LicenseStatusExtractionFailed:
			uncertaintyReason = "extraction_failed"
		case licdomain.LicenseStatusCancelled:
			uncertaintyReason = "cancelled"
		}
	case lerr == nil:
		display = "(not run)"
		status = "(not run)"
	}
	return display, status, resolvedSPDX, uncertaintyReason, arms
}

// applyPolicyEvaluation copies a policy evaluation onto an audit row. Shared by
// the module and stdlib row builders so the two cannot drift in how they
// surface uncertainty or an unevaluated gate.
func applyPolicyEvaluation(res *auditModuleResult, eval configdomain.PolicyEvaluation, uncertaintyReason string) {
	res.LicenseCategory = eval.Category
	res.PolicyOutcome = string(eval.Outcome)
	res.LicenseResolved = !eval.Uncertain
	res.PolicyBlocking = eval.Blocking
	res.PolicyUnevaluated = eval.Unevaluated
	res.policyScope = eval.Scope
	res.policyRuleScopes = eval.RuleScopes
	res.LicenseElectableArms = eval.ElectableArms
	if eval.Uncertain {
		res.LicenseUncertainty = uncertaintyReason
	}
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
// licence resolved by walkdomain.StdlibLicense — the tarball-extracted SPDX
// when facts are present, the published BSD-3-Clause constant when they are
// not — with the licence policy evaluated against that SPDX. The constant is
// the same answer the SBOM and license-compat give for the same node, and the
// row says which of the two answered: LicenseSource "stdlib-tarball" relays
// extracted evidence, "stdlib-known" relays published knowledge, and the
// custody gap itself stays visible in the Verification column's
// "(custody unavailable)". It still consults the vuln store — the stdlib node
// exists so standard-library advisories are scanned — but skips the
// fetch/licence record lookups and the proxy staleness check, which do not
// apply to a toolchain artefact.
func buildStdlibAuditResult(ctx context.Context, coord coordinate.ModuleCoordinate, node walkdomain.GraphNode, policyScope, walkID string, ctr *Container) auditModuleResult {
	res := auditModuleResult{
		Coordinate:   coord.String(),
		Verification: "(custody unavailable)",
		VulnStatus:   "(not scanned)",
		IsLatest:     true, // pinned to the build toolchain; no proxy "latest" applies
	}

	if node.Stdlib != nil && node.Stdlib.VerificationStatus != "" {
		res.Verification = node.Stdlib.VerificationStatus
		// The stdlib's custody rides on the graph node, not a fetch record,
		// and it carries no validation legs — so it reports as measured for
		// the status buckets and as not-measured for the ledger, which is
		// exactly what it is.
		res.coverage = stdlibCoverageObservation(node)
	}

	resolvedSPDX, fromFacts := walkdomain.StdlibLicense(node.Stdlib)
	res.License = resolvedSPDX
	if fromFacts {
		res.LicenseStatus = "Detected"
		res.LicenseSource = "stdlib-tarball"
	} else {
		res.LicenseStatus = "Known"
		res.LicenseSource = "stdlib-known"
	}

	eval := activeConfig.LicensePolicy.EvaluateLicense(resolvedSPDX, policyScope)
	applyPolicyEvaluation(&res, eval, "")

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
// unknown_license policy is "block", or a gate left unevaluated because the
// policy scope in force matches no rule — so `audit` exits non-zero for CI
// gating instead of silently passing uncertain or unmeasured dependencies.
// The unevaluated diagnostic names the scope in force and the scopes that do
// carry rules, so the remedy is visible without reading the config file.
// The full result table/JSON is still emitted before this is returned.
func auditBlockingErr(results []auditModuleResult) error {
	var blocked, unevaluated []string
	scopeInForce := ""
	var ruleScopes []string
	for _, r := range results {
		if !r.PolicyBlocking {
			continue
		}
		if r.PolicyUnevaluated {
			unevaluated = append(unevaluated, r.Coordinate)
			scopeInForce = r.policyScope
			ruleScopes = r.policyRuleScopes
			continue
		}
		blocked = append(blocked, r.Coordinate)
	}
	var msgs []string
	if len(unevaluated) > 0 {
		rules := "none"
		if len(ruleScopes) > 0 {
			rules = strings.Join(ruleScopes, ", ")
		}
		msgs = append(msgs, fmt.Sprintf(
			"license policy: gate unevaluated for %d dependency(ies) — scope %q matches no license_policy rule (scopes with rules: %s)",
			len(unevaluated), scopeInForce, rules))
	}
	if len(blocked) > 0 {
		msgs = append(msgs, fmt.Sprintf(
			"license policy: %d dependency(ies) with an undetermined license blocked by policy (unknown_license=block): %s",
			len(blocked), strings.Join(blocked, ", ")))
	}
	if len(msgs) == 0 {
		return nil
	}
	return &exitError{code: ExitPolicy, msg: strings.Join(msgs, "\n")}
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
			if r.LatestReleaseAgeDays == 0 {
				staleness = fmt.Sprintf("latest: %s (today)", r.LatestVersion)
			} else {
				staleness = fmt.Sprintf("latest: %s (%d days ago)", r.LatestVersion, r.LatestReleaseAgeDays)
			}
		}
		// Appended, not substituted. "current" remains true of this module path;
		// the newer major line is a second fact stated beside it, so a module
		// several majors behind no longer reads as up to date.
		if r.MajorProbed && r.NewerMajorModule != "" {
			staleness += fmt.Sprintf("; newer major: %s@%s", r.NewerMajorModule, r.NewerMajorLatest)
		}
		policy := r.PolicyOutcome
		if r.LicenseCategory != "" {
			policy = fmt.Sprintf("%s [%s]", r.PolicyOutcome, r.LicenseCategory)
		}
		// A disjunction states which licences carry the outcome, so the reader
		// can see the row was decided on an arm rather than on one identity.
		if len(r.LicenseElectableArms) > 0 {
			policy = fmt.Sprintf("%s [electable: %s]", policy, strings.Join(r.LicenseElectableArms, " or "))
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
		// An unevaluated gate measured nothing: name the scope gap in the row
		// so the table never shows a bare word that could read as a verdict.
		if r.PolicyUnevaluated {
			policy = fmt.Sprintf("unevaluated [no rule for scope %s]", r.policyScope)
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
	// The staleness column is dated by its OLDEST lookup: a table where most
	// rows were served from the ledger and a few re-queried is only as current
	// as the row asked about longest ago.
	var oldest time.Time
	for _, r := range results {
		if r.StalenessLookedUpAt.IsZero() {
			continue
		}
		if oldest.IsZero() || r.StalenessLookedUpAt.Before(oldest) {
			oldest = r.StalenessLookedUpAt
		}
	}
	// No --fresh here: on audit the TTL is what governs this column, and the
	// command that re-queries a latest answer on demand is `latest --fresh`.
	if asOf := stalenessAsOf(oldest); asOf != "" {
		if _, err := fmt.Fprintf(stdout, "\nlatest as of %s (staleness.ttl %s; `latest --fresh` to re-query)\n",
			asOf, activeConfig.Staleness.TTL); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	}
	return nil
}
