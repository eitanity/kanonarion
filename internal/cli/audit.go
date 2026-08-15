package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/spf13/cobra"

	proxyadapter "github.com/eitanity/kanonarion/internal/adapters/proxy/direct"
	configdomain "github.com/eitanity/kanonarion/internal/config/domain"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"

	licapp "github.com/eitanity/kanonarion/internal/license/application"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
	staledomain "github.com/eitanity/kanonarion/internal/staleness/domain"
	vulnapp "github.com/eitanity/kanonarion/internal/vuln/application"
	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
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

Beside the table, on stderr, audit states the toolchain axis: the Go toolchain
version the walk was built by, the advisory snapshot it was judged against, and
either that no toolchain advisory covers it or the ones that do. The toolchain
is not a dependency of the artefact, so it is never a row and is counted in no
roll-up.

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
	//
	// Emitted on every row, zero included, and a plain int rather than a pointer.
	// It is derived by the same call, from the same record, as VulnFindings: a row
	// with no scan gets nought for both, and WHICH absence that is — not scanned,
	// superseded, record unreadable — is stated by VulnStatus and VulnReason, not
	// by a missing key. Under `omitempty` "no advisory was retracted" and "this
	// build does not report retractions" were the same document, and the count sat
	// on a different convention from the sibling it is a subset of.
	VulnWithdrawn int `json:"vuln_withdrawn"`
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
	//
	// Emitted on every row, false included, and a plain bool: both row builders
	// evaluate the licence policy before they return, so there is no row on which
	// the gate was not run and no state a null would name. The other CLI surfaces
	// that carry this fact — directives, fips, godebug, vendor — already emit it
	// unconditionally.
	PolicyBlocking bool `json:"policy_blocking"`
	// PolicyUnevaluated is true when the policy scope in force matched no
	// license_policy rule: the gate evaluated nothing for this row, which is
	// reported and blocking — never an implicit allow.
	//
	// Emitted on every row, false included. It is the field that says the gate ran
	// and matched nothing, so omitting it at false destroyed the one distinction it
	// exists to draw: with this and PolicyBlocking both absent, "policy evaluated,
	// nothing blocks" and "no policy evaluated" were the same document. Plain, not
	// a pointer — a null would be a second encoding of "the gate did not decide",
	// competing with the false/true this field already carries, and nothing
	// produces it.
	PolicyUnevaluated bool `json:"policy_unevaluated"`
	// IsLatest answers "is the pin the newest version of this module path".
	//
	// It is a pointer because the question is not always asked. A fully offline
	// run makes no proxy call, and where it has no recorded lookup to serve it
	// has nothing to answer with: the field is then null and StalenessUnmeasured
	// says why. It previously defaulted to true, which rendered an unasked
	// question as the affirmative claim "current" on every offline row.
	IsLatest *bool `json:"is_latest"`
	// PinAheadOfLatest is true when the pin sorts ABOVE the newest version
	// published at this path — a pseudo-version taken after the last tag, or a
	// pre-modules +incompatible major above the newest version @latest serves
	// from the unsuffixed path.
	//
	// It is emitted on every row, false included, so "measured, and not in that
	// state" is distinguishable from "this build does not derive the field at
	// all". It is a POINTER for the same reason IsLatest is: on an unmeasured
	// row no comparison was made, and a bare false there is the claim "the pin
	// is not ahead" about a question nobody put. Null and false are different
	// answers and only one of them is one.
	//
	// IsLatest and this field together are the three-valued answer: false/false
	// is behind, true/false is level, false/true is ahead. IsLatest stays the
	// literal answer to "is the pin the newest version of this module path",
	// which on an ahead row is genuinely false — the pin is not any version
	// @latest names. What made that reading misleading was the age travelling
	// beside it; see LatestReleaseAgeDays.
	PinAheadOfLatest *bool `json:"pin_ahead_of_latest"`
	// StalenessSource names where this row's staleness column came from:
	// "proxy" (this run asked upstream), "ledger" (a recorded lookup inside the
	// staleness TTL, dated by StalenessLookedUpAt), or "unmeasured". A reader
	// that does not care which measured it still gets a measured/unmeasured
	// split from one key.
	StalenessSource string `json:"staleness_source"`
	// StalenessUnmeasured is the machine-readable reason the column is
	// unmeasured: offline_no_ledger_entry | lookup_failed | toolchain_pinned.
	// Empty on a measured row.
	StalenessUnmeasured string `json:"staleness_unmeasured,omitempty"`
	LatestVersion       string `json:"latest_version,omitempty"`
	// LatestReleaseAgeDays is how long ago the LATEST release shipped, not how
	// far behind the pin is. It replaces the `days_behind` key, which named a
	// quantity the value never held: the number is the age of the newest release,
	// so an eighteen-month-old pin on an actively released module reported a
	// smaller figure than a current pin on a quiet one. See latestResult in
	// latest.go for why the genuine pin-to-latest distance is not emitted at all
	// rather than approximated.
	//
	// A POINTER, always emitted, because ZERO IS A REAL ANSWER: a release that
	// shipped today is nought days old, and as a bare int under `omitempty` that
	// row was erased — "the fix landed today" and "the publication date is
	// unknown" collapsed into the same absence. Null now means no age, in
	// exactly two cases told apart by PinAheadOfLatest: no publication date was
	// supplied (false), or the pin is ahead and no distance is offered (true).
	LatestReleaseAgeDays *int `json:"latest_release_age_days"`
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

	// stalenessLedgerAge is how old the served ledger lookup was when this row
	// was built, set only on the offline path — there the recorded lookup IS the
	// whole answer, so the row states its age beside it. Unexported: the JSON
	// already dates the answer with staleness_looked_up_at, from which an age is
	// a subtraction, and the table is where the statement is needed.
	stalenessLedgerAge time.Duration

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
	// version. In --from-modcache mode the run is fully offline, so the column is
	// answered from the staleness ledger alone: a lookup recorded inside the TTL
	// is a measurement and is served with its age stated, and a module with no
	// such lookup is reported unmeasured. No probe is added to the offline path —
	// that would break the mode's whole contract — and nothing is written.
	var staleness stalenessLookup = newOfflineStalenessLookup(ctr.StalenessLedger, activeConfig.Staleness.TTL)
	if !modcacheMode {
		proxy, perr := proxyadapter.New(f.goproxy, false)
		if perr != nil {
			return proxyAdapterError(perr)
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

	// What the answer is ABOUT, before where it came from. A vendored project
	// compiles the bytes under vendor/, and every row below describes the
	// modules go.mod resolves; the reader is told which of the two they have.
	// It goes on stderr with the other basis lines because audit's stdout is a
	// documented array of per-module rows that consumers index into — there is
	// no envelope on that channel to add a field to, and inventing one would
	// break every existing caller to state a fact about the run.
	if verr := writeBuildVendoring(stderr, detectBuildVendoringForGoMod(gomodPath)); verr != nil {
		return verr
	}

	// Where the answer came from, before the answer itself. On stderr for the
	// same reason the coverage aggregate is: a --json caller pipes stdout into
	// jq, and a statement about the run is not one of the run's rows.
	if derr := writeAuditDerivation(stderr, derivation); derr != nil {
		return derr
	}

	// The toolchain axis, beside the module evidence and never inside it. It is
	// derived from the same stored snapshot the scan was judged against, so it
	// costs one local read and states the basis it rests on.
	if terr := writeToolchainJudgment(stderr, derivation.toolchain); terr != nil {
		return terr
	}

	// The aggregate goes to stderr on both paths: a whole-graph collapse in
	// cross-verification is invisible in a populated status column, and stdout
	// is the data channel --json callers pipe into jq.
	if cerr := writeVerificationCoverage(stderr, auditVerificationCoverage(results)); cerr != nil {
		return cerr
	}

	// The staleness column gets its own coverage line for the same reason the
	// verification column does: a run that could not measure the column at all
	// is invisible in a populated table, and the count is what makes the gap a
	// stated quantity rather than something the reader must total by eye.
	if cerr := writeStalenessCoverage(stderr, auditStalenessCoverageOf(results)); cerr != nil {
		return cerr
	}

	// The pre-modules axis, on stderr with the others. Rows for a +incompatible
	// module are honest about that module; what they cannot show is anything
	// UNDER it, because the module system resolved no requirements there — so the
	// audited set is narrower than the build the reader is auditing.
	if cerr := writePreModulesCaveatForSet(stderr, auditPreModulesCoords(results)); cerr != nil {
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
	// toolchain is the derived judgment of the toolchain that built the walk
	// against the same snapshot the module findings were judged against. It rides
	// here because it shares that snapshot and is stated beside the derivation,
	// and it is reported on its own axis: no module row and no roll-up sees it.
	toolchain vulndomain.ToolchainJudgment
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

	return writeDerivation(w, lines...)
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
	staleness stalenessLookup,
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

	// The project walk's target is the local main module.
	localCoord, cErr := coordinate.NewLocalCoordinate(modulePath)
	if cErr != nil {
		return nil, derivation, fmt.Errorf("project coordinate for %s: %w", modulePath, cErr)
	}
	walkScope := walkdomain.WalkScope(scope)

	// Every downstream leg — licence extraction, the reuse question, the scan,
	// the rows, the derivation — is keyed on THIS walk, the one the walk leg just
	// executed or reused. It is taken from that leg's own result and never looked
	// up again.
	//
	// The lookup it replaces asked the store for the latest walk of this target
	// and scope, which is not the same question. Two walks of one target differ
	// on more than target and scope — the build environment among them, and
	// WalkFilter carries no axis for it — so a cross-compiled audit of one
	// platform would extract, scan and report against another platform's walk
	// whenever that one happened to be newer, while the derivation line named the
	// walk this run actually resolved. One audit, two walks, and the report said
	// nothing about the disagreement. This was invisible while every audit minted
	// a fresh walk, because then the latest walk always was this run's; walk reuse
	// is what let the two come apart.
	if walkResult.Record.ID == "" {
		return nil, derivation, fmt.Errorf("project walk produced no record for %s", localCoord)
	}
	walkID := walkResult.Record.ID

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
	if prior, ok, rerr := ctr.ScanWalk.ReusableRun(ctx, walkID, filepath.Dir(f.gomodPath)); rerr != nil {
		_, _ = fmt.Fprintf(stderr, "vuln-scan: %v\n", rerr)
	} else if ok && !f.force {
		derivation.scanReused = true
		derivation.scanRun = prior
	}

	// fresh=false: the refresh above already happened, and the snapshot it
	// settled on is the stored one the scan now resolves. Passing the flag on
	// would check the database a second time in the same invocation.
	_, _ = fmt.Fprintf(progressOut, "==> audit: scanning vulnerabilities for walk %s\n", walkID)
	if verr := runVulnScan(ctx, walkID, f.force, false, false, 1, false, false, "", os.Getenv("USER"), filepath.Dir(f.gomodPath), f.policyPath, vulnapp.ServeSurfaceAudit, false, f.noProgress, false, io.Discard, stderr); verr != nil {
		_, _ = fmt.Fprintf(stderr, "vuln-scan: %v\n", verr)
	}

	// The toolchain axis, derived once the snapshot this run is judged against is
	// settled: the scan run names it when one was reused, and the store's latest
	// otherwise. Both are local reads, and neither the judgment nor its inputs are
	// written anywhere.
	derivation.toolchain = judgeWalkToolchain(ctx, ctr, rec, storedSnapshotFor(ctx, ctr, derivation.scanRun))

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
		res, rerr := buildAuditResult(ctx, node, walkFrameAnchor(walkID, rec.Target), policyScope, overrides, staleness, ctr, stderr)
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
func buildAuditResult(ctx context.Context, node walkdomain.GraphNode, anchor vulnFrameAnchor, policyScope string, overrides licdomain.LicenseOverrideSet, staleness stalenessLookup, ctr *Container, stderr io.Writer) (auditModuleResult, error) {
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
		return buildStdlibAuditResult(ctx, coord, node, policyScope, anchor, ctr), nil
	}

	res := auditModuleResult{
		Coordinate:    coordStr,
		Verification:  "(walk failed)",
		License:       "(not run)",
		LicenseStatus: "(not run)",
		VulnStatus:    "(not run)",
	}
	applyAuditStaleness(ctx, &res, coord, staleness, stderr)

	if anchor.walkID == "" {
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

	// The walk being audited is the frame the vuln column answers in. The
	// frame-blind read this replaces ranked every frame the coordinate was
	// measured in against each other, so a store holding a second project's scans
	// could put that project's verdict in this project's audit row.
	vrec, found, verr := recordInWalkFrame(ctx, ctr.QueryVuln, coord, anchor)
	res.VulnStatus, res.VulnReason, res.VulnFindings, res.VulnWithdrawn =
		vulnAuditStatus(vrec, found, verr, auditSupersededReason(ctx, ctr.QueryVuln, coord, found, verr))

	return res, nil
}

// auditSupersededReason is the row's explanation when the walk-frame read found
// nothing because the records it would have served belong to a generation this
// build no longer reads.
//
// It is a store read, so it is asked only for a row that has nothing else to
// say: a covered module pays for it never, and an uncovered one pays one
// indexed lookup. Empty when the emptiness has some other cause, and the row
// keeps "(not scanned)", which is then true.
func auditSupersededReason(ctx context.Context, uc QueryVulnUseCase, coord coordinate.ModuleCoordinate, found bool, verr error) string {
	if found || verr != nil {
		return ""
	}
	gens, superseded := supersededVulnGenerations(ctx, uc, coord)
	if !superseded {
		return ""
	}
	return fmt.Sprintf("scanned at pipeline %s; this build reads pipeline %s, so no record is served — re-scan",
		supersededVulnHeld(gens), vulnPipelineVersion)
}

// The staleness column's provenance vocabulary. Every audit row carries one of
// these three sources; an unmeasured row additionally carries one of the shared
// reasons in staleness.go, so "the column is empty" is never left for the reader
// to interpret.
const (
	stalenessSourceProxy      = "proxy"
	stalenessSourceLedger     = "ledger"
	stalenessSourceUnmeasured = "unmeasured"
)

// applyAuditStaleness fills a row's staleness columns from one lookup.
//
// The lookup answers in three states and the row keeps all three apart: served
// from the ledger, resolved live, or unmeasured. Unmeasured is never folded into
// the answer a measured-and-current module would give — the offline path used to
// leave IsLatest at its true default and print "current" for every module it had
// not asked about, which is the same absence-as-answer the vulnerability columns
// were taught not to give.
func applyAuditStaleness(ctx context.Context, res *auditModuleResult, coord coordinate.ModuleCoordinate, lookup stalenessLookup, stderr io.Writer) {
	// No lookup at all is the offline case by construction: runAudit wires the
	// ledger-only lookup for --from-modcache and the resolver otherwise, so a nil
	// here is a caller with no staleness source, which measures nothing.
	if lookup == nil {
		res.markStalenessUnmeasured(stalenessOfflineNoEntry)
		return
	}
	ans, lerr := lookup.Resolve(ctx, coord.Path(), coord.Version())
	if ans.LatestVersion == "" {
		// Reported, never swallowed — except for the offline sentinel, which is
		// the mode working as designed and is already stated in the column, the
		// coverage line and the JSON.
		if lerr != nil && !errors.Is(lerr, errStalenessOffline) {
			_, _ = fmt.Fprintf(stderr, "staleness %s: %v\n", coord.Path(), lerr)
			res.markStalenessUnmeasured(stalenessLookupFailed)
			return
		}
		res.markStalenessUnmeasured(stalenessOfflineNoEntry)
		return
	}
	// A partial failure (cached latest, live probe that errored) still reports
	// the half it has, and the half it does not keeps MajorProbed false.
	if lerr != nil {
		_, _ = fmt.Fprintf(stderr, "staleness %s: %v\n", coord.Path(), lerr)
	}

	res.StalenessSource = stalenessSourceProxy
	if ans.Served {
		res.StalenessSource = stalenessSourceLedger
		if modcacheMode {
			// Offline, so this row's whole answer is the recorded one: it states
			// its own age. On the network path the table's dated footer already
			// carries that statement for the run as a whole.
			res.stalenessLedgerAge = time.Since(ans.LookedUpAt)
		}
	}
	// Placed with semver, not string equality: a pin can sort ABOVE @latest, and
	// string equality has no third outcome to put that in, so it landed in
	// "behind" and named a downgrade as the upgrade target.
	pos := staledomain.ComparePin(coord.Version(), ans.LatestVersion)
	isLatest := pos == staledomain.PinLevel
	ahead := pos == staledomain.PinAhead
	res.IsLatest = &isLatest
	res.PinAheadOfLatest = &ahead
	res.StalenessLookedUpAt = ans.LookedUpAt
	// The release age is a fact about the release, so it is recorded whether or
	// not the pin is current — but NOT when the pin is ahead. On a current row
	// the age travels beside is_latest true, which no consumer reads as a
	// distance behind. On an ahead row it would travel beside is_latest FALSE,
	// and false-plus-an-age is exactly the sentence "you are 3868 days behind"
	// — the original wrong answer, surviving on the surface most likely to be
	// read by a machine. The text output drops it here for the same reason, and
	// the two surfaces must not disagree.
	if !ahead {
		res.LatestReleaseAgeDays = latestReleaseAgeDays(ans.LatestPublishedAt)
	}
	if !isLatest {
		res.LatestVersion = ans.LatestVersion
	}
	res.MajorProbed = ans.NewerMajor.Probed
	res.NewerMajorModule = ans.NewerMajor.Path
	res.NewerMajorLatest = ans.NewerMajor.Version
}

// markStalenessUnmeasured records that the column was not answered, and why. It
// leaves IsLatest nil: there is no version comparison to report, and the zero
// value of a bool is a claim.
func (r *auditModuleResult) markStalenessUnmeasured(reason string) {
	r.IsLatest = nil
	r.PinAheadOfLatest = nil
	r.StalenessSource = stalenessSourceUnmeasured
	r.StalenessUnmeasured = reason
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
func vulnAuditStatus(rec vulndomain.VulnerabilityRecord, found bool, err error, supersededReason string) (status, reason string, findings, withdrawn int) {
	if err != nil {
		return "(scan record unreadable)", "reading vulnerability record: " + err.Error(), 0, 0
	}
	if !found {
		// A coordinate whose records were superseded by a pipeline bump has been
		// scanned, and "(not scanned)" is the sentence an operator reads as a
		// dependency nobody has checked. The two absences carry opposite
		// instructions, so the column keeps them apart.
		if supersededReason != "" {
			return "(superseded)", supersededReason, 0, 0
		}
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
func buildStdlibAuditResult(ctx context.Context, coord coordinate.ModuleCoordinate, node walkdomain.GraphNode, policyScope string, anchor vulnFrameAnchor, ctr *Container) auditModuleResult {
	res := auditModuleResult{
		Coordinate:   coord.String(),
		Verification: "(custody unavailable)",
		VulnStatus:   "(not scanned)",
	}
	// Pinned to the build toolchain: there is no proxy "latest" to compare
	// against, so the column says the question does not apply instead of
	// resolving it in the pin's favour.
	res.markStalenessUnmeasured(stalenessToolchainPinned)

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

	vrec, found, verr := recordInWalkFrame(ctx, ctr.QueryVuln, coord, anchor)
	res.VulnStatus, res.VulnReason, res.VulnFindings, res.VulnWithdrawn =
		vulnAuditStatus(vrec, found, verr, auditSupersededReason(ctx, ctr.QueryVuln, coord, found, verr))
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

// auditStalenessCoverage is the run's own tally of how its staleness column was
// answered. It is the staleness analogue of the verification coverage aggregate,
// and it exists for the same reason: a column every row of which says
// "unmeasured" is a fact about the run, and a reader should not have to count
// rows to learn it.
type auditStalenessCoverage struct {
	Total  int
	Proxy  int
	Ledger int
	// Unmeasured is keyed by the machine reason, so the line distinguishes an
	// offline run from a proxy that failed mid-sweep.
	Unmeasured map[string]int
}

// Measured is the count of rows the column actually answers for.
func (c auditStalenessCoverage) Measured() int { return c.Proxy + c.Ledger }

// auditStalenessCoverageOf tallies the rows the run itself produced, for the
// same reason auditVerificationCoverage does: the aggregate equals the table by
// construction rather than by a second read agreeing with the first.
func auditStalenessCoverageOf(results []auditModuleResult) auditStalenessCoverage {
	c := auditStalenessCoverage{Total: len(results), Unmeasured: map[string]int{}}
	for _, r := range results {
		if r.IsLatest == nil {
			c.Unmeasured[r.StalenessUnmeasured]++
			continue
		}
		if r.StalenessSource == stalenessSourceLedger {
			c.Ledger++
			continue
		}
		c.Proxy++
	}
	return c
}

// writeStalenessCoverage states the staleness column's coverage on stderr,
// beside the verification one and on the same channel for the same reason: it is
// a statement about the run, not one of the run's rows.
//
// The measured line is printed even at zero. That is the whole point on an
// offline run: a coverage row that vanishes when it hits zero cannot report the
// collapse it exists to report.
func writeStalenessCoverage(w io.Writer, c auditStalenessCoverage) error {
	if c.Total == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(w, "staleness coverage over %d module(s):\n", c.Total); err != nil {
		return fmt.Errorf("writing coverage header: %w", err)
	}
	rows := []struct {
		label string
		count int
	}{
		{"measured", c.Measured()},
		{"  measured (asked upstream)", c.Proxy},
		{"  measured (served from ledger)", c.Ledger},
	}
	for _, reason := range sortedStalenessReasons(c.Unmeasured) {
		rows = append(rows, struct {
			label string
			count int
		}{stalenessUnmeasuredLabel(reason), c.Unmeasured[reason]})
	}
	for _, row := range rows {
		if row.count == 0 && row.label != "measured" {
			continue
		}
		if _, err := fmt.Fprintf(w, "  %-34s %5d  %5.1f%%\n",
			row.label, row.count, percentOf(row.count, c.Total)); err != nil {
			return fmt.Errorf("writing coverage row: %w", err)
		}
	}
	return nil
}

func sortedStalenessReasons(m map[string]int) []string {
	reasons := make([]string, 0, len(m))
	for k := range m {
		reasons = append(reasons, k)
	}
	sort.Strings(reasons)
	return reasons
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

// auditStalenessCell renders one row's staleness column.
//
// An unmeasured row says so in words, with the reason in the same cell: the
// column is read left to right beside a verification and a vulnerability status,
// and a blank or a bare "current" there is read as an answer.
//
// The newer-major fact is NOT here. It is a second fact about a different module
// path, it is routinely wider than the rest of the row put together, and the
// table states it on a continuation line beneath the row — see printAuditTable
// and auditNewerMajorNote.
func auditStalenessCell(r auditModuleResult) string {
	return auditStalenessAnswer(r) + auditLedgerAgeNote(r)
}

// auditStalenessAnswer is the same-major answer: what this module path's own
// newest version says about the pin, and nothing else.
func auditStalenessAnswer(r auditModuleResult) string {
	// The absent comparison is what makes a row unmeasured — not the source
	// label, which is a detail about a measurement that exists.
	if r.IsLatest == nil {
		return stalenessUnmeasuredLabel(r.StalenessUnmeasured)
	}
	switch {
	case r.PinAheadOfLatest != nil && *r.PinAheadOfLatest:
		// No target and no age. The age would be the age of a release the
		// project is already past, printed in a column whose other rows mean
		// "this is how long you have been behind"; the tag is named because a
		// reader comparing this row against the proxy needs to see the same
		// answer the proxy gave, not a blank.
		return fmt.Sprintf("ahead of latest tag: %s", r.LatestVersion)
	case !*r.IsLatest && r.LatestReleaseAgeDays == nil:
		// A newer version with no publication date. The target is stated and no
		// age is invented for it; a missing date used to reach this line as 0
		// and print "(today)" about a release nothing is known about.
		return fmt.Sprintf("latest: %s", r.LatestVersion)
	case !*r.IsLatest && *r.LatestReleaseAgeDays == 0:
		return fmt.Sprintf("latest: %s (today)", r.LatestVersion)
	case !*r.IsLatest:
		return fmt.Sprintf("latest: %s (%d days ago)", r.LatestVersion, *r.LatestReleaseAgeDays)
	}
	return "current"
}

// auditNewerMajorNote is the newer-major clause: the fact that stops a module
// several majors behind from reading as up to date.
//
// It is stated beside the staleness answer, never folded into it. "current" and
// "a newer major line exists" are both true at once for a module pinned behind a
// major bump, and a rendering that merged them would report the module the way
// this whole context exists to stop reporting it.
func auditNewerMajorNote(r auditModuleResult) string {
	if !r.MajorProbed || r.NewerMajorModule == "" {
		return ""
	}
	return fmt.Sprintf("newer major: %s@%s", r.NewerMajorModule, r.NewerMajorLatest)
}

// auditLedgerAgeNote states how old the recorded lookup this row was answered
// from is. Offline only: on the network path the table's dated footer carries
// that statement for the run as a whole.
func auditLedgerAgeNote(r auditModuleResult) string {
	if r.stalenessLedgerAge <= 0 {
		return ""
	}
	return fmt.Sprintf(" [from ledger, %s old]", roundedAge(r.stalenessLedgerAge))
}

// roundedAge renders a ledger age at a resolution a reader can use: minutes
// under an hour, hours above it. The TTL that admitted the row is measured in
// the same units.
func roundedAge(d time.Duration) string {
	if d < time.Minute {
		// A lookup made moments ago is stated as such: "0s old" reads as a
		// precision the minute-resolution rendering does not have.
		return "under a minute"
	}
	if d < time.Hour {
		return d.Round(time.Minute).String()
	}
	return d.Round(time.Hour).String()
}

// auditRowCells renders one result as the table's cells, left to right. The
// staleness cell deliberately excludes the newer-major clause; see
// auditStalenessCell.
func auditRowCells(r auditModuleResult, showScope bool) []string {
	cells := []string{r.Coordinate}
	if showScope {
		cells = append(cells, r.Scope)
	}
	return append(cells, r.Verification, auditLicenseCell(r), auditStalenessCell(r), auditVulnCell(r), auditPolicyCell(r))
}

// auditVulnCell renders the vulnerability status with its counts.
func auditVulnCell(r auditModuleResult) string {
	// live is the difference, because VulnFindings counts the retracted ones too.
	live := r.VulnFindings - r.VulnWithdrawn
	switch {
	case live > 0 && r.VulnWithdrawn > 0:
		return fmt.Sprintf("%s (%d findings, %d retracted)", r.VulnStatus, live, r.VulnWithdrawn)
	case live > 0:
		return fmt.Sprintf("%s (%d findings)", r.VulnStatus, live)
	case r.VulnWithdrawn > 0:
		// Named as retracted, never as findings: the count column sits beside a
		// Withdrawn status word, and "1 findings" there contradicts it.
		return fmt.Sprintf("%s (%d retracted)", r.VulnStatus, r.VulnWithdrawn)
	case r.VulnReason != "":
		// The reason (govulncheck stderr) is multi-line and too wide for
		// the table; direct the reader to vuln-show, which renders it.
		return fmt.Sprintf("%s (see vuln-show)", r.VulnStatus)
	}
	return r.VulnStatus
}

// auditLicenseCell renders the licence identifier with its status annotation.
func auditLicenseCell(r auditModuleResult) string {
	switch {
	case r.LicenseSource == "override":
		return fmt.Sprintf("%s (override)", r.License)
	case r.LicenseStatus != "(not run)" && r.LicenseStatus != "Detected":
		return fmt.Sprintf("%s [%s]", r.License, r.LicenseStatus)
	}
	return r.License
}

// auditPolicyCell renders the policy outcome and everything that qualifies it.
func auditPolicyCell(r auditModuleResult) string {
	// An unevaluated gate measured nothing: name the scope gap in the row
	// so the table never shows a bare word that could read as a verdict.
	if r.PolicyUnevaluated {
		return fmt.Sprintf("unevaluated [no rule for scope %s]", r.policyScope)
	}
	// Never let an undetermined license read as a clean verdict: make
	// the uncertainty (and any hard block) explicit in the table.
	if !r.LicenseResolved {
		marker := "UNCERTAIN"
		if r.PolicyBlocking {
			marker = "BLOCKED"
		}
		return fmt.Sprintf("%s [%s: %s]", r.PolicyOutcome, marker, r.LicenseUncertainty)
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
	return policy
}

func printAuditTable(stdout io.Writer, results []auditModuleResult) error {
	// minCoordWidth keeps a table of short coordinates from collapsing into a
	// ragged left edge. It is a FLOOR, never a ceiling: a longer coordinate
	// widens the column rather than overflowing it.
	const minCoordWidth = 55
	showScope := false
	for _, r := range results {
		if r.Scope != "" {
			showScope = true
			break
		}
	}

	// Every cell is built before anything is printed, because a column can only
	// be sized from the widest value the run actually produced. The previous
	// pass printed as it went against constant widths, so any cell wider than
	// its constant — a two-fact staleness answer, a long licence expression —
	// pushed every column to its right out of line on that row alone.
	type row struct {
		cells []string
		// note is the newer-major clause, printed beneath the row. See
		// auditStalenessCell for why it is not in the column.
		note string
	}
	rows := make([]row, 0, len(results))
	for _, r := range results {
		rows = append(rows, row{cells: auditRowCells(r, showScope), note: auditNewerMajorNote(r)})
	}

	var widths []int
	for _, rw := range rows {
		for i, c := range rw.cells {
			for len(widths) <= i {
				widths = append(widths, 0)
			}
			// Width is counted in runes, not bytes: a licence expression or a
			// reason carrying a non-ASCII character is one column per rune, and
			// counting bytes over-pads exactly those rows.
			if n := utf8.RuneCountInString(c); n > widths[i] {
				widths[i] = n
			}
		}
	}
	if len(widths) > 0 && widths[0] < minCoordWidth {
		widths[0] = minCoordWidth
	}

	// noteIndent lines the continuation up under the staleness column it
	// belongs to, so the clause reads as that row's second staleness fact
	// rather than as a new row.
	noteIndent := 0
	stalenessCol := 3
	if showScope {
		stalenessCol = 4
	}
	for i := 0; i < stalenessCol && i < len(widths); i++ {
		noteIndent += widths[i] + 2
	}

	for _, rw := range rows {
		var b strings.Builder
		for i, c := range rw.cells {
			if i > 0 {
				b.WriteString("  ")
			}
			// The last column is never padded: trailing whitespace is not
			// alignment, and it is what a reader's diff notices.
			if i == len(rw.cells)-1 {
				b.WriteString(c)
				continue
			}
			fmt.Fprintf(&b, "%-*s", widths[i], c)
		}
		if _, err := fmt.Fprintln(stdout, b.String()); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		if rw.note != "" {
			// Reported in full and never truncated. It is on its own line
			// because it carries a module path and a version, which is wider
			// than the rest of the row put together.
			if _, err := fmt.Fprintf(stdout, "%*s%s\n", noteIndent, "", rw.note); err != nil {
				return fmt.Errorf("writing output: %w", err)
			}
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
