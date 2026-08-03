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

	"github.com/eitanity/kanonarion/internal/adapters/clock"
	localimporter "github.com/eitanity/kanonarion/internal/local/adapters/importer/golist"
	localprober "github.com/eitanity/kanonarion/internal/local/adapters/probe/builder"
	localsnapshot "github.com/eitanity/kanonarion/internal/local/adapters/snapshot/walkdir"
	localvulnstore "github.com/eitanity/kanonarion/internal/local/adapters/vulnfindings/store"
	localapp "github.com/eitanity/kanonarion/internal/local/application"
	localdomain "github.com/eitanity/kanonarion/internal/local/domain"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

const localVulnPipelineVersion = vulnPipelineVersion

// reachabilityMethodNone is the method of a reply that consulted no
// reachability analysis — "not affected" and "withdrawn" are read off the
// advisory set. An empty string would render as a missing value; this says the
// question was not asked.
const reachabilityMethodNone = "none"

// reachability verdicts for the stored-module query mode.
const (
	verdictReachable    = "reachable"
	verdictNotReachable = "not_reachable"
	verdictNotAffected  = "not_affected"
	// verdictWithdrawn is its own verdict, not a flavour of not_affected and
	// certainly not a reachability answer. A retracted advisory is excluded on the
	// strength of its retraction, and answering "not reachable" for one would offer
	// reachability as the mitigation — inviting the reader to conclude the module
	// would be at risk if only something called it, when there is nothing to be at
	// risk from.
	verdictWithdrawn = "withdrawn"
	// verdictPackageLevelOnly is the answer for a coordinate the advisory matches
	// but names no symbol in: the module is affected, and symbol-level
	// reachability was never determinable because there is no symbol to reach.
	// It is neither "reachable" — nothing showed the vulnerable code running —
	// nor "not reachable", which would offer a search that was never possible as
	// the reason.
	verdictPackageLevelOnly = "package_level_only"
)

// -- output types --

type reachabilityFinding struct {
	CVEID          string   `json:"cve_id"`
	Aliases        []string `json:"aliases,omitempty"`
	Summary        string   `json:"summary"`
	Verdict        string   `json:"verdict"`
	VerdictSource  string   `json:"verdict_source,omitempty"`
	Reason         string   `json:"reason,omitempty"`
	MatchedSymbols []string `json:"matched_symbols,omitempty"`
	// MatchedBinaries names the main packages whose symbol table carried the
	// matched symbols — which of a multi-binary build's artefacts ships the
	// vulnerable code.
	MatchedBinaries []string `json:"matched_binaries,omitempty"`
}

type reachabilityModule struct {
	Path     string                `json:"path"`
	Version  string                `json:"version"`
	Findings []reachabilityFinding `json:"findings"`
}

// reachabilityUncovered is one module in the local build the probe holds no
// answer about.
type reachabilityUncovered struct {
	Path    string `json:"path"`
	Version string `json:"version,omitempty"`
	Reason  string `json:"reason"`
}

// reachabilityProbedBinary is one main package of the local build and whether
// the probe read its symbol table.
type reachabilityProbedBinary struct {
	ImportPath string `json:"import_path"`
	// BuildError is the failure that stopped this binary being probed, absent
	// when it was probed. Its presence marks a binary this answer cannot speak
	// about; the probe still answers from the ones that built.
	BuildError string `json:"build_error,omitempty"`
}

// reachabilityCoverage states what the local probe's answer was drawn from and
// what it left out.
//
// It is emitted on every local probe, not only the incomplete ones. A reader
// cannot tell a complete answer from a short one without it, and the field that
// says so has to be present when the answer is complete or its absence becomes
// the signal instead.
type reachabilityCoverage struct {
	// SnapshotTakenAt is when the workspace snapshot behind version_id was
	// built. The snapshot is recomputed from the working tree on every run, so
	// this is the age of the answer.
	SnapshotTakenAt string `json:"snapshot_taken_at"`
	// BuildModules is how many non-main modules the local build resolves.
	BuildModules int `json:"build_modules"`
	// QueriedModules is how many of them named a coordinate the store was asked
	// about.
	QueriedModules int `json:"queried_modules"`
	// CoveredModules is how many the store held a vulnerability record for —
	// the modules this answer speaks about.
	CoveredModules int `json:"covered_modules"`
	// ModulesWithFindings is how many carried at least one stored finding.
	ModulesWithFindings int `json:"modules_with_findings"`
	// UncoveredModules names every module in the build this answer does not
	// speak about. Never capped.
	UncoveredModules []reachabilityUncovered `json:"uncovered_modules,omitempty"`
	// UncoveredRemedy is the invocation that brings the uncovered modules into
	// a later answer. Present exactly when something is uncovered: a remedy for
	// nothing would read as an outstanding action.
	UncoveredRemedy string `json:"uncovered_remedy,omitempty"`
	// ProbedBinaries names every main package of the build, probed or not, so
	// a multi-binary project's answer states its basis. Absent for a library
	// workspace and for a probe that was skipped, neither of which built a
	// main package.
	ProbedBinaries []reachabilityProbedBinary `json:"probed_binaries,omitempty"`
}

type reachabilityOutput struct {
	Root       string `json:"root"`
	ModulePath string `json:"module_path"`
	VersionID  string `json:"version_id"`
	ProbeKind  string `json:"probe_kind"`
	// SeedRestriction names the records the stored-findings seed was drawn from.
	// It is on the JSON surface as well as the text one because the probe's
	// consumers are scripts as often as people, and the restriction is part of
	// what the answer means.
	SeedRestriction string               `json:"seed_restriction,omitempty"`
	Notice          string               `json:"notice,omitempty"`
	Coverage        reachabilityCoverage `json:"coverage"`
	Modules         []reachabilityModule `json:"modules"`
}

// reachabilityFlags holds every flag the reachability command registers. They
// live in one struct, rather than in a local variable each, so that a flag one
// of the command's two dispatch paths never receives is visible per field
// rather than only as a missing argument.
type reachabilityFlags struct {
	localPath string
	vulnID    string
	walkID    string
	gomod     string
}

func newReachabilityCmd(stdout, stderr io.Writer) *cobra.Command {
	var f reachabilityFlags

	cmd := &cobra.Command{
		Use:   "reachability (<module>@<version> --vuln <id> | --local <dir>)",
		Short: "Report whether a CVE is reachable in a module (stored query) or the local working tree",
		Long: `reachability has two modes.

Stored-module query (read-only): 'reachability <module>@<version> --vuln <id>'
reads the reachability verdict that 'vuln-scan --reachability' previously
computed and persisted for a module, for a single CVE. It never scans or
recomputes; when the data is absent it tells you which command to run.

A stored verdict is a verdict about one build, so the query names one:
--walk-id answers in that walk's frame, --gomod in the frame of the newest
project walk for that go.mod (defaults to ./go.mod). A notice states which
build the answer was restricted to, and the verdict names its rooting either
way.

With neither flag, and more than one project's scans of the module in the
store, the query REFUSES and names the frames it found rather than answering
from whichever was scanned last. One project's scans in the store answer as
before.

Local probe: 'reachability --local <dir>' analyses the working tree directly
(a different, live analysis — not a query of stored facts). It seeds itself
only from stored records measured in this tree's own frame or in the isolated
frame — never another project's — and states that restriction in its output.`,
		Example: `  kanonarion reachability golang.org/x/text@v0.3.7 --vuln GO-2021-0113
  kanonarion reachability golang.org/x/text@v0.3.7 --vuln GO-2021-0113 --json
  kanonarion reachability golang.org/x/text@v0.3.7 --vuln GO-2021-0113 --gomod
  kanonarion reachability golang.org/x/text@v0.3.7 --vuln GO-2021-0113 --walk-id 01KQDBVW092ER1HNXZ60X27CMD
  kanonarion reachability --local .`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			coordArg := ""
			if len(args) == 1 {
				coordArg = args[0]
			}

			switch {
			case f.vulnID != "":
				return runReachabilityStoredQuery(cmd.Context(), coordArg, f, cmd.Flags().Changed("gomod"), stdout, stderr)
			case f.localPath != "":
				return runReachabilityLocalProbe(cmd.Context(), coordArg, f, cmd.Flags().Changed("gomod"), stdout, stderr)
			default:
				return fmt.Errorf("specify a target: '<module>@<version> --vuln <id>' to query a scanned module, or '--local <dir>' for the working tree")
			}
		},
	}

	cmd.Flags().StringVar(&f.localPath, "local", "", "path to the local Go workspace to probe")
	cmd.Flags().StringVar(&f.vulnID, "vuln", "", "vulnerability ID (e.g. GO-2024-1234, CVE-..., GHSA-...) to query; requires a <module>@<version> argument")
	cmd.Flags().StringVar(&f.walkID, "walk-id", "", "answer the stored query in the frame of this walk's scans")
	cmd.Flags().StringVar(&f.gomod, "gomod", "",
		"answer the stored query in the frame of the latest project walk for this go.mod (default: ./go.mod)")
	// Cobra only allows a valueless --gomod when the flag declares what that
	// spelling means.
	cmd.Flags().Lookup("gomod").NoOptDefVal = defaultGoModPath

	return cmd
}

// refuseBothReachabilityTargets refuses a run that names both targets. It is
// asked by both dispatch paths, so which flag cobra saw first cannot decide
// whether the conflict is reported.
func refuseBothReachabilityTargets(f reachabilityFlags) error {
	if f.vulnID != "" && f.localPath != "" {
		return fmt.Errorf("--vuln and --local are mutually exclusive: --vuln queries a stored module, --local analyses the working tree")
	}
	return nil
}

// runReachabilityStoredQuery is the command's stored-query dispatch path: it
// reads a persisted verdict and never measures anything. The store is opened
// after the refusals below, so an invocation this path cannot answer costs no
// store access.
func runReachabilityStoredQuery(ctx context.Context, coordArg string, f reachabilityFlags, gomodSet bool, stdout, stderr io.Writer) error {
	// Mutual exclusion is checked FIRST. The default branch of the dispatch
	// offers --local as a peer target, so '--local . --vuln <id>' is exactly
	// what an operator who read that message types next; checking the missing
	// coordinate first answered them with "requires a <module>@<version>
	// argument" — a complaint about the wrong thing, and one that made the
	// conflict message unreachable precisely when it was the accurate one.
	if err := refuseBothReachabilityTargets(f); err != nil {
		return err
	}
	if coordArg == "" {
		return fmt.Errorf("reachability --vuln requires a <module>@<version> argument")
	}
	logger := buildLogger(logLevel, stderr)
	ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() { _ = cleanup() }()
	return runVulnReachability(ctx, coordArg, f.vulnID, f.walkID, f.gomod, gomodSet,
		jsonOut, ctr.QueryVuln, ctr.QueryWalks, ctr.QueryCallGraph, stdout)
}

// runReachabilityLocalProbe is the command's local dispatch path: a live
// analysis of the working tree it is given, not a query of stored facts.
func runReachabilityLocalProbe(ctx context.Context, coordArg string, f reachabilityFlags, gomodSet bool, stdout, stderr io.Writer) error {
	if err := refuseBothReachabilityTargets(f); err != nil {
		return err
	}
	if coordArg != "" {
		return fmt.Errorf("reachability --local does not take a module argument; use '<module>@<version> --vuln <id>' to query a stored module")
	}
	// The local probe measures the working tree it was pointed at, so it
	// already has a build: accepting a second name for one would invite the
	// reader to think the probe was filtered by it. --gomod carries meaning by
	// its spelling alone (it has a NoOptDefVal), so its presence is asked of
	// cobra as well as of its value, which is empty only when unset.
	if f.walkID != "" || f.gomod != "" || gomodSet {
		return fmt.Errorf("--walk-id and --gomod name a stored build and do not apply to --local, which measures the working tree it is given")
	}
	return runLocalReachability(ctx, f.localPath, stdout, stderr)
}

// runVulnReachability answers "is <vulnID> reachable in <arg>?" by reading the
// reachability verdict persisted by a prior 'vuln-scan --reachability'. It is a
// read-only query: it never scans or recomputes. Absent or undetermined data is
// surfaced as a non-zero, actionable diagnostic (never a false "not reachable"),
// distinguishing "not analysed" from "analysed, genuinely not affected/reachable".
func runVulnReachability(
	ctx context.Context,
	arg, vulnID, walkID, gomod string,
	gomodSet, jsonOut bool,
	uc QueryVulnUseCase,
	walks QueryWalksUseCase,
	graphs QueryCallGraphUseCase,
	stdout io.Writer,
) error {
	coord, err := parseCoordinate(arg)
	if err != nil {
		return fmt.Errorf("invalid coordinate %q: %w", arg, err)
	}

	anchor, anchored, err := resolveVulnFrameAnchor(ctx, walks, walkID, gomod, gomodSet)
	if err != nil {
		return err
	}

	// Every generation is read, not the composed "latest", because which record
	// answers this question is a question about analysis frames and the composed
	// read has none: it ranks an isolated scan against a consumer-rooted one on
	// call-graph completeness, a rung the isolated scan always wins. See
	// vuldomain.ComposeForConsumer.
	var (
		rec      vuldomain.VulnerabilityRecord
		aside    vuldomain.VulnerabilityRecord
		hasAside bool
		found    bool
	)
	if anchored {
		// Anchored: the walk's candidates, ranked within the walk's own frame.
		// The candidate set spans every frame of that generation, so ranking it
		// blind is what answered a corteza question from a langchaingo scan.
		candidates, cerr := uc.ListRecordsForModuleInWalk(ctx, coord, localVulnPipelineVersion, anchor.walkID)
		if cerr != nil {
			return fmt.Errorf("getting vulnerability record: %w", cerr)
		}
		var serr error
		rec, aside, hasAside, found, serr = selectAnchoredRecord(candidates, coord, anchor,
			fmt.Sprintf("kanonarion reachability %s --vuln %s", coord, vulnID))
		if serr != nil {
			return serr
		}
		if !found {
			// Refused rather than answered from a neighbouring frame, and refused
			// here rather than falling through to "the module has not been
			// vuln-scanned" — which would be false about a walk whose candidates
			// exist and simply answer someone else's question.
			return frameRecordAbsence(coord, anchor, candidates)
		}
	} else {
		recs, lerr := uc.ListRecordsForModule(ctx, coord, localVulnPipelineVersion)
		if lerr != nil {
			return fmt.Errorf("getting vulnerability record: %w", lerr)
		}
		// Two consumers' builds, one coordinate, no flag naming which: the store
		// holds two true answers and this question distinguishes neither.
		if frames := consumerFrames(recs, coord); len(frames) > 1 {
			return ambiguousFrameRefusal(
				fmt.Sprintf("kanonarion reachability %s --vuln %s", coord, vulnID), coord, frames)
		}
		rec, aside, hasAside, found = selectConsumerRecord(recs, coord)
	}

	res, verr := vulnReachabilityVerdict(coord, rec, found, vulnID, newRouteRootFunc(ctx, graphs, rec), isolatedAsideFor(aside, hasAside, vulnID))
	if verr != nil {
		return verr
	}

	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			return fmt.Errorf("encoding reachability result: %w", err)
		}
		return nil
	}

	writeFrameAnchorNotice(stdout, anchor, anchored)
	printVulnReachability(stdout, res)
	return nil
}

// selectConsumerRecord picks the record that answers a consumer's reachability
// question about coord, and the isolated-frame record it declined to answer
// from. found is false when the ledger holds nothing for the coordinate at all.
//
// The empty group is answered here rather than propagated as the domain's
// "nothing to compose" error: an unscanned module is an absence the caller
// already reports (with the command that fixes it), not a fault.
func selectConsumerRecord(recs []vuldomain.VulnerabilityRecord, coord coordinate.ModuleCoordinate) (vuldomain.VulnerabilityRecord, vuldomain.VulnerabilityRecord, bool, bool) {
	if len(recs) == 0 {
		return vuldomain.VulnerabilityRecord{}, vuldomain.VulnerabilityRecord{}, false, false
	}
	// The error is discarded because it has exactly one cause — an empty group —
	// and the line above rules it out.
	rec, aside, hasAside, _ := vuldomain.ComposeForConsumer(recs, coord)
	return rec, aside, hasAside, true
}

// isolatedAside is what an isolated-frame record says about the queried
// advisory, carried beside an answer drawn from a consumer-rooted record.
//
// It is reported, and it is never the answer. An isolated scan builds the module
// as its own main module and asks whether that build reaches the vulnerable
// symbol; a consumer's question is whether their build does. Serving the first
// as the second is the false stand-down this type exists to stop, so the verdict
// travels with the frame that produced it, labelled, in its own field.
type isolatedAside struct {
	Verdict    string `json:"verdict"`
	Confidence string `json:"confidence,omitempty"`
	Method     string `json:"method,omitempty"`
	Fidelity   string `json:"fidelity,omitempty"`
	ScannedAt  string `json:"scanned_at,omitempty"`
}

// isolatedAsideFor renders what the isolated-frame record says about vulnID, or
// nil when there is no isolated record, it never saw the advisory, or it
// recorded no reachability answer — an aside with nothing to say is noise beside
// the answer, and an absent verdict is not one.
func isolatedAsideFor(rec vuldomain.VulnerabilityRecord, has bool, vulnID string) *isolatedAside {
	if !has {
		return nil
	}
	f, ok := findFindingByID(rec.Findings, vulnID)
	if !ok || f.Reachable == nil {
		return nil
	}
	verdict := verdictNotReachable
	if f.Reachable.IsReachable {
		verdict = verdictReachable
	}
	return &isolatedAside{
		Verdict:    verdict,
		Confidence: string(f.Reachable.Confidence),
		Method:     f.Reachable.DerivedBy.Analyser.String(),
		Fidelity:   f.Reachable.DerivedBy.Fidelity,
		ScannedAt:  rec.ScannedAt.UTC().Format(time.RFC3339),
	}
}

// vulnReachabilityQuery is the curated, snake_case result of a stored-module
// reachability query for a single CVE. Method records which analysis produced
// the verdict so a future probe-based method is reported, not silently mixed in.
type vulnReachabilityQuery struct {
	Module     string   `json:"module"`
	Version    string   `json:"version"`
	VulnID     string   `json:"vuln_id"`
	Aliases    []string `json:"aliases,omitempty"`
	Summary    string   `json:"summary,omitempty"`
	Verdict    string   `json:"verdict"`
	Confidence string   `json:"confidence,omitempty"`
	// Method is the analyser that produced the stored answer, read off the
	// answer itself. It used to be the constant "call-graph" on every reply,
	// which mislabelled every govulncheck-derived answer in the store — most of
	// them — as one this tool had computed.
	Method string `json:"method"`
	// Fidelity and Rooting complete the derivation: how well the analyser could
	// see, and what the analysis was rooted at. Without the root a route reads
	// as a property of the module, and it is a property of one build.
	Fidelity string `json:"fidelity,omitempty"`
	Rooting  string `json:"rooting,omitempty"`
	// Routes are the paths that reach the vulnerable symbol, entry point first,
	// each hop naming its module and version where the analyser knew them.
	Routes []reachabilityRouteOutput `json:"routes,omitempty"`
	// RouteRoot is the classification of the FIRST route's root, repeated here
	// from routes[0].root so a consumer asking "is this a test-only reach" does
	// not have to index into the route list to find out. It is absent when no
	// route was recorded, because a classification of nothing is not a fact.
	//
	// It qualifies the verdict; it never replaces it. A reachable finding whose
	// root is exported-api is still reachable, and naming the root kind is not a
	// statement that anything is exploitable.
	RouteRoot *routeRootOutput `json:"route_root,omitempty"`
	// IsolatedAside is what an isolated-frame scan of this module says about the
	// same advisory, when the answer above came from a consumer-rooted record and
	// the two frames both hold a verdict. Absent otherwise: an aside beside an
	// answer drawn from the isolated frame itself would be the same record twice.
	IsolatedAside *isolatedAside `json:"isolated_aside,omitempty"`
	// WithdrawnAt is set only on the withdrawn verdict, and carries the retraction
	// timestamp so the answer states its reason rather than asserting a bare
	// negative the reader has to take on trust.
	WithdrawnAt string `json:"withdrawn_at,omitempty"`
	ScannedAt   string `json:"scanned_at,omitempty"`
}

// reachabilityRouteOutput is one route in the curated JSON shape. Versioned
// says whether every hop named its module version: a route from the call-graph
// search never does, and a reader must not take an unversioned route for one
// they can check against their own build.
type reachabilityRouteOutput struct {
	Versioned bool                      `json:"versioned"`
	Frames    []reachabilityFrameOutput `json:"frames"`
	// Root is what sits at this route's entry point, classified against the call
	// graph the answer was computed over. Absent when nothing classified it.
	Root *routeRootOutput `json:"root,omitempty"`
}

// routeRootOutput is one route's root classification in the curated JSON shape.
//
// Reason is emitted beside every kind, not only the unrooted one. The kinds are
// coarse — "ingress" covers a request handler and a package initialiser alike —
// and a consumer that routes on the kind without the reason is drawing a
// distinction the field does not carry.
type routeRootOutput struct {
	Kind   string `json:"kind"`
	Reason string `json:"reason,omitempty"`
	// ClosureRooted says the route does not begin in the module the analysis was
	// rooted at: the application's own entry points were never analysed, so the
	// hop above this root is missing rather than absent.
	ClosureRooted bool `json:"closure_rooted,omitempty"`
	// NodeID is the call-graph node the classification was read off, so a reader
	// can re-run the measurement.
	NodeID string `json:"node_id,omitempty"`
	// Remedy is the command that would answer what this classification could not.
	Remedy string `json:"remedy,omitempty"`
}

// rootToOutput renders a classification, or nil when none was computed.
func rootToOutput(root vuldomain.RouteRoot) *routeRootOutput {
	if !root.IsRecorded() {
		return nil
	}
	return &routeRootOutput{
		Kind:          root.Kind.String(),
		Reason:        root.Reason,
		ClosureRooted: root.ClosureRooted,
		NodeID:        root.NodeID,
		Remedy:        root.Remedy,
	}
}

// reachabilityFrameOutput is one hop.
type reachabilityFrameOutput struct {
	Module   string `json:"module,omitempty"`
	Version  string `json:"version,omitempty"`
	Package  string `json:"package,omitempty"`
	Receiver string `json:"receiver,omitempty"`
	Symbol   string `json:"symbol,omitempty"`
}

// routesToOutput renders stored routes for the curated JSON shape, classifying
// each route's root as it goes.
//
// Every route is classified, not only the one the text presenter prints. Two
// routes to one symbol can start in entirely different places — a handler and a
// test — and a consumer reading the list must not have to assume they share the
// first one's root.
func routesToOutput(routes []vuldomain.ReachabilityRoute, classify routeRootFunc) []reachabilityRouteOutput {
	if len(routes) == 0 {
		return nil
	}
	out := make([]reachabilityRouteOutput, 0, len(routes))
	for _, r := range routes {
		frames := make([]reachabilityFrameOutput, 0, len(r))
		for _, f := range r {
			frames = append(frames, reachabilityFrameOutput{
				Module: f.ModulePath, Version: f.ModuleVersion,
				Package: f.Package, Receiver: f.Receiver, Symbol: f.Symbol,
			})
		}
		out = append(out, reachabilityRouteOutput{
			Versioned: r.IsVersioned(),
			Frames:    frames,
			Root:      rootToOutput(classify(r)),
		})
	}
	return out
}

// firstRouteRoot lifts the first route's classification to the reply level.
func firstRouteRoot(routes []reachabilityRouteOutput) *routeRootOutput {
	if len(routes) == 0 {
		return nil
	}
	return routes[0].Root
}

// vulnReachabilityVerdict is the pure classifier (no I/O) so the intent-aware
// distinctions are unit-testable from constructed records. It returns either a
// confident result (reachable / not_reachable / not_affected) for exit 0, or a
// directing error for the cases where the answer is genuinely unknown.
//
// aside is what the isolated frame says about the same advisory, when the record
// being classified came from a consumer-rooted one. It rides along on every
// answer this returns; it is never consulted to reach one.
func vulnReachabilityVerdict(coord coordinate.ModuleCoordinate, rec vuldomain.VulnerabilityRecord, found bool, vulnID string, classify routeRootFunc, aside *isolatedAside) (vulnReachabilityQuery, error) {
	res, err := vulnReachabilityAnswer(coord, rec, found, vulnID, classify, aside)
	if err != nil {
		return vulnReachabilityQuery{}, err
	}
	res.IsolatedAside = aside
	return res, nil
}

// vulnReachabilityAnswer is the classification itself. It is split from the
// function above only so the aside is attached in one place instead of on each
// of the replies below.
func vulnReachabilityAnswer(coord coordinate.ModuleCoordinate, rec vuldomain.VulnerabilityRecord, found bool, vulnID string, classify routeRootFunc, aside *isolatedAside) (vulnReachabilityQuery, error) {
	if classify == nil {
		classify = unclassifiedRoutes
	}
	if !found {
		return vulnReachabilityQuery{}, &exitError{code: ExitNotFound, msg: fmt.Sprintf(
			"no vulnerability record for %s: the module has not been vuln-scanned. %s",
			coord, remedyScanModule(coord))}
	}

	// Whether reachability could have been computed is a coverage question, so it
	// is asked of the coverage axis rather than the collapsed word. A metadata-only
	// record that matched an advisory summarises as Affected, so this switch missed
	// it and the answer fell through to the finding lookup below, which reported
	// "the module was scanned without --reachability" — naming a flag the operator
	// did pass, for a module whose source could never be analysed at all.
	coverage, _ := vuldomain.RecordAxes(rec)
	switch coverage {
	case vuldomain.CoverageFailedScan:
		detail := ""
		if rec.ErrorDetail != "" {
			detail = ": " + rec.ErrorDetail
		}
		return vulnReachabilityQuery{}, fmt.Errorf(
			"%s could not be scanned (ScanFailed)%s; reachability is unknown. %s",
			coord, detail, remedyRescanModule(coord))
	case vuldomain.CoverageUnscannable:
		detail := ""
		if rec.UnscannableReason != "" {
			detail = ": " + rec.UnscannableReason
		}
		return vulnReachabilityQuery{}, fmt.Errorf(
			"%s is unscannable%s; reachability cannot be determined. %s",
			coord, detail, remedyShowRecord(coord))
	case vuldomain.CoverageAnalysed:
		// Analysed: the findings below are an answer about a module that was read.
	}

	// The module was analysed, so its findings answer the question.
	f, ok := findFindingByID(rec.Findings, vulnID)
	if !ok {
		// Genuine zero: the scan ran and this CVE is not among its findings.
		return vulnReachabilityQuery{
			Module:  coord.Path(),
			Version: coord.Version(),
			VulnID:  vulnID,
			Verdict: verdictNotAffected,
			// No Method: this reply is a statement about the advisory set, not the
			// output of a reachability analyser. Naming one would attribute an
			// answer to an instrument that was never consulted.
			Method:    reachabilityMethodNone,
			ScannedAt: rec.ScannedAt.UTC().Format(time.RFC3339),
		}, nil
	}

	// The retraction is answered before reachability is consulted, because it makes
	// the reachability question moot: whether anything calls the symbol does not
	// matter for an advisory that no longer stands, and the two directing errors
	// below would otherwise send the operator to compute a call graph for it.
	if f.IsWithdrawn() {
		return vulnReachabilityQuery{
			Module:  coord.Path(),
			Version: coord.Version(),
			VulnID:  f.ID,
			Aliases: f.Aliases,
			Summary: f.Summary,
			Verdict: verdictWithdrawn,
			// No Method, for the reason given on the not-affected reply above: a
			// retraction is read off the advisory, not computed.
			Method:      reachabilityMethodNone,
			WithdrawnAt: f.WithdrawnAt.UTC().Format(time.RFC3339),
			ScannedAt:   rec.ScannedAt.UTC().Format(time.RFC3339),
		}, nil
	}

	// A nil Reachable is asked WHY before it is explained. It has more than one
	// cause, and the record is the only thing that can say which: attributing it to
	// a missing flag when the flag was passed and the analysis failed sends the
	// operator to re-run a command that already ran, and buries the failure the
	// message exists to surface.
	if f.ReachabilityAttemptFailed() {
		return vulnReachabilityQuery{}, fmt.Errorf(
			"reachability was requested for %s in %s and could not be computed: %s\nThe scan recorded the attempt. Re-run the same scan once that cause is resolved — a per-module re-run would root the analysis at %s rather than at the project, and would not reproduce the route this scan was asked for",
			f.ID, coord, f.ReachabilityNote, coord.Path())
	}

	if f.Reachable == nil {
		return vulnReachabilityQuery{}, nilReachabilityRefusal(coord, rec, f, aside)
	}

	// Answered before the undetermined-confidence diagnostic below, because that
	// diagnostic sends the operator to compute a call graph — advice which cannot
	// help here. No graph resolves a symbol the advisory never named, and the
	// scan that produced this record did run.
	if f.AdvisoryNamesNoSymbols {
		routes := routesToOutput(f.Reachable.Routes, classify)
		return vulnReachabilityQuery{
			Module:     coord.Path(),
			Version:    coord.Version(),
			VulnID:     f.ID,
			Aliases:    f.Aliases,
			Summary:    f.Summary,
			Verdict:    verdictPackageLevelOnly,
			Confidence: string(f.Reachable.Confidence),
			Method:     f.Reachable.DerivedBy.Analyser.String(),
			Fidelity:   f.Reachable.DerivedBy.Fidelity,
			Rooting:    f.Reachable.DerivedBy.Rooting.String(),
			Routes:     routes,
			RouteRoot:  firstRouteRoot(routes),
			ScannedAt:  rec.ScannedAt.UTC().Format(time.RFC3339),
		}, nil
	}

	if f.Reachable.Confidence == vuldomain.ConfidenceUnknown {
		return vulnReachabilityQuery{}, fmt.Errorf(
			"reachability for %s in %s is undetermined: the call graph was unavailable during the scan. %s",
			f.ID, coord, remedyRebuildGraphThenRescan(coord))
	}

	verdict := verdictNotReachable
	if f.Reachable.IsReachable {
		verdict = verdictReachable
	}
	routes := routesToOutput(f.Reachable.Routes, classify)
	return vulnReachabilityQuery{
		Module:     coord.Path(),
		Version:    coord.Version(),
		VulnID:     f.ID,
		Aliases:    f.Aliases,
		Summary:    f.Summary,
		Verdict:    verdict,
		Confidence: string(f.Reachable.Confidence),
		Method:     f.Reachable.DerivedBy.Analyser.String(),
		Fidelity:   f.Reachable.DerivedBy.Fidelity,
		Rooting:    f.Reachable.DerivedBy.Rooting.String(),
		Routes:     routes,
		RouteRoot:  firstRouteRoot(routes),
		ScannedAt:  rec.ScannedAt.UTC().Format(time.RFC3339),
	}, nil
}

// nilReachabilityRefusal names the cause of a finding that carries no
// reachability answer, reading it off the record rather than assuming one.
//
// There is more than one cause and they take opposite remedies, so a message
// that assumes is worse than no message at all. This one asserted the module had
// been "scanned without --reachability" for every nil answer. For a module whose
// newest scan was rooted at ITSELF that claim is contradicted by the record it
// was printed from: the scan did run with --reachability, and the finding has no
// route because a module rooted at itself is the analysis's own main module —
// version-range advisory matching never fires on a main module, so the finding
// is attributed by coordinate, and there is no consumer above it for a route to
// start from. Re-running the named remedy produced the identical refusal, whose
// stated cause was by then demonstrably false.
//
// The absence itself is correct in that case: declining to name a route is the
// tool refusing to fabricate one. Only the explanation was wrong.
func nilReachabilityRefusal(coord coordinate.ModuleCoordinate, rec vuldomain.VulnerabilityRecord, f vuldomain.VulnerabilityFinding, aside *isolatedAside) error {
	// Answered first, because it is the one cause no rooting and no re-run can
	// change. The reachability leg skips a finding that carries no symbols to
	// search for, leaving the same nil answer and the same empty note as an
	// unrequested one — so this record too was being reported as a missing flag,
	// for a question that had no target whichever flags were passed.
	if f.AdvisoryNamesNoSymbols {
		return fmt.Errorf(
			"no symbol-level reachability for %s in %s: the advisory names no symbols for this module path, so there was never a symbol to search for — the module is affected at package level and no flag or re-scan changes that. %s",
			f.ID, coord, remedyShowRecord(coord))
	}
	if rec.Rooting.IsRootedAt(coord) {
		return fmt.Errorf(
			"no reachability route for %s in %s: the scan WAS run with reachability, but it was rooted at %s — the module is its own root, so no consumer entry point exists for a route to start from and none is fabricated. %s",
			f.ID, coord, rec.Rooting.RootTarget(), remedyProjectRooted())
	}
	// The isolated frame HAS a verdict and it is deliberately not being served.
	// Saying so is the whole point of the refusal: without it the operator reads
	// "reachability was not computed" for a module the tool holds a confident
	// not-reachable on, goes looking for it, finds it, and concludes the refusal
	// was a bug. The verdict is named and its frame is named with it, so what is
	// being declined is the transfer across the frame boundary, not the evidence.
	if aside != nil {
		return fmt.Errorf(
			"no reachability answer for %s in %s in the frame that was asked about: the best-founded analysis in a consumer frame (%s) recorded no route, and the answer is not taken from the isolated-frame scan of %s (%s at confidence %s, by %s), which asks whether the module reaches its own vulnerable code when built alone — a different question, and not evidence about the build that consumes it. %s",
			f.ID, coord, rec.Rooting.String(), coord.Path(), aside.Verdict, aside.Confidence, aside.Method, remedyProjectRooted())
	}
	return fmt.Errorf(
		"reachability was not computed for %s in %s (the module was scanned without --reachability). %s",
		f.ID, coord, remedyRebuildGraphThenRescan(coord))
}

// findFindingByID matches a vulnerability ID against each finding's primary ID
// and its aliases, case-insensitively (GO-, CVE-, GHSA- IDs are referenced
// interchangeably).
func findFindingByID(findings []vuldomain.VulnerabilityFinding, vulnID string) (vuldomain.VulnerabilityFinding, bool) {
	for _, f := range findings {
		if strings.EqualFold(f.ID, vulnID) {
			return f, true
		}
		for _, a := range f.Aliases {
			if strings.EqualFold(a, vulnID) {
				return f, true
			}
		}
	}
	return vuldomain.VulnerabilityFinding{}, false
}

// derivationLine renders the instrument, how well it could see and what it was
// rooted at, for the one-line summary.
func derivationLine(res vulnReachabilityQuery) string {
	parts := []string{"by: " + res.Method}
	if res.Fidelity != "" {
		parts = append(parts, "fidelity: "+res.Fidelity)
	}
	if res.Rooting != "" {
		parts = append(parts, "rooted at: "+res.Rooting)
	}
	return strings.Join(parts, ", ")
}

// printRoute prints the first stored route, hop by hop, and says plainly when
// the hops carry no versions — an unversioned route cannot be checked against
// another build, and a reader who assumes it can will draw the wrong conclusion
// about their own.
func printRoute(stdout io.Writer, res vulnReachabilityQuery) {
	if len(res.Routes) == 0 {
		return
	}
	r := res.Routes[0]
	label := "  route (entry point first):"
	if !r.Versioned {
		label = "  route (entry point first; hops carry no module version, so it cannot be checked against another build):"
	}
	_, _ = fmt.Fprintln(stdout, label)
	for _, f := range r.Frames {
		_, _ = fmt.Fprintf(stdout, "    %s\n", frameLine(f))
	}
	printRouteRoot(stdout, r.Root)
	if len(res.Routes) > 1 {
		_, _ = fmt.Fprintf(stdout, "    (%d further route(s) recorded)\n", len(res.Routes)-1)
	}
}

// printRouteRoot prints the evidence behind the root tag on the verdict line.
//
// The kind is on the verdict line so it cannot be missed; the reason is here,
// under the route it describes, because that is where a reader checks it. Both
// are needed: the kind alone is a label, and a label is what turns a measurement
// into a verdict.
func printRouteRoot(stdout io.Writer, root *routeRootOutput) {
	if root == nil {
		return
	}
	_, _ = fmt.Fprintf(stdout, "  root: %s — %s\n", root.Kind, root.Reason)
	if root.NodeID != "" {
		_, _ = fmt.Fprintf(stdout, "    node: %s\n", root.NodeID)
	}
	if root.ClosureRooted {
		_, _ = fmt.Fprintln(stdout, "    closure-rooted: the route does not begin in the module the analysis was rooted at, so the application's own entry points were not analysed")
	}
	if root.Remedy != "" {
		_, _ = fmt.Fprintf(stdout, "    to go further: %s\n", root.Remedy)
	}
}

// frameLine renders one hop, omitting the parts the analyser could not supply.
func frameLine(f reachabilityFrameOutput) string {
	var b strings.Builder
	if f.Module != "" {
		b.WriteString(f.Module)
		if f.Version != "" {
			b.WriteString("@")
			b.WriteString(f.Version)
		}
		b.WriteString(" ")
	}
	if f.Package != "" && f.Package != f.Module {
		b.WriteString(f.Package)
		b.WriteString(".")
	}
	if f.Receiver != "" {
		b.WriteString("(")
		b.WriteString(f.Receiver)
		b.WriteString(").")
	}
	b.WriteString(f.Symbol)
	return strings.TrimSpace(b.String())
}

// printIsolatedAside prints what the isolated frame said, under the answer and
// visibly subordinate to it.
//
// It is printed rather than dropped because the two frames disagreeing is itself
// information — on the store this was measured against, the isolated scan said
// NOT reachable while the consumer's build carried a route to the symbol — and a
// reader who has seen the isolated verdict elsewhere is owed the reason it is not
// the headline.
func printIsolatedAside(stdout io.Writer, aside *isolatedAside) {
	if aside == nil {
		return
	}
	_, _ = fmt.Fprintf(stdout,
		"  isolated frame (a different question — the module built alone, not the build that consumes it): %s [confidence: %s, by: %s]\n",
		aside.Verdict, aside.Confidence, aside.Method)
}

func printVulnReachability(stdout io.Writer, res vulnReachabilityQuery) {
	coord := res.Module + "@" + res.Version
	switch res.Verdict {
	case verdictReachable:
		// The root tag rides on the verdict line rather than under the route,
		// because one of its five values is a warning: a test-scope root read as a
		// production reach is the misreading this classification exists to prevent,
		// and a line further down is a line that gets skipped.
		_, _ = fmt.Fprintf(stdout, "%s is REACHABLE in %s [confidence: %s, %s]%s\n",
			res.VulnID, coord, res.Confidence, derivationLine(res), rootTagFromOutput(res.RouteRoot))
		printRoute(stdout, res)
	case verdictNotReachable:
		// The derivation is printed on the negative too. "Not reachable" from a
		// metadata-only graph and from a built one are different claims, and the
		// negative is the one an operator acts on by NOT upgrading.
		_, _ = fmt.Fprintf(stdout, "%s affects %s but is NOT reachable [confidence: %s, %s]\n", res.VulnID, coord, res.Confidence, derivationLine(res))
	case verdictPackageLevelOnly:
		// Says plainly that the module IS affected, then that the question of
		// whether the vulnerable code runs has no answer here and why. The route is
		// printed if one somehow exists, so the reply never hides evidence it holds.
		_, _ = fmt.Fprintf(stdout, "%s affects %s at PACKAGE level; symbol-level reachability is not determined — the advisory names no symbols for this module path [confidence: %s, %s]%s\n",
			res.VulnID, coord, res.Confidence, derivationLine(res), rootTagFromOutput(res.RouteRoot))
		printRoute(stdout, res)
	case verdictNotAffected:
		_, _ = fmt.Fprintf(stdout, "%s is not affected by %s (scanned %s)\n", coord, res.VulnID, res.ScannedAt)
	case verdictWithdrawn:
		_, _ = fmt.Fprintf(stdout, "%s was WITHDRAWN upstream %s — %s is not affected by it (scanned %s)\n",
			res.VulnID, res.WithdrawnAt, coord, res.ScannedAt)
	}
	printIsolatedAside(stdout, res.IsolatedAside)
}

func runLocalReachability(ctx context.Context, dir string, stdout, stderr io.Writer) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("resolving path %q: %w", dir, err)
	}
	out, err := runLocalReachabilityInner(ctx, abs, stderr)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding reachability result: %w", err)
	}
	if _, err := fmt.Fprintf(stdout, "%s\n", raw); err != nil {
		return fmt.Errorf("writing reachability result: %w", err)
	}
	return nil
}

// runLocalReachabilityInner opens the store and runs the reachability use case,
// returning the serialisable output. Used by both the standalone reachability
// command and the --reachability flag on context.
func runLocalReachabilityInner(ctx context.Context, abs string, stderr io.Writer) (reachabilityOutput, error) {
	dbPath := filepath.Join(storeRoot, "mirror.db")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return reachabilityOutput{}, fmt.Errorf("store not found at %s: run a kanonarion command to initialise it", dbPath)
	}

	logger := buildLogger(logLevel, stderr)
	ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
	if err != nil {
		return reachabilityOutput{}, fmt.Errorf("initialising store: %w", err)
	}
	defer func() { _ = cleanup() }()

	vulnLoader := localvulnstore.New(ctr.VulnStore, localVulnPipelineVersion)
	uc := localapp.NewLocalReachabilityUseCase(
		localsnapshot.Builder{},
		localimporter.New(""),
		vulnLoader,
		localprober.New(""),
		clock.System{},
	)

	result, err := uc.Execute(ctx, abs)
	if err != nil {
		return reachabilityOutput{}, fmt.Errorf("local reachability analysis: %w", err)
	}

	return reachabilityResultToOutput(result), nil
}

func reachabilityResultToOutput(r localdomain.LocalReachabilityResult) reachabilityOutput {
	mods := make([]reachabilityModule, 0, len(r.Modules))
	for _, m := range r.Modules {
		findings := make([]reachabilityFinding, 0, len(m.Findings))
		for _, f := range m.Findings {
			findings = append(findings, reachabilityFinding{
				CVEID:           f.CVEID,
				Aliases:         f.Aliases,
				Summary:         f.Summary,
				Verdict:         string(f.Verdict),
				VerdictSource:   string(f.VerdictSource),
				Reason:          f.Reason,
				MatchedSymbols:  f.MatchedSymbols,
				MatchedBinaries: f.MatchedBinaries,
			})
		}
		mods = append(mods, reachabilityModule{
			Path:     m.Path,
			Version:  m.Version,
			Findings: findings,
		})
	}
	return reachabilityOutput{
		Root:            r.Root,
		ModulePath:      r.ModulePath,
		VersionID:       r.VersionID,
		ProbeKind:       r.ProbeKind,
		SeedRestriction: r.SeedRestriction,
		Notice:          r.Notice,
		Coverage:        coverageToOutput(r.Coverage),
		Modules:         mods,
	}
}

// coverageToOutput renders the probe's coverage, attaching the remedy that
// brings uncovered modules into a later answer.
//
// The remedy is built here rather than in the use case for the reason every
// remedy in this file is: the invocations are contract-tested against the CLI's
// own parser, and a command line assembled below the CLI is one nothing checks.
func coverageToOutput(c localdomain.ProbeCoverage) reachabilityCoverage {
	out := reachabilityCoverage{
		SnapshotTakenAt:     c.TakenAt.UTC().Format(time.RFC3339),
		BuildModules:        c.BuildModules,
		QueriedModules:      c.Queried,
		CoveredModules:      c.Covered,
		ModulesWithFindings: c.WithFindings,
	}
	for _, u := range c.Uncovered {
		out.UncoveredModules = append(out.UncoveredModules, reachabilityUncovered{
			Path: u.Path, Version: u.Version, Reason: u.Reason,
		})
	}
	if len(out.UncoveredModules) > 0 {
		out.UncoveredRemedy = remedyScanUncovered().String()
	}
	for _, b := range c.Binaries {
		out.ProbedBinaries = append(out.ProbedBinaries, reachabilityProbedBinary{
			ImportPath: b.ImportPath, BuildError: b.BuildError,
		})
	}
	return out
}
