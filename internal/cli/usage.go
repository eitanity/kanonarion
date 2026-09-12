package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/mod/semver"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/gotoolchain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// usageConfidenceNote is the distinction the whole report rests on, printed
// where the reader meets the counts rather than in a footer.
//
// Only a Direct edge names a unique concrete callee. Every other confidence is
// an over-approximation of a dispatch the analyser could not resolve, and CHA
// answers such a site with every type-compatible function in the module at once
// — measured on one project, 4 call sites naming 14 symbols. Merging those into
// a usage count reports functions the project never calls.
const usageConfidenceNote = "established use is a Direct call edge: one that names a unique concrete callee. " +
	"An edge of any other confidence is an unresolved dispatch the analysis over-approximated, " +
	"so it names every type-compatible function in the module rather than the one that runs. " +
	"Those are reported below as their own class and are in no count above."

// usageUnmeasuredKindsLead names the declarations this report cannot see at all.
// Their absence from the lists above is an absence of measurement, not of use.
const usageUnmeasuredKindsLead = "unmeasured: types, constants and variables have no call-graph node, so no use of " +
	"one appears anywhere in this report. List them with: "

// usageUnmeasuredKindsNote is the lead with the invocation that carries it out.
//
// interface-show reads a stored interface record and refuses a module that has
// none, naming 'kanonarion interface'; that command in turn reads fetched bytes
// and refuses a module the store has not fetched. Naming only the last step
// therefore costs the reader two round trips, so the whole chain is named — see
// usageMeasureRemedy for the rule.
func usageUnmeasuredKindsNote(coord coordinate.ModuleCoordinate) string {
	line := "kanonarion interface-show " + coord.String()
	if cgdomain.IsReFetchable(coord) {
		line = "kanonarion fetch " + coord.String() +
			" && kanonarion interface " + coord.String() + " && " + line
	}
	return usageUnmeasuredKindsLead + line
}

// usageMeasureRemedy names the commands that put a stored call graph for coord
// in the store, as one line a reader can paste.
//
// Both commands are named because the first creates what the second resolves.
// 'kanonarion callgraph' reads bytes the store already holds: handed a module
// it has not fetched it exits 20 with "module not fetched: run 'kanonarion
// fetch <coord>' first", so a remedy naming it alone costs the reader exactly
// the round trip the remedy existed to save. Fetching a module the store
// already holds returns its verified record immediately, so the pair is right
// whether or not the bytes are there — the same reasoning, and the same shape,
// as the licence-record remedy in provenance_basis.go.
//
// force is owed exactly when a stored record would otherwise answer the re-run,
// which is what RecordIsCacheable decides. A caller holding no record passes
// false: there is nothing for the re-run to be served.
func usageMeasureRemedy(coord coordinate.ModuleCoordinate, force bool) string {
	reanalyse := cgdomain.ReanalysisInstruction(coord, "")
	if force {
		reanalyse = cgdomain.ForcedReanalysisInstruction(coord, "")
	}
	// A project coordinate names a working tree rather than a published artefact,
	// so there is nothing to fetch and no fetch can ever satisfy it.
	if !cgdomain.IsReFetchable(coord) {
		return reanalyse
	}
	return "kanonarion fetch " + coord.String() + " && " + reanalyse
}

// usageSatisfactionNote states the one axis of a migration inventory this report
// cannot measure, and what does measure it.
//
// The satisfaction relation is computed over ONE module's own declarations on
// both sides, so a project type satisfying a dependency's interface is in no
// stored record. Naming the interfaces is what a reader can act on; claiming
// they are unsatisfied would be a measurement nothing took.
const usageSatisfactionNote = "not measured: whether this project's own types satisfy one of these interfaces. " +
	"The satisfaction relation is computed within a single module, so no stored record holds it " +
	"across the project/dependency boundary — including the embedding case, which no text search finds either."

// usageEdgeKindCall and usageEdgeKindReference are how a site is labelled. A
// reference is the function VALUE being taken, which is use of the symbol and is
// never an invocation.
const (
	usageEdgeKindCall      = "call"
	usageEdgeKindReference = "reference"
)

func newUsageCmd(stdout, stderr io.Writer) *cobra.Command {
	var scopeFlags buildScopeFlags

	cmd := &cobra.Command{
		Use: "usage <module>@<version>",
		Annotations: map[string]string{
			annotationStoreIntent: StoreIntentRead,
			annotationNetworkUse:  NetworkNever,
		},
		Short: "Report what the analysed project's own code uses from one dependency",
		Long: `usage reports what one project's own code uses from one of its dependencies:
which symbols, at how many sites, in which files, and which of the module's
public API it never calls.

Only a Direct call edge counts as use. An edge of any other confidence is an
unresolved dispatch the analysis over-approximated across every type-compatible
function in the module, so those are reported as their own class and never
merged into a usage count.

Production and test sites are counted separately and never summed.

An edge to the module's own init is linkage — the calling package imports it —
and is reported as an import count rather than as use.

The report names the version it measured, which is the version asked for
whenever the store holds a call graph for it and another version of the same
path when it does not. With no stored call graph at any version, nothing about
the module was enumerated and the answer is UNRESOLVED rather than a zero.

A module the named build does not contain is answered, not refused: asking what
your code already does with a module you have not adopted is what a migration
needs. 'kanonarion callers' refuses that coordinate, being scoped to the walk.

It reads the project's stored call graph; run 'kanonarion local .' first, and
'kanonarion fetch <module>@<version> && kanonarion callgraph <module>@<version>'
for the module whose surface is being compared against — callgraph reads bytes
the store already holds and refuses a module it has not fetched.`,
		Example: `  kanonarion usage github.com/spf13/cast@v1.7.0
  kanonarion usage github.com/spf13/cast@v1.7.0 --gomod ./go.mod
  kanonarion usage github.com/spf13/cast@v1.7.0 --json
  kanonarion usage github.com/spf13/cast@v1.7.0 --walk-id 01M0RE94X8VJ8C0PT9Z3VJJQ0S`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageErr(cmd)
			}
			if berr := scopeFlags.bind(cmd); berr != nil {
				return berr
			}
			return runUsage(cmd.Context(), args[0], scopeFlags, stdout, stderr)
		},
	}

	registerBuildScopeFlags(cmd, &scopeFlags)
	return cmd
}

func runUsage(ctx context.Context, arg string, f buildScopeFlags, stdout, stderr io.Writer) error {
	coord, err := parseCoordinate(arg)
	if err != nil {
		return fmt.Errorf("invalid coordinate %q: %w", arg, err)
	}
	if f.walkID != "" && f.gomodSet {
		return fmt.Errorf("--walk-id and --gomod are mutually exclusive: both name a build, and they may name different ones")
	}

	logger := buildLogger(logLevel, stderr)
	ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() { _ = cleanup() }()

	return usageWith(ctx, ctr, coord, f, stdout, stderr)
}

// usageWith holds the command's logic over an injected Container so the join is
// exercisable without a live store.
func usageWith(ctx context.Context, ctr *Container, coord coordinate.ModuleCoordinate, f buildScopeFlags, stdout, stderr io.Writer) error {
	sel := consumerSelector{
		gomod:     f.gomod,
		walkID:    f.walkID,
		toolchain: gotoolchain.Version(f.toolchain),
	}
	bound, err := bindConsumer(ctx, ctr.QueryWalks, ctr.QueryCallGraph, sel)
	if err != nil {
		if errors.Is(err, walkports.ErrWalkNotFound) {
			return walkIDMiss(ctx, ctr.QueryWalks, f.walkID, stderr)
		}
		return err
	}
	if !bound.CallGraphFound {
		return &exitError{code: ExitNotFound, msg: fmt.Sprintf(
			"no stored call graph for %s, so nothing can be measured about what its code uses — "+
				"run: kanonarion local .", bound.Consumer)}
	}

	report, err := joinUsage(ctx, ctr.QueryCallGraph, bound, coord, sel.toolchain)
	if err != nil {
		return err
	}

	if jsonOut {
		if encErr := encodeJSON(stdout, toUsageJSON(report)); encErr != nil {
			return encErr
		}
		return usageVerdictExit(report)
	}
	// Which checkout of the project answered is invisible and decides the answer:
	// a store holding two analysed trees of one module serves the one the reader
	// is standing in. The same disclosure `callers` and `implementers` make.
	if werr := writeWorktreeNoticeFor(ctx, bound.Consumer, ctr.QueryCallGraph, stdout); werr != nil {
		return werr
	}
	if perr := printUsageReport(stdout, report); perr != nil {
		return perr
	}
	return usageVerdictExit(report)
}

// -- the join --

// usageSite is one recorded edge from the project's own code into the module.
type usageSite struct {
	// Caller is the project function the edge leaves, and File/Line the position
	// the edge was recorded at — the call site itself, not the caller's
	// declaration.
	Caller string
	File   string
	Line   int
	IsTest bool
	Kind   string
}

// usageSymbol is one symbol of the module together with the project's edges into
// it. Production and test are separate counts and are never summed: a migration
// scoped from a merged count moves the wrong amount of code.
type usageSymbol struct {
	NodeID     string
	Production int
	Test       int
	// References is how many of the sites take the function as a VALUE rather
	// than call it. Use of the symbol either way, never an invocation.
	References int
	Sites      []usageSite
}

// Sites is the total edge count, stated as a method so no caller has to add the
// two axes back together and none of them stores a merged number.
func (s usageSymbol) edgeCount() int { return s.Production + s.Test }

// usageReport is what one project's own code does with one module.
type usageReport struct {
	consumerBinding
	// Module is the ONE coordinate this report is about: the version whose
	// stored call graph was read. Every line that names a module names this one.
	Module coordinate.ModuleCoordinate
	// Requested is the coordinate the caller typed. It differs from Module when
	// the version asked for has no stored call graph, and it is then stated
	// wherever leaving it out would read as a measurement of it.
	Requested coordinate.ModuleCoordinate
	// VersionBasis is how Module was arrived at from Requested.
	VersionBasis usageVersionBasis
	// ModuleInBuild reports whether the answering walk resolves the measured
	// coordinate, and ModulePathInBuild whether it contains the path at any
	// version. The two are separate disclosures: a module the build has not got
	// at all is the migration question this command exists for, while a module
	// present at another version means the sites below were recorded against one
	// version and the public API enumerated from another.
	ModuleInBuild     bool
	ModulePathInBuild bool
	// BuildVersions are the versions the answering walk resolves for the path.
	BuildVersions []string
	// ModuleGraphFound reports whether a call graph was served for the module at
	// any version. Without it the public-API population is unknown, so Unreached
	// is unmeasured rather than empty.
	//
	// It is not on its own what licenses a claim of absence: a served record can
	// enumerate nothing at all. surfaceEnumerated is that question.
	ModuleGraphFound bool
	// ModuleRecord is the module's own stored call graph, zero when none was
	// served. The verdict reads its status to say WHY a public API of zero is not
	// a module with no public API, and its cause to say whether a re-measure
	// would be served the same record back.
	ModuleRecord cgdomain.CallGraphRecord

	// Used are the symbols reached by a Direct edge, sorted by node ID.
	Used []usageSymbol
	// Dispatch are the symbols reached only by an over-approximated edge, sorted
	// by node ID, and DispatchSites the distinct sites those edges leave from.
	// One site commonly appears against many symbols, which is the shape that
	// makes the class a fan-out rather than a set of calls.
	Dispatch      []usageSymbol
	DispatchSites []usageSite
	// LinkedPackages are the project's packages that import the module, read off
	// the edges into the module's own init.
	LinkedPackages []string
	// Unreached are the module's public API nodes with no Direct edge from the
	// project, sorted. PublicAPI is the population they were drawn from.
	Unreached []string
	PublicAPI int
	// Interfaces are the interface types the module declares. Whether the
	// project's own types satisfy one is not measured — see usageSatisfactionNote.
	Interfaces []string
}

// joinUsage reads the project's own call graph once and classifies every edge
// whose callee belongs to the module.
//
// It reads the record rather than querying the edge index because the class this
// report turns on — the call SITE of each edge — is on the record's edges and
// not on an edge query's result. One read also cannot disagree with itself about
// which generation answered.
func joinUsage(
	ctx context.Context,
	graphs QueryCallGraphUseCase,
	bound *consumerBinding,
	requested coordinate.ModuleCoordinate,
	toolchain gotoolchain.Version,
) (*usageReport, error) {
	// One listing, unrestricted, feeding both the version resolution and the
	// owning-module candidates. Restricting it to the build would hide from both
	// exactly what this command exists to answer about: a module the build has
	// not got.
	stored, err := listStoredCoordinates(ctx, graphs, coordinate.ModuleSet{})
	if err != nil {
		return nil, err
	}
	res, err := resolveUsageModule(ctx, graphs, requested, bound.Scope, toolchain, stored)
	if err != nil {
		return nil, err
	}
	module := res.Measured
	rep := &usageReport{
		consumerBinding:   *bound,
		Module:            module,
		Requested:         res.Requested,
		VersionBasis:      res.Basis,
		ModuleInBuild:     bound.Scope.Contains(module),
		ModulePathInBuild: bound.Scope.HasPath(module.Path()),
		BuildVersions:     bound.Scope.VersionsOf(module.Path()),
		ModuleGraphFound:  res.Found,
		ModuleRecord:      res.Record,
	}

	owners := usageModulePaths(bound.Scope, stored, bound.Record, module)
	nodes := bound.nodesByID()

	used := map[string]*usageSymbol{}
	dispatch := map[string]*usageSymbol{}
	linked := map[string]struct{}{}
	sites := map[usageSite]struct{}{}

	for _, e := range bound.Record.Edges {
		owner, ok := cgdomain.ResolveSymbolModule(e.ToID, owners)
		if !ok || owner != module.Path() {
			continue
		}
		callee := nodes[e.ToID]
		caller := nodes[e.FromID]
		site := usageSite{
			Caller: e.FromID,
			File:   e.CallSite.File,
			Line:   e.CallSite.Line,
			IsTest: caller.IsTest,
			Kind:   usageEdgeKindCall,
		}
		if e.Kind.IsReference() {
			site.Kind = usageEdgeKindReference
		}

		switch {
		case e.Confidence == cgdomain.ConfidenceDirect && callee.Symbol == "init" && callee.Receiver == "":
			// An edge into the module's own package initialiser says the calling
			// package imports the module. That is linkage, not use, and the same
			// distinction `capability` records as its linkage_only basis.
			if caller.Package != "" {
				linked[caller.Package] = struct{}{}
			}
		case e.Confidence == cgdomain.ConfidenceDirect:
			addUsageEdge(used, e.ToID, site)
		default:
			addUsageEdge(dispatch, e.ToID, site)
			sites[usageSite{File: site.File, Line: site.Line, Caller: site.Caller, IsTest: site.IsTest, Kind: site.Kind}] = struct{}{}
		}
	}

	rep.Used = sortedUsageSymbols(used)
	rep.Dispatch = sortedUsageSymbols(dispatch)
	rep.DispatchSites = sortedUsageSites(sites)
	rep.LinkedPackages = sortedKeysOf(linked)

	if res.Found {
		usageModuleSurface(rep, res.Record, module, owners)
	}
	return rep, nil
}

// -- which version was measured --

// usageVersionBasis names how the measured coordinate was arrived at from the
// one the caller typed.
type usageVersionBasis string

const (
	// usageVersionAsRequested: the store holds a call graph for the version
	// asked for, and that is the one read.
	usageVersionAsRequested usageVersionBasis = "as_requested"
	// usageVersionBuildResolved: the version asked for has no stored call graph,
	// and the build resolves the path to one that does. That version is also the
	// one the project's own edges were recorded against, so it is preferred over
	// any other the store happens to hold.
	usageVersionBuildResolved usageVersionBasis = "build_resolved"
	// usageVersionHighestStored: neither the requested version nor any the build
	// resolves has a stored call graph; the highest version of the path the store
	// does hold answered.
	usageVersionHighestStored usageVersionBasis = "highest_stored"
	// usageVersionUnenumerated: no version of the path has a stored call graph,
	// so nothing about the module was enumerated.
	usageVersionUnenumerated usageVersionBasis = "none_stored"
)

// usageModuleResolution is the ONE coordinate a report is about, with the
// record read for it.
//
// Requested and Measured are separate facts, and merging them is how a report
// comes to assert use of a version that was never released. The project's own
// edges name a callee by module PATH, so they are found whatever version is
// asked about; the module's public API comes from a stored call graph, which
// exists only at the versions someone analysed. One coordinate is resolved for
// both, and which one is stated.
type usageModuleResolution struct {
	Requested coordinate.ModuleCoordinate
	Measured  coordinate.ModuleCoordinate
	Record    cgdomain.CallGraphRecord
	Found     bool
	Basis     usageVersionBasis
}

// resolveUsageModule picks the version of the module this report measures.
//
// The candidate order is the version asked for, then the version the build
// resolves, then the highest the store holds — each tried against the store and
// the first served one taken. Nothing is fabricated: when no version has a
// stored graph the requested coordinate is kept, Found is false, and the report
// says so rather than answering about a version it never read.
func resolveUsageModule(
	ctx context.Context,
	graphs QueryCallGraphUseCase,
	requested coordinate.ModuleCoordinate,
	scope coordinate.ModuleSet,
	toolchain gotoolchain.Version,
	stored []cgports.CallGraphCoordinate,
) (*usageModuleResolution, error) {
	res := &usageModuleResolution{Requested: requested, Measured: requested, Basis: usageVersionUnenumerated}
	versions := usageStoredVersionsOf(stored, requested.Path())

	for _, cand := range usageVersionCandidates(requested, scope, versions) {
		coord, cerr := coordinate.NewModuleCoordinate(requested.Path(), cand.version)
		if cerr != nil {
			continue
		}
		rec, found, gerr := graphs.GetCallGraphRecordFrom(ctx, coord, cgapp.PipelineVersion,
			cgdomain.ComposeRequest{ToolchainPreference: toolchain})
		if gerr != nil {
			return nil, fmt.Errorf("loading call graph for %s: %w", coord, gerr)
		}
		if !found {
			continue
		}
		res.Measured, res.Record, res.Found, res.Basis = coord, rec, true, cand.basis
		return res, nil
	}
	return res, nil
}

// usageVersionCandidate is one version to try, with the basis it would give.
type usageVersionCandidate struct {
	version string
	basis   usageVersionBasis
}

// usageVersionCandidates orders the versions to try, deduplicated so a version
// that is both requested and build-resolved is read once and reported as
// requested.
func usageVersionCandidates(requested coordinate.ModuleCoordinate, scope coordinate.ModuleSet, stored []string) []usageVersionCandidate {
	out := make([]usageVersionCandidate, 0, len(stored)+2)
	seen := map[string]bool{}
	add := func(v string, b usageVersionBasis) {
		if v == "" || seen[v] {
			return
		}
		seen[v] = true
		out = append(out, usageVersionCandidate{version: v, basis: b})
	}
	add(requested.Version(), usageVersionAsRequested)
	for _, v := range scope.VersionsOf(requested.Path()) {
		add(v, usageVersionBuildResolved)
	}
	for _, v := range stored {
		add(v, usageVersionHighestStored)
	}
	return out
}

// usageStoredVersionsOf is the versions of one path the store serves a call
// graph for at the serving pipeline version, highest first.
//
// The pipeline filter is applied here rather than in the listing because the
// same listing supplies the owning-module candidates, and there a record built
// by superseded logic still proves its module path is a module path.
func usageStoredVersionsOf(stored []cgports.CallGraphCoordinate, path string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(stored))
	for _, c := range stored {
		if c.ModulePath != path || c.PipelineVersion != cgapp.PipelineVersion || seen[c.ModuleVersion] {
			continue
		}
		seen[c.ModuleVersion] = true
		out = append(out, c.ModuleVersion)
	}
	sort.Slice(out, func(i, j int) bool { return usageVersionAfter(out[i], out[j]) })
	return out
}

// usageVersionAfter orders versions newest first, with a string tie-break so
// the order is total: a non-semver version — "local", a malformed pin — sorts
// below every real one rather than at an unstable position.
func usageVersionAfter(a, b string) bool {
	if c := semver.Compare(a, b); c != 0 {
		return c > 0
	}
	return a > b
}

// addUsageEdge records one edge against its callee.
func addUsageEdge(into map[string]*usageSymbol, nodeID string, site usageSite) {
	sym, ok := into[nodeID]
	if !ok {
		sym = &usageSymbol{NodeID: nodeID}
		into[nodeID] = sym
	}
	if site.IsTest {
		sym.Test++
	} else {
		sym.Production++
	}
	if site.Kind == usageEdgeKindReference {
		sym.References++
	}
	sym.Sites = append(sym.Sites, site)
}

// usageModulePaths is the candidate set a callee's owning module is resolved
// against.
//
// The candidates matter because Go module paths NEST. github.com/x/m and
// github.com/x/m/v3 are separate modules, and a longest-match over both is the
// only rule that tells their symbols apart; with the longer path missing, a v3
// symbol is filed under v2 — the two modules a migration is moving between, so
// the inventory conflates the module being left with the module being adopted.
//
// The build alone is therefore not a sufficient source, because the case this
// command exists to serve is a module the build has not got. Four sources are
// unioned so a callee's true owner is among them:
//
//   - every module the build resolves, which is authoritative about its own,
//     analysed or not;
//   - every module path the store has analysed at any version, which is where
//     the successor module a migration is planned towards is found;
//   - the foreign modules the graph being read records having built, which the
//     analyser named from the real module boundaries;
//   - the module asked about, whether or not anything else lists it.
//
// Nothing is derived from package paths. A module boundary is not readable off
// one: github.com/aws/aws-sdk-go-v2/aws/signer/v4 is a PACKAGE of
// aws-sdk-go-v2, named for Signature Version 4, and reading its last element as
// a major-version suffix strips 27 of the module's own API out of its public
// surface. Only a source that names modules as modules may name one here.
func usageModulePaths(scope coordinate.ModuleSet, stored []cgports.CallGraphCoordinate, rec cgdomain.CallGraphRecord, module coordinate.ModuleCoordinate) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(stored)+scope.Len()+1)
	add := func(p string) {
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	for _, c := range scope.Coordinates() {
		add(c.Path())
	}
	for _, c := range stored {
		add(c.ModulePath)
	}
	for _, f := range rec.ForeignModulesBuilt {
		add(f.Path)
	}
	add(module.Path())
	return out
}

// usageModuleSurface reads the module's OWN call graph for the two facts the
// project's graph cannot supply: its public API, and the interfaces it declares.
//
// Absent, the report says the population is unknown rather than reporting an
// empty one — an unreached list drawn from nothing reads as a module with no API.
func usageModuleSurface(rep *usageReport, rec cgdomain.CallGraphRecord, module coordinate.ModuleCoordinate, owners []string) {
	reached := make(map[string]struct{}, len(rep.Used))
	for _, s := range rep.Used {
		reached[s.NodeID] = struct{}{}
	}
	for _, n := range rec.Nodes {
		// A module's test declarations are exported Go identifiers but are not its
		// API: a consumer compiles none of them, so listing TestFoo as unreached
		// would pad the population with functions nothing could ever call.
		if !n.IsExportedAPI || n.IsTest || n.IsExternal {
			continue
		}
		// The population is held to the same identity rule, over the same
		// candidates, that the edge join uses. Two things fall out of it: a node
		// whose ID does not resolve to this module at all — an SSA wrapper spelled
		// "(*pkg.T).M" — could never match a callee, so listing it would put a
		// permanently unreachable row in the unreached set; and a node belonging
		// to a nested module of a different path is not this module's API.
		if owner, ok := cgdomain.ResolveSymbolModule(n.ID, owners); !ok || owner != module.Path() {
			continue
		}
		rep.PublicAPI++
		if _, hit := reached[n.ID]; !hit {
			rep.Unreached = append(rep.Unreached, n.ID)
		}
	}
	sort.Strings(rep.Unreached)

	for _, it := range rec.Interfaces {
		if it.IsTest {
			continue
		}
		rep.Interfaces = append(rep.Interfaces, it.ID)
	}
	sort.Strings(rep.Interfaces)
}

func sortedUsageSymbols(in map[string]*usageSymbol) []usageSymbol {
	out := make([]usageSymbol, 0, len(in))
	for _, s := range in {
		sort.Slice(s.Sites, func(i, j int) bool { return usageSiteLess(s.Sites[i], s.Sites[j]) })
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return out
}

func sortedUsageSites(in map[usageSite]struct{}) []usageSite {
	out := make([]usageSite, 0, len(in))
	for s := range in {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return usageSiteLess(out[i], out[j]) })
	return out
}

// usageSiteLess is a total order over every field a site carries, so two runs
// order one symbol's sites identically whatever the map iteration did.
func usageSiteLess(a, b usageSite) bool {
	if a.File != b.File {
		return a.File < b.File
	}
	if a.Line != b.Line {
		return a.Line < b.Line
	}
	if a.Caller != b.Caller {
		return a.Caller < b.Caller
	}
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	if a.IsTest != b.IsTest {
		return !a.IsTest
	}
	return false
}

func sortedKeysOf(in map[string]struct{}) []string {
	out := make([]string, 0, len(in))
	for k := range in {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// -- totals --

// usageTotals sums one class along the axes that may be summed. Production and
// test stay apart; the total is offered beside them, never instead of them.
func usageTotals(syms []usageSymbol) (production, test, sites int) {
	for _, s := range syms {
		production += s.Production
		test += s.Test
		sites += s.edgeCount()
	}
	return production, test, sites
}

// -- the verdict --

// surfaceEnumerated reports whether the module's public API was actually listed.
//
// A served record is not that listing. A LoadFailed record carries zero nodes,
// and a Partial one carries dozens without a single exported-API node among
// them when the package declaring the API is exactly the one that failed to
// typecheck. Both satisfy "a call graph exists" while enumerating nothing, so
// the population is the test and the record's existence is not.
func (r *usageReport) surfaceEnumerated() bool { return r.ModuleGraphFound && r.PublicAPI > 0 }

// unenumeratedSurfaceSink is the condition RESOLVED-ABSENT may not be claimed
// over: an absence is an absence FROM a population, so the population has to
// have been drawn.
//
// Measured on this store: a module with no record answers UNRESOLVED, and
// following the remedy that answer printed — fetch it, then extract its call
// graph — produced a LoadFailed record of zero nodes and turned the honest
// UNRESOLVED into RESOLVED-ABSENT. The remedy made the answer worse while the
// module stayed exactly as unmeasured as before.
//
// A module whose complete graph genuinely declares no exported API falls under
// the same rule, and correctly: there is nothing there for this project to have
// called, and a stated reason is worth more than a zero that reads as a
// finished migration.
func (r *usageReport) unenumeratedSurfaceSink() (cgdomain.SoundnessSink, bool) {
	if r.surfaceEnumerated() {
		return cgdomain.SoundnessSink{}, false
	}
	return cgdomain.SoundnessSink{
		Kind:   cgdomain.SinkModuleSurfaceUnenumerated,
		Site:   r.Module.Path(),
		Detail: r.surfaceUnenumeratedReason(),
	}, true
}

// surfaceUnenumeratedReason says which of the three ways the population came
// back undrawn, and what — if anything — changes it. They need different
// sentences because they need different advice: a module nobody analysed is
// fixed by analysing it, one whose analysis fell short is fixed by removing
// what stopped it, and one that exports nothing is not fixed at all.
func (r *usageReport) surfaceUnenumeratedReason() string {
	if !r.ModuleGraphFound {
		return fmt.Sprintf("the store holds no call graph for any version of %s, so its public "+
			"API was never enumerated and nothing about the module was measured; check the module "+
			"path, then run: %s", r.Module.Path(), usageMeasureRemedy(r.Requested, false))
	}
	rec := r.ModuleRecord
	if cgdomain.RecordIsFailure(rec) || cgdomain.RecordIsIncomplete(rec) {
		return fmt.Sprintf("the stored call graph for %s is %s and enumerated none of its public API "+
			"(%s, cause: %s), so its surface is unlisted and there is no population for an absence to be "+
			"an absence of; re-measure it: %s",
			r.Module, rec.OverallStatus, countOf(len(rec.Nodes), "nodes"), rec.FailureCause,
			usageMeasureRemedy(r.Module, cgdomain.RecordIsCacheable(rec)))
	}
	return fmt.Sprintf("the stored call graph for %s is %s and declares no exported API at all, so "+
		"there is nothing in it for this project to call and no absence to claim; see it: "+
		"kanonarion callgraph-show %s", r.Module, rec.OverallStatus, r.Module)
}

// usageVerdict classifies the answer with the same three values the edge queries
// use. Presence is never downgraded: a Direct edge is a call anyone can look up.
// An empty Used set is a measurement only when nothing about the project's
// analysis leaves room for a missing edge.
func (r *usageReport) usageVerdict() cgdomain.Answer {
	if len(r.Used) > 0 {
		return cgdomain.Answer{Outcome: cgdomain.AnswerResolvedPresent}
	}
	site := r.Consumer.Path()
	var sinks []cgdomain.SoundnessSink
	if sink, ok := r.unenumeratedSurfaceSink(); ok {
		sinks = append(sinks, sink)
	}
	if len(r.DroppedPackages) > 0 {
		sinks = append(sinks, cgdomain.SoundnessSink{
			Kind: cgdomain.SinkDroppedPackageEdges, Site: site,
			Detail: strings.Join(r.DroppedPackages, ", ") + " did not typecheck, so their edges were dropped",
		})
	}
	if len(r.Dispatch) > 0 {
		sinks = append(sinks, cgdomain.SoundnessSink{
			Kind: cgdomain.SinkUnresolvedEdge, Site: site,
			Detail: fmt.Sprintf("%s reach this module over %s the analysis could not resolve",
				countOf(len(r.DispatchSites), "call sites"), countOf(len(r.Dispatch), "symbols")),
		})
	}
	if !r.Record.ReferenceScope.IsMeasured() {
		sinks = append(sinks, cgdomain.SoundnessSink{
			Kind: cgdomain.SinkReferenceScopeUnmeasured, Site: site,
			Detail: "function-value references were not extracted for this project",
		})
	}
	if !r.Record.TestScope.IsMeasured() {
		detail := r.Record.TestScopeDetail
		if detail == "" {
			detail = "_test.go declarations were not analysed for this project"
		}
		sinks = append(sinks, cgdomain.SoundnessSink{Kind: cgdomain.SinkTestScopeUnmeasured, Site: site, Detail: detail})
	}
	if r.Record.Completeness != cgdomain.CompletenessUnknown && !r.Record.Completeness.IsBuiltWithBodies() {
		sinks = append(sinks, cgdomain.SoundnessSink{
			Kind: cgdomain.SinkTypeOnlyCallee, Site: site,
			Detail: "project completeness " + r.Record.Completeness.String(),
		})
	}
	if len(sinks) == 0 {
		return cgdomain.Answer{Outcome: cgdomain.AnswerResolvedAbsent}
	}
	return cgdomain.Answer{Outcome: cgdomain.AnswerUnresolved, Sinks: sinks}
}

// usageVerdictExit maps the verdict onto the exit taxonomy.
//
// An UNRESOLVED answer is the "completed but known-incomplete" row: the report
// is printed in full and is still an answer, but a script must not read its
// empty used set as a measured zero. Both resolved outcomes exit 0 — a project
// that uses a dependency has not failed at anything — and the polarity is read
// off `answer`, which is the field every sibling command states it on.
func usageVerdictExit(r *usageReport) error {
	v := r.usageVerdict()
	if v.Outcome != cgdomain.AnswerUnresolved {
		return nil
	}
	return &exitError{code: ExitPartial, msg: fmt.Sprintf(
		"UNRESOLVED: no Direct edge from %s reaches %s, and the absence is not proven: %s",
		r.Consumer.Path(), r.Module, v.Reason())}
}

// versionSubstituted reports whether the version measured is not the version
// asked for.
func (r *usageReport) versionSubstituted() bool {
	return r.Requested.Version() != r.Module.Version()
}

// requestedNotMeasuredClause is what keeps the answer sentence a true statement
// standing alone. A reader who sees only the verdict must not come away
// believing the version they typed was the one measured, so the disclaimer is
// in the sentence itself and not only in a caveat above it.
func (r *usageReport) requestedNotMeasuredClause() string {
	if !r.versionSubstituted() {
		return ""
	}
	return fmt.Sprintf("; the version asked for, %s, has no stored call graph and was not measured",
		r.Requested.Version())
}

// basisNotes is what the read owes about the walk it selected. A caller who
// named the walk chose it, so there is no selection to disclose and no manifest
// this read declined to re-resolve.
func (r *usageReport) basisNotes() string {
	if r.Pinned {
		return ""
	}
	return r.choice.basisNotes()
}

// walkSelection renders how the answering walk was arrived at. A caller who
// named one chose it themselves, and reporting that as a choice this command
// made would tell a consumer the walk id was picked for it.
func (r *usageReport) walkSelection() selectionJSON {
	if r.Pinned {
		return pinnedSelection()
	}
	return r.choice.selection()
}

// -- text output --

func printUsageReport(stdout io.Writer, r *usageReport) error {
	if _, err := fmt.Fprintf(stdout, "usage of %s by %s\n", r.Module, r.Consumer); err != nil {
		return fmt.Errorf("writing usage header: %w", err)
	}
	if err := writeScopeNotice(stdout, buildScope{
		modules:   r.Scope,
		source:    fmt.Sprintf("walk %q (%s, frame %s)", r.WalkID, walkScopeLabel(r.WalkScope), r.WalkFrame),
		staleness: r.basisNotes(),
	}); err != nil {
		return err
	}
	if err := printUsageVersionBasis(stdout, r); err != nil {
		return err
	}
	if err := printUsageBuildCaveat(stdout, r); err != nil {
		return err
	}
	if err := writeConsumerDroppedPackages(stdout, &r.consumerBinding); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(stdout, "graph: %s, %s, %s, %d node(s), %d edge(s)\n",
		r.Record.ContentHash, r.Record.OverallStatus, r.Record.Completeness,
		len(r.Record.Nodes), len(r.Record.Edges)); err != nil {
		return fmt.Errorf("writing graph line: %w", err)
	}

	if err := printUsageUsed(stdout, r); err != nil {
		return err
	}
	if err := printUsageDispatch(stdout, r); err != nil {
		return err
	}
	if err := printUsageLinkage(stdout, r); err != nil {
		return err
	}
	if err := printUsageUnreached(stdout, r); err != nil {
		return err
	}
	if err := printUsageInterfaces(stdout, r); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(stdout, "\n%s\n%s\n",
		usageUnmeasuredKindsNote(r.Module), usedByCoverageNote); err != nil {
		return fmt.Errorf("writing usage coverage: %w", err)
	}
	return printUsageVerdict(stdout, r)
}

// printUsageVersionBasis states that the version measured is not the version
// asked for, and which of the two rules chose it.
func printUsageVersionBasis(stdout io.Writer, r *usageReport) error {
	if !r.versionSubstituted() {
		return nil
	}
	why := "the newest version of the module the store holds a call graph for"
	if r.VersionBasis == usageVersionBuildResolved {
		why = "the version the build above resolves, and so the version this project's own edges were recorded against"
	}
	if _, err := fmt.Fprintf(stdout,
		"version: %s has no stored call graph, so nothing below was measured against it. This report "+
			"measures %s — %s. To measure the version you asked for, run: %s\n",
		r.Requested, r.Module, why, usageMeasureRemedy(r.Requested, false)); err != nil {
		return fmt.Errorf("writing version basis: %w", err)
	}
	return nil
}

// printUsageBuildCaveat discloses that the module measured is not the module
// version the named build contains.
//
// The two cases are different questions, so they get different sentences. A
// module the build has not got at all is what this command is for — a migration
// asks what adopting a successor would cost, and its subject is by definition
// not yet in the build — and saying so is what keeps the divergence from
// `callers`, which refuses that same coordinate as a walk-scoped symbol query,
// from being silent. A module present at another version is a narrower thing:
// the sites were recorded against one version and the public API enumerated
// from another.
func printUsageBuildCaveat(stdout io.Writer, r *usageReport) error {
	switch {
	case r.ModuleInBuild:
		return nil
	case !r.ModulePathInBuild:
		if _, err := fmt.Fprintf(stdout,
			"caveat: the build above does not contain %s at any version. Answering about a module "+
				"outside the named build is deliberate here — asking what this project's own code "+
				"already does with a module it has not adopted is the migration question this command "+
				"exists for — so this is an answer, not a fallback. A symbol query scoped to the same "+
				"build (kanonarion callers) refuses that coordinate for the same reason.\n",
			r.Module.Path()); err != nil {
			return fmt.Errorf("writing build-scope caveat: %w", err)
		}
	default:
		if _, err := fmt.Fprintf(stdout,
			"caveat: the build above resolves %s to %s, not the %s measured here, so the sites below "+
				"were recorded against one version of the module and its public API enumerated from "+
				"another\n",
			r.Module.Path(), strings.Join(r.BuildVersions, ", "), r.Module.Version()); err != nil {
			return fmt.Errorf("writing build-scope caveat: %w", err)
		}
	}
	return nil
}

func printUsageUsed(stdout io.Writer, r *usageReport) error {
	prod, test, total := usageTotals(r.Used)
	if _, err := fmt.Fprintf(stdout,
		"\nUsed — reached by a Direct edge from %s own code (%s, %s: %d production, %d test):\n",
		r.Consumer.Path(), countOf(len(r.Used), "symbols"), countOf(total, "sites"), prod, test); err != nil {
		return fmt.Errorf("writing used header: %w", err)
	}
	if _, err := fmt.Fprintf(stdout, "  %s\n", usageConfidenceNote); err != nil {
		return fmt.Errorf("writing confidence note: %w", err)
	}
	for _, s := range r.Used {
		if _, err := fmt.Fprintf(stdout, "  %s — %s (%d production, %d test)\n",
			s.NodeID, countOf(s.edgeCount(), "sites"), s.Production, s.Test); err != nil {
			return fmt.Errorf("writing used symbol: %w", err)
		}
		for _, site := range s.Sites {
			if _, err := fmt.Fprintf(stdout, "      %s\n", usageSiteLine(site)); err != nil {
				return fmt.Errorf("writing used site: %w", err)
			}
		}
	}
	return nil
}

// usageSiteLine renders one site: which surface it is on, where it is, what it
// does, and the function that holds it.
func usageSiteLine(s usageSite) string {
	surface := "production"
	if s.IsTest {
		surface = "test"
	}
	where := s.File
	if s.Line > 0 {
		where = fmt.Sprintf("%s:%d", s.File, s.Line)
	}
	if where == "" {
		where = "(position not recorded)"
	}
	return fmt.Sprintf("%-10s %s  [%s]  %s", surface, where, s.Kind, s.Caller)
}

func printUsageDispatch(stdout io.Writer, r *usageReport) error {
	prod, test, total := usageTotals(r.Dispatch)
	if _, err := fmt.Fprintf(stdout,
		"\nReached only through unresolved dispatch — not established use (%s, %s from %s: %d production, %d test):\n",
		countOf(len(r.Dispatch), "symbols"), countOf(total, "edges"),
		countOf(len(r.DispatchSites), "sites"), prod, test); err != nil {
		return fmt.Errorf("writing dispatch header: %w", err)
	}
	if len(r.Dispatch) == 0 {
		return nil
	}
	if _, err := fmt.Fprintln(stdout,
		"  The project does dispatch into this module at these sites. Which of the symbols below "+
			"each site reaches was not resolved, so none of them is reported as used and none of them "+
			"is reported as unused either."); err != nil {
		return fmt.Errorf("writing dispatch note: %w", err)
	}
	for _, site := range r.DispatchSites {
		if _, err := fmt.Fprintf(stdout, "      %s\n", usageSiteLine(site)); err != nil {
			return fmt.Errorf("writing dispatch site: %w", err)
		}
	}
	for _, s := range r.Dispatch {
		if _, err := fmt.Fprintf(stdout, "  %s — %s (%d production, %d test)\n",
			s.NodeID, countOf(s.edgeCount(), "edges"), s.Production, s.Test); err != nil {
			return fmt.Errorf("writing dispatch symbol: %w", err)
		}
	}
	return nil
}

func printUsageLinkage(stdout io.Writer, r *usageReport) error {
	if _, err := fmt.Fprintf(stdout,
		"\nLinked but not called (%s of this project import the module):\n",
		countOf(len(r.LinkedPackages), "packages")); err != nil {
		return fmt.Errorf("writing linkage header: %w", err)
	}
	if len(r.LinkedPackages) == 0 {
		return nil
	}
	if _, err := fmt.Fprintln(stdout,
		"  An edge into the module's own init says the package imports it and its initialiser ran. "+
			"That is linkage, and it is in no count above."); err != nil {
		return fmt.Errorf("writing linkage note: %w", err)
	}
	for _, p := range r.LinkedPackages {
		if _, err := fmt.Fprintf(stdout, "      %s\n", p); err != nil {
			return fmt.Errorf("writing linked package: %w", err)
		}
	}
	return nil
}

func printUsageUnreached(stdout io.Writer, r *usageReport) error {
	// An unlisted surface is printed as unmeasured whether the store held no
	// record or held one that enumerated nothing. "0 of 0" reads as a module with
	// no public API, which is the misreading this whole section turns on.
	if !r.surfaceEnumerated() {
		if _, err := fmt.Fprintf(stdout,
			"\nUnreached — unmeasured: %s\n", r.surfaceUnenumeratedReason()); err != nil {
			return fmt.Errorf("writing unreached absence: %w", err)
		}
		return nil
	}
	if _, err := fmt.Fprintf(stdout,
		"\nUnreached — in the module's public API, with no Direct edge from this project (%d of %d):\n",
		len(r.Unreached), r.PublicAPI); err != nil {
		return fmt.Errorf("writing unreached header: %w", err)
	}
	dispatched := make(map[string]struct{}, len(r.Dispatch))
	for _, s := range r.Dispatch {
		dispatched[s.NodeID] = struct{}{}
	}
	for _, id := range r.Unreached {
		suffix := ""
		if _, hit := dispatched[id]; hit {
			suffix = "  (named by an unresolved dispatch above)"
		}
		if _, err := fmt.Fprintf(stdout, "      %s%s\n", id, suffix); err != nil {
			return fmt.Errorf("writing unreached symbol: %w", err)
		}
	}
	return nil
}

func printUsageInterfaces(stdout io.Writer, r *usageReport) error {
	if !r.ModuleGraphFound {
		return nil
	}
	if len(r.Interfaces) == 0 {
		// No interface, nothing to satisfy: the unmeasured axis does not arise, and
		// printing its caveat anyway teaches a reader to skip the caveat.
		if _, err := fmt.Fprintln(stdout, "\nInterfaces declared by the module: none"); err != nil {
			return fmt.Errorf("writing interfaces header: %w", err)
		}
		return nil
	}
	if _, err := fmt.Fprintf(stdout,
		"\nInterfaces declared by the module (%d):\n  %s\n",
		len(r.Interfaces), usageSatisfactionNote); err != nil {
		return fmt.Errorf("writing interfaces header: %w", err)
	}
	for _, id := range r.Interfaces {
		if _, err := fmt.Fprintf(stdout, "      %s\n", id); err != nil {
			return fmt.Errorf("writing interface: %w", err)
		}
	}
	return nil
}

func printUsageVerdict(stdout io.Writer, r *usageReport) error {
	v := r.usageVerdict()
	prod, test, total := usageTotals(r.Used)
	switch v.Outcome {
	case cgdomain.AnswerResolvedPresent:
		if _, err := fmt.Fprintf(stdout,
			"answer: RESOLVED-PRESENT — %s own code reaches %s of %s at %s (%d production, %d test)%s\n",
			r.Consumer.Path(), countOf(len(r.Used), "symbols"), r.Module,
			countOf(total, "sites"), prod, test, r.requestedNotMeasuredClause()); err != nil {
			return fmt.Errorf("writing usage answer: %w", err)
		}
	case cgdomain.AnswerUnresolved:
		if _, err := fmt.Fprintf(stdout,
			"answer: UNRESOLVED — no Direct edge from %s reaches %s, and the absence is not proven: %s\n",
			r.Consumer.Path(), r.Module, v.Reason()); err != nil {
			return fmt.Errorf("writing usage answer: %w", err)
		}
	default:
		if _, err := fmt.Fprintf(stdout,
			"answer: RESOLVED-ABSENT — no recorded call edge from %s own code reaches %s, "+
				"measured over the %d edge(s) of its stored call graph%s\n",
			r.Consumer.Path(), r.Module, len(r.Record.Edges), r.requestedNotMeasuredClause()); err != nil {
			return fmt.Errorf("writing usage answer: %w", err)
		}
	}
	return nil
}

// -- JSON output --

type usageSiteJSON struct {
	Caller string `json:"caller"`
	File   string `json:"file,omitempty"`
	Line   int    `json:"line"`
	IsTest bool   `json:"is_test"`
	Kind   string `json:"kind"`
}

type usageSymbolJSON struct {
	NodeID string `json:"node_id"`
	// Production and Test are the two counts, never summed into one field: a
	// consumer that wants the total adds them, and one that wants the production
	// blast radius reads the one it means.
	Production int `json:"production_sites"`
	Test       int `json:"test_sites"`
	// References is how many sites take the function as a value rather than call
	// it — use of the symbol, never an invocation.
	References int             `json:"reference_sites"`
	Sites      []usageSiteJSON `json:"sites"`
}

type usageDispatchJSON struct {
	Symbols []usageSymbolJSON `json:"symbols"`
	// Sites are the distinct project sites the over-approximated edges leave
	// from. One site commonly names many symbols, which is why they are listed
	// once rather than repeated per symbol.
	Sites           []usageSiteJSON `json:"sites"`
	SymbolCount     int             `json:"symbol_count"`
	EdgeCount       int             `json:"edge_count"`
	SiteCount       int             `json:"site_count"`
	ProductionEdges int             `json:"production_edges"`
	TestEdges       int             `json:"test_edges"`
	// EstablishesUse is false on every answer: an over-approximated edge names a
	// callee the analysis could not resolve. It is a field rather than only a
	// sentence because it is the distinction a consumer merging the two arrays
	// would silently lose.
	EstablishesUse bool   `json:"establishes_use"`
	Note           string `json:"note"`
}

type usageJSON struct {
	Module string `json:"module"`
	// Version is the version MEASURED: the one whose stored call graph was read.
	// RequestedVersion is the one the caller typed, present only when the two
	// differ, and VersionBasis names the rule that chose between them. A
	// consumer that reads `version` alone reads a version that was measured.
	Version          string `json:"version"`
	RequestedVersion string `json:"requested_version,omitempty"`
	VersionBasis     string `json:"version_basis"`
	Consumer         string `json:"consumer"`
	GoMod            string `json:"gomod,omitempty"`
	WalkID           string `json:"walk_id"`
	// WalkFrame is the GOOS/GOARCH the answering walk resolved for, and
	// WalkFrameBasis the same fact as data: "platform", "not_platform_scoped" or
	// "unrecorded".
	WalkFrame      string        `json:"walk_frame"`
	WalkFrameBasis string        `json:"walk_frame_basis"`
	WalkScope      string        `json:"walk_scope"`
	WalkSelection  selectionJSON `json:"walk_selection"`
	ScopeSize      int           `json:"scope_size"`
	// ModuleInBuild says whether the answering walk resolves the measured
	// coordinate, and ModulePathInBuild whether it contains the path at any
	// version. Both false is the supported migration question: a module the
	// build has not adopted.
	ModuleInBuild     bool `json:"module_in_build"`
	ModulePathInBuild bool `json:"module_path_in_build"`
	// ModuleCallGraphFound says whether a graph was served for the module at any
	// version. False means unreached_public_api and declared_interfaces were
	// never enumerated and their emptiness is not a measurement.
	//
	// True is not the converse: a served record can enumerate nothing, and
	// public_api_count is what says whether it did. `answer` reads that count,
	// not this flag — a consumer checking a migration finished reads `answer`.
	ModuleCallGraphFound bool     `json:"module_call_graph_found"`
	DroppedPackages      []string `json:"dropped_packages,omitempty"`
	// The project's own graph, named so a reader can tell which of several
	// analysed generations answered: a store holding two checkouts of one project
	// serves the one the caller is standing in, and the counts differ.
	CallGraphContentHash string `json:"call_graph_content_hash"`
	CallGraphStatus      string `json:"call_graph_status"`
	CallGraphNodeCount   int    `json:"call_graph_node_count"`
	CallGraphEdgeCount   int    `json:"call_graph_edge_count"`

	Used                []usageSymbolJSON `json:"used"`
	UsedSymbolCount     int               `json:"used_symbol_count"`
	UsedProductionSites int               `json:"used_production_sites"`
	UsedTestSites       int               `json:"used_test_sites"`

	UnresolvedDispatch usageDispatchJSON `json:"unresolved_dispatch"`

	LinkedPackages     []string `json:"linked_not_called_packages"`
	LinkedPackageCount int      `json:"linked_not_called_package_count"`

	UnreachedPublicAPI []string `json:"unreached_public_api"`
	PublicAPICount     int      `json:"public_api_count"`

	DeclaredInterfaces []string `json:"declared_interfaces"`
	// InterfaceSatisfactionMeasured is false on every answer: no stored record
	// holds the relation across the project/dependency boundary.
	InterfaceSatisfactionMeasured bool   `json:"interface_satisfaction_measured"`
	InterfaceSatisfactionNote     string `json:"interface_satisfaction_note"`

	// UnmeasuredKinds names the declaration kinds with no call-graph node, so a
	// consumer never reads their absence as an absence of use.
	UnmeasuredKinds []string `json:"unmeasured_kinds"`

	Coverage   string `json:"coverage"`
	Confidence string `json:"confidence_note"`
	Answer     string `json:"answer"`
	AnswerWhy  string `json:"answer_reason,omitempty"`
}

func toUsageJSON(r *usageReport) usageJSON {
	usedProd, usedTest, _ := usageTotals(r.Used)
	dispProd, dispTest, dispEdges := usageTotals(r.Dispatch)
	v := r.usageVerdict()

	requested := ""
	if r.versionSubstituted() {
		requested = r.Requested.Version()
	}

	return usageJSON{
		Module:               r.Module.Path(),
		Version:              r.Module.Version(),
		RequestedVersion:     requested,
		VersionBasis:         string(r.VersionBasis),
		Consumer:             r.Consumer.Path() + "@" + r.Consumer.Version(),
		GoMod:                r.GoMod,
		WalkID:               r.WalkID,
		WalkFrame:            r.WalkFrame.Text,
		WalkFrameBasis:       string(r.WalkFrame.Basis),
		WalkScope:            string(r.WalkScope),
		WalkSelection:        r.walkSelection(),
		ScopeSize:            r.ScopeSize,
		ModuleInBuild:        r.ModuleInBuild,
		ModulePathInBuild:    r.ModulePathInBuild,
		ModuleCallGraphFound: r.ModuleGraphFound,
		DroppedPackages:      r.DroppedPackages,
		CallGraphContentHash: r.Record.ContentHash,
		CallGraphStatus:      r.Record.OverallStatus.String(),
		CallGraphNodeCount:   len(r.Record.Nodes),
		CallGraphEdgeCount:   len(r.Record.Edges),

		Used:                toUsageSymbolsJSON(r.Used),
		UsedSymbolCount:     len(r.Used),
		UsedProductionSites: usedProd,
		UsedTestSites:       usedTest,

		UnresolvedDispatch: usageDispatchJSON{
			Symbols:         toUsageSymbolsJSON(r.Dispatch),
			Sites:           toUsageSitesJSON(r.DispatchSites),
			SymbolCount:     len(r.Dispatch),
			EdgeCount:       dispEdges,
			SiteCount:       len(r.DispatchSites),
			ProductionEdges: dispProd,
			TestEdges:       dispTest,
			EstablishesUse:  false,
			Note:            usageConfidenceNote,
		},

		LinkedPackages:     nonNilStrings(r.LinkedPackages),
		LinkedPackageCount: len(r.LinkedPackages),

		UnreachedPublicAPI: nonNilStrings(r.Unreached),
		PublicAPICount:     r.PublicAPI,

		DeclaredInterfaces:            nonNilStrings(r.Interfaces),
		InterfaceSatisfactionMeasured: false,
		InterfaceSatisfactionNote:     usageSatisfactionNote,

		UnmeasuredKinds: []string{"type", "const", "var"},

		Coverage:   usedByCoverageNote,
		Confidence: usageConfidenceNote,
		Answer:     string(v.Outcome),
		AnswerWhy:  v.Reason(),
	}
}

func toUsageSymbolsJSON(syms []usageSymbol) []usageSymbolJSON {
	out := make([]usageSymbolJSON, 0, len(syms))
	for _, s := range syms {
		out = append(out, usageSymbolJSON{
			NodeID:     s.NodeID,
			Production: s.Production,
			Test:       s.Test,
			References: s.References,
			Sites:      toUsageSitesJSON(s.Sites),
		})
	}
	return out
}

func toUsageSitesJSON(sites []usageSite) []usageSiteJSON {
	out := make([]usageSiteJSON, 0, len(sites))
	for _, s := range sites {
		// A conversion rather than a field-by-field copy, so a field added to one
		// shape and not the other stops compiling instead of silently vanishing
		// from the document.
		out = append(out, usageSiteJSON(s))
	}
	return out
}
