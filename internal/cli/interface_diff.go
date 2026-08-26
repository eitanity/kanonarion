package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/gotoolchain"
	ifaceapp "github.com/eitanity/kanonarion/internal/iface/application"
	ifacedomain "github.com/eitanity/kanonarion/internal/iface/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// interfaceDiffCoverageNote is the standing statement of what this comparison
// does and does not measure. It is printed on every run, including the runs that
// find nothing, because a zero is exactly when a reader is most likely to read
// more into the answer than it holds.
const interfaceDiffCoverageNote = "coverage: exported Go declarations and their signatures, compared between two " +
	"stored interface records. Behaviour, string-keyed registries, struct-tag semantics and " +
	"anything decided at run time are outside this comparison; source positions are not compared."

// usedByCoverageNote states the limit of the call-graph join. A symbol reported
// as not reached is not a symbol proved unused: the graph records call edges, so
// a reference that is not a call is not in it to be found.
const usedByCoverageNote = "coverage: reached/not-reached is measured over recorded CALL EDGES in the stored " +
	"call graph. Method values (a method referenced as a value rather than called) are not " +
	"recorded as edges, so a symbol shown as not reached may still be referenced that way. " +
	"Types, constants and variables have no call-graph node at all and are reported as " +
	"unmeasured rather than as unreached."

// zeroBreakingBehaviourNote is what the output says when it found no breaking
// change over a delta that is not empty.
//
// It is printed where the reader meets the zero rather than in a scope footer,
// because the footer was already there and was read past: three independent
// upgrade-triage runs saw the passive scope note beside a zero and still called
// the bump safe. It is an active statement about what the zero does not mean.
//
// It deliberately avoids every word the seam test forbids — the statement is
// about what the zero does NOT establish, and reaching for a verdict adjective
// to say so would defeat it.
const zeroBreakingBehaviourNote = "a zero here is not reassurance. This comparison reads exported " +
	"signatures, so it cannot see behaviour: a release that changes no signature at all can still change " +
	"what your calls return. A zero-breaking bump is the case that most needs checking against something " +
	"this command does not measure."

// zeroBreakingCrossMajorNote is added to the statement when the zero sits on a
// cross-major pair. A new major version is the author declaring an incompatible
// change, so a zero-breaking signature comparison there narrows where to look
// rather than settling it.
const zeroBreakingCrossMajorNote = "this is a new major version, which is the author declaring something " +
	"incompatible changed. The signatures above show none of it, which is a reason to look harder rather " +
	"than a reason to stop."

// zeroBreakingNoUsedByNote names what would answer the question, in the
// consumer's own hands, when no call graph was joined.
const zeroBreakingNoUsedByNote = "what would answer it: exercise your own tests over the call sites this " +
	"bump touches. Pass --used-by ./go.mod to have them enumerated here."

type interfaceDiffFlags struct {
	usedBy string
	// toolchain restricts the consumer's own call graph to one Go toolchain. It is
	// here because --used-by resolves a stored call graph, and a refusal that told
	// the reader to name a toolchain while this command had no way to name one
	// would be advice it could not act on.
	toolchain string
}

// -- interface-diff command --

func newInterfaceDiffCmd(stdout, stderr io.Writer) *cobra.Command {
	var f interfaceDiffFlags

	cmd := &cobra.Command{
		Use:   "interface-diff <moduleA>@<versionA> <moduleB>@<versionB>",
		Short: "Report exported API changes between two versions of a module",
		Long: `interface-diff compares two stored interface records and reports the exported
declarations added, removed and changed between them.

A signature that changed only in a spelling the language treats as identical —
interface{} rewritten as any, a result that stopped being named — is reported
separately as a spelling change and is NOT counted as breaking.

The two module paths may differ by a major-version suffix. Given a cross-major
pair — example.com/mod and example.com/mod/v3 — declarations are matched by
package-relative path, kind and name rather than by import path, so a surface
that only moved is reported as renamed-path rather than as a wall of removals
and additions. Renamed-path is not counted as breaking; the import rewrite it
obliges is stated on its own line.

The count is a count of exported signatures. It is not a claim about behaviour:
a release that changes no signature at all can still change what the code does,
and a zero-breaking result over a non-empty delta says so where it is printed.

Both records must already be extracted — run 'kanonarion interface' first.`,
		Example: `  kanonarion interface-diff github.com/spf13/cast@v1.4.1 github.com/spf13/cast@v1.10.0
  kanonarion interface-diff github.com/spf13/cast@v1.4.1 github.com/spf13/cast@v1.10.0 --json
  kanonarion interface-diff github.com/spf13/cast@v1.4.1 github.com/spf13/cast@v1.10.0 --used-by ./go.mod
  kanonarion interface-diff example.com/mod@v2.22.0+incompatible example.com/mod/v3@v3.3.0`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 2 {
				return usageErr(cmd)
			}
			return runInterfaceDiff(cmd.Context(), args[0], args[1], f, stdout, stderr)
		},
	}

	// A value-taking flag and nothing else: no NoOptDefVal, so "--used-by
	// ./go.mod" is the grammar and a bare --used-by is rejected rather than
	// silently swallowing the next positional.
	cmd.Flags().StringVar(&f.toolchain, "toolchain", "",
		"restrict the consumer's call graph to one Go toolchain, in `go env GOVERSION` form (e.g. go1.26.6)")
	cmd.Flags().StringVar(&f.usedBy, "used-by", "",
		"join the delta against the stored call graph of the project this go.mod declares")

	return cmd
}

func runInterfaceDiff(ctx context.Context, argA, argB string, f interfaceDiffFlags, stdout, stderr io.Writer) error {
	coordA, err := parseCoordinate(argA)
	if err != nil {
		return fmt.Errorf("invalid coordinate %q: %w", argA, err)
	}
	coordB, err := parseCoordinate(argB)
	if err != nil {
		return fmt.Errorf("invalid coordinate %q: %w", argB, err)
	}

	logger := buildLogger(logLevel, stderr)
	ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() { _ = cleanup() }()

	return interfaceDiffWith(ctx, ctr, coordA, coordB, f, stdout)
}

// interfaceMissMessage states why one side of the diff is absent. The use case
// reports a missing record; only the store can say whether the coordinate was
// never extracted or was extracted under logic this build no longer serves, and
// those have opposite remedies. A store that cannot be read leaves the use
// case's own message standing.
func interfaceMissMessage(ctx context.Context, uc QueryInterfaceUseCase, notFound *ifaceapp.ErrInterfaceRecordNotFound) string {
	all := storedInterfaceSummaries(ctx, uc)
	if pipelines, superseded := supersededInterfacePipelines(notFound.Coordinate, all); superseded {
		return supersededInterfaceLine(notFound.Coordinate, pipelines)
	}
	return notFound.Error()
}

// interfaceDiffWith holds the interface-diff logic over an injected Container:
// it runs the diff, maps a missing record to ExitNotFound (absence is surfaced,
// never reported as "no change"), optionally joins the delta against a stored
// call graph, and selects JSON vs text rendering.
func interfaceDiffWith(
	ctx context.Context,
	ctr *Container,
	coordA, coordB coordinate.ModuleCoordinate,
	f interfaceDiffFlags,
	stdout io.Writer,
) error {
	diff, err := ctr.DiffInterface.Diff(ctx, coordA, coordB)
	if err != nil {
		if notFound, ok := errors.AsType[*ifaceapp.ErrInterfaceRecordNotFound](err); ok {
			return &exitError{code: ExitNotFound, msg: interfaceMissMessage(ctx, ctr.QueryInterface, notFound)}
		}
		return fmt.Errorf("diffing interface records: %w", err)
	}

	var used *usedByResult
	if f.usedBy != "" {
		used, err = joinUsedBy(ctx, ctr, diff, f.usedBy, gotoolchain.Version(f.toolchain))
		if err != nil {
			return err
		}
	}

	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if encErr := enc.Encode(toInterfaceDiffJSON(diff, used)); encErr != nil {
			return fmt.Errorf("encoding JSON: %w", encErr)
		}
		return usedSetBreakingErr(used)
	}

	if perr := printInterfaceDiff(diff, used, stdout); perr != nil {
		return perr
	}
	return usedSetBreakingErr(used)
}

// -- the used-by join --

// usedSymbol is one breaking delta together with what the consumer's own code
// does with it.
type usedSymbol struct {
	Symbol ifacedomain.SymbolID
	// Removed distinguishes the two breaking classes for display.
	Removed bool
	// Measurable is false for a declaration that has no call-graph node — a
	// type, a constant, a variable. Such a symbol is not "unused"; it is not a
	// question the call graph can answer.
	Measurable bool
	// SymbolID is the call-graph node ID this was looked up under, empty when
	// not measurable.
	NodeID string
	// Sites is the number of recorded call edges from the consumer's own code.
	Sites int
	// Callers are the consumer's own functions that call it, with the position
	// their declaration sits at, sorted by ID.
	Callers []usedCaller
}

type usedCaller struct {
	ID   string
	File string
	Line int
}

// usedByResult is the join of a delta against one project's stored call graph.
type usedByResult struct {
	GoMod  string
	WalkID string
	// choice is how WalkID was arrived at: which rule picked it out of the store's
	// walks of this project, and what that rule could compare against. --used-by
	// names a manifest, not a walk, so the walk is always chosen for the caller
	// and the choice is always stated, on both surfaces.
	choice walkChoice
	// WalkFrame is the GOOS/GOARCH the answering walk resolved for, carrying the
	// basis that says which: "platform", "not_platform_scoped" for a
	// module-rooted walk (no platform applies, and re-walking never produces
	// one), or "unrecorded" (the platform is not known). Where a
	// platform IS resolved, GOOS gates which files build, so the scope this
	// answer is filtered against is that one platform's build list.
	WalkFrame walkdomain.WalkFrame
	// WalkScope is the dependency scope the answering walk covered. --used-by
	// asks what the consumer's own code calls, so it selects a code-scope walk;
	// the scope is carried so the answer names the build it came from rather
	// than leaving the reader to assume it.
	WalkScope walkdomain.WalkScope
	Consumer  coordinate.ModuleCoordinate
	// ScopeSize is how many module versions the walk pins.
	ScopeSize int
	// Symbols covers every breaking delta, reached or not, in delta order.
	Symbols []usedSymbol
	// Touched covers the declarations a zero-breaking delta moved without
	// breaking anything: the respellings and the cross-major path renames. It is
	// the evidence for the zero-breaking statement — "zero breaking, 341 reached
	// call sites" is a materially different statement from "zero breaking, 2" —
	// and it NEVER gates: there is nothing here for a consumer to be broken by.
	//
	// It is joined only when that statement will be printed, because nothing else
	// reads it and a large respelt surface would otherwise cost one call-graph
	// query per declaration for no reader.
	Touched []usedSymbol
	// CallGraphFound is false when the consumer module has no stored call graph
	// at all — in which case every "not reached" below is an absence of
	// evidence, not evidence of absence, and the command says so.
	CallGraphFound bool
	// DroppedPackages are the consumer's own packages that failed to typecheck,
	// whose edges were therefore dropped.
	//
	// It is disclosed for the same reason 'callers' discloses it: the reach
	// counts here are a join against the consumer's graph, and a call site in a
	// package that produced no SSA cannot appear in it. Without this line the two
	// commands disagree in the worst direction — one states the gap and the other
	// prints a bare "not reached" over the same missing edges.
	DroppedPackages []string
}

// Reached returns the symbols the consumer's own code actually calls.
func (r *usedByResult) Reached() []usedSymbol {
	var out []usedSymbol
	for _, s := range r.Symbols {
		if s.Sites > 0 {
			out = append(out, s)
		}
	}
	return out
}

// TouchedReach summarises the non-breaking touched set: how many of those
// declarations the consumer's own code calls, and at how many recorded sites.
func (r *usedByResult) TouchedReach() (decls, sites int) {
	for _, s := range r.Touched {
		if s.Sites > 0 {
			decls++
			sites += s.Sites
		}
	}
	return decls, sites
}

// joinUsedBy resolves a go.mod to the latest succeeded code-scope project walk
// for the module it declares — the same resolution `callers --gomod` performs —
// and asks the stored call graph which of the breaking deltas that project's own
// code calls.
//
// The code scope is the question: this asks what the consumer's OWN code calls,
// so the build it is answered in is the one that code compiles into. There is no
// flag to widen it, and a tool- or project-scope walk that happened to be walked
// more recently is not allowed to stand in for one.
//
// It never parses the consumer's source. The answer is a read of what was
// already measured and recorded, so it is reproducible and it cannot disagree
// with what `callers` would say about the same symbol.
func joinUsedBy(ctx context.Context, ctr *Container, diff ifacedomain.InterfaceDiff, gomod string, toolchain gotoolchain.Version) (*usedByResult, error) {
	choice, err := latestWalkForGoMod(ctx, ctr.QueryWalks, gomod, scopeCode)
	if err != nil {
		return nil, err
	}
	walkID := choice.summary.ID
	rec, err := choice.walkRecord(ctx, ctr.QueryWalks)
	if err != nil {
		return nil, err
	}
	scope := walkModuleSet(rec)

	res := &usedByResult{
		GoMod:     choice.manifestPath,
		choice:    choice,
		WalkID:    walkID,
		WalkScope: rec.Scope,
		WalkFrame: rec.Graph.Frame(),
		Consumer:  rec.Target,
		ScopeSize: scope.Len(),
	}

	positions, dropped, found, err := consumerNodePositions(ctx, ctr.QueryCallGraph, rec.Target, toolchain)
	if err != nil {
		return nil, err
	}
	res.CallGraphFound = found
	res.DroppedPackages = dropped

	join := func(sym breakingDelta) (usedSymbol, error) {
		entry := usedSymbol{Symbol: sym.Symbol, Removed: sym.Removed}
		nodeID, measurable := callGraphNodeID(sym.Symbol, sym.PtrReceiver)
		entry.Measurable = measurable
		entry.NodeID = nodeID
		if !measurable {
			return entry, nil
		}
		refs, ferr := ctr.QueryCallGraph.FindCallers(ctx, nodeID, cgapp.PipelineVersion, scope, cgports.EdgeQueryOptions{Toolchain: toolchain})
		if ferr != nil {
			return usedSymbol{}, fmt.Errorf("finding callers of %s: %w", nodeID, ferr)
		}
		entry.Sites, entry.Callers = consumerCallers(refs, rec.Target, positions)
		return entry, nil
	}

	for _, sym := range breakingSymbols(diff) {
		entry, jerr := join(sym)
		if jerr != nil {
			return nil, jerr
		}
		res.Symbols = append(res.Symbols, entry)
	}
	if diff.ZeroBreakingOverNonTrivialDelta() {
		for _, sym := range touchedSymbols(diff) {
			entry, jerr := join(sym)
			if jerr != nil {
				return nil, jerr
			}
			res.Touched = append(res.Touched, entry)
		}
	}
	return res, nil
}

// breakingDelta is a removed or changed declaration, in the order the delta
// lists them.
type breakingDelta struct {
	Symbol      ifacedomain.SymbolID
	PtrReceiver bool
	Removed     bool
}

// breakingSymbols enumerates what the join asks about: the removals and the
// real signature changes. Spelling changes are excluded — there is nothing for a
// consumer to be broken by, so asking whether it reaches them would produce a
// finding out of a non-finding.
func breakingSymbols(diff ifacedomain.InterfaceDiff) []breakingDelta {
	out := make([]breakingDelta, 0, diff.BreakingCount())
	for _, s := range diff.Removed {
		out = append(out, breakingDelta{Symbol: s.ID, PtrReceiver: s.PtrReceiver, Removed: true})
	}
	for _, c := range diff.Changed {
		out = append(out, breakingDelta{Symbol: c.Symbol, PtrReceiver: c.PtrReceiver})
	}
	return out
}

// touchedSymbols enumerates the declarations a delta moved without breaking
// anything: the respellings and the cross-major path renames.
//
// They are named on the A-side identity, which is what the consumer's recorded
// call-graph nodes are spelled as — it still depends on version A. Nothing here
// gates: the gate is for a consumer that will be broken, and by construction
// none of these breaks one.
func touchedSymbols(diff ifacedomain.InterfaceDiff) []breakingDelta {
	out := make([]breakingDelta, 0, len(diff.Spelling)+len(diff.RenamedPath))
	for _, c := range diff.Spelling {
		out = append(out, breakingDelta{Symbol: c.Symbol, PtrReceiver: c.PtrReceiver})
	}
	for _, r := range diff.RenamedPath {
		out = append(out, breakingDelta{Symbol: r.From, PtrReceiver: r.PtrReceiver})
	}
	return out
}

// callGraphNodeID renders the call-graph node ID for a declaration, and whether
// the declaration has one at all.
//
// The node-ID convention is "pkg/path.Func" for a function and
// "pkg/path.(*Recv).Method" or "pkg/path.(Recv).Method" for a method, which is
// why the receiver form is carried through the diff: the wrong form finds
// nothing and would read as "not called".
func callGraphNodeID(id ifacedomain.SymbolID, ptrReceiver bool) (string, bool) {
	switch id.Kind {
	case ifacedomain.SymbolFunc:
		return id.Package + "." + id.Name, true
	case ifacedomain.SymbolMethod:
		dot := strings.LastIndex(id.Name, ".")
		if dot < 0 {
			return "", false
		}
		recv, method := id.Name[:dot], id.Name[dot+1:]
		if ptrReceiver {
			return id.Package + ".(*" + recv + ")." + method, true
		}
		return id.Package + ".(" + recv + ")." + method, true
	case ifacedomain.SymbolType, ifacedomain.SymbolConst, ifacedomain.SymbolVar:
		return "", false
	}
	return "", false
}

// writeUsedByDroppedPackages discloses that some of the consumer's own packages
// failed to typecheck, so the reach counts joined against its graph cannot see
// call sites declared in them.
//
// It exists so this command and 'callers' say the same thing about the same
// condition. A silent "not reached" over a package that produced no SSA is the
// same false negative the edge queries refuse to print bare.
func writeUsedByDroppedPackages(stdout io.Writer, used *usedByResult) error {
	if len(used.DroppedPackages) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(stdout,
		"  %d of %s own package(s) did not typecheck when it was analysed, so their edges were "+
			"dropped: %s. A call site declared in one of them cannot appear in any count above — "+
			"those declarations are unmeasured, not unreached.\n",
		len(used.DroppedPackages), used.Consumer.Path(), strings.Join(used.DroppedPackages, ", ")); err != nil {
		return fmt.Errorf("writing used-by dropped packages: %w", err)
	}
	return nil
}

// consumerNodePositions loads the consumer module's own call graph and indexes
// its nodes by ID, so a caller can be reported with the file and line it is
// declared at. It also returns the consumer's own packages whose typecheck
// failed, because a call site in one of them produced no SSA and so cannot join.
// Returns found=false when the project has no stored graph.
func consumerNodePositions(ctx context.Context, uc QueryCallGraphUseCase, consumer coordinate.ModuleCoordinate, toolchain gotoolchain.Version) (map[string]cgdomain.SourcePosition, []string, bool, error) {
	rec, found, err := uc.GetCallGraphRecordFrom(ctx, consumer, cgapp.PipelineVersion, cgdomain.ComposeRequest{ToolchainPreference: toolchain})
	if err != nil {
		return nil, nil, false, fmt.Errorf("loading call graph for %s: %w", consumer, err)
	}
	if !found {
		return nil, nil, false, nil
	}
	positions := make(map[string]cgdomain.SourcePosition, len(rec.Nodes))
	for _, n := range rec.Nodes {
		positions[n.ID] = n.Position
	}
	var dropped []string
	if rec.OverallStatus == cgdomain.CallGraphStatusPartial {
		dropped = append(dropped, rec.FailedPackages...)
		sort.Strings(dropped)
	}
	return positions, dropped, found, nil
}

// consumerCallers keeps the edges owned by the consumer's own module and
// summarises them: how many call sites, and which of its functions they are in.
//
// The filter is what makes the answer "your code", not "some code in your
// build": an edge owned by another dependency is a call the consumer did not
// write and cannot fix.
func consumerCallers(refs []cgports.CallEdgeRef, consumer coordinate.ModuleCoordinate, positions map[string]cgdomain.SourcePosition) (int, []usedCaller) {
	sites := 0
	byID := map[string]struct{}{}
	for _, r := range refs {
		if r.ModulePath != consumer.Path() {
			continue
		}
		sites++
		byID[r.FromID] = struct{}{}
	}
	callers := make([]usedCaller, 0, len(byID))
	for id := range byID {
		c := usedCaller{ID: id}
		if pos, ok := positions[id]; ok {
			c.File, c.Line = pos.File, pos.Line
		}
		callers = append(callers, c)
	}
	sort.Slice(callers, func(i, j int) bool { return callers[i].ID < callers[j].ID })
	if len(callers) == 0 {
		return sites, nil
	}
	return sites, callers
}

// usedSetBreakingErr is the gate --used-by was asked for: the command ran to
// completion, measured the stored call graph, and found the consumer's own code
// calling a declaration this version bump removes or changes.
//
// That is ExitPolicy rather than ExitFailed or ExitConfig by the taxonomy's own
// logic: the work completed (so not 1/2/3), every record it named exists (so not
// 4), the invocation was well formed (so not 20), and the evidence is not in
// doubt (so not 10). What happened is that a gate the caller asked to enforce
// fired on real findings, which is exactly what 5 means — and a CI step must be
// able to route it to a human rather than to whoever fixes broken invocations.
func usedSetBreakingErr(used *usedByResult) error {
	if used == nil {
		return nil
	}
	reached := used.Reached()
	if len(reached) == 0 {
		return nil
	}
	names := make([]string, 0, len(reached))
	for _, s := range reached {
		names = append(names, s.Symbol.String())
	}
	return &exitError{code: ExitPolicy, msg: fmt.Sprintf(
		"breaking within the used set: %d of %d breaking change(s) are called by %s: %v",
		len(reached), len(used.Symbols), used.Consumer.Path(), names)}
}

// -- text output --

func printInterfaceDiff(diff ifacedomain.InterfaceDiff, used *usedByResult, stdout io.Writer) error {
	a := diff.RecordA.Coordinate
	b := diff.RecordB.Coordinate

	// The headline states the fact and the scope it holds over, on one line. A
	// zero here is "no exported signature changed" and nothing else: a measured
	// zero-breaking bump can still change what the code does, so the line must
	// not offer the reader a verdict it has not earned.
	if _, err := fmt.Fprintf(stdout,
		"%d breaking change(s) among exported Go declarations (%s@%s → %s@%s); "+
			"behaviour and string-keyed registries are outside this comparison\n",
		diff.BreakingCount(), a.Path(), a.Version(), b.Path(), b.Version()); err != nil {
		return fmt.Errorf("writing headline: %w", err)
	}
	counts := fmt.Sprintf("added: %d  removed: %d  changed: %d  spelling: %d",
		len(diff.Added), len(diff.Removed), len(diff.Changed), len(diff.Spelling))
	// Printed only for the pair that can have one, so a same-path comparison is
	// not given a column that is structurally always zero.
	if diff.MajorPathPair {
		counts += fmt.Sprintf("  renamed-path: %d", len(diff.RenamedPath))
	}
	if _, err := fmt.Fprintln(stdout, counts); err != nil {
		return fmt.Errorf("writing counts: %w", err)
	}

	if err := printFrameStatement(diff, stdout); err != nil {
		return err
	}
	if err := printCrossMajorStatement(diff, stdout); err != nil {
		return err
	}
	if err := printZeroBreakingStatement(diff, used, stdout); err != nil {
		return err
	}

	if err := printPackageDelta(diff, stdout); err != nil {
		return err
	}
	if err := printSymbolSection(stdout, "Removed", "-", diff.Removed); err != nil {
		return err
	}
	if err := printChangeSection(stdout, "Changed", diff.Changed); err != nil {
		return err
	}
	if err := printSymbolSection(stdout, "Added", "+", diff.Added); err != nil {
		return err
	}
	if err := printChangeSection(stdout,
		"Spelling (type-alias-equivalent, not breaking)", diff.Spelling); err != nil {
		return err
	}
	if err := printRenamedPathSection(diff, stdout); err != nil {
		return err
	}
	if err := printRegistrySection(diff, stdout); err != nil {
		return err
	}
	if err := printExcludedSection(diff, stdout); err != nil {
		return err
	}
	if err := printUsedBySection(used, stdout); err != nil {
		return err
	}

	if _, err := fmt.Fprintf(stdout, "\n%s\n", interfaceDiffCoverageNote); err != nil {
		return fmt.Errorf("writing coverage note: %w", err)
	}
	// A +incompatible side is a version the module system resolves under
	// pre-modules rules, so the two coordinates being compared are not two points
	// on one module's version line in the way the rest of this output implies.
	return writePreModulesCaveatForSet(stdout, []coordinate.ModuleCoordinate{
		diff.RecordA.Coordinate, diff.RecordB.Coordinate,
	})
}

// printCrossMajorStatement says what a cross-major pair costs a consumer, which
// the counts on their own do not: every import path changes, so every reached
// declaration needs rewriting whether or not its signature moved.
func printCrossMajorStatement(diff ifacedomain.InterfaceDiff, stdout io.Writer) error {
	if !diff.MajorPathPair {
		return nil
	}
	if _, err := fmt.Fprintf(stdout,
		"cross-major pair: the module path changes from %s to %s, so every import of it must be "+
			"rewritten — including the %d declaration(s) that carried over otherwise unchanged "+
			"(renamed-path: an import rewrite, not a breaking change). Declarations are matched by "+
			"package-relative path, kind and name rather than by import path.\n",
		diff.RecordA.Coordinate.Path(), diff.RecordB.Coordinate.Path(), len(diff.RenamedPath)); err != nil {
		return fmt.Errorf("writing cross-major statement: %w", err)
	}
	return nil
}

// printZeroBreakingStatement is the statement a zero-breaking result over a
// non-empty delta carries. See zeroBreakingBehaviourNote for why it is here and
// not in the footer.
func printZeroBreakingStatement(diff ifacedomain.InterfaceDiff, used *usedByResult, stdout io.Writer) error {
	if !diff.ZeroBreakingOverNonTrivialDelta() {
		return nil
	}
	if _, err := fmt.Fprintf(stdout, "%s\n", zeroBreakingBehaviourNote); err != nil {
		return fmt.Errorf("writing zero-breaking statement: %w", err)
	}
	if diff.MajorPathPair {
		if _, err := fmt.Fprintf(stdout, "  %s\n", zeroBreakingCrossMajorNote); err != nil {
			return fmt.Errorf("writing zero-breaking statement: %w", err)
		}
	}
	if used == nil {
		if _, err := fmt.Fprintf(stdout, "  %s\n", zeroBreakingNoUsedByNote); err != nil {
			return fmt.Errorf("writing zero-breaking statement: %w", err)
		}
		return nil
	}
	// The counts below are a join against the stored call graph. With no graph
	// stored for the consumer, that join is empty and TouchedReach() returns
	// 0, 0 — which would print as a measured "calls none of them" and read as
	// permission to bump. Say instead that it was not measured, and name the
	// same remedy the used-by section names.
	if !used.CallGraphFound {
		if _, err := fmt.Fprintf(stdout,
			"  what would answer it: exercise your own tests over the call sites this bump touches — "+
				"whether %s own code calls any of the %d declaration(s) it moved could NOT be measured: "+
				"there is no stored call graph for it; run: kanonarion local .\n",
			used.Consumer.Path(), len(used.Touched)); err != nil {
			return fmt.Errorf("writing zero-breaking statement: %w", err)
		}
		return nil
	}
	decls, sites := used.TouchedReach()
	if _, err := fmt.Fprintf(stdout,
		"  what would answer it: exercise your own tests over the call sites this bump touches — "+
			"%s own code calls %d of the %d declaration(s) it moved, at %s.\n",
		used.Consumer.Path(), decls, len(used.Touched), countOf(sites, "recorded call sites")); err != nil {
		return fmt.Errorf("writing zero-breaking statement: %w", err)
	}
	return nil
}

func printRenamedPathSection(diff ifacedomain.InterfaceDiff, stdout io.Writer) error {
	if len(diff.RenamedPath) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(stdout,
		"\nRenamed path (%d) — same declaration under the new module path, not breaking:\n",
		len(diff.RenamedPath)); err != nil {
		return fmt.Errorf("writing renamed-path header: %w", err)
	}
	for _, r := range diff.RenamedPath {
		if _, err := fmt.Fprintf(stdout, "  → %s\n      → %s\n",
			r.From.String(), r.To.String()); err != nil {
			return fmt.Errorf("writing renamed-path symbol: %w", err)
		}
	}
	return nil
}

func printPackageDelta(diff ifacedomain.InterfaceDiff, stdout io.Writer) error {
	for _, p := range diff.PackagesRemoved {
		if _, err := fmt.Fprintf(stdout, "\npackage removed: %s\n", p); err != nil {
			return fmt.Errorf("writing package delta: %w", err)
		}
	}
	for _, p := range diff.PackagesAdded {
		if _, err := fmt.Fprintf(stdout, "\npackage added: %s\n", p); err != nil {
			return fmt.Errorf("writing package delta: %w", err)
		}
	}
	return nil
}

func printSymbolSection(stdout io.Writer, title, marker string, syms []ifacedomain.Symbol) error {
	if len(syms) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(stdout, "\n%s (%d):\n", title, len(syms)); err != nil {
		return fmt.Errorf("writing section header: %w", err)
	}
	for _, s := range syms {
		if _, err := fmt.Fprintf(stdout, "  %s %s\n", marker, s.ID.String()); err != nil {
			return fmt.Errorf("writing symbol: %w", err)
		}
		if s.Signature != "" {
			if _, err := fmt.Fprintf(stdout, "      %s\n", ifacedomain.NormalizeSignature(s.Signature)); err != nil {
				return fmt.Errorf("writing signature: %w", err)
			}
		}
	}
	return nil
}

func printChangeSection(stdout io.Writer, title string, changes []ifacedomain.SignatureChange) error {
	if len(changes) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(stdout, "\n%s (%d):\n", title, len(changes)); err != nil {
		return fmt.Errorf("writing section header: %w", err)
	}
	for _, c := range changes {
		// Across a major path pair the declaration changed AND moved. Naming both
		// identities keeps the row honest about which symbol the consumer calls
		// today and which one it will be calling.
		name := c.Symbol.String()
		if (c.MovedTo != ifacedomain.SymbolID{}) {
			name += " → " + c.MovedTo.String()
		}
		if _, err := fmt.Fprintf(stdout, "  ~ %s\n      - %s\n      + %s\n",
			name,
			ifacedomain.NormalizeSignature(c.From),
			ifacedomain.NormalizeSignature(c.To)); err != nil {
			return fmt.Errorf("writing change: %w", err)
		}
	}
	return nil
}

func printRegistrySection(diff ifacedomain.InterfaceDiff, stdout io.Writer) error {
	if len(diff.Registries) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(stdout,
		"\nString-keyed registries (%d) — a contract outside this comparison:\n",
		len(diff.Registries)); err != nil {
		return fmt.Errorf("writing registry header: %w", err)
	}
	for _, r := range diff.Registries {
		if _, err := fmt.Fprintf(stdout, "  ! %s → %s  [in %s]\n",
			r.Symbol.String(), r.Shape, r.Side); err != nil {
			return fmt.Errorf("writing registry surface: %w", err)
		}
	}
	if _, err := fmt.Fprintln(stdout,
		"    The keys are strings resolved at run time; this command does not read them, "+
			"so a key renamed or dropped is not in any count above."); err != nil {
		return fmt.Errorf("writing registry note: %w", err)
	}
	return nil
}

// printFrameStatement names the build configuration each side was measured in,
// and says plainly when they are not the same one. A declaration that is in one
// platform's build and not the other's is reported as removed or changed by a
// comparison that cannot see the difference, so the reader is told which of the
// two questions this answer is about before reading any count.
func printFrameStatement(diff ifacedomain.InterfaceDiff, stdout io.Writer) error {
	if !diff.FrameMismatch {
		if _, err := fmt.Fprintf(stdout, "build frame: both sides %s\n", diff.RecordA.BuildFrame.String()); err != nil {
			return fmt.Errorf("writing build frame: %w", err)
		}
		return nil
	}
	if _, err := fmt.Fprintf(stdout,
		"build frame: %s → %s — the two sides were not measured in the same build, "+
			"so a change listed below may be a difference between platforms rather than between versions\n",
		diff.RecordA.BuildFrame.String(), diff.RecordB.BuildFrame.String()); err != nil {
		return fmt.Errorf("writing build frame mismatch: %w", err)
	}
	return nil
}

func printExcludedSection(diff ifacedomain.InterfaceDiff, stdout io.Writer) error {
	if len(diff.ExcludedTestdataPackages) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(stdout,
		"\nExcluded from the comparison (%d testdata package(s), not part of any module's API):\n",
		len(diff.ExcludedTestdataPackages)); err != nil {
		return fmt.Errorf("writing exclusion header: %w", err)
	}
	for _, p := range diff.ExcludedTestdataPackages {
		if _, err := fmt.Fprintf(stdout, "  · %s\n", p); err != nil {
			return fmt.Errorf("writing exclusion: %w", err)
		}
	}
	return nil
}

func printUsedBySection(used *usedByResult, stdout io.Writer) error {
	if used == nil {
		return nil
	}
	if _, err := fmt.Fprintf(stdout,
		"\nUsed by %s (walk %q, %s, frame %s, %d module versions in scope):\n",
		used.Consumer.Path(), used.WalkID, walkScopeLabel(used.WalkScope), used.WalkFrame, used.ScopeSize); err != nil {
		return fmt.Errorf("writing used-by header: %w", err)
	}
	// The walk was found by the module path the manifest declares, so the scope
	// above is that walk's build list and not, provably, the one this go.mod
	// resolves to now. Stated here because "your code does not call the removed
	// symbol" is exactly the answer an out-of-date scope gets wrong quietly.
	if used.GoMod != "" {
		basis := used.choice.basisNotes()
		if _, err := fmt.Fprintf(stdout, "  %s\n", strings.TrimPrefix(basis, "; ")); err != nil {
			return fmt.Errorf("writing used-by staleness: %w", err)
		}
	}
	if !used.CallGraphFound {
		if _, err := fmt.Fprintf(stdout,
			"  no stored call graph for %s — every reach count and per-declaration row in this "+
				"report is an absence of evidence, not a measurement of reach; "+
				"run: kanonarion local .\n", used.Consumer.Path()); err != nil {
			return fmt.Errorf("writing used-by absence: %w", err)
		}
	}
	if err := writeUsedByDroppedPackages(stdout, used); err != nil {
		return err
	}
	if len(used.Symbols) == 0 {
		if _, err := fmt.Fprintln(stdout, "  no breaking change to join."); err != nil {
			return fmt.Errorf("writing used-by empty: %w", err)
		}
	}
	for _, s := range used.Symbols {
		class := "changed"
		if s.Removed {
			class = "removed"
		}
		switch {
		case !s.Measurable:
			if _, err := fmt.Fprintf(stdout, "  ? %s [%s] — unmeasured: no call-graph node for this kind\n",
				s.Symbol.String(), class); err != nil {
				return fmt.Errorf("writing used-by row: %w", err)
			}
		case s.Sites == 0:
			if _, err := fmt.Fprintf(stdout, "  · %s [%s] — no call edge recorded from %s\n",
				s.Symbol.String(), class, used.Consumer.Path()); err != nil {
				return fmt.Errorf("writing used-by row: %w", err)
			}
		default:
			if _, err := fmt.Fprintf(stdout, "  ! %s [%s] — %s\n",
				s.Symbol.String(), class, countOf(s.Sites, "call sites")); err != nil {
				return fmt.Errorf("writing used-by row: %w", err)
			}
			for _, c := range s.Callers {
				loc := c.File
				if c.Line > 0 {
					loc = fmt.Sprintf("%s:%d", c.File, c.Line)
				}
				if loc == "" {
					loc = "(position not recorded)"
				}
				if _, err := fmt.Fprintf(stdout, "      %s  %s\n", c.ID, loc); err != nil {
					return fmt.Errorf("writing used-by caller: %w", err)
				}
			}
		}
	}
	if _, err := fmt.Fprintf(stdout, "  %s\n", usedByCoverageNote); err != nil {
		return fmt.Errorf("writing used-by coverage note: %w", err)
	}
	return nil
}

// -- JSON output --

// The field names follow the interface record's own short names — funcs,
// consts, vars — because those are what interface-show emits and what the
// stored record is keyed on. Renaming them here would make the two commands
// disagree about what the same declaration is called.
type interfaceDiffJSON struct {
	ModuleA          string                `json:"module_a"`
	ModuleB          string                `json:"module_b"`
	BreakingCount    int                   `json:"breaking_count"`
	Scope            string                `json:"scope"`
	PackagesAdded    []string              `json:"packages_added"`
	PackagesRemoved  []string              `json:"packages_removed"`
	Added            []symbolDeltaJSON     `json:"added"`
	Removed          []symbolDeltaJSON     `json:"removed"`
	Changed          []signatureChangeJSON `json:"changed"`
	Spelling         []signatureChangeJSON `json:"spelling"`
	MajorPathPair    bool                  `json:"major_path_pair"`
	RenamedPath      []renamedSymbolJSON   `json:"renamed_path"`
	Registries       []registrySurfaceJSON `json:"registries"`
	ExcludedTestdata []string              `json:"excluded_testdata_packages"`
	// BuildFrameA and BuildFrameB name the configuration each side was measured
	// in, and FrameMismatch is true when they are not the same one — the case in
	// which a listed change may be a platform difference, not a version one.
	BuildFrameA   string `json:"build_frame_a"`
	BuildFrameB   string `json:"build_frame_b"`
	FrameMismatch bool   `json:"frame_mismatch"`
	// ZeroBreakingAdvisory carries the statement the text output prints beside a
	// zero over a non-empty delta, and is absent exactly when that statement is
	// not printed — so a machine consumer sees the same distinction a reader does.
	ZeroBreakingAdvisory string      `json:"zero_breaking_advisory,omitempty"`
	UsedBy               *usedByJSON `json:"used_by,omitempty"`
}

type symbolDeltaJSON struct {
	Package   string `json:"package"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Signature string `json:"signature,omitempty"`
}

type signatureChangeJSON struct {
	Package string `json:"package"`
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	From    string `json:"from"`
	To      string `json:"to"`
	// MovedToPackage is the B-side import path when the declaration moved as well
	// as changed, which happens across a major path pair. Absent otherwise.
	MovedToPackage string `json:"moved_to_package,omitempty"`
}

// renamedSymbolJSON is one declaration carried across a major path pair
// unchanged. Package/Kind/Name are the A side — what the consumer calls today —
// and MovedToPackage is the import path it must be rewritten to.
type renamedSymbolJSON struct {
	Package        string `json:"package"`
	Kind           string `json:"kind"`
	Name           string `json:"name"`
	MovedToPackage string `json:"moved_to_package"`
	Signature      string `json:"signature,omitempty"`
}

type registrySurfaceJSON struct {
	Package string `json:"package"`
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	Shape   string `json:"shape"`
	Side    string `json:"side"`
}

type usedByJSON struct {
	GoMod  string `json:"gomod"`
	WalkID string `json:"walk_id"`
	// WalkFrame is the GOOS/GOARCH the answering walk resolved for, and
	// WalkFrameBasis the same fact as data so a consumer never has to recognise a
	// token: "platform", "not_platform_scoped" for a module-rooted walk (no
	// platform applies), or "unrecorded" (the platform is not known).
	WalkFrame      string `json:"walk_frame"`
	WalkFrameBasis string `json:"walk_frame_basis"`
	// WalkScope is the dependency scope the answering walk covered ("code",
	// "tool", "complete", or empty for a walk written before scopes were
	// recorded). It is beside the frame because both narrow which modules were
	// searched, and a count read without them is a count of an unnamed build.
	WalkScope string `json:"walk_scope"`
	// WalkSelection says how walk_id was arrived at. --used-by names a manifest,
	// never a walk, so the walk is always chosen for the caller: a consumer
	// reading walk_id has to be able to tell which rule picked it.
	WalkSelection  selectionJSON `json:"walk_selection"`
	Consumer       string        `json:"consumer"`
	ScopeSize      int           `json:"scope_size"`
	CallGraphFound bool          `json:"call_graph_found"`
	// DroppedPackages are the consumer's own packages that failed to typecheck,
	// so a call site declared in one of them cannot appear in any count here.
	DroppedPackages []string         `json:"dropped_packages,omitempty"`
	ReachedCount    int              `json:"reached_count"`
	Symbols         []usedSymbolJSON `json:"symbols"`
	// Touched is the non-breaking declarations this bump moved — respellings and
	// path renames — joined only when the zero-breaking statement is printed, and
	// never part of the gate.
	Touched             []usedSymbolJSON `json:"touched"`
	TouchedReachedCount int              `json:"touched_reached_count"`
	TouchedSites        int              `json:"touched_call_sites"`
	Coverage            string           `json:"coverage"`
}

type usedSymbolJSON struct {
	Package    string           `json:"package"`
	Kind       string           `json:"kind"`
	Name       string           `json:"name"`
	Class      string           `json:"class"`
	NodeID     string           `json:"node_id,omitempty"`
	Measurable bool             `json:"measurable"`
	Sites      int              `json:"sites"`
	Callers    []usedCallerJSON `json:"callers"`
}

type usedCallerJSON struct {
	ID   string `json:"id"`
	File string `json:"file,omitempty"`
	Line int    `json:"line,omitempty"`
}

func toInterfaceDiffJSON(diff ifacedomain.InterfaceDiff, used *usedByResult) interfaceDiffJSON {
	a := diff.RecordA.Coordinate
	b := diff.RecordB.Coordinate

	out := interfaceDiffJSON{
		ModuleA:       a.Path() + "@" + a.Version(),
		ModuleB:       b.Path() + "@" + b.Version(),
		BreakingCount: diff.BreakingCount(),
		Scope:         interfaceDiffCoverageNote,
		// Every collection is non-nil so the machine-readable answer spells an
		// empty result "[]" rather than "null".
		PackagesAdded:    nonNilStrings(diff.PackagesAdded),
		PackagesRemoved:  nonNilStrings(diff.PackagesRemoved),
		Added:            toSymbolDeltasJSON(diff.Added),
		Removed:          toSymbolDeltasJSON(diff.Removed),
		Changed:          toSignatureChangesJSON(diff.Changed),
		Spelling:         toSignatureChangesJSON(diff.Spelling),
		MajorPathPair:    diff.MajorPathPair,
		RenamedPath:      toRenamedPathJSON(diff.RenamedPath),
		Registries:       toRegistriesJSON(diff.Registries),
		ExcludedTestdata: nonNilStrings(diff.ExcludedTestdataPackages),
		BuildFrameA:      diff.RecordA.BuildFrame.String(),
		BuildFrameB:      diff.RecordB.BuildFrame.String(),
		FrameMismatch:    diff.FrameMismatch,
	}
	if diff.ZeroBreakingOverNonTrivialDelta() {
		out.ZeroBreakingAdvisory = zeroBreakingBehaviourNote
		if diff.MajorPathPair {
			out.ZeroBreakingAdvisory += " " + zeroBreakingCrossMajorNote
		}
	}
	if used != nil {
		out.UsedBy = toUsedByJSON(used)
	}
	return out
}

func toRenamedPathJSON(renamed []ifacedomain.RenamedSymbol) []renamedSymbolJSON {
	out := make([]renamedSymbolJSON, 0, len(renamed))
	for _, r := range renamed {
		out = append(out, renamedSymbolJSON{
			Package:        r.From.Package,
			Kind:           string(r.From.Kind),
			Name:           r.From.Name,
			MovedToPackage: r.To.Package,
			Signature:      ifacedomain.NormalizeSignature(r.Signature),
		})
	}
	return out
}

func nonNilStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

func toSymbolDeltasJSON(syms []ifacedomain.Symbol) []symbolDeltaJSON {
	out := make([]symbolDeltaJSON, 0, len(syms))
	for _, s := range syms {
		out = append(out, symbolDeltaJSON{
			Package:   s.ID.Package,
			Kind:      string(s.ID.Kind),
			Name:      s.ID.Name,
			Signature: ifacedomain.NormalizeSignature(s.Signature),
		})
	}
	return out
}

func toSignatureChangesJSON(changes []ifacedomain.SignatureChange) []signatureChangeJSON {
	out := make([]signatureChangeJSON, 0, len(changes))
	for _, c := range changes {
		row := signatureChangeJSON{
			Package: c.Symbol.Package,
			Kind:    string(c.Symbol.Kind),
			Name:    c.Symbol.Name,
			From:    ifacedomain.NormalizeSignature(c.From),
			To:      ifacedomain.NormalizeSignature(c.To),
		}
		if (c.MovedTo != ifacedomain.SymbolID{}) {
			row.MovedToPackage = c.MovedTo.Package
		}
		out = append(out, row)
	}
	return out
}

func toRegistriesJSON(surfaces []ifacedomain.RegistrySurface) []registrySurfaceJSON {
	out := make([]registrySurfaceJSON, 0, len(surfaces))
	for _, r := range surfaces {
		out = append(out, registrySurfaceJSON{
			Package: r.Symbol.Package,
			Kind:    string(r.Symbol.Kind),
			Name:    r.Symbol.Name,
			Shape:   r.Shape,
			Side:    string(r.Side),
		})
	}
	return out
}

func toUsedByJSON(used *usedByResult) *usedByJSON {
	touchedDecls, touchedSites := used.TouchedReach()
	out := &usedByJSON{
		GoMod:               used.GoMod,
		WalkID:              used.WalkID,
		WalkFrame:           used.WalkFrame.Text,
		WalkFrameBasis:      string(used.WalkFrame.Basis),
		WalkScope:           string(used.WalkScope),
		WalkSelection:       used.choice.selection(),
		Consumer:            used.Consumer.Path() + "@" + used.Consumer.Version(),
		ScopeSize:           used.ScopeSize,
		CallGraphFound:      used.CallGraphFound,
		DroppedPackages:     used.DroppedPackages,
		ReachedCount:        len(used.Reached()),
		Symbols:             toUsedSymbolsJSON(used.Symbols, ""),
		Touched:             toUsedSymbolsJSON(used.Touched, "touched"),
		TouchedReachedCount: touchedDecls,
		TouchedSites:        touchedSites,
		Coverage:            usedByCoverageNote,
	}
	return out
}

// toUsedSymbolsJSON renders one joined set. class, when non-empty, overrides the
// removed/changed classification: a touched declaration is neither.
func toUsedSymbolsJSON(syms []usedSymbol, class string) []usedSymbolJSON {
	out := make([]usedSymbolJSON, 0, len(syms))
	for _, s := range syms {
		rowClass := class
		if rowClass == "" {
			rowClass = "changed"
			if s.Removed {
				rowClass = "removed"
			}
		}
		callers := make([]usedCallerJSON, 0, len(s.Callers))
		for _, c := range s.Callers {
			callers = append(callers, usedCallerJSON(c))
		}
		out = append(out, usedSymbolJSON{
			Package:    s.Symbol.Package,
			Kind:       string(s.Symbol.Kind),
			Name:       s.Symbol.Name,
			Class:      rowClass,
			NodeID:     s.NodeID,
			Measurable: s.Measurable,
			Sites:      s.Sites,
			Callers:    callers,
		})
	}
	return out
}
