package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/callgraph/ports"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
)

// listScopedSummaries lists the call graph records this binary serves, keeping
// only those whose module@version is in scope.
//
// Two filters, and both are about answering from the right records.
//
// The pipeline version is the first. A record produced by superseded extraction
// logic is not served — that is what a pipeline bump means — so a helper that
// reasoned over one would describe an answer the query itself refused to draw
// on. That is not hypothetical: read unfiltered, an empty answer would take its
// soundness axes from a generation the edge query never consulted and report a
// cause that belongs to a record nobody is being served. A coordinate with no
// record at this version is a distinct condition with its own diagnostic; see
// supersededPipelineError.
//
// The build scope is the second. Every verdict helper below reasons over the
// records owning the queried symbol, and a module the store holds at four
// versions contributes four of them. Left unscoped they would read
// completeness, Partial status and dispatch evidence out of versions the build
// does not contain — so a query restricted to one build would still be
// answered, in part, by another. Both filters belong here rather than at the
// call sites so no helper can forget either.
func listScopedSummaries(ctx context.Context, uc QueryCallGraphUseCase, scope coordinate.ModuleSet) ([]ports.CallGraphSummary, error) {
	return listSummaries(ctx, uc, scope, ports.CallGraphFilter{PipelineVersion: cgapp.PipelineVersion})
}

// listStoredSummaries lists every record in scope whatever pipeline version
// produced it. It answers "what does the store hold for this module", which is
// what a diagnostic needs; nothing may answer a query from what it returns.
func listStoredSummaries(ctx context.Context, uc QueryCallGraphUseCase, scope coordinate.ModuleSet) ([]ports.CallGraphSummary, error) {
	return listSummaries(ctx, uc, scope, ports.CallGraphFilter{})
}

func listSummaries(ctx context.Context, uc QueryCallGraphUseCase, scope coordinate.ModuleSet, filter ports.CallGraphFilter) ([]ports.CallGraphSummary, error) {
	sums, err := uc.ListCallGraphRecords(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("listing analysed modules: %w", err)
	}
	if !scope.IsRestricted() {
		return sums, nil
	}
	out := make([]ports.CallGraphSummary, 0, len(sums))
	for _, s := range sums {
		if scope.ContainsPathVersion(s.ModulePath, s.ModuleVersion) {
			out = append(out, s)
		}
	}
	return out, nil
}

// supersededPipelineError is the diagnostic for a module the store has analysed
// only under superseded extraction logic. It is a false-negative case exactly
// like a module that was never analysed: the query found nothing because there
// is nothing here it is allowed to serve, and every other cause an empty answer
// could name — no callers, references unmeasured, a package that failed to
// typecheck — would send a reader after the wrong thing.
//
// It names the versions the store does hold, because "re-analyse" is only
// actionable against a coordinate, and the store's generations are the only
// place those coordinates are written down.
func supersededPipelineError(symbolID, modulePath string, stored []ports.CallGraphSummary) error {
	versions := make([]string, 0, len(stored))
	pipelines := make(map[string]bool)
	seen := make(map[string]bool)
	local := false
	for _, s := range stored {
		if s.ModulePath != modulePath {
			continue
		}
		pipelines[s.PipelineVersion] = true
		if s.ModuleVersion == coordinate.LocalVersion {
			local = true
		}
		if !seen[s.ModuleVersion] {
			seen[s.ModuleVersion] = true
			versions = append(versions, s.ModuleVersion)
		}
	}
	sort.Strings(versions)
	was := make([]string, 0, len(pipelines))
	for p := range pipelines {
		was = append(was, p)
	}
	sort.Strings(was)

	// The remedy is built from a coordinate, not from the path and version as
	// text: which command re-derives a graph is decided by what the coordinate
	// names, and a local one cannot be fetched.
	if len(versions) == 0 {
		// No stored version for this module path: there is no coordinate to name a
		// re-analysis of, and inventing one would print an invocation that resolves
		// to nothing.
		return fmt.Errorf(
			"symbol %q belongs to module %q, whose stored call graphs were produced by "+
				"superseded extraction logic and name no version this build can re-analyse",
			symbolID, modulePath)
	}
	remedyCoord, cErr := coordinate.NewModuleCoordinate(modulePath, versions[0])
	if local {
		remedyCoord, cErr = coordinate.NewLocalCoordinate(modulePath)
	}
	if cErr != nil {
		return fmt.Errorf("naming the re-analysis of module %q: %w", modulePath, cErr)
	}
	remedy := "  " + domain.ReanalysisCommand(remedyCoord, "")
	return fmt.Errorf(
		"symbol %q belongs to module %q, whose every stored call graph was produced by "+
			"superseded extraction logic: this build serves pipeline %s and the store holds "+
			"%s at pipeline %s. A superseded record is not served, so this answer is empty for want "+
			"of a measurement of this module, not because the code holds nothing. Re-analyse it:\n%s",
		symbolID, modulePath, cgapp.PipelineVersion,
		strings.Join(versions, ", "), strings.Join(was, ", "), remedy)
}

// moduleServedAtThisPipeline reports whether any served record covers
// modulePath. It reads summaries already filtered to the serving version.
func moduleServedAtThisPipeline(modulePath string, served []ports.CallGraphSummary) bool {
	for _, s := range served {
		if s.ModulePath == modulePath {
			return true
		}
	}
	return false
}

// checkSymbolInScope refuses a scoped query whose symbol belongs to a module the
// store has analysed but that the named build does not contain at any of the
// analysed versions.
//
// Without it that query returns an empty result and a RESOLVED-ABSENT verdict:
// the answer to "nothing calls this in your build" and the answer to "this isn't
// in your build at all" would be the same output. The second is not a
// measurement of reachability, and reporting it as one is exactly the false
// confidence the scope filter exists to remove.
func checkSymbolInScope(ctx context.Context, symbolID string, uc QueryCallGraphUseCase, sc buildScope) error {
	if !sc.modules.IsRestricted() {
		return nil
	}
	all, err := uc.ListCallGraphRecords(ctx, ports.CallGraphFilter{})
	if err != nil {
		return fmt.Errorf("listing analysed modules: %w", err)
	}
	paths := make([]string, 0, len(all))
	for _, s := range all {
		paths = append(paths, s.ModulePath)
	}
	modulePath, ok := domain.ResolveSymbolModule(symbolID, paths)
	if !ok {
		// The module was never analysed at any version; that is a different
		// diagnostic, raised by classifyEmptyEdgeResult with its own guidance.
		return nil
	}

	analysed := make(map[string]bool)
	for _, s := range all {
		if s.ModulePath == modulePath {
			analysed[s.ModuleVersion] = true
			if sc.modules.ContainsPathVersion(s.ModulePath, s.ModuleVersion) {
				return nil
			}
		}
	}

	versions := make([]string, 0, len(analysed))
	for v := range analysed {
		versions = append(versions, v)
	}
	sort.Strings(versions)

	inBuild := sc.modules.VersionsOf(modulePath)
	switch {
	case len(inBuild) == 0:
		return fmt.Errorf(
			"symbol %q belongs to module %q, which %s does not contain; "+
				"analysed versions in the store are %s. Drop the scope flag to query "+
				"across every stored version",
			symbolID, modulePath, sc.source, strings.Join(versions, ", "))
	default:
		return fmt.Errorf(
			"symbol %q belongs to module %q, which %s resolves to %s — a version that "+
				"has not been analysed; analysed versions are %s. Analyse the version "+
				"the build uses:\n  kanonarion callgraph %s@%s",
			symbolID, modulePath, sc.source, strings.Join(inBuild, ", "),
			strings.Join(versions, ", "), modulePath, inBuild[0])
	}
}

// classifyEmptyEdgeResult turns an empty callers/callees result into either
// nil (the symbol is a node in an analysed module — genuinely zero edges) or a
// directing error (so printing "[]" would be a false negative — /
// ). There are two distinct false-negative cases, both intent-aware per
// the consumer/author model in
// - the symbol's module was never analysed; or
// - the module was analysed but the symbol is not a node in its graph
// (a typo, or unexported/unreachable code).
func classifyEmptyEdgeResult(ctx context.Context, symbolID string, uc QueryCallGraphUseCase, scope coordinate.ModuleSet) error {
	// The module is resolved against everything the store holds, not only what
	// is served: a module analysed solely under superseded logic still owns its
	// symbol, and reporting it as never analysed would name the wrong remedy.
	stored, err := listStoredSummaries(ctx, uc, scope)
	if err != nil {
		return err
	}
	paths := make([]string, 0, len(stored))
	for _, s := range stored {
		paths = append(paths, s.ModulePath)
	}
	modulePath, ok := domain.ResolveSymbolModule(symbolID, paths)
	if !ok {
		return unresolvedSymbolError(symbolID) // module never analysed
	}

	sums, err := listScopedSummaries(ctx, uc, scope)
	if err != nil {
		return err
	}
	if !moduleServedAtThisPipeline(modulePath, sums) {
		return supersededPipelineError(symbolID, modulePath, stored)
	}
	// The module was analysed. Zero edges is only a genuine answer if the
	// symbol is actually a vertex in the graph; otherwise "no callers/callees"
	// is an absence-as-answer for a symbol the store has never seen.
	known, err := symbolIsKnownNode(ctx, uc, symbolID, modulePath, sums)
	if err != nil {
		return err
	}
	if known {
		return nil // analysed, genuinely zero edges
	}
	return errors.New(unknownNodeMessage(symbolID, modulePath))
}

// partialRoot is how a Partial call graph bears on a query rooted at one symbol.
//
// It is a struct rather than a tuple because the dropped-package case needs the
// coordinate as well as the package name: which command re-derives that graph is
// decided by the coordinate, and a caller handed only the package name would
// have to guess.
type partialRoot struct {
	// failedPkg is the failed-typecheck package the queried symbol itself belongs
	// to, empty when its own package typechecked. When set, every edge with an
	// end in that package was dropped, so the answer is unmeasured about the
	// symbol's own side of the graph.
	failedPkg string
	// coord is the record that dropped failedPkg — the module whose analysis
	// failed, which is not always one the reader owns.
	coord coordinate.ModuleCoordinate
	// isPartial reports whether the owning module's graph is Partial at all:
	// edges may be missing elsewhere in the module even when the symbol's own
	// package typechecked.
	isPartial bool
	// failedPkgs is the union of the owning module's failed packages, for
	// messaging.
	failedPkgs []string
	// cause is what the record says limited it: the module's own sources, or the
	// environment the analysis ran in. It decides which remedy is printed, and a
	// remedy chosen without it sends the reader after the wrong fault.
	cause domain.FailureCause
}

// rootPartialStatus loads the call graph record(s) owning symbolID and reports
// how a Partial graph affects a query rooted at that symbol.
//
// A module with no analysed record (symbol's module never analysed) yields the
// zero value; that case is classified separately by classifyEmptyEdgeResult.
func rootPartialStatus(ctx context.Context, symbolID string, uc QueryCallGraphUseCase, scope coordinate.ModuleSet) (partialRoot, error) {
	var out partialRoot
	sums, err := listScopedSummaries(ctx, uc, scope)
	if err != nil {
		return partialRoot{}, err
	}
	paths := make([]string, 0, len(sums))
	for _, s := range sums {
		paths = append(paths, s.ModulePath)
	}
	modulePath, ok := domain.ResolveSymbolModule(symbolID, paths)
	if !ok {
		return partialRoot{}, nil
	}

	failedSet := make(map[string]bool)
	for _, s := range sums {
		if s.ModulePath != modulePath {
			continue
		}
		coord, cErr := coordinate.NewModuleCoordinate(s.ModulePath, s.ModuleVersion)
		if cErr != nil {
			return partialRoot{}, fmt.Errorf("call graph record %s@%s names no module: %w", s.ModulePath, s.ModuleVersion, cErr)
		}
		rec, found, gerr := uc.GetCallGraphRecord(ctx, coord, s.PipelineVersion)
		if gerr != nil {
			return partialRoot{}, fmt.Errorf("loading call graph for %s: %w", coord, gerr)
		}
		if !found || rec.OverallStatus != domain.CallGraphStatusPartial {
			continue
		}
		out.isPartial = true
		for _, p := range rec.FailedPackages {
			failedSet[p] = true
		}
		if fp, hit := symbolFailedPackage(symbolID, rec.FailedPackages); hit && out.failedPkg == "" {
			out.failedPkg = fp
			out.coord = coord
			out.cause = rec.FailureCause
		}
	}
	if len(failedSet) > 0 {
		out.failedPkgs = make([]string, 0, len(failedSet))
		for p := range failedSet {
			out.failedPkgs = append(out.failedPkgs, p)
		}
		sort.Strings(out.failedPkgs)
	}
	return out, nil
}

// rootCompletenessCaveat returns a phase-appropriate caveat when the module
// owning symbolID was analysed below full fidelity (not BUILT_WITH_BODIES), or
// "" when it was built with bodies (or is not resolvable / not stored). It is
// the completeness sibling of rootPartialStatus: the Partial notice covers a
// package that failed to typecheck, this covers a module built type-only /
// metadata-only, where dispatch edges are simply absent. The query commands run
// in the coding phase, so a below-full module is an instruction to rebuild.
func rootCompletenessCaveat(ctx context.Context, symbolID string, uc QueryCallGraphUseCase, phase domain.AnalysisPhase, scope coordinate.ModuleSet) (string, error) {
	sums, err := listScopedSummaries(ctx, uc, scope)
	if err != nil {
		return "", err
	}
	paths := make([]string, 0, len(sums))
	for _, s := range sums {
		paths = append(paths, s.ModulePath)
	}
	modulePath, ok := domain.ResolveSymbolModule(symbolID, paths)
	if !ok {
		return "", nil
	}
	for _, s := range sums {
		if s.ModulePath != modulePath {
			continue
		}
		// Read the level off the SUMMARY, which already describes the generation
		// composition serves. Loading the record here would decode every stored
		// generation's blob and reconstruct all of their edges — measured at 1.5s
		// for a three-generation module with 344k edges — to read one field the
		// summary is already holding, on every callers/callees/implementers query.
		//
		// Only a definite below-full level warrants a caveat. Unknown (a legacy
		// record, one from a path that recorded no level, or a module whose
		// generations are in conflict, which the summary reports with its other
		// fields zeroed) and BuiltWithBodies both stay silent — we never invent a
		// caveat we cannot substantiate. A conflicted module is not silently
		// dropped: the edge query itself refuses it with ErrCallGraphConflict.
		if s.Completeness == domain.CompletenessUnknown || s.Completeness.IsBuiltWithBodies() {
			continue
		}
		if caveat := domain.CompletenessCaveat(s.Completeness, phase); caveat != "" {
			return caveat, nil
		}
	}
	return "", nil
}

// negativeCallVerdict classifies an empty callers/callees answer for symbolID
// into RESOLVED-ABSENT or UNRESOLVED, per the dispatch/edge-level soundness gate
// (see domain.ClassifyNegativeVerdict). It loads the owning module's record(s) to
// read the queried node's leaf facts, the module's completeness level, and — for
// a callers query (scanDispatch) — the module edges scanned for unresolved
// interface invoke sites that dispatch on the queried method's name.
//
// It is only meaningful once classifyEmptyEdgeResult has confirmed the symbol is
// a known node in an analysed module; a symbol whose module was never analysed is
// reported as an error there, not downgraded here. The one exception is
// droppedPkg: a symbol whose own package failed to typecheck is not a node in any
// graph, so classifyEmptyEdgeResult is deliberately skipped for it and the
// dropped package carried here is what keeps the verdict off ABSENT.
func negativeCallVerdict(ctx context.Context, symbolID string, scanDispatch bool, uc QueryCallGraphUseCase, scope coordinate.ModuleSet, opts ports.EdgeQueryOptions, droppedPkg string) (domain.Verdict, error) {
	sums, err := listScopedSummaries(ctx, uc, scope)
	if err != nil {
		return domain.Verdict{}, err
	}
	paths := make([]string, 0, len(sums))
	for _, s := range sums {
		paths = append(paths, s.ModulePath)
	}
	modulePath, ok := domain.ResolveSymbolModule(symbolID, paths)
	if !ok {
		// Unreachable in practice (the caller resolves the module first); a
		// module we cannot resolve carries no dispatch signal, so it is absent.
		return domain.Verdict{Outcome: domain.VerdictResolvedAbsent}, nil
	}

	owning := make([]ports.CallGraphSummary, 0, len(sums))
	for _, s := range sums {
		if s.ModulePath == modulePath {
			owning = append(owning, s)
		}
	}
	sort.Slice(owning, func(i, j int) bool { return owning[i].ModuleVersion < owning[j].ModuleVersion })

	in := domain.NegativeVerdictInputs{
		MethodName:             domain.SymbolMethodName(symbolID),
		NodesByID:              map[string]domain.CallNode{},
		ScanDispatch:           scanDispatch,
		DroppedEdgePackage:     droppedPkg,
		TestsExcludedByRequest: opts.ExcludeTests,
		// Start from Analysed and weaken on the first record that says otherwise:
		// a symbol answered from several analysed versions is only as measured as
		// the least-measured of them.
		TestScope: domain.TestScopeAnalysed,
		// Same rule for the reference axis: a graph extracted before function
		// values were recorded says nothing about registrations, and one record
		// that did not look is enough to make the answer unproven.
		ReferenceScope: domain.ReferenceScopeAnalysed,
	}
	belowFull := domain.CompletenessUnknown
	for _, s := range owning {
		coord, cErr := coordinate.NewModuleCoordinate(s.ModulePath, s.ModuleVersion)
		if cErr != nil {
			return domain.Verdict{}, fmt.Errorf("call graph record %s@%s names no module: %w", s.ModulePath, s.ModuleVersion, cErr)
		}
		rec, found, gerr := uc.GetCallGraphRecord(ctx, coord, s.PipelineVersion)
		if gerr != nil {
			return domain.Verdict{}, fmt.Errorf("loading call graph for %s: %w", coord, gerr)
		}
		if !found {
			continue
		}
		in.Edges = append(in.Edges, rec.Edges...)
		for i := range rec.Nodes {
			n := rec.Nodes[i]
			in.NodesByID[n.ID] = n
			if n.ID == symbolID {
				in.QueriedNode = n
				in.Found = true
				in.ModuleLevel = rec.Completeness
			}
		}
		if belowFull == domain.CompletenessUnknown &&
			rec.Completeness != domain.CompletenessUnknown && !rec.Completeness.IsBuiltWithBodies() {
			belowFull = rec.Completeness
		}
		if !rec.TestScope.IsMeasured() && in.TestScope.IsMeasured() {
			in.TestScope = rec.TestScope
			in.TestScopeDetail = rec.TestScopeDetail
		}
		if !rec.ReferenceScope.IsMeasured() {
			in.ReferenceScope = rec.ReferenceScope
		}
	}
	// When the symbol is not itself a node (e.g. its package was built type-only
	// so it produced no SSA node), fall back to the least-complete level seen so a
	// below-full module still downgrades the verdict.
	if !in.Found {
		in.ModuleLevel = belowFull
	}
	// No record was consulted at all: nothing has claimed the test axis was
	// measured, so it has not been.
	if len(owning) == 0 {
		in.TestScope = domain.TestScopeUnknown
		in.ReferenceScope = domain.ReferenceScopeUnknown
	}

	return domain.ClassifyNegativeVerdict(in), nil
}

// writeCallVerdict prints, in text mode, the three-valued verdict for an empty
// callers/callees answer: a confident RESOLVED-ABSENT, or an UNRESOLVED verdict
// with the soundness sinks named so a reviewer can act on them. kind is
// "callers", "callees", or the transitive variants.
func writeCallVerdict(stdout io.Writer, kind, symbolID string, v domain.Verdict, opts ports.EdgeQueryOptions) error {
	// A scope the caller chose is stated on the verdict line, not folded into
	// the outcome: --exclude-tests narrows what "none" covers, and a reader who
	// cannot see that narrowing will read the answer as wider than it is.
	scope := ""
	if opts.ExcludeTests {
		scope = " (production only; --" + testScopeFlagName + " was given)"
	}
	switch v.Outcome {
	case domain.VerdictUnresolved:
		if _, err := fmt.Fprintf(stdout,
			"verdict: UNRESOLVED — %s of %s cannot be confirmed absent%s: %s\n",
			kind, symbolID, scope, v.Reason()); err != nil {
			return fmt.Errorf("writing verdict: %w", err)
		}
	default:
		if _, err := fmt.Fprintf(stdout,
			"verdict: RESOLVED-ABSENT — no %s of %s across a fully-built path%s\n",
			kind, symbolID, scope); err != nil {
			return fmt.Errorf("writing verdict: %w", err)
		}
	}
	return nil
}

// symbolFailedPackage reports whether symbolID belongs to one of failedPkgs,
// matching by import path. A symbol "<pkg>.<Name>" (or "<pkg>.(*T).M") belongs
// to package pkg exactly when the character after the package path is '.', so a
// sub-package ("<pkg>/sub.Fn", where the next char is '/') is correctly
// excluded. This works even when the symbol never became a graph node — a
// package that fails to typecheck produces no SSA and no nodes, so a node-index
// lookup would miss exactly the symbols this must catch.
func symbolFailedPackage(symbolID string, failedPkgs []string) (string, bool) {
	for _, p := range failedPkgs {
		if p == "" || !strings.HasPrefix(symbolID, p) {
			continue
		}
		if len(symbolID) > len(p) && symbolID[len(p)] == '.' {
			return p, true
		}
	}
	return "", false
}

// droppedEdgesNotice states that the queried symbol's own package failed to
// typecheck, so every edge with an end inside it was dropped.
//
// It is a notice and not a refusal. The refusal it replaces treated the gap as a
// property of the SYMBOL and returned exit 20, which suppressed answers the store
// held: a callee's package dropping its edges says nothing about the edges INTO
// it recorded in a consumer's own, complete graph, and interface-diff --used-by
// was answering that same question off those edges while this path refused it.
// One binary cannot hold two opinions about whether a question is answerable, so
// this path now answers and states what its answer does not cover.
//
// kind is "callers", "callees", or the transitive variants.
func droppedEdgesNotice(kind, symbolID string, pr partialRoot) string {
	line := fmt.Sprintf(
		"notice: unmeasured on one side — package %q did not typecheck when %s was analysed, so edges "+
			"with an end inside it were dropped; the %s of %s listed below are what the store does hold "+
			"(chiefly edges recorded in other modules' graphs), and an edge inside %s that is not listed "+
			"is unmeasured rather than known to be absent",
		pr.failedPkg, pr.coord, kind, symbolID, pr.failedPkg)
	// Which remedy, and whether it needs --force, are decided by the record's own
	// stated cause rather than here: a published dependency's build failure is not
	// the reader's to fix, and a gap this host's cold module cache opened is not a
	// compile error to go looking for. Naming a command that cannot run and naming
	// one that re-serves the record complained about are the same defect.
	return line + ".\n" + domain.IncompleteGraphRemedy(pr.coord, pr.cause, "")
}

// writeDroppedEdgesNotice prints droppedEdgesNotice, in text mode only.
func writeDroppedEdgesNotice(stdout io.Writer, kind, symbolID string, pr partialRoot) error {
	if _, err := fmt.Fprintln(stdout, droppedEdgesNotice(kind, symbolID, pr)); err != nil {
		return fmt.Errorf("writing dropped-edges notice: %w", err)
	}
	return nil
}

// writePartialNotice prints, in text mode only, a caveat that the result was
// computed over a Partial call graph so absences may be under-reported. It is
// emitted for every callers/callees/reachability answer over a Partial graph
// whose root package itself typechecked (the root-in-failed-package case is a
// hard error, not a caveat). Never emitted for an Extracted graph.
func writePartialNotice(stdout io.Writer, kind, symbolID string, failedPkgs []string) error {
	pkgs := "some packages"
	if len(failedPkgs) > 0 {
		pkgs = strings.Join(failedPkgs, ", ")
	}
	if _, err := fmt.Fprintf(stdout,
		"notice: call graph is Partial — %s did not typecheck; %s of %s may be incomplete (edges in the failed package(s) were dropped)\n",
		pkgs, kind, symbolID); err != nil {
		return fmt.Errorf("writing partial notice: %w", err)
	}
	return nil
}

// writeCompletenessNotice prints, in text mode, the coding-phase caveat for a
// queried module analysed below full fidelity, or nothing when it was built with
// bodies. It rides alongside any Partial notice: the two describe different
// gaps (a failed package vs a module built type-/metadata-only).
func writeCompletenessNotice(ctx context.Context, symbolID string, uc QueryCallGraphUseCase, stdout io.Writer, scope coordinate.ModuleSet) error {
	caveat, err := rootCompletenessCaveat(ctx, symbolID, uc, domain.PhaseCoding, scope)
	if err != nil {
		return err
	}
	if caveat == "" {
		return nil
	}
	if _, werr := fmt.Fprintf(stdout, "notice: %s\n", caveat); werr != nil {
		return fmt.Errorf("writing completeness notice: %w", werr)
	}
	return nil
}

// worktreeRouter is the optional read that says which working tree answered.
//
// It is asserted at the call site rather than added to QueryCallGraphUseCase so
// that a caller wired to a use case that cannot answer it prints no notice,
// which is the honest outcome: nothing is known about which tree served, so
// nothing is claimed.
type worktreeRouter interface {
	WorktreeRouting(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (ports.WorktreeRouting, bool, error)
}

// writeWorktreeNotice states, in text mode, which working tree answered a query
// about a local coordinate — but only when the ledger holds more than one.
//
// The condition is the whole design. A routing decision the reader cannot see is
// the defect this exists to close, and replacing a silent wrong tree with a
// silent right one would not close it; but a reader with a single checkout has
// no decision to see, and a line on every answer would be noise on every answer.
//
// The miss is stated as loudly as the hit. A caller standing in a tree the
// ledger has no generation of gets an answer from another tree — which is what
// they got before any of this existed — and being told so is the difference
// between a stale answer and a stale answer they can act on.
func writeWorktreeNotice(ctx context.Context, symbolID string, uc QueryCallGraphUseCase, stdout io.Writer, scope coordinate.ModuleSet) error {
	router, ok := uc.(worktreeRouter)
	if !ok {
		return nil
	}
	coord, ok, err := localCoordinateOwning(ctx, symbolID, uc, scope)
	if err != nil || !ok {
		return err
	}
	r, found, err := router.WorktreeRouting(ctx, coord, cgapp.PipelineVersion)
	if err != nil {
		return fmt.Errorf("resolving which working tree answers for %s: %w", coord, err)
	}
	if !found || !r.WorthReporting() {
		return nil
	}
	if _, werr := fmt.Fprintf(stdout, "notice: %s\n", worktreeNoticeText(coord, r)); werr != nil {
		return fmt.Errorf("writing worktree notice: %w", werr)
	}
	return nil
}

// worktreeNoticeText renders the routing decision for one coordinate.
func worktreeNoticeText(coord coordinate.ModuleCoordinate, r ports.WorktreeRouting) string {
	served := "an earlier generation that recorded no working tree"
	if r.ServedRoot != "" {
		served = "the working tree at " + r.ServedRoot
	}
	predating := fmt.Sprintf("%d %s written before the analysed tree was recorded",
		r.UnlocatedGenerations, pluralise(r.UnlocatedGenerations, "generation", "generations"))
	var held string
	switch {
	case r.LocatedTrees == 0:
		held = fmt.Sprintf("the ledger names no working tree for %s at all — only %s", coord, predating)
	case r.UnlocatedGenerations == 0:
		held = fmt.Sprintf("the ledger holds %d working %s for %s",
			r.LocatedTrees, pluralise(r.LocatedTrees, "tree", "trees"), coord)
	default:
		held = fmt.Sprintf("the ledger holds %d working %s for %s, plus %s",
			r.LocatedTrees, pluralise(r.LocatedTrees, "tree", "trees"), coord, predating)
	}
	switch {
	case r.Matched:
		return fmt.Sprintf("answered from the working tree you are in, %s (tree %s); %s",
			r.ServedRoot, r.ServedDigest, held)
	case r.CallerRoot != "":
		return fmt.Sprintf("NOT answered from the working tree you are in: %s has no analysed generation, "+
			"so the answer comes from %s (tree %s); %s. Analyse this tree to be answered from it:\n"+
			"  kanonarion local %s",
			r.CallerRoot, served, r.ServedDigest, held, r.CallerRoot)
	default:
		return fmt.Sprintf("answered from %s (tree %s); %s, and you are not standing in any of them",
			served, r.ServedDigest, held)
	}
}

// pluralise picks the singular or plural form for n.
func pluralise(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// localCoordinateOwning resolves the symbol to the local coordinate of the
// module that declares it, when the store holds one. Everything else — a symbol
// in a published dependency, a symbol in a module never analysed locally — has
// no working tree behind it and nothing to say about one.
func localCoordinateOwning(ctx context.Context, symbolID string, uc QueryCallGraphUseCase, scope coordinate.ModuleSet) (coordinate.ModuleCoordinate, bool, error) {
	sums, err := listScopedSummaries(ctx, uc, scope)
	if err != nil {
		return coordinate.ModuleCoordinate{}, false, err
	}
	paths := make([]string, 0, len(sums))
	for _, sum := range sums {
		paths = append(paths, sum.ModulePath)
	}
	modulePath, ok := domain.ResolveSymbolModule(symbolID, paths)
	if !ok {
		return coordinate.ModuleCoordinate{}, false, nil
	}
	for _, sum := range sums {
		if sum.ModulePath != modulePath || sum.ModuleVersion != coordinate.LocalVersion {
			continue
		}
		coord, cErr := coordinate.NewLocalCoordinate(modulePath)
		if cErr != nil {
			return coordinate.ModuleCoordinate{}, false, fmt.Errorf("constructing the local coordinate for %s: %w", modulePath, cErr)
		}
		return coord, true, nil
	}
	return coordinate.ModuleCoordinate{}, false, nil
}

// symbolIsKnownNode reports whether symbolID is a node in any analysed call
// graph record for modulePath (a module may have several analysed versions).
func symbolIsKnownNode(ctx context.Context, uc QueryCallGraphUseCase, symbolID, modulePath string, sums []ports.CallGraphSummary) (bool, error) {
	for _, s := range sums {
		if s.ModulePath != modulePath {
			continue
		}
		coord, cErr := coordinate.NewModuleCoordinate(s.ModulePath, s.ModuleVersion)
		if cErr != nil {
			return false, fmt.Errorf("call graph record %s@%s names no module: %w", s.ModulePath, s.ModuleVersion, cErr)
		}
		rec, found, err := uc.GetCallGraphRecord(ctx, coord, s.PipelineVersion)
		if err != nil {
			return false, fmt.Errorf("loading call graph for %s: %w", coord, err)
		}
		if !found {
			continue
		}
		for i := range rec.Nodes {
			if rec.Nodes[i].ID == symbolID {
				return true, nil
			}
		}
	}
	return false, nil
}

// unknownNodeMessage is the diagnostic for a symbol whose module was analysed
// but which is not a node in the stored call graph: distinct from
// the module-never-analysed case so the user knows analysis ran and the symbol
// itself is the problem.
func unknownNodeMessage(symbolID, modulePath string) string {
	return fmt.Sprintf(
		"symbol %q is not a node in the analysed call graph of module %q: "+
			"it may be a typo, or unexported/unreachable code. Verify the "+
			"symbol, or list the module's known symbols:\n"+
			"  kanonarion callgraph-show %s",
		symbolID, modulePath, modulePath)
}

// unresolvedSymbolError builds the intent-aware diagnostic for a symbol whose
// containing module is absent from the call-graph store. The
// local module path is read from the working tree's go.mod (best effort);
// classification is delegated to the pure unresolvedSymbolMessage.
func unresolvedSymbolError(symbolID string) error {
	localModulePath, err := readGoModulePath("go.mod")
	if err != nil {
		localModulePath = ""
	}
	return errors.New(unresolvedSymbolMessage(symbolID, localModulePath))
}

// unresolvedSymbolMessage is the pure intent classifier: if symbolID belongs
// to localModulePath it is author-mode (direct to 'local'); otherwise it is
// consumer-mode (direct to 'callgraph'). localModulePath may be "" when the
// working tree has no go.mod.
func unresolvedSymbolMessage(symbolID, localModulePath string) string {
	if localModulePath != "" {
		if _, ok := domain.ResolveSymbolModule(symbolID, []string{localModulePath}); ok {
			return fmt.Sprintf(
				"symbol %q is not in the call-graph store: it belongs to the local "+
					"module %q (author-mode code); ingest the working tree "+
					"first:\n  kanonarion local <dir>",
				symbolID, localModulePath)
		}
	}
	return fmt.Sprintf(
		"symbol %q is not in the call-graph store: its module has not been "+
			"analysed (consumer-mode code). Analyse it first, e.g.:\n"+
			"  kanonarion callgraph <module>@<version>",
		symbolID)
}
