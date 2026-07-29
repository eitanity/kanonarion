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
)

// listScopedSummaries lists the analysed call graph records, keeping only those
// whose module@version is in scope.
//
// Every verdict helper below reasons over the records owning the queried symbol,
// and a module the store holds at four versions contributes four of them. Left
// unscoped they would read completeness, Partial status and dispatch evidence
// out of versions the build does not contain — so a query restricted to one
// build would still be answered, in part, by another. The filter belongs here
// rather than at the call sites so no helper can forget it.
func listScopedSummaries(ctx context.Context, uc QueryCallGraphUseCase, scope coordinate.ModuleSet) ([]ports.CallGraphSummary, error) {
	sums, err := uc.ListCallGraphRecords(ctx, ports.CallGraphFilter{})
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
	sums, err := listScopedSummaries(ctx, uc, scope)
	if err != nil {
		return err
	}
	paths := make([]string, 0, len(sums))
	for _, s := range sums {
		paths = append(paths, s.ModulePath)
	}
	modulePath, ok := domain.ResolveSymbolModule(symbolID, paths)
	if !ok {
		return unresolvedSymbolError(symbolID) // module never analysed
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

// rootPartialStatus loads the call graph record(s) owning symbolID and reports
// how a Partial graph affects a verdict rooted at that symbol. It returns:
//   - symbolFailedPkg: the failed-typecheck package the symbol itself belongs
//     to, if any. When non-empty, any callers/callees/reachability answer for
//     symbolID is unsound (the package's edges were dropped) and must be
//     downgraded to unresolved rather than rendered as a confident result.
//   - isPartial: whether the owning module's graph is Partial at all (edges may
//     be missing elsewhere in the module, so results are reported with a
//     caveat even when the symbol's own package typechecked).
//   - failedPkgs: the union of the owning module's failed packages, for messaging.
//
// A module with no analysed record (symbol's module never analysed) yields the
// zero value; that case is classified separately by classifyEmptyEdgeResult.
func rootPartialStatus(ctx context.Context, symbolID string, uc QueryCallGraphUseCase, scope coordinate.ModuleSet) (symbolFailedPkg string, isPartial bool, failedPkgs []string, err error) {
	sums, err := listScopedSummaries(ctx, uc, scope)
	if err != nil {
		return "", false, nil, err
	}
	paths := make([]string, 0, len(sums))
	for _, s := range sums {
		paths = append(paths, s.ModulePath)
	}
	modulePath, ok := domain.ResolveSymbolModule(symbolID, paths)
	if !ok {
		return "", false, nil, nil
	}

	failedSet := make(map[string]bool)
	for _, s := range sums {
		if s.ModulePath != modulePath {
			continue
		}
		coord, cErr := coordinate.NewModuleCoordinate(s.ModulePath, s.ModuleVersion)
		if cErr != nil {
			return "", false, nil, fmt.Errorf("call graph record %s@%s names no module: %w", s.ModulePath, s.ModuleVersion, cErr)
		}
		rec, found, gerr := uc.GetCallGraphRecord(ctx, coord, s.PipelineVersion)
		if gerr != nil {
			return "", false, nil, fmt.Errorf("loading call graph for %s: %w", coord, gerr)
		}
		if !found || rec.OverallStatus != domain.CallGraphStatusPartial {
			continue
		}
		isPartial = true
		for _, p := range rec.FailedPackages {
			failedSet[p] = true
		}
		if fp, hit := symbolFailedPackage(symbolID, rec.FailedPackages); hit && symbolFailedPkg == "" {
			symbolFailedPkg = fp
		}
	}
	if len(failedSet) > 0 {
		failedPkgs = make([]string, 0, len(failedSet))
		for p := range failedSet {
			failedPkgs = append(failedPkgs, p)
		}
		sort.Strings(failedPkgs)
	}
	return symbolFailedPkg, isPartial, failedPkgs, nil
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
// reported as an error there, not downgraded here.
func negativeCallVerdict(ctx context.Context, symbolID string, scanDispatch bool, uc QueryCallGraphUseCase, scope coordinate.ModuleSet, opts ports.EdgeQueryOptions) (domain.Verdict, error) {
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
		TestsExcludedByRequest: opts.ExcludeTests,
		// Start from Analysed and weaken on the first record that says otherwise:
		// a symbol answered from several analysed versions is only as measured as
		// the least-measured of them.
		TestScope: domain.TestScopeAnalysed,
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

// partialUnresolvedError is the directing diagnostic for a callers/callees/
// reachability query whose root belongs to a package that failed to typecheck.
// The call graph is Partial and that package's edges were dropped, so any
// "none"/empty answer would be a false negative. kind is "callers", "callees",
// or "transitive callers"/"transitive callees".
func partialUnresolvedError(kind, symbolID, failedPkg string) error {
	return fmt.Errorf(
		"unresolved — package %q did not typecheck, so the call graph is Partial "+
			"and %s of %q cannot be determined (the package's edges were dropped). "+
			"Fix the package so it compiles, then re-run analysis:\n"+
			"  kanonarion local <dir>",
		failedPkg, kind, symbolID)
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
