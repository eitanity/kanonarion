package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/callgraph/ports"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// classifyEmptyEdgeResult turns an empty callers/callees result into either
// nil (the symbol is a node in an analysed module — genuinely zero edges) or a
// directing error (so printing "[]" would be a false negative — /
// ). There are two distinct false-negative cases, both intent-aware per
// the consumer/author model in
// - the symbol's module was never analysed; or
// - the module was analysed but the symbol is not a node in its graph
// (a typo, or unexported/unreachable code).
func classifyEmptyEdgeResult(ctx context.Context, symbolID string, uc QueryCallGraphUseCase) error {
	sums, err := uc.ListCallGraphRecords(ctx, ports.CallGraphFilter{})
	if err != nil {
		return fmt.Errorf("listing analysed modules: %w", err)
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
func rootPartialStatus(ctx context.Context, symbolID string, uc QueryCallGraphUseCase) (symbolFailedPkg string, isPartial bool, failedPkgs []string, err error) {
	sums, err := uc.ListCallGraphRecords(ctx, ports.CallGraphFilter{})
	if err != nil {
		return "", false, nil, fmt.Errorf("listing analysed modules: %w", err)
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
		coord := fetchdomain.ModuleCoordinate{Path: s.ModulePath, Version: s.ModuleVersion}
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

// symbolIsKnownNode reports whether symbolID is a node in any analysed call
// graph record for modulePath (a module may have several analysed versions).
func symbolIsKnownNode(ctx context.Context, uc QueryCallGraphUseCase, symbolID, modulePath string, sums []ports.CallGraphSummary) (bool, error) {
	for _, s := range sums {
		if s.ModulePath != modulePath {
			continue
		}
		coord := fetchdomain.ModuleCoordinate{Path: s.ModulePath, Version: s.ModuleVersion}
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
