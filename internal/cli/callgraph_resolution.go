package cli

import (
	"context"
	"errors"
	"fmt"

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
