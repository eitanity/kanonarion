package application

import (
	"context"
	"fmt"

	"github.com/eitanity/kanonarion/internal/local/domain"
	"github.com/eitanity/kanonarion/internal/local/ports"
)

// LocalContextRequest parameterises a local workspace context analysis.
type LocalContextRequest struct {
	// Root is the local workspace directory to analyse.
	Root string
	// AnalysisLevel controls the depth of analysis.
	AnalysisLevel domain.AnalysisLevel
}

// LocalContextUseCase builds an AI-ready context document for a local Go
// workspace by analysing which dependency packages (and optionally symbols)
// are actually used.
type LocalContextUseCase struct {
	snapshot ports.SnapshotBuilder
	imports  ports.ImportAnalyser
	symbols  ports.SymbolAnalyser // may be nil; only used at AnalysisLevelSymbol
}

// NewLocalContextUseCase constructs a LocalContextUseCase. symbols may be nil
// when symbol-level analysis is not needed (import-level only).
func NewLocalContextUseCase(
	snapshot ports.SnapshotBuilder,
	imports ports.ImportAnalyser,
	symbols ports.SymbolAnalyser,
) *LocalContextUseCase {
	return &LocalContextUseCase{
		snapshot: snapshot,
		imports:  imports,
		symbols:  symbols,
	}
}

// Execute runs the analysis and returns the local workspace context. The
// snapshot is built to obtain a deterministic VersionID and the module path;
// the actual import/symbol analysis runs against the root directory on disk.
func (uc *LocalContextUseCase) Execute(ctx context.Context, req LocalContextRequest) (domain.LocalContext, error) {
	snap, err := uc.snapshot.Build(ctx, req.Root)
	if err != nil {
		return domain.LocalContext{}, fmt.Errorf("building workspace snapshot: %w", err)
	}

	modulePath, err := domain.SnapshotModulePath(snap)
	if err != nil {
		return domain.LocalContext{}, fmt.Errorf("locating go.mod in snapshot: %w", err)
	}

	level := req.AnalysisLevel
	if level == "" {
		level = domain.AnalysisLevelImport
	}

	var mods []domain.ImportedModule
	switch level {
	case domain.AnalysisLevelSymbol:
		if uc.symbols == nil {
			return domain.LocalContext{}, fmt.Errorf("symbol-level analysis requested but no SymbolAnalyser provided")
		}
		mods, err = uc.symbols.AnalyseSymbols(ctx, req.Root)
	default:
		mods, err = uc.imports.AnalyseImports(ctx, req.Root)
	}
	if err != nil {
		return domain.LocalContext{}, fmt.Errorf("analysing workspace (level=%s): %w", level, err)
	}

	domain.SortModules(mods)

	return domain.LocalContext{
		Root:          req.Root,
		ModulePath:    modulePath,
		VersionID:     snap.VersionID,
		AnalysisLevel: level,
		Modules:       mods,
	}, nil
}
