// Package driver holds the narrow write/serving driver use cases the public
// façade graduates: composition-root entrypoints that orchestrate
// existing per-context use cases into a single high-level operation, without
// exposing the bulk pipeline. They sit above the bounded contexts — each driver
// drives several contexts' application use cases — so they live here rather than
// inside any one context.
package driver

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/mod/modfile"

	extractapp "github.com/eitanity/kanonarion/internal/extract/application"
	extractdomain "github.com/eitanity/kanonarion/internal/extract/domain"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	walkapp "github.com/eitanity/kanonarion/internal/walk/application"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// walkRunner is the narrow slice of ExecuteWalkUseCase the driver needs.
// *walkapp.ExecuteWalkUseCase satisfies it; depending on the interface keeps the
// driver unit-testable without wiring the whole walk pipeline.
type walkRunner interface {
	Execute(ctx context.Context, req walkapp.WalkRequest) (walkapp.ExecuteWalkResult, error)
}

// extractRunner is the narrow slice of ExtractUseCase the driver needs.
// *extractapp.ExtractUseCase satisfies it.
type extractRunner interface {
	Execute(ctx context.Context, req extractapp.ExtractRequest) (extractdomain.ExtractionRun, error)
}

// LocalWalkExtractUseCase runs a project-rooted walk over a local working tree
// and its extraction stages, returning the records. It powers the
// local-walking gRPC client: source never leaves the machine. It is a narrow
// driver — it composes the existing ExecuteWalk and Extract use cases — not the
// bulk pipeline, which stays behind the composition root.
type LocalWalkExtractUseCase struct {
	walk          walkRunner
	extract       extractRunner
	defaultStages []string
}

// NewLocalWalkExtractUseCase constructs the driver over an ExecuteWalk use case,
// an Extract use case, and the default stage set to run when a request names no
// stages. The stage set is copied defensively so a later caller cannot mutate
// the driver's default through the shared slice.
func NewLocalWalkExtractUseCase(walk *walkapp.ExecuteWalkUseCase, extract *extractapp.ExtractUseCase, defaultStages []string) *LocalWalkExtractUseCase {
	stages := append([]string(nil), defaultStages...)
	return &LocalWalkExtractUseCase{walk: walk, extract: extract, defaultStages: stages}
}

// LocalWalkExtractRequest is the input to Run.
type LocalWalkExtractRequest struct {
	// Dir is the local working-tree root containing the go.mod to analyse.
	// Empty means the current working directory.
	Dir string
	// Force re-runs the walk and extraction even when cached records exist.
	Force bool
	// Stages names the extraction stages to run. Empty runs the driver's
	// default stage set (the full built-in pipeline).
	Stages []string
	// AnalyseLocalRoot ingests the project's own working tree so the
	// extraction stages analyse the project's OWN packages, not just its
	// dependencies. The tree is re-read fresh on every run — a local version
	// does not pin content, so no cached record is ever served for the root.
	// Default off: the root stays skipped-with-reason and only dependency
	// facts are produced.
	AnalyseLocalRoot bool
}

// LocalWalkExtractResult is the output of Run: the project walk record and the
// extraction run produced over it.
type LocalWalkExtractResult struct {
	// Walk is the project-rooted walk record (target version "local").
	Walk walkdomain.WalkRecord
	// Extraction is the extraction run produced over the walk.
	Extraction extractdomain.ExtractionRun
}

// Run resolves req.Dir's go.mod, executes a project-rooted walk (the local main
// module is the graph root at the synthetic "local" version, its closure the
// union of every require entry), then runs the extraction stages over that walk
// and returns both records. The walk and extract verification/analysis paths are
// unchanged — Run only chains them. It errors on a missing/invalid go.mod or any
// failure surfaced by the walk or extract use case.
func (uc *LocalWalkExtractUseCase) Run(ctx context.Context, req LocalWalkExtractRequest) (LocalWalkExtractResult, error) {
	dir := req.Dir
	if dir == "" {
		dir = "."
	}
	gomodPath := filepath.Join(dir, "go.mod")
	goModBytes, err := os.ReadFile(filepath.Clean(gomodPath))
	if err != nil {
		return LocalWalkExtractResult{}, fmt.Errorf("reading go.mod under %s: %w", dir, err)
	}
	modulePath := modfile.ModulePath(goModBytes)
	if modulePath == "" {
		return LocalWalkExtractResult{}, fmt.Errorf("go.mod under %s declares no module path", dir)
	}

	// The main module is local and unpublished; pin it at the synthetic
	// LocalVersion rather than a semver, matching the default project go.mod walk.
	target := fetchdomain.ModuleCoordinate{Path: modulePath, Version: fetchdomain.LocalVersion}
	var projectDir string
	if req.AnalyseLocalRoot {
		projectDir, err = filepath.Abs(dir)
		if err != nil {
			return LocalWalkExtractResult{}, fmt.Errorf("resolving project directory %s: %w", dir, err)
		}
	}
	// The driver analyses the whole project, so it walks the complete build list
	// (build + tooling); ScopeModules is nil (no scope restriction).
	walkRes, err := uc.walk.Execute(ctx, walkapp.WalkRequest{
		Target:           target,
		Force:            req.Force,
		Scope:            walkdomain.WalkScopeComplete,
		ProjectMode:      true,
		MainModuleGoMod:  goModBytes,
		AnalyseLocalRoot: req.AnalyseLocalRoot,
		ProjectDir:       projectDir,
	})
	if err != nil {
		return LocalWalkExtractResult{}, fmt.Errorf("walking local project %s: %w", modulePath, err)
	}

	stages := req.Stages
	if len(stages) == 0 {
		stages = append([]string(nil), uc.defaultStages...)
	}
	run, err := uc.extract.Execute(ctx, extractapp.ExtractRequest{
		WalkID: walkRes.Record.ID,
		Stages: stages,
		Force:  req.Force,
	})
	if err != nil {
		return LocalWalkExtractResult{}, fmt.Errorf("extracting walk %s: %w", walkRes.Record.ID, err)
	}

	return LocalWalkExtractResult{Walk: walkRes.Record, Extraction: run}, nil
}
