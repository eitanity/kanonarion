package staticcha

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/eitanity/kanonarion/internal/adapters/goenv"
	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"golang.org/x/tools/go/packages"
)

// analysisMode says what kind of source tree one analysis reads. It decides
// three things that have to agree: the environment the Go children are given,
// the pattern the load is asked for, and the rule that says which packages
// belong to the coordinate.
//
// It replaced a `worktree bool`. The third source is neither of the two that
// bool could express, and a second bool beside it would have let a caller ask
// for a combination no analysis performs.
type analysisMode int

const (
	// modeModuleZip is a published module unpacked into a directory this run
	// owns.
	modeModuleZip analysisMode = iota
	// modeWorktree is the developer's own checkout, build configuration and all.
	modeWorktree
	// modeStdlib is an installed toolchain's $GOROOT/src.
	modeStdlib
)

// stdPattern is the go command's own name for the standard library. It is used
// rather than a directory walk because "./..." under GOROOT/src omits the
// vendored packages the toolchain links into the same binaries —
// vendor/golang.org/x/net/idna among them, which carries advisories of its own.
const stdPattern = "std"

// stdlibTestScopeDetail says why a standard-library graph carries no test
// declarations, so an empty answer over one reads as a scope rather than as a
// measured absence.
const stdlibTestScopeDetail = "the standard library's own test files were not loaded: a consumer's build " +
	"compiles none of them, so no route through one is a route in the build this graph describes"

// stdlibAnalysisEnv is the environment for a Go child reading an installed
// toolchain's standard-library source.
//
// -mod=readonly, not -mod=mod: the tree is the toolchain's own and not a copy
// this run owns, and under -mod=mod the go command writes the go.sum entries it
// finds missing — into $GOROOT/src, which no analysis may modify. The standard
// library vendors every dependency it has, so nothing needs resolving anyway,
// and GOPROXY=off makes that explicit rather than incidental.
func stdlibAnalysisEnv() []string {
	return append(os.Environ(),
		"GOWORK=off", "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local", "GOFLAGS=-mod=readonly")
}

// AnalyseStdlib extracts the call graph of the Go standard library from an
// installed toolchain's own source tree.
//
// The source is a toolchain and not an archive, and that is forced rather than
// chosen. The custody chain the standard library already has is over the
// published go<VERSION>.src.tar.gz, but a source tarball carries no compiled
// toolchain: pointing GOROOT at an unpacked one and asking go/packages to
// type-check it fails at `no such tool "compile"`. A call graph therefore comes
// from a toolchain that can run, and what the record does is say which one and
// what its source tree contained, so a reader holding the same toolchain can
// check it.
//
// src.GoBinary is staged in front of the children exactly as --go-binary is, so
// a graph of go1.26.5 is built by go1.26.5 even where the host's PATH leads
// somewhere else.
func (a *Analyser) AnalyseStdlib(
	ctx context.Context,
	src cgports.ToolchainSource,
	coord coordinate.ModuleCoordinate,
) (rec domain.CallGraphRecord, err error) {
	// Stamped on every return path, for the reason Analyse states.
	defer func() { rec.Analyser = observedAnalyser() }()
	a.logMem(ctx, "start")

	root, err := analysisRoot(filepath.Join(src.GoRoot, "src"))
	if err != nil {
		// A toolchain whose own source directory cannot be resolved is this host,
		// not the standard library: there is nothing to record about the coordinate.
		return domain.CallGraphRecord{}, fmt.Errorf("locating the standard-library source of %s: %w", src.GoRoot, err)
	}

	// A copy, so the chosen toolchain is staged for this analysis alone. The
	// analyser holds configuration and ports and no mutable state, and the
	// alternative — a field — would make two concurrent analyses disagree about
	// which Go they are driving.
	sub := *a
	sub.goBinary = src.GoBinary

	var read []string
	rec, err = sub.analyseDir(ctx, root, coord, domain.SynthesisedGoMod{}, &read, modeStdlib, "")
	if err != nil {
		return rec, err
	}

	digest, derr := treeDigest(root, read)
	if derr != nil {
		// A source tree that cannot be identified cannot be told apart from another
		// toolchain's, and a record of it would claim content nothing measured.
		return domain.CallGraphRecord{}, fmt.Errorf("identifying the standard-library source at %s: %w", root, derr)
	}
	rec.AnalysisSource = domain.AnalysisSourceToolchainSource
	rec.WorktreeDigest = digest
	rec.AnalysisRoot = root
	return rec, nil
}

// childEnv is the environment every Go child of one analysis is given, chosen
// by what the analysis is reading. The three postures are stated in
// goenv.Posture and asserted against these producers; nothing is layered on
// top of another, so a reader can see which one a child was handed.
func childEnv(mode analysisMode, dir, goModCache string) []string {
	switch mode {
	case modeWorktree:
		return goenv.Worktree(os.Environ(), dir)
	case modeStdlib:
		return stdlibAnalysisEnv()
	case modeModuleZip:
		return analysisEnv(goModCache)
	}
	return analysisEnv(goModCache)
}

// metaPattern is what the metadata load asks the go command for.
//
// The standard library is named by the go command's own `std` pattern rather
// than by a directory walk: "./..." under $GOROOT/src misses the 17 vendored
// packages the toolchain links into the same binaries, and those carry
// advisories of their own.
func metaPattern(mode analysisMode) string {
	if mode == modeStdlib {
		return stdPattern
	}
	return "./..."
}

// analysedCoordinate is the coordinate membership is measured against.
//
// For a module it is what the analysed tree DECLARES, which is not always the
// coordinate it was published under — see targetCoordinate. The standard
// library declares itself "std" in $GOROOT/src/go.mod and no consumer ever
// names it that way, so the coordinate stands: it is what every advisory, walk
// node and record keys on.
func analysedCoordinate(mode analysisMode, dir string, coord coordinate.ModuleCoordinate) coordinate.ModuleCoordinate {
	if mode == modeStdlib {
		return coord
	}
	return targetCoordinate(dir, coord)
}

// selectTargetPackages is the pattern list for the syntax load: which of the
// packages the metadata load resolved are the analysed module's to build.
//
// Every package the `std` pattern resolved is the standard library's own — its
// closure is closed, and no import path under it begins with "stdlib", so the
// prefix test would select nothing at all.
//
// For a module this is deliberately NOT the membership rule, and the prefix
// here is not a second spelling of it: this decides what to BUILD, and
// moduleMembership decides what a built package is CLAIMED to be. Building
// wide and claiming narrowly is the safe pairing — a nested module's packages
// are built with bodies, so its dispatch is resolved rather than lost, and
// every node it contributes is then attributed to the module the toolchain says
// it came from.
func selectTargetPackages(mode analysisMode, meta []*packages.Package, target coordinate.ModuleCoordinate) []string {
	var out []string
	packages.Visit(meta, nil, func(p *packages.Package) {
		if mode == modeStdlib ||
			p.PkgPath == target.Path() || strings.HasPrefix(p.PkgPath, target.Path()+"/") {
			out = append(out, p.PkgPath)
		}
	})
	return out
}
