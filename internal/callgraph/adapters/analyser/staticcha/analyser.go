package staticcha

import (
	"context"
	"errors"
	"fmt"
	"go/token"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
)

const analyserVersion = "0.1.0"

// Analyser implements cgports.CallGraphAnalyser using CHA.
type Analyser struct {
	pipelineVersion string
	goBinary        string
	logger          *slog.Logger
}

// New constructs an Analyser.
func New(pipelineVersion string, goBinary string, logger *slog.Logger) *Analyser {
	return &Analyser{pipelineVersion: pipelineVersion, goBinary: goBinary, logger: logger}
}

// AnalyserMetadata returns the algorithm and version of this implementation.
func (a *Analyser) AnalyserMetadata() cgports.AnalyserMetadata {
	return cgports.AnalyserMetadata{
		Algorithm: domain.AlgorithmCHA,
		Version:   analyserVersion,
	}
}

func (a *Analyser) logMem(ctx context.Context, phase string) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	a.logger.DebugContext(ctx, "callgraph_memory_telemetry",
		slog.String("phase", phase),
		slog.Uint64("alloc_mb", m.Alloc/1024/1024),
		slog.Uint64("total_alloc_mb", m.TotalAlloc/1024/1024),
		slog.Uint64("sys_mb", m.Sys/1024/1024),
		slog.Uint64("heap_alloc_mb", m.HeapAlloc/1024/1024),
		slog.Uint64("heap_objects", m.HeapObjects),
		slog.Int("num_gc", int(m.NumGC)),
	)
}

// Analyse extracts the call graph from a module zip using CHA.
func (a *Analyser) Analyse(
	ctx context.Context,
	zipPath string,
	coord coordinate.ModuleCoordinate,
	inputs domain.AnalysisInputs,
) (domain.CallGraphRecord, error) {
	a.logMem(ctx, "start")
	tempDir, err := os.MkdirTemp("", "kanonarion-cg-*")
	if err != nil {
		return domain.CallGraphRecord{}, fmt.Errorf("creating temp dir: %w", err)
	}
	defer func() {
		if rerr := os.RemoveAll(tempDir); rerr != nil {
			a.logger.WarnContext(ctx, "callgraph_temp_cleanup_failed",
				slog.String("error", rerr.Error()),
				slog.String("dir", tempDir),
			)
		}
	}()

	modulePrefix := coord.Path() + "@" + coord.Version() + "/"
	if err := extractModuleZip(zipPath, modulePrefix, tempDir); err != nil {
		// The zip is the module: bytes that will not unpack are a property of what
		// was published, and unpacking them again tomorrow fails identically.
		return a.sourced(a.failRecord(coord, domain.CallGraphStatusLoadFailed, domain.CompletenessFailed,
			domain.FailureCauseModule, "extracting module zip: "+err.Error()), domain.SynthesisedGoMod{}, inputs.Source), nil
	}

	// A module published before Go modules ships no go.mod, and an extraction of
	// it loads outside any module: nothing carries the module's import path, so
	// nothing is recognised as the target and the graph comes back empty. Writing
	// one is what makes the module loadable at all — and makes the analysed tree
	// something other than the published tree, which the record then says.
	// Why nothing was written, when nothing was written for a reason the load is
	// then going to fail on. It travels to the record because the load's own
	// account of that failure is a symptom — "directory prefix . does not contain
	// main module" says nothing about a missing require list — and a reader given
	// only the symptom cannot act.
	declined := ""
	synth, err := synthesiseGoMod(tempDir, coord, inputs)
	switch {
	case errors.Is(err, errGoModPresent):
		// The module ships its own go.mod. Whatever happens next is a statement
		// about the module as published; nothing here is allowed to mask it.
		synth = domain.SynthesisedGoMod{}
	case errors.Is(err, errNeedsDependencyResolution):
		// A pre-modules module whose own packages import third-party code needs a
		// require list, and the requesting build list could not pin every one of
		// them. The load proceeds exactly as it did before this file existed, so
		// the record it produces is unchanged — deliberately. Naming the cause on
		// the record would classify the failure as the module's fault, which makes
		// it CACHEABLE, and a permanently-cached failure is the last thing to hand
		// the work that will eventually resolve those dependencies. The reason is
		// logged instead.
		synth = domain.SynthesisedGoMod{}
		declined = err.Error()
		a.logger.InfoContext(ctx, "callgraph_gomod_synthesis_declined",
			slog.String("module", coord.Path()),
			slog.String("version", coord.Version()),
			slog.String("reason", err.Error()),
			slog.String("build_list_source", inputs.Source),
			slog.Int("build_list_size", len(inputs.BuildList)),
		)
	case err != nil:
		// Failing to write into a directory this process just created is the run,
		// not the module: the same zip on a working filesystem extracts and loads.
		return a.sourced(a.failRecord(coord, domain.CallGraphStatusLoadFailed, domain.CompletenessFailed,
			domain.FailureCauseEnvironment, "synthesising go.mod: "+err.Error()), domain.SynthesisedGoMod{}, inputs.Source), nil
	default:
		a.logger.InfoContext(ctx, "callgraph_gomod_synthesised",
			slog.String("module", coord.Path()),
			slog.String("version", coord.Version()),
			slog.String("go_directive", synth.GoDirective),
			slog.Bool("vendor_tree_present", synth.VendorTreePresent),
			slog.Int("pinned_requires", len(synth.Requires)),
			slog.String("build_list_source", inputs.Source),
		)
	}

	if ctx.Err() != nil {
		return a.sourced(a.failRecord(coord, domain.CallGraphStatusCancelled, domain.CompletenessUnknown,
			domain.FailureCauseEnvironment, "cancelled before load"), synth, inputs.Source), nil
	}

	rec, err := a.analyseDir(ctx, tempDir, coord, synth, nil)
	if err != nil {
		return rec, err
	}
	return a.sourced(withDeclinedSynthesis(rec, declined), synth, inputs.Source), nil
}

// withDeclinedSynthesis prefixes a failed record's detail with the reason no
// go.mod was written for a module that ships none.
//
// Only a failure carries it. A module that loaded anyway needed no file and has
// nothing to explain; a module that failed did so BECAUSE it was loaded outside
// any module, and the loader's account of that ("directory prefix . does not
// contain main module or its selected dependencies") names a consequence three
// steps downstream of the cause. The refusal itself names the imports that could
// not be pinned and the build list that failed to pin them, which is the fact a
// reader has to act on.
//
// The record's FAILURE CAUSE is CLEARED. A refusal for want of require
// directives is not a property of the artefact — a build list can arrive
// tomorrow — and the load, knowing nothing about the refusal, files the empty
// target set it then meets as the module's fault. That is what makes the failure
// cacheable, and a cacheable failure here is a permanent wrong answer for a
// module the store already holds the versions for. An unattributed cause is the
// truthful value: nothing has been established about these bytes.
func withDeclinedSynthesis(r domain.CallGraphRecord, declined string) domain.CallGraphRecord {
	if declined == "" || !domain.RecordIsFailure(r) {
		return r
	}
	detail := "no go.mod was synthesised: " + declined +
		" — name a walk that resolved them with --from-walk"
	if r.FailureDetail != "" {
		detail += "; the load then reported: " + r.FailureDetail
	}
	r.FailureDetail = detail
	r.FailureCause = domain.FailureCauseUnrecorded
	return r
}

// sourced stamps a record as built from a fetched module zip, and states how the
// tree it read related to the bytes that were published.
//
// It is applied on every return path of Analyse, including the failures. A
// record that says nothing about what it read cannot be told apart from one
// written before the field existed, and a failed analysis of a zip is still an
// answer about that zip — including a failure of a tree kanonarion had to add a
// file to, where the caveat is exactly as load-bearing as it is on a success.
func (a *Analyser) sourced(r domain.CallGraphRecord, synth domain.SynthesisedGoMod, buildListSource string) domain.CallGraphRecord {
	r.AnalysisSource = domain.AnalysisSourceModuleZip
	r.SynthesisedGoMod = synth
	r.BuildListSource = buildListSource
	return r
}

// AnalyseDir runs the same CHA pipeline as Analyse but against an on-disk Go
// module working tree instead of a fetched module zip. It is used for
// local-analysis ingestion so kanonarion can answer callers/callees for its own
// internal packages. coord.Path must be the module path declared in the
// directory's go.mod; coord.Version is coordinate.LocalVersion, the marker for a
// module nothing published.
//
// The record it returns names its source as a working tree, carries a digest of
// that tree, and states WHERE the tree was.
//
// The digest is computed AFTER the analysis, from the loader's own file list, so
// it describes the bytes that were ANALYSED rather than the bytes that were on
// disk beforehand — which is the claim the field is supposed to make. A load
// that resolved no files at all still has to identify the tree it failed on, and
// falls back to scanning it; the two carry different scheme prefixes, because
// they are different claims.
//
// The root is recorded alongside, and is a different question from the digest.
// The digest says WHICH TREE this is; the root says WHERE it was, which is what
// a reader standing in a checkout is actually asking when they query it. See
// CallGraphRecord.AnalysisRoot.
func (a *Analyser) AnalyseDir(ctx context.Context, dir string, coord coordinate.ModuleCoordinate) (domain.CallGraphRecord, error) {
	a.logMem(ctx, "start")
	root, err := analysisRoot(dir)
	if err != nil {
		// Infrastructure, not a property of the module: a tree whose own location
		// cannot be resolved cannot be told apart from another checkout by a reader
		// standing in one of them.
		return domain.CallGraphRecord{}, fmt.Errorf("locating working tree %s: %w", dir, err)
	}
	// Cancellation is observed inside analyseDir (packages.Load honours ctx,
	// plus explicit ctx.Err checkpoints), so no pre-check is needed here.
	// A working tree is analysed exactly as it is on disk: it is the caller's own
	// module and already declares itself, so nothing is synthesised into it and
	// the record carries the zero value.
	var read []string
	rec, err := a.analyseDir(ctx, dir, coord, domain.SynthesisedGoMod{}, &read)
	if err != nil {
		return rec, err
	}
	digest, err := treeDigest(root, read)
	if err != nil {
		// A tree that cannot be read cannot be identified, and a worktree record
		// with no digest is one that silently merges with every other checkout of
		// the same module path.
		return domain.CallGraphRecord{}, fmt.Errorf("identifying working tree %s: %w", dir, err)
	}
	rec.AnalysisSource = domain.AnalysisSourceWorktree
	rec.WorktreeDigest = digest
	rec.AnalysisRoot = root
	return rec, nil
}

// analysisRoot resolves dir to the absolute, symlink-free path the record states
// it analysed.
//
// Symlinks are evaluated so that one tree reached by two names is one root. The
// alternative — recording whatever spelling the caller typed — would make a
// query run through /home/me/work/project miss every generation analysed at the
// path that symlink resolves to, which is the same tree.
func analysisRoot(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("resolving %s: %w", dir, err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("resolving symlinks in %s: %w", abs, err)
	}
	return resolved, nil
}

// treeDigest identifies the tree at root, preferring what the loader read.
//
// read is empty exactly when the load resolved no packages — a failed analysis —
// and the tree is then scanned instead. The fallback is never silent: it carries
// its own scheme prefix, so a reader can see that this record identifies its tree
// by a proxy for what was analysed rather than by what was analysed.
func treeDigest(root string, read []string) (string, error) {
	if len(read) == 0 {
		return worktreeDigest(root)
	}
	// go.mod and go.sum are not package source and the loader does not list them,
	// but they decide the build list the graph was constructed against, so a change
	// to either is a change to what was analysed.
	for _, name := range []string{"go.mod", "go.sum"} {
		path := filepath.Join(root, name)
		if _, err := os.Stat(path); err == nil {
			read = append(read, path)
		} else if !os.IsNotExist(err) {
			return "", fmt.Errorf("stating %s for worktree digest: %w", name, err)
		}
	}
	return analysedTreeDigest(root, read)
}

// analyseDir holds the shared post-extraction analysis pipeline: load
// packages from dir, build SSA, run CHA, and walk the graph into a
// CallGraphRecord. dir is either an extracted-zip temp dir (Analyse) or a
// local working tree (AnalyseDir).
//
// synth describes any go.mod written into tempDir before the load. It reaches
// here because it changes how the load must run — a synthesised file beside a
// vendor tree would otherwise auto-select vendor mode — not merely because it is
// recorded.
//
// read, when non-nil, is filled with the absolute paths the loader resolved, for
// the caller that identifies the analysed tree by them. It is an out-parameter
// rather than a second result because every failure return here is a RECORD —
// a load that failed is an answer about the module, not an error — and threading
// a second value through a dozen of them would obscure that.
func (a *Analyser) analyseDir(
	ctx context.Context,
	tempDir string,
	coord coordinate.ModuleCoordinate,
	synth domain.SynthesisedGoMod,
	read *[]string,
) (domain.CallGraphRecord, error) {
	fset := token.NewFileSet()
	env := analysisEnv(synth)

	// classifyLoad names the cause of a load failure raised below. The directory
	// is bound once, here, rather than passed at each call site: every load in
	// this function reads tempDir, and a classification asked about any other
	// directory is precisely the defect the probe exists to avoid — it would
	// report a usable toolchain for a load that had none, and file the run's
	// failure as the module's property.
	classifyLoad := func(detail string) domain.FailureCause {
		// The offline posture a pinned synthesis imposes is this host's, not the
		// module's. A dependency absent from the local module cache fails the load
		// with GOPROXY=off in the message, and filing that as the module's fault
		// would cache a warm-cache problem as a permanent property of published
		// bytes — the same permanence this stage keeps off the synthesis-refusal
		// path for the same reason.
		if isOfflineCacheMiss(detail) {
			return domain.FailureCauseEnvironment
		}
		return a.classifyLoadFailure(ctx, tempDir)
	}

	envCleanup, err := a.setupGoEnv(ctx, tempDir)
	if err != nil {
		// Preparing PATH and GOROOT for the analysis is entirely about the run;
		// the module has not been touched at this point.
		return a.failRecord(coord, domain.CallGraphStatusLoadFailed, domain.CompletenessFailed,
			domain.FailureCauseEnvironment, err.Error()), nil
	}
	defer envCleanup()

	// New Architecture: Multi-pass load to bypass go/packages memory limitations.
	// Step 1: Discover ALL packages in the transitive dependency graph (metadata only).
	// This ensures we know about every package that might be imported.
	cfgMeta := &packages.Config{
		Mode:    packages.NeedName | packages.NeedImports | packages.NeedDeps,
		Dir:     tempDir,
		Context: ctx,
		Env:     env,
		Tests:   false,
	}

	pkgsMeta, err := packages.Load(cfgMeta, "./...")
	if err != nil {
		// A Load error is the driver failing, and the driver is the go command. It
		// is raised both by a module whose graph will not resolve and by a PATH with
		// no usable toolchain on it, so which one this is has to be established
		// rather than read off the message.
		return a.failRecord(coord, domain.CallGraphStatusLoadFailed, domain.CompletenessFailed,
			classifyLoad(err.Error()), "meta load: "+err.Error()), nil
	}
	a.logMem(ctx, "meta_loaded")

	// Every error the driver attached to a package rather than returning. A load
	// that resolved nothing still returns a nil error when the go command reported
	// its failures this way, so these strings are the only account of what went
	// wrong — and they were being discarded, which is how nineteen coordinates
	// came to be recorded with a failure line that named no cause at all.
	metaErrs := metaLoadErrors(pkgsMeta)

	if len(pkgsMeta) == 0 {
		// The loader ran and found nothing to analyse: a fact about what the module
		// ships — unless the loader also said why, in which case that is the finding
		// and the count is a symptom of it.
		detail := "no packages found for " + platformFrame() +
			" (the module ships no Go source, or build constraints exclude every file it does ship)"
		if len(metaErrs) > 0 {
			detail += "; the loader reported: " + joinFirst(metaErrs, 3)
		}
		return a.failRecord(coord, domain.CallGraphStatusLoadFailed, domain.CompletenessFailed,
			classifyLoad(detail), detail), nil
	}

	// The membership test asks the tree what module it is, not the coordinate. A
	// fork republished under a new path that never rewrote its module directive
	// still declares — and its consumers still import — the original path, and
	// testing against the coordinate matched none of its own packages.
	target := targetCoordinate(tempDir, coord)

	// The pattern list for the syntax load below. This is deliberately NOT the
	// membership rule, and the prefix here is not a fifth spelling of it: this
	// decides what to BUILD, and moduleMembership decides what a built package is
	// CLAIMED to be. Building wide and claiming narrowly is the safe pairing —
	// a nested module's packages are built with bodies, so its dispatch is
	// resolved rather than lost, and every node it contributes is then attributed
	// to the module the toolchain says it came from. Narrowing this test instead
	// would drop those bodies, which is a change to the graph's fidelity and a
	// separate decision from correcting who owns a node.
	var targetPkgPaths []string
	packages.Visit(pkgsMeta, nil, func(p *packages.Package) {
		isTarget := p.PkgPath == target.Path() || strings.HasPrefix(p.PkgPath, target.Path()+"/")
		if isTarget {
			targetPkgPaths = append(targetPkgPaths, p.PkgPath)
		}
	})

	if len(targetPkgPaths) == 0 {
		// The loader ran, returned packages, and not one of them belongs to the
		// module under analysis. Loading on would register nothing and report "no
		// packages successfully loaded", which names neither what was sought nor
		// what was found nor what the toolchain said about it.
		detail := describeEmptyTargetSet(target, pkgsMeta, metaErrs)
		return a.failRecord(coord, domain.CallGraphStatusLoadFailed, domain.CompletenessMetadataOnly,
			classifyLoad(detail), detail), nil
	}

	build, err := a.loadAndBuildSSA(ctx, fset, tempDir, target, targetPkgPaths, env)
	if err != nil {
		// The only error this returns is a syntax-load failure, which is again the
		// go command failing; same question, same way of answering it.
		return a.failRecord(coord, domain.CallGraphStatusLoadFailed, domain.CompletenessFailed,
			classifyLoad(err.Error()), err.Error()), nil
	}
	if read != nil {
		*read = build.SourceFiles
	}
	prog := build.Prog
	allLoadErrs := build.LoadErrs
	failedPkgs := build.FailedPkgs

	// Step 4: Final Cleanup and Call Graph Construction
	runtime.GC()
	a.logMem(ctx, "all_packages_processed")

	if build.Registered() == 0 {
		// Named target packages, and not one of them type-checked. Whatever the
		// syntax load said comes first; the metadata load's own errors are the
		// fallback, and only with neither is there nothing to report but the count.
		detail := fmt.Sprintf("none of the %d package(s) under %s type-checked", len(targetPkgPaths), target.Path())
		switch {
		case len(allLoadErrs) > 0:
			detail += ": " + joinFirst(allLoadErrs, 3)
		case len(metaErrs) > 0:
			detail += "; the loader reported: " + joinFirst(metaErrs, 3)
		}
		// Metadata resolved and not one package type-checked from it. The toolchain
		// demonstrably ran — it produced the metadata — so this is the module,
		// unless the load could not reach a dependency the local cache does not
		// hold, which is this host and not these bytes.
		cause := domain.FailureCauseModule
		if isOfflineCacheMiss(detail) {
			cause = domain.FailureCauseEnvironment
		}
		return a.failRecord(coord, domain.CallGraphStatusLoadFailed, domain.CompletenessMetadataOnly,
			cause, detail), nil
	}

	if ctx.Err() != nil {
		return a.failRecord(coord, domain.CallGraphStatusCancelled, domain.CompletenessUnknown,
			domain.FailureCauseEnvironment, "cancelled after load"), nil
	}

	a.logger.InfoContext(ctx, "callgraph_load_completed",
		slog.Int("target_pkg_count", len(build.TargetPkgs)),
		slog.Int("test_pkg_count", len(build.TestPkgs)),
		slog.Int("load_errors", len(allLoadErrs)),
	)

	// Step 3: Call Graph Construction (CHA)
	a.logMem(ctx, "pre_cha")
	cg := cha.CallGraph(prog)
	a.logMem(ctx, "post_cha")

	// Ensure GC can reclaim memory before starting walk
	runtime.GC()

	// Pre-filter to the caller nodes walkGraph records — module functions plus
	// dependency functions built with real bodies — to save memory during walk.
	mem := build.Membership
	recordedCallers := recordedCallerNodes(cg, mem)

	// Ensure GC can reclaim memory before starting walk
	runtime.GC()

	nodes, edges, overallStatus := a.walkGraph(ctx, cg, recordedCallers, mem, fset, tempDir)

	// Attach body-level capability facts. These are properties of a
	// function's own body — unsafe.Pointer conversions, assembly/linkname
	// leaves — that the call graph and package sink map cannot witness. Scan
	// only the packages that appear as graph nodes so the extra syntax load is
	// bounded by the graph rather than the full dependency set.
	a.attachBodyFacts(ctx, nodes, tempDir, env)

	// Recover client-side interface-dispatch edges CHA drops when the sole
	// implementer's body was never built into SSA (type-only dep / unbuilt
	// package). Runs after body facts so those only scan built module bodies;
	// devirtualized leaf targets carry no onward edges.
	nodes, edges = a.devirtualizeSingleImplementer(ctx, prog, mem, fset, tempDir, nodes, edges)

	// Record the function values the code takes but does not call. A method
	// registered with a router is passed, never called, so CHA sees nothing —
	// and a handler an HTTP request drives on every hit ends up with no in-edge.
	// Runs after devirtualisation so an edge a call already witnesses keeps the
	// call's key rather than being recorded twice under two kinds.
	nodes, edges = a.collectReferenceEdges(ctx, prog, mem, fset, tempDir, nodes, edges)

	// Record the type-level relation: which of the module's concrete types
	// satisfy which of its interfaces. An interface method has no callers — calls
	// go to implementations — so the edge collections cannot answer "what must
	// change with this port", and a grep for the method name cannot tell an
	// implementation from a call.
	ifaces, impls := a.extractInterfaces(ctx, prog, mem, fset, tempDir)

	// A failed package (or any load error) means the graph is incomplete;
	// never report Extracted when some target package did not resolve. Keeping
	// FailedPackages and the Partial status in lock-step is what lets the query
	// layer trust FailedPackages as the completeness signal.
	if (len(allLoadErrs) > 0 || len(failedPkgs) > 0) && overallStatus == domain.CallGraphStatusExtracted {
		overallStatus = domain.CallGraphStatusPartial
	}

	rec := domain.CallGraphRecord{
		SchemaVersion: domain.CallGraphSchemaVersion,
		Ecosystem:     fetchdomain.EcosystemGo,
		Coordinate:    coord,
		Algorithm:     domain.AlgorithmCHA,
		Completeness:  buildCompleteness(build),
		// Only production packages decide the artifact kind: the test binary main
		// go/packages synthesises is not a command this module ships.
		ArtifactKind:    artifactKind(build.TargetPkgs),
		Nodes:           nodes,
		Edges:           edges,
		Interfaces:      ifaces,
		Implementations: impls,
		TestScope:       build.TestScope,
		TestScopeDetail: build.TestScopeDetail,
		// The axis was walked: whatever references exist in this graph are the
		// ones the code takes. A record that does not say this was produced
		// before references were extracted, and an empty callers answer over it
		// is unproven rather than absent.
		ReferenceScope:  domain.ReferenceScopeAnalysed,
		OverallStatus:   overallStatus,
		NodeCount:       len(nodes),
		EdgeCount:       len(edges),
		PipelineVersion: a.pipelineVersion,
	}
	// A walk cut short by cancellation is the run ending, not the module being
	// unanalysable, and the record it leaves must not be served as though the
	// module had been measured. Every other status reaching here carries a graph,
	// so it states no cause.
	if overallStatus == domain.CallGraphStatusCancelled {
		rec.FailureCause = domain.FailureCauseEnvironment
	}
	if len(allLoadErrs) > 0 {
		rec.FailureDetail = joinFirst(allLoadErrs, 3)
	}
	// FailedPackages scopes the incompleteness to the exact packages that did
	// not typecheck, so callers/callees/reachability verdicts over this Partial
	// graph can be caveated per package rather than by node/edge totals.
	rec.FailedPackages = failedPkgs
	// Every package this analysis admitted to the module by path prefix, because
	// the toolchain placed it in no module at all. Empty is the ordinary case and
	// says the loader named every in-module package itself; non-empty is the
	// reconstruction, stated rather than hidden inside the membership answer.
	rec.PrefixAttributedPackages = mem.prefixAttributed()
	rec.Sort()
	return rec, nil
}

// buildCompleteness reads the module-level fidelity off the load result, at the
// point the result is known.
//
// Reaching this function means at least one package was registered from syntax —
// the caller has already returned METADATA_ONLY when none was. What remains is
// the distinction between having bodies and having only types, and the load
// result is the only place it survives: an ssa.Program with registered packages
// and no built bodies looks exactly like one with built-but-empty packages to
// every consumer downstream, so collapsing the two here would discard a fidelity
// difference at the moment it is known.
//
// Per-package build failures with at least one success are still
// BUILT_WITH_BODIES at module level: the scope of the incompleteness is carried
// in FailedPackages, and the caller forces OverallStatus to Partial for it.
func buildCompleteness(build ssaBuildResult) domain.CompletenessLevel {
	if build.BodiesBuilt == 0 {
		return domain.CompletenessTypeOnly
	}
	return domain.CompletenessBuiltWithBodies
}

// artifactKind classifies the analysed module from the packages it owns: it is
// an application as soon as one of them is a package main defining func main,
// otherwise a library. The distinction cannot be recovered from an import path,
// so it is captured here, at load time, and carried on the record — reachability
// rooting depends on it.
func artifactKind(targetPkgs []*ssa.Package) domain.ArtifactKind {
	for _, p := range targetPkgs {
		if p == nil || p.Pkg == nil {
			continue
		}
		if p.Pkg.Name() == "main" && p.Func("main") != nil {
			return domain.ArtifactApplication
		}
	}
	return domain.ArtifactLibrary
}

// failRecord builds a no-graph record for a fatal extraction outcome. completeness
// is the fidelity the module reached before failing: FAILED when nothing usable
// loaded, METADATA_ONLY when package metadata loaded but no SSA was built, and
// Unknown for a transient outcome (cancellation) that makes no fidelity claim.
//
// cause says what the failure is a statement about — the module, or this run.
// Every failure path names it, so a record written by this generation can never
// be the unattributed failure the cache gate has to treat as unknown.
func (a *Analyser) failRecord(
	coord coordinate.ModuleCoordinate,
	status domain.CallGraphStatus,
	completeness domain.CompletenessLevel,
	cause domain.FailureCause,
	detail string,
) domain.CallGraphRecord {
	return domain.CallGraphRecord{
		SchemaVersion:   domain.CallGraphSchemaVersion,
		Ecosystem:       fetchdomain.EcosystemGo,
		Coordinate:      coord,
		Algorithm:       domain.AlgorithmCHA,
		Completeness:    completeness,
		OverallStatus:   status,
		FailureCause:    cause,
		FailureDetail:   detail,
		PipelineVersion: a.pipelineVersion,
	}
}

func joinFirst(ss []string, n int) string {
	if len(ss) > n {
		ss = ss[:n]
	}
	return strings.Join(ss, "; ")
}

// Ensure Analyser implements cgports.CallGraphAnalyser at compile time.
var _ cgports.CallGraphAnalyser = (*Analyser)(nil)
