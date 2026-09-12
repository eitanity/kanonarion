// Package modulecache materialises the module cache an isolated call-graph
// analysis reads, from the bytes kanonarion's own store holds.
//
// It is the callgraph context's side of a rule the vuln scan has applied since
// its own offline posture landed: an analysis pinned to GOPROXY=off resolves
// from a cache or from nowhere, so the cache is something the run BUILDS rather
// than something it hopes to find. Reading the host's cache instead made the
// answer depend on what unrelated go commands had left on the machine.
package modulecache

import (
	"context"
	"io"
	"log/slog"

	"github.com/eitanity/kanonarion/internal/adapters/modcache"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/semver"
)

// failureLogLimit bounds how many failed coordinates a log line names. The
// counts beside it are the whole population; this bounds the rendering only.
const failureLogLimit = 10

// ModuleFetcher acquires a coordinate the fact store does not hold.
//
// It is declared here rather than imported because this package is the consumer:
// the closure discovers versions no walk ever selected, and a materialiser with
// no fetcher can only report them as holes. The composition root supplies the
// fetch context's adapter, which already satisfies it.
type ModuleFetcher interface {
	// FetchModule acquires the full artefact — zip and go.mod — which is the
	// source a load type-checks.
	FetchModule(ctx context.Context, coord coordinate.ModuleCoordinate) error
	// FetchModuleGoMod acquires the go.mod alone, for a version that is read for
	// module-graph arithmetic and never compiled.
	FetchModuleGoMod(ctx context.Context, coord coordinate.ModuleCoordinate) error
}

// Cache is a cgports.ModuleCache backed by the fetch ledger and the blob store.
type Cache struct {
	facts   fetchports.FactStore
	blobs   fetchports.BlobStore
	fetcher ModuleFetcher // optional; nil confines the cache to what the store holds
	logger  *slog.Logger
}

// New constructs a Cache that populates from the store alone.
func New(facts fetchports.FactStore, blobs fetchports.BlobStore, logger *slog.Logger) *Cache {
	return &Cache{facts: facts, blobs: blobs, logger: logger}
}

// WithFetcher lets the cache acquire coordinates the store is missing.
//
// Without it a module whose own dependency closure no walk ever resolved is
// reported as a set of holes and analysed against a partial cache, which is
// exactly the case this whole path exists for: the walk fetches what the
// CONSUMER's build selected, and a module's own requirements are a different
// set.
func (c *Cache) WithFetcher(f ModuleFetcher) *Cache {
	c.fetcher = f
	return c
}

// Materialise writes the module cache an analysis of this main module reads.
// See cgports.ModuleCache.
//
// Two populations, and the second is conditional on what the toolchain will
// actually read:
//
//   - the SOURCE of every requirement, always, because the type checker compiles
//     it. A main module on go1.17 or later reads a pruned module graph, so its
//     own require block names every module providing a package the build
//     imports — the build's source, established without resolving anything.
//   - the go.mod of everything reachable from the UNPRUNED part of the graph, to
//     a fixpoint. Minimal version selection reads the requirements of versions it
//     goes on to supersede, and those appear on no edge of any walk; but it only
//     reads them where pruning does not apply, which is under a pre-pruning main
//     module or beneath a pre-pruning requirement.
//
// The second population is rooted rather than unconditional, and the rooting is
// the whole of its cost. Expanded from every requirement of a pruned main module
// it has no stopping condition tied to what any toolchain opens: measured on
// cloud.google.com/go/iam@v1.11.0, whose go.mod declares go1.25 and whose graph
// the toolchain prunes to 38 modules, it reached 3361 versions and fetched 1653
// go.mod files that nothing would ever read. Rooted, that module needs none.
//
// The go.mod pass re-reaches its roots as seeds and rewrites none of them —
// their go.mod arrived with their source — following what they require, which is
// the whole point of seeding it there.
func (c *Cache) Materialise(ctx context.Context, dir string, main cgports.MainModule) cgports.ModuleCacheReport {
	if len(main.Requires) == 0 {
		return cgports.ModuleCacheReport{}
	}

	c.prefetchSource(ctx, main.Requires)
	source := modcache.Populate(ctx, c.facts, c.blobs, dir, main.Requires)
	c.report(ctx, "source", source)

	report := cgports.ModuleCacheReport{
		Requested: source.Requested,
		Written:   source.Written,
		Failures:  prefixed("source", source.FailureSummary(failureLogLimit)),
	}

	seeds := c.unprunedRoots(ctx, main)
	if len(seeds) == 0 {
		return report
	}

	graph, reached := modcache.PopulateGoModClosure(ctx, c.facts, c.blobs, dir, seeds,
		func(ctx context.Context, batch []coordinate.ModuleCoordinate) { c.prefetchGoMod(ctx, batch) })
	c.report(ctx, "module-graph go.mod", graph)

	report.Requested += graph.Requested
	report.Written += graph.Written
	report.Failures = joinFailures(report.Failures,
		prefixed("module-graph go.mod", graph.FailureSummary(failureLogLimit)))

	if !walkdomain.PrePruning(main.GoVersion) {
		return report
	}

	// A pre-pruning main module's require block states its DIRECT requirements
	// only, so the source written above is not the build. The versions the build
	// compiles are the ones minimal version selection picks out of the graph just
	// walked — the maximum version of each path — and without them the loader
	// resolves the package and finds no bodies for it. Measured on
	// github.com/minio/minio-go/v6@v6.0.57, whose go.mod declares go1.12 and whose
	// require block names ten of the forty-two modules its build reads: five nodes
	// and five edges in klauspost/cpuid, modern-go/reflect2 and x/text went
	// missing from a graph that otherwise reported as fully extracted.
	selected := selectedVersions(append(append([]coordinate.ModuleCoordinate(nil), main.Requires...), reached...))
	c.prefetchSource(ctx, selected)
	build := modcache.Populate(ctx, c.facts, c.blobs, dir, selected)
	c.report(ctx, "unpruned build list", build)
	report.Requested += build.Requested
	report.Written += build.Written
	report.Failures = joinFailures(report.Failures,
		prefixed("unpruned build list", build.FailureSummary(failureLogLimit)))
	return report
}

// selectedVersions is minimal version selection over an unpruned module graph:
// the highest version of each module path the graph names.
//
// It is the toolchain's own rule, and the graph it is applied to is the one the
// closure just walked, so nothing is resolved here that the toolchain would
// resolve differently. The order is the graph's own discovery order, which keeps
// the population deterministic.
func selectedVersions(coords []coordinate.ModuleCoordinate) []coordinate.ModuleCoordinate {
	best := make(map[string]coordinate.ModuleCoordinate, len(coords))
	order := make([]string, 0, len(coords))
	for _, c := range coords {
		held, seen := best[c.Path()]
		if !seen {
			order = append(order, c.Path())
			best[c.Path()] = c
			continue
		}
		if semver.Compare(c.Version(), held.Version()) > 0 {
			best[c.Path()] = c
		}
	}
	out := make([]coordinate.ModuleCoordinate, 0, len(order))
	for _, path := range order {
		out = append(out, best[path])
	}
	return out
}

// unprunedRoots names the requirements whose own requirement graph the toolchain
// will read in full.
//
// A pre-pruning main module reads the complete graph, so every one of its
// requirements is a root. A pruned one reads only its own require block — which
// the source population has already written — except beneath a requirement that
// is itself pre-pruning, which the toolchain expands. A requirement whose go.mod
// cannot be read is treated as pre-pruning, on the walk's rule: a module that
// does not state its version does not record its full requirements either, and
// under-populating is the failure that leaves a load with no explanation.
func (c *Cache) unprunedRoots(ctx context.Context, main cgports.MainModule) []coordinate.ModuleCoordinate {
	if walkdomain.PrePruning(main.GoVersion) {
		return main.Requires
	}
	var roots []coordinate.ModuleCoordinate
	for _, req := range main.Requires {
		if walkdomain.PrePruning(c.goVersionOf(ctx, req)) {
			roots = append(roots, req)
		}
	}
	return roots
}

// goVersionOf reads a requirement's declared go directive out of the go.mod the
// store holds for it. An unreadable one answers the empty string, which
// PrePruning reads as pre-pruning.
func (c *Cache) goVersionOf(ctx context.Context, coord coordinate.ModuleCoordinate) string {
	record, ok, err := fetchports.ComposedFetchRecord(ctx, c.facts, coord)
	if err != nil || !ok {
		return ""
	}
	identity, hasGoMod, err := fetchports.GoModIdentity(record.FactRecord)
	if err != nil || !hasGoMod {
		return ""
	}
	rc, err := c.blobs.Get(ctx, identity)
	if err != nil {
		return ""
	}
	defer func() { _ = rc.Close() }()
	data, err := io.ReadAll(rc)
	if err != nil {
		return ""
	}
	f, err := modfile.Parse("go.mod", data, nil)
	if err != nil || f.Go == nil {
		return ""
	}
	return f.Go.Version
}

// report states what one population leg wrote, and warns when it wrote less than
// it was asked for. Under GOPROXY=off a hole is the difference between a module
// that resolves and one that does not, so it is named here rather than left to
// surface later as an unexplained load failure.
func (c *Cache) report(ctx context.Context, leg string, r modcache.Report) {
	c.logger.DebugContext(ctx, "callgraph_modcache_populated",
		slog.String("leg", leg), slog.Int("written", r.Written), slog.Int("requested", r.Requested))
	if !r.Complete() {
		c.logger.WarnContext(ctx, "callgraph_modcache_incomplete",
			slog.String("leg", leg),
			slog.Int("written", r.Written), slog.Int("requested", r.Requested),
			slog.String("failures", r.FailureSummary(failureLogLimit)))
	}
}

// prefetchSource acquires the full artefact of every requirement the store
// cannot supply source for. A go.mod-only record does not satisfy it: the
// closure that wrote one was populating a module graph, and a build cannot be
// type-checked from requirement lines.
func (c *Cache) prefetchSource(ctx context.Context, coords []coordinate.ModuleCoordinate) {
	if c.fetcher == nil {
		return
	}
	for _, coord := range coords {
		if ctx.Err() != nil {
			return
		}
		record, ok, err := fetchports.ComposedFetchRecord(ctx, c.facts, coord)
		if err != nil {
			c.logger.WarnContext(ctx, "callgraph_modcache_prefetch_check_failed",
				slog.String("module", coord.String()), slog.String("error", err.Error()))
			continue
		}
		if ok && !record.IsGoModOnly() {
			continue
		}
		c.logger.InfoContext(ctx, "callgraph_modcache_prefetch", slog.String("module", coord.String()))
		if ferr := c.fetcher.FetchModule(ctx, coord); ferr != nil {
			c.logger.WarnContext(ctx, "callgraph_modcache_prefetch_failed",
				slog.String("module", coord.String()), slog.String("error", ferr.Error()))
		}
	}
}

// prefetchGoMod acquires the go.mod alone of every coordinate the store does not
// hold. It is the closure's ensure hook: these versions exist in the cache so
// that MVS can read their requirements, and are never compiled, so their zips
// would be discarded work.
func (c *Cache) prefetchGoMod(ctx context.Context, coords []coordinate.ModuleCoordinate) {
	if c.fetcher == nil {
		return
	}
	for _, coord := range coords {
		if ctx.Err() != nil {
			return
		}
		_, ok, err := fetchports.ComposedFetchRecord(ctx, c.facts, coord)
		if err != nil {
			c.logger.WarnContext(ctx, "callgraph_modcache_prefetch_check_failed",
				slog.String("module", coord.String()), slog.String("error", err.Error()))
			continue
		}
		if ok {
			continue
		}
		c.logger.InfoContext(ctx, "callgraph_modcache_prefetch_gomod", slog.String("module", coord.String()))
		if ferr := c.fetcher.FetchModuleGoMod(ctx, coord); ferr != nil {
			c.logger.WarnContext(ctx, "callgraph_modcache_prefetch_gomod_failed",
				slog.String("module", coord.String()), slog.String("error", ferr.Error()))
		}
	}
}

// prefixed names the leg a rendered failure list came from, so a missing zip is
// not read as a missing requirement line. An empty list stays empty.
func prefixed(leg, failures string) string {
	if failures == "" {
		return ""
	}
	return leg + ": " + failures
}

// joinFailures runs two rendered lists together, dropping the empty ones.
func joinFailures(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	default:
		return a + "; " + b
	}
}
