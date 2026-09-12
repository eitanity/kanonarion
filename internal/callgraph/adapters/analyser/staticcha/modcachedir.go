package staticcha

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/eitanity/kanonarion/internal/adapters/modcache"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/coordinate"
)

// prepareModuleCache resolves the GOMODCACHE this analysis reads and returns the
// function that releases it.
//
// Three answers, in precedence order:
//
//   - --from-modcache names an existing cache. It is used as it stands and
//     nothing is materialised: an operator who has pointed at a populated cache
//     has already answered the question materialisation asks, and building a
//     second copy per module would be work with nothing to show for it.
//   - a materialiser is wired: a cache is built for this one analysis out of the
//     bytes the store holds, seeded with the requirements the extracted module
//     declares, and removed afterwards.
//   - neither: the empty string, leaving the host's own cache in force. That is
//     what every analysis read before this existed, and it is why a module's
//     analysability was a property of what unrelated go commands had left on the
//     machine rather than of what kanonarion had fetched.
//
// dir is the extracted module, read AFTER the replace-dropping and the
// synthesis: the requirements the loader will resolve are the ones the file on
// disk names, not the ones the published zip shipped.
//
// A failure to create the directory is not fatal. The analysis falls back to the
// host cache, which is where it resolved from until now, and says so.
func (a *Analyser) prepareModuleCache(
	ctx context.Context,
	dir string,
	coord coordinate.ModuleCoordinate,
) (string, func()) {
	if a.realModcacheDir != "" {
		return a.realModcacheDir, func() {}
	}
	if a.moduleCache == nil {
		return "", func() {}
	}

	main := declaredMainModule(dir)
	if len(main.Requires) == 0 {
		// Nothing to populate for: a module requiring nothing resolves from the
		// standard library alone, and an empty cache serves it exactly as well as
		// a full one. Materialising a directory to hold nothing would only add a
		// mkdir and a remove to every such analysis.
		return "", func() {}
	}

	cacheDir, err := os.MkdirTemp("", "kanonarion-cg-modcache-*")
	if err != nil {
		a.logger.WarnContext(ctx, "callgraph_modcache_unavailable",
			slog.String("module", coord.Path()),
			slog.String("version", coord.Version()),
			slog.String("error", err.Error()),
		)
		return "", func() {}
	}
	cleanup := func() {
		// modcache.Remove rather than os.RemoveAll: the go command writes the
		// entries it extracts read-only — files 0444, directories 0555 — and
		// RemoveAll cannot unlink a child of a read-only directory. It failed
		// partway and left the tree behind, at 6.7GB over 86 analyses before this
		// used the remover the scan's own temp cache already used.
		if rerr := modcache.Remove(cacheDir); rerr != nil {
			a.logger.WarnContext(ctx, "callgraph_modcache_cleanup_failed",
				slog.String("error", rerr.Error()),
				slog.String("dir", cacheDir),
			)
		}
	}

	a.step(coord, "materialising the module cache")
	report := a.moduleCache.Materialise(ctx, cacheDir, main)
	a.step(coord, fmt.Sprintf("module cache materialised (%d of %d)", report.Written, report.Requested))
	a.logger.InfoContext(ctx, "callgraph_modcache_materialised",
		slog.String("module", coord.Path()),
		slog.String("version", coord.Version()),
		slog.Int("written", report.Written),
		slog.Int("requested", report.Requested),
	)
	if !report.Complete() {
		// Under GOPROXY=off there is no fallback, so a hole here is the difference
		// between a module that resolves and one that records an environment
		// failure. Naming it is what keeps that failure explicable.
		a.logger.WarnContext(ctx, "callgraph_modcache_incomplete",
			slog.String("module", coord.Path()),
			slog.String("version", coord.Version()),
			slog.Int("written", report.Written),
			slog.Int("requested", report.Requested),
			slog.String("failures", report.Failures),
		)
	}
	return cacheDir, cleanup
}

// declaredMainModule reads what the extracted tree states about itself: the
// language version that decides how much of the module graph the toolchain
// reads, and the requirements it reads it for.
//
// It is read from the file on disk rather than from the published go.mod,
// because the file on disk is what the loader opens: the replace-dropping and
// the synthesis have already run, and a synthesised file states its own
// directive.
//
// A go.mod that is absent or will not parse yields the zero value. The load
// reports that in its own terms; nothing here is a gate.
func declaredMainModule(dir string) cgports.MainModule {
	main := cgports.MainModule{GoVersion: declaredGoVersion(dir)}
	for _, r := range declaredRequirements(dir) {
		c, err := coordinate.NewModuleCoordinate(r.Path, r.Version)
		if err != nil {
			// A require line the constructor rejects names no module to populate
			// for. The load reports it in its own terms, with the line number this
			// cannot produce.
			continue
		}
		main.Requires = append(main.Requires, c)
	}
	return main
}
