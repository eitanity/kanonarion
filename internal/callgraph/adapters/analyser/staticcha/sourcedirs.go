package staticcha

import (
	"context"
	"log/slog"
)

// SourceDirsProbe asks the Go toolchain the analysis is about to drive to name
// the directories it resolves files from: GOROOT, which holds the standard
// library; the build cache, which holds everything the toolchain generates; and
// the module cache, which holds the dependencies.
//
// It is asked rather than guessed. A build-cache path is recognised because the
// toolchain says where its cache is, never because the path contains "go-build":
// the cache moves with GOCACHE, and a rule that reads a directory name would
// both miss a cache that had moved and claim one that had not.
//
// dir and env are the load's own, for the reason ToolchainProbe states: a
// toolchain is resolved per directory and every analysis environment pins
// GOTOOLCHAIN=local, so a probe that inherited this process's would answer about
// a toolchain the loader never ran — and therefore about the wrong cache.
type SourceDirsProbe func(ctx context.Context, dir string, env []string) (SourceDirs, error)

// sourceDirsProbe is the probe an analysis consults. It defaults to
// noSourceDirs and is replaced by the composition root via SetSourceDirsProbe:
// this package is an extraction package and must not carry process-spawning
// capability itself (the restricted-imports gate enforces that), so the command
// that asks the toolchain lives with the caller that wires the analyser.
var sourceDirsProbe SourceDirsProbe = noSourceDirs

// SetSourceDirsProbe installs the probe an analysis consults. It is called once
// by the composition root; the probe must be callable while the analysis PATH is
// still in force, or it answers about a different toolchain from the one that
// ran.
func SetSourceDirsProbe(fn SourceDirsProbe) {
	if fn != nil {
		sourceDirsProbe = fn
	}
}

// noSourceDirs is the zero seam: with no probe wired, no directory is named and
// every resolved path is rendered against the roots the run already knows. It
// invents nothing — a seam that guessed a GOROOT would decide what a record
// says about the standard library on a suite that never ran a toolchain.
func noSourceDirs(context.Context, string, []string) (SourceDirs, error) { return SourceDirs{}, nil }

// probeSourceDirs names the analysis's own GOROOT and build cache, and says so
// when it could not.
//
// A probe that fails is disclosed rather than absorbed, because the consequence
// is silent and permanent: an unidentified build cache puts content-addressed
// paths back inside the seal, and a record that changes when nothing changed can
// never be composed with its own predecessor. The analysis still runs — it
// measured the module correctly and refusing would throw that away — but the
// warning is what lets an operator tell a record written without the roots from
// one written with them.
func (a *Analyser) probeSourceDirs(ctx context.Context, dir string, env []string) SourceDirs {
	dirs, err := sourceDirsProbe(ctx, dir, env)
	if err != nil {
		a.logger.WarnContext(ctx, "callgraph_source_dirs_unknown",
			slog.String("dir", dir),
			slog.String("error", err.Error()),
		)
		return SourceDirs{}
	}
	return dirs
}
