package cli

import (
	"context"
	"log/slog"
	"runtime"

	"github.com/eitanity/kanonarion/internal/walk/adapters/buildlist/gotoolchain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// walkBuildEnv names the build a walk taken here and now would be resolved in,
// as filters over stored walks: the target platform, and the toolchain that
// would compile the project.
//
// Both are asked through the same single `go env` probe the walk's own
// build-list resolver uses, in the same directory, so a command selecting a
// stored walk selects one measured in the build its own resolution would
// produce — including any GOOS/GOARCH override, any go.mod toolchain directive
// and any GOTOOLCHAIN switch.
type walkBuildEnv struct {
	platform walkports.BuildEnvFilter
	// toolchain is `go env GOVERSION`, empty when the probe could not answer.
	toolchain string
}

// toolchainFilter is the toolchain as a walk filter: nil when the probe failed.
//
// A failed probe deliberately does not filter on the empty string. The empty
// value selects the walks that recorded no toolchain at all, so filtering on it
// would answer a question nobody asked; and inventing a toolchain would select
// walks measured under one this run cannot confirm. The read widens instead, and
// names the toolchain of the walk it ended up with.
func (e walkBuildEnv) toolchainFilter() *string {
	if e.toolchain == "" {
		return nil
	}
	return &e.toolchain
}

// currentWalkBuildEnv probes the build environment for projectDir.
//
// When the platform probe fails it falls back to the host platform, because
// that is what the walk resolver falls back to when it cannot run the probe
// either. The toolchain has no such fallback: the resolver records the empty
// string, and a filter that guessed would exclude the walks it was meant to
// find.
func currentWalkBuildEnv(ctx context.Context, goBinary, projectDir string, logger *slog.Logger) walkBuildEnv {
	goVersion, goos, goarch := gotoolchain.New(goBinary, logger).BuildEnvironment(ctx, projectDir)
	if goos == "" || goarch == "" {
		return walkBuildEnv{
			platform:  walkports.BuildEnvFilter{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH},
			toolchain: goVersion,
		}
	}
	return walkBuildEnv{
		platform:  walkports.BuildEnvFilter{GOOS: goos, GOARCH: goarch},
		toolchain: goVersion,
	}
}

// String renders the build a read selected in, for output that names the walk it
// answered from. The toolchain is stated beside the platform because it decides
// which standard library the answer is about, and an answer that names only the
// platform reads as though the toolchain did not matter.
func (e walkBuildEnv) String() string {
	toolchain := e.toolchain
	if toolchain == "" {
		toolchain = "an unrecorded toolchain"
	}
	return e.platform.String() + " under " + toolchain
}
