package cli

import (
	"context"
	"log/slog"
	"runtime"

	"github.com/eitanity/kanonarion/internal/walk/adapters/buildlist/gotoolchain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// currentBuildEnvFilter names the target platform a walk taken here and now
// would resolve for, as a filter over stored walks.
//
// It asks the question through the same `go env GOOS GOARCH` probe the walk's
// own build-list resolver uses, in the same directory, so a command selecting a
// stored walk to analyse selects one measured in the frame its own resolution
// would produce — including any GOOS/GOARCH override in the environment.
//
// When the probe fails it falls back to the host platform, because that is
// exactly what the walk resolver falls back to when it cannot run the probe
// either. The two must agree: a fallback that differed would filter for a
// platform no walk ever records.
func currentBuildEnvFilter(ctx context.Context, goBinary, projectDir string, logger *slog.Logger) walkports.BuildEnvFilter {
	goos, goarch := gotoolchain.New(goBinary, logger).TargetPlatform(ctx, projectDir)
	if goos == "" || goarch == "" {
		return walkports.BuildEnvFilter{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}
	}
	return walkports.BuildEnvFilter{GOOS: goos, GOARCH: goarch}
}
