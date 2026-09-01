package staticcha

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

// setupGoEnv puts the caller's chosen Go toolchain in front of this process's
// children, and returns the function that puts the process back as it was.
//
// The chosen binary is linked into a fresh directory under the name `go` rather
// than having its own directory prepended, because --go-binary names a FILE: a
// toolchain installed as `go1.26.6`, or a shim, sits beside a different `go` in
// the same directory, and prepending that directory would resolve to the
// neighbour. The link is the only thing that makes the chosen file the one a
// child finds.
//
// Every failure on that path is reported rather than absorbed. Both were
// previously ignored, and the shape of the second was the hazard: a failed
// symlink left the empty directory leading PATH, so the child resolved `go` from
// whatever came next and the analysis silently ran under a toolchain nobody
// chose — on the one flag whose entire purpose is choosing the toolchain. A run
// that cannot honour it must say so; the caller files that as an environment
// failure, which is what it is.
func (a *Analyser) setupGoEnv(ctx context.Context) (func(), error) {
	if a.goBinary == "" {
		return func() {}, nil
	}

	binDir, err := os.MkdirTemp("", "kanonarion-bin-*")
	if err != nil {
		return nil, fmt.Errorf("creating a directory to stage %s in: %w", a.goBinary, err)
	}
	cleanupBin := func() {
		if rerr := os.RemoveAll(binDir); rerr != nil {
			a.logger.WarnContext(ctx, "callgraph_bin_cleanup_failed",
				slog.String("error", rerr.Error()),
				slog.String("dir", binDir),
			)
		}
	}
	if err := os.Symlink(a.goBinary, filepath.Join(binDir, "go")); err != nil {
		cleanupBin()
		return nil, fmt.Errorf("staging %s as the analysis toolchain: %w", a.goBinary, err)
	}

	oldPath := os.Getenv("PATH")
	newPath := binDir + string(os.PathListSeparator) + oldPath
	if err := os.Setenv("PATH", newPath); err != nil {
		cleanupBin()
		return nil, fmt.Errorf("setting PATH: %w", err)
	}

	oldGoroot, gorootSet := os.LookupEnv("GOROOT")
	if err := os.Unsetenv("GOROOT"); err != nil {
		_ = os.Setenv("PATH", oldPath)
		cleanupBin()
		return nil, fmt.Errorf("unsetting GOROOT: %w", err)
	}

	return func() {
		_ = os.Setenv("PATH", oldPath)
		if gorootSet {
			_ = os.Setenv("GOROOT", oldGoroot)
		}
		cleanupBin()
	}, nil
}
