package staticcha

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

func (a *Analyser) setupGoEnv(ctx context.Context, _ string) (func(), error) {
	if a.goBinary == "" {
		return func() {}, nil
	}

	goDir := filepath.Dir(a.goBinary)
	binDir, err := os.MkdirTemp("", "kanonarion-bin-*")
	var cleanupBin func()
	if err == nil {
		goSymlink := filepath.Join(binDir, "go")
		_ = os.Symlink(a.goBinary, goSymlink)
		goDir = binDir
		cleanupBin = func() {
			if rerr := os.RemoveAll(binDir); rerr != nil {
				a.logger.WarnContext(ctx, "callgraph_bin_cleanup_failed",
					slog.String("error", rerr.Error()),
					slog.String("dir", binDir),
				)
			}
		}
	} else {
		cleanupBin = func() {}
	}

	oldPath := os.Getenv("PATH")
	newPath := goDir + string(os.PathListSeparator) + oldPath
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
