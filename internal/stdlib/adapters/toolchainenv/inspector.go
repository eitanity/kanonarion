// Package toolchainenv implements ports.ToolchainInspector by probing the local
// Go toolchain with `go env GOROOT GOVERSION`. It is the offline custody path's
// anchor: the exact toolchain that compiles the project, resolved without any
// network access.
package toolchainenv

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"strings"

	"github.com/eitanity/kanonarion/internal/stdlib/ports"
)

// Inspector resolves GOROOT and GOVERSION from the local Go toolchain.
type Inspector struct {
	goBinary string // empty → resolved via PATH as "go"
	logger   *slog.Logger
}

// New constructs an Inspector. goBinary may be empty (uses "go" from PATH).
func New(goBinary string, logger *slog.Logger) *Inspector {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Inspector{goBinary: goBinary, logger: logger}
}

func (i *Inspector) goBin() string {
	if i.goBinary == "" {
		return "go"
	}
	return i.goBinary
}

// Locate runs `go env GOROOT GOVERSION` and returns the two values. `go env`
// prints one value per line in argument order. An empty GOROOT is treated as a
// probe failure — without it there is no source tree to anchor to.
func (i *Inspector) Locate(ctx context.Context) (goRoot, goVersion string, err error) {
	cmd := exec.CommandContext(ctx, i.goBin(), "env", "GOROOT", "GOVERSION") // #nosec G204 -- binary path is either "go" (hardcoded) or caller-supplied and trusted
	out, runErr := cmd.Output()
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			return "", "", fmt.Errorf("go env GOROOT GOVERSION: %w\n%s", runErr, exitErr.Stderr)
		}
		return "", "", fmt.Errorf("go env GOROOT GOVERSION: %w", runErr)
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	get := func(n int) string {
		if n < len(lines) {
			return strings.TrimSpace(lines[n])
		}
		return ""
	}
	goRoot, goVersion = get(0), get(1)
	if goRoot == "" {
		return "", "", errors.New("go env reported an empty GOROOT")
	}
	return goRoot, goVersion, nil
}

var _ ports.ToolchainInspector = (*Inspector)(nil)
