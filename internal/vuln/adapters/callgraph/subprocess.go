package callgraph

import (
	"bytes"
	"context"
	"os/exec"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

// spawnTimeout is the per-module timeout for on-demand callgraph subprocesses.
// SSA closure construction for large modules can take many minutes; 10 minutes
// provides headroom while bounding the blast radius of a hung child.
const spawnTimeout = 10 * time.Minute

// OsCallGraphSpawner implements ports.CallGraphSpawner using os/exec. The binary
// path must be pre-resolved via os.Executable() at construction time so that the
// subprocess always runs the same kanonarion binary as the parent.
type OsCallGraphSpawner struct {
	binary string
}

// NewOsCallGraphSpawner constructs an OsCallGraphSpawner using the already-resolved
// binary path. Callers must resolve os.Executable themselves and pass the result.
func NewOsCallGraphSpawner(binary string) *OsCallGraphSpawner {
	return &OsCallGraphSpawner{binary: binary}
}

// Spawn runs `<binary> callgraph <module@version> [--force]` as a child process under
// a 10-minute timeout. It captures stderr and returns it alongside any exec error.
// A non-zero exit, timeout, or OOM kill results in a non-nil error.
func (s *OsCallGraphSpawner) Spawn(ctx context.Context, coord coordinate.ModuleCoordinate, force bool) ([]byte, error) {
	spawnCtx, cancel := context.WithTimeout(ctx, spawnTimeout)
	defer cancel()

	args := []string{"callgraph", coord.String()}
	if force {
		args = append(args, "--force")
	}

	cmd := exec.CommandContext(spawnCtx, s.binary, args...) // #nosec G204 -- binary resolved from os.Executable; args constructed from internal coord strings only
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stderr.Bytes(), err
}

var _ ports.CallGraphSpawner = (*OsCallGraphSpawner)(nil)
