package callgraph

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/childproc"
	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

// OsCallGraphSpawner implements ports.CallGraphSpawner using os/exec. The binary
// path must be pre-resolved via os.Executable() at construction time so that the
// subprocess always runs the same kanonarion binary as the parent.
type OsCallGraphSpawner struct {
	binary string
	bounds childproc.Bounds
}

// NewOsCallGraphSpawner constructs an OsCallGraphSpawner using the already-resolved
// binary path. Callers must resolve os.Executable themselves and pass the result.
//
// ceiling is the wall-clock backstop for one child; zero takes the default. What
// normally ends a wedged child is the stall window — the child reports each phase
// it enters, and silence, not elapsed time, is the evidence of a hang.
func NewOsCallGraphSpawner(binary string, ceiling time.Duration, progress io.Writer) *OsCallGraphSpawner {
	if ceiling <= 0 {
		ceiling = cgports.DefaultCeiling
	}
	return &OsCallGraphSpawner{
		binary: binary,
		bounds: childproc.Bounds{
			Stall:          cgports.DefaultStallWindow,
			Ceiling:        ceiling,
			ProgressPrefix: cgports.ProgressPrefix,
			Progress:       progress,
		},
	}
}

// WithMemoryCeiling gives each child a ceiling on the memory it may hold, in
// bytes, which it enforces on itself. Zero leaves it unbounded.
func (s *OsCallGraphSpawner) WithMemoryCeiling(bytes uint64) *OsCallGraphSpawner {
	s.bounds.MemoryCeiling = bytes
	return s
}

// Spawn runs `<binary> callgraph <module@version> [--force] [--from-walk <id>]`
// as a child process bounded by the progress it reports and by a wall-clock
// backstop. It captures stderr and returns it alongside any exec error. A kill,
// an OOM, or an exit saying no graph was produced results in a non-nil error; an
// exit saying the graph is incomplete does not, because the graph is stored and
// the record states its own completeness.
func (s *OsCallGraphSpawner) Spawn(ctx context.Context, coord coordinate.ModuleCoordinate, force bool, walkID string) ([]byte, error) {
	// The subprocess reports each phase it enters and this process ends it when those
	// reports stop. The instruction is explicit because the child would otherwise
	// take it from the store's own progress preference, which would let a config
	// file turn the stall detector off.
	args := []string{"callgraph", coord.String(), "--narrate-progress"}
	if force {
		args = append(args, "--force")
	}
	// Named on the command line because the child opens the store fresh and knows
	// only its arguments: without it a module published before Go modules is
	// analysed against no build list at all.
	if walkID != "" {
		args = append(args, "--from-walk", walkID)
	}

	// childproc, not exec directly: the child builds an SSA closure that can hold
	// several GB, and must not survive an abnormal death of this process.
	stderr, err := childproc.RunBounded(ctx, s.bounds, s.binary, args...)
	// The child's writes are this run's writes; see the same fold on the extract
	// stage's spawner.
	sqlitestore.AddRetries(sqlitestore.ContentionNoticeIn(string(stderr)))
	// A child that exited Partial stored a graph naming its own gaps. Calling that
	// a spawn failure hides a usable graph behind a note saying there is none.
	if childproc.ExitedPartial(err) {
		return stderr, nil
	}
	// The analysis ran and only its write lost. Said here, where the marker is in
	// hand, so the note the scan records names a condition running again repairs
	// rather than one that reads as a property of the module.
	if err != nil && strings.Contains(string(stderr), sqlitestore.ContentionMarker) {
		return stderr, fmt.Errorf("the record could not be stored: another writer held the store lock "+
			"for the whole retry budget; running the scan again stores it: %w", err)
	}
	return stderr, err //nolint:wrapcheck // the caller classifies the raw exec error (exit status, context deadline); wrapping it here would rewrite the text those classifiers read
}

var _ ports.CallGraphSpawner = (*OsCallGraphSpawner)(nil)
