// Package childproc spawns child processes that cannot outlive their parent.
//
// [exec.CommandContext] alone is not enough for long-running, memory-hungry
// children. Its cancellation is a user-space watcher goroutine in the parent:
// if the parent dies abnormally — OOM-kill, SIGKILL, a closed stdout pipe —
// the watcher never runs and the child is orphaned, holding its working set
// until it finishes on its own. It also signals only the direct child, so any
// grandchildren the child spawned survive the kill.
//
// The commands built here close both gaps:
//
//   - the child leads its own process group, and cancellation kills the whole
//     group rather than the single process;
//   - on Linux the kernel is asked to SIGKILL the child when the parent dies
//     (PR_SET_PDEATHSIG), which is the only mechanism that survives the parent
//     being killed without warning.
package childproc

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"sync"
	"time"
)

// cmdWaitDelay bounds how long Wait blocks on the child's I/O pipes after the
// process itself has gone, so an inherited pipe held open by a grandchild
// cannot hang the parent indefinitely. It matches the gitexec adapter.
const cmdWaitDelay = 3 * time.Second

// CommandContext returns an [exec.Cmd] for name/args that is hardened against
// orphaning, as described in the package documentation. The caller owns every
// other field, including Stdout, Stderr, Dir, Env and WaitDelay; nothing here
// changes how output is captured.
//
// Cancellation runs before the standard kill, so ctx expiry terminates the
// whole process group.
func CommandContext(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 -- provenance of name and args is owned by callers; this wrapper only bounds process lifetime
	harden(cmd)
	cmd.Cancel = func() error { return killGroup(cmd) }
	return cmd
}

// Run runs name with args as a hardened child, capturing stderr, and returns
// what the child wrote there alongside the exec error. A non-zero exit, a
// context deadline or a kill all produce a non-nil error.
//
// Unlike [CommandContext] this also sets a WaitDelay, so a wedged pipe cannot
// keep the caller blocked after the child is gone.
func Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := CommandContext(ctx, name, args...)
	cmd.WaitDelay = cmdWaitDelay
	var stderr syncBuffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stderr.Bytes(), err
}

// syncBuffer is a [bytes.Buffer] safe for the one case WaitDelay creates: when
// the delay elapses, Wait returns while the goroutine copying the child's
// stderr may still be writing. Reading an unsynchronised buffer there is a data
// race, so both ends take the lock.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p) //nolint:wrapcheck // bytes.Buffer.Write never returns an error
}

// Bytes returns a copy of what has been written so far.
func (b *syncBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := b.buf.Bytes()
	return bytes.Clone(out)
}

// PartialExitCode is the exit code a kanonarion child uses for work it completed
// and knows to be incomplete — a call graph missing some packages, an extraction
// missing some stages.
const PartialExitCode = 1

// exitCoder is what an *exec.ExitError satisfies; the interface keeps the check
// exercisable without spawning a process.
type exitCoder interface{ ExitCode() int }

// ExitedPartial reports whether err is a child exit carrying PartialExitCode. A
// parent must not read that as a failure: the child wrote its record, and the
// record is what says how complete it is.
func ExitedPartial(err error) bool {
	var ec exitCoder
	return errors.As(err, &ec) && ec.ExitCode() == PartialExitCode
}
