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
//
// # One regime
//
// Every Go or git child this repository starts is built here. That is the whole
// rule, and it is enforced by TestEveryChildProcessIsHardened rather than by
// habit: the class regrew once already, and twelve call sites bounding child
// lifetime three different ways is twelve chances for two of them to disagree.
//
// The rule is stated as "by default" rather than "when the child is expensive"
// because the hardening is a process-group attribute and a cancel function —
// it costs no wall time, so there is no saving to trade a divergence for. A
// site that genuinely cannot use it says so in [DirectSpawns], with its reason.
//
// Two things this deliberately does NOT decide for the caller:
//
//   - WaitDelay. It bounds the wait on I/O pipes AFTER the child is gone, and
//     it introduces [exec.ErrWaitDelay] into the caller's error surface, so it
//     is the caller's to set — from [WaitDelay], so there is one number.
//   - the process group's effect on terminal signals. Setpgid takes the child
//     out of the terminal's foreground group, so a Ctrl-C no longer reaches it
//     directly; cancellation reaches it through the context instead. Every
//     caller here is under the CLI's signal.NotifyContext, which is what makes
//     that an equal trade rather than a loss.
package childproc

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"sync"
	"time"
)

// WaitDelay bounds how long Wait blocks on the child's I/O pipes after the
// process itself has gone, so an inherited pipe held open by a grandchild
// cannot hang the parent indefinitely.
//
// It is exported because the git adapters need the same bound for the same
// reason — git's transport helper inherits the output pipes and outlives the
// git process — and two constants of three seconds in two packages is the
// shape this package exists to remove.
const WaitDelay = 3 * time.Second

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
	cmd.WaitDelay = WaitDelay
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
