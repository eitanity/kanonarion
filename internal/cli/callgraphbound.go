package cli

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/spf13/cobra"

	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	extextractor "github.com/eitanity/kanonarion/internal/extract/adapters/extractor/local"
)

// callgraphTimeoutUsage is the one help string every --callgraph-timeout
// registration carries, for the reason --no-progress states beside it: the flag
// means one thing everywhere it appears, and a per-command copy is how the same
// flag ends up documented three different ways.
var callgraphTimeoutUsage = fmt.Sprintf(
	"wall-clock ceiling for a single call-graph subprocess. It is a backstop: a child is "+
		"normally ended by making no progress for %s, not by how long it has been working. "+
		"Raise it for a module too large to analyse in the default",
	cgports.DefaultStallWindow)

// registerCallgraphTimeoutFlag registers --callgraph-timeout on cmd, bound to
// the invocation-wide ceiling.
//
// Every command that spawns a call-graph child registers it here. Before this
// existed there was no flag and no environment variable at all, so a module that
// needed more than the hardcoded ten minutes could not be analysed on any host,
// however much time the operator was willing to give it.
func registerCallgraphTimeoutFlag(cmd *cobra.Command) {
	cmd.Flags().DurationVar(&callgraphCeiling, "callgraph-timeout", cgports.DefaultCeiling, callgraphTimeoutUsage)
}

// callgraphWorkersUsage states the cost of raising the bound, because the flag
// that admits another subprocess is the flag that adds another module's SSA
// closure to the run's peak. The figures come from the code so help and
// behaviour cannot drift.
var callgraphWorkersUsage = fmt.Sprintf(
	"how many call-graph subprocesses may run at once. It is separate from the "+
		"module pool, which it does not resize and is not resized by. "+
		"0 sizes it from the host: min(NumCPU, %d, available memory / %d GiB). Each "+
		"subprocess holds one module's whole dependency closure in SSA — tens of GB "+
		"for the largest — so every step up raises the run's peak memory by about "+
		"one more module's worth",
	extextractor.CallgraphCPUCap, extextractor.CallgraphBudgetBytes>>30)

// registerCallgraphWorkersFlag registers --callgraph-workers on cmd, bound to
// the invocation-wide subprocess bound.
func registerCallgraphWorkersFlag(cmd *cobra.Command) {
	cmd.Flags().IntVar(&callgraphWorkers, "callgraph-workers", 0, callgraphWorkersUsage)
}

// describeCallgraphBound renders the bound a run adopted and what decided it.
//
// A run states this because the number on its own is not readable: four
// subprocesses is the healthy default on a large host and is also what a host
// with sixteen gigabytes free gets, and only the budget beside it says which
// one a reader is looking at. It is the answer to "how many workers did it
// actually use", which a reader previously could get only by turning the log
// level up and hoping the memory term had lowered the bound.
func describeCallgraphBound(b extextractor.CallgraphBound) string {
	if b.Requested {
		return fmt.Sprintf("Call-graph subprocesses: %d at once (--callgraph-workers)", b.Workers)
	}
	if !b.AvailableKnown {
		return fmt.Sprintf("Call-graph subprocesses: %d at once (from %d CPUs; this host does not report available memory)",
			b.Workers, b.CPUCap)
	}
	return fmt.Sprintf("Call-graph subprocesses: %d at once (%.1f GiB available, %.1f GiB budgeted each, CPU cap %d)",
		b.Workers,
		float64(b.AvailableBytes)/float64(1<<30),
		float64(b.BudgetBytes)/float64(1<<30),
		b.CPUCap)
}

// callgraphNarrationFor returns where a PARENT's copy of its children's progress
// lines should go, gated exactly as every other stderr narration is.
//
// It is throttled, and the other reporters' interval is the one it uses: a
// hundred and seventy modules each reporting a dozen phases is a firehose, while
// silence is the defect being repaired. One line per interval names the module
// and the phase it reached, which is what tells work from a hang.
func callgraphNarrationFor(stderr io.Writer, noProgress bool, progressPref bool) io.Writer {
	if noProgress || !progressPref {
		return nil
	}
	return newThrottledLines(stderr, progressInterval, time.Now)
}

// throttledLines passes at most one written line per interval. It is safe for
// concurrent use: the spawners copy their children's stderr from a goroutine
// each.
type throttledLines struct {
	w        io.Writer
	interval time.Duration
	now      func() time.Time

	mu   sync.Mutex
	last time.Time
}

func newThrottledLines(w io.Writer, interval time.Duration, now func() time.Time) *throttledLines {
	return &throttledLines{w: w, interval: interval, now: now}
}

func (t *throttledLines) Write(p []byte) (int, error) {
	t.mu.Lock()
	now := t.now()
	pass := t.last.IsZero() || now.Sub(t.last) >= t.interval
	if pass {
		t.last = now
	}
	t.mu.Unlock()
	if !pass {
		// Reported as written: the caller is narrating, not persisting, and a short
		// count would read as an I/O failure on the child's stderr copy.
		return len(p), nil
	}
	n, err := t.w.Write(p)
	if err != nil {
		return n, fmt.Errorf("writing callgraph progress: %w", err)
	}
	return len(p), nil
}
