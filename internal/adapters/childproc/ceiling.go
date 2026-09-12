package childproc

import (
	"fmt"
	"io"
	"runtime/debug"
	"runtime/metrics"
	"strconv"
	"time"
)

// MemoryCeilingEnv carries a child's memory ceiling, in bytes, from the process
// that spawned it to the process that must honour it.
//
// An environment entry is the only route there is: a child reads the env slice
// the executor hands it, so the parent changing its own environment reaches
// nothing, and the runtime's own knobs — GOGC, GOMEMLIMIT — are read once at
// startup and cannot be moved afterwards except through runtime/debug.
const MemoryCeilingEnv = "KANONARION_MEMORY_CEILING_BYTES"

// MemoryCeilingMarker opens the stderr line a child writes when it stops itself
// at its ceiling. It is the whole protocol for that outcome, in the shape this
// package's other parent/child agreements already take: the parent matches the
// marker and records an analysis that reached its ceiling, which is a different
// fact from one the operating system chose.
const MemoryCeilingMarker = "memory ceiling reached: "

// memoryCeilingPoll is how often a bounded child reads its own memory use.
//
// A ceiling enforced by polling is crossed by whatever the process allocates
// between two reads, so this is the precision of the whole mechanism. Reading it
// costs two runtime counters and no syscall, which is why the interval is short
// rather than comfortable.
const memoryCeilingPoll = 100 * time.Millisecond

// memoryCeilingHeadroom is the fraction of the ceiling the collector is given to
// work in. The soft target is set that much below the ceiling so a child reaches
// the ceiling only when the memory is live — garbage it would have collected
// anyway must not end an analysis.
const memoryCeilingHeadroom = 8

// EnforceMemoryCeiling makes this process honour a ceiling handed to it in
// [MemoryCeilingEnv], and reports the ceiling it adopted; zero means there was
// none to adopt and nothing was started.
//
// Two mechanisms, because measurement says neither is enough alone. The soft
// target ([debug.SetMemoryLimit]) is what the Go runtime offers and it does not
// bound this: it makes the collector work harder, and an SSA closure is live
// data with nothing to collect — a real analysis under a 4 GiB target reached
// 12 GB without slowing. Its job here is precision, not enforcement, so that
// what crosses the ceiling is memory the process genuinely needs.
//
// The watch is the enforcement, and it is what makes the outcome recordable. A
// hard rlimit ends a Go process through a runtime abort, which cannot say
// anything an operator can act on; a process that notices its own ceiling says
// what it reached and stops there.
//
// stop ends the process — the CLI's own exit, which owns what code that is —
// and is the test's recorder otherwise.
func EnforceMemoryCeiling(env func(string) string, stderr io.Writer, stop func()) uint64 {
	ceiling, ok := parseMemoryCeiling(env(MemoryCeilingEnv))
	if !ok {
		return 0
	}
	debug.SetMemoryLimit(int64(ceiling - ceiling/memoryCeilingHeadroom)) // #nosec G115 -- parseMemoryCeiling bounds the value below math.MaxInt64.
	go watchMemoryCeiling(ceiling, stderr, stop)
	return ceiling
}

// parseMemoryCeiling reads a ceiling from its environment spelling. Anything
// that is not a positive byte count is "no ceiling": a child must not refuse to
// run because the number handed to it was unreadable.
func parseMemoryCeiling(raw string) (uint64, bool) {
	if raw == "" {
		return 0, false
	}
	ceiling, err := strconv.ParseUint(raw, 10, 63)
	if err != nil || ceiling == 0 {
		return 0, false
	}
	return ceiling, true
}

// watchMemoryCeiling ends this process the moment its own memory passes ceiling.
func watchMemoryCeiling(ceiling uint64, stderr io.Writer, stop func()) {
	for {
		time.Sleep(memoryCeilingPoll)
		if inUse := MemoryInUse(); inUse > ceiling {
			_, _ = fmt.Fprintf(stderr, "%s%d bytes in use against a ceiling of %d\n",
				MemoryCeilingMarker, inUse, ceiling)
			stop()
			return
		}
	}
}

// MemoryInUse is how much memory this process holds that the operating system
// has not been given back — every class the runtime maps, less what it has
// released. That is the figure a ceiling is about, rather than the live heap:
// a span freed and not yet returned is still resident, and still the host's.
func MemoryInUse() uint64 {
	samples := []metrics.Sample{
		{Name: "/memory/classes/total:bytes"},
		{Name: "/memory/classes/heap/released:bytes"},
	}
	metrics.Read(samples)
	total, released := samples[0].Value.Uint64(), samples[1].Value.Uint64()
	if released > total {
		return 0
	}
	return total - released
}
