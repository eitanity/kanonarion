package local

import (
	"io"
	"log/slog"
	"runtime"
)

// HostMemory reports how much memory the host can hand to new work right now.
// It is declared at the consumer so this stage depends on the question, not on
// the adapter that answers it; internal/adapters/meminfo satisfies it.
type HostMemory interface {
	AvailableBytes() (uint64, error)
}

// CallgraphBudgetBytes is the memory one call-graph subprocess is budgeted. It
// is a budget, not a limit: nothing enforces it on the child, and the largest
// modules go far past it. Its only job is to stop the extraction pool admitting
// more concurrent subprocesses than the host can hold.
// Typed rather than untyped because 4 GiB does not fit an int on a 32-bit
// platform, and an untyped constant handed to a variadic any — the logger —
// defaults to int and fails to compile there.
const CallgraphBudgetBytes uint64 = 4 << 30 // 4 GiB

// CallgraphCPUCap is the ceiling from the CPU side. A worker running this stage
// spends nearly all its wall clock inside the subprocess, so more than four buys
// little even on a large host — and each one costs CallgraphBudgetBytes and
// contends for the store's single writer.
const CallgraphCPUCap = 4

// ResolveCallgraphConcurrency returns how many call-graph subprocesses may run
// at once. A non-zero requested value is an operator override and is taken as
// given. Zero is sized from the host: the CPU cap, lowered when the available
// memory cannot fund that many budgets, and never below one — an unreadable
// reading is "unknown", not a budget of zero.
func ResolveCallgraphConcurrency(requested int, mem HostMemory, logger *slog.Logger) int {
	if requested > 0 {
		return requested
	}
	log := logger
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	cpuCap := min(runtime.NumCPU(), CallgraphCPUCap)
	if mem == nil {
		log.Debug("no host-memory reporter wired; bounding call-graph subprocesses by CPU alone",
			"callgraph_workers", cpuCap)
		return cpuCap
	}
	available, err := mem.AvailableBytes()
	if err != nil {
		log.Debug("available memory unreadable; bounding call-graph subprocesses by CPU alone",
			"callgraph_workers", cpuCap, "error", err)
		return cpuCap
	}
	// uint64 division, then a bounded conversion: min caps the quotient at
	// cpuCap (at most CallgraphCPUCap) before it is narrowed, so the result fits
	// an int on every platform however much memory the host reports.
	budgeted := available / CallgraphBudgetBytes
	workers := max(1, int(min(budgeted, uint64(cpuCap)))) // #nosec G115 -- min bounds the value by CallgraphCPUCap before conversion.
	if workers < cpuCap {
		log.Info("call-graph subprocesses capped by available memory",
			"available_bytes", available,
			"per_subprocess_budget_bytes", CallgraphBudgetBytes,
			"callgraph_workers", workers,
			"cpu_cap", cpuCap)
	}
	return workers
}
