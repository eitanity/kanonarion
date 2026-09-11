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

// CallgraphBound is the bound a run adopted and what decided it.
//
// It is a value rather than a bare count because the count on its own is not
// reportable: "four subprocesses" says nothing about whether four was the CPU
// cap, an operator's instruction, or all the memory this host could fund. A run
// that states the bound without stating what produced it leaves a reader unable
// to tell a healthy default from a host in trouble.
type CallgraphBound struct {
	// Workers is how many call-graph subprocesses may run at once.
	Workers int
	// Requested is true when Workers came from the operator rather than the host.
	Requested bool
	// BudgetBytes is the memory one subprocess was budgeted when the host sized
	// the bound. Zero when the operator named the bound.
	BudgetBytes uint64
	// AvailableBytes is the reading the sizing used, and AvailableKnown whether
	// there was one. A host that could not answer is bounded by CPU alone, and
	// saying so is different from reporting zero bytes available.
	AvailableBytes uint64
	AvailableKnown bool
	// CPUCap is the ceiling the CPU side imposed, whatever the memory said.
	CPUCap int
}

// ResolveCallgraphConcurrency returns how many call-graph subprocesses may run
// at once. See ResolveCallgraphBound, whose count this is.
func ResolveCallgraphConcurrency(requested int, mem HostMemory, logger *slog.Logger) int {
	return ResolveCallgraphBound(requested, mem, logger).Workers
}

// ResolveCallgraphBound sizes the call-graph subprocess bound and says what
// sized it. A non-zero requested value is an operator override and is taken as
// given. Zero is sized from the host: the CPU cap, lowered when the available
// memory cannot fund that many budgets, and never below one — an unreadable
// reading is "unknown", not a budget of zero.
func ResolveCallgraphBound(requested int, mem HostMemory, logger *slog.Logger) CallgraphBound {
	cpuCap := min(runtime.NumCPU(), CallgraphCPUCap)
	if requested > 0 {
		return CallgraphBound{Workers: requested, Requested: true, CPUCap: cpuCap}
	}
	log := logger
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if mem == nil {
		log.Debug("no host-memory reporter wired; bounding call-graph subprocesses by CPU alone",
			"callgraph_workers", cpuCap)
		return CallgraphBound{Workers: cpuCap, BudgetBytes: CallgraphBudgetBytes, CPUCap: cpuCap}
	}
	available, err := mem.AvailableBytes()
	if err != nil {
		log.Debug("available memory unreadable; bounding call-graph subprocesses by CPU alone",
			"callgraph_workers", cpuCap, "error", err)
		return CallgraphBound{Workers: cpuCap, BudgetBytes: CallgraphBudgetBytes, CPUCap: cpuCap}
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
	return CallgraphBound{
		Workers:        workers,
		BudgetBytes:    CallgraphBudgetBytes,
		AvailableBytes: available,
		AvailableKnown: true,
		CPUCap:         cpuCap,
	}
}
