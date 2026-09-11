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

// CallgraphBudgetBytes is the memory one call-graph subprocess is budgeted.
// It is what admission is priced in: the bound divides the host's available
// memory by it, and the headroom gate refuses to start an analysis beside
// another while less than this is free. The ceiling an analysis enforces on
// itself is a different and larger figure — see CeilingBytes.
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
	// BudgetBytes is the memory one subprocess is budgeted, which is what the
	// count above is priced in.
	BudgetBytes uint64
	// AvailableBytes is the host's reading, and AvailableKnown whether there was
	// one. It is taken even when the operator named the bound, because the
	// ceiling is shared out of it either way. A host that could not answer is
	// bounded by CPU alone, and saying so is different from reporting zero bytes
	// available.
	AvailableBytes uint64
	AvailableKnown bool
	// CPUCap is the ceiling the CPU side imposed, whatever the memory said.
	CPUCap int
	// CeilingBytes is how much memory one analysis may hold before it stops
	// itself. Zero when the host could not be read and there is none.
	CeilingBytes uint64
}

// ResolveCallgraphConcurrency returns how many call-graph subprocesses may run
// at once. See ResolveCallgraphBound, whose count this is.
func ResolveCallgraphConcurrency(requested int, mem HostMemory, logger *slog.Logger) int {
	return ResolveCallgraphBound(requested, 0, mem, logger).Workers
}

// ResolveCallgraphBound sizes the call-graph subprocess bound and says what
// sized it. A non-zero requested value is an operator override and is taken as
// given. Zero is sized from the host: the CPU cap, lowered when the available
// memory cannot fund that many budgets, and never below one — an unreadable
// reading is "unknown", not a budget of zero.
//
// ceiling, when non-zero, is the operator's own answer to how much one analysis
// may hold and replaces the derived one.
func ResolveCallgraphBound(requested int, ceiling uint64, mem HostMemory, logger *slog.Logger) CallgraphBound {
	cpuCap := min(runtime.NumCPU(), CallgraphCPUCap)
	log := logger
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	available, availableKnown := readAvailable(cpuCap, mem, log)

	bound := CallgraphBound{
		Workers:        cpuCap,
		Requested:      requested > 0,
		BudgetBytes:    CallgraphBudgetBytes,
		AvailableBytes: available,
		AvailableKnown: availableKnown,
		CPUCap:         cpuCap,
	}
	switch {
	case requested > 0:
		bound.Workers = requested
	case availableKnown:
		// uint64 division, then a bounded conversion: min caps the quotient at
		// cpuCap (at most CallgraphCPUCap) before it is narrowed, so the result fits
		// an int on every platform however much memory the host reports.
		budgeted := available / CallgraphBudgetBytes
		bound.Workers = max(1, int(min(budgeted, uint64(cpuCap)))) // #nosec G115 -- min bounds the value by CallgraphCPUCap before conversion.
		if bound.Workers < cpuCap {
			log.Info("call-graph subprocesses capped by available memory",
				"available_bytes", available,
				"per_subprocess_budget_bytes", CallgraphBudgetBytes,
				"callgraph_workers", bound.Workers,
				"cpu_cap", cpuCap)
		}
	}
	bound.CeilingBytes = ceiling
	if ceiling == 0 {
		bound.CeilingBytes = deriveCeiling(available, availableKnown, bound.Workers)
	}
	return bound
}

// readAvailable takes the host's reading, or says there is none. A host that
// cannot answer is bounded by CPU alone, and that is a different fact from a
// host reporting nothing free.
func readAvailable(cpuCap int, mem HostMemory, log *slog.Logger) (uint64, bool) {
	if mem == nil {
		log.Debug("no host-memory reporter wired; bounding call-graph subprocesses by CPU alone",
			"callgraph_workers", cpuCap)
		return 0, false
	}
	available, err := mem.AvailableBytes()
	if err != nil {
		log.Debug("available memory unreadable; bounding call-graph subprocesses by CPU alone",
			"callgraph_workers", cpuCap, "error", err)
		return 0, false
	}
	return available, true
}

// deriveCeiling shares the host's available memory between the analyses the
// bound admits, holding one budget back.
//
// It is a share rather than a constant for the reason the bound is: the figures
// this was tuned against are one host's, and a number tuned to it would be wrong
// on every other. The reserve is what the admission gate already treats as the
// price of one analysis, so a host at the ceiling on every worker can still fund
// the next thing that asks.
//
// It is never below one budget. A ceiling under the figure admission is priced
// in would let the gate start an analysis the ceiling ends immediately, which
// records a memory failure for a module that was never given the memory.
func deriveCeiling(available uint64, availableKnown bool, workers int) uint64 {
	if !availableKnown || workers < 1 {
		return 0
	}
	if available <= CallgraphBudgetBytes {
		return CallgraphBudgetBytes
	}
	return max(CallgraphBudgetBytes, (available-CallgraphBudgetBytes)/uint64(workers)) // #nosec G115 -- workers is at least one and at most CallgraphCPUCap.
}
