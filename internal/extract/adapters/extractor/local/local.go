package local

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/childproc"
	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/extract/domain"
	"github.com/eitanity/kanonarion/internal/extract/ports"

	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	exapp "github.com/eitanity/kanonarion/internal/example/application"
	exdomain "github.com/eitanity/kanonarion/internal/example/domain"
	"github.com/eitanity/kanonarion/internal/failurecause"
	ifaceapp "github.com/eitanity/kanonarion/internal/iface/application"
	ifacedomain "github.com/eitanity/kanonarion/internal/iface/domain"
	licapp "github.com/eitanity/kanonarion/internal/license/application"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
)

type LicenseUseCase interface {
	Execute(ctx context.Context, req licapp.ExtractRequest) (licapp.ExtractResult, error)
}

type InterfaceUseCase interface {
	Execute(ctx context.Context, req ifaceapp.ExtractRequest) (ifaceapp.ExtractResult, error)
}

// SubprocessExecutor runs a child process and returns its stderr output.
// A non-nil error indicates the child exited non-zero or was killed by a signal
// or context deadline.
type SubprocessExecutor interface {
	Execute(ctx context.Context, args []string) (stderr []byte, err error)
}

// CallGraphReader reads back what the subprocess just recorded. It is satisfied
// by the sqlite call graph store.
//
// One read, and a narrow one. The stage asks "what did the child I just ran
// write here", which is answered by the newest generation's own columns and the
// four fields the result carries. It is NOT the question composition answers —
// "which generation should be served for this coordinate" — and asking that one
// instead is what made this stage the most expensive thing in an extraction run:
// composing decodes every generation the ledger holds, rebuilds each one's whole
// edge set, and re-marshals it to check the seal, so a coordinate with a large
// graph or a long history costs gigabytes to learn a status from.
type CallGraphReader interface {
	// LatestCallGraphOutcome returns what the newest generation at the coordinate
	// states, in append order, or (zero, false, nil) when the ledger holds none.
	LatestCallGraphOutcome(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (cgports.CallGraphOutcome, bool, error)
}

type ExampleUseCase interface {
	Execute(ctx context.Context, req exapp.ExtractRequest) (exapp.ExtractResult, error)
}

// AdapterExtractor routes extract calls to the appropriate local use case by
// stage name. Nil use cases are permitted; an Extract call for a nil stage
// returns an error.
type AdapterExtractor struct {
	license           LicenseUseCase
	iface             InterfaceUseCase
	cgExec            SubprocessExecutor
	cgReader          CallGraphReader
	cgPipelineVersion string
	// cgExtraArgs is appended to the "callgraph" subprocess invocation, after
	// the coordinate and before --force. It carries CLI state that is
	// process-global in the parent (e.g. --store-root, --from-modcache) and
	// therefore does not otherwise cross the subprocess boundary.
	cgExtraArgs []string
	example     ExampleUseCase
	// logger is optional; a nil one discards. See WithLogger.
	logger *slog.Logger
	// cgSem admits one call-graph subprocess per slot. It bounds the two costs
	// that scale with the number of children rather than with the pool: the SSA
	// closures held at once, and the writers queueing on the store's single
	// writer. A nil channel means unbounded and is reachable only from a struct
	// literal; the constructor always fills it.
	cgSem chan struct{}
	// cgMem reports what the host can hand to new work, re-read before each
	// analysis starts. The bound alone cannot answer that: it is sized once, when
	// the extractor is built, and the module in front of a worker ten minutes
	// later may be the one that holds fifty gigabytes on its own. A nil reporter
	// means no headroom gate, which is what a composition root with no way to ask
	// the host gets.
	cgMem HostMemory
	// cgRunning counts the analyses actually EXECUTING, not the slots held. The
	// gate reads it to guarantee progress: when none is running, the next one
	// starts whatever the host reports, because a host that cannot fund a single
	// analysis still has to attempt one to find that out — and a gate that could
	// stop every worker at once would turn a tight host into a hang.
	cgRunning atomic.Int64
	// cgPoll overrides CallgraphHeadroomPoll. It is unexported and set only by
	// this package's own tests, which exercise the gate thirty times over and
	// cannot wait two seconds a round for a condition they control.
	cgPoll time.Duration
}

// headroomPoll is how long a waiting worker sleeps before re-reading the host.
func (a *AdapterExtractor) headroomPoll() time.Duration {
	if a.cgPoll > 0 {
		return a.cgPoll
	}
	return CallgraphHeadroomPoll
}

// WithHostMemory wires the reading the headroom gate needs. It is optional — a
// nil reporter leaves the bound as the only limit — and returns the receiver
// for chaining.
func (a *AdapterExtractor) WithHostMemory(m HostMemory) *AdapterExtractor {
	a.cgMem = m
	return a
}

// WithLogger wires a logger so the stage can say when it is waiting for the
// host to have room for the next analysis. It is optional — a nil logger
// discards — and returns the receiver for chaining.
func (a *AdapterExtractor) WithLogger(l *slog.Logger) *AdapterExtractor {
	a.logger = l
	return a
}

// log returns a usable logger, so an adapter constructed without one still runs.
func (a *AdapterExtractor) log() *slog.Logger {
	if a.logger == nil {
		return slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return a.logger
}

// CallGraphSubprocessArgs builds the extra arguments a callgraph child needs to
// run against the same store — and the same module source — as its parent. The
// child is a fresh kanonarion process: it inherits none of the parent's
// process-global CLI state, so anything that state selects must be named on its
// command line or the child silently resolves the DEFAULT store root, reading,
// writing and migrating a store its caller never named.
//
// Every composition root that wires the callgraph stage MUST build its extra
// args here rather than assembling the list itself: a hand-copied argv list is
// how the library driver came to run its children against the default store.
// An empty modcacheDir means "no module-cache mode", which is the library
// driver's case — it has no --from-modcache concept and always reads bytes
// through the content-addressed blob store.
func CallGraphSubprocessArgs(storeRoot, modcacheDir string) []string {
	args := []string{"--store-root=" + storeRoot}
	if modcacheDir != "" {
		args = append(args, "--from-modcache="+modcacheDir)
	}
	return args
}

func NewAdapterExtractor(
	lic LicenseUseCase,
	iface InterfaceUseCase,
	cgExec SubprocessExecutor,
	cgReader CallGraphReader,
	cgPipelineVersion string,
	cgExtraArgs []string,
	ex ExampleUseCase,
) *AdapterExtractor {
	return &AdapterExtractor{
		license:           lic,
		iface:             iface,
		cgExec:            cgExec,
		cgReader:          cgReader,
		cgPipelineVersion: cgPipelineVersion,
		cgExtraArgs:       cgExtraArgs,
		example:           ex,
		cgSem:             make(chan struct{}, ResolveCallgraphConcurrency(0, nil, nil)),
	}
}

// WithCallgraphConcurrency bounds how many call-graph subprocesses this adapter
// runs at once. A value below one restores the CPU-derived default, so a
// composition root that has no operator value to pass still gets a bound.
func (a *AdapterExtractor) WithCallgraphConcurrency(n int) *AdapterExtractor {
	if n < 1 {
		n = ResolveCallgraphConcurrency(0, nil, nil)
	}
	a.cgSem = make(chan struct{}, n)
	return a
}

// CallgraphHeadroomPoll is how often a worker holding a slot re-reads the host
// while it waits for room to start its analysis.
const CallgraphHeadroomPoll = 2 * time.Second

// acquireCallgraphSlot waits for a subprocess slot AND for the host to have
// room for the analysis, and returns the release. A second return of false
// means the run ended while waiting, and the caller records that rather than
// starting an analysis nothing will read.
//
// Two gates, because they bound different things. The slot bounds how many
// analyses this run admits, and it is sized once from the host it started on.
// The headroom gate bounds what the host can carry right NOW: the distribution
// of module sizes is extremely skewed — most under 3 GiB, one over 50 — so four
// slots is a safe bound for four ordinary modules and an unsafe one the moment
// the heaviest module in the walk is one of them.
func (a *AdapterExtractor) acquireCallgraphSlot(ctx context.Context) (func(), bool) {
	releaseSlot := func() {}
	if a.cgSem != nil {
		select {
		case a.cgSem <- struct{}{}:
			releaseSlot = func() { <-a.cgSem }
		case <-ctx.Done():
			return func() {}, false
		}
	}
	if !a.awaitCallgraphHeadroom(ctx) {
		releaseSlot()
		return func() {}, false
	}
	return func() {
		a.cgRunning.Add(-1)
		releaseSlot()
	}, true
}

// awaitCallgraphHeadroom blocks until the host can fund another concurrent
// analysis. It returns false only when the run ended while waiting.
//
// It cannot deadlock, and the reason is the running count rather than a timeout.
// A worker waits only while some other analysis is running, and that analysis is
// what will release the memory it is waiting for; when nothing is running there
// is nothing to wait for and the worker proceeds. So at every moment at least
// one analysis is either running or about to start.
//
// An unreadable host is "unknown", never a budget of zero: refusing to run
// because the memory could not be measured would turn a diagnostic gap into an
// outage.
func (a *AdapterExtractor) awaitCallgraphHeadroom(ctx context.Context) bool {
	if a.cgMem == nil {
		a.cgRunning.Add(1)
		return true
	}
	waiting := false
	for {
		// The claim and the "is anything running" test are one atomic operation.
		// Read-then-increment lets two workers each see an idle run and both start,
		// which is the bound this gate exists to hold reappearing one worker later.
		if a.cgRunning.CompareAndSwap(0, 1) {
			return true
		}
		available, err := a.cgMem.AvailableBytes()
		if err != nil {
			a.cgRunning.Add(1)
			return true
		}
		if available >= CallgraphBudgetBytes {
			a.cgRunning.Add(1)
			return true
		}
		if !waiting {
			waiting = true
			a.log().InfoContext(ctx, "callgraph_analysis_waiting_for_memory",
				slog.Uint64("available_bytes", available),
				slog.Uint64("per_subprocess_budget_bytes", CallgraphBudgetBytes),
				slog.Int64("analyses_running", a.cgRunning.Load()),
			)
		}
		timer := time.NewTimer(a.headroomPoll())
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return false
		}
	}
}

func (a *AdapterExtractor) Extract(ctx context.Context, coord coordinate.ModuleCoordinate, stage string, force bool, walkID string) (ports.StageResult, error) {
	switch stage {
	case "license":
		res, err := a.license.Execute(ctx, licapp.ExtractRequest{Coordinate: coord, Force: force})
		if err != nil {
			return ports.StageResult{}, fmt.Errorf("license extraction failed: %w", err)
		}
		status := domain.StageSucceeded
		switch res.Record.OverallStatus {
		case licdomain.LicenceStatusUnknown, licdomain.LicenseStatusExtractionFailed, licdomain.LicenseStatusCancelled:
			status = domain.StageFailed
		}
		return ports.StageResult{
			RecordID: res.Record.ContentHash,
			Status:   status,
			Error:    failureReason(stage, status, res.Record.OverallStatus.String(), res.Record.FailureDetail),
		}, nil

	case "interface":
		res, err := a.iface.Execute(ctx, ifaceapp.ExtractRequest{Coordinate: coord, Force: force})
		if err != nil {
			return ports.StageResult{}, fmt.Errorf("interface extraction failed: %w", err)
		}
		status := domain.StageSucceeded
		switch res.Record.OverallStatus {
		case ifacedomain.InterfaceStatusUnknown, ifacedomain.InterfaceStatusExtractionFailed, ifacedomain.InterfaceStatusCancelled:
			status = domain.StageFailed
		}
		return ports.StageResult{
			RecordID: res.Record.ContentHash,
			Status:   status,
			Error:    failureReason(stage, status, res.Record.OverallStatus.String(), res.Record.FailureDetail),
		}, nil

	case "callgraph":
		return a.extractCallgraphSubprocess(ctx, coord, force, walkID)

	case "example":
		res, err := a.example.Execute(ctx, exapp.ExtractRequest{Coordinate: coord, Force: force})
		if err != nil {
			return ports.StageResult{}, fmt.Errorf("example extraction failed: %w", err)
		}
		status := domain.StageSucceeded
		switch res.Record.OverallStatus {
		case exdomain.ExampleStatusUnknown, exdomain.ExampleStatusExtractionFailed, exdomain.ExampleStatusCancelled:
			status = domain.StageFailed
		}
		return ports.StageResult{
			RecordID: res.Record.ContentHash,
			Status:   status,
			Error:    failureReason(stage, status, res.Record.OverallStatus.String(), res.Record.FailureDetail),
		}, nil

	default:
		return ports.StageResult{}, fmt.Errorf("unknown stage: %s", stage)
	}
}

// extractCallgraphSubprocess runs the callgraph stage by spawning a child
// process. The child runs the full callgraph extraction and persists the record
// to the store. The parent reads the record back on success.
func (a *AdapterExtractor) extractCallgraphSubprocess(ctx context.Context, coord coordinate.ModuleCoordinate, force bool, walkID string) (ports.StageResult, error) {
	// The subprocess reports each phase it enters and the executor ends it when those
	// reports stop, so the instruction is explicit rather than left to the store's
	// progress preference — a config file must not be able to disable the stall
	// detector.
	args := []string{"callgraph", coord.String(), "--narrate-progress"}
	args = append(args, a.cgExtraArgs...)
	if force {
		args = append(args, "--force")
	}
	// The walk is lost at the process boundary unless it is named on the command
	// line: the child opens the store fresh and knows only its arguments. Without
	// it a pre-modules module is analysed with no build list, which is what left
	// this population failing.
	if walkID != "" {
		args = append(args, "--from-walk", walkID)
	}

	// The subprocesses carry their own bound, however wide the module pool is:
	// one worker runs every stage for its module, and the cheap in-process stages
	// must not be slowed to bound this one.
	release, admitted := a.acquireCallgraphSlot(ctx)
	if !admitted {
		return ports.StageResult{
			Status: domain.StageFailed,
			Cause:  failurecause.Environment,
			Error: fmt.Sprintf("callgraph stage status=%s: the run ended before the analysis could start",
				cgdomain.CallGraphStatusCancelled),
		}, nil
	}
	defer release()

	stderr, execErr := a.cgExec.Execute(ctx, args)
	// The child's writes are this run's writes. Without folding its count in, a
	// run whose children waited repeatedly for the store lock reports none.
	sqlitestore.AddRetries(sqlitestore.ContentionNoticeIn(string(stderr)))
	// A child that exited Partial wrote its graph; the record read below is what
	// classifies it. Reading that exit as a fault made every incompletely
	// analysable module a failed stage.
	if execErr != nil && !childproc.ExitedPartial(execErr) {
		detail, cause, cgStatus := buildSubprocessErrorDetail(execErr, stderr, walkID)
		return ports.StageResult{
			Status: domain.StageFailed,
			Cause:  cause,
			Error:  fmt.Sprintf("callgraph stage status=%s: %s", cgStatus, detail),
		}, nil
	}

	rec, found, err := a.cgReader.LatestCallGraphOutcome(ctx, coord, a.cgPipelineVersion)
	if err != nil {
		return ports.StageResult{}, fmt.Errorf("reading callgraph record after subprocess: %w", err)
	}
	if !found {
		return ports.StageResult{
			Status: domain.StageFailed,
			Error:  "callgraph stage status=ExtractionFailed: subprocess exited 0 but no record found in store",
		}, nil
	}

	status := domain.StageSucceeded
	switch rec.OverallStatus {
	case cgdomain.CallGraphStatusUnknown, cgdomain.CallGraphStatusExtractionFailed, cgdomain.CallGraphStatusCancelled, cgdomain.CallGraphStatusLoadFailed:
		status = domain.StageFailed
	}
	return ports.StageResult{
		RecordID: rec.ContentHash,
		Status:   status,
		// The record already decided what its failure is a statement about; the
		// stage repeats the record's own answer rather than reaching a second one.
		Cause: rec.FailureCause,
		Error: failureReason("callgraph", status, rec.OverallStatus.String(), rec.FailureDetail),
	}, nil
}

// buildSubprocessErrorDetail formats the error_detail for a failed callgraph
// subprocess, says what the failure is a statement about, and names the
// call-graph status it amounts to.
//
// The status is decided here rather than at the call site because it is the same
// judgement as the detail: what ended this child, and what would a reader do
// about it. Everything the child itself could record is in the record it wrote;
// this covers the outcomes where there is no record because there is no longer a
// child, and the parent is the only process left to state them.
//
// The two deadlines are named separately because a reader acts on them
// differently: a subprocess stopped for reporting nothing had halted, while one
// killed at the ceiling was still working and needs a larger number. Both are
// this host rather than the module — the same module on an idle box, or with the
// ceiling raised, may well produce a complete graph — so neither may be cached
// as a property of the published bytes.
func buildSubprocessErrorDetail(execErr error, stderr []byte, walkID string) (string, failurecause.Cause, cgdomain.CallGraphStatus) {
	stderrStr := strings.TrimSpace(string(stderr))
	suffix := ""
	if stderrStr != "" {
		suffix = ": " + stderrStr
	}

	switch {
	case strings.Contains(stderrStr, sqlitestore.ContentionMarker):
		// The analysis ran; only its write lost. That is this host at this moment,
		// never the module, and running again is what repairs it — which is exactly
		// what a reader must not have to guess from "database is locked".
		return "the analysis finished and its record could not be stored: another writer held the " +
				"store lock for the whole retry budget; running the stage again stores it" + suffix,
			failurecause.Environment, cgdomain.CallGraphStatusExtractionFailed
	case errors.Is(execErr, childproc.ErrStalled):
		return fmt.Sprintf("the analysis reported no progress for %s and was stopped%s",
				cgports.DefaultStallWindow, suffix),
			failurecause.Environment, cgdomain.CallGraphStatusExtractionFailed
	case errors.Is(execErr, childproc.ErrCeiling):
		return "the analysis was still working when the wall-clock ceiling was reached; " +
				raiseCeilingRemedy(walkID) + suffix,
			failurecause.Environment, cgdomain.CallGraphStatusExtractionFailed
	case errors.Is(execErr, context.Canceled):
		return "the run was cancelled before the analysis finished" + suffix,
			failurecause.Environment, cgdomain.CallGraphStatusCancelled
	case killedBySignal(execErr):
		// Neither deadline fired, so something outside this process ended the
		// subprocess — the operating system reclaiming memory in every case
		// observed. That is the host's memory, not the module's source: the same
		// module analysed on its own, or with fewer concurrent subprocesses, may
		// well produce a complete graph. --workers is not the control: it sizes
		// the module pool, and the concurrent analyses are bounded separately.
		//
		// This is where OutOfMemory is produced, and it is produced HERE — in the
		// parent, about a child — because a status the dying process has to write
		// is not a status. A process the kernel ends gets no chance to record
		// anything, so the only account of it that can exist is the one its
		// parent writes afterwards.
		return "the analysis was ended by the operating system before it finished, which is " +
				"usually memory: lower --callgraph-workers, or analyse this module on its own" + suffix,
			failurecause.Environment, cgdomain.CallGraphStatusOutOfMemory
	}

	if stderrStr != "" {
		return fmt.Sprintf("subprocess failed (%v): %s", execErr, stderrStr),
			failurecause.Unrecorded, cgdomain.CallGraphStatusExtractionFailed
	}
	return fmt.Sprintf("subprocess failed: %v", execErr),
		failurecause.Unrecorded, cgdomain.CallGraphStatusExtractionFailed
}

// killedBySignal reports whether a child was ended by a signal rather than by
// exiting. exec renders that as "signal: killed"; 137 is the shell's spelling of
// the same thing, and both reach this from different places.
func killedBySignal(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "signal: killed") || strings.Contains(msg, "exit status 137")
}

// raiseCeilingRemedy names the invocation that gives this module more time. The
// walk is named when the stage has one, because a reader copying the line should
// not have to go and find the id of the run they are already inside.
func raiseCeilingRemedy(walkID string) string {
	if walkID == "" {
		return "give it longer with --callgraph-timeout"
	}
	return fmt.Sprintf("give it longer with: kanonarion extract %s --stages callgraph --callgraph-timeout 4h", walkID)
}

// failureReason builds the diagnostic string surfaced via StageResult.Error
// for a non-zero stage status. Only failed stages get a non-empty reason —
// succeeded stages return "" so the JSON field is omitted.
//
// The string always contains the stage name and the underlying record's
// OverallStatus value (e.g. "LoadFailed", "ExtractionFailed") so callers can
// distinguish failure classes without parsing free-form text. The record's
// own FailureDetail is appended when present; when the record forgot to set
// one, the status alone is still actionable.
func failureReason(stage string, status domain.StageStatus, recordStatus, recordDetail string) string {
	if status != domain.StageFailed {
		return ""
	}
	if recordDetail != "" {
		return fmt.Sprintf("%s stage status=%s: %s", stage, recordStatus, recordDetail)
	}
	return fmt.Sprintf("%s stage status=%s (no failure detail recorded)", stage, recordStatus)
}
