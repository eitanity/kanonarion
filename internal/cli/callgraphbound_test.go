package cli

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	extextractor "github.com/eitanity/kanonarion/internal/extract/adapters/extractor/local"
)

// TestCallgraphTimeoutFlag_OnEveryCommandThatSpawnsAChild is the shared-flag
// contract for --callgraph-timeout.
//
// The roster is the set of commands that can spawn a call-graph subprocess, and
// it is a decision rather than an inventory: before the flag existed there was
// none at all, so a module needing more than a hardcoded ten minutes could not
// be analysed on any host however much time the operator was willing to give it.
// A command that cannot spawn one does not get the flag — an instruction it
// cannot carry out is worse than its absence.
func TestCallgraphTimeoutFlag_OnEveryCommandThatSpawnsAChild(t *testing.T) {
	commands := map[string]*cobra.Command{
		// Runs the callgraph stage in a child per module.
		"extract": NewExtractCmd(io.Discard, io.Discard),
		// Runs that stage, and then a scan that spawns children of its own.
		"inspect": newInspectCmd(io.Discard, io.Discard),
		// --reachability spawns a child for any module with no usable graph.
		"vuln-scan":        newVulnScanCmd(io.Discard, io.Discard),
		"vuln-scan-rescan": newVulnScanRescanCmd(io.Discard, io.Discard),
	}

	var usage string
	for name, cmd := range commands {
		flag := cmd.Flags().Lookup("callgraph-timeout")
		if flag == nil {
			t.Errorf("%s spawns a call-graph child and must register --callgraph-timeout", name)
			continue
		}
		if flag.DefValue != cgports.DefaultCeiling.String() {
			t.Errorf("%s: --callgraph-timeout default = %q, want %q", name, flag.DefValue, cgports.DefaultCeiling)
		}
		if usage == "" {
			usage = flag.Usage
			continue
		}
		if flag.Usage != usage {
			t.Errorf("%s: --callgraph-timeout help drifted:\n got %q\nwant %q", name, flag.Usage, usage)
		}
	}
	if usage != callgraphTimeoutUsage {
		t.Errorf("registered help = %q, want the shared constant %q", usage, callgraphTimeoutUsage)
	}
}

// TestCallgraphTimeoutFlag_AbsentWhereNoChildIsSpawned states the other half.
// `callgraph` IS the analysis rather than a spawner of one, and `walk` runs no
// stage at all; a ceiling on either would accept an instruction neither can obey.
func TestCallgraphTimeoutFlag_AbsentWhereNoChildIsSpawned(t *testing.T) {
	for name, cmd := range map[string]*cobra.Command{
		"callgraph": newCallGraphCmd(io.Discard, io.Discard),
		"walk":      newWalkCmd(io.Discard, io.Discard),
	} {
		if flag := cmd.Flags().Lookup("callgraph-timeout"); flag != nil {
			t.Errorf("%s spawns no call-graph child; --callgraph-timeout there would be a dead flag", name)
		}
	}
}

// TestCallgraphWorkersFlag_OnTheCommandWhoseStageSpawnsThem is the other half
// of the subprocess bound: the extraction stage runs one child per module, and
// the module pool cannot bound them without also slowing the cheap in-process
// stages, so the bound is its own flag.
func TestCallgraphWorkersFlag_OnTheCommandWhoseStageSpawnsThem(t *testing.T) {
	commands := map[string]*cobra.Command{
		// Runs the callgraph stage in a subprocess per module.
		"extract": NewExtractCmd(io.Discard, io.Discard),
		// Runs that stage over a whole walk as one step, and prints the remedy
		// that names this flag when a subprocess is ended for memory.
		"inspect": newInspectCmd(io.Discard, io.Discard),
	}
	for name, cmd := range commands {
		flag := cmd.Flags().Lookup("callgraph-workers")
		if flag == nil {
			t.Errorf("%s runs the callgraph stage and must register --callgraph-workers", name)
			continue
		}
		if flag.DefValue != "0" {
			t.Errorf("%s: --callgraph-workers default = %q, want %q so the bound is sized from the host", name, flag.DefValue, "0")
		}
		if flag.Usage != callgraphWorkersUsage {
			t.Errorf("%s: registered help = %q, want the shared constant %q", name, flag.Usage, callgraphWorkersUsage)
		}
	}
	// An operator raising the bound is buying memory with it, so the help has to
	// say so where they read it, not only in the docs.
	for _, want := range []string{"memory", "SSA", "at once"} {
		if !strings.Contains(callgraphWorkersUsage, want) {
			t.Errorf("--callgraph-workers help does not mention %q: %s", want, callgraphWorkersUsage)
		}
	}
	if !strings.Contains(callgraphWorkersUsage, fmt.Sprintf("%d GiB", extextractor.CallgraphBudgetBytes>>30)) {
		t.Errorf("--callgraph-workers help does not carry the per-subprocess budget: %s", callgraphWorkersUsage)
	}
}

// The bound belongs to the extraction stage. `walk` runs no stage, `callgraph`
// IS the analysis, and `vuln-scan` bounds a different pool under a flag it
// already owns — a second spelling of either would be a knob that changes
// nothing.
func TestCallgraphWorkersFlag_AbsentWhereTheExtractionStageIsNotRun(t *testing.T) {
	for name, cmd := range map[string]*cobra.Command{
		"callgraph": newCallGraphCmd(io.Discard, io.Discard),
		"walk":      newWalkCmd(io.Discard, io.Discard),
	} {
		if flag := cmd.Flags().Lookup("callgraph-workers"); flag != nil {
			t.Errorf("%s runs no extraction stage; --callgraph-workers there would be a dead flag", name)
		}
	}
}

// An invocation passed no flag must not inherit the last one's bound.
func TestCallgraphWorkers_ResetsWithTheRestOfTheInvocationState(t *testing.T) {
	callgraphWorkers = 9
	resetInvocationState()
	if callgraphWorkers != 0 {
		t.Errorf("callgraphWorkers = %d after a reset, want 0", callgraphWorkers)
	}
}

// TestThrottledLines_PassesOneLinePerInterval pins the narration's shape. A
// hundred and seventy modules each reporting a dozen phases is a firehose; total
// silence is the defect being repaired. One line per interval is the middle, and
// the interval is the one every other narration in this tool already uses.
func TestThrottledLines_PassesOneLinePerInterval(t *testing.T) {
	var out bytes.Buffer
	now := time.Unix(0, 0)
	w := newThrottledLines(&out, 20*time.Second, func() time.Time { return now })

	write := func(s string) {
		n, err := w.Write([]byte(s))
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
		if n != len(s) {
			t.Fatalf("Write reported %d of %d bytes; a short count reads as an I/O failure "+
				"on the child's stderr copy", n, len(s))
		}
	}

	write("first\n")
	write("dropped\n")
	now = now.Add(19 * time.Second)
	write("still dropped\n")
	now = now.Add(2 * time.Second)
	write("second\n")

	if got, want := out.String(), "first\nsecond\n"; got != want {
		t.Errorf("throttled output = %q, want %q", got, want)
	}
}

// TestCallgraphNarrationFor_SilencedBySuppression pins that the PARENT's copy
// obeys the operator, and that the child's does not depend on it: a config file
// must not be able to turn off the stall detector, so the parent's gate is here
// and the child is told to narrate on its command line.
func TestCallgraphNarrationFor_SilencedBySuppression(t *testing.T) {
	var out bytes.Buffer
	if w := callgraphNarrationFor(&out, true, true); w != nil {
		t.Error("--no-progress must silence the parent's copy of its children's lines")
	}
	if w := callgraphNarrationFor(&out, false, false); w != nil {
		t.Error("preferences.progress=false must silence the parent's copy")
	}
	if w := callgraphNarrationFor(&out, false, true); w == nil {
		t.Error("an unsuppressed run must narrate what its children report")
	}
}
