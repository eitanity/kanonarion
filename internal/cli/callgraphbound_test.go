package cli

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/spf13/cobra"

	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
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
