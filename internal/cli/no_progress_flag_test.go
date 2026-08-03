package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/eitanity/kanonarion/internal/coordinate"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

// TestNoProgressFlag_RegisteredOnEveryProgressEmittingCommand is the shared-flag
// contract for --no-progress.
//
// The flag is not a property of `walk`; it is a property of narrating progress
// on stderr, and every command that does so must accept it. It did not: `walk`,
// `inspect` and `extract` had it while `vuln-scan`, `audit` and `sbom` — the
// commands whose output is longest and most often captured to a log — answered
// "unknown flag". Registering through registerNoProgressFlag is what keeps the
// name, default and help string identical; this test is what keeps the set of
// commands from silently shrinking again.
//
// The roster is a decision, not an inventory: a command earns an entry by
// emitting progress. `fetch` and `latest` are deliberately absent (see
// TestNoProgressFlag_AbsentFromCommandsThatEmitNoProgress), because a flag that
// accepts an instruction it cannot carry out is worse than no flag at all.
func TestNoProgressFlag_RegisteredOnEveryProgressEmittingCommand(t *testing.T) {
	commands := map[string]*cobra.Command{
		// Throttled stderr heartbeat.
		"walk":    newWalkCmd(io.Discard, io.Discard),
		"inspect": newInspectCmd(io.Discard, io.Discard),
		"extract": NewExtractCmd(io.Discard, io.Discard),
		"sbom":    newSBOMCmd(io.Discard, io.Discard),
		// Per-module progress lines, one per coordinate in the walk.
		"vuln-scan": newVulnScanCmd(io.Discard, io.Discard),
		// The same per-module stream, over every module in the walk: a re-scan
		// forces the lot, so it is the longest of them.
		"vuln-scan-rescan": newVulnScanRescanCmd(io.Discard, io.Discard),
		// Both: audit drives a walk and a scan beneath its own stage narration.
		"audit": newAuditCmd(io.Discard, io.Discard),
	}

	var usage string
	for name, cmd := range commands {
		flag := cmd.Flags().Lookup("no-progress")
		if flag == nil {
			t.Errorf("%s emits progress and must register --no-progress", name)
			continue
		}
		if flag.DefValue != "false" {
			t.Errorf("%s: --no-progress default = %q, want false", name, flag.DefValue)
		}
		if usage == "" {
			usage = flag.Usage
			continue
		}
		if flag.Usage != usage {
			t.Errorf("%s: --no-progress help drifted:\n got %q\nwant %q", name, flag.Usage, usage)
		}
	}
	if usage != noProgressUsage {
		t.Errorf("registered help = %q, want the shared constant %q", usage, noProgressUsage)
	}
}

// TestNoProgressFlag_AbsentFromCommandsThatEmitNoProgress states the other half
// of the decision. `fetch` narrates one preamble line and writes its result to
// stdout; `latest` writes only results and per-module errors. Neither runs a
// heartbeat or a per-module progress stream, so neither gets the flag: a
// registered --no-progress that suppresses nothing tells a caller their run was
// silenced when it never spoke.
func TestNoProgressFlag_AbsentFromCommandsThatEmitNoProgress(t *testing.T) {
	for name, cmd := range map[string]*cobra.Command{
		"fetch":  newFetchCmd(io.Discard, io.Discard),
		"latest": newLatestCmd(io.Discard, io.Discard),
	} {
		if flag := cmd.Flags().Lookup("no-progress"); flag != nil {
			t.Errorf("%s emits no progress; --no-progress there would be a dead flag", name)
		}
	}
}

// TestNoProgressFlag_AcceptedEndToEnd proves the registration parses rather than
// merely existing on a constructed command. The go.mod has an empty dependency
// scope, so audit returns before any walk: this exercises acceptance (not
// "unknown flag") without touching the network or a real store.
func TestNoProgressFlag_AcceptedEndToEnd(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(path, []byte("module example.com/app\n\ngo 1.24\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, cmd := range []string{"audit", "inspect"} {
		t.Run(cmd, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if err := Run([]string{cmd, "--gomod", path, "--no-progress"}, &stdout, &stderr); err != nil {
				t.Fatalf("%s --no-progress should be accepted, got: %v", cmd, err)
			}
		})
	}
}

// TestProgressWriter_SilencesNarrationOnly pins the semantics the flag promises:
// the narration goes to a sink, and every other stderr writer is untouched. The
// split is what lets a silenced run still report a failure.
func TestProgressWriter_SilencesNarrationOnly(t *testing.T) {
	var stderr bytes.Buffer
	if got := progressWriter(&stderr, false); got != io.Writer(&stderr) {
		t.Errorf("progressWriter(stderr, false) must be stderr itself, got %T", got)
	}

	silenced := progressWriter(&stderr, true)
	coord, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	writeVulnScanProgress(vuldomain.VulnerabilityRecord{OverallStatus: vuldomain.StatusClean}, coord, 1, 1, silenced)
	if stderr.Len() != 0 {
		t.Errorf("--no-progress must write no progress line, got: %q", stderr.String())
	}

	// The same line, unsilenced, is what the flag is suppressing.
	writeVulnScanProgress(vuldomain.VulnerabilityRecord{OverallStatus: vuldomain.StatusClean}, coord, 1, 1, &stderr)
	if !strings.Contains(stderr.String(), "example.com/mod@v1.0.0") {
		t.Errorf("progress line missing without the flag, got: %q", stderr.String())
	}
}
