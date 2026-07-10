package cli

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	walkapp "github.com/eitanity/kanonarion/internal/walk/application"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// TestStdlibFromGoModFlag_RegisteredOnAllProjectCommands guards the parity the
// KN-399 refactor introduced: walk, sbom, audit, and inspect all drive a
// project walk that injects the synthetic stdlib node, so every one of them must
// expose --stdlib-from-gomod, defaulting to false, with an identical help
// string. Sharing registerStdlibFromGoModFlag is what keeps them from drifting;
// this test fails if any command drops the flag or hand-rolls a divergent copy.
func TestStdlibFromGoModFlag_RegisteredOnAllProjectCommands(t *testing.T) {
	commands := map[string]*cobra.Command{
		"walk":    newWalkCmd(io.Discard, io.Discard),
		"sbom":    newSBOMCmd(io.Discard, io.Discard),
		"audit":   newAuditCmd(io.Discard, io.Discard),
		"inspect": newInspectCmd(io.Discard, io.Discard),
	}

	var usage string
	for name, cmd := range commands {
		flag := cmd.Flags().Lookup("stdlib-from-gomod")
		if flag == nil {
			t.Errorf("%s must register --stdlib-from-gomod", name)
			continue
		}
		if flag.DefValue != "false" {
			t.Errorf("%s: --stdlib-from-gomod default = %q, want false", name, flag.DefValue)
		}
		if usage == "" {
			usage = flag.Usage
		} else if flag.Usage != usage {
			t.Errorf("%s: --stdlib-from-gomod help drifted:\n got %q\nwant %q", name, flag.Usage, usage)
		}
	}
}

// TestStdlibFromGoModFlag_AcceptedByGoModCommands confirms the flag parses
// end-to-end on the go.mod commands with an empty-scope module: the scope
// resolves to zero dependencies and the command returns before any walk, so
// this exercises flag acceptance (not "unknown flag") without a network fetch.
func TestStdlibFromGoModFlag_AcceptedByGoModCommands(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(path, []byte("module example.com/app\n\ngo 1.24\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, cmd := range []string{"audit", "inspect"} {
		t.Run(cmd, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if err := Run([]string{cmd, "--gomod", path, "--stdlib-from-gomod"}, &stdout, &stderr); err != nil {
				t.Fatalf("%s --stdlib-from-gomod should be accepted, got: %v", cmd, err)
			}
			if !strings.Contains(stdout.String(), "dependencies found") {
				t.Errorf("expected empty-scope message, got: %q", stdout.String())
			}
		})
	}
}

// TestRunWalkProject_ThreadsStdlibFromGoMod proves the flag is not merely
// registered but actually reaches the walk request. All four go.mod commands
// funnel through runWalkProject's stdlibFromGoMod positional, so asserting it
// lands in WalkRequest.StdlibFromGoMod covers the shared plumbing once.
func TestRunWalkProject_ThreadsStdlibFromGoMod(t *testing.T) {
	dir := t.TempDir()
	gomodPath := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(gomodPath, []byte("module example.com/app\n\ngo 1.24\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, want := range []bool{true, false} {
		t.Run(map[bool]string{true: "enabled", false: "disabled"}[want], func(t *testing.T) {
			uc := &testfakes.FakeExecuteWalk{Result: walkapp.ExecuteWalkResult{
				Record: walkdomain.WalkRecord{ID: "W1", OverallStatus: walkdomain.WalkSucceeded},
			}}
			progress := newWalkProgressReporter(io.Discard, true, activeConfig, logLevel)
			// scopeComplete keeps the whole build list, so runWalkProject skips
			// the Go-toolchain scope resolution and stays hermetic.
			err := runWalkProject(context.Background(), gomodPath, commonWalkFlags{}, false, true, 0, "", "", false,
				scopeComplete, walkdomain.WalkDepthFull, "", false, want, progress, uc, io.Discard, io.Discard)
			if err != nil {
				t.Fatalf("runWalkProject: %v", err)
			}
			if uc.LastRequest.StdlibFromGoMod != want {
				t.Errorf("WalkRequest.StdlibFromGoMod = %v, want %v", uc.LastRequest.StdlibFromGoMod, want)
			}
		})
	}
}
