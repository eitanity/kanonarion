package cli

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	walkapp "github.com/eitanity/kanonarion/internal/walk/application"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// The pairs below were each measured emitting byte-identical output with and
// without the flag, at exit 0: the caller's question was discarded and nothing
// in the answer said so. Each is now either honoured or refused by name, and
// each test states which.

// TestContextCoordinateRefusesGoModScopeFlags: --tool and --project select a
// projection of a go.mod build list. A module coordinate names its own module
// and has no build list to project, so the flags are refused rather than
// parsed and dropped.
func TestContextCoordinateRefusesGoModScopeFlags(t *testing.T) {
	for _, flag := range []string{"--tool", "--project"} {
		t.Run(flag, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			err := Run([]string{"context", "golang.org/x/mod@v0.35.0", flag, "--store-root", t.TempDir()}, &stdout, &stderr)
			if err == nil {
				t.Fatalf("context <coordinate> %s must be refused, got exit 0", flag)
			}
			if !strings.Contains(err.Error(), "context <module>@<version> does not act on "+flag) {
				t.Errorf("refusal must name the path and the flag, got: %v", err)
			}
			if stdout.Len() != 0 {
				t.Errorf("a refused invocation must write no document, got %d bytes", stdout.Len())
			}
		})
	}
}

// TestContextLocalRefusesGoModScopeFlags: a local working tree is analysed as
// itself, not as a projection of a go.mod scope.
func TestContextLocalRefusesGoModScopeFlags(t *testing.T) {
	for _, flag := range []string{"--tool", "--project"} {
		t.Run(flag, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			err := Run([]string{"context", ".", flag, "--store-root", t.TempDir()}, &stdout, &stderr)
			if err == nil {
				t.Fatalf("context <local path> %s must be refused, got exit 0", flag)
			}
			if !strings.Contains(err.Error(), "context <local path> does not act on "+flag) {
				t.Errorf("refusal must name the path and the flag, got: %v", err)
			}
		})
	}
}

// TestContextRefusesExcludeTestsOffTheLocalPath: --exclude-tests narrows a
// working tree's dependency list to the code its production files reach, and a
// go.mod scope's resolution to the packages production code imports. The other
// two forms name a module set that was fixed elsewhere — a coordinate names
// itself, a walk id names a stored record — so there is nothing there for the
// flag to narrow and it is refused by name rather than parsed and dropped.
//
// context --gomod is deliberately absent: it honours the flag. See
// TestContextGoMod_ExcludeTestsChangesTheStatedScope.
func TestContextRefusesExcludeTestsOffTheLocalPath(t *testing.T) {
	cases := map[string][]string{
		"context <module>@<version>": {"context", "golang.org/x/mod@v0.35.0"},
		"context --walk-id":          {"context", "--walk-id", "nosuchwalk"},
	}
	for path, argv := range cases {
		t.Run(path, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			args := append(append([]string{}, argv...), "--exclude-tests", "--store-root", t.TempDir())
			err := Run(args, &stdout, &stderr)
			if err == nil {
				t.Fatalf("%s --exclude-tests must be refused, got exit 0", path)
			}
			if !strings.Contains(err.Error(), path+" does not act on --exclude-tests") {
				t.Errorf("refusal must name the path and the flag, got: %v", err)
			}
			if stdout.Len() != 0 {
				t.Errorf("a refused invocation must write no document, got %d bytes", stdout.Len())
			}
		})
	}
}

// TestContextWalkIDRefusesGoModScopeFlags: a walk id names the module set
// already; there is no go.mod scope left to select.
func TestContextWalkIDRefusesGoModScopeFlags(t *testing.T) {
	for _, flag := range []string{"--tool", "--project"} {
		t.Run(flag, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			err := Run([]string{"context", "--walk-id", "01ABC", flag, "--store-root", t.TempDir()}, &stdout, &stderr)
			if err == nil {
				t.Fatalf("context --walk-id %s must be refused, got exit 0", flag)
			}
			if !strings.Contains(err.Error(), "context --walk-id does not act on "+flag) {
				t.Errorf("refusal must name the path and the flag, got: %v", err)
			}
		})
	}
}

// TestContextGoModHonoursStream: --stream selects NDJSON without --json on the
// --gomod path, the same meaning it already carries on --walk-id. The empty
// scope is the cheapest place to see the difference: an NDJSON stream spells
// "nothing matched" as zero bytes, the text path as prose.
func TestContextGoModHonoursStream(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(path, []byte("module example.com/app\n\ngo 1.24\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Control: without --stream the same invocation prints prose. A stream test
	// whose control is also empty proves nothing.
	var plain, stderr bytes.Buffer
	if err := Run([]string{"context", "--gomod", path, "--store-root", t.TempDir()}, &plain, &stderr); err != nil {
		t.Fatalf("context --gomod: %v", err)
	}
	if !strings.Contains(plain.String(), "dependencies found") {
		t.Fatalf("control must print the text-path prose, got %q", plain.String())
	}

	var streamed bytes.Buffer
	stderr.Reset()
	if err := Run([]string{"context", "--gomod", path, "--stream", "--store-root", t.TempDir()}, &streamed, &stderr); err != nil {
		t.Fatalf("context --gomod --stream: %v", err)
	}
	if streamed.Len() != 0 {
		t.Errorf("--stream must select the NDJSON stream (empty for an empty scope), got %q", streamed.String())
	}
}

// TestWalkModuleRefusesProjectOnlyFlags: a walk of a published coordinate has
// no project go.mod behind it, so it can read neither a toolchain directive nor
// a local-replace base.
func TestWalkModuleRefusesProjectOnlyFlags(t *testing.T) {
	for flag, field := range map[string]func(*walkFlags){
		"--stdlib-from-gomod": func(f *walkFlags) { f.stdlibFromGoMod = true },
		"--analyse-local":     func(f *walkFlags) { f.analyseLocal = true },
	} {
		t.Run(flag, func(t *testing.T) {
			uc := &testfakes.FakeExecuteWalk{Result: walkapp.ExecuteWalkResult{
				Record: walkdomain.WalkRecord{ID: "W1", OverallStatus: walkdomain.WalkSucceeded},
			}}
			var f walkFlags
			field(&f)
			progress := newWalkProgressReporter(io.Discard, true, activeConfig, logLevel)
			err := runWalkCmdModule(context.Background(), "example.com/mod@v1.0.0", f, progress, uc, nil, io.Discard, io.Discard)
			if err == nil {
				t.Fatalf("walk <module@version> %s must be refused, got exit 0", flag)
			}
			if !strings.Contains(err.Error(), "walk <module@version> does not act on "+flag) {
				t.Errorf("refusal must name the path and the flag, got: %v", err)
			}
			if uc.Calls != 0 {
				t.Errorf("a refused invocation must not execute a walk, got %d", uc.Calls)
			}

			// Control: the same walk without the flag runs.
			if err := runWalkCmdModule(context.Background(), "example.com/mod@v1.0.0", walkFlags{}, progress, uc, nil, io.Discard, io.Discard); err != nil {
				t.Fatalf("walk without %s must still run: %v", flag, err)
			}
		})
	}
}

// TestWalkHonoursOperatorOnBothPaths: operator is provenance any walk can
// carry. It reached the walk request from neither path before — the project
// path took it as an argument and discarded it, the positional path was never
// handed it — so both are asserted here.
func TestWalkHonoursOperatorOnBothPaths(t *testing.T) {
	dir := t.TempDir()
	gomodPath := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(gomodPath, []byte("module example.com/app\n\ngo 1.24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	progress := newWalkProgressReporter(io.Discard, true, activeConfig, logLevel)

	t.Run("positional", func(t *testing.T) {
		uc := &testfakes.FakeExecuteWalk{Result: walkapp.ExecuteWalkResult{
			Record: walkdomain.WalkRecord{ID: "W1", OverallStatus: walkdomain.WalkSucceeded},
		}}
		f := walkFlags{operator: "auditor-7"}
		if err := runWalkCmdModule(context.Background(), "example.com/mod@v1.0.0", f, progress, uc, nil, io.Discard, io.Discard); err != nil {
			t.Fatalf("runWalkCmdModule: %v", err)
		}
		if uc.LastRequest.Operator != "auditor-7" {
			t.Errorf("WalkRequest.Operator = %q, want %q", uc.LastRequest.Operator, "auditor-7")
		}
	})

	t.Run("project", func(t *testing.T) {
		uc := &testfakes.FakeExecuteWalk{Result: walkapp.ExecuteWalkResult{
			Record: walkdomain.WalkRecord{ID: "W1", OverallStatus: walkdomain.WalkSucceeded},
		}}
		// --project keeps the whole build list, so the walk stays hermetic:
		// no Go-toolchain scope resolution runs.
		f := walkFlags{operator: "auditor-7", gomodPath: gomodPath, project: true}
		if err := runWalkCmdProject(context.Background(), f, progress, uc, nil, io.Discard, io.Discard); err != nil {
			t.Fatalf("runWalkCmdProject: %v", err)
		}
		if uc.LastRequest.Operator != "auditor-7" {
			t.Errorf("WalkRequest.Operator = %q, want %q", uc.LastRequest.Operator, "auditor-7")
		}
	})

	t.Run("unset stays empty", func(t *testing.T) {
		uc := &testfakes.FakeExecuteWalk{Result: walkapp.ExecuteWalkResult{
			Record: walkdomain.WalkRecord{ID: "W1", OverallStatus: walkdomain.WalkSucceeded},
		}}
		if err := runWalkCmdModule(context.Background(), "example.com/mod@v1.0.0", walkFlags{}, progress, uc, nil, io.Discard, io.Discard); err != nil {
			t.Fatalf("runWalkCmdModule: %v", err)
		}
		if uc.LastRequest.Operator != "" {
			t.Errorf("WalkRequest.Operator = %q, want empty so the use case's own operator stands", uc.LastRequest.Operator)
		}
	})
}

// TestSBOMWalkIDRefusesStdlibFromGoMod: --stdlib-from-gomod shapes the project
// walk sbom builds when it has none. Given a walk id, the walk exists and its
// stdlib node is already pinned, so the flag has nothing left to shape.
//
// This pair sits below the flag-reach guard, which works at function
// granularity: both branches live inside sbomGenerateWith. This test is what
// holds it closed.
func TestSBOMWalkIDRefusesStdlibFromGoMod(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Run([]string{"sbom", "01KQDBVW092ER1HNXZ60X27CMD", "--stdlib-from-gomod", "--store-root", t.TempDir()}, &stdout, &stderr)
	if err == nil {
		t.Fatal("sbom <walk-id> --stdlib-from-gomod must be refused, got exit 0")
	}
	if !strings.Contains(err.Error(), "sbom <walk-id> does not act on --stdlib-from-gomod") {
		t.Errorf("refusal must name the path and the flag, got: %v", err)
	}
	if stdout.Len() != 0 {
		t.Errorf("a refused invocation must write no document, got %d bytes", stdout.Len())
	}

	// Control: the same walk id without the flag gets past flag scoping and
	// fails on the absent walk instead.
	var cstdout, cstderr bytes.Buffer
	cerr := Run([]string{"sbom", "01KQDBVW092ER1HNXZ60X27CMD", "--store-root", t.TempDir()}, &cstdout, &cstderr)
	if cerr == nil || strings.Contains(cerr.Error(), "does not act on") {
		t.Errorf("control must reach the store, got: %v", cerr)
	}
}

// TestVulnScanModuleRefusesWalkOnlyFlags and its scope sibling cover the same
// defect shape found beside the seven: --binary-pre-pass reached the scan
// request from the walk-id path alone, and --no-vendor names a project tree a
// module-rooted walk does not have.
func TestVulnScanRefusesFlagsItNeverPassedOn(t *testing.T) {
	dir := t.TempDir()
	gomodPath := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(gomodPath, []byte("module example.com/app\n\ngo 1.24\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{
			name: "module with binary pre-pass",
			args: []string{"vuln-scan", "--module", "example.com/mod@v1.0.0", "--binary-pre-pass"},
			want: "vuln-scan --module does not act on --binary-pre-pass",
		},
		{
			name: "module with no-vendor",
			args: []string{"vuln-scan", "--module", "example.com/mod@v1.0.0", "--no-vendor"},
			want: "vuln-scan --module does not act on --no-vendor",
		},
		{
			name: "gomod scope with binary pre-pass",
			args: []string{"vuln-scan", "--gomod", gomodPath, "--binary-pre-pass"},
			want: "vuln-scan --gomod/--tool/--project does not act on --binary-pre-pass",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			err := Run(append(tc.args, "--store-root", t.TempDir()), &stdout, &stderr)
			if err == nil {
				t.Fatalf("%v must be refused, got exit 0", tc.args)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("refusal must name the path and the flag, got: %v", err)
			}
		})
	}
}

// TestFetchPositionalRefusesGoModScopeFlags: a positional fetch names its own
// module, so a go.mod scope has nothing to select. The scope loop reaches the
// same fetch through fetchOne, where the flags have already been acted on.
func TestFetchPositionalRefusesGoModScopeFlags(t *testing.T) {
	for _, flag := range []string{"--tool", "--project"} {
		t.Run(flag, func(t *testing.T) {
			err := runFetch(context.Background(), "example.com/mod@v1.0.0",
				fetchFlags{tool: flag == "--tool", project: flag == "--project"}, io.Discard, io.Discard)
			if err == nil {
				t.Fatalf("fetch <module> %s must be refused, got exit 0", flag)
			}
			if !strings.Contains(err.Error(), "fetch <module>[@<version>] does not act on "+flag) {
				t.Errorf("refusal must name the path and the flag, got: %v", err)
			}
		})
	}
}
