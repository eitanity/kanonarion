package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// `inspect`, `walk`, and `context` each accept a positional module and
// a recursive `--gomod` form. A bare invocation (no positional module, no
// `--gomod`) must default `--gomod` to./go.mod — matching audit, directives,
// fips, godebug, vendor, and latest — instead of failing with a usage error.
//
// Each command has a pair of tests covering both branches of resolveGoModPath:
// default-found (./go.mod present) routes into the go.mod scan, and
// default-missing surfaces the resolveGoModPath diagnostic rather than the
// usageErr "invalid arguments" message.

// chdirWithGoMod creates a temp dir, optionally writes a./go.mod with the
// given content, chdir's into it, and restores the original cwd on cleanup.
func chdirWithGoMod(t *testing.T, gomod string) {
	t.Helper()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if gomod != "" {
		if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig) })
}

func TestInspectDefaultsToCwdGoMod(t *testing.T) {
	// A module with no Go files has an empty code scope, reported before any
	// store/network access — proving bare inspect reached the go.mod scan.
	chdirWithGoMod(t, "module example.com/app\n\ngo 1.21\n")
	var stdout, stderr bytes.Buffer
	if err := Run([]string{"inspect"}, &stdout, &stderr); err != nil {
		t.Fatalf("bare inspect should default --gomod to ./go.mod, got error: %v", err)
	}
	if !strings.Contains(stdout.String(), "no code dependencies found") {
		t.Errorf("expected go.mod scan output, got stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestInspectNoGoModIsNotUsageError(t *testing.T) {
	chdirWithGoMod(t, "")
	var stdout, stderr bytes.Buffer
	err := Run([]string{"inspect"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error when ./go.mod is absent")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected resolveGoModPath diagnostic, got: %v", err)
	}
	if strings.Contains(err.Error(), "invalid arguments") {
		t.Errorf("bare inspect must not fall through to a usage error, got: %v", err)
	}
}

func TestWalkDefaultsToCwdGoMod(t *testing.T) {
	// A dependency-free module keeps this hermetic: the default project
	// build-list walk derives `go list -m all` offline — just the main module.
	jsonOut = true
	t.Cleanup(func() { jsonOut = false })
	chdirWithGoMod(t, "module example.com/myapp\n\ngo 1.21\n")
	var stdout, stderr bytes.Buffer
	if err := Run([]string{"walk", "--json", "--store-root", t.TempDir()}, &stdout, &stderr); err != nil {
		t.Fatalf("bare walk should default --gomod to ./go.mod, got error: %v", err)
	}
	// The default is the project build-list walk: one record rooted at the local
	// main module (version=local), not the per-require path.
	if !strings.Contains(stdout.String(), "example.com/myapp") {
		t.Errorf("expected project walk rooted at the local module, got stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestWalkNoGoModIsNotUsageError(t *testing.T) {
	chdirWithGoMod(t, "")
	var stdout, stderr bytes.Buffer
	err := Run([]string{"walk", "--store-root", t.TempDir()}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error when ./go.mod is absent")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected resolveGoModPath diagnostic, got: %v", err)
	}
	if strings.Contains(err.Error(), "invalid arguments") {
		t.Errorf("bare walk must not fall through to a usage error, got: %v", err)
	}
}

func TestContextDefaultsToCwdGoMod(t *testing.T) {
	// A module with no Go files has an empty code scope, reported before any
	// store access; bare context and bare inspect resolve the same scope, so
	// they compose. This proves context defaulted --gomod to ./go.mod.
	chdirWithGoMod(t, "module example.com/myapp\n\ngo 1.21\n")
	var stdout, stderr bytes.Buffer
	if err := Run([]string{"context", "--store-root", t.TempDir()}, &stdout, &stderr); err != nil {
		t.Fatalf("bare context should default --gomod to ./go.mod, got error: %v", err)
	}
	if !strings.Contains(stdout.String(), "no code dependencies found") {
		t.Errorf("expected go.mod context output, got stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestContextNoGoModIsNotUsageError(t *testing.T) {
	chdirWithGoMod(t, "")
	var stdout, stderr bytes.Buffer
	err := Run([]string{"context", "--store-root", t.TempDir()}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error when ./go.mod is absent")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected resolveGoModPath diagnostic, got: %v", err)
	}
	if strings.Contains(err.Error(), "invalid arguments") {
		t.Errorf("bare context must not fall through to a usage error, got: %v", err)
	}
}

func TestVulnScanNoGoModIsNotUsageError(t *testing.T) {
	chdirWithGoMod(t, "")
	var stdout, stderr bytes.Buffer
	err := Run([]string{"vuln-scan", "--store-root", t.TempDir()}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error when ./go.mod is absent")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected resolveGoModPath diagnostic, got: %v", err)
	}
	if strings.Contains(err.Error(), "provide either") {
		t.Errorf("bare vuln-scan must not refuse with the alternatives list, got: %v", err)
	}
}

func TestVulnScanDefaultsToCwdGoMod(t *testing.T) {
	// A dependency-free module keeps this hermetic: the go.mod path resolves,
	// the project walk is looked up, and no walk exists in a fresh store — the
	// diagnostic proves the scan reached the go.mod scope path rather than the
	// usage refusal.
	chdirWithGoMod(t, "module example.com/mod\n\ngo 1.21\n")
	var stdout, stderr bytes.Buffer
	err := Run([]string{"vuln-scan", "--store-root", t.TempDir()}, &stdout, &stderr)
	if err == nil {
		t.Fatalf("expected a no-walk diagnostic, got stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if strings.Contains(err.Error(), "provide either") {
		t.Fatalf("bare vuln-scan should default --gomod to ./go.mod, got: %v", err)
	}
	if !strings.Contains(err.Error(), "walk") {
		t.Errorf("expected a project-walk diagnostic from the go.mod scope path, got: %v", err)
	}
}

// TestGoModFlagDefaultsAreStated is the grammar check over every command that
// registers --gomod: a usage string that advertises a default must name the
// path the shared resolver actually uses. resolveGoModPath stats ./go.mod in
// the current directory and does not search upward, so no help text may say it
// does.
func TestGoModFlagDefaultsAreStated(t *testing.T) {
	root := newRootCmd(io.Discard, io.Discard)
	var walk func(c *cobra.Command)
	seen := 0
	walk = func(c *cobra.Command) {
		if fl := c.Flags().Lookup("gomod"); fl != nil {
			seen++
			usage := fl.Usage
			if strings.Contains(usage, "upward") {
				t.Errorf("%s --gomod: no command searches upward for go.mod; usage says %q", c.Name(), usage)
			}
			if strings.Contains(usage, "default") && !strings.Contains(usage, "./go.mod") {
				t.Errorf("%s --gomod: usage advertises a default that is not ./go.mod: %q", c.Name(), usage)
			}
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(root)
	if seen == 0 {
		t.Fatal("no command registered --gomod; the grammar check measured nothing")
	}
}
