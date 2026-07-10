package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// TestStoreIsolation_NotProductionUnderTest guards the package-cli
// test binary (TestMain) must route store-root resolution away from the
// developer's real ~/.kanonarion, so in-process Run calls that omit
// --store-root cannot pollute the production store with fixture walks.
func TestStoreIsolation_NotProductionUnderTest(t *testing.T) {
	env := os.Getenv("KANONARION_STORE")
	if env == "" {
		t.Fatal("TestMain did not set KANONARION_STORE; tests can reach ~/.kanonarion")
	}
	if home, err := os.UserHomeDir(); err == nil {
		if prod := filepath.Join(home, ".kanonarion"); env == prod {
			t.Fatalf("KANONARION_STORE points at production store %q", prod)
		}
	}
}

func TestParseModuleArg(t *testing.T) {
	tests := []struct {
		input       string
		wantPath    string
		wantVersion string
		wantErrMsg  string
	}{
		{"golang.org/x/mod@v0.35.0", "golang.org/x/mod", "v0.35.0", ""},
		{"golang.org/x/mod@latest", "golang.org/x/mod", "latest", ""},
		{"golang.org/x/mod", "golang.org/x/mod", "", ""},
		{"", "", "", "module path must not be empty"},
		{"@v1.0.0", "", "", "module path must not be empty"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			path, version, err := parseModuleArg(tt.input)
			if tt.wantErrMsg != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErrMsg)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if path != tt.wantPath {
				t.Errorf("path: got %q, want %q", path, tt.wantPath)
			}
			if version != tt.wantVersion {
				t.Errorf("version: got %q, want %q", version, tt.wantVersion)
			}
		})
	}
}

func TestReadGoModModules_Basic(t *testing.T) {
	content := `module example.com/myapp

go 1.21

require (
	github.com/spf13/cobra v1.8.1
	github.com/spf13/pflag v1.0.5 // indirect
)
`
	dir := t.TempDir()
	path := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	coords, err := readGoModModules(path)
	if err != nil {
		t.Fatalf("readGoModModules: %v", err)
	}
	if len(coords) != 2 {
		t.Fatalf("expected 2 coords, got %d: %v", len(coords), coords)
	}

	want := map[string]bool{
		"github.com/spf13/cobra@v1.8.1": true,
		"github.com/spf13/pflag@v1.0.5": true,
	}
	for _, c := range coords {
		if !want[c] {
			t.Errorf("unexpected coord %q", c)
		}
	}
}

func TestReadGoModModules_NoRequires(t *testing.T) {
	content := `module example.com/myapp

go 1.21
`
	dir := t.TempDir()
	path := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	coords, err := readGoModModules(path)
	if err != nil {
		t.Fatalf("readGoModModules: %v", err)
	}
	if len(coords) != 0 {
		t.Errorf("expected 0 coords, got %d: %v", len(coords), coords)
	}
}

func TestReadGoModModules_FileNotFound(t *testing.T) {
	_, err := readGoModModules("/nonexistent/path/go.mod")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestReadGoModModules_InvalidGoMod(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(path, []byte("this is not valid go.mod content %%%"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := readGoModModules(path)
	if err == nil {
		t.Fatal("expected error for invalid go.mod, got nil")
	}
}

func TestReadGoModModules_IncludesIndirect(t *testing.T) {
	content := `module example.com/myapp

go 1.21

require (
	github.com/direct/dep v1.0.0
	github.com/indirect/dep v1.2.0 // indirect
)
`
	dir := t.TempDir()
	path := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	coords, err := readGoModModules(path)
	if err != nil {
		t.Fatalf("readGoModModules: %v", err)
	}
	// Both direct and indirect deps should be included.
	if len(coords) != 2 {
		t.Errorf("expected 2 coords (direct + indirect), got %d: %v", len(coords), coords)
	}
}

func TestReadGoModToolModules_Basic(t *testing.T) {
	content := `module example.com/myapp

go 1.24

require (
	golang.org/x/tools v0.30.0
	github.com/golangci/golangci-lint v1.64.0
	github.com/foo/dep v1.5.0
)

tool (
	golang.org/x/tools/cmd/stringer
	github.com/golangci/golangci-lint/cmd/golangci-lint
)
`
	dir := t.TempDir()
	path := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	coords, err := readGoModToolModules(path)
	if err != nil {
		t.Fatalf("readGoModToolModules: %v", err)
	}
	if len(coords) != 2 {
		t.Fatalf("expected 2 coords, got %d: %v", len(coords), coords)
	}
	wantCoords := map[string]bool{
		"golang.org/x/tools@v0.30.0":                true,
		"github.com/golangci/golangci-lint@v1.64.0": true,
	}
	for _, c := range coords {
		if !wantCoords[c] {
			t.Errorf("unexpected coord %q", c)
		}
	}
}

func TestReadGoModToolModules_DeduplicatesSameModule(t *testing.T) {
	content := `module example.com/myapp

go 1.24

require golang.org/x/tools v0.30.0

tool (
	golang.org/x/tools/cmd/stringer
	golang.org/x/tools/cmd/goimports
)
`
	dir := t.TempDir()
	path := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	coords, err := readGoModToolModules(path)
	if err != nil {
		t.Fatalf("readGoModToolModules: %v", err)
	}
	if len(coords) != 1 {
		t.Errorf("expected 1 coord (deduped), got %d: %v", len(coords), coords)
	}
	if len(coords) == 1 && coords[0] != "golang.org/x/tools@v0.30.0" {
		t.Errorf("coord = %q, want golang.org/x/tools@v0.30.0", coords[0])
	}
}

func TestReadGoModToolModules_NoTools(t *testing.T) {
	content := `module example.com/myapp

go 1.21

require github.com/foo/bar v1.2.3
`
	dir := t.TempDir()
	path := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	coords, err := readGoModToolModules(path)
	if err != nil {
		t.Fatalf("readGoModToolModules: %v", err)
	}
	if len(coords) != 0 {
		t.Errorf("expected 0 coords for no tool directives, got %d", len(coords))
	}
}

func TestReadGoModToolModules_WorkspaceFallback(t *testing.T) {
	// Workspace layout:
	// root/
	// go.work (use./app use./lib)
	// app/go.mod (tool golang.org/x/tools/cmd/stringer, no require for it)
	// lib/go.mod (require golang.org/x/tools v0.31.0)
	root := t.TempDir()

	// lib/go.mod — holds the require that resolves the tool
	libDir := filepath.Join(root, "lib")
	if err := os.MkdirAll(libDir, 0o700); err != nil {
		t.Fatal(err)
	}
	libGomod := "module example.com/lib\n\ngo 1.24\n\nrequire golang.org/x/tools v0.31.0\n"
	if err := os.WriteFile(filepath.Join(libDir, "go.mod"), []byte(libGomod), 0o600); err != nil {
		t.Fatal(err)
	}

	// app/go.mod — declares the tool but has no require for its module
	appDir := filepath.Join(root, "app")
	if err := os.MkdirAll(appDir, 0o700); err != nil {
		t.Fatal(err)
	}
	appGomod := "module example.com/app\n\ngo 1.24\n\ntool golang.org/x/tools/cmd/stringer\n"
	appGomodPath := filepath.Join(appDir, "go.mod")
	if err := os.WriteFile(appGomodPath, []byte(appGomod), 0o600); err != nil {
		t.Fatal(err)
	}

	// go.work — ties them together
	gowork := "go 1.24\n\nuse ./app\nuse ./lib\n"
	if err := os.WriteFile(filepath.Join(root, "go.work"), []byte(gowork), 0o600); err != nil {
		t.Fatal(err)
	}

	coords, err := readGoModToolModules(appGomodPath)
	if err != nil {
		t.Fatalf("readGoModToolModules: %v", err)
	}
	if len(coords) != 1 || coords[0] != "golang.org/x/tools@v0.31.0" {
		t.Errorf("got %v, want [golang.org/x/tools@v0.31.0]", coords)
	}
}

func TestReadGoModToolModules_WorkspaceNotFound(t *testing.T) {
	// go.work present but none of the use-listed modules have the tool's require.
	root := t.TempDir()

	otherDir := filepath.Join(root, "other")
	if err := os.MkdirAll(otherDir, 0o700); err != nil {
		t.Fatal(err)
	}
	otherGomod := "module example.com/other\n\ngo 1.24\n\nrequire github.com/unrelated/pkg v1.0.0\n"
	if err := os.WriteFile(filepath.Join(otherDir, "go.mod"), []byte(otherGomod), 0o600); err != nil {
		t.Fatal(err)
	}

	appDir := filepath.Join(root, "app")
	if err := os.MkdirAll(appDir, 0o700); err != nil {
		t.Fatal(err)
	}
	appGomod := "module example.com/app\n\ngo 1.24\n\ntool golang.org/x/tools/cmd/stringer\n"
	appGomodPath := filepath.Join(appDir, "go.mod")
	if err := os.WriteFile(appGomodPath, []byte(appGomod), 0o600); err != nil {
		t.Fatal(err)
	}

	gowork := "go 1.24\n\nuse ./app\nuse ./other\n"
	if err := os.WriteFile(filepath.Join(root, "go.work"), []byte(gowork), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := readGoModToolModules(appGomodPath)
	if err == nil {
		t.Fatal("expected error when tool module not found even after workspace lookup")
	}
	if !strings.Contains(err.Error(), "go.work") {
		t.Errorf("expected error to mention go.work, got: %v", err)
	}
}

func TestReadGoModToolModules_NoWorkspace_OriginalError(t *testing.T) {
	// No go.work anywhere — error must match the original behaviour (no mention of go.work).
	dir := t.TempDir()
	gomod := "module example.com/app\n\ngo 1.24\n\ntool golang.org/x/tools/cmd/stringer\n"
	path := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(path, []byte(gomod), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := readGoModToolModules(path)
	if err == nil {
		t.Fatal("expected error when tool module not in go.mod and no go.work")
	}
	if strings.Contains(err.Error(), "go.work") {
		t.Errorf("error should not mention go.work when none exists, got: %v", err)
	}
}

func TestReadGoModToolModules_GomodPrecedenceOverWorkspace(t *testing.T) {
	// Tool module appears in both go.mod (v0.30.0) and a workspace module (v0.31.0).
	// go.mod version must win.
	root := t.TempDir()

	libDir := filepath.Join(root, "lib")
	if err := os.MkdirAll(libDir, 0o700); err != nil {
		t.Fatal(err)
	}
	libGomod := "module example.com/lib\n\ngo 1.24\n\nrequire golang.org/x/tools v0.31.0\n"
	if err := os.WriteFile(filepath.Join(libDir, "go.mod"), []byte(libGomod), 0o600); err != nil {
		t.Fatal(err)
	}

	appDir := filepath.Join(root, "app")
	if err := os.MkdirAll(appDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// app/go.mod already has the require at v0.30.0
	appGomod := "module example.com/app\n\ngo 1.24\n\nrequire golang.org/x/tools v0.30.0\n\ntool golang.org/x/tools/cmd/stringer\n"
	appGomodPath := filepath.Join(appDir, "go.mod")
	if err := os.WriteFile(appGomodPath, []byte(appGomod), 0o600); err != nil {
		t.Fatal(err)
	}

	gowork := "go 1.24\n\nuse ./app\nuse ./lib\n"
	if err := os.WriteFile(filepath.Join(root, "go.work"), []byte(gowork), 0o600); err != nil {
		t.Fatal(err)
	}

	coords, err := readGoModToolModules(appGomodPath)
	if err != nil {
		t.Fatalf("readGoModToolModules: %v", err)
	}
	if len(coords) != 1 || coords[0] != "golang.org/x/tools@v0.30.0" {
		t.Errorf("got %v, want [golang.org/x/tools@v0.30.0] (go.mod must take precedence)", coords)
	}
}

func TestResolveGoModPath_Explicit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(path, []byte("module example.com/m\n\ngo 1.21\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := resolveGoModPath(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != path {
		t.Errorf("got %q, want %q", got, path)
	}
}

func TestResolveGoModPath_DefaultFound(t *testing.T) {
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(orig) }()

	if err := os.WriteFile("go.mod", []byte("module example.com/m\n\ngo 1.21\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := resolveGoModPath("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "./go.mod" {
		t.Errorf("got %q, want \"./go.mod\"", got)
	}
}

func TestResolveGoModPath_DefaultMissing(t *testing.T) {
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(orig) }()

	_, err = resolveGoModPath("")
	if err == nil {
		t.Fatal("expected error when ./go.mod does not exist")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' in error, got: %v", err)
	}
}

// projectModulePathFromGoMod reads the module directive so commands
// (e.g. `directives list`) can infer --project from cwd's go.mod.
func TestProjectModulePathFromGoMod(t *testing.T) {
	t.Run("returns declared module path", func(t *testing.T) {
		dir := t.TempDir()
		gomod := filepath.Join(dir, "go.mod")
		if err := os.WriteFile(gomod, []byte("module example.com/foo\n\ngo 1.22\n"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		got, err := projectModulePathFromGoMod(gomod)
		if err != nil {
			t.Fatalf("projectModulePathFromGoMod: %v", err)
		}
		if got != "example.com/foo" {
			t.Errorf("got %q, want example.com/foo", got)
		}
	})

	t.Run("missing file is an actionable error", func(t *testing.T) {
		_, err := projectModulePathFromGoMod(filepath.Join(t.TempDir(), "absent.mod"))
		if err == nil {
			t.Fatal("expected error for missing file, got nil")
		}
	})

	t.Run("file without module directive is rejected", func(t *testing.T) {
		dir := t.TempDir()
		gomod := filepath.Join(dir, "go.mod")
		if err := os.WriteFile(gomod, []byte("// no module directive here\n"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		_, err := projectModulePathFromGoMod(gomod)
		if err == nil {
			t.Fatal("expected error for module-less go.mod, got nil")
		}
		if !strings.Contains(err.Error(), "no module directive") {
			t.Errorf("error %q should name the missing module directive", err)
		}
	})
}

// ExitCodeFromError surfaces the explicit exit code carried by an
// *exitError, including when the *exitError is wrapped via fmt.Errorf("%w").
// Plain errors return (_, false) so the caller falls back to its default.
func TestExitCodeFromError(t *testing.T) {
	t.Run("direct exitError surfaces its code", func(t *testing.T) {
		err := &exitError{code: ExitNotFound, msg: "not found: X"}
		code, ok := ExitCodeFromError(err)
		if !ok || code != ExitNotFound {
			t.Errorf("got (%d, %t), want (%d, true)", code, ok, ExitNotFound)
		}
	})

	t.Run("wrapped exitError still surfaces its code", func(t *testing.T) {
		wrapped := fmt.Errorf("running directives diff: %w", &exitError{code: ExitNotFound, msg: "scan not found"})
		code, ok := ExitCodeFromError(wrapped)
		if !ok || code != ExitNotFound {
			t.Errorf("wrapped: got (%d, %t), want (%d, true)", code, ok, ExitNotFound)
		}
	})

	t.Run("non-exitError returns ok=false", func(t *testing.T) {
		_, ok := ExitCodeFromError(errors.New("generic"))
		if ok {
			t.Error("got ok=true for non-exitError; caller would shadow its fallback")
		}
	})

	t.Run("nil error returns ok=false", func(t *testing.T) {
		_, ok := ExitCodeFromError(nil)
		if ok {
			t.Error("got ok=true for nil err; main would emit a categorised non-zero")
		}
	})

	t.Run("each named exit code stays distinct", func(t *testing.T) {
		seen := map[int]string{}
		for _, c := range []struct {
			name string
			code int
		}{
			{"ExitOK", ExitOK},
			{"ExitPartial", ExitPartial},
			{"ExitFailed", ExitFailed},
			{"ExitCancelled", ExitCancelled},
			{"ExitNotFound", ExitNotFound},
			{"ExitIntegrity", ExitIntegrity},
			{"ExitConfig", ExitConfig},
		} {
			if prev, ok := seen[c.code]; ok {
				t.Errorf("exit code %d collision: %s and %s share the same numeric value", c.code, prev, c.name)
			}
			seen[c.code] = c.name
		}
	})
}

// ExitCodeForError maps a Run error onto the process exit code: nil is ExitOK, an
// explicit exit-code carrier wins over everything, the walk-integrity sentinel
// maps to ExitIntegrity, and anything else falls back to ExitConfig. Shared by
// every main entry point, so its precedence is pinned here.
func TestExitCodeForError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"nil is OK", nil, ExitOK},
		{"exitError carrier wins", &exitError{code: ExitNotFound, msg: "x"}, ExitNotFound},
		{"wrapped exitError carrier wins", fmt.Errorf("ctx: %w", &exitError{code: ExitNotFound, msg: "x"}), ExitNotFound},
		{"walk integrity maps to ExitIntegrity", fmt.Errorf("verifying: %w", walkports.ErrWalkIntegrity), ExitIntegrity},
		{"generic falls back to ExitConfig", errors.New("boom"), ExitConfig},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ExitCodeForError(c.err); got != c.want {
				t.Errorf("ExitCodeForError(%v) = %d, want %d", c.err, got, c.want)
			}
		})
	}
}

// TestReadPackageModules runs against the real kanonarion module in this repo.
// It exercises the full go list path and verifies the output:
// - contains known runtime deps (modernc.org/sqlite, golang.org/x/mod)
// - does NOT contain dev/tool deps (golangci-lint)
// - does NOT contain the local module itself (no version)
func TestReadPackageModules_LiveRepo(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live go list test in short mode")
	}

	coords, err := readPackageModules("github.com/eitanity/kanonarion/cmd/kanonarion")
	if err != nil {
		t.Fatalf("readPackageModules: %v", err)
	}
	if len(coords) == 0 {
		t.Fatal("expected at least one module, got none")
	}

	idx := make(map[string]bool)
	for _, c := range coords {
		idx[c] = true
		// Every coordinate must have a version (path@vX.Y.Z).
		if !strings.Contains(c, "@") || strings.HasSuffix(c, "@") {
			t.Errorf("coordinate missing version: %q", c)
		}
	}

	// Known runtime deps that must be present.
	for _, must := range []string{
		"modernc.org/sqlite",
		"golang.org/x/mod",
		"github.com/spf13/cobra",
	} {
		found := false
		for c := range idx {
			if strings.HasPrefix(c, must+"@") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected runtime dep %q not found in %v", must, coords)
		}
	}

	// golangci-lint is a dev tool and must not appear.
	for c := range idx {
		if strings.Contains(c, "golangci-lint") {
			t.Errorf("dev tool golangci-lint must not appear in binary deps: %q", c)
		}
	}
}
