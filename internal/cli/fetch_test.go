package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFetchCmd_NoVersion(t *testing.T) {
	tests := []struct {
		name string
		arg  string
	}{
		{"bare module path", "notamodule"},
		{"module path without @version", "github.com/gorilla/mux"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			err := Run([]string{"fetch", tt.arg}, &stdout, &stderr)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), "version required") {
				t.Errorf("expected 'version required' in error, got: %v", err)
			}
		})
	}
}

func TestFetchCmd_ToolAndArgMutuallyExclusive(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Run([]string{"fetch", "--tool", "github.com/foo/bar@v1.0.0"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error when --tool and positional arg are both given")
	}
	if !strings.Contains(err.Error(), "go.mod scope fetch") {
		t.Errorf("expected go.mod-scope-vs-positional error, got: %v", err)
	}
}

func TestFetchCmd_ToolAndListVersionsMutuallyExclusive(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Run([]string{"fetch", "--tool", "--list-versions"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error when --tool and --list-versions are both given")
	}
	if !strings.Contains(err.Error(), "--list-versions with a go.mod scope fetch") {
		t.Errorf("expected list-versions-vs-scope error, got: %v", err)
	}
}

func TestFetchCmd_ToolNoGomodFound(t *testing.T) {
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(orig) }()

	var stdout, stderr bytes.Buffer
	runErr := Run([]string{"fetch", "--tool"}, &stdout, &stderr)
	if runErr == nil {
		t.Fatal("expected error when no go.mod present")
	}
	if !strings.Contains(runErr.Error(), "not found") {
		t.Errorf("expected 'not found' in error, got: %v", runErr)
	}
}

func TestFetchCmd_ToolNoToolDirectives(t *testing.T) {
	dir := t.TempDir()
	gomod := "module example.com/myapp\n\ngo 1.24\n\nrequire github.com/foo/bar v1.0.0\n"
	gomodPath := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(gomodPath, []byte(gomod), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	err := Run([]string{"fetch", "--tool", "--gomod", gomodPath}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout.String(), "no tool dependencies found") {
		t.Errorf("expected 'no tool dependencies found' in output, got: %q", stdout.String())
	}
}

func TestFetchCmd_ToolGomodMissingFile(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Run([]string{"fetch", "--tool", "--gomod", "/nonexistent/go.mod"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for missing go.mod file")
	}
}

func TestRunFetchScope_NoToolDirectives(t *testing.T) {
	dir := t.TempDir()
	gomod := "module example.com/myapp\n\ngo 1.24\n"
	gomodPath := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(gomodPath, []byte(gomod), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	err := runFetchScope(context.TODO(), gomodPath, scopeTool, fetchFlags{}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout.String(), "no tool dependencies found") {
		t.Errorf("expected 'no tool dependencies found', got: %q", stdout.String())
	}
}

// fakeVersionLister returns a fixed version list, so runListVersions can be
// exercised at its seam without reaching the network proxy.
type fakeVersionLister struct{ versions []string }

func (f fakeVersionLister) ListVersions(context.Context, string) ([]string, error) {
	return f.versions, nil
}

// TestRunListVersions_EmptyJSONIsArrayNotProse guards that a module with no
// known versions is reported to a --json caller as an empty array. The
// empty-result branch used to return above the jsonOut check, so it wrote a
// human sentence onto the data channel and exited 0.
func TestRunListVersions_EmptyJSONIsArrayNotProse(t *testing.T) {
	for _, tc := range []struct {
		name     string
		versions []string
	}{
		{"nil slice", nil},
		{"empty slice", []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout bytes.Buffer
			err := runListVersions(context.Background(), "example.com/mod", true,
				fakeVersionLister{versions: tc.versions}, &stdout)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			out := strings.TrimSpace(stdout.String())
			var got []string
			if uerr := json.Unmarshal([]byte(out), &got); uerr != nil {
				t.Fatalf("--json emitted non-JSON: %q", out)
			}
			if got == nil {
				t.Errorf("--json emitted null, not []: %q", out)
			}
			if len(got) != 0 {
				t.Errorf("expected no versions, got %d", len(got))
			}
		})
	}
}

// TestRunListVersions_EmptyTextKeepsProse guards that the human path still
// says so in words: routing the empty case to JSON must not silently drop the
// text answer.
func TestRunListVersions_EmptyTextKeepsProse(t *testing.T) {
	var stdout bytes.Buffer
	if err := runListVersions(context.Background(), "example.com/mod", false,
		fakeVersionLister{}, &stdout); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout.String(), "no versions found for example.com/mod") {
		t.Errorf("expected the empty-result sentence, got: %q", stdout.String())
	}
}
