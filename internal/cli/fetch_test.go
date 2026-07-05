package cli

import (
	"bytes"
	"context"
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
