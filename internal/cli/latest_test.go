package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	proxyadapter "github.com/eitanity/kanonarion/internal/adapters/proxy/direct"
)

func TestLatestCmd_Help(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Run([]string{"latest", "--help"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := stdout.String()
	for _, want := range []string{"--gomod", "--goproxy", "latest"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in help output, got:\n%s", want, out)
		}
	}
}

func TestLatestCmd_NoArgs_NoGomod(t *testing.T) {
	// Run from a temp dir with no go.mod so auto-detect fails.
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
	runErr := Run([]string{"latest"}, &stdout, &stderr)
	if runErr == nil {
		t.Fatal("expected error when no go.mod present and no module arg given")
	}
	if !strings.Contains(runErr.Error(), "not found") {
		t.Errorf("expected 'not found' in error, got: %v", runErr)
	}
}

func TestLatestCmd_NoArgs_GomodFound(t *testing.T) {
	// Run from a temp dir with a go.mod with no direct deps (avoids network).
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/myapp\n\ngo 1.21\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(orig) }()

	var stdout, stderr bytes.Buffer
	runErr := Run([]string{"latest"}, &stdout, &stderr)
	if runErr != nil {
		t.Fatalf("unexpected error: %v", runErr)
	}
	if !strings.Contains(stdout.String(), "no code dependencies found") {
		t.Errorf("expected empty-deps message, got: %q", stdout.String())
	}
}

func TestLatestCmd_BothArgAndGomod(t *testing.T) {
	dir := t.TempDir()
	gomod := "module example.com/app\n\ngo 1.21\n"
	path := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(path, []byte(gomod), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	err := Run([]string{"latest", "github.com/foo/bar", "--gomod", path}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error when both module and --gomod given")
	}
	if !strings.Contains(err.Error(), "cannot specify both") {
		t.Errorf("expected 'cannot specify both' in error, got: %v", err)
	}
}

func TestLatestCmd_GomodMissingFile(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Run([]string{"latest", "--gomod", "/nonexistent/go.mod"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for missing go.mod")
	}
	if !strings.Contains(err.Error(), "resolving code scope") {
		t.Errorf("expected 'resolving code scope' in error, got: %v", err)
	}
}

func TestLatestCmd_GomodAllIndirect(t *testing.T) {
	gomod := "module example.com/app\n\ngo 1.21\n\nrequire (\n\tgithub.com/only/indirect v1.0.0 // indirect\n)\n"
	dir := t.TempDir()
	path := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(path, []byte(gomod), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	err := Run([]string{"latest", "--gomod", path}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout.String(), "no code dependencies found") {
		t.Errorf("expected empty-deps message, got: %q", stdout.String())
	}
}

func TestLatestCmd_ToolAndArgMutuallyExclusive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(path, []byte("module example.com/app\n\ngo 1.24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	err := Run([]string{"latest", "github.com/foo/bar", "--tool", "--gomod", path}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error when both module arg and --tool given")
	}
	if !strings.Contains(err.Error(), "cannot specify both") {
		t.Errorf("expected 'cannot specify both' in error, got: %v", err)
	}
}

func TestLatestCmd_ToolNoDirectives(t *testing.T) {
	gomod := "module example.com/app\n\ngo 1.24\n\nrequire (\n\tgithub.com/foo/bar v1.0.0\n)\n"
	dir := t.TempDir()
	path := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(path, []byte(gomod), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	err := Run([]string{"latest", "--gomod", path, "--tool"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout.String(), "no tool dependencies found") {
		t.Errorf("expected 'no tool dependencies found' in output, got: %q", stdout.String())
	}
}

func fakeLatestProxy(t *testing.T, versions map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// path is /<module>/@latest
		for mod, ver := range versions {
			if strings.HasSuffix(r.URL.Path, mod+"/@latest") {
				w.Header().Set("Content-Type", "application/json")
				payload, _ := json.Marshal(map[string]any{
					"Version": ver,
					"Time":    time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC),
				})
				_, _ = w.Write(payload)
				return
			}
		}
		http.NotFound(w, r)
	}))
	return srv
}

// runLatestGomod now resolves its scope via the Go toolchain (go list), so the
// scope-resolution path is exercised by resolveScopeModules' own tests and the
// integration fixtures rather than a hermetic fake-go.mod unit test here.

func TestLatestCmd_Help_ToolFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Run([]string{"latest", "--help"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout.String(), "--tool") {
		t.Errorf("expected '--tool' in help output, got:\n%s", stdout.String())
	}
}

// TestRunLatestModules_MultipleArgs is the regression: passing more
// than one positional argument used to silently drop everything after the
// first. The command now resolves every argument and renders one line per
// module in text mode and a JSON array in --json mode.
func TestRunLatestModules_MultipleArgs(t *testing.T) {
	srv := fakeLatestProxy(t, map[string]string{
		"github.com/spf13/cobra":      "v1.10.2",
		"github.com/stretchr/testify": "v1.10.0",
	})
	defer srv.Close()

	proxy, err := proxyadapter.New(srv.URL, true)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	t.Run("text mode resolves every module", func(t *testing.T) {
		prev := jsonOut
		jsonOut = false
		t.Cleanup(func() { jsonOut = prev })

		var stdout bytes.Buffer
		err := runLatestModules(context.Background(),
			[]string{"github.com/spf13/cobra", "github.com/stretchr/testify"},
			proxy, &stdout)
		if err != nil {
			t.Fatalf("runLatestModules: %v", err)
		}
		out := stdout.String()
		for _, want := range []string{
			"github.com/spf13/cobra@v1.10.2",
			"github.com/stretchr/testify@v1.10.0",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("missing %q in text output:\n%s", want, out)
			}
		}
		// Two modules in, two lines out.
		if got := strings.Count(out, "\n"); got != 2 {
			t.Errorf("expected 2 output lines, got %d:\n%s", got, out)
		}
	})

	t.Run("json mode of multiple modules emits an array", func(t *testing.T) {
		prev := jsonOut
		jsonOut = true
		t.Cleanup(func() { jsonOut = prev })

		var stdout bytes.Buffer
		err := runLatestModules(context.Background(),
			[]string{"github.com/spf13/cobra", "github.com/stretchr/testify"},
			proxy, &stdout)
		if err != nil {
			t.Fatalf("runLatestModules: %v", err)
		}
		var got []latestResult
		if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
			t.Fatalf("output is not a JSON array: %v\noutput: %s", err, stdout.String())
		}
		if len(got) != 2 {
			t.Fatalf("expected 2 results in array, got %d", len(got))
		}
		// Order must follow the argv order.
		if got[0].Module != "github.com/spf13/cobra" {
			t.Errorf("results[0].Module = %q, want github.com/spf13/cobra", got[0].Module)
		}
		if got[1].Module != "github.com/stretchr/testify" {
			t.Errorf("results[1].Module = %q, want github.com/stretchr/testify", got[1].Module)
		}
	})

	t.Run("json mode of single module keeps object shape", func(t *testing.T) {
		prev := jsonOut
		jsonOut = true
		t.Cleanup(func() { jsonOut = prev })

		var stdout bytes.Buffer
		err := runLatestModules(context.Background(),
			[]string{"github.com/spf13/cobra"},
			proxy, &stdout)
		if err != nil {
			t.Fatalf("runLatestModules: %v", err)
		}
		var got latestResult
		if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
			t.Fatalf("single-module JSON output is not an object: %v\noutput: %s", err, stdout.String())
		}
		if got.Module != "github.com/spf13/cobra" {
			t.Errorf("Module = %q, want github.com/spf13/cobra", got.Module)
		}
	})
}

func TestPrintLatestTable(t *testing.T) {
	tests := []struct {
		name    string
		results []latestResult
		checks  []string
		absent  []string
	}{
		{
			name: "current dep",
			results: []latestResult{
				{
					Module:   "github.com/foo/bar",
					Pinned:   "v1.0.0",
					Latest:   "v1.0.0",
					IsLatest: true,
				},
			},
			checks: []string{"github.com/foo/bar@v1.0.0", "current"},
			absent: []string{"latest:"},
		},
		{
			name: "stale dep",
			results: []latestResult{
				{
					Module:     "github.com/foo/bar",
					Pinned:     "v1.0.0",
					Latest:     "v1.2.0",
					IsLatest:   false,
					DaysBehind: 30,
				},
			},
			checks: []string{"github.com/foo/bar@v1.0.0", "latest: v1.2.0", "30 days ago"},
		},
		{
			name: "stale dep released today",
			results: []latestResult{
				{
					Module:     "github.com/foo/bar",
					Pinned:     "v1.0.0",
					Latest:     "v1.1.0",
					IsLatest:   false,
					DaysBehind: 0,
				},
			},
			checks: []string{"latest: v1.1.0", "released today"},
		},
		{
			name: "error resolving",
			results: []latestResult{
				{
					Module: "github.com/foo/bar",
					Pinned: "v1.0.0",
					Latest: "(error)",
				},
			},
			checks: []string{"(error resolving latest)"},
		},
		{
			name:    "empty results",
			results: []latestResult{},
			checks:  []string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf strings.Builder
			if err := printLatestTable(&buf, tc.results); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			got := buf.String()
			for _, want := range tc.checks {
				if !strings.Contains(got, want) {
					t.Errorf("missing %q in output:\n%s", want, got)
				}
			}
			for _, absent := range tc.absent {
				if strings.Contains(got, absent) {
					t.Errorf("unexpected %q in output:\n%s", absent, got)
				}
			}
		})
	}
}
