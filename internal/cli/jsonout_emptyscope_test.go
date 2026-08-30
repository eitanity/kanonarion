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

// emptyToolScopeGoMod writes a go.mod with no tool directives, so
// resolveScopeModules(scopeTool) resolves to zero modules without invoking the
// go toolchain — a hermetic way to reach every command's empty-scope branch.
func emptyToolScopeGoMod(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(p, []byte("module example.com/myapp\n\ngo 1.24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestContextGomod_EmptyScope_JSONIsEmptyArray guards that context's --json
// output decodes as [] on an empty scope, keeping the empty and populated
// answers the same type — and that the prose sentence a caller cannot parse
// still stays off stdout. Zero bytes is a document only in the newline-
// delimited form --stream selects, which its own test covers.
func TestContextGomod_EmptyScope_JSONIsEmptyArray(t *testing.T) {
	p := emptyToolScopeGoMod(t)
	jsonOut = true
	defer func() { jsonOut = false }()

	var stdout, stderr bytes.Buffer
	if err := runContextGoMod(context.Background(), contextFlags{gomodPath: p}, scopeTool, &stdout, &stderr); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var decoded []json.RawMessage
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("empty scope under --json is not a JSON array: %v\noutput: %q", err, stdout.String())
	}
	if len(decoded) != 0 {
		t.Errorf("empty scope produced %d documents, want none", len(decoded))
	}
}

// TestContextGomod_EmptyScope_TextKeepsProse guards that routing the empty case
// away from stdout under --json did not drop the human sentence on the text path.
func TestContextGomod_EmptyScope_TextKeepsProse(t *testing.T) {
	p := emptyToolScopeGoMod(t)
	var stdout, stderr bytes.Buffer
	if err := runContextGoMod(context.Background(), contextFlags{gomodPath: p}, scopeTool, &stdout, &stderr); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout.String(), "no tool dependencies found") {
		t.Errorf("expected the empty-scope sentence on the text path, got: %q", stdout.String())
	}
}

// TestLatestGomod_EmptyScope_JSONIsEmptyArray guards that latest's JSON array
// output decodes as [] on an empty scope, keeping the empty and populated
// results the same type. The proxy is unused on this path, so nil is safe.
func TestLatestGomod_EmptyScope_JSONIsEmptyArray(t *testing.T) {
	p := emptyToolScopeGoMod(t)
	jsonOut = true
	defer func() { jsonOut = false }()

	var stdout, stderr bytes.Buffer
	if err := runLatestGomod(context.Background(), p, scopeTool, false, func([]string) stalenessLookup { return nil }, &stdout, &stderr); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := strings.TrimSpace(stdout.String())
	if out == "null" {
		t.Fatalf("emitted JSON null instead of []")
	}
	var arr []latestResult
	if err := json.Unmarshal([]byte(out), &arr); err != nil {
		t.Fatalf("--json did not emit a JSON array: %v (out=%q)", err, out)
	}
	if len(arr) != 0 {
		t.Errorf("expected empty array, got %d entries", len(arr))
	}
}

// TestLatestGomod_EmptyScope_TextKeepsProse guards the text-path sentence.
func TestLatestGomod_EmptyScope_TextKeepsProse(t *testing.T) {
	p := emptyToolScopeGoMod(t)
	var stdout, stderr bytes.Buffer
	if err := runLatestGomod(context.Background(), p, scopeTool, false, func([]string) stalenessLookup { return nil }, &stdout, &stderr); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout.String(), "no tool dependencies found") {
		t.Errorf("expected the empty-scope sentence on the text path, got: %q", stdout.String())
	}
}

// TestInspectGomod_EmptyScope_JSONIsSummaryObject guards that inspect's JSON
// object output decodes as an inspectSummary on an empty scope — the same type
// the populated path emits — with no walks, rather than a prose sentence.
func TestInspectGomod_EmptyScope_JSONIsSummaryObject(t *testing.T) {
	p := emptyToolScopeGoMod(t)
	jsonOut = true
	defer func() { jsonOut = false }()

	var stdout, stderr bytes.Buffer
	if err := runInspectGoMod(context.Background(), inspectFlags{gomodPath: p}, scopeTool, &stdout, &stderr); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := strings.TrimSpace(stdout.String())
	var summary inspectSummary
	if err := json.Unmarshal([]byte(out), &summary); err != nil {
		t.Fatalf("--json did not emit an inspectSummary object: %v (out=%q)", err, out)
	}
	if summary.ModuleCount != 0 {
		t.Errorf("expected zero modules for an empty scope, got %d", summary.ModuleCount)
	}
	// walk_ids must be [] not null so empty and populated decode alike.
	if strings.Contains(out, `"walk_ids": null`) {
		t.Errorf("walk_ids emitted as null, not []: %q", out)
	}
}

// TestInspectGomod_EmptyScope_TextKeepsProse guards the text-path sentence.
func TestInspectGomod_EmptyScope_TextKeepsProse(t *testing.T) {
	p := emptyToolScopeGoMod(t)
	var stdout, stderr bytes.Buffer
	if err := runInspectGoMod(context.Background(), inspectFlags{gomodPath: p}, scopeTool, &stdout, &stderr); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout.String(), "no tool dependencies found") {
		t.Errorf("expected the empty-scope sentence on the text path, got: %q", stdout.String())
	}
}
