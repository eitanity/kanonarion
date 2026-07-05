package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validPolicyYAML = `version: "1"
stages:
  fetch:
    max_depth: 1
`

const invalidPolicyYAML = `version: "invalid"
`

func TestRunPolicyValidate_ValidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(validPolicyYAML), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	var buf bytes.Buffer
	err := runPolicyValidate(context.Background(), path, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "ok:") {
		t.Errorf("expected 'ok:' in output, got: %q", buf.String())
	}
}

func TestRunPolicyValidate_InvalidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "invalid.yaml")
	if err := os.WriteFile(path, []byte(invalidPolicyYAML), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	var buf bytes.Buffer
	err := runPolicyValidate(context.Background(), path, &buf)
	if err == nil {
		t.Fatal("expected error for invalid policy")
	}
	if !strings.Contains(err.Error(), "invalid policy") {
		t.Errorf("expected 'invalid policy' in error, got: %v", err)
	}
}

// TestRunPolicyValidate_GovernanceSchema is the regression: a config
// file carrying a governance block must route to the governance schema, a
// well-formed block must validate, and a bad outcome must be rejected with
// the governance-schema diagnostic (not silently accepted as a depth policy).
func TestRunPolicyValidate_GovernanceSchema(t *testing.T) {
	dir := t.TempDir()

	good := filepath.Join(dir, "gov-ok.yaml")
	if err := os.WriteFile(good, []byte(`version: "2"
directive_policy:
  local_path_replace: warn
godebug_policy:
  red: warn
`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	var buf bytes.Buffer
	if err := runPolicyValidate(context.Background(), good, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "governance schema") {
		t.Errorf("expected governance schema routing, got: %q", buf.String())
	}

	bad := filepath.Join(dir, "gov-bad.yaml")
	if err := os.WriteFile(bad, []byte(`version: "2"
directive_policy:
  local_path_replace: explode
`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	err := runPolicyValidate(context.Background(), bad, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error for invalid governance outcome")
	}
	if !strings.Contains(err.Error(), "governance schema") {
		t.Errorf("expected governance-schema diagnostic, got: %v", err)
	}
}

func TestRunPolicyValidate_NotFound(t *testing.T) {
	var buf bytes.Buffer
	err := runPolicyValidate(context.Background(), "non-existent.yaml", &buf)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !strings.Contains(err.Error(), "policy file not found") {
		t.Errorf("expected 'policy file not found' in error, got: %v", err)
	}
}

func TestRunPolicyValidate_RepoDefaultPolicy(t *testing.T) {
	var buf bytes.Buffer
	err := runPolicyValidate(context.Background(), "../../docs/examples/policies/default.yaml", &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "ok:") {
		t.Errorf("expected 'ok:' in output, got: %q", buf.String())
	}
}

func TestRunPolicyShow_NoArgs(t *testing.T) {
	// With no path, loadPolicy returns the default policy (version "1").
	var stdout, stderr bytes.Buffer
	err := runPolicyShow(context.Background(), "", &stdout, &stderr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, `"version": "1"`) {
		t.Errorf("expected version in output, got: %q", out)
	}
	if !strings.Contains(out, "stage_depths") {
		t.Errorf("expected stage_depths in output, got: %q", out)
	}
}

func TestPolicyValidateCmd_NoArgs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	// a missing required arg must be a non-zero usage error, not a
	// help dump that exits 0. usage must not be dumped to stdout.
	err := Run([]string{"policy", "validate"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected a non-nil error for missing <path> argument")
	}
	if strings.Contains(stdout.String(), "Usage:") {
		t.Errorf("cobra usage dumped to stdout: %q", stdout.String())
	}
}

func TestPolicyCmd_NoArgs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Run([]string{"policy"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout.String(), "Usage:") {
		t.Errorf("expected usage in output, got: %q", stdout.String())
	}
}

func TestRunPolicyShow_ExplicitFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(validPolicyYAML), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	var stdout, stderr bytes.Buffer
	err := runPolicyShow(context.Background(), path, &stdout, &stderr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, `"version": "1"`) {
		t.Errorf("expected version in output, got: %q", out)
	}
	if !strings.Contains(out, "MaxDepth") {
		t.Errorf("expected MaxDepth in output, got: %q", out)
	}
}

func TestRunPolicyValidateDir_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	err := runPolicyValidate(context.Background(), dir, &buf)
	if err != nil {
		t.Fatalf("unexpected error for empty dir: %v", err)
	}
	if !strings.Contains(buf.String(), "no policy files found") {
		t.Errorf("expected 'no policy files found', got: %q", buf.String())
	}
}

func TestRunPolicyValidateDir_WithValidFiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"policy.yaml", "rules.yml"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(validPolicyYAML), 0o600); err != nil {
			t.Fatalf("WriteFile %s: %v", name, err)
		}
	}
	var buf bytes.Buffer
	err := runPolicyValidate(context.Background(), dir, &buf)
	if err != nil {
		t.Fatalf("unexpected error for valid dir: %v", err)
	}
	if !strings.Contains(buf.String(), "ok:") {
		t.Errorf("expected 'ok:' in output, got: %q", buf.String())
	}
}

func TestRunPolicyValidateDir_WithInvalidFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte(invalidPolicyYAML), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	var buf bytes.Buffer
	err := runPolicyValidate(context.Background(), dir, &buf)
	if err == nil {
		t.Fatal("expected error for directory with invalid policy")
	}
	if !strings.Contains(buf.String(), "FAIL:") {
		t.Errorf("expected 'FAIL:' in output, got: %q", buf.String())
	}
}
