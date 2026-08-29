package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
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
	err := runPolicyValidate(context.Background(), path, false, &buf)
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
	err := runPolicyValidate(context.Background(), path, false, &buf)
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
	if err := runPolicyValidate(context.Background(), good, false, &buf); err != nil {
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
	err := runPolicyValidate(context.Background(), bad, false, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error for invalid governance outcome")
	}
	if !strings.Contains(err.Error(), "governance schema") {
		t.Errorf("expected governance-schema diagnostic, got: %v", err)
	}
}

func TestRunPolicyValidate_NotFound(t *testing.T) {
	var buf bytes.Buffer
	err := runPolicyValidate(context.Background(), "non-existent.yaml", false, &buf)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !strings.Contains(err.Error(), "policy file not found") {
		t.Errorf("expected 'policy file not found' in error, got: %v", err)
	}
}

func TestRunPolicyValidate_RepoDefaultPolicy(t *testing.T) {
	var buf bytes.Buffer
	err := runPolicyValidate(context.Background(), "../../docs/examples/policies/default.yaml", false, &buf)
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
	err := runPolicyValidate(context.Background(), dir, false, &buf)
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
	err := runPolicyValidate(context.Background(), dir, false, &buf)
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
	err := runPolicyValidate(context.Background(), dir, false, &buf)
	if err == nil {
		t.Fatal("expected error for directory with invalid policy")
	}
	if !strings.Contains(buf.String(), "FAIL:") {
		t.Errorf("expected 'FAIL:' in output, got: %q", buf.String())
	}
}

// `policy show` must report the VCS forge allowlist that will actually be
// contacted, resolved rather than as authored: an operator syncing an egress
// allowlist (harden-runner) needs the effective set, and a policy that omits
// the field still cross-verifies against the built-in one.
func TestRunPolicyShow_ReportsEffectiveVCSHosts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(validPolicyYAML), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	var out, errBuf bytes.Buffer
	if err := runPolicyShow(context.Background(), path, &out, &errBuf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var got struct {
		EffectiveVCSHosts []string       `json:"effective_vcs_hosts"`
		StageDepths       map[string]any `json:"stage_depths"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("decoding policy show output: %v\n%s", err, out.String())
	}
	if len(got.EffectiveVCSHosts) != len(fetchdomain.DefaultVCSHosts()) {
		t.Errorf("effective_vcs_hosts = %v, want the built-in default set", got.EffectiveVCSHosts)
	}
	// A policy that does not override the list must render exactly as before,
	// so the absent field stays absent from the per-stage object.
	if _, present := got.StageDepths["fetch"].(map[string]any)["AllowedVCSHosts"]; present {
		t.Error("an unset allowed_vcs_hosts must not appear in the per-stage output")
	}
}

func TestRunPolicyShow_ReportsOverriddenVCSHosts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	src := "version: \"1\"\nstages:\n  fetch:\n    allowed_vcs_hosts:\n      - github.com\n"
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	var out, errBuf bytes.Buffer
	if err := runPolicyShow(context.Background(), path, &out, &errBuf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var got struct {
		EffectiveVCSHosts []string `json:"effective_vcs_hosts"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("decoding policy show output: %v\n%s", err, out.String())
	}
	if len(got.EffectiveVCSHosts) != 1 || got.EffectiveVCSHosts[0] != "github.com" {
		t.Errorf("effective_vcs_hosts = %v, want [github.com]", got.EffectiveVCSHosts)
	}
}

// A policy whose allowlist cannot be resolved must fail the command rather than
// print the default set as if it were in force.
func TestRunPolicyShow_UnusableVCSHostsIsAnError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	src := "version: \"1\"\nstages:\n  fetch:\n    allowed_vcs_hosts: []\n"
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	var out, errBuf bytes.Buffer
	err := runPolicyShow(context.Background(), path, &out, &errBuf)
	if err == nil {
		t.Fatal("expected an empty allowed_vcs_hosts to fail policy show")
	}
	if !strings.Contains(err.Error(), "--skip-vcs-verify") {
		t.Errorf("error should point at --skip-vcs-verify, got %q", err)
	}
}

// resolveFetchVCSHosts is what `kanonarion fetch` uses to honour the policy
// without a dedicated flag: an absent policy yields the built-in set, and an
// override reaches the fetch.
func TestResolveFetchVCSHosts(t *testing.T) {
	var errBuf bytes.Buffer
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	src := "version: \"1\"\nstages:\n  fetch:\n    allowed_vcs_hosts:\n      - git.example.org\n"
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	hosts, err := resolveFetchVCSHosts(context.Background(), path, &errBuf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hosts.IsAllowed("git.example.org") {
		t.Error("the policy's forge did not reach the fetch command")
	}
	if hosts.IsAllowed("github.com") {
		t.Error("the override must replace the built-in set")
	}

	if _, err := resolveFetchVCSHosts(context.Background(), filepath.Join(dir, "missing.yaml"), &errBuf); err == nil {
		t.Error("an explicit policy path that does not exist should be an error")
	}
}

// ---- policy validate --json -------------------------------------------------

// runPolicyValidateCLI drives the command the way an operator does, so the
// --json flag is resolved by the root exactly as it is in a shell, and returns
// stdout with the process exit code the invocation would have produced.
func runPolicyValidateCLI(t *testing.T, args ...string) (string, int) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	full := append([]string{"policy", "validate"}, args...)
	full = append(full, "--store-root", t.TempDir())
	err := Run(full, &stdout, &stderr)
	return stdout.String(), ExitCodeForError(err)
}

func policyDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("WriteFile %s: %v", name, err)
		}
	}
	return dir
}

// A directory renders as one array with one object per file, not as a run of
// prose lines that no parser accepts.
func TestPolicyValidate_JSONDirectoryIsOneArray(t *testing.T) {
	dir := policyDir(t, map[string]string{
		"a.yaml": validPolicyYAML,
		"b.yml":  validPolicyYAML,
	})
	out, code := runPolicyValidateCLI(t, dir, "--json")
	if code != ExitOK {
		t.Fatalf("exit code = %d, want %d\n%s", code, ExitOK, out)
	}
	assertSingleJSONValue(t, "policy validate --json", []byte(out))

	var got []policyValidationJSON
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("decoding: %v\n%s", err, out)
	}
	if len(got) != 2 {
		t.Fatalf("got %d results, want one per file\n%s", len(got), out)
	}
	for _, r := range got {
		if !r.Passed || r.Error != "" {
			t.Errorf("%s: passed=%v error=%q, want a clean pass", r.File, r.Passed, r.Error)
		}
		if r.Schema != "depth-policy" {
			t.Errorf("%s: schema = %q, want depth-policy", r.File, r.Schema)
		}
		if filepath.Dir(r.File) != dir {
			t.Errorf("file = %q, want a path inside %s", r.File, dir)
		}
	}
}

// One valid file is still an array, and still exits 0.
func TestPolicyValidate_JSONSingleValidFile(t *testing.T) {
	dir := policyDir(t, map[string]string{"policy.yaml": validPolicyYAML})
	path := filepath.Join(dir, "policy.yaml")
	out, code := runPolicyValidateCLI(t, path, "--json")
	if code != ExitOK {
		t.Fatalf("exit code = %d, want %d\n%s", code, ExitOK, out)
	}
	assertSingleJSONValue(t, "policy validate --json", []byte(out))

	var got []policyValidationJSON
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("decoding: %v\n%s", err, out)
	}
	if len(got) != 1 || got[0].File != path || !got[0].Passed {
		t.Fatalf("got %+v, want one passing result for %s", got, path)
	}
}

// The flag changes rendering, never the verdict: a file that fails schema
// validation still exits non-zero, because a CI check reads that exit code.
func TestPolicyValidate_JSONInvalidFileKeepsItsExitCode(t *testing.T) {
	dir := policyDir(t, map[string]string{"bad.yaml": invalidPolicyYAML})
	path := filepath.Join(dir, "bad.yaml")

	textOut, textCode := runPolicyValidateCLI(t, path)
	jsonOutput, jsonCode := runPolicyValidateCLI(t, path, "--json")
	if textCode != ExitConfig {
		t.Errorf("text exit code = %d, want %d", textCode, ExitConfig)
	}
	if jsonCode != textCode {
		t.Errorf("--json exit code = %d, text exit code = %d: the flag must not change the verdict", jsonCode, textCode)
	}
	if textOut != "" {
		t.Errorf("text stdout = %q, want nothing", textOut)
	}
	assertSingleJSONValue(t, "policy validate --json", []byte(jsonOutput))

	var got []policyValidationJSON
	if err := json.Unmarshal([]byte(jsonOutput), &got); err != nil {
		t.Fatalf("decoding: %v\n%s", err, jsonOutput)
	}
	if len(got) != 1 {
		t.Fatalf("got %d results, want 1\n%s", len(got), jsonOutput)
	}
	if got[0].Passed {
		t.Error("the failing file is reported as passed")
	}
	if !strings.Contains(got[0].Error, "invalid policy") {
		t.Errorf("error = %q, want the schema diagnostic", got[0].Error)
	}
	if got[0].Schema != "depth-policy" {
		t.Errorf("schema = %q, want the schema it was routed to", got[0].Schema)
	}
}

// A mixed directory reports every file and still fails the run.
func TestPolicyValidate_JSONMixedDirectoryReportsEveryFile(t *testing.T) {
	dir := policyDir(t, map[string]string{
		"a.yaml": validPolicyYAML,
		"b.yaml": invalidPolicyYAML,
	})
	out, code := runPolicyValidateCLI(t, dir, "--json")
	if code != ExitConfig {
		t.Errorf("exit code = %d, want %d", code, ExitConfig)
	}
	assertSingleJSONValue(t, "policy validate --json", []byte(out))

	var got []policyValidationJSON
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("decoding: %v\n%s", err, out)
	}
	if len(got) != 2 {
		t.Fatalf("got %d results, want one per file\n%s", len(got), out)
	}
	passed := 0
	for _, r := range got {
		if r.Passed {
			passed++
		}
	}
	if passed != 1 {
		t.Errorf("%d files reported as passing, want 1\n%s", passed, out)
	}
}

// An empty directory is an empty array. Prose here is the defect: a caller
// that asked for JSON gets something no parser accepts, on the exact path
// where there is nothing to report.
func TestPolicyValidate_JSONEmptyDirectoryIsAnEmptyArray(t *testing.T) {
	out, code := runPolicyValidateCLI(t, t.TempDir(), "--json")
	if code != ExitOK {
		t.Fatalf("exit code = %d, want %d\n%s", code, ExitOK, out)
	}
	if out != "[]\n" {
		t.Fatalf("stdout = %q, want an empty array", out)
	}
}

// Without --json the rendering is byte-for-byte what it has always been. The
// expectations are written out rather than compared against a helper so that a
// change to the text output has to be made here, deliberately.
func TestPolicyValidate_TextRenderingIsUnchanged(t *testing.T) {
	valid := policyDir(t, map[string]string{"policy.yaml": validPolicyYAML})
	mixed := policyDir(t, map[string]string{"a.yaml": validPolicyYAML, "b.yaml": invalidPolicyYAML})
	empty := t.TempDir()

	badErr := "invalid policy (depth-policy schema): " +
		"policy schema version \"invalid\" is newer than supported \"1\"; " +
		"upgrade kanonarion to use this policy"

	for _, tc := range []struct {
		name string
		arg  string
		want string
		code int
	}{
		{
			name: "single valid file",
			arg:  filepath.Join(valid, "policy.yaml"),
			want: "ok: " + filepath.Join(valid, "policy.yaml") + " (depth-policy schema)\n",
			code: ExitOK,
		},
		{
			name: "directory of one",
			arg:  valid,
			want: "ok: " + filepath.Join(valid, "policy.yaml") + " (depth-policy schema)\n",
			code: ExitOK,
		},
		{
			name: "empty directory",
			arg:  empty,
			want: "no policy files found in " + empty + "\n",
			code: ExitOK,
		},
		{
			name: "mixed directory",
			arg:  mixed,
			want: "ok: " + filepath.Join(mixed, "a.yaml") + " (depth-policy schema)\n" +
				"FAIL: " + filepath.Join(mixed, "b.yaml") + ": " + badErr + "\n",
			code: ExitConfig,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, code := runPolicyValidateCLI(t, tc.arg)
			if out != tc.want {
				t.Errorf("stdout =\n%q\nwant\n%q", out, tc.want)
			}
			if code != tc.code {
				t.Errorf("exit code = %d, want %d", code, tc.code)
			}
		})
	}
}
