package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runCLIErr runs one invocation and returns stdout, the refusal's text and the
// exit code; the refusal is printed by main, not by Run.
func runCLIErr(t *testing.T, args ...string) (stdout, refusal string, code int) {
	t.Helper()
	isolateInvocationState(t)
	var out, errBuf bytes.Buffer
	err := Run(args, &out, &errBuf)
	if err != nil {
		refusal = err.Error()
	}
	return out.String(), refusal, ExitCodeForError(err)
}

// writeStoreConfig writes body as the config file of a fresh store.
func writeStoreConfig(t *testing.T, body string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "config.yaml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

// Each config.yaml that once loaded and changed nothing is now refused at exit
// 20, naming the file and the key, while `config show` still reports it.
func TestConfigFile_UnknownKeyOrRefusedValueIsARejection(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{"licence_policy: {default: warn}", `unknown key "licence_policy" (did you mean "license_policy"?)`},
		{"preferences: {log_level: verbose}", `preferences.log_level must be one of: debug, info, warn, error; got "verbose"`},
		{"fetch_policy: {alowed_vcs_hosts: [example.org]}", `unknown key "fetch_policy.alowed_vcs_hosts" (did you mean "allowed_vcs_hosts"?)`},
		{"postgres: {url: x}", `unknown key "postgres"`},
	} {
		root := writeStoreConfig(t, "version: \"3\"\n"+tc.body+"\n")
		path := filepath.Join(root, "config.yaml")

		_, refusal, code := runCLIErr(t, "walk-list", "--store-root", root)
		if code != ExitConfig {
			t.Errorf("%s: walk-list exit = %d, want %d", tc.body, code, ExitConfig)
		}
		if !strings.Contains(refusal, "config file "+path+" was rejected: "+tc.want) {
			t.Errorf("%s: walk-list refusal does not name the file and the refusal:\n%s", tc.body, refusal)
		}

		out, _, code := runCLI(t, "config", "show", "--store-root", root)
		if code != ExitOK {
			t.Errorf("%s: config show exit = %d, want %d", tc.body, code, ExitOK)
		}
		if !strings.Contains(out, "was REJECTED and is NOT in force: "+tc.want) {
			t.Errorf("%s: config show does not state the rejection:\n%s", tc.body, out)
		}
	}
}

// The registered backend's own section is not an unknown key.
func TestConfigFile_RegisteredBackendSectionLoads(t *testing.T) {
	root := writeStoreConfig(t, "version: \"3\"\nsqlite:\n  # nothing set\n")
	if _, refusal, code := runCLIErr(t, "walk-list", "--store-root", root); code == ExitConfig {
		t.Fatalf("sqlite section refused:\n%s", refusal)
	}
}

// `config set` refuses with the words the loader uses for the same value.
func TestConfigSet_RefusesLikeTheLoader(t *testing.T) {
	root := t.TempDir()
	_, refusal, code := runCLIErr(t, "config", "set", "preferences.log_level", "verbose", "--store-root", root)
	if code != ExitConfig {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(refusal, `preferences.log_level must be one of: debug, info, warn, error; got "verbose"`) {
		t.Errorf("refusal = %s", refusal)
	}
	_, refusal, code = runCLIErr(t, "config", "set", "--store-root", root, "--", "staleness.ttl", "-1h")
	if code != ExitConfig || !strings.Contains(refusal, `staleness.ttl must not be negative (use 0 to disable the ledger), got "-1h"`) {
		t.Errorf("negative ttl: exit %d, refusal %s", code, refusal)
	}
}

// `policy validate` fails on the inputs the loaders refuse, in the same words,
// naming the file.
func TestPolicyValidate_RefusesUnknownKeys(t *testing.T) {
	for name, tc := range map[string]struct{ body, want string }{
		"depth-top.yaml":     {"version: \"1\"\nstage:\n  fetch:\n    allowed_vcs_hosts: [example.org]\n", `unknown key "stage" in %s (did you mean "stages"?)`},
		"depth-field.yaml":   {"version: \"1\"\nstages:\n  fetch:\n    allowed_vcs_host: [example.org]\n", `unknown key "stages.fetch.allowed_vcs_host" in %s (did you mean "allowed_vcs_hosts"?)`},
		"depth-stage.yaml":   {"version: \"1\"\nstages:\n  fecth:\n    max_depth: 1\n", `unknown key "stages.fecth" in %s (did you mean "fetch"?)`},
		"gov-nested.yaml":    {"version: \"3\"\nfetch_policy: {alowed_vcs_hosts: [example.org]}\n", `unknown key "fetch_policy.alowed_vcs_hosts" in %s (did you mean "allowed_vcs_hosts"?)`},
		"gov-value.yaml":     {"version: \"3\"\npreferences: {log_level: verbose}\n", `preferences.log_level must be one of: debug, info, warn, error; got "verbose"`},
		"gov-backend.yaml":   {"version: \"3\"\npreferences: {json: true}\nsqlite:\n  # nothing\n", ""},
		"gov-unknown.yaml":   {"version: \"3\"\npreferences: {json: true}\npostgres: {url: x}\n", `unknown key "postgres" in %s`},
		"gov-storage.yaml":   {"version: \"3\"\nstorage:\n  backend: sqlite\n", ""},
		"depth-control.yaml": {"version: \"1\"\nstages:\n  fetch:\n    allowed_vcs_hosts: [example.org]\n", ""},
	} {
		dir := policyDir(t, map[string]string{name: tc.body})
		path := filepath.Join(dir, name)
		_, refusal, code := runCLIErr(t, "policy", "validate", path, "--store-root", t.TempDir())
		if tc.want == "" {
			if code != ExitOK {
				t.Errorf("%s: exit %d, refusal %s", name, code, refusal)
			}
			continue
		}
		want := strings.Replace(tc.want, "%s", path, 1)
		if code != ExitConfig || !strings.Contains(refusal, want) {
			t.Errorf("%s: exit %d, refusal %s\nwant %s", name, code, refusal, want)
		}
	}
}
