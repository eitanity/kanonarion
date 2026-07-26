package gitenv_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/vcs/gitenv"
)

// envMap indexes a KEY=VALUE block. A duplicate key is a defect in itself: it
// would mean the block relies on the child's getenv resolution order to decide
// which value wins, which is exactly the weakness the allowlist replaced.
func envMap(t *testing.T, env []string) map[string]string {
	t.Helper()
	m := make(map[string]string, len(env))
	for _, entry := range env {
		key, val, ok := strings.Cut(entry, "=")
		if !ok {
			t.Errorf("malformed environment entry %q", entry)
			continue
		}
		if _, dup := m[key]; dup {
			t.Errorf("duplicate key %q in the environment block", key)
		}
		m[key] = val
	}
	return m
}

// A hostile GIT_CONFIG_* in the parent must be absent from the child's block,
// not merely followed by an override.
func TestBase_DropsInheritedConfigVariables(t *testing.T) {
	t.Setenv("GIT_CONFIG_GLOBAL", "/poisoned/global")
	t.Setenv("GIT_CONFIG_SYSTEM", "/poisoned/system")
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "core.hooksPath")
	t.Setenv("GIT_CONFIG_VALUE_0", "/poisoned")
	t.Setenv("XDG_CONFIG_HOME", "/poisoned/xdg")
	t.Setenv("HOME", "/poisoned/home")

	home, workDir := t.TempDir(), t.TempDir()
	env := envMap(t, gitenv.Base(home, workDir, "https"))

	if got := env["GIT_CONFIG_GLOBAL"]; got != "/dev/null" {
		t.Errorf("GIT_CONFIG_GLOBAL = %q, want /dev/null", got)
	}
	if got := env["GIT_CONFIG_SYSTEM"]; got != "/dev/null" {
		t.Errorf("GIT_CONFIG_SYSTEM = %q, want /dev/null", got)
	}
	if got := env["HOME"]; got != home {
		t.Errorf("HOME = %q, want the isolated %q", got, home)
	}
	for _, key := range []string{"GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0", "XDG_CONFIG_HOME"} {
		if val, present := env[key]; present {
			t.Errorf("%s survived into the child environment as %q", key, val)
		}
	}
}

// The variables that make git work on a constrained network are the ones that
// cannot name a config file or a command, and they must still be passed.
func TestBase_PassesTransportVariables(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://proxy.example:8080")
	t.Setenv("SSL_CERT_FILE", "/etc/ssl/custom.pem")

	env := envMap(t, gitenv.Base(t.TempDir(), t.TempDir(), "https"))

	if got := env["HTTPS_PROXY"]; got != "http://proxy.example:8080" {
		t.Errorf("HTTPS_PROXY = %q, want it passed through", got)
	}
	if got := env["SSL_CERT_FILE"]; got != "/etc/ssl/custom.pem" {
		t.Errorf("SSL_CERT_FILE = %q, want it passed through", got)
	}
	if got := env["GIT_ALLOW_PROTOCOL"]; got != "https" {
		t.Errorf("GIT_ALLOW_PROTOCOL = %q, want https", got)
	}
}

// The discovery ceiling is the parent of the working directory, never the
// directory itself: a checkout that is deliberately a repository must still
// find its own .git, while discovery cannot walk above it.
func TestBase_CeilingIsTheParentOfWorkDir(t *testing.T) {
	workDir := t.TempDir()
	env := envMap(t, gitenv.Base(t.TempDir(), workDir, "https"))

	if got, want := env["GIT_CEILING_DIRECTORIES"], filepath.Dir(workDir); got != want {
		t.Errorf("GIT_CEILING_DIRECTORIES = %q, want %q", got, want)
	}
	if env["GIT_CEILING_DIRECTORIES"] == workDir {
		t.Error("the ceiling must not be the working directory itself; a real checkout would stop finding its own .git")
	}
}

func TestScratchHome_IsPrivateEmptyAndRemoved(t *testing.T) {
	dir, cleanup, err := gitenv.ScratchHome()
	if err != nil {
		t.Fatalf("ScratchHome: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("scratch HOME is not empty: %v", entries)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("scratch HOME mode = %o, want no group/other access", perm)
	}

	cleanup()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("scratch HOME survived cleanup: %v", err)
	}
}

// The -c overrides must close the sinks that a config file could otherwise
// reopen, and they must be well-formed -c pairs.
func TestConfigArgs_ClosesExecutionSinks(t *testing.T) {
	args := gitenv.ConfigArgs()
	if len(args)%2 != 0 {
		t.Fatalf("args %v are not -c/value pairs", args)
	}
	settings := make(map[string]bool)
	for i := 0; i < len(args); i += 2 {
		if args[i] != "-c" {
			t.Errorf("args[%d] = %q, want -c", i, args[i])
		}
		settings[args[i+1]] = true
	}
	for _, want := range []string{"core.hooksPath=/dev/null", "core.fsmonitor=", "protocol.ext.allow=never"} {
		if !settings[want] {
			t.Errorf("missing override %q in %v", want, args)
		}
	}
}
