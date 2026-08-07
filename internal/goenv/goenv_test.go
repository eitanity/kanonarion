package goenv_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/eitanity/kanonarion/internal/goenv"
)

// writeEnvFile writes a Go env file at a path unique to this subtest and points
// $GOENV at it. A unique path matters: the parsed file is cached per path, and
// two subtests sharing one would read the first one's contents.
func writeEnvFile(t *testing.T, contents string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "env")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("writing env file: %v", err)
	}
	t.Setenv("GOENV", path)
}

// noEnvFile points $GOENV at a path that does not exist, so a test asserting on
// the environment variable alone cannot be answered by whatever this developer's
// real ~/.config/go/env happens to say.
func noEnvFile(t *testing.T) {
	t.Helper()
	t.Setenv("GOENV", filepath.Join(t.TempDir(), "absent"))
}

// TestValue_EnvironmentWinsOverFile pins the go command's precedence: a
// variable set in the process environment is the answer, and the env file is
// not consulted for it.
func TestValue_EnvironmentWinsOverFile(t *testing.T) {
	writeEnvFile(t, "GOPROXY=off\n")
	t.Setenv("GOPROXY", "https://proxy.example.com")

	if got := goenv.Proxy(); got != "https://proxy.example.com" {
		t.Errorf("Proxy() = %q, want the environment's value", got)
	}
	if goenv.NetworkForbidden() {
		t.Error("NetworkForbidden() = true; the environment names a proxy and outranks the file")
	}
}

// TestValue_FileConsultedWhenUnset is member 5's whole point: `go env -w
// GOPROXY=off` sets nothing in the process environment, and a reader that only
// looked at os.Getenv saw an operator's declared air gap as "unset".
func TestValue_FileConsultedWhenUnset(t *testing.T) {
	writeEnvFile(t, "GOPROXY=off\nGOSUMDB=sum.golang.org\n")
	t.Setenv("GOPROXY", "")

	if got := goenv.Proxy(); got != "off" {
		t.Errorf("Proxy() = %q, want off read from the env file", got)
	}
	if !goenv.NetworkForbidden() {
		t.Error("NetworkForbidden() = false; `go env -w GOPROXY=off` must forbid the network")
	}
	if got := goenv.Value("GOSUMDB"); got != "sum.golang.org" {
		t.Errorf("Value(GOSUMDB) = %q, want the file's value", got)
	}
}

// TestValue_EmptyEnvironmentFallsThrough guards the distinction the go command
// draws: an empty variable is "this shell says nothing", not "this shell says
// empty", so the file still answers.
func TestValue_EmptyEnvironmentFallsThrough(t *testing.T) {
	writeEnvFile(t, "GOPRIVATE=corp.example.com\n")
	t.Setenv("GOPRIVATE", "")

	if got := goenv.Value("GOPRIVATE"); got != "corp.example.com" {
		t.Errorf("Value(GOPRIVATE) = %q, want the file's value", got)
	}
}

// TestValue_GOENVOff disables the env file entirely, as the go command does.
func TestValue_GOENVOff(t *testing.T) {
	t.Setenv("GOENV", "off")
	t.Setenv("GOPROXY", "")

	if got := goenv.Proxy(); got != "" {
		t.Errorf("Proxy() = %q, want empty: GOENV=off means no file is read", got)
	}
	if goenv.NetworkForbidden() {
		t.Error("NetworkForbidden() = true with no source naming off")
	}
}

// TestValue_AbsentFileIsNotAnError: the env file is optional, and a process
// without one must not behave differently from one whose file is empty.
func TestValue_AbsentFileIsNotAnError(t *testing.T) {
	noEnvFile(t)
	t.Setenv("GOPROXY", "")

	if got := goenv.Proxy(); got != "" {
		t.Errorf("Proxy() = %q, want empty", got)
	}
}

// TestParse_MalformedLinesIgnored: a hand-edited file must not make an egress
// decision unreadable. Lines without "=" and lines with an empty key are
// skipped; the rest still answer.
func TestParse_MalformedLinesIgnored(t *testing.T) {
	writeEnvFile(t, "\r\nnot-an-assignment\n=novalue\nGOPROXY=off\r\nGOFLAGS=-mod=mod\n")
	t.Setenv("GOPROXY", "")

	if got := goenv.Proxy(); got != "off" {
		t.Errorf("Proxy() = %q, want off", got)
	}
	if got := goenv.Value("GOFLAGS"); got != "-mod=mod" {
		t.Errorf("Value(GOFLAGS) = %q, want -mod=mod (a value containing '=' keeps it)", got)
	}
}

// TestFirstProxyEntry_Grammar pins Go's list grammar, including the case that
// decides whether the air gap is honoured: `off` first terminates the chain,
// while `off` after a URL is never reached.
func TestFirstProxyEntry_Grammar(t *testing.T) {
	for _, tc := range []struct{ list, want string }{
		{"", ""},
		{",,", ""},
		{"off", "off"},
		{" off ", "off"},
		{"off,https://proxy.example.com", "off"},
		{"https://proxy.example.com,off", "https://proxy.example.com"},
		{"https://a|https://b", "https://a"},
		{",off|direct", "off"},
		{"direct", "direct"},
	} {
		if got := goenv.FirstProxyEntry(tc.list); got != tc.want {
			t.Errorf("FirstProxyEntry(%q) = %q, want %q", tc.list, got, tc.want)
		}
	}
}

// TestNetworkForbidden_OnlyOff: `direct` is a different route to the network,
// not the absence of one, and must not be read as an air gap.
func TestNetworkForbidden_OnlyOff(t *testing.T) {
	noEnvFile(t)
	for _, tc := range []struct {
		proxy string
		want  bool
	}{
		{"off", true},
		{"OFF", false}, // the go command is case-sensitive here; so is this
		{"direct", false},
		{"", false},
		{"https://proxy.example.com", false},
		{"https://proxy.example.com,off", false},
		{"off,https://proxy.example.com", true},
	} {
		t.Setenv("GOPROXY", tc.proxy)
		if got := goenv.NetworkForbidden(); got != tc.want {
			t.Errorf("NetworkForbidden() with GOPROXY=%q = %v, want %v", tc.proxy, got, tc.want)
		}
	}
}

// BenchmarkNetworkForbidden measures what every egress decision now pays. The
// env file is read once per process and cached per path, so the steady-state
// cost is the cached map lookup, not a syscall.
func BenchmarkNetworkForbidden(b *testing.B) {
	b.Setenv("GOENV", filepath.Join(b.TempDir(), "absent"))
	b.Setenv("GOPROXY", "")
	for b.Loop() {
		_ = goenv.NetworkForbidden()
	}
}

// BenchmarkNetworkForbidden_EveryResolutionReadsTheFile measures the
// pessimistic case the cache exists to avoid: a resolution that has to open,
// read and parse the env file. It defeats the cache by alternating $GOENV
// between two files, so the per-op figure includes one os.Setenv as well as the
// read — an over-estimate, which is the safe direction for a cost claim.
func BenchmarkNetworkForbidden_EveryResolutionReadsTheFile(b *testing.B) {
	dir := b.TempDir()
	paths := [2]string{filepath.Join(dir, "a"), filepath.Join(dir, "b")}
	for _, path := range paths {
		if err := os.WriteFile(path, []byte("GOPROXY=off\nGOFLAGS=-mod=mod\nGOSUMDB=sum.golang.org\n"), 0o600); err != nil {
			b.Fatalf("writing env file: %v", err)
		}
	}
	b.Setenv("GOPROXY", "")
	b.Setenv("GOENV", paths[0])
	var i int
	for b.Loop() {
		i++
		if err := os.Setenv("GOENV", paths[i%2]); err != nil {
			b.Fatalf("setting GOENV: %v", err)
		}
		_ = goenv.NetworkForbidden()
	}
}
