package goenv_test

import (
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/goenv"
)

// TestTargetApply_MatchesTheDeclaredTargetPosture holds the one producer that
// names a platform against the one posture that states it, on the same terms
// every other producer in this repository is held to.
func TestTargetApply_MatchesTheDeclaredTargetPosture(t *testing.T) {
	base := []string{"PATH=/usr/bin"}

	checkPosture(t, "declared-target", base, goenv.PostureTarget.Apply(base))
}

// TestTargetApply_UndeclaredWritesTheHostAnyway is the leak this type closes.
// Nothing was asked for, an export is in scope, and the child must still be told
// the platform the invocation is actually about.
func TestTargetApply_UndeclaredWritesTheHostAnyway(t *testing.T) {
	base := []string{"PATH=/usr/bin", "GOOS=windows", "GOARCH=arm64"}

	got := goenv.Target{}.Apply(base)

	if goos := lastEnvValue(got, "GOOS"); goos != runtime.GOOS {
		t.Errorf("the child sees GOOS=%q, want the measured host %q — an undeclared target must not "+
			"let an inherited export choose the platform", goos, runtime.GOOS)
	}
	if goarch := lastEnvValue(got, "GOARCH"); goarch != runtime.GOARCH {
		t.Errorf("the child sees GOARCH=%q, want the measured host %q", goarch, runtime.GOARCH)
	}
}

// TestTargetApply_DeclaredBeatsAnInheritedExport is the other half: a
// declaration wins over the environment, whichever way the environment leans.
func TestTargetApply_DeclaredBeatsAnInheritedExport(t *testing.T) {
	base := []string{"PATH=/usr/bin", "GOOS=windows", "GOARCH=arm64"}
	declared, err := goenv.ParseTarget("wasip1/wasm")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}

	got := declared.Apply(base)

	if goos, goarch := lastEnvValue(got, "GOOS"), lastEnvValue(got, "GOARCH"); goos != "wasip1" || goarch != "wasm" {
		t.Errorf("the child sees %s/%s, want wasip1/wasm", goos, goarch)
	}
}

// TestTargetApply_DoesNotMutateTheCallersSlice pins the copy-on-append: every
// caller layers this onto an environment another producer built, and the three
// layers must not write through each other.
func TestTargetApply_DoesNotMutateTheCallersSlice(t *testing.T) {
	base := make([]string, 1, 8)
	base[0] = "PATH=/usr/bin"

	_ = goenv.PostureTarget.Apply(base)

	if len(base) != 1 || base[0] != "PATH=/usr/bin" {
		t.Errorf("Apply rewrote the caller's environment: %v", base)
	}
}

// TestNewTarget_RefusesHalfAPair is the zero-value refusal this value object
// needs: half a declaration is one whose other half comes from the environment,
// which is exactly what declaring a target is for.
func TestNewTarget_RefusesHalfAPair(t *testing.T) {
	for _, tc := range []struct{ goos, goarch, want string }{
		{"", "", "both halves"},
		{"linux", "", "without a GOARCH"},
		{"", "amd64", "without a GOOS"},
	} {
		got, err := goenv.NewTarget(tc.goos, tc.goarch)
		if err == nil {
			t.Errorf("NewTarget(%q, %q) = %s, want a refusal", tc.goos, tc.goarch, got)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("NewTarget(%q, %q) refused with %q, which does not say %q", tc.goos, tc.goarch, err, tc.want)
		}
	}
}

// TestParseTarget_ReadsTheCanonicalPair holds the spelling docs and `go tool
// dist list` share, and the refusal for everything else.
func TestParseTarget_ReadsTheCanonicalPair(t *testing.T) {
	got, err := goenv.ParseTarget(" wasip1/wasm ")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	if got.String() != "wasip1/wasm" {
		t.Errorf("ParseTarget = %s, want wasip1/wasm", got)
	}
	if _, err := goenv.ParseTarget("wasip1"); err == nil {
		t.Error("a bare GOOS parsed as a pair")
	}
}

// TestTarget_UndeclaredSaysSo keeps a half-rendered pair out of a refusal: a
// message naming "/" for a target nobody declared says nothing a reader can act
// on.
func TestTarget_UndeclaredSaysSo(t *testing.T) {
	var undeclared goenv.Target
	if undeclared.Declared() {
		t.Error("the zero value reports itself as a declaration")
	}
	if got := undeclared.String(); got != "undeclared" {
		t.Errorf("the zero value renders as %q", got)
	}
	if !undeclared.IsHost() || undeclared.OrHost() != goenv.Host() {
		t.Error("an undeclared target must resolve to the measured host")
	}
}

// TestPostureTarget_IsNotThisHost is the control on the posture assertion: a
// producer that dropped the declaration and left the ambient pair in place would
// pass against a table stated on the host's own platform.
func TestPostureTarget_IsNotThisHost(t *testing.T) {
	if goenv.PostureTarget.IsHost() {
		t.Errorf("the posture is stated against %s, which is this host — pick a pair the suite can never be "+
			"run on, or the assertion cannot fail", goenv.PostureTarget)
	}
}

// TestPostureTarget_IsAPairTheToolchainKnows keeps the posture's pair usable by
// the tests that share these producers with a real go command.
func TestPostureTarget_IsAPairTheToolchainKnows(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("the go toolchain is not on PATH; this test measures what it supports")
	}
	out, err := exec.Command("go", "tool", "dist", "list").Output() // #nosec G204 -- fixed binary, literal arguments
	if err != nil {
		t.Skipf("go tool dist list: %v", err)
	}
	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimSpace(line) == goenv.PostureTarget.String() {
			return
		}
	}
	t.Errorf("the posture is stated against %s, which this toolchain does not build for", goenv.PostureTarget)
}

// lastEnvValue is what a child resolves a key to: the last entry wins.
func lastEnvValue(env []string, key string) string {
	value := ""
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == key {
			value = v
		}
	}
	return value
}
