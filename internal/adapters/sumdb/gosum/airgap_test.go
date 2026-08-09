package gosum

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
)

// clearSumEnv puts every variable this adapter reads into a known state, so a
// subtest asserts on what it sets rather than on what the developer's shell
// happens to hold.
func clearSumEnv(t *testing.T) {
	t.Helper()
	t.Setenv("GOENV", filepath.Join(t.TempDir(), "absent"))
	for _, k := range []string{"GOSUMDB", "GOPROXY", "GOPRIVATE", "GONOSUMCHECK", "GONOSUMDB"} {
		t.Setenv(k, "")
	}
}

// TestNew_ControlBuildsALiveClient is the non-zero control for both refusals
// below: with nothing declared, the client is live and a lookup would reach the
// checksum database.
func TestNew_ControlBuildsALiveClient(t *testing.T) {
	clearSumEnv(t)
	t.Setenv("GOPROXY", "https://proxy.example.com")

	c := New(t.TempDir())
	if c.disabledReason != "" {
		t.Fatalf("client disabled with reason %q; nothing declared it off", c.disabledReason)
	}
	if c.newOps == nil {
		t.Error("live client has no ops builder, so no transport would ever be built")
	}
}

// TestNew_GOPROXYOffDisablesTheChecksumDatabase: the go command reaches the
// checksum database through $GOPROXY, so an environment that declares
// GOPROXY=off has declared this traffic away too. The refusal is at
// construction, so no sumdb client and therefore no transport is ever built.
func TestNew_GOPROXYOffDisablesTheChecksumDatabase(t *testing.T) {
	clearSumEnv(t)
	t.Setenv("GOPROXY", "off")

	c := New(t.TempDir())
	if c.newOps != nil {
		t.Error("an ops builder was wired under GOPROXY=off; the client must have no way to dial")
	}
	res := c.Lookup(context.Background(), coordinatetest.MustNew("example.com/mod", "v1.0.0"))
	if res.Available {
		t.Error("Lookup reported available under GOPROXY=off")
	}
	if !strings.Contains(res.Reason, "GOPROXY=off") {
		t.Errorf("reason = %q, want it to name GOPROXY=off", res.Reason)
	}
	if res.LookupFailed() {
		t.Error("an operator's declaration must be a policy answer, not a failure a retry could change")
	}
}

// TestNew_GOPROXYOffFromEnvFile: the declaration counts wherever Go would read
// it, including the file `go env -w` writes and the process environment never
// shows.
func TestNew_GOPROXYOffFromEnvFile(t *testing.T) {
	clearSumEnv(t)
	path := filepath.Join(t.TempDir(), "env")
	if err := os.WriteFile(path, []byte("GOPROXY=off\n"), 0o600); err != nil {
		t.Fatalf("writing env file: %v", err)
	}
	t.Setenv("GOENV", path)

	if c := New(t.TempDir()); c.disabledReason == "" {
		t.Error("`go env -w GOPROXY=off` left the checksum-database client live")
	}
}

// TestNoSumCheck_BooleanIsNotAPattern is the second half of the sumdb member.
// GONOSUMCHECK=1 is the legacy boolean; read as a pattern list it matches the
// module path "1" and nothing else, so an operator who switched the database
// off had it left on for every module they own.
func TestNoSumCheck_BooleanIsNotAPattern(t *testing.T) {
	clearSumEnv(t)
	t.Setenv("GOPROXY", "https://proxy.example.com")
	t.Setenv("GONOSUMCHECK", "1")

	c := New(t.TempDir())
	if c.disabledReason == "" {
		t.Fatal("GONOSUMCHECK=1 left the checksum database on")
	}
	res := c.Lookup(context.Background(), coordinatetest.MustNew("example.com/mod", "v1.0.0"))
	if res.Available {
		t.Error("Lookup reported available under GONOSUMCHECK=1")
	}
	if got := noSumPatterns(); len(got) != 0 {
		t.Errorf("noSumPatterns() = %v, want none: the boolean form is not a pattern list", got)
	}
}

// TestNoSumCheck_PatternFormStillWorks is the control for the boolean fix: a
// GONOSUMCHECK naming module prefixes keeps its pattern meaning and does not
// switch the database off wholesale.
func TestNoSumCheck_PatternFormStillWorks(t *testing.T) {
	clearSumEnv(t)
	t.Setenv("GOPROXY", "https://proxy.example.com")
	t.Setenv("GONOSUMCHECK", "corp.example.com")

	c := New(t.TempDir())
	if c.disabledReason != "" {
		t.Fatalf("a pattern list disabled the whole client: %q", c.disabledReason)
	}
	if !matchesNoSum("corp.example.com/internal/thing") {
		t.Error("pattern did not match the module it names")
	}
	if matchesNoSum("example.com/other") {
		t.Error("pattern matched a module it does not name")
	}
}

// TestGOSUMDBOff_StillTakesPrecedence guards the pre-existing behaviour whose
// message shape the new reasons follow.
func TestGOSUMDBOff_StillTakesPrecedence(t *testing.T) {
	clearSumEnv(t)
	t.Setenv("GOSUMDB", "off")
	t.Setenv("GOPROXY", "https://proxy.example.com")

	res := New(t.TempDir()).Lookup(context.Background(), coordinatetest.MustNew("example.com/mod", "v1.0.0"))
	if res.Reason != "GOSUMDB=off" {
		t.Errorf("reason = %q, want GOSUMDB=off", res.Reason)
	}
}
