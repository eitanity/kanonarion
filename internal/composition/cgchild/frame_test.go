package cgchild

import (
	"strings"
	"testing"

	cgdomain "code.eitanity.com/kanonarion/internal/callgraph/domain"
	walkdomain "code.eitanity.com/kanonarion/internal/walk/domain"
)

// The discovery search passes over a consumer walk of another frame, and the
// notice counts it.
func TestFramePassedOverClause(t *testing.T) {
	host := cgdomain.BuildFrame{GOOS: "linux", GOARCH: "amd64"}
	if got := framePassedOverClause(0, host); got != "" {
		t.Errorf("nothing passed over still says %q", got)
	}
	if got := framePassedOverClause(2, host); !strings.Contains(got, "2 walk(s) resolved for a frame other than "+host.String()) {
		t.Errorf("clause = %q", got)
	}
	env := walkdomain.BuildEnv{GOOS: "linux", GOARCH: "arm"}
	if !WalkFrameMatches(env, cgdomain.BuildFrame{GOOS: "linux", GOARCH: "arm", GOARM: "7"}) {
		t.Error("a standard walk records no GOARM and was refused for stating none")
	}
	env.GOARM, env.TinyGoTarget = "6", "pico"
	if WalkFrameMatches(env, cgdomain.BuildFrame{GOOS: "linux", GOARCH: "arm", GOARM: "7"}) {
		t.Error("a pico walk matched a plain linux/arm frame")
	}
}
