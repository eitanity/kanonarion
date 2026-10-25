package domain_test

import (
	"bytes"
	"reflect"
	"testing"

	domain3 "github.com/eitanity/kanonarion/internal/walk/domain"
)

// standardBuildEnvIdentity is the identity of the record below as the build
// before the TinyGo fields computed it. A standard walk must keep it.
const standardBuildEnvIdentity = "sha256:604441e353d5193df27be41df73afa297955d351669dbd0a0bbab93acd3bc762"

func identityWithEnv(t *testing.T, env domain3.BuildEnv) string {
	t.Helper()
	outcome := buildOutcome(t)
	outcome.Graph.BuildEnv = env
	return identityOf(t, "01ARZ3NDEKTSV4RRFFQ69G5FAV", "alice", outcome)
}

func tinyGoEnv() domain3.BuildEnv {
	return domain3.BuildEnv{
		GOOS: "linux", GOARCH: "arm", GoVersion: "go1.27.2", GOARM: "6",
		TinyGoTarget: "pico", TinyGoVersion: "0.42.0", TinyGoTags: []string{"cortexm", "baremetal", "pico", "tinygo"},
	}
}

func TestWalkIdentity_AStandardBuildEnvHashesAsBefore(t *testing.T) {
	env := domain3.BuildEnv{GOOS: "linux", GOARCH: "arm64", GoVersion: "go1.26.4"}
	if got := identityWithEnv(t, env); got != standardBuildEnvIdentity {
		t.Errorf("a walk with no TinyGo frame changed identity: %s, want %s", got, standardBuildEnvIdentity)
	}

	rec := domain3.NewWalkRecord("01ARZ3NDEKTSV4RRFFQ69G5FAV", "ci-bot", "0.2.0", domain3.WalkScopeCode, domain3.WalkDepthFull, buildOutcome(t), domain3.DefaultDepthPolicy(), "")
	rec.Graph.BuildEnv = env
	data, err := domain3.WalkRecordHasher{}.Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if want := []byte(`"build_env":{"goarch":"arm64","goos":"linux","go_version":"go1.26.4"}`); !bytes.Contains(data, want) {
		t.Errorf("a standard build_env no longer marshals as %s:\n%s", want, data)
	}
}

func TestWalkIdentity_CoversTheTinyGoFrame(t *testing.T) {
	base := identityWithEnv(t, tinyGoEnv())
	if base == identityWithEnv(t, domain3.BuildEnv{GOOS: "linux", GOARCH: "arm", GoVersion: "go1.27.2"}) {
		t.Fatal("a TinyGo walk has the identity of a standard linux/arm walk")
	}
	for name, change := range map[string]func(*domain3.BuildEnv){
		"one tag":        func(e *domain3.BuildEnv) { e.TinyGoTags[1] = "baremetal2" },
		"target":         func(e *domain3.BuildEnv) { e.TinyGoTarget = "pico2" },
		"TinyGo version": func(e *domain3.BuildEnv) { e.TinyGoVersion = "0.43.0" },
		"GOARM":          func(e *domain3.BuildEnv) { e.GOARM = "7" },
	} {
		env := tinyGoEnv()
		change(&env)
		if got := identityWithEnv(t, env); got == base {
			t.Errorf("changing the %s left the identity at %s", name, base)
		}
	}
}

func TestWalkRecordHasher_TinyGoBuildEnvRoundTrip(t *testing.T) {
	hasher := domain3.WalkRecordHasher{}
	rec := domain3.NewWalkRecord("01ARZ3NDEKTSV4RRFFQ69G5FAV", "ci-bot", "0.2.0", domain3.WalkScopeCode, domain3.WalkDepthFull, buildOutcome(t), domain3.DefaultDepthPolicy(), "")
	rec.Graph.BuildEnv = tinyGoEnv()
	rec, err := hasher.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	data, err := hasher.Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	back, err := hasher.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(back.Graph.BuildEnv, rec.Graph.BuildEnv) {
		t.Errorf("BuildEnv after round-trip = %+v, want %+v", back.Graph.BuildEnv, rec.Graph.BuildEnv)
	}
	if verr := hasher.VerifyContentHash(back); verr != nil {
		t.Errorf("a TinyGo walk does not verify after a round trip: %v", verr)
	}
}

func TestFrameOf_ATinyGoWalkNamesItsTarget(t *testing.T) {
	got := domain3.FrameOf(mustFrameCoord(t, "example.com/proj", "local"), tinyGoEnv())
	if got.Text != "tinygo/pico (linux/arm)" || got.Basis != domain3.FrameBasisPlatform {
		t.Errorf("FrameOf = %+v", got)
	}
	if (domain3.BuildEnv{TinyGoTarget: "pico"}).IsZero() {
		t.Error("a TinyGo build environment reports itself zero")
	}
}
