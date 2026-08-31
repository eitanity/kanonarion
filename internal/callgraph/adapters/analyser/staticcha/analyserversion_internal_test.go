package staticcha

import (
	"runtime/debug"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
)

// TestAnalyserFromBuildInfo measures the extraction against build info handed
// in, because the real read cannot be measured from inside the suite: a `go
// test` binary carries ten build settings and ZERO dependency entries, so a test
// that called debug.ReadBuildInfo would only assert that it is a test binary.
// The production read is confirmed the other way — `go version -m` on a built
// kanonarion prints the `dep golang.org/x/tools` line this walks.
func TestAnalyserFromBuildInfo(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		info *debug.BuildInfo
		ok   bool
		want domain.AnalyserIdentity
	}{
		{
			name: "the linked version is observed",
			info: &debug.BuildInfo{Deps: []*debug.Module{
				{Path: "modernc.org/sqlite", Version: "v1.40.0"},
				{Path: "golang.org/x/tools", Version: "v0.49.0"},
			}},
			ok:   true,
			want: domain.ObservedAnalyser("v0.49.0"),
		},
		{
			name: "a replacement is what actually parsed the code",
			info: &debug.BuildInfo{Deps: []*debug.Module{{
				Path:    "golang.org/x/tools",
				Version: "v0.49.0",
				Replace: &debug.Module{Path: "golang.org/x/tools", Version: "v0.47.0"},
			}}},
			ok:   true,
			want: domain.ObservedAnalyser("v0.47.0"),
		},
		{
			// A replacement pointing at a directory states no version. Reporting the
			// replaced module's version there would name a library that did not run.
			name: "a directory replacement states no version",
			info: &debug.BuildInfo{Deps: []*debug.Module{{
				Path:    "golang.org/x/tools",
				Version: "v0.49.0",
				Replace: &debug.Module{Path: "../tools"},
			}}},
			ok: true,
		},
		{
			name: "a build that does not link the analyser says nothing",
			info: &debug.BuildInfo{Deps: []*debug.Module{{Path: "modernc.org/sqlite", Version: "v1.40.0"}}},
			ok:   true,
		},
		{
			name: "a test binary carries no dependency list",
			info: &debug.BuildInfo{},
			ok:   true,
		},
		{
			name: "no build info at all",
			ok:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := analyserFromBuildInfo(tc.info, tc.ok)
			if got != tc.want {
				t.Errorf("analyserFromBuildInfo = %+v, want %+v", got, tc.want)
			}
			// Whatever it reports, it never reports a guess: this seam reads a
			// measurement or it reads nothing.
			if got.IsInferred() {
				t.Errorf("the build-info read produced an inferred identity: %+v", got)
			}
		})
	}
}

// TestObservedAnalyser_NeverInfers pins the same rule on the memoised reader the
// analyser actually calls. Under `go test` it answers "not recorded", which is
// the truth about a binary with no dependency list; what it must never do is
// reconstruct one.
func TestObservedAnalyser_NeverInfers(t *testing.T) {
	t.Parallel()

	if got := observedAnalyser(); got.IsInferred() {
		t.Errorf("observedAnalyser produced an inferred identity: %+v", got)
	}
}
