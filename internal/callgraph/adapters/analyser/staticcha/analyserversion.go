package staticcha

import (
	"runtime/debug"
	"sync"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
)

// analyserModule is the library this package is built against: it type-checks
// the source and builds the SSA every graph here is computed over. Which version
// of it ran is what decides what a graph CONTAINS, so a record that cannot name
// it cannot be told apart from one built by a library that understood less of
// the code.
const analyserModule = "golang.org/x/tools"

// observedAnalyser names the x/tools THIS BINARY was linked against.
//
// It is read from the running process's own build info, never from a go.mod on
// disk. A go.mod read at extraction time is a fact about the checkout the
// process happens to be standing in; a go.mod read later describes the reader.
// The linked library is the only one that actually parsed anything, and the
// binary is the only thing that knows which it is.
//
// Asked once. Build info does not change under a running process, and the
// alternative is one map walk per analysed module.
var observedAnalyser = sync.OnceValue(func() domain.AnalyserIdentity {
	return analyserFromBuildInfo(debug.ReadBuildInfo())
})

// analyserFromBuildInfo extracts the analyser identity from build info.
//
// It is separated from the read so it can be measured: a `go test` binary
// carries NO dependency list at all — measured on this repository, ten build
// settings and zero deps — so a test that called the real reader would assert
// only that the suite is a test binary. The production binary does carry it;
// `go version -m` on a built kanonarion shows the dep line this walks.
//
// A build with no info, or one whose dependency list does not name x/tools,
// yields the zero identity: "this binary cannot say" is the honest answer, and
// it is the one answer that can never be mistaken for a measurement.
func analyserFromBuildInfo(info *debug.BuildInfo, ok bool) domain.AnalyserIdentity {
	if !ok || info == nil {
		return domain.AnalyserIdentity{}
	}
	for _, dep := range info.Deps {
		if dep == nil || dep.Path != analyserModule {
			continue
		}
		// A replaced module is the one that was actually compiled in, so it is the
		// one that parsed the code. A replacement pointing at a directory states no
		// version, and that is an absence rather than a value: reporting the
		// replaced module's version there would name a library that did not run.
		if dep.Replace != nil {
			dep = dep.Replace
		}
		return domain.ObservedAnalyser(domain.AnalyserVersion(dep.Version))
	}
	return domain.AnalyserIdentity{}
}
