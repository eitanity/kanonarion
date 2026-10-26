package staticcha

import (
	"os"

	"code.eitanity.com/kanonarion/internal/adapters/goenv"
	"code.eitanity.com/kanonarion/internal/callgraph/domain"
)

// WithTarget declares the platform every child of an analysis resolves for.
// The zero value declares this host's pair, which applyFrame still writes.
func (a *Analyser) WithTarget(t goenv.Target) *Analyser {
	a.target = t
	return a
}

// WithTinyGo declares the TinyGo frame every child of an analysis resolves
// under: its platform, GOROOT and cgo in the environment, its tags as -tags.
func (a *Analyser) WithTinyGo(f goenv.TinyGo) *Analyser {
	a.tinygo = f
	return a
}

// applyFrame writes the frame onto env, last, so it wins over the toolchain's
// own values. With nothing declared it writes the host pair, as the walk does:
// a GOOS/GOARCH exported in the calling shell reaches no analysis.
func (a *Analyser) applyFrame(env []string) []string {
	return a.tinygo.Apply(a.target.Apply(env))
}

// buildFlags are the go command flags every load passes: TinyGo's tag set, as
// the scanner passes it, never through GOFLAGS.
func (a *Analyser) buildFlags() []string { return a.tinygo.ListArgs() }

// declaredFrame is this analyser's frame before any child has answered.
func (a *Analyser) declaredFrame() domain.BuildFrame { return DeclaredFrame(a.target, a.tinygo) }

// measuredFrame is the frame a record states: GOOS, GOARCH and GOARM as the
// loader's own go command resolved them, the TinyGo half from the declaration.
// A probe that could not answer leaves the declared frame, so no record written
// by this build is unframed.
func (a *Analyser) measuredFrame(dirs SourceDirs) domain.BuildFrame {
	f := a.declaredFrame()
	if dirs.GOOS != "" && dirs.GOARCH != "" {
		f.GOOS, f.GOARCH, f.GOARM = dirs.GOOS, dirs.GOARCH, dirs.GOARM
	}
	return f
}

// DeclaredFrame is the frame a declaration selects and an analysis under it
// records: the TinyGo frame when one is declared, otherwise the declared pair or
// this host's. A read selects on it before any analysis runs.
func DeclaredFrame(t goenv.Target, tg goenv.TinyGo) domain.BuildFrame {
	if tg.Declared() {
		return domain.BuildFrame{
			GOOS: tg.GOOS(), GOARCH: tg.GOARCH(), GOARM: tg.GOARM(),
			TinyGoTarget: tg.Target(), TinyGoVersion: tg.Version(), TinyGoTags: tg.Tags(),
		}
	}
	r := t.OrHost()
	return domain.BuildFrame{GOOS: r.GOOS(), GOARCH: r.GOARCH(), GOARM: defaultGOARM(r.GOARCH())}
}

// defaultGOARM is what `go env GOARM` answers for goarch with no TinyGo frame:
// empty off arm, the inherited GOARM on it, and the go command's default 7.
func defaultGOARM(goarch string) string {
	if goarch != "arm" {
		return ""
	}
	if v := os.Getenv("GOARM"); v != "" {
		return v
	}
	return "7"
}

// frameOr keeps a frame the analysis stamped and supplies the declared one on a
// return path that failed before any child ran.
func (a *Analyser) frameOr(f domain.BuildFrame) domain.BuildFrame {
	if f.IsZero() {
		return a.declaredFrame()
	}
	return f
}
