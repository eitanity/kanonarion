package goenv

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// TinyGo is a TinyGo target as the tinygo command defined it: the board or
// runtime name, the TinyGo and merged Go versions, the platform, the build tags,
// the GOROOT TinyGo builds with, TinyGo's own source root and the LLVM triple.
// The zero value declares nothing.
type TinyGo struct {
	target, version, goVersion, goos, goarch, goarm, goroot string
	sourceRoot, llvmTriple                                  string
	tags                                                    []string
	// hostGOOS and hostGOARCH are the platform the tinygo binary was built
	// for, as tinygo version reports it; they name its release archive.
	hostGOOS, hostGOARCH string
}

// NewTinyGo is a complete frame. A partial one would let the missing half come
// from the inherited environment, so every field the children need is required
// and the GOROOT and TINYGOROOT must hold the source trees that are read.
func NewTinyGo(target, version, goVersion, goos, goarch, goarm, goroot, sourceRoot, llvmTriple string, tags []string) (TinyGo, error) {
	for _, f := range []struct{ name, value string }{
		{"target", target}, {"TinyGo version", version}, {"GOOS", goos}, {"GOARCH", goarch}, {"GOROOT", goroot},
		{"TINYGOROOT", sourceRoot}, {"LLVM triple", llvmTriple},
	} {
		if f.value == "" {
			return TinyGo{}, fmt.Errorf("a TinyGo frame names its %s; tinygo reported none", f.name)
		}
	}
	if info, err := os.Stat(filepath.Join(goroot, "src")); err != nil || !info.IsDir() {
		return TinyGo{}, fmt.Errorf("the TinyGo GOROOT %s holds no src directory", goroot)
	}
	if info, err := os.Stat(filepath.Join(sourceRoot, "src")); err != nil || !info.IsDir() {
		return TinyGo{}, fmt.Errorf("the TINYGOROOT %s holds no src directory", sourceRoot)
	}
	return TinyGo{
		target: target, version: version, goVersion: goVersion,
		goos: goos, goarch: goarch, goarm: goarm, goroot: goroot,
		sourceRoot: sourceRoot, llvmTriple: llvmTriple,
		tags: append([]string(nil), tags...),
	}, nil
}

// WithHost returns the frame with the platform tinygo itself was built for.
func (f TinyGo) WithHost(goos, goarch string) TinyGo {
	f.hostGOOS, f.hostGOARCH = goos, goarch
	return f
}

// HostGOOS is the operating system the tinygo binary was built for, empty
// when it was not reported.
func (f TinyGo) HostGOOS() string { return f.hostGOOS }

// HostGOARCH is the architecture the tinygo binary was built for, empty when
// it was not reported.
func (f TinyGo) HostGOARCH() string { return f.hostGOARCH }

// Declared reports whether this value names a TinyGo target at all.
func (f TinyGo) Declared() bool { return f.target != "" }

// Target is the TinyGo target name, such as pico or wasip1.
func (f TinyGo) Target() string { return f.target }

// Version is the TinyGo release, such as 0.42.0.
func (f TinyGo) Version() string { return f.version }

// GoVersion is the Go release TinyGo reports it merges, such as go1.27.2.
func (f TinyGo) GoVersion() string { return f.goVersion }

// GOOS is the operating system TinyGo resolves the target for.
func (f TinyGo) GOOS() string { return f.goos }

// GOARCH is the architecture TinyGo resolves the target for.
func (f TinyGo) GOARCH() string { return f.goarch }

// GOARM is the ARM variant TinyGo reports, possibly empty.
func (f TinyGo) GOARM() string { return f.goarm }

// Tags is the target's build tag set, in the order tinygo reported it.
func (f TinyGo) Tags() []string { return append([]string(nil), f.tags...) }

// BuildsWasm reports whether this frame's artefact is a wasm module. The tag
// decides as well as GOARCH: tinygo reports wasip2 and wasm-unknown as linux/arm
// and tags every wasm target tinygo.wasm.
func (f TinyGo) BuildsWasm() bool {
	return f.goarch == "wasm" || slices.Contains(f.tags, "tinygo.wasm")
}

// GOROOT is the merged root TinyGo builds with.
func (f TinyGo) GOROOT() string { return f.goroot }

// SourceRoot is TINYGOROOT, the tree TinyGo's own packages and target
// definitions live in. It is a host path, so it reaches no record.
func (f TinyGo) SourceRoot() string { return f.sourceRoot }

// LLVMTriple is the triple tinygo info reports for the target.
func (f TinyGo) LLVMTriple() string { return f.llvmTriple }

// Apply returns env as a child resolving under this frame must see it, written
// last so it wins over the inherited values and over Target.Apply. cgo is on
// because TinyGo compiles C, so build constraints select the cgo files. An
// undeclared frame leaves env as it is.
func (f TinyGo) Apply(env []string) []string {
	out := env[:len(env):len(env)]
	if !f.Declared() {
		return out
	}
	out = append(out, "GOOS="+f.goos, "GOARCH="+f.goarch)
	if f.goarm != "" {
		out = append(out, "GOARM="+f.goarm)
	}
	return append(out, "GOROOT="+f.goroot, "CGO_ENABLED=1")
}

// ListArgs is the tag set as a go list or govulncheck argument, nil when there
// are none.
func (f TinyGo) ListArgs() []string {
	if len(f.tags) == 0 {
		return nil
	}
	return []string{"-tags=" + strings.Join(f.tags, ",")}
}

// ResolutionClause names this frame in a refusal raised by a child that
// resolved under it, empty when none was declared.
func (f TinyGo) ResolutionClause() string {
	if !f.Declared() {
		return ""
	}
	return fmt.Sprintf(" (resolving for the declared build target --tinygo %s; this failure may be the target's rather than the project's)", f.target)
}

// PostureTinyGo is the frame the declared-tinygo-target posture is stated
// against. It is not this host's platform, so a producer that dropped the frame
// and kept the ambient values fails the assertion.
var PostureTinyGo = TinyGo{
	target: "pico", version: "0.0.0", goVersion: "go0.0.0",
	goos: "linux", goarch: "arm", goarm: "6", goroot: "/kanonarion-posture/tinygo-goroot",
	sourceRoot: "/kanonarion-posture/tinygo-root", llvmTriple: "thumbv6m-unknown-unknown-eabi",
	tags: []string{"tinygo", "baremetal"},
}
