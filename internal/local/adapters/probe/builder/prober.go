// Package builder implements ports.SymbolTableProber. It builds a probe binary
// from a local Go workspace with inlining disabled (-gcflags='all=-l') and
// reads the binary's symbol table via go tool nm. Under a TinyGo frame tinygo
// builds it at -opt=0, the same guard against inlining.
//
// For binary targets, every main package the workspace declares is built
// directly and their symbol tables unioned — a project with more than one main
// ships more than one artefact, and a symbol linked into any of them is in the
// product. For library targets, a synthetic main package is generated inside the
// workspace under a _kanonarion_probe directory (excluded from./...) that
// takes references to all exported functions and methods, preventing dead-code
// elimination. Generic declarations are instantiated, the harness is
// type-checked before it is built, and any reference that fails is left out
// and named.
package builder

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/version"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"code.eitanity.com/kanonarion/internal/adapters/childproc"
	"code.eitanity.com/kanonarion/internal/adapters/goenv"
	"code.eitanity.com/kanonarion/internal/adapters/interrupt"
	"code.eitanity.com/kanonarion/internal/gotoolchain"
	localdomain "code.eitanity.com/kanonarion/internal/local/domain"
	"code.eitanity.com/kanonarion/internal/local/ports"
)

const probeHarnessDir = "_kanonarion_probe"

// probeEnv is the environment for every go child this prober spawns. The probe
// and the call-graph load measure one tree, and these children resolved by
// whatever flags the caller happened to export while that load was pinned.
func probeEnv(root string) []string { return goenv.Worktree(os.Environ(), root) }

// capture is how one child's output and its own account of a failure are read.
// A build reports through its combined output; a list and go tool nm keep stdout
// clean and report on stderr. Both feed the same decision, because the go
// command writes a toolchain refusal wherever the caller is already looking.
type capture func(*exec.Cmd) (out []byte, detail string, err error)

func stdoutCapture(cmd *exec.Cmd) ([]byte, string, error) {
	out, err := cmd.Output()
	if ee, ok := errors.AsType[*exec.ExitError](err); ok {
		return out, string(ee.Stderr), err //nolint:wrapcheck // each caller names the command it ran; wrapping here would say it twice
	}
	return out, "", err //nolint:wrapcheck // as above
}

func combinedCapture(cmd *exec.Cmd) ([]byte, string, error) {
	out, err := cmd.CombinedOutput()
	return out, string(out), err
}

// runChild runs one Go child over the tree at root, and runs it again under a
// toolchain already unpacked on this host when it refuses for want of a newer
// Go than the installed one.
//
// Every child of one probe shares the tc it is given, so the decision is taken
// once: a probe spawns up to five children, and neither paying five failed first
// attempts nor letting two of them measure under different toolchains would be
// right. detail is the child's own account of the failure, returned so each
// caller keeps its own wording, and carries the refusal in its place when this
// host has nothing that can serve.
func runChild(ctx context.Context, tc *goenv.Toolchains, root, bin string, frame childFrame, read capture, args ...string) ([]byte, string, error) {
	for {
		cmd := childproc.CommandContext(ctx, bin, args...) // #nosec G204 -- binary path is "go", "tinygo" or caller-supplied and trusted
		cmd.Dir = root
		// A build the cancellation kills cannot remove its own work directory, so
		// it gets a temp root this process removes once it has exited.
		scratch, removeScratch := childproc.Scratch()
		cmd.Env = append(frame(tc.Apply(probeEnv(root))), scratch...)
		out, detail, err := read(cmd)
		removeScratch()
		if err == nil {
			return out, "", nil
		}
		retry, refusal := tc.Escalate(detail)
		if refusal != "" {
			return nil, refusal, err
		}
		if !retry {
			return nil, detail, err
		}
	}
}

// childFrame writes the build frame onto one child's environment, after the
// toolchain's values.
type childFrame func(env []string) []string

// noFrame leaves a child's environment as the posture and toolchain built it.
func noFrame(env []string) []string { return env }

// Prober implements ports.SymbolTableProber.
type Prober struct {
	goBinary string
	// target and tinygo are the declared build frame; zero declares the host.
	target goenv.Target
	tinygo goenv.TinyGo
}

// New constructs a Prober. goBinary may be empty (uses "go" from PATH).
func New(goBinary string) *Prober { return &Prober{goBinary: goBinary} }

func (p *Prober) goBin() string {
	if p.goBinary == "" {
		return "go"
	}
	return p.goBinary
}

// WithTarget declares the platform the probe lists and builds for. The zero
// value declares this host's pair, which every listing and build still pins.
func (p *Prober) WithTarget(t goenv.Target) *Prober {
	p.target = t
	return p
}

// WithTinyGo declares a TinyGo frame: its GOROOT, platform and tags reach every
// go list, and its artefact is built by tinygo for that target.
func (p *Prober) WithTinyGo(f goenv.TinyGo) *Prober {
	p.tinygo = f
	return p
}

// listFrame is the frame a go list child resolves under: the platform, then
// the TinyGo frame when one is declared, as the call-graph load applies them.
func (p *Prober) listFrame(env []string) []string { return p.tinygo.Apply(p.target.Apply(env)) }

// exportFrame is the frame the library harness's export data is compiled in.
// gc cannot compile TinyGo's GOROOT, so a TinyGo frame lists exports for its
// platform and tags against Go's own root, without cgo.
func (p *Prober) exportFrame(env []string) []string {
	if !p.tinygo.Declared() {
		return p.listFrame(env)
	}
	out := slices.Clip(env)
	out = append(out, "GOOS="+p.tinygo.GOOS(), "GOARCH="+p.tinygo.GOARCH())
	if p.tinygo.GOARM() != "" {
		out = append(out, "GOARM="+p.tinygo.GOARM())
	}
	return append(out, "CGO_ENABLED=0")
}

// listArgs puts TinyGo's tag set after the go subcommand, never in GOFLAGS.
func (p *Prober) listArgs(args ...string) []string {
	tags := p.tinygo.ListArgs()
	if len(tags) == 0 || len(args) == 0 {
		return args
	}
	return append(append([]string{args[0]}, tags...), args[1:]...)
}

// builder names the command that builds this frame's artefacts.
func (p *Prober) builder() string {
	if p.tinygo.Declared() {
		return localdomain.ProbeBuilderTinyGo
	}
	return localdomain.ProbeBuilderGo
}

// buildsWasm reports whether this frame's artefact is a wasm module.
func (p *Prober) buildsWasm() bool {
	if p.tinygo.Declared() {
		return p.tinygo.BuildsWasm()
	}
	return p.target.OrHost().GOARCH() == "wasm"
}

// frameFlag is the declaration as a refusal names it.
func (p *Prober) frameFlag() string {
	if p.tinygo.Declared() {
		return "--tinygo " + p.tinygo.Target()
	}
	return "--target " + p.target.OrHost().String()
}

// WasmArtefactError is the refusal for a frame whose artefact is a wasm
// module: the probe reads a symbol table, and this build has no reader for one.
type WasmArtefactError struct {
	// Flag is the declaration that selected the frame, as typed.
	Flag string
}

func (e *WasmArtefactError) Error() string {
	return fmt.Sprintf("%s builds a wasm module, and the probe reads a symbol table this build has no reader for in a wasm module", e.Flag)
}

// build compiles one package into outBin. go build disables inlining with
// -gcflags=all=-l; tinygo's equivalent is -opt=0, without which a called
// function is inlined away and missing from the table.
func (p *Prober) build(ctx context.Context, tc *goenv.Toolchains, root, pkg, outBin string) (string, error) {
	if p.tinygo.Declared() {
		// The target flag is tinygo's whole frame: its own GOROOT in the
		// environment stops tinygo resolving the standard library.
		_, detail, err := runChild(ctx, tc, root, "tinygo", noFrame, combinedCapture,
			"build", "-target="+p.tinygo.Target(), "-opt=0", "-o", outBin, pkg)
		return detail, err
	}
	_, detail, err := runChild(ctx, tc, root, p.goBin(), p.target.Apply, combinedCapture,
		"build", "-gcflags=all=-l", "-o", outBin, pkg)
	return detail, err
}

// Probe builds a probe binary from the workspace at root with inlining
// disabled and returns its symbol table.
//
// Every main package the workspace declares is built, not the first one only.
// A project with two mains ships two artefacts, and building whichever sorts
// first answered "absent" for every symbol linked solely into the other — a
// false negative on precisely the question the probe exists to answer. The
// symbol tables are unioned for the verdict and kept per binary for
// attribution.
func (p *Prober) Probe(ctx context.Context, root string) (ports.SymbolProbeResult, error) {
	if p.buildsWasm() {
		return ports.SymbolProbeResult{}, &WasmArtefactError{Flag: p.frameFlag()}
	}
	toolchains := goenv.NewToolchains()
	defer func() { _ = toolchains.Close() }()

	mainPkgs, err := p.findMainPackages(ctx, toolchains, root)
	if err != nil {
		return ports.SymbolProbeResult{}, fmt.Errorf("detecting workspace kind: %w", err)
	}

	outDir, err := os.MkdirTemp("", "kanonarion_probe_bin")
	if err != nil {
		return ports.SymbolProbeResult{}, fmt.Errorf("creating probe output directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(outDir) }()

	if len(mainPkgs) == 0 {
		return p.probeLibrary(ctx, toolchains, root, filepath.Join(outDir, "probe"))
	}
	return p.probeBinaries(ctx, toolchains, root, outDir, mainPkgs)
}

// probeBinaries builds every main package and unions their symbol tables.
//
// A main that fails to build (or whose symbol table cannot be read) is recorded
// against its import path rather than aborting the probe: the other binaries
// still answer for the symbols they carry. The probe fails only when no main at
// all could be probed, because then there is no symbol table and every finding
// would read "absent" on the strength of a build that never happened.
func (p *Prober) probeBinaries(ctx context.Context, tc *goenv.Toolchains, root, outDir string, mainPkgs []string) (ports.SymbolProbeResult, error) {
	sorted := make([]string, len(mainPkgs))
	copy(sorted, mainPkgs)
	sort.Strings(sorted)

	union := make(map[string]struct{})
	binaries := make([]ports.ProbedBinary, 0, len(sorted))
	probed := 0
	var firstErr error

	for i, mainPkg := range sorted {
		entry := ports.ProbedBinary{ImportPath: mainPkg, Builder: p.builder()}
		outBin := filepath.Join(outDir, fmt.Sprintf("probe_%d", i))
		symbols, err := p.buildAndRead(ctx, tc, root, mainPkg, outBin)
		if interrupt.Cancelled(ctx, err) {
			// A build the run's cancellation stopped is not a binary that failed to
			// build, and the binaries after it were never tried.
			return ports.SymbolProbeResult{}, fmt.Errorf("building the probe binary for %s: %w", mainPkg, ctx.Err())
		}
		if err != nil {
			entry.BuildError = err.Error()
			if firstErr == nil {
				firstErr = err
			}
		} else {
			entry.Symbols = symbols
			probed++
			for sym := range symbols {
				union[sym] = struct{}{}
			}
		}
		_ = os.Remove(outBin)
		binaries = append(binaries, entry)
	}

	if probed == 0 {
		return ports.SymbolProbeResult{}, fmt.Errorf("building probe binary: no main package of %d could be probed: %w", len(sorted), firstErr)
	}

	return ports.SymbolProbeResult{BinarySymbols: union, Kind: localdomain.ProbeKindBinary, Builder: p.builder(), Binaries: binaries}, nil
}

// buildAndRead builds one main package and reads the resulting symbol table.
func (p *Prober) buildAndRead(ctx context.Context, tc *goenv.Toolchains, root, mainPkg, outBin string) (map[string]struct{}, error) {
	if detail, err := p.build(ctx, tc, root, mainPkg, outBin); err != nil {
		return nil, fmt.Errorf("building probe binary: %w\n%s", err, detail)
	}
	symbols, err := p.readSymbols(ctx, tc, root, outBin)
	if err != nil {
		return nil, fmt.Errorf("reading symbol table: %w", err)
	}
	return symbols, nil
}

// probeLibrary builds the synthetic harness for a workspace with no main
// package and reads its symbol table.
func (p *Prober) probeLibrary(ctx context.Context, tc *goenv.Toolchains, root, outBin string) (ports.SymbolProbeResult, error) {
	harnessDir := filepath.Join(root, probeHarnessDir)
	defer func() { _ = os.RemoveAll(harnessDir) }()

	omitted, err := p.buildLibraryProbe(ctx, tc, root, harnessDir, outBin)
	if err != nil {
		return ports.SymbolProbeResult{}, fmt.Errorf("building library probe: %w", err)
	}
	symbols, err := p.readSymbols(ctx, tc, root, outBin)
	if err != nil {
		return ports.SymbolProbeResult{}, fmt.Errorf("reading symbol table: %w", err)
	}
	return ports.SymbolProbeResult{BinarySymbols: symbols, Kind: localdomain.ProbeKindLibrary, Builder: p.builder(), HarnessOmitted: omitted}, nil
}

// readSymbols reads outBin's symbol table, in Go's spelling whichever builder
// produced it.
func (p *Prober) readSymbols(ctx context.Context, tc *goenv.Toolchains, root, outBin string) (map[string]struct{}, error) {
	symbols, err := readSymbolTable(ctx, tc, root, outBin, p.goBin())
	if err != nil || !p.tinygo.Declared() {
		return symbols, err
	}
	out := make(map[string]struct{}, len(symbols))
	for sym := range symbols {
		out[normaliseTinyGoSymbol(sym)] = struct{}{}
	}
	return out, nil
}

// goListPackage mirrors the fields we need from `go list -json`.
type goListPackage struct {
	ImportPath string
	Name       string
	Export     string        // the export data file, under -export
	DepOnly    bool          // a dependency of the patterns, under -deps
	Module     *goListModule // the module providing the package
}

type goListModule struct {
	Path string
}

// findMainPackages runs go list -json./... under the frame and returns the
// import paths of packages whose Name == "main".
func (p *Prober) findMainPackages(ctx context.Context, tc *goenv.Toolchains, root string) ([]string, error) {
	out, detail, err := runChild(ctx, tc, root, p.goBin(), p.listFrame, stdoutCapture, p.listArgs("list", "-json", "./...")...)
	if err != nil {
		return nil, fmt.Errorf("go list: %w\n%s", err, detail)
	}

	dec := json.NewDecoder(bytes.NewReader(out))
	var mains []string
	for {
		var pkg goListPackage
		if err := dec.Decode(&pkg); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("parsing go list output: %w", err)
		}
		if pkg.Name == "main" {
			mains = append(mains, pkg.ImportPath)
		}
	}
	return mains, nil
}

// buildLibraryProbe generates a synthetic harness inside harnessDir and
// builds it into outBin with inlining disabled. It returns the exported
// declarations the harness had to leave out.
func (p *Prober) buildLibraryProbe(ctx context.Context, tc *goenv.Toolchains, root, harnessDir, outBin string) ([]localdomain.HarnessOmission, error) {
	if err := os.MkdirAll(harnessDir, 0o700); err != nil {
		return nil, fmt.Errorf("creating harness dir: %w", err)
	}

	pkgs, err := p.listWorkspaceExports(ctx, tc, root)
	if err != nil {
		return nil, fmt.Errorf("compiling workspace packages: %w", err)
	}

	goMod, err := os.ReadFile(filepath.Join(root, "go.mod")) // #nosec G304 -- the workspace root the caller named
	if err != nil {
		goMod = nil // an unreadable go.mod claims no limit, as before
	}
	code, omitted, err := libraryHarness(pkgs, goMod)
	if err != nil {
		return nil, err
	}

	mainPath := filepath.Join(harnessDir, "main.go")
	if err := os.WriteFile(mainPath, []byte(code), 0o600); err != nil { // #nosec G703 -- the workspace root the caller named, plus a fixed directory and file name
		return nil, fmt.Errorf("writing harness: %w", err)
	}

	if detail, err := p.build(ctx, tc, root, "./"+probeHarnessDir, outBin); err != nil {
		return nil, fmt.Errorf("building harness: %w\n%s", err, detail)
	}
	return omitted, nil
}

// libraryHarness generates the harness under the module's go directive. Under a
// directive newer than this binary's Go, export data or a harness this binary's
// go/types cannot read is the analyser limit, not a defect.
func libraryHarness(pkgs []goListPackage, goMod []byte) (string, []localdomain.HarnessOmission, error) {
	directive := gotoolchain.GoDirective(goMod)
	limit, limited := gotoolchain.LimitForDirective(directive)
	goVersion := "go" + directive
	if !version.IsValid(goVersion) {
		goVersion = ""
	}
	code, omitted, err := harnessSource(pkgs, goVersion)
	if err != nil && limited {
		return "", nil, &gotoolchain.AnalyserLimitError{Limit: limit}
	}
	if err != nil {
		return "", nil, fmt.Errorf("generating harness: %w", err)
	}
	return code, omitted, nil
}

// listWorkspaceExports lists the workspace packages and their dependencies with
// export data. The flags match the harness build, so that build reuses this
// compilation. A workspace that does not compile fails here, with the compiler's
// own report, as it failed at the harness build before.
func (p *Prober) listWorkspaceExports(ctx context.Context, tc *goenv.Toolchains, root string) ([]goListPackage, error) {
	out, detail, err := runChild(ctx, tc, root, p.goBin(), p.exportFrame, stdoutCapture,
		p.listArgs("list", "-export", "-deps", "-json", "-gcflags=all=-l", "./...")...)
	if err != nil {
		return nil, fmt.Errorf("go list: %w\n%s", err, detail)
	}
	dec := json.NewDecoder(bytes.NewReader(out))
	var pkgs []goListPackage
	for {
		var pkg goListPackage
		if err := dec.Decode(&pkg); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("parsing go list output: %w", err)
		}
		pkgs = append(pkgs, pkg)
	}
	return pkgs, nil
}

// readSymbolTable runs go tool nm on binPath and returns the set of symbol names.
// nm runs outside the frame: it reads any platform's container, and under a
// TinyGo GOROOT the go command cannot build the tool at all.
func readSymbolTable(ctx context.Context, tc *goenv.Toolchains, root, binPath, goBin string) (map[string]struct{}, error) {
	out, detail, err := runChild(ctx, tc, root, goBin, noFrame, stdoutCapture, "tool", "nm", binPath)
	if err != nil {
		return nil, fmt.Errorf("go tool nm: %w\n%s", err, detail)
	}

	symbols := make(map[string]struct{})
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		symbols[fields[2]] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning nm output: %w", err)
	}
	return symbols, nil
}

// Ensure Prober implements ports.SymbolTableProber at compile time.
var _ ports.SymbolTableProber = (*Prober)(nil)

// normaliseTinyGoSymbol rewrites TinyGo's method spelling to Go's, which the
// stored findings and the matcher use: (*P.T).M becomes P.(*T).M and (P.T).M
// becomes P.T.M. Anything else passes through.
func normaliseTinyGoSymbol(sym string) string {
	if !strings.HasPrefix(sym, "(") {
		return sym
	}
	end := closingParen(sym)
	if end < 0 || end+1 >= len(sym) || sym[end+1] != '.' {
		return sym
	}
	recv, method := sym[1:end], sym[end+2:]
	ptr := strings.HasPrefix(recv, "*")
	recv = strings.TrimPrefix(recv, "*")
	base := recv
	if i := strings.IndexByte(base, '['); i >= 0 {
		base = base[:i]
	}
	dot := strings.IndexByte(base[strings.LastIndexByte(base, '/')+1:], '.')
	if dot < 0 {
		return sym
	}
	dot += strings.LastIndexByte(base, '/') + 1
	pkg, typ := recv[:dot], recv[dot+1:]
	if ptr {
		return pkg + ".(*" + typ + ")." + method
	}
	return pkg + "." + typ + "." + method
}

// closingParen is the index of the parenthesis closing the one sym opens with,
// or -1 when it is never closed.
func closingParen(sym string) int {
	depth := 0
	for i, r := range sym {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}
