package cli

import (
	"bytes"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/config/domain"
)

// The process-wide state a command leaves behind must not be readable by the
// next command in the same process.
//
// One process runs one command in production, so none of this is reachable
// there. The golden harness runs the whole command set in one binary, and a
// case that inherits an earlier case's fetch mode is a case that can pass for
// the wrong reason — or, as happened once, invert its own exit code.
//
// The tests below come in three kinds and the difference matters:
//
//   - Discriminators. They plant a previous invocation's value, run a command,
//     and fail unless the value is gone. Each one fails without the reset.
//   - Controls. They record that the flag-BOUND variables are put back by flag
//     registration as well as by the reset — StringVar/BoolVar assign the
//     flag's default, and newRootCmd registers every flag on every invocation
//     — so a later change that registers a flag once, lazily, is caught rather
//     than assumed away.
//   - The roster. One test derives the variables this file has to be about
//     from the package's own source, rather than naming them. A hand-written
//     roster is what let jsonOut, logLevel and storeRoot sit outside the reset
//     while the file above read as though the class were closed.

// primeInvocation runs one command through the real command tree, without Run's
// end-of-invocation reset, so the state that invocation leaves is still
// readable.
//
// Run is deliberately not used: it clears the state on the way out, which is
// what makes a direct render call after it safe, and would also make the
// "the priming command really did enter this state" check below vacuous. The
// command still executes for real — cobra parses the flags and the resolve*
// helper runs — so what is planted is what a command plants, not what a test
// assigned.
func primeInvocation(t *testing.T, args ...string) string {
	t.Helper()
	var stdout, stderr bytes.Buffer
	root := newRootCmd(&stdout, &stderr)
	root.SetArgs(args)
	_ = root.Execute()
	return stderr.String()
}

// staleInvocationState plants the state a previous command would have left and
// restores the package to a clean slate afterwards.
func staleInvocationState(t *testing.T) {
	t.Helper()
	cfg, cfgErr := activeConfig, activeConfigErr
	t.Cleanup(func() {
		modcacheMode, modcacheDir, goSumPath, projectGoSumPath = false, "", "", ""
		activeConfig, activeConfigErr = cfg, cfgErr
	})
}

// A previous `audit --from-modcache` puts modcacheMode, modcacheDir and
// goSumPath in place. Three commands call resolveModcacheMode; every command
// builds a Container that reads those variables. The reset is what makes the
// forty-odd that never see the flag run on the network path they asked for.
func TestRun_ModcacheModeDoesNotSurviveIntoTheNextCommand(t *testing.T) {
	staleInvocationState(t)

	// The previous command, run for real rather than simulated by assigning the
	// variables: whatever else this audit does, it passes through
	// resolveModcacheMode and leaves the process in module-cache mode.
	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, "go.mod"), []byte("module example.com/previous\n\ngo 1.26\n"), 0o600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(project, "go.sum"), nil, 0o600); err != nil {
		t.Fatalf("write go.sum: %v", err)
	}
	cache := t.TempDir()
	primeErr := primeInvocation(t, "audit", "--gomod", filepath.Join(project, "go.mod"),
		"--from-modcache="+cache, "--store-root", t.TempDir())
	if !modcacheMode {
		t.Fatalf("the priming audit never entered module-cache mode, so this test proves nothing\nstderr:\n%s",
			primeErr)
	}

	var stdout, stderr bytes.Buffer
	err := Run([]string{"walk-list", "--store-root", t.TempDir()}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("a command that never named --from-modcache took the module-cache path: %v\nstderr:\n%s",
			err, stderr.String())
	}
	if modcacheMode || modcacheDir != "" || goSumPath != "" {
		t.Errorf("module-cache state survived the invocation: mode=%v dir=%q goSum=%q",
			modcacheMode, modcacheDir, goSumPath)
	}
}

// projectGoSumPath decides which go.sum anchors checksum verification on the
// normal network path. Inherited, a command verifies this project's modules
// against the previous project's checksums.
func TestRun_ProjectGoSumDoesNotSurviveIntoTheNextCommand(t *testing.T) {
	staleInvocationState(t)

	// The previous command, run for real: an audit of a project that has a
	// go.sum beside its go.mod.
	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, "go.mod"), []byte("module example.com/previous\n\ngo 1.26\n"), 0o600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(project, "go.sum"), nil, 0o600); err != nil {
		t.Fatalf("write go.sum: %v", err)
	}
	primeErr := primeInvocation(t, "audit", "--gomod", filepath.Join(project, "go.mod"),
		"--store-root", t.TempDir())
	if projectGoSumPath == "" {
		t.Fatalf("the priming audit never anchored on its own go.sum, so this test proves nothing\nstderr:\n%s",
			primeErr)
	}

	var stdout, stderr bytes.Buffer
	err := Run([]string{"walk-list", "--store-root", t.TempDir()}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("a command with no go.mod of its own anchored on a previous project's go.sum: %v\nstderr:\n%s",
			err, stderr.String())
	}
	if projectGoSumPath != "" {
		t.Errorf("projectGoSumPath = %q after an unrelated command, want empty", projectGoSumPath)
	}
}

// --help and --version are answered before any PersistentPreRunE, so the config
// the previous command loaded is never overwritten on that path. The reset runs
// at construction for that reason.
func TestRun_ConfigDoesNotSurviveOntoThePathThatSkipsPreRun(t *testing.T) {
	staleInvocationState(t)
	activeConfigErr = errors.New("a previous store's config file was rejected")

	var stdout, stderr bytes.Buffer
	if err := Run([]string{"--help"}, &stdout, &stderr); err != nil {
		t.Fatalf("--help: %v", err)
	}
	if activeConfigErr != nil {
		t.Errorf("activeConfigErr = %v after an unrelated invocation, want nil", activeConfigErr)
	}
}

// Discriminator at the resolver: an absent go.sum must mean "no local anchor",
// not "keep the last one".
func TestResolveProjectGoSum_AbsentGoSumClearsAPreviousProjectsPath(t *testing.T) {
	staleInvocationState(t)
	previous := filepath.Join(t.TempDir(), "previous-project", "go.sum")
	projectGoSumPath = previous

	dir := t.TempDir()
	gomod := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(gomod, []byte("module x\n"), 0o600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	// No go.sum beside it.
	resolveProjectGoSum(gomod)
	if projectGoSumPath != "" {
		t.Errorf("projectGoSumPath = %q, want empty; this project has no go.sum", projectGoSumPath)
	}
}

// Same at the --from-modcache early return, where go.sum is threaded through
// goSumPath instead and the normal-path variable must not be left behind.
func TestResolveProjectGoSum_ModcacheModeClearsAPreviousProjectsPath(t *testing.T) {
	staleInvocationState(t)
	projectGoSumPath = filepath.Join(t.TempDir(), "previous-project", "go.sum")
	modcacheMode = true

	dir := t.TempDir()
	gomod := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(gomod, []byte("module x\n"), 0o600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.sum"), nil, 0o600); err != nil {
		t.Fatalf("write go.sum: %v", err)
	}
	resolveProjectGoSum(gomod)
	if projectGoSumPath != "" {
		t.Errorf("projectGoSumPath = %q, want empty in --from-modcache mode", projectGoSumPath)
	}
}

// Control, not a discriminator. Every flag-bound package variable is re-assigned
// its default by StringVar/BoolVar when newRootCmd registers the flag, which it
// does on every invocation — a second mechanism over the reset, not a substitute
// for it: it acts on the way IN, and says nothing about what the invocation
// leaves behind for a reader that never registers a flag. It is asserted rather
// than argued so that registering one of these flags lazily — inside a RunE, or
// once per process — shows up here.
func TestRun_FlagBoundStateIsResetWhenTheFlagIsRegistered(t *testing.T) {
	storeWas, levelWas, jsonWas, downgradeWas := storeRoot, logLevel, jsonOut, allowVerificationDowngrade
	t.Cleanup(func() {
		storeRoot, logLevel, jsonOut, allowVerificationDowngrade = storeWas, levelWas, jsonWas, downgradeWas
	})

	stale := filepath.Join(t.TempDir(), "previous-store")
	storeRoot, logLevel, jsonOut, allowVerificationDowngrade = stale, "debug", true, true

	var stdout, stderr bytes.Buffer
	if err := Run([]string{"--help"}, &stdout, &stderr); err != nil {
		t.Fatalf("--help: %v", err)
	}
	if storeRoot == stale {
		t.Errorf("storeRoot kept the previous invocation's %q", stale)
	}
	if logLevel != "warn" {
		t.Errorf("logLevel = %q, want the registered default %q", logLevel, "warn")
	}
	if jsonOut {
		t.Error("jsonOut stayed true, want the registered default false")
	}
	if allowVerificationDowngrade {
		t.Error("allowVerificationDowngrade stayed true, want the registered default false")
	}
}

// Control for the reset's own value: a fresh invocation starts on the built-in
// defaults, which is what a store with no config file loads — not the zero
// Config, whose thresholds are all zero.
func TestResetInvocationState_StartsFromTheBuiltInDefaults(t *testing.T) {
	staleInvocationState(t)
	resetInvocationState()
	if activeConfig.Preferences.LogLevel != domain.DefaultConfig().Preferences.LogLevel {
		t.Errorf("activeConfig is not the built-in defaults: %+v", activeConfig.Preferences)
	}
}

// The defect the reset was widened for, held as a behaviour rather than as a
// list: a --json invocation used to leave jsonOut true, and the next thing to
// render in the same process — a test calling a run* function directly, which
// never goes through the flag registration — answered in JSON. It was seen
// once, patched inside the tests that tripped over it, and left in the package
// for the next shuffle to find.
func TestRun_RenderingFlagsDoNotSurviveTheInvocationThatSetThem(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := Run([]string{"--help", "--json", "--log-level", "debug"}, &stdout, &stderr); err != nil {
		t.Fatalf("--help --json: %v", err)
	}
	if jsonOut {
		t.Error("jsonOut is still true after the invocation that set it: the next direct render answers in JSON")
	}
	if logLevel != defaultLogLevel {
		t.Errorf("logLevel = %q after the invocation that set it, want the default %q", logLevel, defaultLogLevel)
	}
	if storeRoot != "" {
		t.Errorf("storeRoot = %q after the invocation, want empty: a reader that opens it without being "+
			"asked to must fail rather than reach a store nobody named", storeRoot)
	}
}

// resetExemptions names the package-scope variables the reset must NOT touch,
// with the reason, so the roster below can be derived and still have an answer
// for them. An exemption is a decision recorded where the derivation runs into
// it; it is not a list of what to reset, which is the thing that goes stale.
var resetExemptions = map[string]string{
	"cliClock": "the test seam SetClockForTest pins it BEFORE the invocation runs, so resetting it here " +
		"would unpin every golden",
}

// TestResetInvocationState_CoversEveryInvocationVariable derives the roster from
// the package's own source: every package-scope variable that any function in
// this package assigns — or binds to a flag by address, which is the same thing
// one level down — is state one invocation writes and the next reader inherits,
// so resetInvocationState has to put it back.
//
// It is derived rather than written down because a written-down roster is
// exactly what failed: three flag-bound variables were argued out of the reset
// in a comment, and nothing checked the argument again when the package started
// rendering from them directly. A variable added next month is decided here.
func TestResetInvocationState_CoversEveryInvocationVariable(t *testing.T) {
	sources, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("globbing package sources: %v", err)
	}
	fset := token.NewFileSet()
	pkgVars := map[string]bool{}
	var files []*ast.File
	for _, path := range sources {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Fatalf("parsing %s: %v", path, perr)
		}
		files = append(files, file)
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.VAR {
				continue
			}
			for _, spec := range gen.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, name := range vs.Names {
					pkgVars[name.Name] = true
				}
			}
		}
	}
	if len(files) == 0 {
		t.Fatal("no package sources parsed: the roster would be empty and this test would pass vacuously")
	}

	written, reset := map[string]bool{}, map[string]bool{}
	for _, file := range files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			target := written
			if fn.Name.Name == "resetInvocationState" {
				target = reset
			}
			for name := range assignedPackageVars(fn, pkgVars) {
				target[name] = true
			}
		}
	}
	if len(reset) == 0 {
		t.Fatal("resetInvocationState was not found, or assigns nothing: the comparison below would pass vacuously")
	}

	names := make([]string, 0, len(written))
	for name := range written {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if reset[name] {
			continue
		}
		if why, exempt := resetExemptions[name]; exempt {
			t.Logf("%s is exempt from the reset: %s", name, why)
			continue
		}
		t.Errorf("%s is package-level state an invocation writes, and resetInvocationState does not put it back: "+
			"the next reader in this process inherits it — reset it, or record why it must survive in resetExemptions",
			name)
	}
	for name, why := range resetExemptions {
		if !pkgVars[name] {
			t.Errorf("resetExemptions names %q, which is not a package-level variable any more: remove it (%s)", name, why)
		}
		if reset[name] {
			t.Errorf("resetExemptions names %q, which resetInvocationState resets after all: "+
				"one of the two is wrong and the exemption is the one that reads as a decision", name)
		}
	}
	t.Logf("package-level invocation variables: %v; exempt: %v", names, resetExemptions)
}

// assignedPackageVars returns the package-scope variables fn writes: assigned
// with =, or had their address taken, which is how a flag registration writes
// one. Names fn declares itself are excluded, so a local called `version` is not
// mistaken for the package variable of that name.
func assignedPackageVars(fn *ast.FuncDecl, pkgVars map[string]bool) map[string]bool {
	local := locallyDeclared(fn)
	out := map[string]bool{}
	note := func(id *ast.Ident) {
		if pkgVars[id.Name] && !local[id.Name] {
			out[id.Name] = true
		}
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			if x.Tok != token.ASSIGN {
				return true
			}
			for _, lhs := range x.Lhs {
				if id, ok := lhs.(*ast.Ident); ok {
					note(id)
				}
			}
		case *ast.UnaryExpr:
			if x.Op != token.AND {
				return true
			}
			if id, ok := x.X.(*ast.Ident); ok {
				note(id)
			}
		}
		return true
	})
	return out
}

// locallyDeclared collects the names fn binds itself — receiver, parameters,
// results, :=, var/const, range and closure parameters — so a shadowed name is
// not read as a write to the package variable it happens to share a spelling
// with.
func locallyDeclared(fn *ast.FuncDecl) map[string]bool {
	out := map[string]bool{}
	fields := func(fl *ast.FieldList) {
		if fl == nil {
			return
		}
		for _, f := range fl.List {
			for _, name := range f.Names {
				out[name.Name] = true
			}
		}
	}
	fields(fn.Recv)
	if fn.Type != nil {
		fields(fn.Type.Params)
		fields(fn.Type.Results)
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			if x.Tok != token.DEFINE {
				return true
			}
			for _, lhs := range x.Lhs {
				if id, ok := lhs.(*ast.Ident); ok {
					out[id.Name] = true
				}
			}
		case *ast.GenDecl:
			if x.Tok != token.VAR && x.Tok != token.CONST {
				return true
			}
			for _, spec := range x.Specs {
				if vs, ok := spec.(*ast.ValueSpec); ok {
					for _, name := range vs.Names {
						out[name.Name] = true
					}
				}
			}
		case *ast.RangeStmt:
			for _, e := range []ast.Expr{x.Key, x.Value} {
				if id, ok := e.(*ast.Ident); ok {
					out[id.Name] = true
				}
			}
		case *ast.FuncLit:
			if x.Type != nil {
				fields(x.Type.Params)
				fields(x.Type.Results)
			}
		}
		return true
	})
	return out
}
