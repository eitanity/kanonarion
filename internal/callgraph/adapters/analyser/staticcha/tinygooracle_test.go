package staticcha_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/adapters/childproc"
	"code.eitanity.com/kanonarion/internal/callgraph/adapters/analyser/staticcha"
	"code.eitanity.com/kanonarion/internal/callgraph/domain"
	"code.eitanity.com/kanonarion/internal/coordinate"
	"code.eitanity.com/kanonarion/internal/walk/adapters/buildlist/tinygo"
)

// TinyGo's linker is the oracle: every Go function it keeps in the artefact must
// be reachable in the record from main, package init, the //export roots and
// the interrupt handlers, over call, compiler-inserted and linkname edges.
func TestTinyGoOracle_EveryLinkedFunctionIsReachable(t *testing.T) {
	if _, err := exec.LookPath("tinygo"); err != nil {
		t.Skip("skipping: tinygo is not on PATH")
	}
	cases := []struct {
		program, target string
		// residual is what this record cannot reach and why; see the wexp case.
		residual []string
	}{
		{program: "devarm", target: "pico"},
		{program: "devarm", target: "pico2"},
		{program: "blinky", target: "pico"},
		{program: "blinky", target: "arduino"},
		{program: "blinky", target: "hifive1b"},
		{program: "irq", target: "pico"},
		{program: "irq", target: "feather-nrf52840"},
		{program: "irq", target: "microbit"},
		{program: "irq", target: "arduino"},
		{program: "irq", target: "hifive1b"},
		// Each is called only from fmt, strconv, time, cmp or x/mod, which the
		// record holds without bodies.
		{program: "wexp", target: "wasip1", residual: []string{
			"internal/reflectlite.(*RawType).Elem", "internal/reflectlite.(Value).IsNil", "internal/reflectlite.(Value).Pointer",
			"internal/reflectlite.New", "internal/task.(*Mutex).Unlock", "os.(*File).Write", "os.(unixFileHandle).Write",
			"reflect.(Value).Elem", "reflect.(Value).Field", "reflect.(Value).Index",
			"runtime.interfaceTypeAssert", "runtime.stringLess", "runtime.stringNext",
			"unicode/utf8.AppendRune", "unicode/utf8.RuneCountInString",
		}},
	}
	for _, c := range cases {
		t.Run(c.program+"/"+c.target, func(t *testing.T) {
			ctx := context.Background()
			dir := t.TempDir()
			_, file, _, _ := runtime.Caller(0)
			copyFixture(t, filepath.Join(filepath.Dir(file), "testdata", "tinygooracle", c.program), dir)
			frame, err := tinygo.Probe(ctx, "", c.target)
			if err != nil {
				t.Fatalf("probing %s: %v", c.target, err)
			}
			linked := linkedGoFunctions(t, ctx, dir, c.target)
			coord, err := coordinate.NewModuleCoordinate(modulePath(t, dir), coordinate.LocalVersion)
			if err != nil {
				t.Fatal(err)
			}
			rec, err := staticcha.New("0.0.0-test", "", slog.Default()).WithTinyGo(frame).AnalyseDir(ctx, dir, coord)
			if err != nil || rec.OverallStatus != domain.CallGraphStatusExtracted {
				t.Fatalf("AnalyseDir = %v, %v: %s", rec.OverallStatus, err, rec.FailureDetail)
			}
			reached := reachedFromRoots(rec)
			bodied := func(id string) bool {
				pkg := oraclePackage(id)
				return pkg == coord.Path() || isDir(filepath.Join(frame.SourceRoot(), "src", pkg))
			}
			var unreachable []string
			for _, name := range linked {
				id := oracleID(name, coord.Path())
				if bodied(id) && !reached[id] && !reached[wrapperSpelling(id)] {
					unreachable = append(unreachable, id)
				}
			}
			slices.Sort(unreachable)
			if !slices.Equal(unreachable, c.residual) {
				t.Errorf("%d of %d linked Go functions unreachable: %v\nwant %v", len(unreachable), len(linked), unreachable, c.residual)
			}
		})
	}
}

func isDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

func modulePath(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "go.mod")) // #nosec G304 -- a fixture copy
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(string(b))[1]
}

// linkedGoFunctions builds the program and lists the Go functions the linker
// kept: ELF text symbols, or the wasm name section's defined functions.
func linkedGoFunctions(t *testing.T, ctx context.Context, dir, target string) []string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "out")
	if target == "wasip1" {
		out += ".wasm"
	}
	build := childproc.CommandContext(ctx, "tinygo", "build", "-o", out, "-target", target, ".")
	build.Dir = dir
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("tinygo build -target %s: %v\n%s", target, err, b)
	}
	var names []string
	if target == "wasip1" {
		names = wasmFunctionNames(t, out)
	} else {
		nm := childproc.CommandContext(ctx, "nm", "--defined-only", out)
		b, err := nm.Output()
		if err != nil {
			t.Fatalf("nm: %v", err)
		}
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			f := strings.SplitN(sc.Text(), " ", 3)
			if len(f) == 3 && (f[1] == "t" || f[1] == "T") {
				names = append(names, f[2])
			}
		}
	}
	var goNamed []string
	for _, n := range names {
		if isGoFunctionName(n) {
			goNamed = append(goNamed, n)
		}
	}
	return goNamed
}

// isGoFunctionName keeps dotted names and drops what TinyGo links that no Go
// declaration produces: type descriptors, constant data (pkg$string.N and the
// like), assembler-local labels, and the wrappers and dispatch thunks its
// compiler synthesises (goroutine.go:300, goroutine.go:155, interface.go).
func isGoFunctionName(n string) bool {
	if !strings.Contains(n, ".") || strings.HasPrefix(n, "reflect/types.") || strings.HasPrefix(n, ".L") ||
		strings.HasPrefix(n, "interface:") || strings.Contains(n, "$gowrapper") || strings.HasSuffix(n, "#wasmexport") {
		return false
	}
	head := strings.TrimLeft(n, "(*")
	return !strings.Contains(strings.SplitN(head, ".", 2)[0], "$")
}

var recvSpelling = regexp.MustCompile(`^\((\*?)(.+)\.([^.]+)\)\.(.+)$`)

// oracleID renders TinyGo's spelling of a function as the record's node ID.
func oracleID(n, module string) string {
	n = strings.NewReplacer("basic:", "", "named:", "", "slice:", "[]").Replace(n)
	for _, p := range []string{"main.", "(main.", "(*main."} {
		if strings.HasPrefix(n, p) {
			n = strings.Replace(n, "main", module, 1)
		}
	}
	if m := recvSpelling.FindStringSubmatch(n); m != nil {
		n = m[2] + ".(" + m[1] + m[3] + ")." + m[4]
	}
	return n
}

// wrapperSpelling is the record's spelling of a synthesised method wrapper.
func wrapperSpelling(id string) string {
	if m := regexp.MustCompile(`^(.+)\.\((\*?)([^.()]+)\)\.(.+)$`).FindStringSubmatch(id); m != nil {
		return "(" + m[2] + m[1] + "." + m[3] + ")." + m[4]
	}
	return id
}

func oraclePackage(id string) string {
	id = strings.TrimLeft(id, "(*")
	if i := strings.Index(id, "["); i >= 0 {
		id = id[:i]
	}
	slash := strings.LastIndex(id, "/")
	dot := strings.Index(id[slash+1:], ".")
	if dot < 0 {
		return id
	}
	return id[:slash+1+dot]
}

func reachedFromRoots(rec domain.CallGraphRecord) map[string]bool {
	adj := make(map[string][]string)
	for _, e := range rec.Edges {
		if !e.Kind.IsReference() {
			adj[e.FromID] = append(adj[e.FromID], e.ToID)
		}
	}
	seen := make(map[string]bool)
	var stack []string
	for _, n := range rec.Nodes {
		root := (n.Symbol == "main" && n.Receiver == "" && n.Package == rec.Coordinate.Path()) ||
			(domain.IsInitSymbol(n.Symbol) && n.Receiver == "") ||
			!n.ExportDirective.IsZero() || !n.InterruptHandler.IsZero()
		if root && !seen[n.ID] {
			seen[n.ID] = true
			stack = append(stack, n.ID)
		}
	}
	for len(stack) > 0 {
		x := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, y := range adj[x] {
			if !seen[y] {
				seen[y] = true
				stack = append(stack, y)
			}
		}
	}
	return seen
}

// wasmFunctionNames reads the function names of a wasm module's name section,
// leaving out imported functions, which have no body in the module.
func wasmFunctionNames(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 -- the artefact this test built
	if err != nil {
		t.Fatal(err)
	}
	r := &wasmReader{b: b, i: 8}
	imported := 0
	var names []string
	for r.i < len(b) && r.err == nil {
		id := r.byte()
		end := r.i + r.size()
		switch id {
		case 2:
			imported = r.importedFunctions()
		case 0:
			if r.name() == "name" {
				names = r.functionNames(end, imported)
			}
		}
		r.i = end
	}
	if r.err != nil {
		t.Fatalf("reading %s: %v", path, r.err)
	}
	return names
}

// importedFunctions counts the import section's function imports.
func (r *wasmReader) importedFunctions() int {
	imported := 0
	for n := r.size(); n > 0; n-- {
		r.name()
		r.name()
		switch r.byte() {
		case 0:
			r.size()
			imported++
		case 1:
			r.byte()
			r.limits()
		case 2:
			r.limits()
		case 3:
			r.byte()
			r.byte()
		}
	}
	return imported
}

// functionNames reads the name section's function-name subsection.
func (r *wasmReader) functionNames(end, imported int) []string {
	var names []string
	for r.i < end && r.err == nil {
		sub := r.byte()
		subEnd := r.i + r.size()
		if sub == 1 {
			for n := r.size(); n > 0; n-- {
				if idx, name := r.size(), r.name(); idx >= imported {
					names = append(names, name)
				}
			}
		}
		r.i = subEnd
	}
	return names
}

type wasmReader struct {
	b   []byte
	i   int
	err error
}

func (r *wasmReader) byte() byte {
	if r.i >= len(r.b) {
		r.err = errors.New("truncated")
		return 0
	}
	r.i++
	return r.b[r.i-1]
}

func (r *wasmReader) uleb() uint64 {
	v, n := binary.Uvarint(r.b[min(r.i, len(r.b)):])
	if n <= 0 {
		r.err = errors.New("bad LEB128")
		return 0
	}
	r.i += n
	return v
}

// size is a LEB128 count or length, refused when it cannot index the module.
func (r *wasmReader) size() int {
	v := r.uleb()
	if v > uint64(len(r.b)) {
		r.err = errors.New("size beyond the module")
		return 0
	}
	return int(v) // #nosec G115 -- bounded by len(r.b) above
}

func (r *wasmReader) name() string {
	n := r.size()
	if r.i+n > len(r.b) {
		r.err = errors.New("truncated name")
		return ""
	}
	r.i += n
	return string(r.b[r.i-n : r.i])
}

func (r *wasmReader) limits() {
	if r.byte()&1 != 0 {
		r.uleb()
	}
	r.uleb()
}
