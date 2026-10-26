package builder

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/adapters/goenv"
	localdomain "code.eitanity.com/kanonarion/internal/local/domain"
)

// frameStubs installs a go and a tinygo that log every invocation with the
// frame variables it saw, and answer as a one-main tree would. It returns the
// go binary and the log path.
func frameStubs(t *testing.T) (goBin, logPath string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stubs are shell scripts")
	}
	dir := t.TempDir()
	logPath = filepath.Join(dir, "children.log")
	log := `echo "$(basename "$0") $* | GOOS=$GOOS GOARCH=$GOARCH GOROOT=$GOROOT CGO=$CGO_ENABLED" >> ` + logPath + "\n"
	out := `out=""; prev=""; for a in "$@"; do [ "$prev" = "-o" ] && out="$a"; prev="$a"; done` + "\n"
	goScript := "#!/bin/sh\n" + log + out + `case "$1" in
list) echo '{"ImportPath":"example.com/fw","Name":"main","Dir":"/src/fw"}' ;;
build) : > "$out" ;;
tool) echo '1000 T example.com/fw.main'; echo '1001 T (*golang.org/x/text/language.Tag).String'; echo '1002 T (golang.org/x/text/language.Tag).Base'; echo '1003 T golang.org/x/text/language.ParseAcceptLanguage' ;;
esac
`
	tinygoScript := "#!/bin/sh\n" + log + out + `[ "$1" = build ] && : > "$out"` + "\n"
	for name, body := range map[string]string{"go": goScript, "tinygo": tinygoScript} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o700); err != nil { // #nosec G306 -- test stubs must be executable
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return filepath.Join(dir, "go"), logPath
}

func childLines(t *testing.T, logPath string) []string {
	t.Helper()
	raw, err := os.ReadFile(logPath) // #nosec G304 -- the test's own log
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(raw)), "\n")
}

func tinyGoFrame(t *testing.T, target, goos, goarch string, tags []string) goenv.TinyGo {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "src"), 0o750); err != nil {
		t.Fatal(err)
	}
	f, err := goenv.NewTinyGo(target, "0.42.0", "go1.27.2", goos, goarch, "6", root, root, "thumbv6m-unknown-unknown-eabi", tags)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// A TinyGo frame lists under its GOROOT and tags, builds with tinygo at -opt=0,
// reads the table with go tool nm outside the frame, and reports Go's spelling.
func TestProbe_TinyGoFrameBuildsWithTinyGo(t *testing.T) {
	goBin, logPath := frameStubs(t)
	pico := tinyGoFrame(t, "pico", "linux", "arm", []string{"tinygo", "pico"})
	res, err := New(goBin).WithTinyGo(pico).Probe(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	lines := childLines(t, logPath)
	if len(lines) != 3 {
		t.Fatalf("children = %q, want list, tinygo build, nm", lines)
	}
	want := []string{
		"go list -tags=tinygo,pico -json ./... | GOOS=linux GOARCH=arm GOROOT=" + pico.GOROOT() + " CGO=1",
		"tinygo build -target=pico -opt=0 -o ",
		"go tool nm ",
	}
	for i, w := range want {
		if !strings.HasPrefix(lines[i], w) {
			t.Errorf("child %d = %q, want it to begin %q", i, lines[i], w)
		}
	}
	if !strings.HasSuffix(lines[1], " example.com/fw | GOOS= GOARCH= GOROOT= CGO=") {
		t.Errorf("tinygo build was handed the frame's environment or another package: %q", lines[1])
	}
	if strings.Contains(lines[2], pico.GOROOT()) {
		t.Errorf("go tool nm ran under the TinyGo GOROOT: %q", lines[2])
	}
	if res.Builder != localdomain.ProbeBuilderTinyGo || len(res.Binaries) != 1 || res.Binaries[0].Builder != localdomain.ProbeBuilderTinyGo {
		t.Errorf("builder = %q, binaries %+v", res.Builder, res.Binaries)
	}
	for _, sym := range []string{"golang.org/x/text/language.(*Tag).String", "golang.org/x/text/language.Tag.Base", "golang.org/x/text/language.ParseAcceptLanguage"} {
		if _, ok := res.BinarySymbols[sym]; !ok {
			t.Errorf("symbol %s is not in Go's spelling in %v", sym, res.BinarySymbols)
		}
	}
}

// A standard frame builds with go build under its GOOS/GOARCH, and the table
// keeps go's own spelling.
func TestProbe_StandardFrameBuildsUnderTheTarget(t *testing.T) {
	goBin, logPath := frameStubs(t)
	target, err := goenv.ParseTarget("linux/arm64")
	if err != nil {
		t.Fatal(err)
	}
	res, err := New(goBin).WithTarget(target).Probe(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	lines := childLines(t, logPath)
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "go list -json ./... | GOOS=linux GOARCH=arm64 ") ||
		!strings.HasPrefix(lines[1], "go build -gcflags=all=-l -o ") || !strings.Contains(lines[1], "| GOOS=linux GOARCH=arm64 ") {
		t.Errorf("children = %q", lines)
	}
	if res.Builder != localdomain.ProbeBuilderGo {
		t.Errorf("builder = %q", res.Builder)
	}
	if _, ok := res.BinarySymbols["(*golang.org/x/text/language.Tag).String"]; !ok {
		t.Error("a go build table was rewritten as if TinyGo had produced it")
	}
}

// Every wasm frame is refused before any child runs, naming the declaration.
func TestProbe_WasmFramesAreRefusedBeforeAnyChild(t *testing.T) {
	goBin, logPath := frameStubs(t)
	wasip1, err := goenv.ParseTarget("wasip1/wasm")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		p    *Prober
		flag string
	}{
		{New(goBin).WithTarget(wasip1), "--target wasip1/wasm"},
		{New(goBin).WithTinyGo(tinyGoFrame(t, "wasip1", "wasip1", "wasm", []string{"tinygo.wasm"})), "--tinygo wasip1"},
		{New(goBin).WithTinyGo(tinyGoFrame(t, "wasip2", "linux", "arm", []string{"tinygo.wasm", "wasip2"})), "--tinygo wasip2"},
	} {
		_, perr := tc.p.Probe(context.Background(), t.TempDir())
		var refusal *WasmArtefactError
		if !errors.As(perr, &refusal) || refusal.Flag != tc.flag || !strings.Contains(perr.Error(), "wasm module") {
			t.Errorf("Probe under %s = %v, want the wasm refusal", tc.flag, perr)
		}
	}
	if lines := childLines(t, logPath); len(lines) != 0 {
		t.Errorf("a refused frame ran children: %q", lines)
	}
}

func TestNormaliseTinyGoSymbol(t *testing.T) {
	for in, want := range map[string]string{
		"(*golang.org/x/text/language.Tag).String":            "golang.org/x/text/language.(*Tag).String",
		"(golang.org/x/text/language.Tag).Base":               "golang.org/x/text/language.Tag.Base",
		"golang.org/x/text/language.ParseAcceptLanguage":      "golang.org/x/text/language.ParseAcceptLanguage",
		"(*example.com/m.Box[example.com/m/v.T]).Get":         "example.com/m.(*Box[example.com/m/v.T]).Get",
		"(*example.com/m.T":                                   "(*example.com/m.T",
		"(noDot).M":                                           "(noDot).M",
		"(*example.com/m.T)":                                  "(*example.com/m.T)",
		"runtime.alloc":                                       "runtime.alloc",
		"(*golang.org/x/text/internal/language.Builder).Make": "golang.org/x/text/internal/language.(*Builder).Make",
	} {
		if got := normaliseTinyGoSymbol(in); got != want {
			t.Errorf("normaliseTinyGoSymbol(%q) = %q, want %q", in, got, want)
		}
	}
}
