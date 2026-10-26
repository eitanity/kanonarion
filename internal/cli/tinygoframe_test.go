package cli

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/adapters/goenv"
	cgdomain "code.eitanity.com/kanonarion/internal/callgraph/domain"
	"code.eitanity.com/kanonarion/internal/coordinate"
)

// writeTree writes files under a fresh directory and returns it.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// offlineWithoutTinyGo runs the test offline, with no tinygo to ask, from dir.
func offlineWithoutTinyGo(t *testing.T, dir string) {
	t.Helper()
	requireGoOnPath(t)
	t.Setenv("GOPROXY", "off")
	t.Setenv("GOFLAGS", "-mod=readonly")
	t.Setenv("PATH", pathWithoutTinyGo(t))
	t.Chdir(dir)
}

// The blinky fixture: a program importing machine, which only TinyGo provides.
func blinkyTree(t *testing.T, pkg string) string {
	return writeTree(t, map[string]string{
		"go.mod":  "module example.com/blinky\n\ngo 1.24\n",
		"main.go": "package main\n\nimport \"" + pkg + "\"\n\nfunc main() { _ = " + filepath.Base(pkg) + ".LED }\n",
	})
}

// Every command that loads or resolves the standard frame names TinyGo for a
// package only TinyGo provides, with the exit code it had.
func TestTinyGoPackage_EveryCommandNamesTinyGo(t *testing.T) {
	offlineWithoutTinyGo(t, blinkyTree(t, "machine"))
	root := t.TempDir()
	for _, tc := range []struct {
		args  []string
		rerun string
		code  int
	}{
		{[]string{"local", "."}, "kanonarion local ", ExitFailed},
		{[]string{"walk", "--gomod", "./go.mod", "--no-progress"}, "kanonarion walk --gomod ./go.mod --no-progress --tinygo <target>", ExitConfig},
		{[]string{"audit", "--gomod", "./go.mod"}, "kanonarion audit --gomod ./go.mod --tinygo <target>", ExitConfig},
		{[]string{"inspect", "--gomod", "./go.mod"}, "kanonarion inspect --gomod ./go.mod --tinygo <target>", ExitPartial},
		{[]string{"sbom", "--package", "."}, "kanonarion sbom --package . --tinygo <target>", ExitConfig},
	} {
		t.Run(tc.args[0], func(t *testing.T) {
			out, stderr, code := runTinyGoCLI(t, root, tc.args...)
			all := out + stderr
			if !strings.Contains(all, "machine is provided by TinyGo, not Go: analyse the TinyGo build with\n  "+tc.rerun) ||
				!strings.Contains(all, "--tinygo <target>\n  (`tinygo targets` lists the targets)") {
				t.Errorf("%v does not name TinyGo and --tinygo:\n%s", tc.args, all)
			}
			if strings.Contains(all, "Fix the package so it compiles") {
				t.Errorf("%v still says to fix a package that compiles under TinyGo:\n%s", tc.args, all)
			}
			if code != tc.code {
				t.Errorf("%v exited %d, want %d", tc.args, code, tc.code)
			}
		})
	}
}

// A package neither Go nor TinyGo provides keeps the compile-error remedy.
func TestTinyGoPackage_AnUnknownPackageKeepsTodaysRemedy(t *testing.T) {
	offlineWithoutTinyGo(t, blinkyTree(t, "foo/bar"))
	out, stderr, _ := runTinyGoCLI(t, t.TempDir(), "local", ".")
	if !strings.Contains(out, "Fix the package so it compiles") || strings.Contains(out+stderr, "provided by TinyGo") {
		t.Errorf("foo/bar is not TinyGo's, so the remedy is unchanged:\n%s%s", out, stderr)
	}
}

// A stored record's remedy, for a fetched module, names the TinyGo build too.
func TestTinyGoPackage_FetchedRecordRemedy(t *testing.T) {
	t.Setenv("PATH", pathWithoutTinyGo(t))
	coord, err := coordinate.NewModuleCoordinate("example.com/drivers", "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	got := incompleteGraphRemedy(context.Background(), coord, cgdomain.FailureCauseModule,
		"x.go:3:2: package machine is not in std (src/machine)", "")
	if !strings.Contains(got, "machine is provided by TinyGo, not Go") ||
		!strings.Contains(got, "kanonarion callgraph example.com/drivers@v1.0.0 --tinygo <target>") {
		t.Errorf("remedy:\n%s", got)
	}
	// One missing package TinyGo does not provide: --tinygo would not find it either.
	mixed := incompleteGraphRemedy(context.Background(), coord, cgdomain.FailureCauseModule,
		"package machine is not in std (a); package foo/bar is not in std (b)", "")
	if strings.Contains(mixed, "provided by TinyGo") {
		t.Errorf("a remedy with an unknown package named TinyGo:\n%s", mixed)
	}
}

// A declared TinyGo frame is never sent to --tinygo.
func TestTinyGoPackage_NotUnderADeclaredTinyGoFrame(t *testing.T) {
	installFakeTinyGo(t)
	if err := resolveTinyGoTarget(context.Background(), "pico"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { declare(goenv.Target{}, goenv.TinyGo{}); invokedCmd = nil })
	invokedCmd = newWalkCmd(io.Discard, io.Discard)
	if got := withTinyGoRemedy(context.Background(), "package machine is not in std (x)"); got != "package machine is not in std (x)" {
		t.Errorf("under --tinygo the refusal gained a remedy: %s", got)
	}
}

// A command that takes no --tinygo is never told to pass it.
func TestTinyGoPackage_OnlyWhereTheFlagExists(t *testing.T) {
	offlineWithoutTinyGo(t, blinkyTree(t, "machine"))
	_, stderr, code := runTinyGoCLI(t, t.TempDir(), "latest", "--gomod", "./go.mod")
	if code != ExitConfig || strings.Contains(stderr, "--tinygo") || !strings.Contains(stderr, "package machine is not in std") {
		t.Errorf("latest (exit %d):\n%s", code, stderr)
	}
}

// The tg fixture with a dependency beside it: a TinyGo-only file in the module
// and one in a dependency it compiles against.
func tagDepTree(t *testing.T, extra map[string]string) string {
	files := map[string]string{
		"go.mod":        "module example.com/tagdep\n\ngo 1.24\n\nrequire example.com/dep v0.0.0\n\nreplace example.com/dep => ./dep\n",
		"main.go":       "package main\n\nimport \"example.com/dep\"\n\nfunc main() { println(version(), dep.V) }\n",
		"v_std.go":      "//go:build !tinygo\n\npackage main\n\nfunc version() string { return \"v1.2.0\" }\n",
		"v_tinygo.go":   "//go:build tinygo\n\npackage main\n\nimport \"example.com/dep/only\"\n\nfunc version() string { return only.V }\n",
		"dep/go.mod":    "module example.com/dep\n\ngo 1.24\n",
		"dep/dep.go":    "package dep\n\nconst V = 1\n",
		"dep/only/o.go": "package only\n\nconst V = \"v1\"\n",
	}
	for k, v := range extra {
		files[k] = v
	}
	return writeTree(t, files)
}

// walk, sbom and local state v_tinygo.go and name the flag; the exit is unchanged.
func TestFrameExcludes_TheTagDepFixture(t *testing.T) {
	offlineWithoutTinyGo(t, tagDepTree(t, nil))
	root := t.TempDir()
	for _, args := range [][]string{
		{"walk", "--gomod", "./go.mod", "--no-progress"},
		{"sbom", "--package", "."},
		{"local", "."},
	} {
		t.Run(args[0], func(t *testing.T) {
			_, stderr, _ := runTinyGoCLI(t, root, args...)
			want := "notice: 1 file(s) built only by TinyGo are not in this frame (v_tinygo.go): their imports and code are not analysed; " +
				"analyse the TinyGo build with kanonarion " + strings.Join(args, " ") + " --tinygo <target>\n"
			if strings.Count(stderr, "built only by TinyGo") != 1 || !strings.Contains(stderr, want) {
				t.Errorf("%v stderr does not state the file once:\n%s", args, stderr)
			}
		})
	}
	for _, args := range [][]string{{"walk", "--gomod", "./go.mod", "--no-progress", "--json"}, {"local", ".", "--force", "--json"}} {
		out, _, _ := runTinyGoCLI(t, root, args...)
		var doc struct {
			FrameExcludes *frameExcludesJSON `json:"frame_excludes"`
		}
		if err := json.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if doc.FrameExcludes == nil || strings.Join(doc.FrameExcludes.Files, ",") != "v_tinygo.go" ||
			!strings.HasSuffix(doc.FrameExcludes.Command, " --tinygo <target>") {
			t.Errorf("%v frame_excludes = %+v", args, doc.FrameExcludes)
		}
	}
}

// The b fixture: local states the TinyGo half of a split function.
func TestFrameExcludes_LocalStatesTheSplitFile(t *testing.T) {
	offlineWithoutTinyGo(t, writeTree(t, map[string]string{
		"go.mod":        "module example.com/split\n\ngo 1.24\n",
		"main.go":       "package main\n\nfunc main() { run() }\n",
		"run_std.go":    "//go:build !tinygo\n\npackage main\n\nimport \"fmt\"\n\nfunc run() { fmt.Println(\"std\") }\n",
		"run_tinygo.go": "//go:build tinygo\n\npackage main\n\nfunc run() { tinyOnly() }\n\nfunc tinyOnly() {}\n",
	}))
	if _, stderr, code := runTinyGoCLI(t, t.TempDir(), "local", "."); code != ExitOK || !strings.Contains(stderr, "(run_tinygo.go)") {
		t.Errorf("local (exit %d) does not state run_tinygo.go:\n%s", code, stderr)
	}
}

// Neighbouring constraints and a dependency's file, through the walk.
func TestFrameExcludes_NeighbouringConstraints(t *testing.T) {
	for _, tc := range []struct {
		name  string
		extra map[string]string
		want  string // the file list, empty for no notice
	}{
		{"tinygo and wasm", map[string]string{"x.go": "//go:build tinygo && wasm\n\npackage main\n"}, "v_tinygo.go, x.go"},
		{"not tinygo", map[string]string{"v_tinygo.go": "//go:build !tinygo\n\npackage main\n"}, ""},
		{"tinygo or windows", map[string]string{"v_tinygo.go": "//go:build tinygo || windows\n\npackage main\n"}, ""},
		{"legacy line", map[string]string{"v_tinygo.go": "// +build tinygo\n\npackage main\n"}, "v_tinygo.go"},
		{"control", map[string]string{"v_tinygo.go": "//go:build windows\n\npackage main\n"}, ""},
		{"a dependency's file", map[string]string{"dep/t.go": "//go:build tinygo\n\npackage dep\n"}, "dep/t.go, v_tinygo.go"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			offlineWithoutTinyGo(t, tagDepTree(t, tc.extra))
			_, stderr, code := runTinyGoCLI(t, t.TempDir(), "walk", "--gomod", "./go.mod", "--no-progress")
			if code != ExitOK {
				t.Fatalf("walk exited %d: %s", code, stderr)
			}
			got := ""
			if _, rest, ok := strings.Cut(stderr, "are not in this frame ("); ok {
				got, _, _ = strings.Cut(rest, "):")
			}
			if got != tc.want {
				t.Errorf("notice names %q, want %q:\n%s", got, tc.want, stderr)
			}
		})
	}
}

// Under --tinygo the files are in the frame, and nothing is said.
func TestFrameExcludes_SilentUnderTinyGo(t *testing.T) {
	offlineWithoutTinyGo(t, tagDepTree(t, nil))
	installFakeTinyGo(t)
	_, stderr, code := runTinyGoCLI(t, t.TempDir(), "walk", "--gomod", "./go.mod", "--no-progress", "--tinygo", "pico")
	if code != ExitOK || strings.Contains(stderr, "built only by TinyGo") {
		t.Errorf("walk --tinygo pico (exit %d) stated the notice:\n%s", code, stderr)
	}
}

// The statement names five files and counts the rest.
func TestFrameExcludes_StatementCapsTheList(t *testing.T) {
	j := &frameExcludesJSON{Files: []string{"a", "b", "c", "d", "e", "f", "g"}, Command: "kanonarion local . --tinygo <target>"}
	want := "notice: 7 file(s) built only by TinyGo are not in this frame (a, b, c, d, e … and 2 more): " +
		"their imports and code are not analysed; analyse the TinyGo build with kanonarion local . --tinygo <target>\n"
	if got := j.statement(); got != want {
		t.Errorf("statement:\n%s\nwant:\n%s", got, want)
	}
}

// A package go cannot find has no module; the package list says so in go's
// words alone, without a template failing over the missing module.
func TestSBOMPackage_AMissingPackageFailsOnlyInGosWords(t *testing.T) {
	offlineWithoutTinyGo(t, blinkyTree(t, "machine"))
	_, stderr, code := runTinyGoCLI(t, t.TempDir(), "sbom", "--package", ".")
	if code != ExitConfig || strings.Contains(stderr, "nil pointer evaluating") || !strings.Contains(stderr, "package machine is not in std") {
		t.Errorf("sbom --package . (exit %d):\n%s", code, stderr)
	}
}
