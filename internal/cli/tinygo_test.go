package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/goenv"
	"github.com/eitanity/kanonarion/internal/walk/adapters/buildlist/tinygotest"
)

// hostGOROOT is the toolchain's own root, which the stubbed TinyGo frame names
// so the go children it runs under still have a standard library to list.
func hostGOROOT(t *testing.T) string {
	t.Helper()
	requireGoOnPath(t)
	out, err := exec.Command("go", "env", "GOROOT").Output() // #nosec G204 -- fixed binary, literal arguments
	if err != nil {
		t.Fatalf("go env GOROOT: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// installFakeTinyGo puts a fake tinygo knowing pico first on PATH.
func installFakeTinyGo(t *testing.T) tinygotest.Fake {
	t.Helper()
	pico := tinygotest.Pico()
	pico.GOROOT = hostGOROOT(t)
	fake := tinygotest.Install(t, map[string]tinygotest.Target{"pico": pico})
	t.Setenv("PATH", fake.Dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return fake
}

// pathWithoutTinyGo is PATH with every directory holding a tinygo removed.
func pathWithoutTinyGo(t *testing.T) string {
	t.Helper()
	var keep []string
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if _, err := os.Stat(filepath.Join(dir, "tinygo")); err == nil { // #nosec G703 -- directories of this process's own PATH
			continue
		}
		keep = append(keep, dir)
	}
	return strings.Join(keep, string(os.PathListSeparator))
}

// runTinyGoCLI runs one command against root and returns stdout, stderr and the exit code.
func runTinyGoCLI(t *testing.T, root string, args ...string) (string, string, int) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	err := Run(append(args, "--store-root", root), &stdout, &stderr)
	if err != nil {
		stderr.WriteString(err.Error())
	}
	return stdout.String(), stderr.String(), ExitCodeForError(err)
}

func TestTinyGoFlag_Refusals(t *testing.T) {
	gomod := writeWalkGoMod(t)
	for _, tc := range []struct {
		name string
		path func(t *testing.T) string
		args []string
		want string
	}{
		{"with --target", nil, []string{"walk", "--gomod", gomod, "--tinygo", "pico", "--target", "linux/arm"},
			"--tinygo and --target both declare the build target; pass one of them"},
		{"with --goos", nil, []string{"walk", "--gomod", gomod, "--tinygo", "pico", "--goos", "linux", "--goarch", "arm"},
			"--tinygo and --goos/--goarch both declare the build target; pass one of them"},
		{"on a positional walk", nil, []string{"walk", "example.com/mod@v1.0.0", "--tinygo", "pico"},
			"does not act on --tinygo (applies to walk --gomod"},
		{"no tinygo on PATH", pathWithoutTinyGo, []string{"walk", "--gomod", gomod, "--tinygo", "pico"},
			"declaring --tinygo needs the tinygo command on PATH"},
		{"unknown target", nil, []string{"walk", "--gomod", gomod, "--tinygo", "nosuchboard"},
			"tinygo does not know the target \"nosuchboard\": run `tinygo targets` for the names it offers"},
		{"walk-list with --goos", nil, []string{"walk-list", "--tinygo", "pico", "--goos", "linux", "--goarch", "arm"},
			"--tinygo and --goos/--goarch both declare"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := installFakeTinyGo(t)
			if tc.path != nil {
				t.Setenv("PATH", tc.path(t))
			}
			_, stderr, code := runTinyGoCLI(t, t.TempDir(), tc.args...)
			if code != ExitConfig {
				t.Errorf("exit %d, want %d", code, ExitConfig)
			}
			if !strings.Contains(stderr, tc.want) {
				t.Errorf("refusal %q does not say %q", stderr, tc.want)
			}
			if tc.name == "with --target" || tc.name == "on a positional walk" {
				if calls := fake.Calls(t); len(calls) != 0 {
					t.Errorf("a refused declaration still asked tinygo %q", calls)
				}
			}
		})
	}
}

// Every command that declares --target declares --tinygo with one help text.
func TestTinyGoFlag_RidesWithEveryTargetFlag(t *testing.T) {
	tree := commandsByPath(newRootCmd(io.Discard, io.Discard))
	want := tree["walk"].Flags().Lookup("tinygo")
	if want == nil {
		t.Fatal("walk declares no --tinygo")
	}
	for path, cmd := range tree {
		if path == "walk-list" || cmd.Flags().Lookup("target") == nil || cmd.Flags().Lookup("goos") == nil {
			continue
		}
		got := cmd.Flags().Lookup("tinygo")
		if got == nil {
			t.Errorf("%s declares --target but no --tinygo", path)
			continue
		}
		if got.Usage != want.Usage {
			t.Errorf("%s: --tinygo reads %q, walk reads %q", path, got.Usage, want.Usage)
		}
	}
}

type walkListDoc struct {
	Records []struct {
		ID            string `json:"id"`
		GOOS          string `json:"goos"`
		TinyGoTarget  string `json:"tinygo_target"`
		TinyGoVersion string `json:"tinygo_version"`
	} `json:"records"`
}

func listedIDs(t *testing.T, out string) []string {
	t.Helper()
	var doc walkListDoc
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("walk-list --json: %v\n%s", err, out)
	}
	ids := []string{}
	for _, r := range doc.Records {
		ids = append(ids, r.ID)
	}
	return ids
}

func onlyWalk(t *testing.T, out string) string {
	t.Helper()
	ids := listedIDs(t, out)
	if len(ids) != 1 {
		t.Fatalf("listing holds %v, want exactly one walk", ids)
	}
	return ids[0]
}

// A walk under the stubbed pico frame records it, is selected only by the
// same declaration, and a standard linux/arm walk only by its own.
func TestTinyGoWalk_RecordsAndIsSelectedByItsFrame(t *testing.T) {
	t.Setenv("GOPROXY", "off")
	installFakeTinyGo(t)
	gomod := filepath.Join(writeBothPathsProject(t), "go.mod")
	root := t.TempDir()

	pico := walkAndList(t, root, gomod, []string{"--tinygo", "pico"}, []string{"--tinygo", "pico"})
	assertPicoRecord(t, root, pico)
	if out, _, _ := runTinyGoCLI(t, root, "walk-list", "--goos", "linux", "--goarch", "arm", "--json"); len(listedIDs(t, out)) != 0 {
		t.Errorf("a standard linux/arm listing selected the pico walk: %s", out)
	}

	standard := walkAndList(t, root, gomod, []string{"--target", "linux/arm"}, []string{"--goos", "linux", "--goarch", "arm"})
	if standard == pico {
		t.Fatal("the standard walk reused the TinyGo one")
	}
	if out, _, _ := runTinyGoCLI(t, root, "walk-list", "--tinygo", "pico", "--json"); onlyWalk(t, out) != pico {
		t.Errorf("--tinygo pico selected another walk than %s: %s", pico, out)
	}

	// A manifest-selecting reader under the declaration answers from the pico walk.
	out, stderr, code := runTinyGoCLI(t, root, "dependents", "example.test/proj@local", "--gomod", gomod, "--tinygo", "pico")
	if !strings.Contains(out+stderr, "walk "+pico+" (code scope, frame tinygo/pico (linux/arm))") {
		t.Errorf("dependents --tinygo pico (exit %d) did not answer from %s:\n%s%s", code, pico, out, stderr)
	}
}

// walkAndList walks gomod under declare and returns the one walk list selects.
func walkAndList(t *testing.T, root, gomod string, declare, list []string) string {
	t.Helper()
	if _, stderr, code := runTinyGoCLI(t, root, append([]string{"walk", "--gomod", gomod, "--no-progress"}, declare...)...); code != ExitOK {
		t.Fatalf("walk %v exited %d: %s", declare, code, stderr)
	}
	out, _, _ := runTinyGoCLI(t, root, append([]string{"walk-list", "--json"}, list...)...)
	return onlyWalk(t, out)
}

// assertPicoRecord checks the stored frame on both walk-show surfaces.
func assertPicoRecord(t *testing.T, root, id string) {
	t.Helper()
	show, stderr, code := runTinyGoCLI(t, root, "walk-show", id, "--json")
	if code != ExitOK {
		t.Fatalf("walk-show exited %d: %s", code, stderr)
	}
	var rec struct {
		Graph struct {
			BuildEnv struct {
				GOOS          string   `json:"goos"`
				GOARCH        string   `json:"goarch"`
				GOARM         string   `json:"goarm"`
				TinyGoTarget  string   `json:"tinygo_target"`
				TinyGoVersion string   `json:"tinygo_version"`
				TinyGoTags    []string `json:"tinygo_tags"`
			} `json:"build_env"`
		} `json:"graph"`
	}
	if err := json.Unmarshal([]byte(show), &rec); err != nil {
		t.Fatalf("walk-show --json: %v", err)
	}
	env := rec.Graph.BuildEnv
	if env.GOOS != "linux" || env.GOARCH != "arm" || env.GOARM != "6" || env.TinyGoTarget != "pico" || env.TinyGoVersion != "0.42.0" ||
		strings.Join(env.TinyGoTags, ",") != strings.Join(tinygotest.Pico().Tags, ",") {
		t.Errorf("build_env = %+v", env)
	}
	if text, _, _ := runTinyGoCLI(t, root, "walk-show", id); !strings.Contains(text, "tinygo/pico (linux/arm) under ") {
		t.Errorf("walk-show does not name the TinyGo frame:\n%s", text)
	}
}

// The default path never asks tinygo anything, even with one on PATH.
func TestTinyGo_ADefaultWalkRunsNoProbe(t *testing.T) {
	t.Setenv("GOPROXY", "off")
	fake := installFakeTinyGo(t)
	root := t.TempDir()

	if _, stderr, code := runTinyGoCLI(t, root, "walk", "--gomod", filepath.Join(writeBothPathsProject(t), "go.mod"), "--no-progress"); code != ExitOK {
		t.Fatalf("walk exited %d: %s", code, stderr)
	}
	runTinyGoCLI(t, root, "walk-list", "--json")
	if calls := fake.Calls(t); len(calls) != 0 {
		t.Errorf("a run that declared no TinyGo target asked tinygo %q", calls)
	}
	if declaredTinyGo.Declared() {
		t.Error("a run that declared nothing left a TinyGo frame behind")
	}
}

// The tag-gated dependency, measured with the real tinygo: TinyGo's build
// selects golang.org/x/mod, the host's does not.
func TestTinyGoWalk_RealToolchainSelectsTheTaggedDependency(t *testing.T) {
	if _, err := exec.LookPath("tinygo"); err != nil {
		t.Skip("tinygo is not on PATH; this test measures what it defines")
	}
	requireGoOnPath(t)
	modcache, err := exec.Command("go", "env", "GOMODCACHE").Output() // #nosec G204 -- fixed binary, literal arguments
	if err != nil {
		t.Fatalf("go env GOMODCACHE: %v", err)
	}
	cache := strings.TrimSpace(string(modcache))
	if _, err := os.Stat(filepath.Join(cache, "cache", "download", "golang.org", "x", "mod", "@v", "v0.41.0.zip")); err != nil {
		t.Skip("golang.org/x/mod@v0.41.0 is not in the module cache; this test runs offline")
	}
	t.Setenv("GOPROXY", "off")
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":      "module example.com/tagdep\n\ngo 1.26.0\n\nrequire golang.org/x/mod v0.41.0\n",
		"go.sum":      "golang.org/x/mod v0.41.0 h1:qJmnOUb4YB+FsEuM3HcWucdZASCPGhsX6uljO6pog0c=\ngolang.org/x/mod v0.41.0/go.mod h1:Ek9pY8RKWXwsWvd3rQiHYtMqkjSUV+s1Rj7j4H5Ur6o=\n",
		"main.go":     "package main\n\nfunc main() { println(version()) }\n",
		"v_std.go":    "//go:build !tinygo\n\npackage main\n\nfunc version() string { return \"v1.2.0\" }\n",
		"v_tinygo.go": "//go:build tinygo\n\npackage main\n\nimport \"golang.org/x/mod/semver\"\n\nfunc version() string { return semver.Canonical(\"v1.2\") }\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	gomod := filepath.Join(dir, "go.mod")
	root := t.TempDir()
	nodes := func(args ...string) (string, []string) {
		t.Helper()
		if _, stderr, code := runTinyGoCLI(t, root, append([]string{"walk", "--gomod", gomod, "--from-modcache=" + cache, "--no-progress"}, args...)...); code != ExitOK {
			t.Fatalf("walk %v exited %d: %s", args, code, stderr)
		}
		filter := []string{"walk-list", "--json"}
		if len(args) > 0 {
			filter = append(filter, args...)
		} else {
			filter = append(filter, "--goos", "linux", "--goarch", "amd64")
		}
		out, _, _ := runTinyGoCLI(t, root, filter...)
		id := onlyWalk(t, out)
		show, _, _ := runTinyGoCLI(t, root, "walk-show", id, "--json")
		var rec struct {
			Graph struct {
				Nodes []struct {
					Coordinate struct{ Path string } `json:"coordinate"`
				} `json:"nodes"`
			} `json:"graph"`
		}
		if err := json.Unmarshal([]byte(show), &rec); err != nil {
			t.Fatalf("walk-show --json: %v", err)
		}
		var paths []string
		for _, n := range rec.Graph.Nodes {
			if p := n.Coordinate.Path; p != "example.com/tagdep" && p != "stdlib" {
				paths = append(paths, p)
			}
		}
		text, _, _ := runTinyGoCLI(t, root, "walk-show", id)
		return text, paths
	}

	text, tinyGoModules := nodes("--tinygo", "wasip1")
	if strings.Join(tinyGoModules, ",") != "golang.org/x/mod" {
		t.Errorf("the TinyGo walk's code scope holds %v, want golang.org/x/mod", tinyGoModules)
	}
	if !strings.Contains(text, "tinygo/wasip1 (wasip1/wasm) under ") {
		t.Errorf("the TinyGo walk's frame is not tinygo/wasip1 (wasip1/wasm):\n%s", text)
	}
	if _, hostModules := nodes(); len(hostModules) != 0 {
		t.Errorf("the host walk's code scope holds %v, want no module", hostModules)
	}
}

// Remedies and refusal clauses name the declaration the reader typed.
func TestTinyGo_RemediesAndClausesNameTheDeclaration(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "src"), 0o750); err != nil {
		t.Fatal(err)
	}
	frame, err := goenv.NewTinyGo("pico", "0.42.0", "go1.27.2", "linux", "arm", "6", root, nil)
	if err != nil {
		t.Fatalf("NewTinyGo: %v", err)
	}
	withDeclaredTarget(t, "linux/arm")
	prev := declaredTinyGo
	t.Cleanup(func() { declaredTinyGo = prev })
	declaredTinyGo = frame

	if got := targetFlagHint(); got != " --tinygo pico" {
		t.Errorf("targetFlagHint() = %q", got)
	}
	if got := targetClause(); !strings.Contains(got, "--tinygo pico") {
		t.Errorf("targetClause() = %q", got)
	}

	err = resolveReadTarget(context.Background(), buildTargetFlags{tinygo: "pico"}, "vuln-show", false, "")
	if err == nil || !strings.Contains(err.Error(), "--tinygo") {
		t.Errorf("a --tinygo the read cannot act on was refused as %v", err)
	}
}

// walk-list matches a TinyGo target on its recorded name and never asks the
// tinygo command, so a store can be read on a host without one.
func TestTinyGoWalkList_ReadsTheRecordedNameWithoutTinyGo(t *testing.T) {
	t.Setenv("GOPROXY", "off")
	installFakeTinyGo(t)
	gomod := filepath.Join(writeBothPathsProject(t), "go.mod")
	root := t.TempDir()
	pico := walkAndList(t, root, gomod, []string{"--tinygo", "pico"}, []string{"--tinygo", "pico"})

	t.Setenv("PATH", pathWithoutTinyGo(t))
	out, stderr, code := runTinyGoCLI(t, root, "walk-list", "--tinygo", "pico", "--json")
	if code != ExitOK || onlyWalk(t, out) != pico {
		t.Errorf("walk-list --tinygo pico without tinygo (exit %d) did not select %s: %s%s", code, pico, out, stderr)
	}
	text, _, code := runTinyGoCLI(t, root, "walk-list", "--tinygo", "nosuchboard")
	if code != ExitOK || !strings.Contains(text, `"tinygo/nosuchboard"`) {
		t.Errorf("an unrecorded name (exit %d) did not answer with an empty listing naming it: %s", code, text)
	}
}

// The binary-mode pre-pass is refused by name under --tinygo before anything
// runs: tinygo is never asked and no test binary is built.
func TestTinyGoVulnScan_RefusesTheBinaryPrePass(t *testing.T) {
	gomod := writeWalkGoMod(t)
	for _, args := range [][]string{
		{"vuln-scan", "--gomod", gomod, "--tinygo", "pico", "--binary-pre-pass"},
		{"vuln-scan", "01KQDBVW092ER1HNXZ60X27CMD", "--tinygo", "pico", "--binary-pre-pass"},
	} {
		fake := installFakeTinyGo(t)
		_, stderr, code := runTinyGoCLI(t, t.TempDir(), args...)
		if code != ExitConfig {
			t.Errorf("%v: exit %d, want %d", args, code, ExitConfig)
		}
		if !strings.Contains(stderr, "vuln-scan --tinygo does not act on --binary-pre-pass (applies to a scan without --tinygo") {
			t.Errorf("%v: refusal %q does not name the flag and the reason", args, stderr)
		}
		if calls := fake.Calls(t); len(calls) != 0 {
			t.Errorf("%v: a refused scan still asked tinygo %q", args, calls)
		}
	}
}

// Measured with the real tinygo and govulncheck: the pico closure compiles C,
// so its scan records mode module and its findings read not_determined; the
// wasip1 closure does not, so it is scanned from source.
func TestTinyGoVulnScan_RealToolchainRecordsTheMode(t *testing.T) {
	cache := requireRealTinyGoScan(t)
	gomod := writeWVulnProject(t)
	// One store for both frames, so the advisory database is fetched once.
	root := t.TempDir()
	for _, tc := range []struct{ target, mode string }{{"pico", "module"}, {"wasip1", "source"}} {
		if _, stderr, code := runTinyGoCLI(t, root, "walk", "--gomod", gomod, "--from-modcache="+cache, "--tinygo", tc.target, "--no-progress"); code != ExitOK {
			t.Fatalf("walk --tinygo %s exited %d: %s", tc.target, code, stderr)
		}
		out, stderr, code := runTinyGoCLI(t, root, "vuln-scan", "--gomod", gomod, "--tinygo", tc.target, "--no-progress")
		if code != ExitOK {
			t.Fatalf("vuln-scan --tinygo %s exited %d: %s", tc.target, code, stderr)
		}
		assertTinyGoFindings(t, root, gomod, tc.target, tc.mode)
		if tc.mode == "module" {
			assertModuleModeText(t, root, gomod, tc.target, out)
		}
	}
}

// requireRealTinyGoScan skips unless network tests are enabled (the scan
// downloads the advisory database) and tinygo, govulncheck and the fixture's
// one dependency are present; it returns the module cache the walk reads.
func requireRealTinyGoScan(t *testing.T) string {
	t.Helper()
	if os.Getenv("KANONARION_NETWORK_TESTS") == "" {
		t.Skip("set KANONARION_NETWORK_TESTS=1 to exercise the live advisory database download from vuln.go.dev under a TinyGo frame")
	}
	for _, tool := range []string{"tinygo", "govulncheck"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not on PATH; this test measures what it does", tool)
		}
	}
	requireGoOnPath(t)
	modcache, err := exec.Command("go", "env", "GOMODCACHE").Output() // #nosec G204 -- fixed binary, literal arguments
	if err != nil {
		t.Fatalf("go env GOMODCACHE: %v", err)
	}
	cache := strings.TrimSpace(string(modcache))
	if _, err := os.Stat(filepath.Join(cache, "cache", "download", "golang.org", "x", "text", "@v", "v0.3.7.zip")); err != nil {
		t.Skip("golang.org/x/text@v0.3.7 is not in the module cache; the walk runs offline")
	}
	return cache
}

// writeWVulnProject is a TinyGo program exporting a function that calls the
// vulnerable golang.org/x/text/language.Parse, and returns its go.mod.
func writeWVulnProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":  "module example.com/wvuln\n\ngo 1.24\n\nrequire golang.org/x/text v0.3.7 // indirect\n",
		"go.sum":  "golang.org/x/text v0.3.7 h1:olpwvP2KacW1ZWvsR7uQhoyTYvKAupfQrRGBFM352Gk=\ngolang.org/x/text v0.3.7/go.mod h1:u+2+/6zg+i71rQMx5EYifcz6MCKuco9NR6JIITiCfzQ=\n",
		"main.go": "package main\n\nimport \"golang.org/x/text/language\"\n\n//go:wasmexport parse\nfunc parse(n int32) int32 {\n\t_, err := language.Parse(\"en-US\")\n\tif err != nil {\n\t\treturn -1\n\t}\n\treturn n\n}\n\nfunc main() {}\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, "go.mod")
}

// assertTinyGoFindings reads x/text's record under the frame and checks every
// finding states mode, and that a module-mode one is not_determined.
func assertTinyGoFindings(t *testing.T, root, gomod, target, mode string) {
	t.Helper()
	show, _, _ := runTinyGoCLI(t, root, "vuln-show", "golang.org/x/text@v0.3.7", "--gomod", gomod, "--tinygo", target, "--json")
	var rec struct {
		Findings []struct {
			ID        string `json:"id"`
			State     string `json:"reachability_state"`
			Sound     string `json:"soundness"`
			Reachable struct {
				DerivedBy struct {
					Fidelity string `json:"fidelity"`
				} `json:"derived_by"`
			} `json:"reachable"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(show), &rec); err != nil || len(rec.Findings) == 0 {
		t.Fatalf("vuln-show --tinygo %s --json: %v\n%s", target, err, show)
	}
	for _, f := range rec.Findings {
		if f.Reachable.DerivedBy.Fidelity != mode {
			t.Errorf("%s %s: fidelity %q, want %q", target, f.ID, f.Reachable.DerivedBy.Fidelity, mode)
		}
		if mode == "module" && (f.State != "not_determined" || f.Sound != "unconfirmed") {
			t.Errorf("%s %s: state %s soundness %s, want not_determined unconfirmed", target, f.ID, f.State, f.Sound)
		}
	}
}

// assertModuleModeText checks the text says reachability is not established
// and vuln-scan-show's JSON carries the mode.
func assertModuleModeText(t *testing.T, root, gomod, target, scanOut string) {
	t.Helper()
	if text, _, _ := runTinyGoCLI(t, root, "vuln-show", "golang.org/x/text@v0.3.7", "--gomod", gomod, "--tinygo", target); !strings.Contains(text, "reachability is not established") {
		t.Errorf("vuln-show text does not say reachability is not established:\n%s", text)
	}
	run := regexp.MustCompile(`Run ID: (\S+)`).FindStringSubmatch(scanOut)
	if run == nil {
		t.Fatalf("vuln-scan printed no run id:\n%s", scanOut)
	}
	if scanShow, _, _ := runTinyGoCLI(t, root, "vuln-scan-show", run[1], "--json"); !strings.Contains(scanShow, `"fidelity": "module"`) {
		t.Errorf("vuln-scan-show --json does not print the module mode:\n%s", scanShow)
	}
}

// A walk-id scan of a TinyGo walk is refused by name before any child runs:
// the frame reaches the scanner only through the manifest path.
func TestTinyGoVulnScan_WalkIDOfATinyGoWalkIsRefused(t *testing.T) {
	t.Setenv("GOPROXY", "off")
	installFakeTinyGo(t)
	gomod := filepath.Join(writeBothPathsProject(t), "go.mod")
	root := t.TempDir()
	pico := walkAndList(t, root, gomod, []string{"--tinygo", "pico"}, []string{"--tinygo", "pico"})
	// Control: a standard --target walk is not refused by this check.
	standard := walkAndList(t, root, gomod, []string{"--target", "linux/arm"}, []string{"--goos", "linux", "--goarch", "arm"})
	if _, stderr, _ := runTinyGoCLI(t, root, "vuln-scan", standard, "--no-progress"); strings.Contains(stderr, "cannot scan a walk recorded under") {
		t.Errorf("a standard --target walk was refused as a TinyGo one: %s", stderr)
	}

	stubs := t.TempDir()
	spawned := filepath.Join(t.TempDir(), "spawned")
	for _, name := range []string{"go", "govulncheck", "tinygo"} {
		writeStub(t, filepath.Join(stubs, name), "#!/bin/sh\necho "+name+" >> "+spawned+"\nexit 1\n")
	}
	t.Setenv("PATH", stubs+string(os.PathListSeparator)+os.Getenv("PATH"))
	for _, extra := range [][]string{nil, {"--reachability"}, {"--force"}} {
		_, stderr, code := runTinyGoCLI(t, root, append([]string{"vuln-scan", pico, "--no-progress"}, extra...)...)
		if code != ExitConfig {
			t.Errorf("%v: exit %d, want %d", extra, code, ExitConfig)
		}
		want := "vuln-scan <walk-id> cannot scan a walk recorded under tinygo/pico (linux/arm): a TinyGo frame reaches the scan only through the manifest; run vuln-scan --gomod " + gomod + " --tinygo pico"
		if !strings.Contains(stderr, want) {
			t.Errorf("%v: refusal %q does not say %q", extra, stderr, want)
		}
	}
	if raw, err := os.ReadFile(spawned); err == nil { // #nosec G304 -- written by this test's own stubs
		t.Errorf("a refused scan spawned children: %q", raw)
	}
}

func writeStub(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil { // #nosec G306 -- a stub this test execs
		t.Fatal(err)
	}
}
