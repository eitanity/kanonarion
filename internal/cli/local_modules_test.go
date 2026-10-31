package cli

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	walkdomain "code.eitanity.com/kanonarion/internal/walk/domain"
)

// localShape is one way a project compiles corp.example.com modules from
// directories: a go.work member, corp.example.com/wsmem, and a local-path
// replacement of the require named here.
type localShape struct {
	require, replace, libModule, importPath string
	// extra is appended to the app's go.mod.
	extra string
}

var baseLocalShape = localShape{
	require:    "corp.example.com/lib v0.0.0",
	replace:    "corp.example.com/lib => ../lib",
	libModule:  "corp.example.com/lib",
	importPath: "corp.example.com/lib",
}

// buildLocalFixture writes a workspace (go.work using ./app and ./wsmem) whose
// app requires example.org/pub from the recording proxy and corp.example.com
// code from directories, and returns it served like the private fixture.
func buildLocalFixture(t *testing.T, shape localShape) *privateFixture {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the recording stubs are shell scripts")
	}
	realGo, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not on PATH")
	}
	root := t.TempDir()
	ws := filepath.Join(root, "ws")
	fx := &privateFixture{
		project:  filepath.Join(ws, "app"),
		modcache: filepath.Join(root, "modcache"),
		store:    filepath.Join(root, "store"),
	}
	proxyDir, sums := filepath.Join(root, "proxy"), filepath.Join(root, "sums")
	for _, d := range []string{proxyDir, fx.modcache, fx.project, sums,
		filepath.Join(ws, "lib"), filepath.Join(ws, "wsmem")} {
		if merr := os.MkdirAll(d, 0o750); merr != nil {
			t.Fatal(merr)
		}
	}
	publishPrivateFixtureModule(t, proxyDir, "example.org/pub", "pub")
	// go.sum for the public module, from a module that requires only it: the
	// app itself cannot be tidied, since its member import resolves only
	// through the workspace.
	writePrivateFixtureFile(t, filepath.Join(sums, "go.mod"), "module example.net/sums\n\ngo 1.24\n\nrequire example.org/pub v1.0.0\n")
	writePrivateFixtureFile(t, filepath.Join(sums, "s.go"), "package sums\n\nimport \"example.org/pub\"\n\nvar _ = pub.F\n")
	cmd := exec.Command(realGo, "mod", "tidy") // #nosec G204 -- literal arguments, test fixture only
	cmd.Dir = sums
	cmd.Env = append(os.Environ(), "GOPROXY=file://"+proxyDir, "GOMODCACHE="+fx.modcache, "GOPRIVATE=", "GONOPROXY=",
		"GOSUMDB=off", "GOFLAGS=-mod=mod -modcacherw", "GOTOOLCHAIN=local", "GOENV=off", "GOWORK=off")
	if out, terr := cmd.CombinedOutput(); terr != nil {
		t.Fatalf("go mod tidy: %v\n%s", terr, out)
	}
	goSum, err := os.ReadFile(filepath.Join(sums, "go.sum")) // #nosec G304 -- this test's own temp file
	if err != nil {
		t.Fatal(err)
	}

	writePrivateFixtureFile(t, filepath.Join(ws, "go.work"), "go 1.24\n\nuse (\n\t./app\n\t./wsmem\n)\n")
	writePrivateFixtureFile(t, filepath.Join(ws, "lib", "go.mod"), "module "+shape.libModule+"\n\ngo 1.24\n")
	writePrivateFixtureFile(t, filepath.Join(ws, "lib", "lib.go"), "package lib\n\nfunc L() string { return \"l\" }\n")
	writePrivateFixtureFile(t, filepath.Join(ws, "wsmem", "go.mod"), "module corp.example.com/wsmem\n\ngo 1.24\n")
	writePrivateFixtureFile(t, filepath.Join(ws, "wsmem", "w.go"), "package wsmem\n\nfunc W() string { return \"w\" }\n")
	writePrivateFixtureFile(t, filepath.Join(fx.project, "go.mod"), "module corp.example.com/app\n\ngo 1.24\n\nrequire (\n\t"+
		shape.require+"\n\texample.org/pub v1.0.0\n)\n\nreplace "+shape.replace+"\n"+shape.extra)
	writePrivateFixtureFile(t, filepath.Join(fx.project, "go.sum"), string(goSum))
	writePrivateFixtureFile(t, filepath.Join(fx.project, "main.go"), "package main\n\nimport (\n\tlib \""+shape.importPath+
		"\"\n\t\"corp.example.com/wsmem\"\n\t\"example.org/pub\"\n)\n\nfunc main() { _, _ = lib.L(), wsmem.W(); pub.F() }\n")
	fx.serve(t, root, proxyDir, realGo)
	return fx
}

// localRows decodes the modules array of an audit or latest --json document
// into module path -> staleness_unmeasured, with is_latest required null.
func localRows(t *testing.T, r privateRun) map[string]string {
	t.Helper()
	var doc struct {
		Modules []struct {
			Coordinate          string `json:"coordinate"`
			Module              string `json:"module"`
			IsLatest            *bool  `json:"is_latest"`
			StalenessUnmeasured string `json:"staleness_unmeasured"`
		} `json:"modules"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &doc); err != nil {
		t.Fatalf("decoding %q: %v\nstderr:\n%s", r.stdout, err, r.stderr)
	}
	rows := map[string]string{}
	for _, m := range doc.Modules {
		name, _, _ := strings.Cut(m.Coordinate+m.Module, "@")
		if strings.HasPrefix(name, "corp.example.com") && m.IsLatest != nil {
			t.Errorf("%s: is_latest = %v for a local module, want null", name, *m.IsLatest)
		}
		rows[name] = m.StalenessUnmeasured
	}
	return rows
}

// assertNothingAskedAboutLocal holds a run to no proxy request, no direct dial
// and no go command argument naming a corp.example.com module.
func assertNothingAskedAboutLocal(t *testing.T, r privateRun) {
	t.Helper()
	if got := namingCorp(r.paths); len(got) != 0 {
		t.Errorf("the proxy was asked about a local module: %v", got)
	}
	if got := namingCorp(r.dials); len(got) != 0 {
		t.Errorf("dialled a local module's host: %v", got)
	}
	if got := namingCorp(r.goArgs); len(got) != 0 {
		t.Errorf("the go command was asked about a local module: %v", got)
	}
	if !strings.Contains(strings.Join(r.paths, "\n"), "example.org/pub") {
		t.Errorf("control: the public module was never asked of the proxy: %v", r.paths)
	}
}

// TestLocalModules_NeverNamedToAProxyOrTheGoCommand: a local-path replacement
// and a go.work member are compiled from directories, so with no GOPRIVATE
// setting audit, latest and fetch name neither to the proxy or to a go command
// child, report each as unmeasured for being local, and fetch exits 0.
func TestLocalModules_NeverNamedToAProxyOrTheGoCommand(t *testing.T) {
	shapes := []struct {
		name    string
		shape   localShape
		private bool
		lib     string
	}{
		{"replace", baseLocalShape, false, "corp.example.com/lib"},
		{"replace of a zero pseudo-version require", localShape{
			require: "corp.example.com/lib v0.0.0-00010101000000-000000000000", replace: baseLocalShape.replace,
			libModule: "corp.example.com/lib", importPath: "corp.example.com/lib",
		}, false, "corp.example.com/lib"},
		{"replace at one version", localShape{
			require: "corp.example.com/lib v0.0.0", replace: "corp.example.com/lib v0.0.0 => ../lib",
			libModule: "corp.example.com/lib", importPath: "corp.example.com/lib",
		}, false, "corp.example.com/lib"},
		{"v2 local module", localShape{
			require: "corp.example.com/lib/v2 v2.0.0", replace: "corp.example.com/lib/v2 => ../lib",
			libModule: "corp.example.com/lib/v2", importPath: "corp.example.com/lib/v2",
		}, false, "corp.example.com/lib/v2"},
		{"member also replaced", localShape{
			require: baseLocalShape.require, replace: baseLocalShape.replace, libModule: baseLocalShape.libModule,
			importPath: baseLocalShape.importPath, extra: "\nreplace corp.example.com/wsmem => ../wsmem\n",
		}, false, "corp.example.com/lib"},
		{"local path matching GOPRIVATE", baseLocalShape, true, "corp.example.com/lib"},
	}
	for _, sc := range shapes {
		t.Run(sc.name, func(t *testing.T) {
			fx := buildLocalFixture(t, sc.shape)
			if sc.private {
				t.Setenv("GOPRIVATE", "corp.example.com")
			}
			want := map[string]string{sc.lib: stalenessLocalReplace, "corp.example.com/wsmem": stalenessLocalWorkspaceMember}

			audit := fx.run(t, fx.project, "audit", "--gomod", "./go.mod", "--no-progress", "--json")
			assertNothingAskedAboutLocal(t, audit)
			rows := localRows(t, audit)
			for path, reason := range want {
				if rows[path] != reason {
					t.Errorf("audit row %s: staleness_unmeasured %q, want %q\nstdout:\n%s", path, rows[path], reason, audit.stdout)
				}
			}

			latest := fx.run(t, fx.project, "latest", "--gomod", "./go.mod", "--no-progress", "--json")
			assertNothingAskedAboutLocal(t, latest)
			rows = localRows(t, latest)
			for path, reason := range want {
				if rows[path] != reason {
					t.Errorf("latest row %s: staleness_unmeasured %q, want %q\nstdout:\n%s", path, rows[path], reason, latest.stdout)
				}
			}

			fetch := fx.run(t, fx.project, "fetch", "--gomod", "./go.mod", "--no-progress")
			assertNothingAskedAboutLocal(t, fetch)
			if fetch.exit != 0 || !strings.Contains(fetch.stderr, "fetching 1 code modules from ./go.mod; 1 compiled from a local directory, not fetched") {
				t.Errorf("fetch --gomod exit %d, want 0 with the local module counted as not fetched\nstderr:\n%s", fetch.exit, fetch.stderr)
			}
		})
	}
}

// TestLocalModules_TextRowsSayLocal: the text tables of audit and latest state
// both local reasons in the shared words.
func TestLocalModules_TextRowsSayLocal(t *testing.T) {
	fx := buildLocalFixture(t, baseLocalShape)
	for _, args := range [][]string{
		{"audit", "--gomod", "./go.mod", "--no-progress"},
		{"latest", "--gomod", "./go.mod", "--no-progress"},
	} {
		r := fx.run(t, fx.project, args...)
		for _, line := range strings.Split(r.stdout, "\n") {
			switch {
			case strings.HasPrefix(line, "corp.example.com/lib@") && !strings.Contains(line, "unmeasured (local replace)"),
				strings.HasPrefix(line, "corp.example.com/wsmem@local") && !strings.Contains(line, "unmeasured (workspace member)"):
				t.Errorf("%s: row %q does not say it is local", args[0], line)
			}
		}
		if !strings.Contains(r.stdout, "corp.example.com/wsmem@local") {
			t.Errorf("%s: no row for the workspace member:\n%s", args[0], r.stdout)
		}
	}
}

// TestLocalScopeOf: a member wins over a replace of its path, and a module
// replaced by another module is not local.
func TestLocalScopeOf(t *testing.T) {
	mods := mustParseRecords(t,
		"\tcorp.example.com/lib@v0.0.0\t../lib\n"+
			"\tcorp.example.com/wsmem@v0.0.0\t../wsmem\n"+
			"example.org/fork@v1.1.0\texample.org/orig@v1.0.0\t\n"+
			"example.org/pub@v1.0.0\t\t\n")
	local := localScopeOf(mods, []string{"corp.example.com/wsmem"})
	want := localScope{"corp.example.com/lib": stalenessLocalReplace, "corp.example.com/wsmem": stalenessLocalWorkspaceMember}
	if len(local) != len(want) {
		t.Errorf("localScopeOf = %v, want %v", local, want)
	}
	for path, reason := range want {
		if local[path] != reason {
			t.Errorf("localScopeOf[%s] = %q, want %q", path, local[path], reason)
		}
	}
	got := strings.Join(publishedCoords(mods), " ")
	if got != "example.org/orig@v1.0.0 example.org/pub@v1.0.0" {
		t.Errorf("publishedCoords = %q, want the two published requires", got)
	}
}

func mustParseRecords(t *testing.T, records string) []scopeModule {
	t.Helper()
	mods, err := parseGoListModuleRecords([]byte(records))
	if err != nil {
		t.Fatal(err)
	}
	return mods
}

// TestLocalStalenessReason: every walk node read from disk, including a
// replacement recorded before the local identity, is answered from the walk.
func TestLocalStalenessReason(t *testing.T) {
	for source, want := range map[walkdomain.ResolutionSource]string{
		walkdomain.ResolutionLocalReplace:         stalenessLocalReplace,
		walkdomain.ResolutionLocalAnalysed:        stalenessLocalReplace,
		walkdomain.ResolutionLocalWorkspaceMember: stalenessLocalWorkspaceMember,
		walkdomain.ResolutionMVS:                  "",
		walkdomain.ResolutionReplace:              "",
	} {
		got, local := localStalenessReason(walkdomain.GraphNode{ResolutionSource: source})
		if got != want || local != (want != "") {
			t.Errorf("%s: (%q, %v), want %q", source, got, local, want)
		}
	}
}
