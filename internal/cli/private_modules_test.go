package cli

import (
	"archive/zip"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	_ "modernc.org/sqlite"
)

// privateFixture is a project requiring a private module (corp.example.com/a)
// and a public one (example.org/pub), both primed in its own module cache, with
// an HTTPS module proxy that serves both and records every path it is asked.
type privateFixture struct {
	project, modcache, store, gitLog, goLog string
	proxyURL, proxyAddr                     string

	mu    sync.Mutex
	paths []string
}

type privateRun struct {
	stdout, stderr string
	exit           int
	paths, dials   []string
	git, goArgs    []string
}

func buildPrivateFixture(t *testing.T) *privateFixture {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the recording stubs are shell scripts")
	}
	realGo, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not on PATH")
	}
	root := t.TempDir()
	fx := &privateFixture{
		project:  filepath.Join(root, "project"),
		modcache: filepath.Join(root, "modcache"),
		store:    filepath.Join(root, "store"),
	}
	proxyDir := filepath.Join(root, "proxy")
	for _, d := range []string{proxyDir, fx.modcache, fx.project} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	publishPrivateFixtureModule(t, proxyDir, "corp.example.com/a", "a")
	publishPrivateFixtureModule(t, proxyDir, "example.org/pub", "pub")
	writePrivateFixtureFile(t, filepath.Join(fx.project, "go.mod"),
		"module example.net/app\n\ngo 1.24\n\nrequire (\n\tcorp.example.com/a v1.0.0\n\texample.org/pub v1.0.0\n)\n")
	writePrivateFixtureFile(t, filepath.Join(fx.project, "main.go"),
		"package main\n\nimport (\n\t\"corp.example.com/a\"\n\t\"example.org/pub\"\n)\n\nfunc main() { a.F(); pub.F() }\n")
	cmd := exec.Command(realGo, "mod", "tidy") // #nosec G204 -- literal arguments, test fixture only
	cmd.Dir = fx.project
	cmd.Env = append(os.Environ(), "GOPROXY=file://"+proxyDir, "GOMODCACHE="+fx.modcache, "GOPRIVATE=", "GONOPROXY=",
		"GOSUMDB=off", "GOFLAGS=-mod=mod -modcacherw", "GOTOOLCHAIN=local", "GOENV=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go mod tidy: %v\n%s", err, out)
	}
	fx.serve(t, root, proxyDir, realGo)
	return fx
}

// serve puts the recording stubs on PATH and the recording proxy over
// proxyDir in GOPROXY, trusted through SSL_CERT_FILE.
func (fx *privateFixture) serve(t *testing.T, root, proxyDir, realGo string) {
	t.Helper()
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o750); err != nil {
		t.Fatal(err)
	}
	fx.gitLog, fx.goLog = filepath.Join(root, "git.log"), filepath.Join(root, "go.log")
	// git answers nothing; the go command keeps its own route to the recorder
	// but any direct fetch it makes is sent to a closed loopback port.
	writeAirGapExec(t, filepath.Join(bin, "git"), "#!/bin/sh\nprintf '%s\\n' \"$*\" >> "+fx.gitLog+"\nexit 1\n")
	writeAirGapExec(t, filepath.Join(bin, "go"), "#!/bin/sh\nprintf '%s\\n' \"$*\" >> "+fx.goLog+"\nHTTPS_PROXY=http://127.0.0.1:9 https_proxy=http://127.0.0.1:9 GOSUMDB=off exec "+realGo+" \"$@\"\n")
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	for k, v := range map[string]string{"GOMODCACHE": fx.modcache, "GOENV": "off", "GOTOOLCHAIN": "local", "GOFLAGS": "",
		"GOSUMDB": "", "GONOSUMDB": "", "GONOSUMCHECK": "", "GOPRIVATE": "", "GONOPROXY": ""} {
		t.Setenv(k, v)
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fx.mu.Lock()
		fx.paths = append(fx.paths, r.URL.Path)
		fx.mu.Unlock()
		http.FileServer(http.Dir(proxyDir)).ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	fx.proxyURL, fx.proxyAddr = srv.URL, srv.Listener.Addr().String()
	ca := filepath.Join(root, "ca.pem")
	writePrivateFixtureFile(t, ca, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})))
	t.Setenv("SSL_CERT_FILE", ca)
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Fatalf("http.DefaultTransport is %T", http.DefaultTransport)
	}
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	original := transport.TLSClientConfig
	transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	t.Cleanup(func() { transport.TLSClientConfig = original })
	t.Setenv("GOPROXY", fx.proxyURL)
}

func publishPrivateFixtureModule(t *testing.T, proxyDir, path, pkg string) {
	t.Helper()
	dir := filepath.Join(proxyDir, filepath.FromSlash(path), "@v")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	gomod := "module " + path + "\n\ngo 1.24\n"
	writePrivateFixtureFile(t, filepath.Join(dir, "v1.0.0.mod"), gomod)
	writePrivateFixtureFile(t, filepath.Join(dir, "v1.0.0.info"), `{"Version":"v1.0.0","Time":"2026-01-01T00:00:00Z"}`)
	writePrivateFixtureFile(t, filepath.Join(dir, "list"), "v1.0.0\n")
	writePrivateFixtureFile(t, filepath.Join(dir, "v1.0.0.zip"), zipOf(t, path+"@v1.0.0/", map[string]string{
		"go.mod":    gomod,
		pkg + ".go": "package " + pkg + "\n\n// F is called by the fixture project.\nfunc F() {}\n",
	}))
}

func writePrivateFixtureFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil { // #nosec G703 -- a path under this test's temp dir
		t.Fatalf("writing %s: %v", path, err)
	}
}

func zipOf(t *testing.T, prefix string, files map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(prefix + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// run executes args from dir against a fresh store.
func (fx *privateFixture) run(t *testing.T, dir string, args ...string) privateRun {
	t.Helper()
	if err := os.RemoveAll(fx.store); err != nil {
		t.Fatal(err)
	}
	return fx.runKeepingStore(t, dir, args...)
}

// runKeepingStore executes args from dir against the store as it stands.
func (fx *privateFixture) runKeepingStore(t *testing.T, dir string, args ...string) privateRun {
	t.Helper()
	for _, p := range []string{fx.gitLog, fx.goLog} {
		if err := os.RemoveAll(p); err != nil {
			t.Fatal(err)
		}
	}
	fx.mu.Lock()
	fx.paths = nil
	fx.mu.Unlock()
	t.Chdir(dir)
	dials := refuseEveryDial(t, fx.proxyAddr)
	var stdout, stderr bytes.Buffer
	err := Run(append([]string{"--store-root", fx.store}, args...), &stdout, &stderr)
	if err != nil {
		stderr.WriteString("error: " + err.Error() + "\n")
	}
	fx.mu.Lock()
	defer fx.mu.Unlock()
	return privateRun{stdout: stdout.String(), stderr: stderr.String(), exit: ExitCodeForError(err),
		paths: append([]string(nil), fx.paths...), dials: dials.addrs(), git: readAirGapLog(t, fx.gitLog),
		goArgs: readAirGapLog(t, fx.goLog)}
}

func namingCorp(lines []string) []string {
	var out []string
	for _, l := range lines {
		if strings.Contains(l, "corp.example.com") {
			out = append(out, l)
		}
	}
	return out
}

// corpRecord reads the stored fetch record of the private module, if any.
func (fx *privateFixture) corpRecord(t *testing.T) (status, vcs, mode, detail string, ok bool) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(fx.store, "mirror.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	err = db.QueryRow(`SELECT verification_status, vcs_check, acquisition_mode, verification_detail FROM fetch_records
		WHERE module_path = 'corp.example.com/a'`).Scan(&status, &vcs, &mode, &detail)
	return status, vcs, mode, detail, err == nil
}

func (fx *privateFixture) corpStalenessRows(t *testing.T) int {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(fx.store, "mirror.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM staleness_records WHERE module_path LIKE 'corp.example.com%'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestPrivateModules_NoCommandNamesAPrivatePathToAProxy: under GOPRIVATE no
// command sends the private path to the proxy or to git; the module is read
// from the module cache, recorded VerifiedByGoSum, and its staleness is
// unmeasured with no ledger row.
func TestPrivateModules_NoCommandNamesAPrivatePathToAProxy(t *testing.T) {
	fx := buildPrivateFixture(t)
	t.Setenv("GOPRIVATE", "corp.example.com")
	cases := []struct {
		name      string
		args      []string
		record    bool
		staleness bool
	}{
		{"walk --gomod", []string{"walk", "--gomod", "./go.mod", "--no-progress"}, true, false},
		{"audit", []string{"audit", "--gomod", "./go.mod", "--no-progress"}, true, true},
		{"sbom --package", []string{"sbom", "--package", ".", "--no-progress"}, true, false},
		{"latest --gomod", []string{"latest", "--gomod", "./go.mod", "--no-progress"}, false, true},
		{"latest positional", []string{"latest", "corp.example.com/a", "--no-progress"}, false, true},
		{"fetch --gomod", []string{"fetch", "--gomod", "./go.mod", "--no-progress"}, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := fx.run(t, fx.project, tc.args...)
			if got := namingCorp(r.paths); len(got) != 0 {
				t.Errorf("the proxy was asked about the private module: %v", got)
			}
			if got := namingCorp(r.git); len(got) != 0 {
				t.Errorf("git was started for the private module: %v", got)
			}
			if got := namingCorp(r.dials); len(got) != 0 {
				t.Errorf("dialled the private module's host: %v", got)
			}
			if tc.record {
				status, vcs, mode, detail, ok := fx.corpRecord(t)
				if !ok || status != "VerifiedByGoSum" || vcs != "private_module" || mode != "modcache" ||
					!strings.Contains(detail, "private module (GOPRIVATE)") {
					t.Errorf("record = %v %q %q %q %q; want VerifiedByGoSum, private_module, modcache, GOPRIVATE named\nstderr:\n%s",
						ok, status, vcs, mode, detail, r.stderr)
				}
			}
			if tc.staleness && !strings.Contains(r.stdout, "unmeasured (private module)") {
				t.Errorf("staleness of the private module is not unmeasured (private module):\n%s\nstderr:\n%s", r.stdout, r.stderr)
			}
			if n := fx.corpStalenessRows(t); n != 0 {
				t.Errorf("%d staleness ledger rows written for the private module", n)
			}
		})
	}
}

// TestPrivateModules_LatestJSONStatesTheReason.
func TestPrivateModules_LatestJSONStatesTheReason(t *testing.T) {
	fx := buildPrivateFixture(t)
	t.Setenv("GOPRIVATE", "corp.example.com")
	r := fx.run(t, fx.project, "latest", "--gomod", "./go.mod", "--json", "--no-progress")
	var doc struct {
		Modules []struct {
			Module              string `json:"module"`
			IsLatest            *bool  `json:"is_latest"`
			StalenessUnmeasured string `json:"staleness_unmeasured"`
		} `json:"modules"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &doc); err != nil {
		t.Fatalf("decoding %q: %v", r.stdout, err)
	}
	found := false
	for _, m := range doc.Modules {
		if m.Module == "corp.example.com/a" {
			found = true
			if m.IsLatest != nil || m.StalenessUnmeasured != "private_module" {
				t.Errorf("row = %+v, want is_latest null and staleness_unmeasured private_module", m)
			}
		}
	}
	if !found {
		t.Errorf("no row for the private module:\n%s", r.stdout)
	}
	if len(namingCorp(r.paths)) != 0 {
		t.Errorf("the proxy was asked about the private module: %v", r.paths)
	}
}

// TestPrivateModules_GONOPROXYNoneRoutesThroughTheProxy: Go's precedence. The
// proxy leg is GONOPROXY's, so the module is fetched through the proxy, while
// GOPRIVATE still withholds the checksum leg and the record names it.
func TestPrivateModules_GONOPROXYNoneRoutesThroughTheProxy(t *testing.T) {
	fx := buildPrivateFixture(t)
	t.Setenv("GOPRIVATE", "corp.example.com")
	t.Setenv("GONOPROXY", "none")
	r := fx.run(t, fx.project, "walk", "--gomod", "./go.mod", "--no-progress")
	if len(namingCorp(r.paths)) == 0 {
		t.Errorf("the module was not fetched through the proxy under GONOPROXY=none: %v", r.paths)
	}
	_, _, mode, detail, ok := fx.corpRecord(t)
	if !ok || mode != "proxy" || !strings.Contains(detail, "the setting in force is GOPRIVATE") {
		t.Errorf("record = %v %q %q; want a proxy record naming GOPRIVATE on the checksum leg", ok, mode, detail)
	}
}

// TestPrivateModules_ControlWithNoPatternAsksTheProxy: with no private
// variable the recorder sees the path, so the zeros above are not a blind
// instrument.
func TestPrivateModules_ControlWithNoPatternAsksTheProxy(t *testing.T) {
	fx := buildPrivateFixture(t)
	r := fx.run(t, fx.project, "walk", "--gomod", "./go.mod", "--no-progress")
	if len(namingCorp(r.paths)) == 0 {
		t.Errorf("control: the proxy was never asked about corp.example.com/a: %v", r.paths)
	}
	if _, vcs, mode, _, ok := fx.corpRecord(t); !ok || mode != "proxy" || vcs == "private_module" {
		t.Errorf("control record = %v %q %q, want the proxy route", ok, mode, vcs)
	}
}

// TestPrivateModules_MissingFromGoSumIsRefusedAsUnderModcache: a private
// module absent from go.sum is refused exactly as --from-modcache refuses it,
// and nothing is asked of the proxy.
func TestPrivateModules_MissingFromGoSumIsRefusedAsUnderModcache(t *testing.T) {
	fx := buildPrivateFixture(t)
	t.Setenv("GOPRIVATE", "corp.example.com")
	sum, err := os.ReadFile(filepath.Join(fx.project, "go.sum")) // #nosec G304 -- this test's own file
	if err != nil {
		t.Fatal(err)
	}
	var kept []string
	for _, l := range strings.Split(string(sum), "\n") {
		if !strings.HasPrefix(l, "corp.example.com/") {
			kept = append(kept, l)
		}
	}
	writePrivateFixtureFile(t, filepath.Join(fx.project, "go.sum"), strings.Join(kept, "\n"))
	private := fx.run(t, fx.project, "walk", "--gomod", "./go.mod", "--no-progress")
	modcache := fx.run(t, fx.project, "walk", "--gomod", "./go.mod", "--from-modcache="+fx.modcache, "--no-progress")
	if private.exit == 0 || private.exit != modcache.exit {
		t.Errorf("exit %d, --from-modcache exit %d; want the same refusal", private.exit, modcache.exit)
	}
	if len(namingCorp(private.paths)) != 0 {
		t.Errorf("the proxy was asked about the private module: %v", private.paths)
	}
}

// TestPrivateModules_PositionalFetchIsRefused: with no project go.sum the
// module-cache route has no anchor, so fetch, walk and inspect refuse at exit
// 20 before any request.
func TestPrivateModules_PositionalFetchIsRefused(t *testing.T) {
	fx := buildPrivateFixture(t)
	t.Setenv("GOPRIVATE", "corp.example.com")
	empty := t.TempDir()
	for _, args := range [][]string{
		{"fetch", "corp.example.com/a@v1.0.0"},
		{"fetch", "corp.example.com/a@latest"},
		{"fetch", "corp.example.com/a", "--list-versions"},
		{"walk", "corp.example.com/a@v1.0.0", "--no-progress"},
		{"inspect", "corp.example.com/a@latest", "--no-progress"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			r := fx.run(t, empty, args...)
			if r.exit != ExitConfig || !strings.Contains(r.stderr,
				"corp.example.com/a matches GOPRIVATE/GONOPROXY: kanonarion reads a private module only from the module cache "+
					"against a project go.sum; run from the project with --gomod") {
				t.Errorf("exit %d, stderr %q; want the exit-20 refusal", r.exit, r.stderr)
			}
			if len(r.paths) != 0 || len(r.git) != 0 {
				t.Errorf("requests %v, git %v; want none", r.paths, r.git)
			}
		})
	}
}

// TestPrivateModules_HostGlobIsGoRule: GOPRIVATE=*.example.com, the form the
// Go documentation gives, makes corp.example.com/a private here too.
func TestPrivateModules_HostGlobIsGoRule(t *testing.T) {
	fx := buildPrivateFixture(t)
	t.Setenv("GOPRIVATE", "*.example.com")
	r := fx.run(t, fx.project, "walk", "--gomod", "./go.mod", "--no-progress")
	if got := namingCorp(r.paths); len(got) != 0 {
		t.Errorf("the proxy was asked about the private module: %v", got)
	}
	if _, vcs, mode, _, ok := fx.corpRecord(t); !ok || mode != "modcache" || vcs != "private_module" {
		t.Errorf("record = %v %q %q, want the module-cache route", ok, mode, vcs)
	}
}

// TestPrivateModules_NotFetchedRemedyNamesTheRouteThatWorks: a read with no
// record for a private module names fetch against the project's go.mod, and
// running that remedy produces the record the read needs.
func TestPrivateModules_NotFetchedRemedyNamesTheRouteThatWorks(t *testing.T) {
	fx := buildPrivateFixture(t)
	t.Setenv("GOPRIVATE", "corp.example.com")
	const remedy = "run 'kanonarion fetch corp.example.com/a@v1.0.0 --gomod <path to the project's go.mod>' " +
		"from the project that requires it (a private module is verified against its go.sum)"
	empty := t.TempDir()
	miss := fx.run(t, empty, "license", "corp.example.com/a@v1.0.0")
	if miss.exit != ExitNotFound || !strings.Contains(miss.stderr, remedy) {
		t.Fatalf("license: exit %d, stderr %q; want exit 4 naming the private route", miss.exit, miss.stderr)
	}
	gomod := filepath.Join(fx.project, "go.mod")
	fetch := fx.runKeepingStore(t, fx.project, "fetch", "corp.example.com/a@v1.0.0", "--gomod", gomod, "--no-progress")
	if fetch.exit != 0 || len(namingCorp(fetch.paths)) != 0 {
		t.Fatalf("the remedy: exit %d, proxy paths %v, stderr %q", fetch.exit, fetch.paths, fetch.stderr)
	}
	if status, vcs, _, _, ok := fx.corpRecord(t); !ok || status != "VerifiedByGoSum" || vcs != "private_module" {
		t.Errorf("record after the remedy = %v %q %q", ok, status, vcs)
	}
	again := fx.runKeepingStore(t, empty, "license", "corp.example.com/a@v1.0.0")
	if again.exit == ExitNotFound {
		t.Errorf("license still finds no record after the remedy: %q", again.stderr)
	}
	latest := fx.run(t, fx.project, "fetch", "corp.example.com/a@latest", "--gomod", gomod)
	if latest.exit != ExitConfig || len(latest.paths) != 0 {
		t.Errorf("fetch @latest --gomod: exit %d, paths %v; want exit 20 and no request", latest.exit, latest.paths)
	}
}
