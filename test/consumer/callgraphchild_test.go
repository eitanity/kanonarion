package consumer_test

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"code.eitanity.com/kanonarion/pkg/kanonarion"
)

// probeBackend records that it was opened, in the file its config.yaml
// section names, and refuses to open: it shows which process's registrations a
// call-graph child selected its backend from.
func probeBackend() kanonarion.Backend {
	type settings struct {
		Marker string `yaml:"marker"`
	}
	return kanonarion.Backend{
		Name:     "probe",
		Section:  "probe",
		Defaults: settings{},
		Open: func(_ context.Context, req kanonarion.StorageRequest) (*kanonarion.Storage, error) {
			marker := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(req.Section)), "marker:"))
			if err := os.WriteFile(marker, []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
				return nil, err //nolint:wrapcheck // test backend
			}
			return nil, errors.New("the probe backend was opened")
		},
	}
}

const (
	// childModule is published at two versions below the fixed one, so each
	// entry can analyse a version the other has not.
	childModule      = "example.com/mod"
	childAdvisory    = "GO-2026-0001"
	childDBGenerated = "2026-02-14T00:00:00Z"
	// childApp requires childModule@v1.1.0 and does not compile, so its scan
	// cannot root at it and scans each module on its own: the path on which the
	// scan starts its own call-graph child.
	childApp = "example.com/app"
)

// graphModule is a call chain Thrice -> Twice -> Up and an interface with one
// implementer, for the call-graph queries.
const (
	graphModule  = "example.com/graph"
	graphVersion = "v1.0.0"
	graphSource  = "// Package graph is a fixture module.\npackage graph\n\n" +
		"// Greeter is satisfied by english.\ntype Greeter interface{ Greet() string }\n\n" +
		"type english struct{}\n\n// Greet says hello.\nfunc (english) Greet() string { return \"hello\" }\n\n" +
		"// New returns a Greeter.\nfunc New() Greeter { return english{} }\n\n" +
		"// Up ends the chain.\nfunc Up() {}\n\n// Twice calls Up.\nfunc Twice() { Up() }\n\n// Thrice calls Twice.\nfunc Thrice() { Twice() }\n"
)

// childFixture serves childModule, childApp, graphModule and an advisory database naming
// childModule's Handle over TLS, the one host this test reaches.
type childFixture struct {
	srv      *httptest.Server
	certFile string
}

func newChildFixture(t *testing.T) *childFixture {
	t.Helper()
	files := map[string][]byte{}
	publish := func(path, version, gomod string, sources [][2]string) {
		at := "/" + path + "/@v/" + version
		files[at+".mod"] = []byte(gomod)
		files[at+".info"] = []byte(`{"Version":"` + version + `","Time":"2025-06-01T00:00:00Z"}`)
		files[at+".zip"] = moduleZip(t, path+"@"+version+"/", append([][2]string{{"go.mod", gomod}}, sources...))
		files["/"+path+"/@v/list"] = append(files["/"+path+"/@v/list"], version+"\n"...)
	}
	for _, v := range []string{"v1.1.0", "v1.2.0"} {
		publish(childModule, v, "module "+childModule+"\n\ngo 1.24\n", [][2]string{{"mod.go",
			"// Package mod is a fixture module.\npackage mod\n\n// Handle is the symbol the fixture advisory names.\nfunc Handle() {}\n\n// Serve reaches Handle.\nfunc Serve() { Handle() }\n"}})
	}
	publish(childApp, "v1.0.0", "module "+childApp+"\n\ngo 1.24\n\nrequire "+childModule+" v1.1.0\n", [][2]string{{"app.go",
		"// Package app is a fixture module that does not compile.\npackage app\n\nimport \"" + childModule + "\"\n\n// Run reaches Handle.\nfunc Run() { mod.Serve(); undefined() }\n"}})
	publish(graphModule, graphVersion, "module "+graphModule+"\n\ngo 1.24\n", [][2]string{{"graph.go", graphSource}})
	files["/vulndb/vulndb.zip"] = advisoryDB(t)
	files["/vulndb/index/db.json"] = []byte(`{"modified":"` + childDBGenerated + `"}`)
	files["/vulndb/index/modules.json.gz"] = gzipped(t, modulesIndex())

	f := &childFixture{}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body) //nolint:errcheck // a failed write is seen by the client under test
	}))
	t.Cleanup(f.srv.Close)
	f.certFile = filepath.Join(t.TempDir(), "fixture.pem")
	if err := os.WriteFile(f.certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

// moduleZip is a module zip of entries, name then content, in order.
func moduleZip(t *testing.T, prefix string, entries [][2]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: prefix + e[0], Method: zip.Deflate, Modified: time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(e[1])); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func modulesIndex() string {
	return `[{"path":"` + childModule + `","vulns":[{"id":"` + childAdvisory + `","modified":"` + childDBGenerated + `","fixed":"1.3.0"}]}]`
}

func advisoryDB(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range []struct{ name, body string }{
		{"index/db.json", `{"modified":"` + childDBGenerated + `"}`},
		{"index/modules.json", modulesIndex()},
		{"ID/" + childAdvisory + ".json", `{"schema_version":"1.3.1","id":"` + childAdvisory + `","modified":"` + childDBGenerated +
			`","published":"2026-01-05T00:00:00Z","summary":"fixture vulnerability in ` + childModule + `",` +
			`"affected":[{"package":{"name":"` + childModule + `","ecosystem":"Go"},` +
			`"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.3.0"}]}],` +
			`"ecosystem_specific":{"imports":[{"path":"` + childModule + `","symbols":["Handle"]}]}}]}`},
	} {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: e.name, Method: zip.Deflate, Modified: time.Date(2026, 2, 14, 0, 0, 0, 0, time.UTC)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(e.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func gzipped(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

var (
	govulncheckOnce sync.Once
	govulncheckDir  string
	govulncheckErr  error
)

// govulncheckBin builds the scanner this module pins, so the scan does not
// depend on whether the machine has one on PATH.
func govulncheckBin(t *testing.T) string {
	t.Helper()
	govulncheckOnce.Do(func() {
		if govulncheckDir, govulncheckErr = os.MkdirTemp("", "kanonarion-consumer-govulncheck-*"); govulncheckErr != nil {
			return
		}
		cmd := exec.Command("go", "build", "-o", filepath.Join(govulncheckDir, "govulncheck"), "golang.org/x/vuln/cmd/govulncheck") // #nosec G204 -- this test's own temp dir
		cmd.Dir = filepath.Join("..", "..")
		if out, err := cmd.CombinedOutput(); err != nil {
			govulncheckErr = errors.Join(err, errors.New(string(out)))
		}
	})
	if govulncheckErr != nil {
		t.Fatalf("building govulncheck: %v", govulncheckErr)
	}
	return govulncheckDir
}

// offline points this process and its children at the fixture alone: module
// downloads and the advisory database come from it, and any other host this
// process asks for is refused before a socket opens and reported.
func (f *childFixture) offline(t *testing.T) {
	t.Helper()
	bin := govulncheckBin(t)
	modcache := t.TempDir()
	t.Cleanup(func() { makeWritable(modcache) })
	for k, v := range map[string]string{
		"GOPROXY": f.srv.URL, "SSL_CERT_FILE": f.certFile, "GOSUMDB": "off", "GONOPROXY": "", "GONOSUMDB": "",
		"GOPRIVATE": "", "GOFLAGS": "-mod=mod", "GOMODCACHE": modcache, "GOTOOLCHAIN": "local",
		"PATH": bin + string(os.PathListSeparator) + os.Getenv("PATH"),
	} {
		t.Setenv(k, v)
	}
	tr, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Fatal("http.DefaultTransport is not an *http.Transport")
	}
	pool := x509.NewCertPool()
	pool.AddCert(f.srv.Certificate())
	host := f.srv.Listener.Addr().String()
	var mu sync.Mutex
	var refused []string
	oldTLS, oldProxy := tr.TLSClientConfig, tr.Proxy
	tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	tr.Proxy = func(r *http.Request) (*url.URL, error) {
		if r.URL.Host == host {
			return nil, nil
		}
		mu.Lock()
		refused = append(refused, r.URL.Host)
		mu.Unlock()
		return nil, errors.New("unreachable in this test: only the fixture is")
	}
	t.Cleanup(func() {
		tr.TLSClientConfig, tr.Proxy = oldTLS, oldProxy
		tr.CloseIdleConnections()
		mu.Lock()
		defer mu.Unlock()
		for _, h := range refused {
			t.Errorf("a request for %s was made", h)
		}
	})
}

// makeWritable restores write permission under a Go module cache, which the
// toolchain writes read-only, so its temp directory can be removed.
func makeWritable(root string) {
	_ = filepath.WalkDir(root, func(path string, _ fs.DirEntry, err error) error { //nolint:errcheck // the callback returns only nil
		if err == nil {
			_ = os.Chmod(path, 0o700) /* #nosec G302 G122 -- a module cache this test created in its own temp dir */ //nolint:errcheck // a path that cannot be repaired is left to the temp cleanup
		}
		return nil
	})
}

// store is a store root whose config.yaml names the fixture's advisory
// database; records go to the default SQLite backend under it.
func (f *childFixture) store(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeConfig(t, root, "version: \"3\"\nvulndb:\n  url: "+f.srv.URL+"/vulndb\n")
	return root
}

// analyse runs CoordinateAnalysis with reachability on a driver over root.
func analyse(t *testing.T, root, path, version string, stages []string) kanonarion.CoordinateAnalysisResult {
	t.Helper()
	coord := mustCoord(t, path, version)
	drv, cleanup, err := kanonarion.OpenDriver(root)
	if err != nil {
		t.Fatalf("OpenDriver: %v", err)
	}
	defer closeStore(t, cleanup)
	res, err := drv.CoordinateAnalysis.Run(t.Context(), kanonarion.CoordinateAnalysisRequest{
		Coordinate: coord, Stages: stages, Reachability: true, Operator: "test",
	})
	if err != nil {
		t.Fatalf("CoordinateAnalysis.Run %s: %v", coord, err)
	}
	return res
}

// callGraphStage is the call-graph stage of coordinate childModule@version.
func callGraphStage(t *testing.T, res kanonarion.CoordinateAnalysisResult, version string) kanonarion.StageResult {
	t.Helper()
	for coord, mod := range res.Extraction.PerModuleResults {
		if coord.String() == childModule+"@"+version {
			if st, ok := mod.Stages["callgraph"]; ok {
				return st
			}
		}
	}
	t.Fatalf("the extraction run holds no callgraph stage for %s@%s: %+v", childModule, version, res.Extraction.PerModuleResults)
	return kanonarion.StageResult{}
}

// advisoryFinding is the fixture advisory's finding on childModule@version in
// the scan res recorded, read back from the store at root.
func advisoryFinding(t *testing.T, root string, res kanonarion.CoordinateAnalysisResult, version string) kanonarion.VulnerabilityFinding {
	t.Helper()
	q, cleanup, err := kanonarion.Open(root)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer closeStore(t, cleanup)
	recs, err := q.Vuln.ListRecordsForRun(t.Context(), res.Scan.ID)
	if err != nil {
		t.Fatalf("ListRecordsForRun: %v", err)
	}
	for _, rec := range recs {
		if rec.Coordinate.String() != childModule+"@"+version {
			continue
		}
		for _, f := range rec.Findings {
			if f.ID == childAdvisory {
				return f
			}
		}
	}
	t.Fatalf("scan run %s recorded no %s finding on %s@%s: %+v", res.Scan.ID, childAdvisory, childModule, version, recs)
	return kanonarion.VulnerabilityFinding{}
}

// An application that serves the call-graph child with ServeCallGraphChild
// gets call graphs from both spawners: the extraction stage, and a scan that
// analyses a module the extraction did not graph.
func TestConsumer_TheCallGraphChildServedByTheApplicationAnswers(t *testing.T) {
	f := newChildFixture(t)
	f.offline(t)
	root := f.store(t)

	full := analyse(t, root, childModule, "v1.2.0", nil)
	if st := callGraphStage(t, full, "v1.2.0"); st.Status != kanonarion.StageSucceeded {
		t.Errorf("callgraph stage = %+v, want succeeded", st)
	}
	if full.Extraction.OverallStatus == kanonarion.ExtractionRunPartial {
		t.Errorf("extraction run is partial: %+v", full.Extraction.PerModuleResults)
	}

	// No callgraph stage, so the scan's own child is what graphs v1.1.0.
	scanned := analyse(t, root, childApp, "v1.0.0", []string{"license", "interface", "example"})
	if fd := advisoryFinding(t, root, scanned, "v1.1.0"); fd.Reachable == nil || fd.ReachabilityNote != "" {
		t.Errorf("v1.1.0 finding: reachable %+v, note %q; want an answer from the scan's child", fd.Reachable, fd.ReachabilityNote)
	}
}

// The child opens the backend the store root's config.yaml selects among the
// registrations of the application serving it: the probe backend this binary
// registers in TestMain is opened in the child process, not in this one.
func TestConsumer_TheCallGraphChildOpensTheApplicationsBackend(t *testing.T) {
	root, marker := t.TempDir(), filepath.Join(t.TempDir(), "opened")
	writeConfig(t, root, "version: \"3\"\nstorage:\n  backend: probe\nprobe:\n  marker: "+marker+"\n")
	cmd := exec.Command(os.Args[0], "callgraph", childModule+"@v1.2.0", "--narrate-progress", "--store-root="+root) // #nosec G204 G702 -- this test binary
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() == 0 {
		t.Fatalf("child exited %v; want the probe backend's refusal\n%s", err, stderr.String())
	}
	if !strings.Contains(stderr.String(), "the probe backend was opened") {
		t.Errorf("child stderr does not carry the probe backend's refusal:\n%s", stderr.String())
	}
	pid, rerr := os.ReadFile(filepath.Clean(marker))
	if rerr != nil {
		t.Fatalf("the probe backend was not opened: %v\n%s", rerr, stderr.String())
	}
	if string(pid) == strconv.Itoa(os.Getpid()) {
		t.Error("the probe backend was opened in the test process, not the child")
	}
}

// An application that does not serve the call-graph child still gets an
// answer: Run returns no error, the extraction run reads partial with the
// child's failure on the stage, and the scan's finding says why reachability
// has no answer.
func TestConsumer_AnUnservedCallGraphChildLeavesTheRunPartial(t *testing.T) {
	f := newChildFixture(t)
	f.offline(t)
	t.Setenv(noCallGraphEnv, "1")
	root := f.store(t)

	res := analyse(t, root, childModule, "v1.2.0", nil)
	if res.Extraction.OverallStatus != kanonarion.ExtractionRunPartial {
		t.Errorf("extraction run status = %s, want partial", res.Extraction.OverallStatus)
	}
	st := callGraphStage(t, res, "v1.2.0")
	if st.Status != kanonarion.StageFailed || !strings.Contains(st.Error, "callgraph stage") ||
		!strings.Contains(st.Error, "subprocess failed") || !strings.Contains(st.Error, noCallGraphMessage) {
		t.Errorf("callgraph stage = %+v, want the child's failure", st)
	}

	scanned := analyse(t, root, childApp, "v1.0.0", []string{"license", "interface", "example"})
	if fd := advisoryFinding(t, root, scanned, "v1.1.0"); !strings.Contains(fd.ReachabilityNote, "callgraph subprocess failed") ||
		!strings.Contains(fd.ReachabilityNote, noCallGraphMessage) {
		t.Errorf("v1.1.0 finding note = %q, want the child's failure", fd.ReachabilityNote)
	}
}

// ServeCallGraphChild serves the one command a parent starts it with and
// refuses any other before anything runs.
func TestConsumer_ServeCallGraphChildRefusesAnyOtherCommand(t *testing.T) {
	for _, args := range [][]string{nil, {"walk-list"}, {"--store-root", t.TempDir(), "callgraph"}} {
		var stdout, stderr bytes.Buffer
		code := kanonarion.ServeCallGraphChild(args, &stdout, &stderr)
		if code == 0 || stdout.Len() != 0 || !strings.Contains(stderr.String(), `the call-graph child serves only "callgraph"`) {
			t.Errorf("ServeCallGraphChild(%q) = %d, stdout %q, stderr %q; want a refusal", args, code, stdout.String(), stderr.String())
		}
	}
}
