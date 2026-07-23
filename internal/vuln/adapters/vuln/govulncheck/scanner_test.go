package govulncheck

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

func TestPreflight_AbsentReturnsActionableError(t *testing.T) {
	// PATH points at an empty dir so govulncheck cannot be resolved.
	t.Setenv("PATH", t.TempDir())

	err := New("v1", nil).Preflight(t.Context())
	if err == nil {
		t.Fatal("Preflight: expected error when govulncheck is absent, got nil")
	}
	if !errors.Is(err, ErrGovulncheckNotFound) {
		t.Errorf("Preflight error = %v, want it to wrap ErrGovulncheckNotFound", err)
	}
	if !strings.Contains(err.Error(), "go install golang.org/x/vuln/cmd/govulncheck@latest") {
		t.Errorf("Preflight error %q is missing the install command", err)
	}
}

func TestPreflight_PresentReturnsNil(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "govulncheck")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil { //nolint:gosec // test stub must be executable
		t.Fatalf("writing fake govulncheck: %v", err)
	}
	t.Setenv("PATH", dir)

	if err := New("v1", nil).Preflight(t.Context()); err != nil {
		t.Errorf("Preflight: expected nil when govulncheck is on PATH, got %v", err)
	}
}

func TestScanner_ParseResults_OrderIssue(t *testing.T) {
	s := New("v1", nil)

	// JSON stream where Finding comes BEFORE OSV
	jsonStream := `
{"finding": {"osv": "GO-2021-0001", "fixed_version": "v1.2.3", "trace": [{"symbol": "Foo"}]}}
{"osv": {"id": "GO-2021-0001", "summary": "Vulnerability summary"}}
`
	findings, err := s.parseResults(t.Context(), strings.NewReader(jsonStream), "example.com/mod")
	if err != nil {
		t.Fatalf("parseResults failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("expected findings to be non-empty when OSV info is present later in the stream")
	}
}

func TestScanner_ParseResults_MockGin(t *testing.T) {
	s := New("v1", nil)

	// Simulating some findings for Gin v1.6.2
	// Based on govulncheck JSON output format
	jsonStream := `
{"osv": {"id": "GO-2020-0015", "summary": "Infinite loop in Gin", "aliases": ["CVE-2020-28483"]}}
{"finding": {"osv": "GO-2020-0015", "fixed_version": "v1.6.3", "trace": [{"symbol": "Context.Bind"}]}}
`
	findings, err := s.parseResults(t.Context(), strings.NewReader(jsonStream), "github.com/gin-gonic/gin")
	if err != nil {
		t.Fatalf("parseResults failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected findings for mock gin")
	}

	if findings[0].ID != "GO-2020-0015" {
		t.Errorf("expected GO-2020-0015, got %s", findings[0].ID)
	}
}

func TestScanner_ClassifyScanFailure(t *testing.T) {
	// A non-OOM govulncheck failure must land its reason in ErrorDetail (the
	// field vuln-show and audit read for ScanFailed), not UnscannableReason —
	// otherwise the reason is dropped and the user sees "unknown reason".
	t.Run("scan failure puts reason in ErrorDetail with stderr", func(t *testing.T) {
		status, errorDetail, unscannableReason, unscanReason := classifyScanFailure(
			errors.New("exit status 1"),
			"govulncheck: loading packages: invalid array length",
		)
		if status != domain.StatusScanFailed {
			t.Fatalf("status = %s, want %s", status, domain.StatusScanFailed)
		}
		if errorDetail == "" {
			t.Error("ErrorDetail must carry the failure reason for ScanFailed")
		}
		if !strings.Contains(errorDetail, "invalid array length") {
			t.Errorf("ErrorDetail %q must include the govulncheck stderr", errorDetail)
		}
		if unscannableReason != "" {
			t.Errorf("UnscannableReason must be empty for ScanFailed, got %q", unscannableReason)
		}
		if unscanReason != "" {
			t.Errorf("UnscanReason must be empty for ScanFailed, got %q", unscanReason)
		}
	})

	// OOM-style kills are Unscannable; their reason belongs in UnscannableReason.
	oomCases := []string{"signal: killed", "killed", "Killed", "exit status 137"}
	for _, errStr := range oomCases {
		t.Run("OOM: "+errStr, func(t *testing.T) {
			status, errorDetail, unscannableReason, unscanReason := classifyScanFailure(errors.New(errStr), "")
			if status != domain.StatusUnscannable {
				t.Errorf("status = %s, want %s", status, domain.StatusUnscannable)
			}
			if unscannableReason == "" {
				t.Error("UnscannableReason must carry the reason for Unscannable")
			}
			if errorDetail != "" {
				t.Errorf("ErrorDetail must be empty for Unscannable, got %q", errorDetail)
			}
			if unscanReason != domain.UnscanReasonOOMKilled {
				t.Errorf("UnscanReason = %q, want %q", unscanReason, domain.UnscanReasonOOMKilled)
			}
		})
	}
}

// TestScanner_ParseResults_FiltersDependencyFindings is the regression guard
// for govulncheck reports vulnerable dependencies of the scanned
// module too; those must NOT be attributed to the scanned module's record.
func TestScanner_ParseResults_FiltersDependencyFindings(t *testing.T) {
	s := New("v1", nil)

	jsonStream := `
{"osv": {"id": "GO-SELF-0001", "summary": "Vuln in the scanned module"}}
{"finding": {"osv": "GO-SELF-0001", "fixed_version": "v0.25.0", "trace": [{"module": "golang.org/x/crypto", "package": "golang.org/x/crypto/ssh", "function": "Marshal"}]}}
{"osv": {"id": "GO-DEP-0002", "summary": "Vuln in a dependency (x/net)"}}
{"finding": {"osv": "GO-DEP-0002", "fixed_version": "v0.27.0", "trace": [{"module": "golang.org/x/net", "package": "golang.org/x/net/http2", "function": "ConfigureServer"}]}}
{"osv": {"id": "GO-STD-0003", "summary": "Stdlib vuln"}}
{"finding": {"osv": "GO-STD-0003", "fixed_version": "go1.22.0", "trace": [{"module": "stdlib", "package": "net/http", "function": "Serve"}]}}
`
	findings, err := s.parseResults(t.Context(), strings.NewReader(jsonStream), "golang.org/x/crypto")
	if err != nil {
		t.Fatalf("parseResults failed: %v", err)
	}

	got := map[string]bool{}
	for _, f := range findings {
		got[f.ID] = true
	}
	if !got["GO-SELF-0001"] {
		t.Error("expected the scanned module's own finding GO-SELF-0001 to be kept")
	}
	if got["GO-DEP-0002"] {
		t.Error("dependency advisory GO-DEP-0002 (golang.org/x/net) must not be attributed to golang.org/x/crypto")
	}
	if !got["GO-STD-0003"] {
		t.Error("stdlib advisory GO-STD-0003 should be kept (not a dependency-module advisory)")
	}
}

// TestScanner_ParseResults_VulnerableSymbolNotCallers is the regression guard
// for AffectedSymbols must be the vulnerable symbol (Trace[0]), not
// the caller frames that follow it up the call stack.
func TestScanner_ParseResults_VulnerableSymbolNotCallers(t *testing.T) {
	s := New("v1", nil)

	// Trace[0] is the vulnerable symbol; the rest are its callers.
	jsonStream := `
{"osv": {"id": "GO-2024-9999", "summary": "Vuln in x/text"}}
{"finding": {"osv": "GO-2024-9999", "fixed_version": "v0.36.0", "trace": [{"module": "golang.org/x/text", "package": "golang.org/x/text/language", "receiver": "*Parser", "function": "Parse"}, {"module": "golang.org/x/text", "package": "golang.org/x/text/language", "function": "MustParse"}, {"module": "example.com/app", "package": "example.com/app", "function": "main"}]}}
`
	findings, err := s.parseResults(t.Context(), strings.NewReader(jsonStream), "golang.org/x/text")
	if err != nil {
		t.Fatalf("parseResults failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	want := []string{"*Parser.Parse"}
	got := findings[0].AffectedSymbols
	if len(got) != len(want) || got[0] != want[0] {
		t.Errorf("AffectedSymbols = %v, want %v (vulnerable symbol only, no callers like MustParse/main)", got, want)
	}
}

// envMap collapses a "key=value" environment slice into a map, honouring the
// exec.Cmd rule that the last value for a duplicate key wins.
func envMap(env []string) map[string]string {
	m := make(map[string]string, len(env))
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok {
			m[k] = v
		}
	}
	return m
}

// TestScanEnv_PopulatedModcacheRunsHermetic guards that with a populated
// GOMODCACHE the toolchain runs offline and writable: -mod=mod so it computes
// the go.sum entries a multi-module member's published go.sum omits for a
// cache-resolved sibling, GOSUMDB=off to skip the offline-unreachable checksum
// DB, and GOPROXY=off to pin resolution to the cache with no network fallback.
// The cache now carries the superseded intermediate go.mod files a pre-pruning
// dependency needs, so GOPROXY=off can no longer fail on a missing go.mod.
func TestScanEnv_PopulatedModcacheRunsHermetic(t *testing.T) {
	got := envMap(scanEnv([]string{"PATH=/usr/bin"}, "/tmp/kanonarion-modcache"))

	want := map[string]string{
		"GOMODCACHE": "/tmp/kanonarion-modcache",
		"GOFLAGS":    "-mod=mod", // allow the toolchain to compute & write missing go.sum entries
		"GOSUMDB":    "off",      // skip the checksum DB (unreachable offline, redundant once cached)
		"GOPROXY":    "off",      // hermetic: resolve only from the pre-populated cache
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("scanEnv[%s] = %q, want %q", k, got[k], v)
		}
	}
}

// TestScanEnv_DisablesWorkspaceMode guards that GOWORK=off is set on every scan,
// with or without a populated cache. A module may ship a go.work in its
// published zip (github.com/bytedance/sonic@v1.11.6 does); left on, the
// toolchain discovers it in the extract dir and enters workspace mode, which
// rejects -mod=mod and gets misreported as a module that does not build.
func TestScanEnv_DisablesWorkspaceMode(t *testing.T) {
	for _, modcache := range []string{"/tmp/kanonarion-modcache", ""} {
		got := envMap(scanEnv([]string{"PATH=/usr/bin"}, modcache))
		if got["GOWORK"] != "off" {
			t.Errorf("scanEnv(modcache=%q) GOWORK = %q, want off", modcache, got["GOWORK"])
		}
	}
}

// TestScanEnv_LastValueWinsOverInheritedWorkspace guards that an ambient GOWORK
// pointing at a workspace file cannot leak into an isolated single-module scan.
func TestScanEnv_LastValueWinsOverInheritedWorkspace(t *testing.T) {
	got := envMap(scanEnv([]string{"GOWORK=/home/dev/go.work"}, "/tmp/kanonarion-modcache"))

	if got["GOWORK"] != "off" {
		t.Errorf("GOWORK = %q, want off to override the inherited workspace file", got["GOWORK"])
	}
}

// TestScanEnv_LastValueWinsOverInheritedFlags guards that the offline overrides
// take effect even when the ambient environment already pins conflicting
// values — exec.Cmd honours the last value for a duplicate key.
func TestScanEnv_LastValueWinsOverInheritedFlags(t *testing.T) {
	base := []string{"GOFLAGS=-mod=readonly", "GOSUMDB=sum.golang.org"}
	got := envMap(scanEnv(base, "/tmp/kanonarion-modcache"))

	if got["GOFLAGS"] != "-mod=mod" {
		t.Errorf("GOFLAGS = %q, want -mod=mod to override the inherited -mod=readonly", got["GOFLAGS"])
	}
	if got["GOSUMDB"] != "off" {
		t.Errorf("GOSUMDB = %q, want off to override the inherited checksum DB", got["GOSUMDB"])
	}
}

// TestScanEnv_LastValueWinsOverInheritedProxy guards that GOPROXY=off overrides
// an ambient GOPROXY pointing at a network proxy, so a populated-cache scan is
// hermetic regardless of the inherited environment.
func TestScanEnv_LastValueWinsOverInheritedProxy(t *testing.T) {
	base := []string{"GOPROXY=https://proxy.golang.org"}
	got := envMap(scanEnv(base, "/tmp/kanonarion-modcache"))

	if got["GOPROXY"] != "off" {
		t.Errorf("GOPROXY = %q, want off to override the inherited network proxy", got["GOPROXY"])
	}
}

// TestScanEnv_NoModcacheLeavesResolutionDefault guards that scans without a
// populated cache keep the default network-backed resolution — the offline
// overrides must not leak into that path.
func TestScanEnv_NoModcacheLeavesResolutionDefault(t *testing.T) {
	got := envMap(scanEnv([]string{"PATH=/usr/bin"}, ""))

	for _, k := range []string{"GOMODCACHE", "GOPROXY", "GOSUMDB"} {
		if v, ok := got[k]; ok {
			t.Errorf("scanEnv without a modcache set %s=%q; default resolution must stay untouched", k, v)
		}
	}
	if got["GOFLAGS"] == "-mod=mod" {
		t.Error("scanEnv without a modcache must not force -mod=mod")
	}
}

func TestScanner_Scan_Integration_Like(t *testing.T) {
	// This might be hard to run without real environment, but we can try to see if it even starts.
	// Actually, Scan requires a zip file and runs external command.
	// Let's skip it if we can't easily provide a zip.
}

// makeModuleZip builds an in-memory module zip from a path->content map,
// mirroring the layout of a mirror-fetch module zip that Scan extracts.
func makeModuleZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create %q: %v", name, err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatalf("zip write %q: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

// fakeGovulncheckOnPath writes an executable shell stub named "govulncheck" that
// prints stderrOut to stderr and exits with exitCode, then prepends its dir to
// PATH so lookupGovulncheck resolves it while the real go toolchain stays
// reachable. Skips on non-POSIX shells.
func fakeGovulncheckOnPath(t *testing.T, exitCode int, stderrOut string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake govulncheck stub uses a POSIX shell script")
	}
	dir := t.TempDir()
	script := "#!/bin/sh\n"
	if stderrOut != "" {
		script += "echo " + shellQuote(stderrOut) + " 1>&2\n"
	}
	script += "exit " + strconv.Itoa(exitCode) + "\n"
	stub := filepath.Join(dir, "govulncheck")
	if err := os.WriteFile(stub, []byte(script), 0o755); err != nil { //nolint:gosec // test stub must be executable
		t.Fatalf("writing fake govulncheck: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// capturingScanner returns a Scanner whose logger writes records at or above
// level into buf, so a test can assert which error-path messages were emitted.
func capturingScanner(buf *bytes.Buffer, level slog.Level) *Scanner {
	handler := slog.NewTextHandler(buf, &slog.HandlerOptions{Level: level})
	return New("test", nil).WithLogger(slog.New(handler))
}

// TestScan_GovulncheckExitErrorLogsAtDebugNotWarn is the regression guard for
// the adapter demoting the error it hands back for classification from warn to
// debug: a govulncheck non-zero exit (the out-of-toolchain case dumps stderr
// here) must not surface as a WARN at the default level — severity is owned by
// the application that classifies the returned error — but must stay available
// at debug.
func TestScan_GovulncheckExitErrorLogsAtDebugNotWarn(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	const msg = "vuln-scan: govulncheck exited with error"
	zipBytes := makeModuleZip(t, map[string]string{
		"example.com/mod@v1.0.0/go.mod": "module example.com/mod\n\ngo 1.21\n",
		"example.com/mod@v1.0.0/mod.go": "package mod\n",
	})
	coord := coordinate.ModuleCoordinate{Path: "example.com/mod", Version: "v1.0.0"}

	// govulncheck exits non-zero with a scary stderr dump, as it does for an
	// out-of-toolchain module.
	fakeGovulncheckOnPath(t, 2, "govulncheck: loading packages: no required module provides package")

	t.Run("default warn level omits the error-path message", func(t *testing.T) {
		var buf bytes.Buffer
		s := capturingScanner(&buf, slog.LevelWarn)
		rec, err := s.Scan(t.Context(), ports.ScanRequest{Coordinate: coord, ModuleSource: bytes.NewReader(zipBytes), Snapshot: domain.DatabaseSnapshot{}, GoModCache: "", DBDir: "", ScanMode: ""})
		if err != nil {
			t.Fatalf("Scan returned a hard error: %v", err)
		}
		if rec.OverallStatus != domain.StatusScanFailed {
			t.Fatalf("OverallStatus = %s, want %s", rec.OverallStatus, domain.StatusScanFailed)
		}
		if strings.Contains(buf.String(), msg) {
			t.Errorf("error-path message %q must not appear at the default (warn) level; logs:\n%s", msg, buf.String())
		}
	})

	t.Run("debug level still carries the error-path message and stderr", func(t *testing.T) {
		var buf bytes.Buffer
		s := capturingScanner(&buf, slog.LevelDebug)
		if _, err := s.Scan(t.Context(), ports.ScanRequest{Coordinate: coord, ModuleSource: bytes.NewReader(zipBytes), Snapshot: domain.DatabaseSnapshot{}, GoModCache: "", DBDir: "", ScanMode: ""}); err != nil {
			t.Fatalf("Scan returned a hard error: %v", err)
		}
		if !strings.Contains(buf.String(), msg) {
			t.Errorf("error-path message %q must remain available at debug; logs:\n%s", msg, buf.String())
		}
		if !strings.Contains(buf.String(), "no required module provides package") {
			t.Errorf("govulncheck stderr must remain available at debug; logs:\n%s", buf.String())
		}
	})
}

// TestScan_GoModDownloadFailureLogsAtDebugNotWarn is the regression guard for
// the companion precursor: a failed `go mod download` (the source-mode path
// continues past it) is a debug precursor to the classified error, not a
// standalone warn. A require that cannot resolve under a hermetic empty cache
// (GOPROXY=off) forces the download failure without touching the network.
func TestScan_GoModDownloadFailureLogsAtDebugNotWarn(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	const msg = "vuln-scan: go mod download failed"
	zipBytes := makeModuleZip(t, map[string]string{
		"example.com/mod@v1.0.0/go.mod": "module example.com/mod\n\ngo 1.21\n\nrequire example.invalid/missing v1.0.0\n",
		"example.com/mod@v1.0.0/mod.go": "package mod\n",
	})
	coord := coordinate.ModuleCoordinate{Path: "example.com/mod", Version: "v1.0.0"}
	// Empty cache dir makes scanEnv pin GOPROXY=off, so the unresolvable require
	// fails `go mod download` offline. govulncheck itself exits 0 (clean) so this
	// message is the only error-path log under test.
	emptyCache := t.TempDir()
	fakeGovulncheckOnPath(t, 0, "")

	t.Run("default warn level omits the download-failure message", func(t *testing.T) {
		var buf bytes.Buffer
		s := capturingScanner(&buf, slog.LevelWarn)
		if _, err := s.Scan(t.Context(), ports.ScanRequest{Coordinate: coord, ModuleSource: bytes.NewReader(zipBytes), Snapshot: domain.DatabaseSnapshot{}, GoModCache: emptyCache, DBDir: "", ScanMode: ""}); err != nil {
			t.Fatalf("Scan returned a hard error: %v", err)
		}
		if strings.Contains(buf.String(), msg) {
			t.Errorf("download-failure message %q must not appear at the default (warn) level; logs:\n%s", msg, buf.String())
		}
	})

	t.Run("debug level still carries the download-failure message", func(t *testing.T) {
		var buf bytes.Buffer
		s := capturingScanner(&buf, slog.LevelDebug)
		if _, err := s.Scan(t.Context(), ports.ScanRequest{Coordinate: coord, ModuleSource: bytes.NewReader(zipBytes), Snapshot: domain.DatabaseSnapshot{}, GoModCache: emptyCache, DBDir: "", ScanMode: ""}); err != nil {
			t.Fatalf("Scan returned a hard error: %v", err)
		}
		if !strings.Contains(buf.String(), msg) {
			t.Errorf("download-failure message %q must remain available at debug; logs:\n%s", msg, buf.String())
		}
	})
}

// TestScanner_ParseResultsByModule_GroupsAllModules is the project-rooted
// counterpart to the single-module filter test: one scan over the project's
// import graph must KEEP every reachable finding and file it under the module
// that owns the vulnerable symbol, so a per-module verdict can be derived for
// the whole build. Stdlib advisories collapse onto the {stdlib, ""} key.
func TestScanner_ParseResultsByModule_GroupsAllModules(t *testing.T) {
	s := New("v1", nil)

	jsonStream := `
{"osv": {"id": "GO-SELF-0001", "summary": "Vuln in x/crypto"}}
{"finding": {"osv": "GO-SELF-0001", "fixed_version": "v0.25.0", "trace": [{"module": "golang.org/x/crypto", "version": "v0.24.0", "package": "golang.org/x/crypto/ssh", "function": "Marshal"}]}}
{"osv": {"id": "GO-DEP-0002", "summary": "Vuln in x/net"}}
{"finding": {"osv": "GO-DEP-0002", "fixed_version": "v0.27.0", "trace": [{"module": "golang.org/x/net", "version": "v0.26.0", "package": "golang.org/x/net/http2", "function": "ConfigureServer"}]}}
{"osv": {"id": "GO-STD-0003", "summary": "Stdlib vuln"}}
{"finding": {"osv": "GO-STD-0003", "fixed_version": "go1.22.0", "trace": [{"module": "stdlib", "version": "go1.21.0", "package": "net/http", "function": "Serve"}]}}
`
	byModule, err := s.parseResultsByModule(t.Context(), strings.NewReader(jsonStream))
	if err != nil {
		t.Fatalf("parseResultsByModule failed: %v", err)
	}

	crypto := coordinate.ModuleCoordinate{Path: "golang.org/x/crypto", Version: "v0.24.0"}
	net := coordinate.ModuleCoordinate{Path: "golang.org/x/net", Version: "v0.26.0"}
	stdlib := coordinate.ModuleCoordinate{Path: "stdlib"}

	if len(byModule[crypto]) != 1 || byModule[crypto][0].ID != "GO-SELF-0001" {
		t.Errorf("x/crypto findings = %+v, want GO-SELF-0001", byModule[crypto])
	}
	// Unlike the single-module parse, the dependency advisory is KEPT and
	// attributed to its own module — that is what lets the audit path read it.
	if len(byModule[net]) != 1 || byModule[net][0].ID != "GO-DEP-0002" {
		t.Errorf("x/net findings = %+v, want GO-DEP-0002 attributed to x/net", byModule[net])
	}
	if len(byModule[stdlib]) != 1 || byModule[stdlib][0].ID != "GO-STD-0003" {
		t.Errorf("stdlib findings = %+v, want GO-STD-0003 under the {stdlib,\"\"} key", byModule[stdlib])
	}
	// Every kept finding is reachability-annotated true: the project-rooted
	// analysis is itself the reachability answer.
	if r := byModule[net][0].Reachable; r == nil || !r.IsReachable {
		t.Errorf("x/net finding reachable = %+v, want reachable=true", r)
	}
}

// TestScan_NoGoModInZipIsSynthesisedNotAbandoned is the regression guard for a
// module zip published before Go modules. govulncheck refuses source analysis
// when the directory it is pointed at has no go.mod, but that is a precondition
// on the scan directory rather than a property of the artefact: supplying one in
// the scratch directory makes the module analysable. Returning Unscannable here
// would record a coverage gap that is not real and would deny the module any
// reachability verdict.
func TestScan_NoGoModInZipIsSynthesisedNotAbandoned(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	fakeGovulncheckOnPath(t, 0, "")
	zipBytes := makeModuleZip(t, map[string]string{
		"github.com/boltdb/bolt@v1.3.1/db.go": "package bolt\n\nfunc Open() {}\n",
	})
	coord := coordinate.ModuleCoordinate{Path: "github.com/boltdb/bolt", Version: "v1.3.1"}

	var buf bytes.Buffer
	s := capturingScanner(&buf, slog.LevelInfo)
	rec, err := s.Scan(t.Context(), ports.ScanRequest{
		Coordinate:   coord,
		ModuleSource: bytes.NewReader(zipBytes),
		Snapshot:     domain.DatabaseSnapshot{},
		BuildList: map[coordinate.ModuleCoordinate]struct{}{
			{Path: "example.com/dep", Version: "v0.3.0"}: {},
		},
	})
	if err != nil {
		t.Fatalf("Scan returned a hard error: %v", err)
	}
	if rec.UnscanReason == domain.UnscanReasonNoGoMod {
		t.Errorf("module was abandoned as %s; it should have been scanned with a synthesised go.mod\nlogs:\n%s",
			domain.UnscanReasonNoGoMod, buf.String())
	}
	if rec.OverallStatus == domain.StatusUnscannable {
		t.Errorf("OverallStatus = %s, want a scanned verdict\nlogs:\n%s", rec.OverallStatus, buf.String())
	}
	if !strings.Contains(buf.String(), "synthesised one for isolated scan") {
		t.Errorf("expected the synthesis to be recorded in the log, got:\n%s", buf.String())
	}
}

// A zip that does carry its own go.mod must not be touched: the published
// requirements are the module's own and synthesis must never displace them.
func TestScan_ExistingGoModIsNotReplacedBySynthesis(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	fakeGovulncheckOnPath(t, 0, "")
	zipBytes := makeModuleZip(t, map[string]string{
		"example.com/mod@v1.0.0/go.mod": "module example.com/mod\n\ngo 1.21\n",
		"example.com/mod@v1.0.0/m.go":   "package mod\n",
	})
	coord := coordinate.ModuleCoordinate{Path: "example.com/mod", Version: "v1.0.0"}

	var buf bytes.Buffer
	s := capturingScanner(&buf, slog.LevelInfo)
	if _, err := s.Scan(t.Context(), ports.ScanRequest{
		Coordinate:   coord,
		ModuleSource: bytes.NewReader(zipBytes),
		Snapshot:     domain.DatabaseSnapshot{},
		BuildList: map[coordinate.ModuleCoordinate]struct{}{
			{Path: "example.com/dep", Version: "v0.3.0"}: {},
		},
	}); err != nil {
		t.Fatalf("Scan returned a hard error: %v", err)
	}
	if strings.Contains(buf.String(), "synthesised one for isolated scan") {
		t.Errorf("synthesis ran for a module that ships its own go.mod; logs:\n%s", buf.String())
	}
}

// TestScanProject_InputFaultsCarryDistinctReasons pins the taxonomy of the two
// project-directory input faults: an unreadable directory and a directory with
// no go.mod are separate conditions, and neither is the module-zip no-go-mod
// reason, which names a property of a published artefact instead.
func TestScanProject_InputFaultsCarryDistinctReasons(t *testing.T) {
	s := New("v1", nil)
	s.logger = slog.New(slog.NewTextHandler(io.Discard, nil))

	missing := filepath.Join(t.TempDir(), "does-not-exist")
	res, err := s.ScanProject(t.Context(), missing, domain.DatabaseSnapshot{}, "")
	if err != nil {
		t.Fatalf("ScanProject on a missing directory must not error: %v", err)
	}
	if res.Status != domain.StatusUnscannable {
		t.Errorf("Status = %q, want %q", res.Status, domain.StatusUnscannable)
	}
	if res.UnscanReason != domain.UnscanReasonProjectDirUnavailable {
		t.Errorf("UnscanReason = %q, want %q", res.UnscanReason, domain.UnscanReasonProjectDirUnavailable)
	}

	empty := t.TempDir()
	res, err = s.ScanProject(t.Context(), empty, domain.DatabaseSnapshot{}, "")
	if err != nil {
		t.Fatalf("ScanProject on a go.mod-less directory must not error: %v", err)
	}
	if res.Status != domain.StatusUnscannable {
		t.Errorf("Status = %q, want %q", res.Status, domain.StatusUnscannable)
	}
	if res.UnscanReason != domain.UnscanReasonProjectNoGoMod {
		t.Errorf("UnscanReason = %q, want %q", res.UnscanReason, domain.UnscanReasonProjectNoGoMod)
	}
}
