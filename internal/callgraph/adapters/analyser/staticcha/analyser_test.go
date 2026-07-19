package staticcha_test

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"slices"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/adapters/analyser/staticcha"
	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

func makeZip(t testing.TB, coord fetchdomain.ModuleCoordinate, files map[string]string) []byte {
	t.Helper()
	prefix := coord.Path + "@" + coord.Version + "/"
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(prefix + name)
		if err != nil {
			t.Fatalf("creating zip entry %s: %v", name, err)
		}
		if _, err := io.WriteString(w, content); err != nil {
			t.Fatalf("writing zip entry %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("closing zip writer: %v", err)
	}
	return buf.Bytes()
}

var testCoord, _ = fetchdomain.NewModuleCoordinate("example.com/cgtestmod", "v1.0.0")

// testModule is a minimal Go module with no external dependencies.
var testModuleFiles = map[string]string{
	"go.mod": "module example.com/cgtestmod\n\ngo 1.21\n",
	"cgtestmod.go": `package cgtestmod

// Alpha calls Beta directly.
func Alpha() {
	Beta()
}

// Beta calls Gamma directly.
func Beta() {
	Gamma()
}

// Gamma is a leaf function.
func Gamma() {}

// unexported is not part of the public API.
func unexported() {}
`,
}

func writeZipToTemp(t *testing.T, data []byte) string {
	t.Helper()
	f, err := os.CreateTemp("", "kanonarion-test-*.zip")
	if err != nil {
		t.Fatalf("creating temp zip: %v", err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(data); err != nil {
		t.Fatalf("writing temp zip: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(f.Name()) })
	return f.Name()
}

func TestAnalyse_BasicCallGraph(t *testing.T) {
	a := staticcha.New("0.1.0", "", slog.Default())

	zipData := makeZip(t, testCoord, testModuleFiles)
	zipPath := writeZipToTemp(t, zipData)
	rec, err := a.Analyse(context.Background(), zipPath, testCoord)
	if err != nil {
		t.Fatalf("Analyse returned error: %v", err)
	}

	switch rec.OverallStatus {
	case domain.CallGraphStatusExtracted, domain.CallGraphStatusPartial:
		// acceptable
	default:
		t.Fatalf("unexpected status %s: %s", rec.OverallStatus, rec.FailureDetail)
	}

	// A clean extraction is built with bodies, the only level a confident
	// negative verdict may rest on.
	if rec.Completeness != domain.CompletenessBuiltWithBodies {
		t.Errorf("expected Completeness BUILT_WITH_BODIES, got %s", rec.Completeness)
	}

	if len(rec.Nodes) == 0 {
		t.Error("expected at least one node in the call graph")
	}

	// Check that Alpha, Beta, Gamma nodes exist.
	nodeIDs := make(map[string]bool)
	for _, n := range rec.Nodes {
		nodeIDs[n.Symbol] = true
	}
	for _, sym := range []string{"Alpha", "Beta", "Gamma"} {
		if !nodeIDs[sym] {
			t.Errorf("expected node for symbol %q not found; nodes: %v", sym, rec.Nodes)
		}
	}

	// Check that Alpha→Beta and Beta→Gamma edges exist.
	type edgeKey struct{ from, to string }
	edges := make(map[edgeKey]bool)
	for _, e := range rec.Edges {
		edges[edgeKey{e.FromID, e.ToID}] = true
	}
	for _, fromSym := range []string{"Alpha", "Beta"} {
		toSym := map[string]string{"Alpha": "Beta", "Beta": "Gamma"}[fromSym]
		found := false
		for k := range edges {
			// IDs are in "pkg.Symbol" format; check suffix.
			if hasSuffix(k.from, fromSym) && hasSuffix(k.to, toSym) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected edge %s→%s not found; edges: %v", fromSym, toSym, rec.Edges)
		}
	}
}

func TestAnalyse_DirectConfidence(t *testing.T) {
	a := staticcha.New("0.1.0", "", slog.Default())
	zipData := makeZip(t, testCoord, testModuleFiles)
	zipPath := writeZipToTemp(t, zipData)
	rec, err := a.Analyse(context.Background(), zipPath, testCoord)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	if rec.OverallStatus == domain.CallGraphStatusLoadFailed {
		t.Skip("go/packages load failed; skipping confidence test")
	}

	for _, e := range rec.Edges {
		// All calls in testModuleFiles are direct static calls.
		if e.Confidence == domain.ConfidenceUnknown {
			// Some synthetic edges (e.g. init) may be unknown; that's fine.
			continue
		}
		if e.Confidence != domain.ConfidenceDirect &&
			e.Confidence != domain.ConfidenceCHAOverapprox {
			t.Errorf("unexpected confidence %q for edge %s→%s", e.Confidence, e.FromID, e.ToID)
		}
	}
}

func TestAnalyse_InterfaceDispatch(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.com/cgtestmod\n\ngo 1.21\n",
		"iface.go": `package cgtestmod

type Doer interface {
	Do()
}

type Impl struct{}

func (Impl) Do() {}

func CallDoer(d Doer) {
	d.Do()
}
`,
	}
	a := staticcha.New("0.1.0", "", slog.Default())
	zipData := makeZip(t, testCoord, files)
	zipPath := writeZipToTemp(t, zipData)
	rec, err := a.Analyse(context.Background(), zipPath, testCoord)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	if rec.OverallStatus == domain.CallGraphStatusLoadFailed {
		t.Skip("go/packages load failed; skipping interface dispatch test")
	}

	// CHA should produce at least one CHA-overapprox edge for d.Do.
	var gotDynamic bool
	for _, e := range rec.Edges {
		if e.Confidence == domain.ConfidenceCHAOverapprox {
			gotDynamic = true
			break
		}
	}
	if !gotDynamic {
		t.Errorf("expected at least one CHA-overapprox edge; edges: %v", rec.Edges)
	}
}

func TestAnalyse_Deterministic(t *testing.T) {
	a := staticcha.New("0.1.0", "", slog.Default())
	zipData := makeZip(t, testCoord, testModuleFiles)
	zipPath := writeZipToTemp(t, zipData)

	r1, err := a.Analyse(context.Background(), zipPath, testCoord)
	if err != nil {
		t.Fatalf("first Analyse: %v", err)
	}
	r2, err := a.Analyse(context.Background(), zipPath, testCoord)
	if err != nil {
		t.Fatalf("second Analyse: %v", err)
	}

	if len(r1.Nodes) != len(r2.Nodes) {
		t.Errorf("node count differs: %d vs %d", len(r1.Nodes), len(r2.Nodes))
	}
	if len(r1.Edges) != len(r2.Edges) {
		t.Errorf("edge count differs: %d vs %d", len(r1.Edges), len(r2.Edges))
	}
}

func TestAnalyse_InvalidZip(t *testing.T) {
	a := staticcha.New("0.1.0", "", slog.Default())
	zipPath := writeZipToTemp(t, []byte("not a zip"))
	rec, err := a.Analyse(context.Background(), zipPath, testCoord)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	if rec.OverallStatus != domain.CallGraphStatusLoadFailed {
		t.Errorf("expected LoadFailed for invalid zip, got %s", rec.OverallStatus)
	}
}

func TestAnalyse_IsExportedAPI(t *testing.T) {
	a := staticcha.New("0.1.0", "", slog.Default())
	zipData := makeZip(t, testCoord, testModuleFiles)
	zipPath := writeZipToTemp(t, zipData)
	rec, err := a.Analyse(context.Background(), zipPath, testCoord)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	if rec.OverallStatus == domain.CallGraphStatusLoadFailed {
		t.Skip("go/packages load failed; skipping export API test")
	}

	for _, n := range rec.Nodes {
		if n.IsExternal {
			continue
		}
		if n.Symbol == "unexported" && n.IsExportedAPI {
			t.Error("unexported function should not be marked IsExportedAPI")
		}
		if n.Symbol == "Alpha" && !n.IsExportedAPI {
			t.Error("Alpha should be marked IsExportedAPI")
		}
	}
}

func TestAnalyserMetadata(t *testing.T) {
	a := staticcha.New("0.1.0", "", slog.Default())
	meta := a.AnalyserMetadata()
	if meta.Algorithm != domain.AlgorithmCHA {
		t.Errorf("Algorithm = %q, want CHA", meta.Algorithm)
	}
	if meta.Version == "" {
		t.Error("Version should not be empty")
	}
}

func TestAnalyse_MainPackage(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.com/cgtestmod\n\ngo 1.21\n",
		"main.go": `package main

import "fmt"

func main() {
	greet()
}

func greet() {
	fmt.Println("hello")
}
`,
	}
	a := staticcha.New("0.1.0", "", slog.Default())
	zipData := makeZip(t, testCoord, files)
	zipPath := writeZipToTemp(t, zipData)
	rec, err := a.Analyse(context.Background(), zipPath, testCoord)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	if rec.OverallStatus == domain.CallGraphStatusLoadFailed {
		t.Skip("go/packages load failed; skipping main package test")
	}
	// Nodes in a main package should not be marked IsExportedAPI.
	for _, n := range rec.Nodes {
		if !n.IsExternal && n.IsExportedAPI {
			t.Errorf("node %q in main package should not be IsExportedAPI", n.ID)
		}
	}
}

func TestAnalyse_PathTraversalInZip(t *testing.T) {
	// Create a zip with a path traversal entry — should be silently skipped.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	prefix := testCoord.Path + "@" + testCoord.Version + "/"

	// Valid entry.
	w, err := zw.Create(prefix + "go.mod")
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(w, "module example.com/cgtestmod\n\ngo 1.21\n") //nolint:errcheck,gosec

	// Path traversal entry — should be ignored.
	w2, err := zw.Create(prefix + "../evil.go")
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(w2, "package evil") //nolint:errcheck,gosec

	zw.Close() //nolint:errcheck,gosec

	a := staticcha.New("0.1.0", "", slog.Default())
	zipPath := writeZipToTemp(t, buf.Bytes())
	rec, err := a.Analyse(context.Background(), zipPath, testCoord)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	// May succeed or fail cleanly (no.go files), but must not error.
	if rec.OverallStatus == domain.CallGraphStatusExtractionFailed {
		t.Errorf("unexpected ExtractionFailed for path traversal test: %s", rec.FailureDetail)
	}
}

func TestAnalyse_ReflectionCall(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.com/cgtestmod\n\ngo 1.21\n",
		"reflect_test_mod.go": `package cgtestmod

import "reflect"

func UseReflect(v any) string {
	return reflect.TypeOf(v).String()
}
`,
	}
	a := staticcha.New("0.1.0", "", slog.Default())
	zipData := makeZip(t, testCoord, files)
	zipPath := writeZipToTemp(t, zipData)
	rec, err := a.Analyse(context.Background(), zipPath, testCoord)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	if rec.OverallStatus == domain.CallGraphStatusLoadFailed {
		t.Skip("go/packages load failed; skipping reflection test")
	}
	// Reflection is no longer a distinct confidence rank: reflect-dispatched
	// edges fold into Unknown and carry the ReflectDispatch attribute. CHA may
	// not resolve a static callee into the reflect package here, so we don't
	// require a reflect edge — but any edge flagged ReflectDispatch must be
	// tagged Unknown, never a distinct Reflection value.
	for _, e := range rec.Edges {
		if e.ReflectDispatch && e.Confidence != domain.ConfidenceUnknown {
			t.Errorf("reflect-dispatched edge %s→%s has confidence %q, want Unknown", e.FromID, e.ToID, e.Confidence)
		}
	}
	t.Logf("status=%s nodes=%d edges=%d", rec.OverallStatus, len(rec.Nodes), len(rec.Edges))
}

func TestAnalyse_ZipWithDirectoryEntries(t *testing.T) {
	// Create a zip that contains explicit directory entries (IsDir == true).
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	prefix := testCoord.Path + "@" + testCoord.Version + "/"

	// Explicit directory entry.
	if _, err := zw.Create(prefix + "subdir/"); err != nil {
		t.Fatal(err)
	}
	// go.mod in root.
	w, err := zw.Create(prefix + "go.mod")
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(w, "module example.com/cgtestmod\n\ngo 1.21\n") //nolint:errcheck,gosec
	// A file in the subdir.
	w2, err := zw.Create(prefix + "subdir/doc.go")
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(w2, "package subdir\n") //nolint:errcheck,gosec
	// Root package file.
	w3, err := zw.Create(prefix + "cgtestmod.go")
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(w3, "package cgtestmod\n\nfunc Root() {}\n") //nolint:errcheck,gosec

	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	a := staticcha.New("0.1.0", "", slog.Default())
	zipPath := writeZipToTemp(t, buf.Bytes())
	rec, err := a.Analyse(context.Background(), zipPath, testCoord)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	// Any non-infra-error status is acceptable; the zip was valid.
	if rec.OverallStatus == domain.CallGraphStatusExtractionFailed {
		t.Errorf("unexpected ExtractionFailed: %s", rec.FailureDetail)
	}
}

func TestAnalyse_PartialLoadWithBrokenSubpackage(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.com/cgtestmod\n\ngo 1.21\n",
		"cgtestmod.go": `package cgtestmod

func Good() {}
`,
		// subpkg has a syntax error; go/packages may produce a load error for it.
		"broken/broken.go": `package broken

func(  // intentional syntax error
`,
	}
	a := staticcha.New("0.1.0", "", slog.Default())
	zipData := makeZip(t, testCoord, files)
	zipPath := writeZipToTemp(t, zipData)
	rec, err := a.Analyse(context.Background(), zipPath, testCoord)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	// May be Partial (some packages loaded), LoadFailed, or Extracted —
	// depending on how go/packages handles the syntax error.
	switch rec.OverallStatus {
	case domain.CallGraphStatusExtracted,
		domain.CallGraphStatusPartial,
		domain.CallGraphStatusLoadFailed:
		// all acceptable
	default:
		t.Errorf("unexpected status %s: %s", rec.OverallStatus, rec.FailureDetail)
	}
	t.Logf("status=%s nodes=%d edges=%d detail=%s",
		rec.OverallStatus, len(rec.Nodes), len(rec.Edges), rec.FailureDetail)
}

// TestAnalyse_FailedPackagesRecordedOnTypecheckError is the partial-graph
// regression fixture. It reproduces the observed real-world shape with a
// purpose-built module (no third-party code): one sub-package fails to
// typecheck (an undefined symbol,
// which parses cleanly but does not type-check), while the root package
// compiles. The record must be Partial and must name exactly the failing
// package in FailedPackages, so verdicts can be scoped to it rather than
// inferred from node/edge totals.
func TestAnalyse_FailedPackagesRecordedOnTypecheckError(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.com/cgtestmod\n\ngo 1.21\n",
		"cgtestmod.go": `package cgtestmod

// Good compiles cleanly and calls a local helper.
func Good() { helper() }

func helper() {}
`,
		// broken parses fine but fails type checking: notDefined is undefined.
		// This is the moral equivalent of the sqlc DBTX interface mismatch —
		// a real type error localised to one package.
		"broken/broken.go": `package broken

// Broken references an undefined symbol, so this package does not typecheck.
func Broken() int { return notDefined() }
`,
	}
	a := staticcha.New("0.1.0", "", slog.Default())
	zipData := makeZip(t, testCoord, files)
	zipPath := writeZipToTemp(t, zipData)
	rec, err := a.Analyse(context.Background(), zipPath, testCoord)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}

	if rec.OverallStatus != domain.CallGraphStatusPartial {
		t.Fatalf("expected Partial status, got %s (detail=%s)", rec.OverallStatus, rec.FailureDetail)
	}
	const wantPkg = "example.com/cgtestmod/broken"
	if !slices.Contains(rec.FailedPackages, wantPkg) {
		t.Errorf("expected FailedPackages to contain %q, got %v", wantPkg, rec.FailedPackages)
	}
	// The clean root package must not be flagged as failed.
	if slices.Contains(rec.FailedPackages, "example.com/cgtestmod") {
		t.Errorf("root package must not be reported as failed; FailedPackages=%v", rec.FailedPackages)
	}
	// The root package was built into SSA with bodies, so the module-level
	// fidelity is BUILT_WITH_BODIES even though one sub-package failed — the
	// per-package failure lives in FailedPackages, not the completeness level.
	if rec.Completeness != domain.CompletenessBuiltWithBodies {
		t.Errorf("expected Completeness BUILT_WITH_BODIES, got %s", rec.Completeness)
	}
}

func TestAnalyse_ContextCancellation(t *testing.T) {
	a := staticcha.New("0.1.0", "", slog.Default())
	zipData := makeZip(t, testCoord, testModuleFiles)
	zipPath := writeZipToTemp(t, zipData)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	rec, err := a.Analyse(ctx, zipPath, testCoord)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	// Either cancelled or load failed (go/packages may detect cancelled context).
	switch rec.OverallStatus {
	case domain.CallGraphStatusCancelled, domain.CallGraphStatusLoadFailed:
		// acceptable
	case domain.CallGraphStatusExtracted, domain.CallGraphStatusPartial:
		// go/packages returned before context was checked — also acceptable
	default:
		t.Errorf("unexpected status for cancelled context: %s", rec.OverallStatus)
	}
}

func TestAnalyse_BodyLevelFacts(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.com/cgtestmod\n\ngo 1.21\n",
		"facts.go": `package cgtestmod

import (
	"plugin"
	"unsafe"
)

// nanotime has no Go body — it is provided via //go:linkname, so it is an
// ARBITRARY_EXECUTION leaf.
//
//go:linkname nanotime runtime.nanotime
func nanotime() int64

// UsesUnsafe performs an unsafe.Pointer conversion in its body.
func UsesUnsafe(p *int) uintptr {
	return uintptr(unsafe.Pointer(p))
}

// LoadsPlugin opens a plugin — a runtime code-load boundary the static graph
// cannot follow.
func LoadsPlugin(path string) error {
	_, err := plugin.Open(path)
	return err
}

// Safe touches neither fact.
func Safe() int { return 1 }

// Root reaches every fact-bearing function.
func Root() {
	_ = nanotime()
	_ = UsesUnsafe(nil)
	_ = LoadsPlugin("")
	_ = Safe()
}
`,
	}
	a := staticcha.New("0.1.0", "", slog.Default())
	zipData := makeZip(t, testCoord, files)
	zipPath := writeZipToTemp(t, zipData)
	rec, err := a.Analyse(context.Background(), zipPath, testCoord)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	if rec.OverallStatus == domain.CallGraphStatusLoadFailed {
		t.Skipf("go/packages load failed; skipping body-facts test: %s", rec.FailureDetail)
	}

	bySymbol := make(map[string]domain.CallNode)
	for _, n := range rec.Nodes {
		bySymbol[n.Symbol] = n
	}

	unsafeFn, ok := bySymbol["UsesUnsafe"]
	if !ok {
		t.Fatalf("UsesUnsafe node not found; nodes: %v", rec.Nodes)
	}
	if !unsafeFn.UsesUnsafePointer {
		t.Error("UsesUnsafe should have UsesUnsafePointer=true")
	}
	if unsafeFn.IsAssemblyOrLinkname {
		t.Error("UsesUnsafe has a Go body; IsAssemblyOrLinkname should be false")
	}

	nano, ok := bySymbol["nanotime"]
	if !ok {
		t.Fatalf("nanotime node not found; nodes: %v", rec.Nodes)
	}
	if !nano.IsAssemblyOrLinkname {
		t.Error("nanotime has no Go body; IsAssemblyOrLinkname should be true")
	}
	if nano.UsesUnsafePointer {
		t.Error("nanotime should not use unsafe.Pointer")
	}

	pluginFn, ok := bySymbol["LoadsPlugin"]
	if !ok {
		t.Fatalf("LoadsPlugin node not found; nodes: %v", rec.Nodes)
	}
	if !pluginFn.UsesPlugin {
		t.Error("LoadsPlugin should have UsesPlugin=true")
	}
	if unsafeFn.UsesPlugin {
		t.Error("UsesUnsafe does not touch the plugin package; UsesPlugin should be false")
	}

	if safe, ok := bySymbol["Safe"]; ok {
		if safe.UsesUnsafePointer || safe.IsAssemblyOrLinkname || safe.UsesPlugin {
			t.Errorf("Safe should carry no body facts, got %+v", safe)
		}
	}
}

func hasSuffix(s, suffix string) bool {
	if len(s) < len(suffix) {
		return false
	}
	if s == suffix {
		return true
	}
	// Check ".Suffix" suffix.
	return s[len(s)-len(suffix)-1:] == "."+suffix
}
