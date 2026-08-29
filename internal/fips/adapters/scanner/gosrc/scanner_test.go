package gosrc_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/fips/adapters/scanner/gosrc"
	fipsvendortree "github.com/eitanity/kanonarion/internal/fips/adapters/vendortree"
	"github.com/eitanity/kanonarion/internal/fips/domain"
	venlocalfs "github.com/eitanity/kanonarion/internal/vendortree/adapters/scanner/localfs"
	vendordomain "github.com/eitanity/kanonarion/internal/vendortree/domain"
)

// scanner is the scanner as the composition root builds it: the vendor
// context's own reader of vendor/modules.txt behind the fips port. The tests
// below assert what a vendored finding NAMES, so wiring a stub here would be
// testing the stub.
func scanner() *gosrc.Scanner {
	return gosrc.New(fipsvendortree.New(venlocalfs.New(nil)))
}

// TestScanProject_NativeFIPSFacts: the go directive version and a
// `//go:debug fips140=…` directive are surfaced on the ParseResult so the
// domain can decide native-FIPS capability.
func TestScanProject_NativeFIPSFacts(t *testing.T) {
	dir := t.TempDir()
	goMod := "module example.com/native\n\ngo 1.24\n\ngodebug fips140=on\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o600); err != nil {
		t.Fatalf("writing go.mod: %v", err)
	}
	res, err := scanner().ScanProject(context.Background(), filepath.Join(dir, "go.mod"))
	if err != nil {
		t.Fatalf("ScanProject: %v", err)
	}
	if res.GoVersion != "1.24" {
		t.Errorf("GoVersion = %q, want 1.24", res.GoVersion)
	}
	if res.FIPS140 != "on" {
		t.Errorf("FIPS140 = %q, want on", res.FIPS140)
	}
}

const corpus = "../../../../../test/fixtures/supplychain/fips"

// TestScanProject_StockGoNotCapable: stock Go (no variant) reads through
// the buildinfo.txt sidecar; RecogniseToolchain returns "" and the
// downstream assessor will classify the toolchain finding as deviation.
func TestScanProject_StockGoNotCapable(t *testing.T) {
	res, err := scanner().ScanProject(context.Background(), filepath.Join(corpus, "stock", "go.mod"))
	if err != nil {
		t.Fatalf("ScanProject: %v", err)
	}
	if res.ToolchainRaw == "" {
		t.Fatal("expected toolchain raw to be populated from buildinfo.txt")
	}
	if got := domain.RecogniseToolchain(res.ToolchainRaw); got != "" {
		t.Errorf("stock Go must not match a FIPS variant, got %q", got)
	}
	if res.ProjectModulePath != "example.com/supplychain/fips/stock" {
		t.Errorf("module path = %q", res.ProjectModulePath)
	}
}

// TestScanProject_BoringCryptoCapable: a BoringCrypto buildinfo signal is
// picked up and matches the catalogue.
func TestScanProject_BoringCryptoCapable(t *testing.T) {
	res, err := scanner().ScanProject(context.Background(), filepath.Join(corpus, "boringcrypto", "go.mod"))
	if err != nil {
		t.Fatalf("ScanProject: %v", err)
	}
	if got := domain.RecogniseToolchain(res.ToolchainRaw); got != "boringcrypto" {
		t.Errorf("variant = %q, want boringcrypto", got)
	}
}

// TestScanProject_MD5InDep: a vendored dep importing crypto/md5 produces an
// algorithm finding with module + source provenance (acceptance).
func TestScanProject_MD5InDep(t *testing.T) {
	res, err := scanner().ScanProject(context.Background(), filepath.Join(corpus, "md5-in-dep", "go.mod"))
	if err != nil {
		t.Fatalf("ScanProject: %v", err)
	}
	var found *domain.Finding
	for i := range res.Findings {
		if res.Findings[i].Kind == domain.FindingAlgorithm &&
			res.Findings[i].Package == "crypto/md5" {
			found = &res.Findings[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("expected crypto/md5 finding, got %+v", res.Findings)
	}
	if found.Module != "example.com/dep" {
		t.Errorf("module = %q, want example.com/dep", found.Module)
	}
	if !strings.HasPrefix(found.Source, "vendor/example.com/dep/") || found.Line == 0 {
		t.Errorf("provenance not captured: %+v", *found)
	}
}

// TestScanProject_CgoCryptoFinding: a vendored dep that imports "C" *and*
// has a crypto-shaped path produces a cgo-crypto finding — the heuristic
// that surfaces the known cgo gap.
func TestScanProject_CgoCryptoFinding(t *testing.T) {
	res, err := scanner().ScanProject(context.Background(), filepath.Join(corpus, "cgo-crypto", "go.mod"))
	if err != nil {
		t.Fatalf("ScanProject: %v", err)
	}
	var cgo *domain.Finding
	for i := range res.Findings {
		if res.Findings[i].Kind == domain.FindingCgoCrypto {
			cgo = &res.Findings[i]
		}
	}
	if cgo == nil {
		t.Fatalf("expected a cgo_crypto finding, got %+v", res.Findings)
	}
	if !strings.Contains(cgo.Module, "openssl") {
		t.Errorf("cgo finding module = %q, want it to mention openssl", cgo.Module)
	}
}

// TestScanProject_CleanBoringCrypto: clean project with crypto/rand and
// crypto/sha256 — direct-rand is surfaced (a fact, not a deviation) and
// no algorithm findings are produced.
func TestScanProject_CleanBoringCrypto(t *testing.T) {
	res, err := scanner().ScanProject(context.Background(), filepath.Join(corpus, "clean-bc", "go.mod"))
	if err != nil {
		t.Fatalf("ScanProject: %v", err)
	}
	var algoCount, randCount int
	for _, f := range res.Findings {
		switch f.Kind {
		case domain.FindingAlgorithm:
			algoCount++
		case domain.FindingDirectRandom:
			randCount++
		}
	}
	if algoCount != 0 {
		t.Errorf("clean fixture must have no algorithm findings, got %d", algoCount)
	}
	if randCount == 0 {
		t.Errorf("expected at least one crypto/rand finding, got %d", randCount)
	}
}

// TestScanProject_UnlistedVendorDirIsUnresolved: a directory under vendor/
// that vendor/modules.txt does not list is reported as unresolved. The listed
// sibling in the same fixture is the control — the mapping is read, and only
// the path nothing claims goes unattributed.
//
// Guessing here is the defect this closes: the plausible answer for the stray
// directory is "example.com/stray", which names nothing anyone can upgrade,
// pin or exempt, and is plausible enough to be pasted into a report.
func TestScanProject_UnlistedVendorDirIsUnresolved(t *testing.T) {
	res, err := scanner().ScanProject(context.Background(), filepath.Join(corpus, "unlisted-in-vendor", "go.mod"))
	if err != nil {
		t.Fatalf("ScanProject: %v", err)
	}
	got := map[string]string{}
	for _, f := range res.Findings {
		if f.Kind == domain.FindingAlgorithm {
			got[f.Source] = f.Module
		}
	}
	want := map[string]string{
		"vendor/example.com/listed/hash.go.txt": "example.com/listed",
		"vendor/example.com/stray/hash.go.txt":  vendordomain.ModuleUnresolved,
	}
	if len(got) != len(want) {
		t.Fatalf("algorithm findings = %v, want %v", got, want)
	}
	for src, wantMod := range want {
		if got[src] != wantMod {
			t.Errorf("module for %s = %q, want %q", src, got[src], wantMod)
		}
	}
}

// TestScanProject_NoVendorTreeReportsTheProjectModule: a project with no
// vendor/ directory reports the project module for every finding, exactly as
// before. Not vendored is an answer the lister gives, not a failure.
func TestScanProject_NoVendorTreeReportsTheProjectModule(t *testing.T) {
	res, err := scanner().ScanProject(context.Background(), filepath.Join(corpus, "clean-bc", "go.mod"))
	if err != nil {
		t.Fatalf("ScanProject: %v", err)
	}
	var checked int
	for _, f := range res.Findings {
		if f.Source == "" {
			continue
		}
		checked++
		if f.Module != res.ProjectModulePath {
			t.Errorf("%s: module = %q, want the project module %q", f.Source, f.Module, res.ProjectModulePath)
		}
	}
	if checked == 0 {
		t.Fatal("no source-bearing findings in the clean-bc fixture to check")
	}
}

// TestScanProject_MissingGoMod surfaces the I/O error rather than
// substituting an empty result (never present "" as a verdict).
func TestScanProject_MissingGoMod(t *testing.T) {
	_, err := scanner().ScanProject(context.Background(), filepath.Join(corpus, "does-not-exist", "go.mod"))
	if err == nil {
		t.Fatal("expected error for missing go.mod")
	}
}
