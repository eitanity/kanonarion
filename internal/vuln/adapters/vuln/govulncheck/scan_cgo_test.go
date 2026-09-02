package govulncheck

import (
	"bytes"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

// TestScan_BinaryModeBuildChildRunsWithoutCgo asserts the reduction on the
// environment the subprocess was actually handed, not on what a builder returns
// in isolation: the test build is the one scan child that compiles an untrusted
// module's C source with the system C compiler, and only a recording of the
// child's own env says whether it did.
//
// The same run measures the other half of the decision. The source-mode child
// must still see the caller's cgo setting, because it loads packages with type
// information — turning cgo off there makes a cgo module unloadable, which is
// coverage lost rather than surface reduced.
func TestScan_BinaryModeBuildChildRunsWithoutCgo(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the go and govulncheck stubs are POSIX shell scripts")
	}
	t.Setenv("CGO_ENABLED", "1")

	recordDir := t.TempDir()
	stubDir := t.TempDir()
	// The go stub records the build child's environment and exits 0 without
	// producing a binary, so the scan takes its no-test-files fallback to source
	// mode and the govulncheck child below runs too.
	writeExecutable(t, filepath.Join(stubDir, "go"),
		"#!/bin/sh\nfor a in \"$@\"; do if [ \"$a\" = \"-c\" ]; then env > "+
			filepath.Join(recordDir, "build.env")+"; fi; done\nexit 0\n")
	writeExecutable(t, filepath.Join(stubDir, "govulncheck"),
		"#!/bin/sh\nenv > "+filepath.Join(recordDir, "govulncheck.env")+"\nexit 0\n")
	t.Setenv("PATH", stubDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	zipBytes := makeModuleZip(t, map[string]string{
		"example.com/mod@v1.0.0/go.mod": "module example.com/mod\n\ngo 1.21\n",
		"example.com/mod@v1.0.0/mod.go": "package mod\n",
	})
	var buf bytes.Buffer
	s := capturingScanner(t, &buf, slog.LevelDebug)
	if _, err := s.Scan(t.Context(), ports.ScanRequest{
		Coordinate:   coordinatetest.MustNew("example.com/mod", "v1.0.0"),
		ModuleSource: bytes.NewReader(zipBytes),
		Snapshot:     fixtureSnapshot(t),
		GoModCache:   t.TempDir(),
		ScanMode:     domain.ScanModeBinary,
	}); err != nil {
		t.Fatalf("Scan returned a hard error: %v\nlogs:\n%s", err, buf.String())
	}

	build := recordedEnv(t, filepath.Join(recordDir, "build.env"),
		"the scan never ran a `go test -c` child, so nothing about its environment was measured")
	if got := build["CGO_ENABLED"]; got != "0" {
		t.Errorf("the binary-mode test build was handed CGO_ENABLED=%q, want 0: this child compiles an untrusted "+
			"module's C source with the system C compiler and binary mode reads only a symbol table", got)
	}

	scan := recordedEnv(t, filepath.Join(recordDir, "govulncheck.env"),
		"the scan never ran a govulncheck child")
	if got := scan["CGO_ENABLED"]; got != "1" {
		t.Errorf("the source-mode child was handed CGO_ENABLED=%q, want the caller's own 1: source analysis loads "+
			"packages with type information, so turning cgo off there makes a cgo module Unscannable", got)
	}
}

// TestScan_CgoModuleFallsBackToSourceModeAndStillAnswers is the cost side of the
// decision, measured against the real toolchain: a module whose only Go file
// needs cgo cannot build with it off, and the scan must reach an answer through
// the existing downgrade rather than losing the module.
func TestScan_CgoModuleFallsBackToSourceModeAndStillAnswers(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available; this test measures a real build")
	}
	fakeGovulncheckOnPath(t, 0, "")

	zipBytes := makeModuleZip(t, map[string]string{
		"example.com/mod@v1.0.0/go.mod":      "module example.com/mod\n\ngo 1.21\n",
		"example.com/mod@v1.0.0/mod.go":      "package mod\n\n/*\n#include <stdlib.h>\n*/\nimport \"C\"\n\n// Size is the one symbol, and it needs cgo.\nfunc Size() int { return int(C.sizeof_int) }\n",
		"example.com/mod@v1.0.0/mod_test.go": "package mod\n\nimport \"testing\"\n\nfunc TestSize(t *testing.T) { _ = Size() }\n",
	})
	var buf bytes.Buffer
	s := capturingScanner(t, &buf, slog.LevelDebug)
	rec, err := s.Scan(t.Context(), ports.ScanRequest{
		Coordinate:   coordinatetest.MustNew("example.com/mod", "v1.0.0"),
		ModuleSource: bytes.NewReader(zipBytes),
		Snapshot:     fixtureSnapshot(t),
		GoModCache:   t.TempDir(),
		ScanMode:     domain.ScanModeBinary,
	})
	if err != nil {
		t.Fatalf("Scan returned a hard error: %v\nlogs:\n%s", err, buf.String())
	}

	const fallback = "binary build failed, falling back to source mode"
	if !strings.Contains(buf.String(), fallback) {
		t.Errorf("a cgo-only module did not take the %q route; the downgrade this reduction relies on is not the "+
			"one that ran\nlogs:\n%s", fallback, buf.String())
	}
	if rec.OverallStatus == domain.StatusUnscannable {
		t.Errorf("a module that needs cgo came back %s: the reduction may cost a scan mode, never an answer (%s)",
			rec.OverallStatus, rec.UnscannableReason)
	}
	if rec.OverallStatus != domain.StatusClean {
		t.Errorf("OverallStatus = %s, want %s from the stub's clean exit", rec.OverallStatus, domain.StatusClean)
	}
}

// TestScanEnv_NoSurfaceDecidesCgo holds the boundary of the decision: cgo is
// turned off for one child, so a builder that answered for it would put the same
// policy in two places.
func TestScanEnv_NoSurfaceDecidesCgo(t *testing.T) {
	base := []string{"PATH=/usr/bin", "CGO_ENABLED=1"}
	for _, surface := range []scanSurface{surfaceNormalised, surfaceVendored, surfaceLiveTree} {
		for _, cache := range []string{"", "/tmp/kanonarion-modcache"} {
			got := envMap(scanEnv(base, cache, surface))
			if got["CGO_ENABLED"] != "1" {
				t.Errorf("scanEnv(surface=%d, modcache=%q) set CGO_ENABLED=%q; only the binary-mode test build "+
					"decides that, and it decides it in one place", surface, cache, got["CGO_ENABLED"])
			}
		}
	}
}

// recordedEnv reads an environment a stub child wrote out, failing with reason
// when the child never ran at all.
func recordedEnv(t *testing.T, path, reason string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(path) // #nosec G304 -- written by this test into its own t.TempDir()
	if err != nil {
		t.Fatalf("%s: %v", reason, err)
	}
	return envMap(strings.Split(strings.TrimRight(string(raw), "\n"), "\n"))
}
