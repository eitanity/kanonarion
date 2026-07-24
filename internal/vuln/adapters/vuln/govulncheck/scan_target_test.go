package govulncheck

import (
	"bytes"
	"log/slog"
	"os/exec"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

// TestScanTargetModule_AnalysesTheExtractedTarget asserts the target-rooted scan
// prepares the target's own zip as the analysis root: the zip is extracted, the
// module root located beneath its path@version prefix, and govulncheck run
// there. That is what makes each dependency's package set import-driven, which
// is the whole point of the path.
func TestScanTargetModule_AnalysesTheExtractedTarget(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	fakeGovulncheckOnPath(t, 0, "")
	zipBytes := makeModuleZip(t, map[string]string{
		"github.com/example/engine@v1.4.0/go.mod": "module github.com/example/engine\n\ngo 1.21\n",
		"github.com/example/engine@v1.4.0/e.go":   "package engine\n",
	})
	coord := coordinate.ModuleCoordinate{Path: "github.com/example/engine", Version: "v1.4.0"}

	var buf bytes.Buffer
	s := capturingScanner(&buf, slog.LevelInfo)
	res, err := s.ScanTargetModule(t.Context(), ports.TargetScanRequest{
		Coordinate:   coord,
		ModuleSource: bytes.NewReader(zipBytes),
		Snapshot:     domain.DatabaseSnapshot{},
	})
	if err != nil {
		t.Fatalf("ScanTargetModule returned a hard error: %v", err)
	}
	if res.Status != domain.StatusClean {
		t.Errorf("Status = %s, want Clean for a target that analyses successfully with no findings", res.Status)
	}
	if !strings.Contains(buf.String(), "target-rooted scan starting") {
		t.Errorf("expected the target-rooted scan to be recorded in the log, got:\n%s", buf.String())
	}
}

// TestScanTargetModule_UnanalysableTargetIsAFaultNotACleanVerdict is the guard
// against the worst failure this path could have: a target that does not build
// must not read as a clean walk. The status has to carry the fault so the caller
// falls back to isolated scanning rather than recording every module Clean.
func TestScanTargetModule_UnanalysableTargetIsAFaultNotACleanVerdict(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	fakeGovulncheckOnPath(t, 2, "govulncheck: loading packages: no required module provides package")
	zipBytes := makeModuleZip(t, map[string]string{
		"example.com/mod@v1.0.0/go.mod": "module example.com/mod\n\ngo 1.21\n",
		"example.com/mod@v1.0.0/m.go":   "package mod\n",
	})

	s := capturingScanner(&bytes.Buffer{}, slog.LevelWarn)
	res, err := s.ScanTargetModule(t.Context(), ports.TargetScanRequest{
		Coordinate:   coordinate.ModuleCoordinate{Path: "example.com/mod", Version: "v1.0.0"},
		ModuleSource: bytes.NewReader(zipBytes),
		Snapshot:     domain.DatabaseSnapshot{},
	})
	if err != nil {
		t.Fatalf("ScanTargetModule returned a hard error: %v", err)
	}
	if res.Status == domain.StatusClean {
		t.Fatal("a target govulncheck could not analyse reported Clean; the fault must be carried in the status")
	}
	if res.Status != domain.StatusScanFailed {
		t.Errorf("Status = %s, want ScanFailed", res.Status)
	}
	if res.ErrorDetail == "" {
		t.Error("ScanFailed carries no ErrorDetail; the reason must be named")
	}
	if len(res.FindingsByModule) != 0 {
		t.Errorf("a failed analysis attributed findings: %+v", res.FindingsByModule)
	}
}

// TestScanTargetModule_SharesGoModSynthesisWithTheIsolatedPath asserts a target
// whose zip predates Go modules is still analysable: both scan paths run the
// same directory preparation, so the synthesis the isolated path gained applies
// here too rather than the target-rooted path silently refusing such a module.
func TestScanTargetModule_SharesGoModSynthesisWithTheIsolatedPath(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	fakeGovulncheckOnPath(t, 0, "")
	zipBytes := makeModuleZip(t, map[string]string{
		"github.com/boltdb/bolt@v1.3.1/db.go": "package bolt\n\nfunc Open() {}\n",
	})

	var buf bytes.Buffer
	s := capturingScanner(&buf, slog.LevelInfo)
	res, err := s.ScanTargetModule(t.Context(), ports.TargetScanRequest{
		Coordinate:   coordinate.ModuleCoordinate{Path: "github.com/boltdb/bolt", Version: "v1.3.1"},
		ModuleSource: bytes.NewReader(zipBytes),
		Snapshot:     domain.DatabaseSnapshot{},
	})
	if err != nil {
		t.Fatalf("ScanTargetModule returned a hard error: %v", err)
	}
	if res.UnscanReason == domain.UnscanReasonNoGoMod {
		t.Errorf("target abandoned as %s; the shared preparation should have synthesised a go.mod\nlogs:\n%s",
			domain.UnscanReasonNoGoMod, buf.String())
	}
	if !strings.Contains(buf.String(), "synthesised one for the scan") {
		t.Errorf("expected the shared synthesis to run for the target-rooted path, got:\n%s", buf.String())
	}
}
