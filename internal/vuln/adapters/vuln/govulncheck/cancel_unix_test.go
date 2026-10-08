//go:build unix

package govulncheck

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

// stubGovulncheck puts a govulncheck on PATH that runs body, after touching
// started so a test knows the scan child is live.
func stubGovulncheck(t *testing.T, body string) (started string) {
	t.Helper()
	dir := t.TempDir()
	started = filepath.Join(dir, "started")
	writeExecutable(t, filepath.Join(dir, "govulncheck"), "#!/bin/sh\ntouch "+started+"\n"+body+"\n")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return started
}

// cancelOnceStarted cancels once the stub has touched started.
func cancelOnceStarted(t *testing.T, started string) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() {
		for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			if _, err := os.Stat(started); err == nil {
				break
			}
		}
		cancel()
	}()
	return ctx
}

// scanEntryPoints runs each of the three govulncheck entry points against a
// minimal module, under ctx.
func scanEntryPoints(t *testing.T) map[string]func(ctx context.Context, s *Scanner) (domain.VulnerabilityStatus, string, error) {
	t.Helper()
	zipBytes := makeModuleZip(t, map[string]string{
		"example.com/mod@v1.0.0/go.mod": "module example.com/mod\n\ngo 1.21\n",
		"example.com/mod@v1.0.0/m.go":   "package mod\n",
	})
	project := t.TempDir()
	writeFile(t, filepath.Join(project, "go.mod"), "module example.com/proj\n\ngo 1.21\n")
	writeFile(t, filepath.Join(project, "main.go"), "package main\n\nfunc main() {}\n")
	coord := coordinatetest.MustNew("example.com/mod", "v1.0.0")
	return map[string]func(ctx context.Context, s *Scanner) (domain.VulnerabilityStatus, string, error){
		"module": func(ctx context.Context, s *Scanner) (domain.VulnerabilityStatus, string, error) {
			rec, err := s.Scan(ctx, ports.ScanRequest{
				Coordinate: coord, ModuleSource: bytes.NewReader(zipBytes),
				Snapshot: fixtureSnapshot(t), GoModCache: t.TempDir(), ScanMode: domain.ScanModeSource,
			})
			return rec.OverallStatus, rec.UnscannableReason, err //nolint:wrapcheck // the test reads the scanner's own error
		},
		"target": func(ctx context.Context, s *Scanner) (domain.VulnerabilityStatus, string, error) {
			res, err := s.ScanTargetModule(ctx, ports.TargetScanRequest{
				Coordinate: coord, ModuleSource: bytes.NewReader(zipBytes), Snapshot: fixtureSnapshot(t),
			})
			return res.Status, res.UnscannableReason, err //nolint:wrapcheck // as above
		},
		"project": func(ctx context.Context, s *Scanner) (domain.VulnerabilityStatus, string, error) {
			res, err := s.ScanProject(ctx, ports.ProjectScanRequest{ProjectDir: project, Snapshot: fixtureSnapshot(t)})
			return res.Status, res.UnscannableReason, err //nolint:wrapcheck // as above
		},
	}
}

// A govulncheck child the run's cancellation killed returns the cancellation and
// no verdict. Classified, its SIGKILL reads as an out-of-memory Unscannable, and
// the scan would state a coverage gap for a module nothing failed to analyse.
func TestScan_ChildKilledByTheCancellationIsNotUnscannable(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	for name, scan := range scanEntryPoints(t) {
		t.Run(name, func(t *testing.T) {
			started := stubGovulncheck(t, "sleep 30")
			var buf bytes.Buffer
			status, reason, err := scan(cancelOnceStarted(t, started), capturingScanner(t, &buf, slog.LevelWarn))
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("err = %v (status %q, reason %q), want the cancellation", err, status, reason)
			}
			if status != "" {
				t.Errorf("a stopped scan returned a verdict: %s (%s)", status, reason)
			}
			if strings.Contains(buf.String(), "level=WARN") {
				t.Errorf("a stopped scan logged a warning:\n%s", buf.String())
			}
		})
	}
}

// The control: a child killed from outside, with the context live, is still the
// out-of-memory Unscannable it always was.
func TestScan_ChildKilledFromOutsideIsStillUnscannable(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	for name, scan := range scanEntryPoints(t) {
		t.Run(name, func(t *testing.T) {
			stubGovulncheck(t, "kill -9 $$")
			status, reason, err := scan(t.Context(), capturingScanner(t, &bytes.Buffer{}, slog.LevelWarn))
			if err != nil {
				t.Fatalf("an outside kill returned a hard error: %v", err)
			}
			if status != domain.StatusUnscannable || !strings.Contains(reason, "killed") {
				t.Errorf("status = %s (%q), want Unscannable naming the kill", status, reason)
			}
		})
	}
}

// The binary-mode test build is a child too: one the cancellation stopped is not
// a build failure to fall back from.
func TestScan_BinaryBuildStoppedByTheCancellationDoesNotFallBack(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	stubGovulncheck(t, "exit 0")
	zipBytes := makeModuleZip(t, map[string]string{
		"example.com/mod@v1.0.0/go.mod":    "module example.com/mod\n\ngo 1.21\n",
		"example.com/mod@v1.0.0/m.go":      "package mod\n",
		"example.com/mod@v1.0.0/m_test.go": "package mod\n\nimport \"testing\"\n\nfunc TestM(t *testing.T) {}\n",
	})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var buf bytes.Buffer
	_, err := capturingScanner(t, &buf, slog.LevelWarn).Scan(ctx, ports.ScanRequest{
		Coordinate: coordinatetest.MustNew("example.com/mod", "v1.0.0"), ModuleSource: bytes.NewReader(zipBytes),
		Snapshot: fixtureSnapshot(t), GoModCache: t.TempDir(), ScanMode: domain.ScanModeBinary,
	})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want the cancellation", err)
	}
	if strings.Contains(buf.String(), "falling back to source mode") {
		t.Errorf("a build the cancellation stopped was reported as a failed build:\n%s", buf.String())
	}
}

// The dependency download that precedes a source-mode scan is a child too: one
// the cancellation stopped is not a download that failed.
func TestScan_DownloadStoppedByTheCancellationIsNotAFailedDownload(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	stubGovulncheck(t, "exit 0")
	for name, scan := range scanEntryPoints(t) {
		if name == "project" {
			continue // the project surface downloads nothing
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			var buf bytes.Buffer
			_, _, err := scan(ctx, capturingScanner(t, &buf, slog.LevelDebug))
			if !errors.Is(err, context.Canceled) {
				t.Errorf("err = %v, want the cancellation", err)
			}
			if strings.Contains(buf.String(), "go mod download failed") {
				t.Errorf("a download the cancellation stopped was logged as failed:\n%s", buf.String())
			}
		})
	}
}
