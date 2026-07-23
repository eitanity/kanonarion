package govulncheck

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// ScanProject runs a single project-rooted govulncheck over the project's live
// working tree — the same live analysis reachability --local performs — reading
// its real import graph from its real entry points at the versions the project's
// own build resolves. Unlike Scan, which scans one module in isolation as its
// own main module and keeps only that module's findings, ScanProject keeps every
// reachable finding and returns them grouped by the module that owns the
// vulnerable symbol, so the caller derives a per-module verdict for the whole
// build from one analysis the project actually produces. No dependency is
// re-resolved alone, so a version-not-in-toolchain gap cannot arise on this path.
//
// The scan is deliberately not run against the pinned blob-store module cache:
// the working tree is a real, buildable project, so its own go.mod/go.sum and
// the host toolchain resolve exactly the versions MVS selected. It is live and
// uncached — the working tree mutates between runs, so the verdict is recomputed
// fresh, never stored coordinate-globally.
//
// A genuine fault — no go.mod, an OOM kill, a build that does not compile —
// yields a StatusUnscannable/StatusScanFailed result with the diagnostic, never
// a false clean. The error return is reserved for infrastructure failures
// (missing govulncheck) that abort the whole scan.
func (s *Scanner) ScanProject(
	ctx context.Context,
	projectDir string,
	snapshot domain.DatabaseSnapshot,
	dbDir string,
) (domain.ProjectScanResult, error) {
	s.logMem(ctx, "project_scan_start")
	s.logger.Info("vuln-scan: project-rooted scan starting", "dir", projectDir)

	if _, err := os.Stat(projectDir); err != nil {
		return domain.ProjectScanResult{
			Status:            domain.StatusUnscannable,
			UnscanReason:      domain.UnscanReasonProjectDirUnavailable,
			UnscannableReason: "project directory not accessible: " + err.Error(),
		}, nil
	}
	if _, err := os.Stat(projectDir + "/go.mod"); err != nil {
		return domain.ProjectScanResult{
			Status:            domain.StatusUnscannable,
			UnscanReason:      domain.UnscanReasonProjectNoGoMod,
			UnscannableReason: "no go.mod in the project directory",
		}, nil
	}

	dbArg, dbCleanup := s.prepareDBArg(ctx, snapshot, dbDir)
	defer dbCleanup()

	govulncheckBin, err := lookupGovulncheck()
	if err != nil {
		return domain.ProjectScanResult{}, err
	}

	s.logger.Info("vuln-scan: running project-rooted govulncheck source mode", "dir", projectDir, "db", dbArg)
	cmd := exec.CommandContext(ctx, govulncheckBin, "-json", "-db", dbArg, "./...") // #nosec G204 -- binary path from exec.LookPath
	cmd.Dir = projectDir
	cmd.Env = append(os.Environ(), "GOGC=30")

	stderr := &limitWriter{limit: 2048}
	cmd.Stderr = stderr
	pr, pw := io.Pipe()
	cmd.Stdout = pw

	if err := cmd.Start(); err != nil {
		_ = pw.Close()
		return domain.ProjectScanResult{}, fmt.Errorf("start govulncheck: %w", err)
	}

	var waitErr error
	go func() {
		waitErr = cmd.Wait()
		_ = pw.Close() /* #nosec G104 -- pipe close in goroutine, error not actionable */
	}()

	byModule, perr := s.parseResultsByModule(ctx, pr)
	// Drain before closing so the writer goroutine reaches cmd.Wait() and waitErr
	// is settled: a scan that died mid-stream must be classified as the failure it
	// is, not as the truncated parse it also produced.
	_, _ = io.Copy(io.Discard, pr)
	_ = pr.Close()

	if waitErr != nil {
		stderrStr := stderr.String()
		s.logger.Debug("vuln-scan: project-rooted govulncheck exited with error", "error", waitErr, "stderr", stderrStr)
		status, errorDetail, unscannableReason, unscanReason := classifyScanFailure(waitErr, stderrStr)
		return domain.ProjectScanResult{
			Status:            status,
			UnscanReason:      unscanReason,
			ErrorDetail:       errorDetail,
			UnscannableReason: unscannableReason,
		}, nil
	}

	if perr != nil {
		return domain.ProjectScanResult{}, fmt.Errorf("parse project govulncheck output: %w", perr)
	}

	status := domain.StatusClean
	if len(byModule) > 0 {
		status = domain.StatusAffected
	}
	s.logger.Info("vuln-scan: project-rooted scan finished", "modules_with_findings", len(byModule))
	return domain.ProjectScanResult{
		FindingsByModule: byModule,
		Status:           status,
	}, nil
}
