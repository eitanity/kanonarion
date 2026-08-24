package govulncheck

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/eitanity/kanonarion/internal/adapters/childproc"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/gotoolchain"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

// projectScanStatus renders the scan-level summary word for a grouped
// (project- or target-rooted) parse.
//
// It reads the findings rather than counting the modules that carry them: a build
// whose only matches name retracted advisories has found nothing that stands, and
// the count cannot tell that apart from a real finding. Both grouped entry points
// share this so the two cannot disagree about the same finding set.
func projectScanStatus(byModule map[coordinate.ModuleCoordinate][]domain.VulnerabilityFinding) domain.VulnerabilityStatus {
	all := make([]domain.VulnerabilityFinding, 0, len(byModule))
	for _, findings := range byModule {
		all = append(all, findings...)
	}
	return domain.DetermineRecordOverallStatus(
		domain.CoverageAnalysed, domain.DetermineFindingsAxis(all),
	)
}

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
//
// For a project that carries vendor/modules.txt, the vendored tree — not the
// module cache — is what the project compiles, so it is what the scan measures.
// The whole build is analysed from vendor/ in one pass under -mod=vendor: no
// module is resolved on its own, so a dependency shipping no go.mod (every
// pre-modules dependency does) needs no synthesised one, and MVS is not re-run,
// so no version can be out of the toolchain. The surface that actually ran is
// reported on the result rather than assumed by the caller: the caller asks,
// the project on disk decides, and the verdict names which bytes were measured.
func (s *Scanner) ScanProject(ctx context.Context, req ports.ProjectScanRequest) (res domain.ProjectScanResult, err error) {
	projectDir := req.ProjectDir
	s.logMem(ctx, "project_scan_start")
	s.logger.Info("vuln-scan: project-rooted scan starting", "dir", projectDir)

	if _, err := os.Stat(projectDir); err != nil {
		return domain.ProjectScanResult{
			Status:            domain.StatusUnscannable,
			UnscanReason:      domain.UnscanReasonProjectDirUnavailable,
			UnscannableReason: "project directory not accessible: " + err.Error(),
		}, nil
	}
	if _, err := os.Stat(filepath.Join(projectDir, "go.mod")); err != nil {
		return domain.ProjectScanResult{
			Status:            domain.StatusUnscannable,
			UnscanReason:      domain.UnscanReasonProjectNoGoMod,
			UnscannableReason: "no go.mod in the project directory",
		}, nil
	}

	surface, env := projectScanSurface(projectDir, req.Vendored)

	// Stamped on every result this scan returns, faults included: a project's
	// reachable set is the toolchain's, and it is resolved from the project
	// directory, so it is asked there rather than wherever this process runs.
	toolchain := gotoolchain.Version(toolchainGoVersion(ctx, projectDir, env))
	defer func() { res.Toolchain = toolchain }()

	dbArg, advisories, dbCleanup, err := s.prepareDBArg(ctx, req.Snapshot, req.DBDir)
	if err != nil {
		return domain.ProjectScanResult{}, err
	}
	defer dbCleanup()

	govulncheckBin, err := lookupGovulncheck()
	if err != nil {
		return domain.ProjectScanResult{}, err
	}

	s.logger.Info("vuln-scan: running project-rooted govulncheck source mode",
		"dir", projectDir, "db", dbArg, "analysis_surface", string(surface))
	cmd := childproc.CommandContext(ctx, govulncheckBin, "-json", "-db", dbArg, "./...") // #nosec G204 -- binary path from exec.LookPath
	cmd.Dir = projectDir
	cmd.Env = env

	stderr := &limitWriter{limit: 2048}
	cmd.Stderr = stderr
	pr, pw := io.Pipe()
	cmd.Stdout = pw

	if err := cmd.Start(); err != nil {
		_ = pw.Close()
		return domain.ProjectScanResult{}, fmt.Errorf("start govulncheck: %w", err)
	}

	waitErrCh := make(chan error, 1)
	go func() {
		waitErrCh <- cmd.Wait()
		_ = pw.Close() /* #nosec G104 -- pipe close in goroutine, error not actionable */
	}()

	byModule, perr := s.parseResultsByModule(ctx, pr, domain.ScanModeSource)
	// Drain before closing so the writer goroutine reaches cmd.Wait() and waitErr
	// is settled: a scan that died mid-stream must be classified as the failure it
	// is, not as the truncated parse it also produced. The channel receive is the
	// synchronisation edge that publishes the goroutine's write to this goroutine.
	_, _ = io.Copy(io.Discard, pr)
	_ = pr.Close()
	waitErr := <-waitErrCh

	if waitErr != nil {
		stderrStr := stderr.String()
		s.logger.Debug("vuln-scan: project-rooted govulncheck exited with error", "error", waitErr, "stderr", stderrStr)
		status, errorDetail, unscannableReason, unscanReason := classifyScanFailure(waitErr, stderrStr)
		return domain.ProjectScanResult{
			Status:            status,
			UnscanReason:      unscanReason,
			ErrorDetail:       errorDetail,
			UnscannableReason: unscannableReason,
			// A failure is still a failure of a named surface. Which one it was is
			// the first thing a reader needs — a build break under -mod=vendor says
			// the vendored tree does not compile, which is a different fact from the
			// same break under a fetched resolution.
			AnalysisSurface: surface,
			AdvisoryCount:   advisories,
		}, nil
	}

	if perr != nil {
		return domain.ProjectScanResult{}, fmt.Errorf("parse project govulncheck output: %w", perr)
	}

	status := projectScanStatus(byModule)
	s.logger.Info("vuln-scan: project-rooted scan finished",
		"modules_with_findings", len(byModule), "analysis_surface", string(surface))
	return domain.ProjectScanResult{
		FindingsByModule: byModule,
		Status:           status,
		AnalysisSurface:  surface,
		AdvisoryCount:    advisories,
	}, nil
}

// projectScanSurface decides which copy of the source a project scan resolves
// from, and returns the process environment that makes that decision real.
//
// The decision needs both the caller's request and the tree on disk. A caller
// asking for a vendored analysis of a project that has no vendor/modules.txt
// gets the fetched surface, because that is the only one that exists — the
// returned surface is what ran, never what was wanted.
//
// The other direction is the one that is easy to get wrong. A caller declining
// the vendored surface for a project that HAS one cannot simply leave the
// toolchain alone: Go defaults to -mod=vendor whenever vendor/modules.txt is
// present, so an unforced run would silently be the vendored analysis under a
// fetched label. -mod=mod is forced explicitly there, which is what makes a
// deliberate comparison run against the fetched artefacts a real comparison.
//
// Every branch takes its environment from scanEnv. Workspace mode rejects
// -mod=mod outright, so a branch that forces the flag from os.Environ() exits 1
// instead of comparing anything the moment a go.work is in scope.
func projectScanSurface(projectDir string, wantVendored bool) (domain.AnalysisSurface, []string) {
	_, err := os.Stat(filepath.Join(projectDir, "vendor", "modules.txt"))
	hasVendorTree := err == nil

	switch {
	case hasVendorTree && wantVendored:
		return domain.AnalysisSurfaceVendored, scanEnv(os.Environ(), "", domain.AnalysisSurfaceVendored)
	case hasVendorTree:
		return domain.AnalysisSurfaceFetched,
			append(scanEnv(os.Environ(), "", domain.AnalysisSurfaceFetched), "GOFLAGS=-mod=mod")
	default:
		// No vendor tree: the toolchain's own default resolution against the
		// project's go.mod/go.sum is the fetched surface, and forcing a mode flag
		// would only override whatever the project itself declares.
		return domain.AnalysisSurfaceFetched, scanEnv(os.Environ(), "", domain.AnalysisSurfaceFetched)
	}
}
