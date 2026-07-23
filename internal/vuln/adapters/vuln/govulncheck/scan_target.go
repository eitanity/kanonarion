package govulncheck

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

// ScanTargetModule runs one grouped, target-rooted scan for a walk whose root is
// a published module rather than a local project, and returns every finding the
// analysis reports grouped by the module that owns the vulnerable symbol.
//
// The walk target is extracted and analysed as the main module — which it is,
// being the root of the walk — and every dependency is reached the way the
// target's own build reaches it. That is the point of this path. Loading is
// import-driven: it starts at the packages the pattern matches and follows
// imports, so a dependency contributes exactly the packages the target reaches
// and nothing else. Scanning each dependency in isolation instead points
// `./...` at the dependency, which matches every package in it — commands,
// examples and internal tooling no consumer can import — and each of those drags
// in imports demanding module versions the target's build never selected. A
// module was then recorded as a coverage gap because a package the target never
// builds could not be loaded, which is not a real gap: supplying the missing
// versions would mean analysing code the build never links.
//
// The target itself is the main module here, and a main module has no version,
// so this analysis cannot match an advisory about the target by version range.
// That is not a hole in this path: the caller matches every coordinate's
// advisory set from the pinned database unconditionally and merges it with what
// the analysis attributed, so the target is covered by the same coordinate match
// as every other module and the analysis contributes reachability to it.
//
// A genuine fault — a target that does not build, an OOM kill — is carried in
// the result's Status so the caller can fall back rather than record a false
// clean across the whole walk. The error return is reserved for infrastructure
// failures (missing govulncheck) that abort the scan.
func (s *Scanner) ScanTargetModule(ctx context.Context, req ports.TargetScanRequest) (domain.ProjectScanResult, error) {
	coord := req.Coordinate
	s.logMem(ctx, "target_scan_start")
	s.logger.Info("vuln-scan: target-rooted scan starting", "module", coord.Path, "version", coord.Version)

	tmpDir, err := os.MkdirTemp("", "kanonarion-vuln-target-*")
	if err != nil {
		return domain.ProjectScanResult{}, fmt.Errorf("create temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	env := scanEnv(os.Environ(), req.GoModCache)

	scanDir, fault, err := s.prepareScanDir(ctx, tmpDir, coord, req.ModuleSource, env, req.BuildList)
	if err != nil {
		return domain.ProjectScanResult{}, err
	}
	if fault != nil {
		return domain.ProjectScanResult{
			Status:            domain.StatusUnscannable,
			UnscanReason:      fault.unscanReason,
			UnscannableReason: fault.reason,
		}, nil
	}

	dbArg, dbCleanup := s.prepareDBArg(ctx, req.Snapshot, req.DBDir)
	defer dbCleanup()

	govulncheckBin, err := lookupGovulncheck()
	if err != nil {
		return domain.ProjectScanResult{}, err
	}

	// The walk already fetched every module the target's build selects into the
	// shared GOMODCACHE, so this resolves offline. A download failure is not
	// fatal on its own — the packages may still load — so it is reported by the
	// scan's own exit status rather than pre-empted here.
	s.logger.Info("vuln-scan: downloading target dependencies", "dir", scanDir)
	dlCmd := exec.CommandContext(ctx, "go", "mod", "download")
	dlCmd.Dir = scanDir
	dlCmd.Env = env
	if out, dlErr := dlCmd.CombinedOutput(); dlErr != nil {
		s.logger.Debug("vuln-scan: go mod download failed for target", "error", dlErr, "output", string(out))
	}
	s.logMem(ctx, "target_deps_downloaded")

	s.logger.Info("vuln-scan: running target-rooted govulncheck source mode", "dir", scanDir, "db", dbArg)
	cmd := exec.CommandContext(ctx, govulncheckBin, "-json", "-db", dbArg, "./...") // #nosec G204 -- binary path from exec.LookPath
	cmd.Dir = scanDir
	cmd.Env = env

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
	s.logMem(ctx, "target_output_parsed")

	if waitErr != nil {
		stderrStr := stderr.String()
		s.logger.Debug("vuln-scan: target-rooted govulncheck exited with error", "error", waitErr, "stderr", stderrStr)
		status, errorDetail, unscannableReason, unscanReason := classifyScanFailure(waitErr, stderrStr)
		return domain.ProjectScanResult{
			Status:            status,
			UnscanReason:      unscanReason,
			ErrorDetail:       errorDetail,
			UnscannableReason: unscannableReason,
		}, nil
	}
	if perr != nil {
		return domain.ProjectScanResult{}, fmt.Errorf("parse target govulncheck output for %s@%s: %w", coord.Path, coord.Version, perr)
	}

	runtime.GC()
	s.logMem(ctx, "target_post_parse_gc")

	status := domain.StatusClean
	if len(byModule) > 0 {
		status = domain.StatusAffected
	}
	s.logger.Info("vuln-scan: target-rooted scan finished", "modules_with_findings", len(byModule))
	return domain.ProjectScanResult{
		FindingsByModule: byModule,
		Status:           status,
	}, nil
}
