package govulncheck

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// Scan performs a vulnerability scan on a module.
func (s *Scanner) Scan(
	ctx context.Context,
	coord coordinate.ModuleCoordinate,
	moduleSource io.Reader,
	snapshot domain.DatabaseSnapshot,
	goModCache string,
	dbDir string, // pre-extracted vuln DB dir; empty = extract from store on each call
	scanMode domain.ScanMode, // source or binary; empty defaults to source
) (domain.VulnerabilityRecord, error) {
	s.logMem(ctx, "start")
	// 1. Prepare temporary directory
	tmpDir, err := os.MkdirTemp("", "kanonarion-vuln-scan-*")
	if err != nil {
		return domain.VulnerabilityRecord{}, fmt.Errorf("create temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	s.logger.Info("vuln-scan: starting", "module", coord.Path, "version", coord.Version)

	// 2. Extract module source (zip) to temp directory
	s.logger.Info("vuln-scan: extracting module zip", "module", coord.Path)
	if err := s.extractZip(ctx, moduleSource, tmpDir); err != nil {
		return domain.VulnerabilityRecord{}, fmt.Errorf("extract module: %w", err)
	}
	s.logMem(ctx, "module_extracted")

	// 2.5 Find where go.mod is. mirror-fetch zips typically have a prefix like "github.com/gin-gonic/gin@v1.6.2/"
	scanDir, foundGoMod := locateGoMod(tmpDir)

	if !foundGoMod {
		s.logger.Warn("vuln-scan: go.mod not found, marking unscannable", "module", coord.Path)
		// If go.mod is not found, we can't run govulncheck.
		// We return StatusUnscannable instead of an error to indicate it's not a failure of the scanner itself.
		return domain.VulnerabilityRecord{
			Coordinate:        coord,
			Findings:          nil,
			OverallStatus:     domain.StatusUnscannable,
			UnscanReason:      domain.UnscanReasonNoGoMod,
			UnscannableReason: "no go.mod found in module zip",
			DatabaseSnapshot:  snapshot,
			ScannedAt:         time.Now(),
			PipelineVersion:   s.pipelineVersion,
		}, nil
	}

	// 2.6 Neutralise the module's own filesystem replace directives. A module is
	// scanned in isolation as its own main module, so govulncheck honours them;
	// a multi-module member's dev-time `replace ... => ../` points outside the
	// published zip and would fail the build. Dropping them matches a consumer's
	// view, where a dependency's replaces are ignored and siblings resolve from
	// GOMODCACHE.
	if changed, nerr := neutraliseLocalReplaces(filepath.Join(scanDir, "go.mod")); nerr != nil {
		s.logger.Warn("vuln-scan: failed to neutralise local replaces", "module", coord.Path, "error", nerr)
	} else if changed {
		s.logger.Info("vuln-scan: dropped filesystem replace directives for isolated scan", "module", coord.Path)
	}

	// 3. Prepare vulnerability database argument.
	dbArg, dbCleanup := s.prepareDBArg(ctx, snapshot, dbDir)
	defer dbCleanup()

	govulncheckBin, err := lookupGovulncheck()
	if err != nil {
		return domain.VulnerabilityRecord{}, err
	}

	env := scanEnv(os.Environ(), goModCache)

	// 4. Mode dispatch: binary mode builds a test binary first for a fast symbol-table
	// scan; source mode does the full SSA + call-graph analysis.
	var cmd *exec.Cmd
	if scanMode == domain.ScanModeBinary {
		pkg := findFirstGoPackage(scanDir)
		s.logger.Info("vuln-scan: binary mode — building test binary", "dir", scanDir, "pkg", pkg)
		tmpBin := filepath.Join(tmpDir, "vuln-test.bin")
		buildCmd := exec.CommandContext(ctx, "go", "test", "-c", "-o", tmpBin, pkg) // #nosec G204 -- pkg derived from local filesystem walk
		buildCmd.Dir = scanDir
		buildCmd.Env = env
		out, buildErr := buildCmd.CombinedOutput()
		_, statErr := os.Stat(tmpBin)
		switch {
		case buildErr != nil:
			s.logger.Warn("vuln-scan: binary build failed, falling back to source mode",
				"error", buildErr, "output", string(out))
			scanMode = domain.ScanModeSource
		case statErr != nil:
			// go test -c exits 0 without creating a binary when there are no test files.
			s.logger.Warn("vuln-scan: test binary not created (no test files?), falling back to source mode",
				"pkg", pkg, "output", string(out))
			scanMode = domain.ScanModeSource
		default:
			s.logger.Info("vuln-scan: test binary built, running govulncheck -mode=binary", "binary", tmpBin)
			cmd = exec.CommandContext(ctx, govulncheckBin, "-json", "-db", dbArg, "-mode=binary", tmpBin) // #nosec G204 -- binary path from exec.LookPath
			s.logMem(ctx, "binary_built")
		}
	}
	if scanMode != domain.ScanModeBinary {
		// Source mode: download deps then run govulncheck source analysis.
		s.logger.Info("vuln-scan: downloading dependencies", "dir", scanDir)
		dlCmd := exec.Command("go", "mod", "download")
		dlCmd.Dir = scanDir
		dlCmd.Env = env
		if out, dlErr := dlCmd.CombinedOutput(); dlErr != nil {
			// Source mode continues regardless: a download failure often just means
			// the module's isolated build needs a version outside the project's
			// pinned cache — an expected out-of-toolchain outcome the application
			// classifies from the returned error. Severity for that error is owned
			// by the application layer, so this precursor stays at debug (the full
			// output is available at --log-level debug) rather than a misleading warn.
			s.logger.Debug("vuln-scan: go mod download failed", "error", dlErr, "output", string(out))
		} else {
			s.logger.Debug("vuln-scan: go mod download succeeded", "output", string(out))
		}
		s.logMem(ctx, "deps_downloaded")
		s.logger.Info("vuln-scan: running govulncheck source mode", "dir", scanDir, "db", dbArg)
		cmd = exec.CommandContext(ctx, govulncheckBin, "-json", "-db", dbArg, "./...") // #nosec G204 -- binary path from exec.LookPath
		cmd.Dir = scanDir
	}
	cmd.Env = env

	// 5. Stream govulncheck JSON output and parse results.
	stderr := &limitWriter{limit: 2048}
	cmd.Stderr = stderr
	pr, pw := io.Pipe()
	cmd.Stdout = pw

	if err := cmd.Start(); err != nil {
		_ = pw.Close()
		return domain.VulnerabilityRecord{}, fmt.Errorf("start govulncheck: %w", err)
	}

	var waitErr error
	go func() {
		waitErr = cmd.Wait()
		_ = pw.Close() /* #nosec G104 -- pipe close in goroutine, error not actionable */
	}()

	s.logger.Info("vuln-scan: parsing govulncheck output")
	findings, err := s.parseResults(ctx, pr, coord.Path)
	if err != nil {
		_ = pr.Close()
		return domain.VulnerabilityRecord{}, fmt.Errorf("parse govulncheck output for %s@%s: %w", coord.Path, coord.Version, err)
	}
	_ = pr.Close()
	s.logMem(ctx, "output_parsed")
	if waitErr != nil {
		stderrStr := stderr.String()
		// This error is handed back to the application to classify: an
		// out-of-toolchain module reads as an expected metadata-only outcome
		// (logged at info by reason), a genuine crash as a warn — both from the
		// application layer that owns severity. Logging it at warn here would dump
		// govulncheck's stderr for every expected out-of-toolchain module,
		// contradicting that classification. The stderr stays available at debug.
		s.logger.Debug("vuln-scan: govulncheck exited with error", "error", waitErr, "stderr", stderrStr)
		status, errorDetail, unscannableReason, unscanReason := classifyScanFailure(waitErr, stderrStr)
		return domain.VulnerabilityRecord{
			Coordinate:        coord,
			Findings:          nil,
			OverallStatus:     status,
			UnscanReason:      unscanReason,
			ErrorDetail:       errorDetail,
			UnscannableReason: unscannableReason,
			DatabaseSnapshot:  snapshot,
			ScannedAt:         time.Now(),
			PipelineVersion:   s.pipelineVersion,
		}, nil
	}
	s.logger.Info("vuln-scan: govulncheck finished", "findings", len(findings))

	// Aggressive cleanup after parsing
	runtime.GC()
	s.logMem(ctx, "post_parse_gc")

	status := domain.StatusClean
	if len(findings) > 0 {
		status = domain.StatusAffected
	}

	return domain.VulnerabilityRecord{
		Coordinate:       coord,
		Findings:         findings,
		OverallStatus:    status,
		DatabaseSnapshot: snapshot,
		ScannedAt:        time.Now(),
		PipelineVersion:  s.pipelineVersion,
	}, nil
}

// locateGoMod finds the directory containing the first go.mod under root.
// mirror-fetch zips carry a module@version/ prefix, so the go.mod is rarely at
// the extract root.
func locateGoMod(root string) (string, bool) {
	scanDir := root
	found := false
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && info.Name() == "go.mod" {
			scanDir = filepath.Dir(path)
			found = true
			return filepath.SkipDir
		}
		return nil
	})
	return scanDir, found
}

// prepareDBArg resolves the govulncheck -db argument for a snapshot. It prefers
// the pre-extracted dir shared across a walk's scans, falls back to extracting
// the snapshot from the store into a temp dir, and finally to the live database.
// The returned cleanup removes any temp dir it created (a no-op otherwise) and
// must be deferred by the caller.
func (s *Scanner) prepareDBArg(ctx context.Context, snapshot domain.DatabaseSnapshot, dbDir string) (string, func()) {
	noop := func() {}
	s.logger.Info("vuln-scan: preparing vulnerability database", "snapshot", snapshot.Version)
	if dbDir != "" {
		s.logger.Info("vuln-scan: using pre-extracted local database", "path", dbDir)
		return "file://" + dbDir, noop
	}
	if s.vulnStore == nil {
		return "https://vuln.go.dev", noop
	}
	snapshotContent, err := s.vulnStore.GetDatabaseSnapshot(ctx, snapshot)
	if err != nil {
		s.logger.Warn("vuln-scan: failed to retrieve snapshot, falling back to live DB", "error", err)
		return "https://vuln.go.dev", noop
	}
	defer func() {
		if cerr := snapshotContent.Close(); cerr != nil {
			s.logger.Warn("vuln-scan: failed to close snapshot content", "error", cerr)
		}
	}()
	extractedDir, err := os.MkdirTemp("", "kanonarion-vulndb-*")
	if err != nil {
		s.logger.Warn("vuln-scan: failed to create temp dir for snapshot, falling back to live DB", "error", err)
		return "https://vuln.go.dev", noop
	}
	if err := s.extractZip(ctx, snapshotContent, extractedDir); err != nil {
		s.logger.Warn("vuln-scan: failed to extract snapshot, falling back to live DB", "error", err)
		_ = os.RemoveAll(extractedDir)
		return "https://vuln.go.dev", noop
	}
	s.logger.Info("vuln-scan: using pinned local database", "path", extractedDir)
	s.logMem(ctx, "db_extracted")
	return "file://" + extractedDir, func() { _ = os.RemoveAll(extractedDir) }
}

// scanEnv builds the process environment for the Go toolchain and govulncheck.
//
// When a pre-populated GOMODCACHE is supplied, three overrides let the toolchain
// resolve a multi-module member's siblings from the cache. A member's published
// go.sum omits the sibling entries that were satisfied by a dev-time local
// `replace ... => ../` at publish time (local replaces carry no checksum). Once
// that replace is neutralised for an isolated scan the sibling resolves from the
// cache, and the toolchain — running read-only by default — errors on the
// missing go.sum entry instead of computing it. -mod=mod lets it compute and
// write those entries into the disposable extract dir's go.sum from the cached
// zips; GOSUMDB=off skips the checksum database, which is unreachable offline
// and redundant once the cache — already fetch-verified upstream — is trusted.
//
// GOPROXY=off pins resolution to the cache with no network fallback. This is a
// fidelity choice, not just an optimisation: the cache is the project's verified
// toolchain — the exact module versions its build list resolved and that were
// fetch-verified into the store. A network fallback would let a module scanned
// in isolation re-run MVS as its own main module and pull in a dependency
// version the project never builds (a lower version this module alone selects),
// analysing a dependency graph that does not represent the toolchain. Pinning
// off keeps the analysis faithful: the cache holds the selected zips plus the
// go.mod of the superseded intermediate versions a pre-pruning (go<1.17)
// dependency makes -mod=mod read for module-graph bookkeeping (e.g. a stdr@vX
// requirement on logr@vY when the walk selected a higher logr), so an
// in-toolchain scan resolves fully offline. A module whose isolated build needs
// an out-of-toolchain version fails here deliberately — surfaced as an honest
// Unscannable (version-not-in-toolchain), never papered over with a network
// fetch. Without a modcache the default (network-backed) resolution is untouched.
//
// Duplicate keys are appended rather than replaced because exec.Cmd honours the
// last value for a repeated key, so these overrides win over any inherited
// GOFLAGS/GOSUMDB/GOPROXY.
func scanEnv(base []string, goModCache string) []string {
	// Copy rather than append onto base so a caller's slice is never mutated.
	env := make([]string, len(base), len(base)+5)
	copy(env, base)
	env = append(env, "GOGC=30")
	if goModCache != "" {
		env = append(env,
			"GOMODCACHE="+goModCache,
			"GOFLAGS=-mod=mod",
			"GOSUMDB=off",
			"GOPROXY=off",
		)
	}
	return env
}

// classifyScanFailure maps a govulncheck non-zero exit to a status and the
// matching diagnostic field. OOM-style kills (SIGKILL / exit 137) are
// Unscannable — resource-bound and retryable; any other non-zero exit is a
// ScanFailed. The human-readable reason is returned in the field the query and
// presentation layers read for that status — ErrorDetail for ScanFailed,
// UnscannableReason for Unscannable — so a failed scan never surfaces as an
// "unknown reason".
func classifyScanFailure(waitErr error, stderr string) (status domain.VulnerabilityStatus, errorDetail, unscannableReason string, unscanReason domain.UnscanReason) {
	errStr := strings.ToLower(waitErr.Error())
	if strings.Contains(errStr, "killed") || strings.Contains(errStr, "exit status 137") {
		return domain.StatusUnscannable, "", "govulncheck was killed (likely OOM)", domain.UnscanReasonOOMKilled
	}
	reason := "govulncheck exited with error: " + waitErr.Error()
	if stderr != "" {
		reason += "; stderr: " + stderr
	}
	return domain.StatusScanFailed, reason, "", ""
}
