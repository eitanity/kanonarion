package govulncheck

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/childproc"
	"github.com/eitanity/kanonarion/internal/adapters/goenv"
	"github.com/eitanity/kanonarion/internal/adapters/vulndbdir"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/gotoolchain"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

// Scan performs a vulnerability scan on a module.
func (s *Scanner) Scan(ctx context.Context, req ports.ScanRequest) (rec domain.VulnerabilityRecord, err error) {
	coord, moduleSource, snapshot := req.Coordinate, req.ModuleSource, req.Snapshot
	goModCache, dbDir, scanMode := req.GoModCache, req.DBDir, req.ScanMode
	s.logMem(ctx, "start")
	// 1. Prepare temporary directory
	tmpDir, err := os.MkdirTemp("", "kanonarion-vuln-scan-*")
	if err != nil {
		return domain.VulnerabilityRecord{}, fmt.Errorf("create temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	s.logger.Info("vuln-scan: starting", "module", coord.Path(), "version", coord.Version())

	// An isolated scan extracts a published zip into a scratch directory: there
	// is no working tree and therefore no vendor/ tree to root at, so this path
	// is fetched-surface by construction.
	env := scanEnv(os.Environ(), goModCache, domain.AnalysisSurfaceFetched)

	// The environment above pins the toolchain so no scan child can download one,
	// which also refuses a toolchain already unpacked on this host. One decision
	// covers every child of this scan; see runGovulncheck.
	toolchains := goenv.NewToolchains()
	defer func() {
		if cerr := toolchains.Close(); cerr != nil {
			s.logger.Warn("vuln-scan: failed to remove the staged toolchain directory", "error", cerr)
		}
	}()

	// Which toolchain compiled the module is stamped on EVERY record this scan
	// returns, faults included, because the reachable set is the toolchain's and a
	// verdict that cannot say which one produced it cannot be told apart from one
	// written before the field existed. It is asked in the directory the scan will
	// run in, under the scan's own environment, so it names the toolchain that
	// will run rather than the one this process was compiled by.
	toolchainVersion := toolchainGoVersion(ctx, tmpDir, env)
	defer func() { rec.Toolchain = gotoolchain.Version(toolchainVersion) }()

	scanDir, fault, err := s.prepareScanDir(ctx, tmpDir, coord, moduleSource, env, req.BuildList)
	if err != nil {
		return domain.VulnerabilityRecord{}, err
	}
	if fault != nil {
		return domain.VulnerabilityRecord{
			Coordinate:        coord,
			Findings:          nil,
			OverallStatus:     domain.StatusUnscannable,
			UnscanReason:      fault.unscanReason,
			UnscannableReason: fault.reason,
			DatabaseSnapshot:  snapshot,
			ScannedAt:         time.Now(),
			PipelineVersion:   s.pipelineVersion,
		}, nil
	}

	// 2. Prepare vulnerability database argument.
	dbArg, advisories, dbCleanup, err := s.prepareDBArg(ctx, snapshot, dbDir)
	if err != nil {
		return domain.VulnerabilityRecord{}, err
	}
	defer dbCleanup()

	// When this scan extracted its own database it also counted it, and the count
	// belongs on the snapshot every record below names — otherwise a verdict
	// reached against a database of four thousand advisories is indistinguishable
	// from one reached against three, and from a record written before the count
	// existed at all. The fault record above is deliberately outside this: it was
	// sealed before any database was prepared, so there is nothing to state.
	snapshot, err = snapshotCountingAdvisories(snapshot, advisories)
	if err != nil {
		return domain.VulnerabilityRecord{}, err
	}

	govulncheckBin, err := lookupGovulncheck()
	if err != nil {
		return domain.VulnerabilityRecord{}, err
	}

	// 3. Mode dispatch: binary mode builds a test binary first for a fast symbol-table
	// scan; source mode does the full SSA + call-graph analysis.
	var build func(childEnv []string) *exec.Cmd
	if scanMode == domain.ScanModeBinary {
		pkg := findFirstGoPackage(scanDir)
		s.logger.Info("vuln-scan: binary mode — building test binary", "dir", scanDir, "pkg", pkg)
		tmpBin := filepath.Join(tmpDir, "vuln-test.bin")
		out, buildErr := runGoChild(ctx, toolchains, env, scanDir, "test", "-c", "-o", tmpBin, pkg)
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
			build = func(childEnv []string) *exec.Cmd {
				cmd := childproc.CommandContext(ctx, govulncheckBin, "-json", "-db", dbArg, "-mode=binary", tmpBin) // #nosec G204 -- binary path from exec.LookPath
				cmd.Env = childEnv
				return cmd
			}
			s.logMem(ctx, "binary_built")
		}
	}
	if scanMode != domain.ScanModeBinary {
		// Source mode: download deps then run govulncheck source analysis.
		s.logger.Info("vuln-scan: downloading dependencies", "dir", scanDir)
		if out, dlErr := runGoChild(ctx, toolchains, env, scanDir, "mod", "download"); dlErr != nil {
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
		build = func(childEnv []string) *exec.Cmd {
			cmd := childproc.CommandContext(ctx, govulncheckBin, "-json", "-db", dbArg, "./...") // #nosec G204 -- binary path from exec.LookPath
			cmd.Dir = scanDir
			cmd.Env = childEnv
			return cmd
		}
	}

	// 4. Stream govulncheck JSON output and parse results.
	s.logger.Info("vuln-scan: parsing govulncheck output")
	var findings []domain.VulnerabilityFinding
	run, err := runGovulncheck(toolchains, env, build, func(r io.Reader) error {
		var perr error
		findings, perr = s.parseResults(ctx, r, coord.Path(), scanMode)
		return perr
	})
	if err != nil {
		return domain.VulnerabilityRecord{}, err
	}
	// An escalation moved this scan onto a toolchain other than the installed one,
	// so the version the record names is re-asked of the environment its children
	// were actually handed. A verdict naming a Go that did not compile it names a
	// reachable set that was never computed.
	toolchainVersion = ranToolchain(ctx, toolchains, env, scanDir, toolchainVersion)
	s.logMem(ctx, "output_parsed")
	if run.waitErr != nil {
		waitErr, stderrStr := run.waitErr, run.detail
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
	if run.parseErr != nil {
		return domain.VulnerabilityRecord{}, fmt.Errorf("parse govulncheck output for %s@%s: %w", coord.Path(), coord.Version(), run.parseErr)
	}
	s.logger.Info("vuln-scan: govulncheck finished", "findings", len(findings))

	// Aggressive cleanup after parsing
	runtime.GC()
	s.logMem(ctx, "post_parse_gc")

	// The set decides the word, not its length. A stream whose every finding names
	// a retracted advisory has matched nothing that stands, and calling that
	// Affected is the false positive a withdrawal exists to prevent.
	status := domain.DetermineRecordOverallStatus(
		domain.CoverageAnalysed, domain.DetermineFindingsAxis(findings),
	)

	return domain.VulnerabilityRecord{
		Coordinate:       coord,
		Findings:         findings,
		OverallStatus:    status,
		DatabaseSnapshot: snapshot,
		ScannedAt:        time.Now(),
		PipelineVersion:  s.pipelineVersion,
	}, nil
}

// prepareFault is a condition that leaves a module unanalysable before
// govulncheck is ever started, carried as data so each caller can render it in
// the result shape it owns rather than the preparation step deciding.
type prepareFault struct {
	unscanReason domain.UnscanReason
	reason       string
}

// prepareScanDir extracts a module zip into tmpDir and returns the directory
// govulncheck should be pointed at: the module root, with a go.mod present and
// its dev-time filesystem replace directives neutralised.
//
// It is shared by the isolated per-module scan and the target-rooted scan of a
// coordinate-keyed walk. Both extract the same published zip and need the same
// directory preconditions; only what they do with the resulting analysis
// differs, so the preparation is one step and the divergence is downstream.
func (s *Scanner) prepareScanDir(
	ctx context.Context,
	tmpDir string,
	coord coordinate.ModuleCoordinate,
	moduleSource io.Reader,
	env []string,
	buildList map[coordinate.ModuleCoordinate]struct{},
) (string, *prepareFault, error) {
	s.logger.Info("vuln-scan: extracting module zip", "module", coord.Path())
	if err := s.extractZip(ctx, moduleSource, tmpDir); err != nil {
		return "", nil, fmt.Errorf("extract module: %w", err)
	}
	s.logMem(ctx, "module_extracted")

	// mirror-fetch zips typically have a prefix like "github.com/gin-gonic/gin@v1.6.2/"
	scanDir, foundGoMod := locateGoMod(tmpDir)

	if !foundGoMod {
		// A module zip published before Go modules carries no go.mod and never
		// will, but govulncheck's refusal is a precondition on the directory it
		// is pointed at, not on the artefact: it checks for the file before
		// loading any package and its own diagnostic says to create one. Supply
		// it here, in the scratch directory the zip was just extracted into. The
		// zip itself is immutable and checksum-verified; nothing about custody
		// changes, exactly as for the replace directives rewritten below.
		//
		// Abandoning the scan instead would record a coverage gap that is not
		// real: the module is analysable, and treating it as permanently
		// unscannable would leave its advisories matched by coordinate alone,
		// with no reachability, for a condition kanonarion can lift.
		root, skipped, werr := writeSynthesisedGoMod(scanDir, coord, toolchainGoVersion(ctx, scanDir, env), buildList)
		if len(skipped) > 0 {
			// The require set was assembled from less than the whole module. Name
			// the files so a later unresolved-package failure is attributable here
			// rather than appearing as an unexplained resolution error.
			s.logger.Warn("vuln-scan: some source files could not be read while synthesising go.mod; the require set may be incomplete",
				"module", coord.Path(), "skipped_files", strings.Join(skipped, ", "), "skipped_count", len(skipped))
		}
		if werr != nil {
			s.logger.Warn("vuln-scan: could not synthesise go.mod, marking unscannable",
				"module", coord.Path(), "error", werr)
			return "", &prepareFault{
				unscanReason: domain.UnscanReasonNoGoMod,
				reason:       "no go.mod in module zip and none could be synthesised: " + werr.Error(),
			}, nil
		}
		scanDir = root
		s.logger.Info("vuln-scan: no go.mod in module zip, synthesised one for the scan",
			"module", coord.Path(), "dir", scanDir)
	}

	// Neutralise the module's own filesystem replace directives. The module is
	// the main module of this scan, so govulncheck honours them; a multi-module
	// member's dev-time `replace ... => ../` points outside the published zip and
	// would fail the build. Dropping them matches a consumer's view, where a
	// dependency's replaces are ignored and siblings resolve from GOMODCACHE.
	if changed, nerr := neutraliseLocalReplaces(filepath.Join(scanDir, "go.mod")); nerr != nil {
		s.logger.Warn("vuln-scan: failed to neutralise local replaces", "module", coord.Path(), "error", nerr)
	} else if changed {
		s.logger.Info("vuln-scan: dropped filesystem replace directives for the scan", "module", coord.Path())
	}
	return scanDir, nil, nil
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
// the pre-extracted dir shared across a walk's scans and otherwise extracts the
// snapshot from the store into a temp dir. The returned cleanup removes any temp
// dir it created (a no-op otherwise) and must be deferred by the caller.
//
// EVERY OUTCOME IS THE PINNED SNAPSHOT OR A REFUSAL. There is no live-database
// fallback, because the live database is a DIFFERENT advisory set from the one
// the record about to be written names: answering from it produces findings that
// cite a snapshot whose bytes were never consulted, and the coordinate-match
// route beside it then treats the analyser's silence about advisories it was
// never given as a reachability answer. That fallback was reached on a snapshot
// the store would not produce, on a scratch directory that could not be created,
// and on an archive that would not extract — each announced by a log warning
// while the record went on naming the snapshot. A log line is not a record
// annotation, so the three are refusals now, on the terms a snapshot integrity
// failure was already refused on.
//
// A pre-extracted directory is checked against the snapshot rather than trusted.
// It is the one input here that arrives already opened by someone else, and the
// guarantee this whole seam exists to give — the analysis and the record name
// one database — would rest on nothing if a directory extracted from another
// generation could be handed straight to govulncheck.
//
// A snapshot that extracts to a database holding no advisories is fatal for a
// related reason: govulncheck clears every module against it at exit 0, so the
// scan would seal a Clean verdict that consulted nothing. This is enforced here
// as well as at the walk's shared pre-extraction because the two paths reach a
// database independently, and a decision enforced at only one of them is
// enforced only while the other stays unused.
//
// The advisory count this path measures is returned to the caller, which carries
// it onto the snapshot the record names. It is a positive number only when this
// function extracted and counted a database itself; the pre-extracted dir was
// already counted by the walk that supplied it, and the live-database fallback
// is a set nothing here has read, so both report zero — unmeasured, which is
// what the snapshot's own invariant admits.
func (s *Scanner) prepareDBArg(ctx context.Context, snapshot domain.DatabaseSnapshot, dbDir string) (string, int, func(), error) {
	noop := func() {}
	s.logger.Info("vuln-scan: preparing vulnerability database", "snapshot", snapshot.Version())
	if dbDir != "" {
		if err := verifyExtractedGeneration(dbDir, snapshot); err != nil {
			return "", 0, noop, fmt.Errorf("preparing the advisory database: %w", err)
		}
		s.logger.Info("vuln-scan: using pre-extracted local database", "path", dbDir)
		return "file://" + dbDir, 0, noop, nil
	}
	if s.vulnStore == nil {
		return "", 0, noop, fmt.Errorf("preparing the advisory database: %w",
			ports.UnavailableSnapshotAbort(snapshot, "this scanner was built with no vulnerability store to read", errNoVulnStore))
	}
	snapshotContent, err := s.vulnStore.GetDatabaseSnapshot(ctx, snapshot)
	if err != nil {
		if errors.Is(err, ports.ErrSnapshotIntegrity) {
			return "", 0, noop, fmt.Errorf("preparing the advisory database: %w", ports.SnapshotIntegrityAbort(snapshot, err))
		}
		return "", 0, noop, fmt.Errorf("preparing the advisory database: %w",
			ports.UnavailableSnapshotAbort(snapshot, "the store would not produce the snapshot", err))
	}
	defer func() {
		if cerr := snapshotContent.Close(); cerr != nil {
			s.logger.Warn("vuln-scan: failed to close snapshot content", "error", cerr)
		}
	}()
	extractedDir, err := os.MkdirTemp("", "kanonarion-vulndb-*")
	if err != nil {
		return "", 0, noop, fmt.Errorf("preparing the advisory database: %w",
			ports.UnavailableSnapshotAbort(snapshot, "no scratch directory could be created to unpack the snapshot into", err))
	}
	if err := s.extractZip(ctx, snapshotContent, extractedDir); err != nil {
		_ = os.RemoveAll(extractedDir)
		return "", 0, noop, fmt.Errorf("preparing the advisory database: %w",
			ports.UnavailableSnapshotAbort(snapshot, "the snapshot archive would not extract", err))
	}
	count, err := vulndbdir.CountAdvisories(extractedDir)
	if err != nil {
		_ = os.RemoveAll(extractedDir)
		return "", 0, noop, fmt.Errorf("measuring the extracted advisory database: %w", err)
	}
	if count == 0 {
		_ = os.RemoveAll(extractedDir)
		return "", 0, noop, fmt.Errorf("preparing the advisory database: %w", ports.EmptySnapshotAbort(snapshot, count))
	}
	s.logger.Info("vuln-scan: using pinned local database", "path", extractedDir, "advisories", count)
	s.logMem(ctx, "db_extracted")
	return "file://" + extractedDir, count, func() { _ = os.RemoveAll(extractedDir) }, nil
}

// errNoVulnStore states the one way this seam can be asked for a pinned database
// it was never wired to reach. It is a construction fault rather than a runtime
// one, and it is named so the refusal reads the same as the others.
var errNoVulnStore = errors.New("no vulnerability store is configured")

// verifyExtractedGeneration checks that a pre-extracted advisory database is the
// generation the scan is pinned to, by reading the index/db.json the extraction
// carried over from the archive.
//
// The directory is prepared by the walk once and shared by every scan in it, so
// this is a read of one small file per scan and not a re-measurement of the
// database. What it buys is that "the analysis read the snapshot the record
// names" is asserted from the bytes govulncheck is about to be pointed at,
// rather than from the fact that the same variable was passed to both.
//
// An unreadable or unparsable db.json is refused for the same reason a mismatch
// is: the answer to "which generation is this" is then unknown, and a scan may
// not seal a verdict against a database it cannot name.
func verifyExtractedGeneration(dbDir string, snapshot domain.DatabaseSnapshot) error {
	data, err := os.ReadFile(filepath.Join(filepath.Clean(dbDir), "index", "db.json"))
	if err != nil {
		return fmt.Errorf("checking the pre-extracted advisory database: %w", ports.UnavailableSnapshotAbort(snapshot, "the pre-extracted database does not state its generation", err))
	}
	var meta struct {
		Modified string `json:"modified"`
	}
	if err := json.Unmarshal(data, &meta); err != nil {
		return fmt.Errorf("checking the pre-extracted advisory database: %w", ports.UnavailableSnapshotAbort(snapshot, "the pre-extracted database's index/db.json could not be read", err))
	}
	if meta.Modified != snapshot.Version() {
		return fmt.Errorf("checking the pre-extracted advisory database: %w",
			ports.UnavailableSnapshotAbort(snapshot, "the pre-extracted database is a different generation",
				fmt.Errorf("the directory holds %q", meta.Modified)))
	}
	return nil
}

// snapshotCountingAdvisories returns snapshot carrying the advisory count a
// database preparation measured, and snapshot unchanged when it measured none.
//
// Zero is the unmeasured reading, not a database of zero advisories: an empty
// database is refused at the seam that would have counted it, so the only way to
// arrive here with nothing is to have consulted a database this process did not
// open (a dir another stage extracted and counted, or the live service). The
// domain refuses a non-positive count for the same reason, so the guard here is
// what keeps that refusal from turning an unmeasured scan into an error.
func snapshotCountingAdvisories(snapshot domain.DatabaseSnapshot, count int) (domain.DatabaseSnapshot, error) {
	if count <= 0 {
		return snapshot, nil
	}
	counted, err := snapshot.WithAdvisoryCount(count)
	if err != nil {
		return domain.DatabaseSnapshot{}, fmt.Errorf("recording the advisory count on the snapshot: %w", err)
	}
	return counted, nil
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
// GOWORK=off is set unconditionally. A module is scanned in isolation as its
// own main module, so a go.work shipped in its published zip is dev-time
// configuration that does not apply here — exactly as its own filesystem
// replace directives do not (neutraliseLocalReplaces). Left on, the toolchain
// discovers ./go.work in the extract dir and enters workspace mode, which both
// rejects -mod=mod outright and would resolve against sibling modules the zip
// does not contain. Disabling it is the same normalisation applied to the same
// class of dev-time metadata; without it such a module is misreported as not
// building under the host toolchain.
//
// The vendored surface is the other regime, and it is the opposite choice on
// the one flag that matters. -mod=mod is precisely what tells the toolchain to
// IGNORE a vendor/ directory, so for a project that carries one the environment
// above does not merely prefer the fetched copy — it makes the vendored copy
// unreadable, and the analysis measures bytes the project does not compile.
// AnalysisSurfaceVendored therefore sets -mod=vendor and nothing else that
// touches resolution: under vendor mode the toolchain reads no module cache and
// performs no MVS, so GOMODCACHE and a checksum database have nothing to say.
// GOPROXY=off stays as the guarantee that a vendored analysis fetches nothing —
// a vendored build that reached the network would no longer be the build.
//
// GOTOOLCHAIN=local rides with GOSUMDB=off: a switch must verify what it
// downloads, so with the checksum database off it can only fail, and fails
// naming that setting rather than the version gap. Not on the vendored surface,
// which leaves the database on and completes a switch from cached data.
//
// Duplicate keys are appended rather than replaced because exec.Cmd honours the
// last value for a repeated key, so these overrides win over any inherited
// GOWORK/GOFLAGS/GOSUMDB/GOPROXY/GOTOOLCHAIN.
func scanEnv(base []string, goModCache string, surface domain.AnalysisSurface) []string {
	// Copy rather than append onto base so a caller's slice is never mutated.
	env := make([]string, len(base), len(base)+7)
	copy(env, base)
	env = append(env, "GOGC=30", "GOWORK=off")
	if surface == domain.AnalysisSurfaceVendored {
		return append(env, "GOFLAGS=-mod=vendor", "GOPROXY=off")
	}
	if goModCache != "" {
		env = append(env,
			"GOMODCACHE="+goModCache,
			"GOFLAGS=-mod=mod",
			"GOSUMDB=off",
			"GOTOOLCHAIN=local",
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
