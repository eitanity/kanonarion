package kanonarion

import (
	"fmt"

	"github.com/eitanity/kanonarion/internal/composition"
	"github.com/eitanity/kanonarion/internal/driver"
	fetchapp "github.com/eitanity/kanonarion/internal/fetch/application"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// Driver/serving surface (§1). The write entries are whole operations — serve
// one coordinate, walk and extract a working tree, analyse a published
// version as inspect does, re-scan a stored walk — and never the stage use
// cases they compose, which stay behind the composition root so their
// orchestration shape is free to change.

// ServeModuleUseCase resolves a single ModuleCoordinate to a servable blob,
// fetching and verifying on a miss and returning a BlobIdentity the caller streams
// to its consumer. It is a TYPE ALIAS to the internal use case; the verification
// path (sumdb/hash) is unchanged. Serve never gates: the caller inspects the
// returned VerificationStatus and applies its own fail-closed policy.
//
// Stability: driver use case (called by consumers); unstable pre-v1. May gain
// methods within a major version (§4).
type ServeModuleUseCase = fetchapp.ServeModuleUseCase

// ServeRequest is the input to ServeModuleUseCase.Serve: the coordinate to
// resolve and the optional SkipVCSVerify flag, forwarded to the fetch pipeline.
//
// Stability: request struct (passed by consumers); unstable pre-v1. Fields may
// be added within a major version (§4).
type ServeRequest = fetchapp.ServeRequest

// ServeResult is the output of ServeModuleUseCase.Serve: the servable BlobIdentity
// (guaranteed present on success), the recorded VerificationStatus, the full
// FactRecord, and whether the result came from cache.
//
// Stability: result type (received by consumers); unstable pre-v1. Fields may be
// added within a major version (§4).
type ServeResult = fetchapp.ServeResult

// VerificationStatus is the outcome of cross-verifying a module zip against the
// checksum database and its git source. A consumer compares ServeResult's status
// against the exported constants below to make its own fail-closed gating
// decision before serving the bytes.
//
// Stability: result type (received by consumers); unstable pre-v1. New status
// values may be added within a major version; consumers must treat an
// unrecognised status conservatively (§4).
type VerificationStatus = fetchdomain.VerificationStatus

// Verification status constants. Verified is the strongest assurance (zip hash
// matches both the checksum database and the git source); the Unverified* values
// each name a distinct gap. A gating proxy typically serves only Verified (and
// possibly VerifiedBySumDBOnly) and refuses the rest.
//
// Stability: result-type enumeration (compared by consumers); unstable pre-v1.
// New status values may be added within a major version; consumers must treat an
// unrecognised status conservatively (§4).
const (
	// Verified means the zip hash matches both the checksum database and the
	// content extracted from the git commit.
	Verified = fetchdomain.Verified
	// VerifiedBySumDBOnly means the zip hash matches the checksum database but
	// the VCS could not be reached or its URL could not be inferred.
	VerifiedBySumDBOnly = fetchdomain.VerifiedBySumDBOnly
	// UnverifiedNoSumDB means the checksum database was disabled, unreachable, or
	// had no entry for this module version.
	UnverifiedNoSumDB = fetchdomain.UnverifiedNoSumDB
	// UnverifiedMissingOrigin means no origin metadata and no inferable VCS URL.
	UnverifiedMissingOrigin = fetchdomain.UnverifiedMissingOrigin
	// UnverifiedHashMismatch means the computed hash matched neither the checksum
	// database nor the git tree — possible tampering.
	UnverifiedHashMismatch = fetchdomain.UnverifiedHashMismatch
	// UnverifiedGoModInconsistent means the standalone go.mod does not match the
	// go.mod embedded in the zip.
	UnverifiedGoModInconsistent = fetchdomain.UnverifiedGoModInconsistent
	// UnverifiedNoVCS means a VCS checkout was attempted but could not be
	// completed (e.g. the repository or commit was unreachable).
	UnverifiedNoVCS = fetchdomain.UnverifiedNoVCS
	// UnverifiedVCSToolMissing means cross-verification never ran because the VCS
	// tool is absent from the host (e.g. no git binary in PATH) — an
	// un-analysed/unknown outcome resolved by installing the tool, distinct from
	// UnverifiedNoVCS.
	UnverifiedVCSToolMissing = fetchdomain.UnverifiedVCSToolMissing
	// LocalSource means the artefact was created from a local path, so checksum
	// and VCS verification do not apply.
	LocalSource = fetchdomain.LocalSource
)

// LocalWalkExtractUseCase runs a project-rooted walk over a local working tree
// and its extraction stages, returning the records (§1). It powers the
// local-walking gRPC client — source never leaves the machine — and is a narrow
// driver composing the walk and extract use cases, not the bulk pipeline. It is
// a TYPE ALIAS to the internal use case.
//
// Stability: driver use case (called by consumers); unstable pre-v1. May gain
// methods within a major version (§4).
type LocalWalkExtractUseCase = driver.LocalWalkExtractUseCase

// LocalWalkExtractRequest is the input to LocalWalkExtractUseCase.Run: the
// working-tree directory to analyse, whether to force past cached records, and
// the optional extraction stage subset (empty runs the full built-in set).
//
// Stability: request struct (passed by consumers); unstable pre-v1. Fields may
// be added within a major version (§4).
type LocalWalkExtractRequest = driver.LocalWalkExtractRequest

// LocalWalkExtractResult is the output of LocalWalkExtractUseCase.Run: the
// project WalkRecord and the ExtractionRun produced over it.
//
// Stability: result type (received by consumers); unstable pre-v1. Fields may be
// added within a major version (§4).
type LocalWalkExtractResult = driver.LocalWalkExtractResult

// CoordinateAnalysisUseCase runs, for one published module version, what
// `kanonarion inspect <module>@<version>` runs — the walk, the extraction
// stages and the vulnerability scan — writing to the driver's storage. The
// CLI builds its stage requests from the same functions. Driver.CoordinateAnalysis
// holds it.
//
// Stability: driver use case (called by consumers); unstable pre-v1. May gain
// methods within a major version (§4).
type CoordinateAnalysisUseCase = driver.CoordinateAnalysisUseCase

// CoordinateAnalysisRequest is the input to CoordinateAnalysisUseCase.Run: the
// coordinate, whether to force past stored records, the extraction stage
// subset (empty runs every stage), and the scan's reachability, advisory
// refresh and operator.
//
// Stability: request struct (passed by consumers); unstable pre-v1. Fields may
// be added within a major version (§4).
type CoordinateAnalysisRequest = driver.CoordinateAnalysisRequest

// CoordinateAnalysisResult is the output of CoordinateAnalysisUseCase.Run: the
// WalkRecord, ExtractionRun and WalkScanRun, and whether the walk and the scan
// were served from the store.
//
// Stability: result type (received by consumers); unstable pre-v1. Fields may be
// added within a major version (§4).
type CoordinateAnalysisResult = driver.CoordinateAnalysisResult

// RescanUseCase re-scans a stored walk against a fresh or pinned advisory
// snapshot and returns the new WalkScanRun, as `kanonarion vuln-scan-rescan
// <walk-id>` does; the command runs through it. Driver.Rescan holds it.
//
// Stability: driver use case (called by consumers); unstable pre-v1. May gain
// methods within a major version (§4).
type RescanUseCase = driver.RescanUseCase

// RescanRequest is the input to RescanUseCase.Run: the walk id, an optional
// pinned DatabaseSnapshot, reachability, the operator and an optional
// per-module progress callback.
//
// Stability: request struct (passed by consumers); unstable pre-v1. Fields may
// be added within a major version (§4).
type RescanRequest = driver.RescanRequest

// Driver is the write/serving surface (§1): a pointer to every driver
// use case, constructed together against one store handle. Its
// StalenessResolver method builds the staleness resolver over the store's
// ledger. Further drivers join as fields within a major version.
//
// Stability: result of the public driver composition entrypoint; unstable
// pre-v1. Fields may be added within a major version (§4).
type Driver = composition.Driver

// OpenDriver builds the write/serving surface against the kanonarion store
// rooted at storeRoot (the standard default is ~/.kanonarion). The backend is
// selected as Open selects it: storage.backend in <storeRoot>/config.yaml among
// the registered backends, the SQLite backend when none is named. It wires the fetch pipeline — proxy, VCS, sumdb,
// blob store, fact store — with the OSS no-op Signer, and returns the
// constructed Driver together with a cleanup function that closes the store.
// Callers MUST invoke cleanup when finished.
//
// This is the only supported way for an external consumer to obtain the
// verified fetch/serve driver; it constructs it without exposing internal/cli
// (§2.2). The proxy resolves $GOPROXY (or proxy.golang.org).
//
// Stability: public driver composition entrypoint; unstable pre-v1. It may gain
// optional configuration via a variadic option within a major version
// (§4).
func OpenDriver(storeRoot string, opts ...Option) (*Driver, func() error, error) {
	driver, cleanup, err := composition.NewDriver(storeRoot, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("opening kanonarion driver: %w", err)
	}
	return driver, cleanup, nil
}
