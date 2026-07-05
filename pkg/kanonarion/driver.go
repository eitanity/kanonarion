package kanonarion

import (
	"fmt"

	"github.com/eitanity/kanonarion/internal/composition"
	"github.com/eitanity/kanonarion/internal/driver"
	fetchapp "github.com/eitanity/kanonarion/internal/fetch/application"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// Driver/serving surface (§1). The verified single-coordinate
// fetch/serve use case is the ONLY individually exported write use case: it
// powers a gating module proxy that serves only approved packages and
// fetches-and-verifies on miss. The bulk extraction pipeline stays behind the
// composition root, so its orchestration shape is free to change.

// ServeModuleUseCase resolves a single ModuleCoordinate to a servable blob,
// fetching and verifying on a miss and returning a BlobHandle the caller streams
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

// ServeResult is the output of ServeModuleUseCase.Serve: the servable BlobHandle
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

// Driver is the write/serving surface (§1): a pointer to every driver
// use case, constructed together against one store handle. It carries the
// verified fetch/serve driver and the local walk→extract driver; further drivers
// join as fields within a major version.
//
// Stability: result of the public driver composition entrypoint; unstable
// pre-v1. Fields may be added within a major version (§4).
type Driver = composition.Driver

// OpenDriver builds the write/serving surface against the kanonarion store
// rooted at storeRoot (the directory holding mirror.db and blobs; the standard
// default is ~/.kanonarion). It wires the fetch pipeline — proxy, VCS, sumdb,
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
func OpenDriver(storeRoot string) (*Driver, func() error, error) {
	driver, cleanup, err := composition.NewDriver(storeRoot)
	if err != nil {
		return nil, nil, fmt.Errorf("opening kanonarion driver: %w", err)
	}
	return driver, cleanup, nil
}
