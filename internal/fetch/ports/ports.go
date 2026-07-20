package ports

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/eitanity/kanonarion/internal/audit"
	"github.com/eitanity/kanonarion/internal/coordinate"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// AuditSink appends an audit event to the append-only assurance log. The shared
// JSONL AuditLog satisfies this; the read/serve verification path depends only
// on this narrow port, never on the factstore adapter that persists it. It
// mirrors the identically named ports the directive/godebug/fips/vendortree
// contexts already emit through.
type AuditSink interface {
	RecordEvent(audit.Event) error
}

// ErrVCSToolMissing is returned by a VCSClient when the underlying version
// control tool is not available on the host (e.g. no git binary in PATH).
// It is part of the VCSClient contract so callers can distinguish "cross-verify
// could not run because the tool is absent" (an un-analysed/unknown outcome)
// from "cross-verify ran and could not confirm" (a negative result) — see
// Implementations wrap it with an actionable, transport-specific
// message; callers match with errors.Is, never on the string.
var ErrVCSToolMissing = errors.New("vcs tool not available")

// SumDBClient queries the Go checksum database (sum.golang.org or configured
// GOSUMDB) for module hash entries. Implementations must never return a non-nil
// error; failures are encoded in SumDBResult.Available.
type SumDBClient interface {
	// Lookup returns the hash entries recorded in the transparency log for
	// the given module version. If sumdb is disabled, not found, or
	// unreachable, Available is false and Reason describes why.
	Lookup(ctx context.Context, coord coordinate.ModuleCoordinate) SumDBResult
}

// SumDBResult is the outcome of a checksum database lookup.
type SumDBResult struct {
	// Available is true when the lookup succeeded and hashes were returned.
	Available bool
	// Reason is set when Available is false; describes why the lookup was skipped.
	Reason string
	// ZipHash is the h1 hash of the module zip as recorded in the transparency log.
	ZipHash domain2.ModuleHash
	// GoModHash is the h1 hash of the go.mod as recorded in the transparency log.
	GoModHash domain2.ModuleHash
}

// ModuleProxy retrieves modules via the Go module proxy protocol.
// Implementations: directProxy (proxy.golang.org), fakeProxy (tests).
type ModuleProxy interface {
	// Info returns the.info JSON for a module version, including the
	// Origin block if the proxy populates it.
	Info(ctx context.Context, coord coordinate.ModuleCoordinate) (ModuleInfo, error)

	// Download fetches the module zip and go.mod, returning readers and
	// the h1 hashes the proxy reports. Callers must close the readers.
	Download(ctx context.Context, coord coordinate.ModuleCoordinate) (ModuleDownload, error)
}

// ModuleInfo is the parsed response from a proxy.info endpoint.
type ModuleInfo struct {
	Version string
	Time    time.Time
	// Origin is populated by proxies that track VCS provenance (e.g. sum.golang.org).
	// Nil if the proxy did not include an Origin block.
	Origin *ModuleOrigin
}

// ModuleOrigin carries VCS provenance from a proxy.info response.
type ModuleOrigin struct {
	VCS  string // "git"
	URL  string // canonical clone URL
	Ref  string // e.g. "refs/tags/v1.8.1"
	Hash string // full commit SHA
}

// ModuleDownload carries the artefacts from a proxy download.
// Callers must close Zip and GoMod after use.
//
// ZipHash and GoModHash are always computed by the adapter from the actual
// downloaded bytes, not taken from proxy-reported values. InsecureTransport
// is true when the connection used plain HTTP.
type ModuleDownload struct {
	Zip               io.ReadCloser
	GoMod             io.ReadCloser
	ZipHash           domain2.ModuleHash
	GoModHash         domain2.ModuleHash
	InsecureTransport bool
	// Digests are the raw SHA-256/384/512 hashes of the zip bytes, computed by
	// the adapter from the same bytes as ZipHash. They are carried into the SBOM
	// as the component's <hashes>; the SBOM never recomputes them.
	Digests domain2.ArtifactDigests
}

// VCSClient performs git operations on source repositories.
// Implementations: gitExec (shells out to git), fakeVCS (tests).
//
// Runtime dependency: the gitExec implementation requires a git binary in PATH.
type VCSClient interface {
	// ResolveTag returns the full commit SHA that a tag or ref points to.
	ResolveTag(ctx context.Context, url, ref string) (string, error)

	// CheckoutToDir clones/fetches the repository and checks out the given
	// commit into dir. dir must exist and be empty.
	CheckoutToDir(ctx context.Context, url, commit, dir string) error
}

// BlobStore persists opaque binary artefacts content-addressably.
// Implementations: localfsBlob, fakeBlob (tests).
//
// BlobHandle is an opaque string returned by Put. Callers must not interpret
// its internal format; it may be a hash, a path segment, or an OCI digest.
type BlobStore interface {
	// Put stores content and returns an opaque handle. Idempotent: storing
	// the same bytes twice returns the same handle.
	Put(ctx context.Context, content io.Reader) (BlobHandle, error)

	// Get opens a stored blob for reading. Returns an error if the handle
	// is unknown.
	Get(ctx context.Context, handle BlobHandle) (io.ReadCloser, error)

	// Exists reports whether the handle is present in the store.
	Exists(ctx context.Context, handle BlobHandle) (bool, error)
}

// BlobPathOptimizer is an optional capability a BlobStore may also implement
// when it can hand back a local filesystem path to a blob, letting callers pass
// the path to external tools or avoid reading the whole blob into memory. It is
// kept off BlobStore because object stores (e.g. S3) cannot honour it; callers
// must type-assert for it and degrade gracefully (materialise the blob bytes)
// when it is absent. Per the published-port asymmetry rule, capabilities grow
// by new optional interfaces like this one, never by widening BlobStore.
type BlobPathOptimizer interface {
	// GetPath returns the local filesystem path to the blob identified by
	// handle. Returns ErrBlobNotFound if the handle is unknown.
	GetPath(ctx context.Context, handle BlobHandle) (string, error)
}

// BlobHandle is an opaque reference to a stored blob. Treat as an identifier,
// not a filesystem path.
type BlobHandle string

// Signer signs a subject digest taken from the content-identity surface and
// returns an attestation over it. It is a published substitution port: OSS
// ships a no-op default and enterprise injects a keyed (e.g. sigstore-backed)
// implementation through the DI container. Signing on a keyed subject digest
// closes the T9 residual the keyless self-hash leaves open — an attacker who
// rewrites a blob and its fact record consistently can recompute the self-hash
// but cannot forge a keyed signature.
//
// A Signer attests provenance ("kanonarion received/produced these bytes"),
// never source authenticity or fact correctness.
type Signer interface {
	// Sign signs the subject digest and returns an Attestation. An
	// unconfigured signer (the OSS no-op default) returns an Attestation whose
	// Present field is false: per the absence-vs-zero rule this is *no
	// attestation*, distinct from a present attestation that carries empty
	// trust material. Implementations must encode an inability to sign as a
	// non-Present attestation, not as an error; a returned error means the
	// signing operation itself failed.
	Sign(ctx context.Context, subject SubjectDigest) (Attestation, error)
}

// SubjectDigest is the canonical digest of a record or blob, as produced by the
// content-identity surface. It is the single value a Signer attests over, so a
// signature can never drift from core's canonical digest.
type SubjectDigest struct {
	// Algorithm names the digest function, e.g. "sha256".
	Algorithm string
	// Hex is the lowercase hex-encoded digest value.
	Hex string
}

// Attestation is the result of signing a SubjectDigest.
type Attestation struct {
	// Present reports whether an attestation was produced. It is false for the
	// OSS no-op default. A false Present must not be read as a signature with
	// empty trust; it means no signing occurred.
	Present bool
	// Subject is the digest this attestation covers. Zero when Present is false.
	Subject SubjectDigest
	// Bundle is the opaque signed attestation/bundle (e.g. a sigstore bundle).
	// Consumers must treat it as opaque bytes. Nil when Present is false.
	Bundle []byte
}

// FactStore persists FactRecords durably and structurally.
// Implementations: sqliteFact, fakeFact (tests).
type FactStore interface {
	// PutFetchRecord persists a fact record. Idempotent on
	// (module_path, module_version, pipeline_version): a second call with
	// the same coordinate and pipeline version overwrites the existing record.
	PutFetchRecord(ctx context.Context, record domain2.FactRecord) error

	// GetFetchRecord retrieves the fact record for the given coordinate and
	// pipeline version. The bool is false if no record exists.
	GetFetchRecord(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (domain2.FactRecord, bool, error)
}

// AttestationStore persists provenance attestations additively, separate from
// the records they attest so the attested record's serialisation is unchanged.
// Implementations: sqliteFact (shares the fetch store), fakeAttestation (tests).
type AttestationStore interface {
	// PutAttestation persists an attestation. Idempotent on
	// (coordinate, pipeline version, subject kind, subject digest): re-signing
	// the same subject overwrites the prior bundle rather than duplicating it.
	PutAttestation(ctx context.Context, record domain2.AttestationRecord) error

	// ListAttestations returns all attestations for a coordinate and pipeline
	// version, in deterministic order. Empty (not an error) when none exist.
	ListAttestations(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) ([]domain2.AttestationRecord, error)
}

// Clock is injected wherever wall-clock time is needed, so that tests can
// use a fixed instant for deterministic FactRecord hashes.
type Clock interface {
	Now() time.Time
}

// Stopwatch is injected wherever elapsed time is measured for instrumentation
// (e.g. duration log metrics). It is distinct from Clock: Clock provides
// domain-relevant wall-clock timestamps, whereas Stopwatch measures monotonic
// elapsed durations and must not be used for domain timestamps. Injecting it
// keeps instrumentation timing deterministic and controllable in tests.
type Stopwatch interface {
	// Start begins a new measurement and returns a Lap whose Elapsed reports
	// the duration since Start was called.
	Start() Lap
}

// Lap is a single in-flight measurement produced by Stopwatch.Start.
type Lap interface {
	// Elapsed returns the duration since the originating Start call.
	Elapsed() time.Duration
}
