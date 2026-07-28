package ports

import (
	"context"
	"errors"
	"fmt"
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

// SumDBUnavailability discriminates why a checksum-database lookup produced no
// hashes. The distinction is the difference between a measurement and a finding:
// a policy answer is the database's real answer about the module and is stable
// across runs, whereas a failure is a statement about the lookup, not about the
// module, and a later attempt may well succeed. Collapsing the two lets one
// network flake be recorded — and cached — as a property of a dependency.
type SumDBUnavailability string

const (
	// SumDBUnavailabilityNone is the zero value, used when Available is true.
	SumDBUnavailabilityNone SumDBUnavailability = ""

	// SumDBUnavailabilityPolicy means the database was deliberately not
	// consulted, or answered without a hash line: GOSUMDB=off, a
	// GOPRIVATE/GONOSUMCHECK match, or a response carrying no hash for the
	// module. It is a settled answer; callers treat it exactly as they treat
	// any other stable verification outcome.
	SumDBUnavailabilityPolicy SumDBUnavailability = "policy"

	// SumDBUnavailabilityFailure means the lookup itself returned an error, so
	// nothing is known about the module's transparency-log entry. Err carries
	// the error for transient classification, and the resulting record is not
	// eligible as a cache hit — the next fetch must re-verify rather than serve
	// a downgrade produced by a bad network moment.
	SumDBUnavailabilityFailure SumDBUnavailability = "failure"
)

// SumDBResult is the outcome of a checksum database lookup.
type SumDBResult struct {
	// Available is true when the lookup succeeded and hashes were returned.
	Available bool
	// Reason is set when Available is false; describes why the lookup was skipped.
	Reason string
	// Unavailability discriminates a policy answer from a lookup failure when
	// Available is false; it is SumDBUnavailabilityNone when Available is true.
	// A client that leaves it unset on an unavailable result is read as a policy
	// answer, which is the pre-existing behaviour for every caller.
	Unavailability SumDBUnavailability
	// Err is the error the lookup returned when Unavailability is
	// SumDBUnavailabilityFailure, carried as a value so a decorator can classify
	// it (domain.IsTransientFetchError) rather than re-parse Reason. Nil for
	// every other outcome.
	Err error
	// ZipHash is the h1 hash of the module zip as recorded in the transparency log.
	ZipHash domain2.ModuleHash
	// GoModHash is the h1 hash of the go.mod as recorded in the transparency log.
	GoModHash domain2.ModuleHash
}

// LookupFailed reports whether the result is an unavailable-because-the-lookup-
// failed outcome, as opposed to an available result or a settled policy answer.
func (r SumDBResult) LookupFailed() bool {
	return !r.Available && r.Unavailability == SumDBUnavailabilityFailure
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

	// DownloadGoMod fetches only the standalone go.mod for a module version —
	// the go.mod-only counterpart to Download for callers that read a module's
	// requirements without ever compiling or analysing its source (module-graph
	// resolution). It returns the go.mod reader and the h1 hash computed from the
	// received bytes; the caller must close GoMod. It never fetches the zip, so
	// it does not spend the network (or module-cache) work the full Download
	// spends downloading and hashing the zip blob.
	DownloadGoMod(ctx context.Context, coord coordinate.ModuleCoordinate) (GoModDownload, error)
}

// GoModDownload carries the standalone go.mod artefact from a proxy go.mod-only
// download. Callers must close GoMod.
//
// GoModHash is always computed by the adapter from the actual downloaded bytes,
// never taken from a proxy-reported value. InsecureTransport is true when the
// connection used plain HTTP.
type GoModDownload struct {
	GoMod             io.ReadCloser
	GoModHash         domain2.ModuleHash
	InsecureTransport bool
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

// BlobStore persists binary artefacts under an address chosen by their content.
// Implementations: localfsBlob, modcache, fakeBlob (tests).
//
// The store does not choose the address. Every method takes the artefact's
// identity — the h1 hash the fetch pipeline measured — and the adapter maps that
// identity onto its own layout internally, never persisting the mapping. This is
// the correction of a real defect: when Put returned a store-chosen opaque
// handle and that handle was written into a fact record, the record described
// where one run had put the bytes rather than what the bytes were, and a
// coordinate measured by two routes acquired two irreconcilable records. With a
// content-chosen address, the same artefact measured any number of ways produces
// one address, and the same artefact may legitimately be held by several stores
// at once.
//
// Every implementation satisfies four obligations and is otherwise free:
//
//   - Addressed by artefact identity. The adapter's internal layout is its own
//     business, but it is never persisted and never leaks into a record.
//   - Verify before serve. Get produces bytes that hash to the requested
//     identity or reports absence. Absence is not a failure; wrong bytes are a
//     tamper finding.
//   - Materialise locally on demand, via BlobPathOptimizer, for the consumers
//     that need a filesystem path. A remote backend must not pretend to have
//     paths — it declines the optional interface instead.
//   - Population is the adapter's business. The port guarantees only that after
//     Put, Exists(identity) is true. Whether the bytes arrive by write, copy,
//     hard link or server-side copy is the adapter's choice.
type BlobStore interface {
	// Put stores content under the given artefact identity. Idempotent: storing
	// the same identity twice is a no-op the second time.
	Put(ctx context.Context, identity BlobIdentity, content io.Reader) error

	// Get opens the artefact for reading. Returns an error if the identity is
	// not held.
	Get(ctx context.Context, identity BlobIdentity) (io.ReadCloser, error)

	// Exists reports whether the artefact is present in the store.
	Exists(ctx context.Context, identity BlobIdentity) (bool, error)
}

// BlobPathOptimizer is an optional capability a BlobStore may also implement
// when it can hand back a local filesystem path to an artefact, letting callers
// pass the path to external tools or avoid reading the whole artefact into
// memory. It is kept off BlobStore because object stores (e.g. S3) cannot honour
// it; callers must type-assert for it and degrade gracefully (materialise the
// bytes) when it is absent. Per the published-port asymmetry rule, capabilities
// grow by new optional interfaces like this one, never by widening BlobStore.
type BlobPathOptimizer interface {
	// GetPath returns the local filesystem path to the artefact identified by
	// identity. Returns ErrBlobNotFound if it is not held.
	GetPath(ctx context.Context, identity BlobIdentity) (string, error)
}

// BlobIdentity addresses an artefact by what it is. It is derived from the
// fetch measurement, never invented by a store, so two stores asked for the same
// artefact are asked with the same value.
//
// Kind distinguishes the module zip from the standalone go.mod, because a
// go.mod-only measurement records the go.mod's h1 as the artefact identity and
// the two must not collide in a store that holds both.
type BlobIdentity struct {
	// Kind names which artefact of the module this identity addresses.
	Kind BlobKind

	// Hash is the h1 hash of the artefact's bytes.
	Hash domain2.ModuleHash
}

// BlobKind names an artefact of a module version.
type BlobKind string

const (
	// BlobKindZip is the module zip.
	BlobKindZip BlobKind = "zip"

	// BlobKindGoMod is the standalone go.mod.
	BlobKindGoMod BlobKind = "gomod"
)

// IsZero reports whether the identity addresses nothing.
func (b BlobIdentity) IsZero() bool { return b.Hash.IsZero() }

// String renders the identity as "<kind>:<algorithm>:<value>". It is the
// canonical spelling adapters key their internal layout from and the form a
// record persists when it needs to name an artefact.
func (b BlobIdentity) String() string {
	if b.IsZero() {
		return ""
	}
	return string(b.Kind) + ":" + b.Hash.String()
}

// ZipIdentity derives the blob identity of a fact record's module zip. The
// second result is false when the record describes a go.mod-only measurement,
// which has no zip to address — absence, not an error.
//
// Callers must use this rather than reading a handle off the record. A handle
// says where one measurement put the bytes; the identity says what the bytes
// are, and only the identity is the same for every store that holds them.
func ZipIdentity(r domain2.FactRecord) (BlobIdentity, bool, error) {
	h, err := domain2.StoredModuleHash(r.ModuleHash)
	if err != nil {
		return BlobIdentity{}, false, fmt.Errorf("deriving zip identity for %s: %w", r.Coordinate(), err)
	}
	if h.IsZero() {
		return BlobIdentity{}, false, nil
	}
	return BlobIdentity{Kind: BlobKindZip, Hash: h}, true, nil
}

// GoModIdentity derives the blob identity of a fact record's standalone go.mod.
// The second result is false when the record carries no go.mod hash.
func GoModIdentity(r domain2.FactRecord) (BlobIdentity, bool, error) {
	h, err := domain2.StoredModuleHash(r.GoModHash)
	if err != nil {
		return BlobIdentity{}, false, fmt.Errorf("deriving go.mod identity for %s: %w", r.Coordinate(), err)
	}
	if h.IsZero() {
		return BlobIdentity{}, false, nil
	}
	return BlobIdentity{Kind: BlobKindGoMod, Hash: h}, true, nil
}

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

// FactStore persists FactRecords durably and structurally, as an append-only
// ledger. Implementations: sqliteFact, fakeFact (tests).
//
// A measurement is never overwritten; it is appended. What a reader gets back is
// composed from the records describing the same artefact, so a re-measurement
// adds to the evidence rather than destroying its predecessor. That is what lets
// the store corroborate its own audit log: before this, the log could record
// fifteen writes for a coordinate while the store kept one, and an investigation
// into what changed had no surviving evidence to read.
//
// The zero coordinate is the one value the signatures cannot exclude: Go
// always permits coordinate.ModuleCoordinate{}, and it names no module.
// Implementations MUST refuse it with coordinate.ErrZeroCoordinate — on a
// write because it would key a row on the empty path at the empty version,
// which every later read treats as a genuine measurement, and on a read
// because absence is the wrong answer to a question about no module.
// coordinatetest.AssertRefusesZeroCoordinate pins the rule for every store.
type FactStore interface {
	// PutFetchRecord appends a measurement to the ledger. It never updates and
	// never deduplicates: each call is its own row, keyed on the coordinate, the
	// pipeline version, the artefact hash and the time of measurement.
	//
	// It accepts only a SealedRecord, so a record whose content hash does not
	// describe its contents cannot reach storage. Callers obtain one from
	// domain.Seal, which hashes at construction.
	//
	// The zero SealedRecord is the one value the signature cannot exclude —
	// SealedRecord is an exported struct, so the literal domain.SealedRecord{}
	// compiles anywhere and seals nothing. Implementations MUST refuse it with
	// domain.ErrUnsealedRecord and store nothing; accepting it would append an
	// all-empty row that every later read treats as a genuine measurement.
	PutFetchRecord(ctx context.Context, record domain2.SealedRecord) error

	// GetFetchRecord returns the composed view of the measurements held for the
	// given coordinate and pipeline version. The bool is false if no record
	// exists.
	//
	// It returns an error, not absence, when a stored record fails to rehydrate:
	// a detected tamper reported as "nothing here" becomes a silent re-fetch
	// that overwrites the evidence of the tamper.
	GetFetchRecord(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (domain2.CompositeRecord, bool, error)
}

// FactRecordLister is the optional capability a FactStore may also implement to
// hand back the individual measurements behind a composed record, rather than
// the composition alone.
//
// It arrives as a separate optional interface because the published-port
// asymmetry rule forbids widening FactStore with a third method;
// BlobPathOptimizer is the established precedent. Callers type-assert for it and
// degrade to the composed read when it is absent.
//
// It is needed by the write path as much as the read path. A run that skips the
// VCS check but is forced to re-measure has to find the earlier measurements of
// the same artefact in order to inherit their legs, and a composed record cannot
// answer that: it has already folded the measurements into one.
type FactRecordLister interface {
	// ListFetchRecords returns every measurement held for the coordinate and
	// pipeline version, oldest first. Empty (not an error) when none exist.
	// Records that fail to rehydrate are an error, on the same terms as
	// GetFetchRecord.
	ListFetchRecords(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) ([]domain2.FactRecord, error)
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
