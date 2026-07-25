package domain

import (
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
)

// SchemaVersion is the version of the FactRecord JSON schema. Bump when
// the serialisation format changes in a backwards-incompatible way.
const SchemaVersion = "4"

// EcosystemGo is the only ecosystem kanonarion records describe. The
// ecosystem field declares the schema's scope — kanonarion is fitted for
// Go module coordinates, Go semver and Go tooling — rather than enabling
// polyglot mode. There is deliberately no "npm" or "cargo": a second
// ecosystem would mean new record types, not a different value here.
const EcosystemGo = "go"

// FactRecord is the persisted, tamper-evident representation of a
// FetchedModule. It is a value object: once written it is immutable.
//
// Serialisation invariants (enforced by CanonicalHasher):
// - JSON keys are sorted lexicographically.
// - Times are formatted as RFC3339 in UTC with nanosecond precision zeroed.
// - ContentHash is computed over the canonical JSON with ContentHash zeroed;
// this prevents circular self-reference.
// - SchemaVersion is always present.
type FactRecord struct {
	SchemaVersion      string    `json:"schema_version"`
	Ecosystem          string    `json:"ecosystem"`
	ModulePath         string    `json:"module_path"`
	ModuleVersion      string    `json:"module_version"`
	ModuleHash         string    `json:"module_hash"`
	GoModHash          string    `json:"go_mod_hash"`
	ZipSHA256          string    `json:"zip_sha256"`
	ZipSHA384          string    `json:"zip_sha384"`
	ZipSHA512          string    `json:"zip_sha512"`
	GitURL             string    `json:"git_url"`
	GitRef             string    `json:"git_ref"`
	GitCommitHash      string    `json:"git_commit_hash"`
	VerificationStatus string    `json:"verification_status"`
	VerificationDetail string    `json:"verification_detail"`
	FetchedAt          time.Time `json:"fetched_at"`
	PipelineVersion    string    `json:"pipeline_version"`
	ContentLocation    string    `json:"content_location"`
	GoModLocation      string    `json:"go_mod_location"`
	ContentHash        string    `json:"content_hash"`
	Retracted          bool      `json:"retracted"`

	// SumDBLookupFailed reports that the checksum-database lookup behind this
	// record's VerificationStatus failed rather than answering. It is what makes
	// the record's status readable as a property of the measurement instead of a
	// property of the module: the status may be UnverifiedNoSumDB, or
	// VerifiedByGoSum where a local go.sum entry covered the gap, but in neither
	// case did the transparency log get consulted successfully.
	//
	// Such a record is persisted so a walk completes, but it is not eligible as a
	// cache hit — see RecordIsCacheable — so the next fetch re-verifies instead of
	// serving a downgrade produced by a bad network moment.
	SumDBLookupFailed bool `json:"sumdb_lookup_failed"`

	// AcquisitionMode names the path the module's bytes arrived by — proxy,
	// modcache, or local. It is what makes ContentLocation readable: the handle's
	// resolvability depends on the mode that wrote it, and without the mode a
	// reader has to parse the handle to work out which blob store can produce the
	// bytes. Empty on records written before the field existed.
	AcquisitionMode string `json:"acquisition_mode,omitempty"`
}

// NewFactRecord constructs a FactRecord from a FetchedModule. ContentHash is
// left empty; call CanonicalHasher.SetContentHash to populate it.
func NewFactRecord(m FetchedModule) FactRecord {
	return FactRecord{
		SchemaVersion:      SchemaVersion,
		Ecosystem:          EcosystemGo,
		ModulePath:         m.Coordinate.Path,
		ModuleVersion:      m.Coordinate.Version,
		ModuleHash:         m.ModuleHash.String(),
		GoModHash:          m.GoModHash.String(),
		ZipSHA256:          m.Digests.SHA256,
		ZipSHA384:          m.Digests.SHA384,
		ZipSHA512:          m.Digests.SHA512,
		GitURL:             m.GitReference.URL,
		GitRef:             m.GitReference.Ref,
		GitCommitHash:      m.GitReference.CommitHash,
		VerificationStatus: string(m.VerificationStatus),
		VerificationDetail: m.VerificationDetail,
		FetchedAt:          m.FetchedAt.UTC().Truncate(0),
		PipelineVersion:    m.PipelineVersion,
		ContentLocation:    m.ContentLocation,
		GoModLocation:      m.GoModLocation,
		Retracted:          m.Retracted,
		SumDBLookupFailed:  m.SumDBLookupFailed,
		AcquisitionMode:    string(m.AcquisitionMode),
	}
}

// RecordIsCacheable reports whether a record may satisfy a later fetch of the
// same coordinate, or whether that fetch must re-verify instead.
//
// A record whose checksum-database lookup failed is not cacheable. Its
// verification status describes a lookup that never answered, so serving it back
// would make one transient failure permanent: the downgrade would be returned on
// every subsequent run until --force, and the audit would keep reporting a
// finding about the module that is really an artefact of a bad network moment.
// Re-verifying costs one lookup on a run that would otherwise have skipped it,
// and it is the only way the downgrade can ever be undone on its own.
//
// Every other record — including one whose sumdb answer was a settled policy
// answer (GOSUMDB=off, GOPRIVATE, no hash line) — is cacheable exactly as before.
//
// It is a free function rather than a method, on the same terms as RecordDigests:
// cache eligibility is fetch-pipeline policy, not the read-shape plumbing a
// graduated result alias is allowed to carry, so it must not reach the public API.
func RecordIsCacheable(r FactRecord) bool {
	return !r.SumDBLookupFailed
}

// Coordinate returns the ModuleCoordinate this record describes.
func (r FactRecord) Coordinate() coordinate.ModuleCoordinate {
	return coordinate.ModuleCoordinate{Path: r.ModulePath, Version: r.ModuleVersion}
}

// IsGoModOnly reports whether this record was produced by the go.mod-only
// acquisition path: its go.mod is stored and verified but its module zip was
// never fetched, so ContentLocation is empty while GoModLocation is set.
//
// Such a record exists purely so the toolchain can read a superseded version's
// requirements while rebuilding a module graph; the version is never compiled
// and its source is never analysed. It therefore satisfies a caller that reads
// only go.mod (module-graph resolution) but MUST NOT satisfy a scan that needs
// source — a consumer of ContentLocation must treat it as absent and re-fetch
// the full artefact rather than silently degrade the scan to metadata-only.
func (r FactRecord) IsGoModOnly() bool {
	return r.ContentLocation == "" && r.GoModLocation != ""
}

// RecordDigests projects a fact record's persisted digest fields onto an
// ArtifactDigests value. It is a free function rather than a method so the
// graduated read-shaped result alias does not grow behaviour. The zero value is
// returned when no digests were captured (a record produced before digests
// existed, or a local source).
func RecordDigests(r FactRecord) ArtifactDigests {
	return ArtifactDigests{SHA256: r.ZipSHA256, SHA384: r.ZipSHA384, SHA512: r.ZipSHA512}
}
