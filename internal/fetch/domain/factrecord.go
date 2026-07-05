package domain

import "time"

// SchemaVersion is the version of the FactRecord JSON schema. Bump when
// the serialisation format changes in a backwards-incompatible way.
const SchemaVersion = "3"

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
	}
}

// Coordinate returns the ModuleCoordinate this record describes.
func (r FactRecord) Coordinate() ModuleCoordinate {
	return ModuleCoordinate{Path: r.ModulePath, Version: r.ModuleVersion}
}
