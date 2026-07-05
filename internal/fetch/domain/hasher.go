package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ErrUnsupportedEcosystem is returned when a record's ecosystem field is
// absent or holds a value other than EcosystemGo. The field declares the
// schema's Go-only scope; kanonarion never holds npm packages or Rust
// crates, so any other value is a malformed or foreign record.
var ErrUnsupportedEcosystem = errors.New("unsupported ecosystem: kanonarion records are Go-only")

// CanonicalHasher computes and embeds a content hash into a FactRecord.
// The hash is over the canonical JSON serialisation with ContentHash zeroed,
// preventing circular self-reference.
type CanonicalHasher struct{}

// canonicalRecord is the fixed-field-order struct used for hashing.
// Fields must match FactRecord exactly but are listed in sorted key order
// to guarantee byte-identical output regardless of Go struct field ordering.
type canonicalRecord struct {
	ContentHash        string `json:"content_hash"`
	ContentLocation    string `json:"content_location"`
	Ecosystem          string `json:"ecosystem"`
	FetchedAt          string `json:"fetched_at"`
	GitCommitHash      string `json:"git_commit_hash"`
	GitRef             string `json:"git_ref"`
	GitURL             string `json:"git_url"`
	GoModHash          string `json:"go_mod_hash"`
	ModuleHash         string `json:"module_hash"`
	ModulePath         string `json:"module_path"`
	ModuleVersion      string `json:"module_version"`
	PipelineVersion    string `json:"pipeline_version"`
	Retracted          bool   `json:"retracted"`
	SchemaVersion      string `json:"schema_version"`
	VerificationDetail string `json:"verification_detail"`
	VerificationStatus string `json:"verification_status"`
}

// SetContentHash computes the canonical hash of r (with ContentHash zeroed),
// sets r.ContentHash, and returns the updated record.
func (CanonicalHasher) SetContentHash(r FactRecord) (FactRecord, error) {
	r.ContentHash = ""
	data, err := marshalCanonical(r)
	if err != nil {
		return FactRecord{}, fmt.Errorf("marshalling for hash: %w", err)
	}
	sum := sha256.Sum256(data)
	r.ContentHash = "sha256:" + hex.EncodeToString(sum[:])
	return r, nil
}

// VerifyContentHash re-computes the canonical hash and checks it matches
// r.ContentHash. Returns nil if valid.
func (CanonicalHasher) VerifyContentHash(r FactRecord) error {
	saved := r.ContentHash
	r.ContentHash = ""
	data, err := marshalCanonical(r)
	if err != nil {
		return fmt.Errorf("marshalling for verification: %w", err)
	}
	sum := sha256.Sum256(data)
	expected := "sha256:" + hex.EncodeToString(sum[:])
	if saved != expected {
		return fmt.Errorf("content hash mismatch: stored %q, computed %q", saved, expected)
	}
	return nil
}

// marshalCanonical produces the deterministic JSON bytes for a FactRecord.
// Times are formatted as RFC3339 UTC. Keys are sorted by the canonicalRecord
// struct field order (which matches lexicographic key order).
func marshalCanonical(r FactRecord) ([]byte, error) {
	c := canonicalRecord{
		ContentHash:        r.ContentHash,
		ContentLocation:    r.ContentLocation,
		Ecosystem:          r.Ecosystem,
		FetchedAt:          r.FetchedAt.UTC().Format(time.RFC3339),
		GitCommitHash:      r.GitCommitHash,
		GitRef:             r.GitRef,
		GitURL:             r.GitURL,
		GoModHash:          r.GoModHash,
		ModuleHash:         r.ModuleHash,
		ModulePath:         r.ModulePath,
		ModuleVersion:      r.ModuleVersion,
		PipelineVersion:    r.PipelineVersion,
		Retracted:          r.Retracted,
		SchemaVersion:      r.SchemaVersion,
		VerificationDetail: r.VerificationDetail,
		VerificationStatus: r.VerificationStatus,
	}
	b, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("marshalling canonical record: %w", err)
	}
	return b, nil
}

// Marshal returns the canonical JSON bytes for a FactRecord, including its
// ContentHash field. Use SetContentHash before calling this.
func (CanonicalHasher) Marshal(r FactRecord) ([]byte, error) {
	return marshalCanonical(r)
}

// Unmarshal parses a FactRecord from its canonical JSON representation.
// It is the inverse of Marshal.
func (CanonicalHasher) Unmarshal(data []byte) (FactRecord, error) {
	var c canonicalRecord
	if err := json.Unmarshal(data, &c); err != nil {
		return FactRecord{}, fmt.Errorf("unmarshalling canonical fact record: %w", err)
	}
	if c.Ecosystem != EcosystemGo {
		return FactRecord{}, fmt.Errorf("%w: got %q, want %q", ErrUnsupportedEcosystem, c.Ecosystem, EcosystemGo)
	}
	t, err := time.Parse(time.RFC3339, c.FetchedAt)
	if err != nil {
		return FactRecord{}, fmt.Errorf("parsing fetched_at %q: %w", c.FetchedAt, err)
	}
	return FactRecord{
		SchemaVersion:      c.SchemaVersion,
		Ecosystem:          c.Ecosystem,
		ModulePath:         c.ModulePath,
		ModuleVersion:      c.ModuleVersion,
		ModuleHash:         c.ModuleHash,
		GoModHash:          c.GoModHash,
		GitURL:             c.GitURL,
		GitRef:             c.GitRef,
		GitCommitHash:      c.GitCommitHash,
		VerificationStatus: c.VerificationStatus,
		VerificationDetail: c.VerificationDetail,
		FetchedAt:          t.UTC(),
		PipelineVersion:    c.PipelineVersion,
		ContentLocation:    c.ContentLocation,
		ContentHash:        c.ContentHash,
		Retracted:          c.Retracted,
	}, nil
}
