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
	// AcquisitionMode is covered by the hash so the field that tells a reader
	// which blob store resolves ContentLocation is as tamper-evident as the
	// handle itself. omitempty keeps the canonical bytes — and therefore the
	// content hash — identical to a pre-field record when unset, so records
	// written before the field existed still verify, on the same terms as
	// SumDBLookupFailed and the digest fields below.
	AcquisitionMode string `json:"acquisition_mode,omitempty"`
	ContentHash     string `json:"content_hash"`
	ContentLocation string `json:"content_location"`
	Ecosystem       string `json:"ecosystem"`
	FetchedAt       string `json:"fetched_at"`
	GitCommitHash   string `json:"git_commit_hash"`
	GitRef          string `json:"git_ref"`
	GitURL          string `json:"git_url"`
	GoModHash       string `json:"go_mod_hash"`
	// MeasurementKind and the two validation-leg pairs below are covered by the
	// hash on the same terms as every other field, and omitempty on the same
	// terms as SumDBLookupFailed: a record written before they existed produces
	// byte-identical canonical JSON and so still verifies its stored hash. The
	// leg fields especially must be tamper-evident — an inherited leg names the
	// record it was copied from, and a name that could be rewritten freely would
	// make the copy uncheckable against its source, which is the whole point of
	// recording it.
	MeasurementKind string `json:"measurement_kind,omitempty"`
	ModuleHash      string `json:"module_hash"`
	ModulePath      string `json:"module_path"`
	ModuleVersion   string `json:"module_version"`
	PipelineVersion string `json:"pipeline_version"`
	Retracted       bool   `json:"retracted"`
	SchemaVersion   string `json:"schema_version"`
	SumDBCheck      string `json:"sumdb_check,omitempty"`
	// SumDBCheckSource sorts after SumDBCheck and before SumDBLookupFailed,
	// keeping the struct in lexicographic key order.
	SumDBCheckSource string `json:"sumdb_check_source,omitempty"`
	// SumDBLookupFailed is covered by the hash so the flag that suppresses a
	// record's cache eligibility is itself tamper-evident: without it, flipping
	// the bit would silently promote a failed measurement back to a cache hit.
	// omitempty keeps the canonical bytes — and therefore the content hash —
	// identical to a pre-flag record when false, so records written before the
	// field existed still verify, on the same terms as the digest fields below.
	SumDBLookupFailed  bool   `json:"sumdb_lookup_failed,omitempty"`
	VCSCheck           string `json:"vcs_check,omitempty"`
	VCSCheckSource     string `json:"vcs_check_source,omitempty"`
	VerificationDetail string `json:"verification_detail"`
	VerificationStatus string `json:"verification_status"`
	// Raw artefact digests. omitempty keeps the canonical bytes — and therefore
	// the content hash — identical to a pre-digest record when unset, so legacy
	// records still verify; when present they are covered by the hash and thus
	// tamper-evident like every other field.
	ZipSHA256 string `json:"zip_sha256,omitempty"`
	ZipSHA384 string `json:"zip_sha384,omitempty"`
	ZipSHA512 string `json:"zip_sha512,omitempty"`
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

// CanonicalTimeFormat is the fixed-width nanosecond encoding a measurement time
// takes when it carries sub-second precision. The width is fixed — nine digits
// always — so the encoding is also usable as a sort key; time.RFC3339Nano strips
// trailing zeros and would not be.
const CanonicalTimeFormat = "2006-01-02T15:04:05.000000000Z07:00"

// canonicalTime encodes a measurement time for hashing, at the precision the
// value actually carries.
//
// A whole-second value encodes as plain RFC3339, exactly as every record written
// before sub-second measurement existed. Those records were produced by a
// pipeline that truncated to seconds, so they all take this branch and their
// stored content hashes still recompute — no record is rehashed and none needs
// to be. A value carrying nanoseconds encodes them, so two measurements taken
// within one second are distinguishable in the ledger and correlatable against
// the assurance log, which is the forensic question a second-precision timestamp
// cannot answer.
//
// The precision follows the VALUE, not a schema version or a flag on the record.
// That is what makes verification self-describing: recomputing a record's hash
// asks only what the record says, so there is no second decoder to pick between
// and no way for the two generations to be read through the wrong one.
func canonicalTime(t time.Time) string {
	t = t.UTC()
	if t.Nanosecond() == 0 {
		return t.Format(time.RFC3339)
	}
	return t.Format(CanonicalTimeFormat)
}

// marshalCanonical produces the deterministic JSON bytes for a FactRecord.
// Times are formatted as RFC3339 UTC. Keys are sorted by the canonicalRecord
// struct field order (which matches lexicographic key order).
func marshalCanonical(r FactRecord) ([]byte, error) {
	c := canonicalRecord{
		AcquisitionMode:    r.AcquisitionMode,
		ContentHash:        r.ContentHash,
		ContentLocation:    r.ContentLocation,
		Ecosystem:          r.Ecosystem,
		FetchedAt:          canonicalTime(r.FetchedAt),
		GitCommitHash:      r.GitCommitHash,
		GitRef:             r.GitRef,
		GitURL:             r.GitURL,
		GoModHash:          r.GoModHash,
		MeasurementKind:    r.MeasurementKind,
		ModuleHash:         r.ModuleHash,
		ModulePath:         r.ModulePath,
		ModuleVersion:      r.ModuleVersion,
		PipelineVersion:    r.PipelineVersion,
		Retracted:          r.Retracted,
		SchemaVersion:      r.SchemaVersion,
		SumDBCheck:         r.SumDBCheck,
		SumDBCheckSource:   r.SumDBCheckSource,
		SumDBLookupFailed:  r.SumDBLookupFailed,
		VCSCheck:           r.VCSCheck,
		VCSCheckSource:     r.VCSCheckSource,
		VerificationDetail: r.VerificationDetail,
		VerificationStatus: r.VerificationStatus,
		ZipSHA256:          r.ZipSHA256,
		ZipSHA384:          r.ZipSHA384,
		ZipSHA512:          r.ZipSHA512,
	}
	b, err := canonicalMarshal(c)
	if err != nil {
		return nil, fmt.Errorf("marshalling canonical record: %w", err)
	}
	return b, nil
}

// canonicalMarshal is a seam over json.Marshal used to test the
// marshal-failure guard's wrapping and propagation logic. No field in
// canonicalRecord can currently make json.Marshal fail (no NaN/Inf floats,
// no unsupported types), so this proves the guard's error handling is
// correct, not that the guard is reachable with a real value today — it
// exists for the never-silent-failure invariant, not a known failure mode.
var canonicalMarshal = json.Marshal

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
		SumDBLookupFailed:  c.SumDBLookupFailed,
		AcquisitionMode:    c.AcquisitionMode,
		MeasurementKind:    c.MeasurementKind,
		SumDBCheck:         c.SumDBCheck,
		SumDBCheckSource:   c.SumDBCheckSource,
		VCSCheck:           c.VCSCheck,
		VCSCheckSource:     c.VCSCheckSource,
		ZipSHA256:          c.ZipSHA256,
		ZipSHA384:          c.ZipSHA384,
		ZipSHA512:          c.ZipSHA512,
	}, nil
}
