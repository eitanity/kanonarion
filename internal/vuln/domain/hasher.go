package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// VulnerabilityRecordHasher computes, embeds and verifies the content hash of a
// VulnerabilityRecord. The rule lives in the domain rather than in the use case
// that writes records so that both legs of the store can reach it: a hash only
// the writer can compute is a hash only the writer can check, which detects
// nothing that happens to a record after it is stored.
type VulnerabilityRecordHasher struct{}

// SetContentHash returns r with its three status fields reconciled and
// ContentHash set to the hash of the result.
//
// Reconciling here rather than at each construction site is deliberate: every
// record that reaches a store passes through this call — it is the only way to
// obtain the hash the store demands — so no writer can produce a record whose
// summary and axes disagree, and none can omit either by forgetting.
//
// Which side is authoritative depends on what the caller stated:
//
//   - A caller that set only OverallStatus (every writer that predates the
//     split) has its axes derived from it. The summary is untouched, so stored
//     values are unchanged.
//   - A caller that set the axes has OverallStatus derived from them, exactly as
//     WalkScanRun treats its own collapsed summary. This is what lets a record
//     say something the single word cannot — an advisory matched, but coverage
//     failed, so whether it applies was never established. That pair collapses
//     to a coverage word while FindingsStatus keeps the finding, instead of
//     becoming a Clean that reads as an all-clear.
//
// A caller that set both is taken at the axes' word, since they are the more
// specific statement.
func (h VulnerabilityRecordHasher) SetContentHash(r VulnerabilityRecord) (VulnerabilityRecord, error) {
	switch {
	case r.CoverageStatus == "" && r.FindingsStatus == "":
		r.CoverageStatus = DetermineRecordCoverageStatus(r.OverallStatus)
		r.FindingsStatus = DetermineRecordFindingsStatus(r.OverallStatus)
	default:
		// One axis stated and not the other still leaves the record fully
		// determined: the unstated one falls back to the summary's projection,
		// which is what the record said before the caller narrowed it.
		if r.CoverageStatus == "" {
			r.CoverageStatus = DetermineRecordCoverageStatus(r.OverallStatus)
		}
		if r.FindingsStatus == "" {
			r.FindingsStatus = DetermineRecordFindingsStatus(r.OverallStatus)
		}
		r.OverallStatus = DetermineRecordOverallStatus(r.CoverageStatus, r.FindingsStatus)
	}
	hash, err := h.hash(r)
	if err != nil {
		return VulnerabilityRecord{}, err
	}
	r.ContentHash = hash
	return r, nil
}

// VerifyContentHash recomputes the hash of r's contents and checks it against
// the hash r carries. Returns nil when the hash describes the contents.
func (h VulnerabilityRecordHasher) VerifyContentHash(r VulnerabilityRecord) error {
	computed, err := h.hash(r)
	if err != nil {
		return fmt.Errorf("hashing for verification: %w", err)
	}
	if r.ContentHash != computed {
		return fmt.Errorf("content hash mismatch: stored %q, computed %q", r.ContentHash, computed)
	}
	return nil
}

// hash renders the content hash of r.
//
// The recipe is fixed by the records already in every store and must not be
// changed: the JSON encoding of the record itself — struct field order is the
// wire order, there is no separate canonical type — with FirstScannedAt zeroed
// and ContentHash empty, rendered as bare hex. Unlike every other context this
// hash carries no "sha256:" prefix; adding one now would invalidate every
// stored record the moment the read leg checks it.
//
// FirstScannedAt is excluded because it is first-seen provenance, not part of
// the verdict: a reused record whose ScannedAt advances must not change
// identity on account of an anchor that never moves. ContentHash is excluded
// because a hash cannot cover itself. r is a value copy, so zeroing them here
// does not affect the caller's record.
func (VulnerabilityRecordHasher) hash(r VulnerabilityRecord) (string, error) {
	r.FirstScannedAt = time.Time{}
	r.ContentHash = ""
	data, err := json.Marshal(r)
	if err != nil {
		return "", fmt.Errorf("marshalling vulnerability record for content hash: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// Marshal returns the bytes a store persists for r, hash field included. Call
// SetContentHash first.
func (VulnerabilityRecordHasher) Marshal(r VulnerabilityRecord) ([]byte, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("marshalling vulnerability record: %w", err)
	}
	return data, nil
}

// Unmarshal parses the bytes Marshal produced back into a record.
func (VulnerabilityRecordHasher) Unmarshal(data []byte) (VulnerabilityRecord, error) {
	var r VulnerabilityRecord
	if err := json.Unmarshal(data, &r); err != nil {
		return VulnerabilityRecord{}, fmt.Errorf("unmarshalling vulnerability record: %w", err)
	}
	return r, nil
}

// WalkScanRunHasher computes, embeds and verifies the content hash of a
// WalkScanRun, on the same terms as VulnerabilityRecordHasher and for the same
// reason: the store must be able to check the seal it persists.
type WalkScanRunHasher struct{}

// SetContentHash returns run with ContentHash set to the hash of its contents.
func (h WalkScanRunHasher) SetContentHash(run WalkScanRun) (WalkScanRun, error) {
	hash, err := h.hash(run)
	if err != nil {
		return WalkScanRun{}, err
	}
	run.ContentHash = hash
	return run, nil
}

// VerifyContentHash recomputes the hash of run's contents and checks it against
// the hash run carries. Returns nil when the hash describes the contents.
func (h WalkScanRunHasher) VerifyContentHash(run WalkScanRun) error {
	computed, err := h.hash(run)
	if err != nil {
		return fmt.Errorf("hashing for verification: %w", err)
	}
	if run.ContentHash != computed {
		return fmt.Errorf("content hash mismatch: stored %q, computed %q", run.ContentHash, computed)
	}
	return nil
}

// hash renders the content hash of run: the JSON encoding of the run with
// ContentHash empty, as bare hex. As with VulnerabilityRecord the recipe is
// fixed by the runs already stored and carries no "sha256:" prefix.
func (WalkScanRunHasher) hash(run WalkScanRun) (string, error) {
	run.ContentHash = ""
	data, err := walkScanRunMarshal(run)
	if err != nil {
		return "", fmt.Errorf("marshalling walk scan run for content hash: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// Marshal returns the bytes a store persists for run, hash field included.
// Call SetContentHash first.
func (WalkScanRunHasher) Marshal(run WalkScanRun) ([]byte, error) {
	data, err := json.Marshal(run)
	if err != nil {
		return nil, fmt.Errorf("marshalling walk scan run: %w", err)
	}
	return data, nil
}

// Unmarshal parses the bytes Marshal produced back into a run.
func (WalkScanRunHasher) Unmarshal(data []byte) (WalkScanRun, error) {
	var run WalkScanRun
	if err := json.Unmarshal(data, &run); err != nil {
		return WalkScanRun{}, fmt.Errorf("unmarshalling walk scan run: %w", err)
	}
	return run, nil
}

// walkScanRunMarshal is a seam over json.Marshal used to test the
// marshal-failure guard's wrapping and propagation logic. No field in
// WalkScanRun can currently make json.Marshal fail (no NaN/Inf floats, no
// unsupported types), so this proves the guard's error handling is correct,
// not that the guard is reachable with a real value today — it exists for
// the never-silent-failure invariant, not a known failure mode. A
// VulnerabilityRecord needs no such seam: a finding's CVSS score is a plain
// float64, so NaN makes the record's own guard reachable for real.
var walkScanRunMarshal = json.Marshal
