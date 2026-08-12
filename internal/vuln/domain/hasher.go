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
// Each of the three fields is filled only when the writer left it empty, and
// whatever the writer stated stands:
//
//   - Coverage comes from DetermineRecordCoverage, which reads the record's
//     diagnostics rather than the summary word. A writer that has both a coverage
//     gap and a matching advisory can put only one of them in the single word and
//     puts the finding there, so deriving coverage from the word answers
//     "Analysed" for a module that was never analysed.
//   - Findings comes from DetermineRecordFindings, which reads the findings the
//     record kept. A retracted advisory is not a finding against the module and
//     not an absence either, and only the set can say which of the two a match
//     is; the word cannot, because a writer that matched an advisory puts
//     Affected there whether or not it has since been withdrawn.
//   - The summary is collapsed from the axes when the writer stated none, so a
//     writer that has decided the axes need not restate the word.
//
// A stated summary is never overwritten from the axes, and that is deliberate.
// The collapse is lossy in one direction — coverage outranks findings, so
// (Unscannable, Affected) collapses to Unscannable — and applying it to a record
// whose writer already reported Affected would retire a finding for every
// consumer that reads the summary. A record may therefore carry a summary its
// axes would not have produced; the axes are the fact, and the summary is the
// compatibility word the writer chose to keep the finding visible in.
func (h VulnerabilityRecordHasher) SetContentHash(r VulnerabilityRecord) (VulnerabilityRecord, error) {
	// The record is put into canonical order BEFORE it is sealed, and is handed
	// back in the order it was sealed in. A record whose collections were
	// arranged differently from its own bytes would describe itself twice and
	// disagree, and every reader downstream of the seal — the store, a JSON
	// rendering, a diff — would be reading an arrangement the hash does not
	// stand behind. See SealedCollections for which collections have a canonical
	// order and why each does.
	//
	// This is deliberately here and NOT in hash, which is the recipe both the
	// seal and VerifyContentHash run. Canonicalising inside the recipe would
	// re-order a STORED record on the way to verifying it, and every record
	// already in a store whose collections are not in the new order would then
	// fail to reproduce its own seal: measured on the working store, 52 of the
	// 2,006 vulnerability records. Those records are not wrong about what they
	// measured — they are arranged differently — so making them unverifiable,
	// and owing a PipelineVersion bump that darkens all 2,006 until re-scan, buys
	// nothing. Sealing in canonical order makes every record written from here on
	// reproducible while leaving stored bytes verifiable exactly as they are.
	r = canonicalOrder(r)
	if r.CoverageStatus == "" {
		r.CoverageStatus = DetermineRecordCoverage(r)
	}
	if r.FindingsStatus == "" {
		r.FindingsStatus = DetermineRecordFindings(r)
	}
	if r.OverallStatus == "" {
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
// The recipe is the JSON encoding of the record itself — struct field order is
// the wire order, there is no separate canonical type — with FirstScannedAt
// zeroed and ContentHash empty, rendered as hex behind the "sha256:" label
// every other domain uses.
//
// The label costs nothing and is not decoration. A bare digest does not name the
// algorithm that produced it, and SHA3-256, BLAKE2s-256 and SM3 all emit 64 hex
// characters, so a bare seal cannot say which of them it is. It also left one
// record carrying two rules: its own seal was bare while the database snapshot
// hash inside it is prefixed, and NewDatabaseSnapshot refuses a bare one.
//
// The digest itself is unchanged by the label, because the seal covers the JSON
// with ContentHash blanked and the blanked bytes do not depend on how the field
// is later spelled. A stored record therefore re-notates by pure prefix — the
// new value is exactly "sha256:" plus the old one — which is what makes the
// migration that rewrote the existing rows self-verifying rather than a reseal.
// A walk scan run is not: its PerModuleResults embed record hashes, so its own
// content really does change and its seal is genuinely recomputed.
//
// FirstScannedAt is excluded because it is first-seen provenance, not part of
// the verdict: a reused record whose ScannedAt advances must not change
// identity on account of an anchor that never moves. ContentHash is excluded
// because a hash cannot cover itself. r is a value copy, so zeroing them here
// does not affect the caller's record.
//
// The anchor's exclusion is also stated by SealExcludes, which is what a reader
// verifying the STORED bytes needs: the field is omitzero, not omitted, so a
// populated anchor is in the blob and was not in the seal. Both must move
// together.
func (VulnerabilityRecordHasher) hash(r VulnerabilityRecord) (string, error) {
	r.FirstScannedAt = time.Time{}
	r.ContentHash = ""
	data, err := json.Marshal(r)
	if err != nil {
		return "", fmt.Errorf("marshalling vulnerability record for content hash: %w", err)
	}
	sum := sha256.Sum256(data)
	return contentHashPrefix + hex.EncodeToString(sum[:]), nil
}

// SealExcludes names the top-level JSON fields that are in a stored record but
// not in the bytes its seal covers.
//
// It exists because the two are not the same set, and a verifier working from
// the stored bytes alone cannot discover the difference. hash zeroes
// FirstScannedAt, while the field is tagged omitzero rather than omitted, so a
// record whose anchor has been set carries a member the seal never saw. Anything
// recomputing the seal from a stored blob must remove those members first or it
// will fail to reproduce every record that has been re-scanned — and report
// intact bytes in the wording reserved for altered ones.
//
// It is stated here, next to the recipe, so the two cannot drift apart: a field
// added to or removed from hash's exclusions is one line away from this list.
func (VulnerabilityRecordHasher) SealExcludes() []string {
	return []string{"first_scanned_at"}
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
// ContentHash empty, hex behind the "sha256:" label, on the same terms as
// VulnerabilityRecordHasher.hash.
func (WalkScanRunHasher) hash(run WalkScanRun) (string, error) {
	run.ContentHash = ""
	data, err := walkScanRunMarshal(run)
	if err != nil {
		return "", fmt.Errorf("marshalling walk scan run for content hash: %w", err)
	}
	sum := sha256.Sum256(data)
	return contentHashPrefix + hex.EncodeToString(sum[:]), nil
}

// contentHashPrefix labels the digest algorithm inside the ContentHash of a
// VulnerabilityRecord and a WalkScanRun, as it does in every other record
// domain and, inside these same records, on the database snapshot hash.
const contentHashPrefix = "sha256:"

// SealExcludes names the top-level JSON fields that are in a stored run but not
// in the bytes its seal covers. There are none: hash zeroes only ContentHash,
// which the shared verifier blanks for every domain.
//
// It is stated rather than left implicit so that a reader wires the run the same
// way it wires the record, and so that a field excluded from the recipe later
// has an obvious place to be declared instead of silently making every stored
// run unverifiable.
func (WalkScanRunHasher) SealExcludes() []string {
	return nil
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
