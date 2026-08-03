package application

import (
	"fmt"

	"github.com/eitanity/kanonarion/internal/audit"

	"github.com/eitanity/kanonarion/internal/stdlib/domain"
	"github.com/eitanity/kanonarion/internal/stdlib/ports"
)

// Anchor names published in the assurance log. They name what an acquisition
// CONSULTED and established, not how far the toolchain is trusted: the record
// carries the verification status, and the log has the content hash to reach it
// with.
const (
	anchorGoDevChecksum      = "godev_checksum"
	anchorLocalToolchainSrc  = "local_toolchain_source"
	anchorGoogleSourceCommit = "googlesource_commit"
)

// emitCustodyRecorded appends one stdlib_custody_recorded event for a
// measurement this run persisted. A nil sink disables emission, and a run served
// from cache never reaches here: the event says a measurement was WRITTEN, so
// emitting on a cache hit would report a write that did not happen. A run that
// could not establish custody at all returns before the write and so appends
// nothing — an absence is not an observation.
func emitCustodyRecorded(sink ports.AuditSink, facts domain.Facts) error {
	if sink == nil {
		return nil
	}
	if err := sink.RecordEvent(custodyRecordedEvent(facts)); err != nil {
		return fmt.Errorf("recording stdlib custody audit event: %w", err)
	}
	return nil
}

// custodyRecordedEvent builds the assurance-log envelope for one persisted
// standard-library custody measurement.
//
// The payload identifies the write — which toolchain version, by which route,
// over which bytes, sealed under which hash — and names the anchors that
// acquisition established. It deliberately carries neither the verification
// status nor the published checksum, the licence or the verification detail:
// those are the RECORD's claims about the toolchain, and restating them here
// would make the log a second, unsealed copy of the evidence rather than a
// witness that the evidence was written. A reader that wants the claims has the
// content hash to ask the ledger with.
func custodyRecordedEvent(facts domain.Facts) audit.Event {
	payload := map[string]any{
		"go_version":           facts.GoVersion,
		"acquisition_route":    facts.AcquisitionRoute.String(),
		"verification_anchors": verificationAnchors(facts),
		"content_hash":         facts.ContentHash,
	}
	// Which bytes the measurement was taken over. Together with the route it is
	// what tells two measurements of one toolchain version apart — the ledger keys
	// on exactly that pair — so without it a re-acquisition and a first
	// acquisition read identically in the log. Omitted when no digest was
	// computed, since an empty identity would read as bytes that hashed to
	// nothing.
	if id := domain.ArtefactIdentity(facts); id != "" {
		payload["artefact_identity"] = id
	}
	return audit.Event{Type: audit.EventStdlibCustodyRecorded, Payload: payload}
}

// verificationAnchors names the anchors an acquisition established, in a stable
// order. The list is empty — never absent — when none were: a run that
// downloaded the published tarball but could not match it against a published
// checksum did establish a record, and the log says so by naming no anchor,
// which is a statement about the acquisition rather than a verdict about the
// toolchain.
func verificationAnchors(facts domain.Facts) []string {
	anchors := []string{}
	switch facts.VerificationStatus {
	case domain.VerifiedGoDevChecksum:
		anchors = append(anchors, anchorGoDevChecksum)
	case domain.VerifiedLocalToolchain:
		anchors = append(anchors, anchorLocalToolchainSrc)
	case domain.GoDevChecksumMismatch, domain.UnverifiedGoDevUnavailable:
		// The tarball was acquired and sealed, but nothing corroborated it.
	}
	if facts.VCSCommit != "" {
		anchors = append(anchors, anchorGoogleSourceCommit)
	}
	return anchors
}
