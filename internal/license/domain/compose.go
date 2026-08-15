package domain

import (
	"errors"
	"fmt"
	"sort"

	"github.com/eitanity/kanonarion/internal/coordinate"
)

// ErrNoRecordsToCompose is returned by Compose when handed no records. It is a
// programming error rather than an absence: absence is reported by the store as
// "not found", and composing nothing has no meaningful answer.
var ErrNoRecordsToCompose = errors.New("no licence records to compose")

// LicenceConflict is two licence records that describe the same artefact, stand
// at the same position on the composition ladder, and still disagree.
//
// It is deliberately not "the records disagree". A licence answer for one
// artefact legitimately changes when the CLASSIFIER improves: a later run that
// resolves a previously low-confidence file to a confident SPDX identifier is a
// refinement of the same answer, not a contradiction, and composition serves the
// refinement. What cannot be a refinement is two detections that are equally
// confident about the same bytes and name different licences. That is either a
// relicensing recorded against one artefact or a misdetection, and both are
// findings worth surfacing rather than composing away — a licence is the
// downstream fact with legal weight, and picking one silently answers a question
// nobody can audit afterwards.
//
// It mirrors fetch's Divergence, including reporting the content hashes of the
// records carrying each value so an operator can go straight to the rows.
type LicenceConflict struct {
	// Coordinate is the module and version the disagreeing records describe.
	Coordinate coordinate.ModuleCoordinate

	// PipelineVersion is the pipeline version every conflicting record was
	// written under.
	PipelineVersion string

	// Field names what the records disagree on: "artefact_identity" or
	// "primary_spdx".
	Field string

	// Values are the distinct values recorded for Field, sorted, so the report is
	// stable across runs.
	Values []string

	// ContentHashes name the records carrying each of Values, in the same order.
	ContentHashes []string
}

// Error renders the conflict as a message. LicenceConflict satisfies error so
// the store can return it directly.
func (c LicenceConflict) Error() string {
	return fmt.Sprintf(
		"conflicting licence records for %s at pipeline %s: %s disagrees (%v; records %v)",
		c.Coordinate, c.PipelineVersion, c.Field, c.Values, c.ContentHashes,
	)
}

// Compose returns the licence record a reader gets for one coordinate and
// pipeline version, given every record the ledger holds for it.
//
// Records must be supplied in the order they were appended, and each must
// already have verified its own content hash: a record that cannot be checked
// stops the read before it reaches here, so composition never has to decide what
// to do about an unverifiable row.
//
// The ladder is HIGHEST CONFIDENCE, then recency. Recency is never authority on
// its own. Serving the newest record would let a classifier regression or a
// partial read displace a confident earlier detection merely by running later,
// which is the same defect the fetch ledger's anchor-strength ordering exists to
// prevent. Confidence is what orders answers to the question "which licence is
// this", so it orders the ladder; the timestamp only separates records that the
// ladder itself cannot.
func Compose(records []LicenseRecord) (LicenseRecord, error) {
	if len(records) == 0 {
		return LicenseRecord{}, ErrNoRecordsToCompose
	}
	if records[0].Coordinate.IsLocal() {
		// A local version pins no content — the working tree behind it is
		// deliberately re-read on every run, and the extraction path never serves
		// it from cache for exactly that reason — so its records are a SEQUENCE of
		// observations of a changing tree, not competing claims about one pinned
		// artefact. The last one is the only correct answer: serving a
		// higher-confidence earlier record would hand back a state of the tree that
		// no longer exists, so deleting a LICENSE file would silently fail to
		// register.
		//
		// "Last" is by position, not by timestamp. extracted_at persists at second
		// precision, so two runs within one second carry the same time and a
		// timestamp comparison cannot order them. The ledger is append-only and the
		// store lists in insertion order, which is the sequence.
		return records[len(records)-1], nil
	}

	candidates := identifiedOrAll(records)
	if c := findConflict(candidates); c != nil {
		return LicenseRecord{}, *c
	}

	ordered := make([]LicenseRecord, len(candidates))
	copy(ordered, candidates)
	sort.SliceStable(ordered, func(i, j int) bool { return servesBefore(ordered[i], ordered[j]) })
	return ordered[0], nil
}

// identifiedOrAll drops the records that name no artefact, unless none of them
// names one.
//
// A record written before the artefact identity existed cannot be shown to
// describe the same bytes as one that names an artefact, so composing the two
// together would assert they measured the same thing on no evidence. Once a
// measurement exists that says which bytes it read, it is the better-evidenced
// answer and the unidentified ones stop competing with it.
//
// Nothing is discarded from the ledger by this — the rows remain, and a history
// read still returns them. Composition serves the best-evidenced answer; it does
// not decide what the store keeps.
func identifiedOrAll(records []LicenseRecord) []LicenseRecord {
	identified := make([]LicenseRecord, 0, len(records))
	for _, r := range records {
		if r.ArtefactIdentity != "" {
			identified = append(identified, r)
		}
	}
	if len(identified) == 0 {
		return records
	}
	return identified
}

// findConflict reports the first disagreement that composition must not resolve
// by picking, or nil when the records can be laddered.
func findConflict(records []LicenseRecord) *LicenceConflict {
	if len(records) < 2 {
		return nil
	}

	// Two artefact identities for one pinned version means the same module at the
	// same version yielded two different sets of bytes. Composition is defined
	// over the records describing ONE artefact, so there is no ladder that orders
	// these: serving either would answer a question about bytes the caller never
	// named. It cannot fire on the upgrade path — identifiedOrAll has already
	// removed the records that name no artefact — so reaching here means two
	// measurements each named an artefact and named different ones.
	if c := disagreement(records, "artefact_identity", func(r LicenseRecord) string { return r.ArtefactIdentity }); c != nil {
		return c
	}

	// Within one artefact, only the records at the TOP of the ladder can
	// conflict. A lower-confidence record disagreeing with a higher-confidence
	// one is the refinement case the ladder exists to resolve.
	//
	// "The top" is a BAND, not an exact value, and the width is the one this
	// domain already uses for the same judgement: DeriveExpression treats two
	// candidates within exprCompoundDelta as near-equal coverage where neither
	// dominates, which is why it reads the file's prose rather than picking on
	// the margin. The same reasoning applies here.
	//
	// Exact equality would make this rule very nearly unfireable, and that was
	// measured rather than reasoned. Two detections of one real module in the
	// maintainer's store came out at 0.98816568047337283 and 0.99: a fifth of a
	// percent apart, naming MIT and AGPL-3.0-only. Under exact equality the
	// ladder would silently serve AGPL — a different licence family chosen on a
	// 0.002 confidence margin, which is precisely the relicensing-or-misdetection
	// signal this rule exists to surface. Confidence is a float derived from
	// coverage percentages, so two answers about the same bytes essentially never
	// tie to the bit unless they came from an identical run.
	top := records[0].PrimaryConfidence
	for _, r := range records[1:] {
		if r.PrimaryConfidence > top {
			top = r.PrimaryConfidence
		}
	}
	tied := make([]LicenseRecord, 0, len(records))
	for _, r := range records {
		// A record that identified no licence makes no claim about WHICH licence
		// the artefact carries, so it cannot contradict one that did. Letting it
		// take part would report every "no licence found, then MIT" pair as a
		// relicensing.
		if top-r.PrimaryConfidence <= exprCompoundDelta && r.PrimarySPDX != "" {
			tied = append(tied, r)
		}
	}
	return disagreement(tied, "primary_spdx", func(r LicenseRecord) string { return r.PrimarySPDX })
}

// disagreement reports the distinct values of one field across records, as a
// conflict, when there is more than one.
func disagreement(records []LicenseRecord, field string, value func(LicenseRecord) string) *LicenceConflict {
	if len(records) < 2 {
		return nil
	}
	seen := map[string]string{} // value -> content hash of a record carrying it
	for _, r := range records {
		v := value(r)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; !ok {
			seen[v] = r.ContentHash
		}
	}
	if len(seen) < 2 {
		return nil
	}
	values := make([]string, 0, len(seen))
	for v := range seen {
		values = append(values, v)
	}
	sort.Strings(values)
	hashes := make([]string, 0, len(values))
	for _, v := range values {
		hashes = append(hashes, seen[v])
	}
	return &LicenceConflict{
		Coordinate:      records[0].Coordinate,
		PipelineVersion: records[0].PipelineVersion,
		Field:           field,
		Values:          values,
		ContentHashes:   hashes,
	}
}

// servesBefore orders two records by which should be served first.
func servesBefore(a, b LicenseRecord) bool {
	if a.PrimaryConfidence != b.PrimaryConfidence {
		return a.PrimaryConfidence > b.PrimaryConfidence
	}
	if !a.ExtractedAt.Equal(b.ExtractedAt) {
		return a.ExtractedAt.After(b.ExtractedAt)
	}
	// Neither the ladder nor the clock separates these. The content hash is not
	// authority and is not claimed to be — it is here so the served record does
	// not depend on the order rows happen to come back in.
	return a.ContentHash < b.ContentHash
}
