package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
)

// ErrNoRecordsToCompose is returned by Compose when handed no records. It is a
// programming error rather than an absence: absence is reported by the store as
// "not found", and composing nothing has no meaningful answer.
var ErrNoRecordsToCompose = errors.New("no interface records to compose")

// InterfaceConflict is two interface records that composition must not resolve
// by picking.
//
// It reports two distinct disagreements, and the distinction between them is the
// point of the ticket that introduced this type.
//
//   - "artefact_identity": two identities for one pinned module version, which
//     means the same module at the same version yielded two different sets of
//     bytes. There is no ladder between answers about different bytes.
//   - "public_api": two records describing the SAME artefact at the SAME
//     extraction status that disagree about the exported API. That narrow case is
//     evidence of non-determinism in the extractor and is worth surfacing rather
//     than absorbing.
//
// The second is deliberately narrow. A public API is close to a function of the
// artefact's bytes, but not purely: type resolution for exported generic and
// embedded types draws on dependency type information, and a package that could
// not be parsed on one run can parse on the next for reasons that have nothing to
// do with the bytes. Those runs differ in STATUS, the ladder orders them, and a
// complete extraction is strictly better evidence than a partial one. Only when
// the ladder cannot separate two records is a disagreement between them a finding
// rather than a refinement.
//
// It mirrors fetch's Divergence and licence's LicenceConflict, including
// reporting the content hashes of the records carrying each value.
type InterfaceConflict struct {
	// Coordinate is the module and version the disagreeing records describe.
	Coordinate coordinate.ModuleCoordinate

	// PipelineVersion is the pipeline version every conflicting record was
	// written under.
	PipelineVersion string

	// Field names what the records disagree on: "artefact_identity" or
	// "public_api".
	Field string

	// Values are the distinct values recorded for Field, sorted, so the report is
	// stable across runs.
	Values []string

	// ContentHashes name the records carrying each of Values, in the same order.
	ContentHashes []string
}

// Error renders the conflict as a message. InterfaceConflict satisfies error so
// the store can return it directly.
func (c InterfaceConflict) Error() string {
	return fmt.Sprintf(
		"conflicting interface records for %s at pipeline %s: %s disagrees (%v; records %v)",
		c.Coordinate, c.PipelineVersion, c.Field, c.Values, c.ContentHashes,
	)
}

// Compose returns the interface record a reader gets for one coordinate and
// pipeline version, given every record the ledger holds for it.
//
// Records must be supplied in the order they were appended, and each must
// already have verified its own content hash: a record that cannot be checked
// stops the read before it reaches here, so composition never has to decide what
// to do about an unverifiable row.
//
// The ladder is EXTRACTION STATUS, then recency. A complete extraction outranks
// a Partial one regardless of which was written later, exactly as the fetch
// ledger serves the strongest anchor rather than the newest measurement: a
// Partial record missed at least one package to a parse failure, so it is a
// weaker measurement of the same API, not a competing answer. Recency is only
// ever the last tiebreaker.
func Compose(records []InterfaceRecord) (InterfaceRecord, error) {
	if len(records) == 0 {
		return InterfaceRecord{}, ErrNoRecordsToCompose
	}
	if records[0].Coordinate.IsLocal() {
		// A local version pins no content — the working tree behind it is
		// deliberately re-read on every run — so its records are a SEQUENCE of
		// observations of a changing tree, not competing claims about one pinned
		// artefact. The last one is the only correct answer: serving a
		// higher-status earlier record would hand back an API the tree no longer
		// has, so deleting an exported symbol would silently fail to register.
		//
		// "Last" is by position, not by timestamp. extracted_at persists at second
		// precision, so two runs within one second carry the same time and a
		// timestamp comparison cannot order them. The ledger is append-only and the
		// store lists in insertion order, which is the sequence.
		return records[len(records)-1], nil
	}

	candidates := identifiedOrAll(records)
	if c := findConflict(candidates); c != nil {
		return InterfaceRecord{}, *c
	}

	ordered := make([]InterfaceRecord, len(candidates))
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
// read still returns them.
func identifiedOrAll(records []InterfaceRecord) []InterfaceRecord {
	identified := make([]InterfaceRecord, 0, len(records))
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

// findConflict reports the first disagreement composition must not resolve by
// picking, or nil when the records can be laddered.
func findConflict(records []InterfaceRecord) *InterfaceConflict {
	if len(records) < 2 {
		return nil
	}

	// It cannot fire on the upgrade path — identifiedOrAll has already removed the
	// records that name no artefact — so reaching here means two measurements each
	// named an artefact and named different ones.
	if c := disagreement(records, "artefact_identity",
		func(r InterfaceRecord) string { return r.ArtefactIdentity }); c != nil {
		return c
	}

	// Within one artefact, only records the ladder cannot separate can conflict.
	// A Partial extraction disagreeing with a complete one is the refinement case
	// the ladder exists to resolve; two records at the SAME status disagreeing
	// about the exported API is non-determinism in the extractor.
	//
	// The rung is exact here, unlike the licence conversion's confidence band. The
	// status is an enum with five values, not a float derived from coverage
	// percentages, so equality is a real equivalence rather than a coincidence
	// that essentially never happens.
	top := rank(records[0])
	for _, r := range records[1:] {
		if rank(r) > top {
			top = rank(r)
		}
	}
	tied := make([]InterfaceRecord, 0, len(records))
	for _, r := range records {
		// A failed or cancelled extraction makes no claim about the API at all, so
		// it cannot contradict one that does. Letting it take part would report
		// every "extraction failed, then extracted" pair as non-determinism.
		if rank(r) == top && rank(r) > 0 {
			tied = append(tied, r)
		}
	}
	return disagreement(tied, "public_api", APIDigest)
}

// disagreement reports the distinct values of one field across records, as a
// conflict, when there is more than one.
func disagreement(records []InterfaceRecord, field string, value func(InterfaceRecord) string) *InterfaceConflict {
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
	return &InterfaceConflict{
		Coordinate:      records[0].Coordinate,
		PipelineVersion: records[0].PipelineVersion,
		Field:           field,
		Values:          values,
		ContentHashes:   hashes,
	}
}

// APIDigest is a hash of everything a record says about the exported API, and of
// nothing else.
//
// It exists because ContentHash cannot answer "do these two records agree". The
// content hash covers the time of measurement and the provenance of the bytes,
// so two runs of an extractor that produced the identical API a second apart
// carry different content hashes. Blanking those three fields leaves the claim.
//
// It is NOT a second seal and is never persisted. It reuses the canonical
// marshal, so it changes only when the hashed shape does, and no stored record's
// own hash depends on it.
func APIDigest(r InterfaceRecord) string {
	r.ContentHash = ""
	r.ExtractedAt = time.Time{}
	// Which fetch measurement supplied the bytes is provenance, not API. Two fetch
	// records of identical bytes carry the same artefact identity and different
	// content hashes, and this comparison only ever runs between records whose
	// artefact identity already matches.
	r.SourceContentHash = ""
	data, err := marshalCanonical(r)
	if err != nil {
		// marshalCanonical fails only on a value json.Marshal cannot encode, which
		// this shape has none of. Returning a distinct marker rather than a
		// plausible digest keeps a failure from reading as agreement.
		return "unhashable:" + err.Error()
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// rank orders extraction statuses by how much they are worth as evidence about
// the exported API. Higher is better; 0 means the extraction says nothing about
// the API at all.
func rank(r InterfaceRecord) int {
	switch r.OverallStatus {
	case InterfaceStatusExtracted:
		return 2
	case InterfaceStatusPartial:
		return 1
	case InterfaceStatusUnknown, InterfaceStatusExtractionFailed, InterfaceStatusCancelled:
		return 0
	default:
		return 0
	}
}

// servesBefore orders two records by which should be served first.
func servesBefore(a, b InterfaceRecord) bool {
	if ra, rb := rank(a), rank(b); ra != rb {
		return ra > rb
	}
	if !a.ExtractedAt.Equal(b.ExtractedAt) {
		return a.ExtractedAt.After(b.ExtractedAt)
	}
	// Neither the ladder nor the clock separates these. The content hash is not
	// authority and is not claimed to be — it is here so the served record does
	// not depend on the order rows happen to come back in.
	return a.ContentHash < b.ContentHash
}
