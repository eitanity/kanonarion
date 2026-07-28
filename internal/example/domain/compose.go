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
var ErrNoRecordsToCompose = errors.New("no example records to compose")

// ExampleConflict is two example records that describe one pinned module version
// and name different artefacts.
//
// It is deliberately narrow. An example extraction that reports different
// findings for the same artefact is ordered by the ladder Compose implements —
// a run with fewer parse failures is strictly better evidence about the same
// bytes, not a competing answer — so disagreement about WHAT was found is
// composed rather than reported. What has no ladder at all is disagreement about
// WHICH BYTES were read: two artefact identities for one pinned version means
// the same module at the same version yielded two different sets of bytes, and
// serving either answers a question about bytes the caller never named.
//
// It mirrors fetch's Divergence and licence's LicenceConflict, including
// reporting the content hashes of the records carrying each value so an operator
// can go straight to the rows.
type ExampleConflict struct {
	// Coordinate is the module and version the disagreeing records describe.
	Coordinate coordinate.ModuleCoordinate

	// PipelineVersion is the pipeline version every conflicting record was
	// written under.
	PipelineVersion string

	// Field names what the records disagree on. Today always
	// "artefact_identity"; the field is carried so the report reads the same as
	// the licence one and so a later rung can be added without changing shape.
	Field string

	// Values are the distinct values recorded for Field, sorted, so the report is
	// stable across runs.
	Values []string

	// ContentHashes name the records carrying each of Values, in the same order.
	ContentHashes []string
}

// Error renders the conflict as a message. ExampleConflict satisfies error so
// the store can return it directly.
func (c ExampleConflict) Error() string {
	return fmt.Sprintf(
		"conflicting example records for %s at pipeline %s: %s disagrees (%v; records %v)",
		c.Coordinate, c.PipelineVersion, c.Field, c.Values, c.ContentHashes,
	)
}

// Compose returns the example record a reader gets for one coordinate and
// pipeline version, given every record the ledger holds for it.
//
// Records must be supplied in the order they were appended, and each must
// already have verified its own content hash: a record that cannot be checked
// stops the read before it reaches here, so composition never has to decide what
// to do about an unverifiable row.
//
// The ladder is COMPLETED EXTRACTION first, then FEWEST PARSE FAILURES, then
// recency. Recency is never authority on its own: an extraction that regresses
// to more parse failures must not displace a cleaner earlier one merely by
// running later, which is the same defect the fetch ledger's anchor-strength
// ordering exists to prevent.
//
// The first rung is what keeps the ladder honest. An example record persists its
// parse failures, so "0 examples" carries two meanings that must not be
// conflated — a module that genuinely has none, and a measurement that failed —
// and a failed extraction records NO parse failures at all, because it never got
// as far as parsing a file. Ordering on the failure count alone would therefore
// rank a total failure above a partial success, which inverts exactly the
// distinction the count exists to draw.
func Compose(records []ExampleRecord) (ExampleRecord, error) {
	if len(records) == 0 {
		return ExampleRecord{}, ErrNoRecordsToCompose
	}
	if records[0].Coordinate.IsLocal() {
		// A local version pins no content — the working tree behind it is
		// deliberately re-read on every run, and the extraction path never serves
		// it from cache for exactly that reason — so its records are a SEQUENCE of
		// observations of a changing tree, not competing claims about one pinned
		// artefact. The last one is the only correct answer: serving a cleaner
		// earlier record would hand back a state of the tree that no longer exists,
		// so deleting an example would silently fail to register.
		//
		// "Last" is by position, not by timestamp. extracted_at persists at second
		// precision, so two runs within one second carry the same time and a
		// timestamp comparison cannot order them. The ledger is append-only and the
		// store lists in insertion order, which is the sequence.
		return records[len(records)-1], nil
	}

	candidates := identifiedOrAll(records)
	if c := findConflict(candidates); c != nil {
		return ExampleRecord{}, *c
	}

	ordered := make([]ExampleRecord, len(candidates))
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
func identifiedOrAll(records []ExampleRecord) []ExampleRecord {
	identified := make([]ExampleRecord, 0, len(records))
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

// findConflict reports the disagreement that composition must not resolve by
// picking, or nil when the records can be laddered.
func findConflict(records []ExampleRecord) *ExampleConflict {
	if len(records) < 2 {
		return nil
	}
	// It cannot fire on the upgrade path — identifiedOrAll has already removed the
	// records that name no artefact — so reaching here means two measurements each
	// named an artefact and named different ones.
	seen := map[string]string{} // identity -> content hash of a record carrying it
	for _, r := range records {
		if r.ArtefactIdentity == "" {
			continue
		}
		if _, ok := seen[r.ArtefactIdentity]; !ok {
			seen[r.ArtefactIdentity] = r.ContentHash
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
	return &ExampleConflict{
		Coordinate:      records[0].Coordinate,
		PipelineVersion: records[0].PipelineVersion,
		Field:           "artefact_identity",
		Values:          values,
		ContentHashes:   hashes,
	}
}

// completed reports whether the extraction ran to a conclusion about the module,
// as opposed to failing or being cancelled before it could reach one.
//
// ExampleStatusNone is a completed extraction: it says the module has no
// Example* functions, which is a fact about the module. ExtractionFailed and
// Cancelled say nothing about the module at all.
func completed(r ExampleRecord) bool {
	return r.OverallStatus == ExampleStatusFound || r.OverallStatus == ExampleStatusNone
}

// servesBefore orders two records by which should be served first.
func servesBefore(a, b ExampleRecord) bool {
	if ca, cb := completed(a), completed(b); ca != cb {
		return ca
	}
	if len(a.ParseFailures) != len(b.ParseFailures) {
		return len(a.ParseFailures) < len(b.ParseFailures)
	}
	if !a.ExtractedAt.Equal(b.ExtractedAt) {
		return a.ExtractedAt.After(b.ExtractedAt)
	}
	// Neither the ladder nor the clock separates these. The content hash is not
	// authority and is not claimed to be — it is here so the served record does
	// not depend on the order rows happen to come back in.
	return a.ContentHash < b.ContentHash
}
