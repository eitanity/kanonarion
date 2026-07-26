package domain

import (
	"fmt"
	"sort"

	"github.com/eitanity/kanonarion/internal/coordinate"
)

// Divergence is two records for one coordinate and pipeline version that
// disagree on a hash they BOTH carry: the same pinned version described by two
// different artefacts.
//
// The rule is deliberately "disagreement on a shared hash" rather than "more
// than one artefact hash for a coordinate". A go.mod-only record followed by a
// full record of the same module is the ordinary upgrade path — they agree on
// the go.mod hash they share, and only one of them carries a zip hash at all —
// so the naive rule would report the upgrade as a contradiction. Measured
// against the maintainer's store of 6629 records, the naive rule fires on 90
// legitimate upgrade pairs and a content-hash rule on 1342 keys, while the
// shared-hash rule fires on none: across 1509 coordinates present at more than
// one pipeline version, zero disagree on module_hash and zero on go_mod_hash.
//
// A divergence is always operator-created. A run whose record fails integrity
// exits without appending, so no routine run can add a contradicting record; two
// disagreeing hashes can only arrive via --force. That makes the state rare,
// explicable and recoverable by policy rather than something the fetch path has
// to arbitrate.
type Divergence struct {
	// Coordinate is the module and version the disagreeing records describe.
	Coordinate coordinate.ModuleCoordinate

	// PipelineVersion is the pipeline version both records were written under.
	PipelineVersion string

	// Field names the hash the records disagree on: "module_hash" or
	// "go_mod_hash".
	Field string

	// Values are the distinct values recorded for Field, sorted, so the report
	// is stable across runs.
	Values []string

	// ContentHashes name the records carrying each of Values, in the same order,
	// so an operator can go straight to the rows rather than search for them.
	ContentHashes []string
}

// Error renders the divergence as a message. Divergence satisfies error so the
// consuming commands that fail closed on it can return it directly.
func (d Divergence) Error() string {
	return fmt.Sprintf(
		"divergent fetch records for %s at pipeline %s: %s disagrees (%v; records %v)",
		d.Coordinate, d.PipelineVersion, d.Field, d.Values, d.ContentHashes,
	)
}

// FindDivergence reports the first disagreement among records describing one
// coordinate and pipeline version, or nil when they are consistent.
//
// Records are consistent when, for each hash field, every record that carries a
// value agrees with every other record that carries one. Records that omit a
// field say nothing about it and constrain nothing.
//
// A coordinate at the synthetic local version is exempt. A local version pins no
// content — the working tree behind it is deliberately re-read on every walk —
// so successive measurements are a sequence of observations, not competing
// claims about one pinned artefact.
func FindDivergence(records []FactRecord) *Divergence {
	if len(records) < 2 {
		return nil
	}
	if records[0].Coordinate().IsLocal() {
		return nil
	}
	for _, field := range []struct {
		name  string
		value func(FactRecord) string
	}{
		{"module_hash", func(r FactRecord) string { return r.ModuleHash }},
		{"go_mod_hash", func(r FactRecord) string { return r.GoModHash }},
	} {
		seen := map[string]string{} // hash value -> content hash of a record carrying it
		for _, r := range records {
			v := field.value(r)
			// An omitted hash carries no claim, so it cannot disagree with one.
			if v == "" || v == ZeroString {
				continue
			}
			if _, ok := seen[v]; !ok {
				seen[v] = r.ContentHash
			}
		}
		if len(seen) < 2 {
			continue
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
		return &Divergence{
			Coordinate:      records[0].Coordinate(),
			PipelineVersion: records[0].PipelineVersion,
			Field:           field.name,
			Values:          values,
			ContentHashes:   hashes,
		}
	}
	return nil
}
