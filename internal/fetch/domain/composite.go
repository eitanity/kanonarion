package domain

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

// ErrNoRecordsToCompose is returned by Compose when handed no records. It is a
// programming error rather than an absence: absence is reported by the store as
// "not found", and composing nothing has no meaningful answer.
var ErrNoRecordsToCompose = errors.New("no fetch records to compose")

// CompositeRecord is what domains outside fetch receive: not a row, but the
// artefact as the ledger knows it.
//
// The ledger holds one row per measurement, and several measurements may
// describe one artefact — a network fetch, a later module-cache measurement, a
// forced revalidation. A reader wants the artefact, so composition folds those
// rows into a single answer: the identity they share, when the artefact was
// first seen, when it was last measured, which record is authoritative to serve,
// and the union of the validation legs any measurement established.
//
// The served record is embedded, so every existing field read continues to mean
// what it always meant, and the embedded record still verifies its own content
// hash — composition never mints a record that cannot be checked. The composed
// facts that are not properties of any single row sit alongside it. In
// particular FirstFetchedAt, not the embedded FetchedAt, is the date "when was
// this module fetched" should be answered with: the embedded record's own
// FetchedAt is the time of the measurement being served, which for a
// revalidation is not when the artefact was first seen.
type CompositeRecord struct {
	// FactRecord is the record composition serves: the strongest cache-eligible
	// measurement of this artefact. It is embedded whole and unaltered.
	FactRecord

	// Identity is the artefact identity every composed record shares.
	Identity ArtefactIdentity `json:"identity"`

	// FirstFetchedAt is the earliest measurement bearing this identity — when
	// these bytes were first seen. Deleting a blob and re-acquiring it does not
	// move it.
	FirstFetchedAt time.Time `json:"first_fetched_at"`

	// LatestFetchedAt is the most recent measurement of this artefact.
	LatestFetchedAt time.Time `json:"latest_fetched_at"`

	// Legs is the union of the validation legs established across the composed
	// records, each carrying the date it was established and whether the record
	// carrying it rechecked it or inherited it. A leg no measurement performed
	// is absent from the slice — which is a different claim from a check that
	// ran and answered negatively.
	Legs []ValidationLeg `json:"legs,omitempty"`

	// MeasurementCount is how many records were composed.
	MeasurementCount int `json:"measurement_count"`
}

// Compose folds the measurements of one artefact into the record a reader gets.
//
// Every record handed in must already have been rehydrated, so composition never
// has to decide what to do about an unverifiable row: a bad row stops the read
// before it reaches here.
//
// The served record is the STRONGEST ELIGIBLE measurement, not simply the most
// recent. Serving the newest would reinstate the defect that made a failed
// checksum-database lookup permanent: a record whose lookup never answered,
// appended after a good one, would become the answer on every subsequent run
// until an operator forced a re-measurement. Eligibility is therefore applied
// first (a record whose sumdb lookup failed describes the lookup, not the
// module, and cannot be served), then anchor strength, then schema version, then
// recency. When no record is eligible the strongest ineligible one is served, so
// a store holding only failed-lookup measurements still answers rather than
// reporting absence.
func Compose(records []FactRecord) (CompositeRecord, error) {
	if len(records) == 0 {
		return CompositeRecord{}, ErrNoRecordsToCompose
	}

	identity, err := ArtefactIdentityOf(records[0])
	if err != nil {
		return CompositeRecord{}, err
	}

	var served FactRecord
	if records[0].Coordinate().IsLocal() {
		// A local version pins no content — the working tree behind it is
		// deliberately re-read on every walk — so its measurements are a SEQUENCE
		// of observations of a changing tree, not competing claims about one
		// pinned artefact. The last one is the only correct answer: serving any
		// earlier one hands back a state of the tree that no longer exists, so an
		// edit made between two runs silently fails to appear.
		//
		// "Last" is by position, not by timestamp. fetched_at persists at second
		// precision, so two runs within the same second carry the same time and a
		// timestamp comparison cannot order them. The ledger is append-only, so
		// its own insertion order — which the store preserves when listing — is
		// the sequence, and the caller passes the records in it.
		served = records[len(records)-1]
		for _, r := range records {
			if r.FetchedAt.After(served.FetchedAt) {
				served = r
			}
		}
		// The identity is the served measurement's own: successive measurements of
		// a working tree describe different artefacts, so there is no shared
		// identity to take from the first record.
		identity, err = ArtefactIdentityOf(served)
		if err != nil {
			return CompositeRecord{}, err
		}
	} else {
		ordered := make([]FactRecord, len(records))
		copy(ordered, records)
		sort.SliceStable(ordered, func(i, j int) bool { return servesBefore(ordered[i], ordered[j]) })
		served = ordered[0]
	}

	first, latest := records[0].FetchedAt, records[0].FetchedAt
	for _, r := range records[1:] {
		if r.FetchedAt.Before(first) {
			first = r.FetchedAt
		}
		if r.FetchedAt.After(latest) {
			latest = r.FetchedAt
		}
	}

	return CompositeRecord{
		FactRecord:       served,
		Identity:         identity,
		FirstFetchedAt:   first.UTC(),
		LatestFetchedAt:  latest.UTC(),
		Legs:             composeLegs(records),
		MeasurementCount: len(records),
	}, nil
}

// canonicalComposite is the fixed-field-order struct used to serialise a
// composite deterministically, on the same terms as canonicalRecord: keys in
// lexicographic order, times RFC3339 UTC, so the bytes are stable regardless of
// Go struct field ordering. The served record is nested as its own canonical
// JSON rather than flattened, so a reader can lift it out and verify its content
// hash without reassembling anything.
type canonicalComposite struct {
	FirstFetchedAt   string          `json:"first_fetched_at"`
	Identity         string          `json:"identity"`
	LatestFetchedAt  string          `json:"latest_fetched_at"`
	Legs             []canonicalLeg  `json:"legs,omitempty"`
	MeasurementCount int             `json:"measurement_count"`
	Record           json.RawMessage `json:"record"`
}

// canonicalLeg is the serialised form of a ValidationLeg.
type canonicalLeg struct {
	EstablishedAt string `json:"established_at"`
	Kind          string `json:"kind"`
	Provenance    string `json:"provenance"`
	Source        string `json:"source,omitempty"`
}

// MarshalComposite returns the canonical JSON bytes for a composite record.
func (h CanonicalHasher) MarshalComposite(c CompositeRecord) ([]byte, error) {
	record, err := h.Marshal(c.FactRecord)
	if err != nil {
		return nil, fmt.Errorf("marshalling served record: %w", err)
	}
	legs := make([]canonicalLeg, 0, len(c.Legs))
	for _, l := range c.Legs {
		legs = append(legs, canonicalLeg{
			EstablishedAt: l.EstablishedAt,
			Kind:          string(l.Kind),
			Provenance:    string(l.Provenance),
			Source:        l.Source,
		})
	}
	if len(legs) == 0 {
		legs = nil
	}
	b, err := canonicalMarshal(canonicalComposite{
		FirstFetchedAt:   canonicalTime(c.FirstFetchedAt),
		Identity:         c.Identity.String(),
		LatestFetchedAt:  canonicalTime(c.LatestFetchedAt),
		Legs:             legs,
		MeasurementCount: c.MeasurementCount,
		Record:           record,
	})
	if err != nil {
		return nil, fmt.Errorf("marshalling canonical composite: %w", err)
	}
	return b, nil
}

// UnmarshalComposite parses a composite from its canonical JSON. It is the
// inverse of MarshalComposite.
func (h CanonicalHasher) UnmarshalComposite(data []byte) (CompositeRecord, error) {
	var c canonicalComposite
	if err := json.Unmarshal(data, &c); err != nil {
		return CompositeRecord{}, fmt.Errorf("unmarshalling canonical composite: %w", err)
	}
	record, err := h.Unmarshal(c.Record)
	if err != nil {
		return CompositeRecord{}, err
	}
	identity, err := ArtefactIdentityOf(record)
	if err != nil {
		return CompositeRecord{}, err
	}
	first, err := time.Parse(time.RFC3339, c.FirstFetchedAt)
	if err != nil {
		return CompositeRecord{}, fmt.Errorf("parsing first_fetched_at %q: %w", c.FirstFetchedAt, err)
	}
	latest, err := time.Parse(time.RFC3339, c.LatestFetchedAt)
	if err != nil {
		return CompositeRecord{}, fmt.Errorf("parsing latest_fetched_at %q: %w", c.LatestFetchedAt, err)
	}
	var legs []ValidationLeg
	for _, l := range c.Legs {
		legs = append(legs, ValidationLeg{
			Kind:          ValidationLegKind(l.Kind),
			Provenance:    LegProvenance(l.Provenance),
			Source:        l.Source,
			EstablishedAt: l.EstablishedAt,
		})
	}
	return CompositeRecord{
		FactRecord:       record,
		Identity:         identity,
		FirstFetchedAt:   first.UTC(),
		LatestFetchedAt:  latest.UTC(),
		Legs:             legs,
		MeasurementCount: c.MeasurementCount,
	}, nil
}

// servesBefore orders records so the one that should be served sorts first.
// Eligibility dominates, then anchor strength, then schema version, then
// recency; the content hash breaks remaining ties so composition is
// deterministic across runs rather than dependent on row order.
//
// It is not used for a local coordinate, which Compose handles separately: a
// local version pins no content, so its measurements are a sequence rather than
// competing claims and the last one always wins.
func servesBefore(a, b FactRecord) bool {
	if ea, eb := RecordIsCacheable(a), RecordIsCacheable(b); ea != eb {
		return ea
	}
	if sa, sb := verificationStrength(VerificationStatus(a.VerificationStatus)), verificationStrength(VerificationStatus(b.VerificationStatus)); sa != sb {
		return sa > sb
	}
	if a.SchemaVersion != b.SchemaVersion {
		return a.SchemaVersion > b.SchemaVersion
	}
	if !a.FetchedAt.Equal(b.FetchedAt) {
		return a.FetchedAt.After(b.FetchedAt)
	}
	return a.ContentHash < b.ContentHash
}

// composeLegs unions the validation legs across the composed records, keeping
// for each kind the leg established most recently by a measurement that actually
// performed the check. A rechecked leg beats an inherited one of the same date,
// because the inherited one is a copy of some earlier recheck and the recheck
// itself is the primary evidence.
func composeLegs(records []FactRecord) []ValidationLeg {
	best := map[ValidationLegKind]ValidationLeg{}
	for _, r := range records {
		for _, leg := range RecordLegs(r) {
			cur, ok := best[leg.Kind]
			if !ok || legIsBetter(leg, cur) {
				best[leg.Kind] = leg
			}
		}
	}
	out := make([]ValidationLeg, 0, len(best))
	for _, kind := range []ValidationLegKind{LegSumDB, LegVCS} {
		if leg, ok := best[kind]; ok {
			out = append(out, leg)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// legIsBetter reports whether candidate should replace current as the composed
// evidence for a leg kind.
func legIsBetter(candidate, current ValidationLeg) bool {
	if candidate.EstablishedAt != current.EstablishedAt {
		return candidate.EstablishedAt > current.EstablishedAt
	}
	return candidate.Provenance == LegRechecked && current.Provenance == LegInherited
}
