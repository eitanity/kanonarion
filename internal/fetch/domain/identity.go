package domain

import "fmt"

// ArtefactIdentity is the content-chosen address of the artefact a fact record
// describes. It is the key the ledger composes on: two records share an identity
// exactly when they describe the same bytes, whatever route those bytes arrived
// by and whichever store happens to hold them.
//
// The identity is the module zip's h1 hash when the zip was fetched, and the
// go.mod's h1 hash when it was not. Both are present on every record since
// schema v1 and both are what sumdb and go.sum speak, so an identity can always
// be derived without consulting a storage handle. The raw SHA-256/384/512
// digests corroborate; they are absent on records predating them and so cannot
// serve as identity.
type ArtefactIdentity struct {
	// Hash is the h1 hash naming the artefact.
	Hash ModuleHash

	// GoModOnly reports that Hash names a go.mod rather than a module zip,
	// because this measurement never fetched the zip. It is what stops a
	// go.mod-only record and a full record of the same coordinate being read as
	// competing claims: they describe one artefact at two depths, and the full
	// record subsumes the shallower one.
	GoModOnly bool
}

// IsZero reports whether no identity could be derived — no module hash and no
// go.mod hash. Such a record names no artefact at all and cannot take part in
// composition.
func (a ArtefactIdentity) IsZero() bool { return a.Hash.IsZero() }

// String renders the identity for keying and for logs. The go.mod-only form is
// prefixed so a go.mod hash can never collide with a zip hash that happens to
// hold the same value.
func (a ArtefactIdentity) String() string {
	if a.IsZero() {
		return ""
	}
	if a.GoModOnly {
		return "gomod:" + a.Hash.String()
	}
	return "zip:" + a.Hash.String()
}

// Equal reports whether two identities name the same artefact at the same depth.
func (a ArtefactIdentity) Equal(other ArtefactIdentity) bool {
	return a.GoModOnly == other.GoModOnly && a.Hash.Equal(other.Hash)
}

// ArtefactIdentityOf derives the identity of a fact record.
//
// Absence is tested with ModuleHash.IsZero and never by string comparison: a
// zero hash persists as ModuleHash.ZeroString, so comparing the stored string
// would collide every go.mod-only record of every module into a single bucket.
// A stored hash that is neither well-formed nor the canonical spelling of
// absence is an error rather than a silently zero identity.
func ArtefactIdentityOf(r FactRecord) (ArtefactIdentity, error) {
	moduleHash, err := StoredModuleHash(r.ModuleHash)
	if err != nil {
		return ArtefactIdentity{}, fmt.Errorf("parsing module hash of %s: %w", r.Coordinate(), err)
	}
	if !moduleHash.IsZero() {
		return ArtefactIdentity{Hash: moduleHash}, nil
	}
	goModHash, err := StoredModuleHash(r.GoModHash)
	if err != nil {
		return ArtefactIdentity{}, fmt.Errorf("parsing go.mod hash of %s: %w", r.Coordinate(), err)
	}
	return ArtefactIdentity{Hash: goModHash, GoModOnly: true}, nil
}

// StoredModuleHash reads a hash as it is held on a record, where absence has two
// spellings: an unset field on an in-memory record, and the ":" a persisted
// record carries because String concatenates an empty algorithm and value. Both
// are the zero hash. Anything else malformed is still an error, so a corrupt
// value can never be mistaken for an absent one.
func StoredModuleHash(s string) (ModuleHash, error) {
	if s == "" {
		return ModuleHash{}, nil
	}
	return ParseModuleHash(s)
}

// MeasurementKind names what a measurement did to reach the record it wrote.
//
// There is deliberately no "unchanged" kind on a record. A cache hit writes
// nothing at all, so there is no row for such a value to sit on, and inventing
// one per run is precisely what converts a ledger of artefacts into a ledger of
// runs. That a run checked and found nothing changed is recorded in the audit
// log, where an event about a run belongs.
type MeasurementKind string

const (
	// MeasurementAcquired means the artefact's bytes were fetched by this
	// measurement, from a proxy, a module cache or a local tree.
	MeasurementAcquired MeasurementKind = "acquired"

	// MeasurementRevalidated means the bytes were already held and re-hashed to
	// the digest already recorded, so they were not downloaded again, while the
	// network anchors (checksum database, VCS) were queried afresh. A
	// revalidated record therefore carries the same class of anchor as a freshly
	// acquired one.
	MeasurementRevalidated MeasurementKind = "revalidated"
)

// ValidationLeg names a check a measurement may perform, and LegProvenance says
// how a given record came by that check's result. Together they are what makes
// an inherited result falsifiable: a leg copied from an earlier measurement
// names the record it came from, so a reader can fetch that record and check the
// copy against its source. Without the name, "inherited" is an unfalsifiable
// claim sitting on a tamper-evident record.
type ValidationLeg struct {
	// Kind names the check.
	Kind ValidationLegKind

	// Provenance says whether the result was established by this measurement or
	// transferred from an earlier one.
	Provenance LegProvenance

	// Source is the content hash of the record the result was inherited from.
	// Empty when Provenance is LegRechecked.
	Source string

	// EstablishedAt is the fetch time of the measurement that actually performed
	// the check — this record's own time when rechecked, the source record's
	// time when inherited.
	EstablishedAt string
}

// ValidationLegKind enumerates the checks a fetch measurement can perform.
type ValidationLegKind string

const (
	// LegSumDB is the checksum-database (transparency log) lookup.
	LegSumDB ValidationLegKind = "sumdb"

	// LegVCS is the cross-verification of the zip against its git source.
	LegVCS ValidationLegKind = "vcs"
)

// LegProvenance discriminates a check performed by this measurement from one
// carried forward.
type LegProvenance string

const (
	// LegAbsent is the zero value: the check was neither performed on this
	// measurement nor inherited. Absence is not a negative result — a --skip-vcs
	// run records no VCS leg, which is a different claim from a VCS check that
	// ran and could not confirm.
	LegAbsent LegProvenance = ""

	// LegRechecked means the check was performed on this measurement.
	LegRechecked LegProvenance = "rechecked"

	// LegInherited means the result was transferred from an earlier record of
	// the same artefact, named by ValidationLeg.Source.
	LegInherited LegProvenance = "inherited"
)

// RecordLegs projects a record's persisted leg provenance onto ValidationLeg
// values, omitting legs the measurement neither performed nor inherited. It is a
// free function on the same terms as RecordDigests: leg composition is fetch
// policy, not read-shape plumbing the public alias is allowed to carry.
func RecordLegs(r FactRecord) []ValidationLeg {
	at := canonicalTime(r.FetchedAt)
	var legs []ValidationLeg
	for _, l := range []ValidationLeg{
		{Kind: LegSumDB, Provenance: LegProvenance(r.SumDBCheck), Source: r.SumDBCheckSource},
		{Kind: LegVCS, Provenance: LegProvenance(r.VCSCheck), Source: r.VCSCheckSource},
	} {
		if l.Provenance == LegAbsent {
			continue
		}
		l.EstablishedAt = at
		legs = append(legs, l)
	}
	return legs
}
