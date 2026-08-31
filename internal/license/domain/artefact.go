package domain

import (
	"fmt"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// RecordArtefactIdentity reads back the artefact identity r was derived from.
//
// The zero identity means the record does not record one — it predates the
// field, or it describes no fetched artefact — and is returned without error, so
// absence is a value a caller can test with IsZero rather than an error it has
// to classify. A field that is present but unreadable is still an error: a
// corrupt identity must never be mistaken for an absent one.
//
// It is a free function rather than a method because LicenseRecord is aliased into
// pkg/kanonarion as a result type, and result types are read shapes that must
// not grow behaviour.
func RecordArtefactIdentity(r LicenseRecord) (fetchdomain.ArtefactIdentity, error) {
	id, err := fetchdomain.StoredArtefactIdentity(r.ArtefactIdentity)
	if err != nil {
		return fetchdomain.ArtefactIdentity{}, fmt.Errorf("reading the artefact identity of the licence finding for %s: %w", r.Coordinate, err)
	}
	return id, nil
}

// NamesAnalysedContent reports whether a record says WHICH content its
// extraction read.
//
// A record that does not is not evidence that it read the same bytes as any
// other, including another that also says nothing: absence is not a value two
// records can share. The write leg refuses a record naming no artefact, so the
// only shape this excludes is a generation written before the field existed —
// which the read leg still serves, and which must not be collapsed with a second
// such generation on the strength of a field neither of them carries.
//
// An identity the store cannot parse says nothing either. RecordArtefactIdentity
// keeps a corrupt identity distinct from an absent one; both are answered here
// with "does not name", because neither shows what was read.
func NamesAnalysedContent(r LicenseRecord) bool {
	id, err := RecordArtefactIdentity(r)
	if err != nil {
		return false
	}
	return !id.IsZero()
}
