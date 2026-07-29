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
// It is a free function rather than a method because InterfaceRecord is aliased into
// pkg/kanonarion as a result type, and result types are read shapes that must
// not grow behaviour.
func RecordArtefactIdentity(r InterfaceRecord) (fetchdomain.ArtefactIdentity, error) {
	id, err := fetchdomain.StoredArtefactIdentity(r.ArtefactIdentity)
	if err != nil {
		return fetchdomain.ArtefactIdentity{}, fmt.Errorf("reading the artefact identity of the interface record for %s: %w", r.Coordinate, err)
	}
	return id, nil
}
