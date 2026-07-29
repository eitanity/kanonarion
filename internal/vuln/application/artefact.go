package application

import (
	"fmt"

	"github.com/eitanity/kanonarion/internal/vuln/domain"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// derivedFrom is the fetch measurement a vulnerability record was produced from,
// in the form the record persists it. It is threaded through the scan rather than
// re-derived at each write site so every record a single scan produces — clean,
// affected, metadata-only fallback — names the same artefact, and so the sites
// that legitimately have no artefact are the ones that hold the zero value rather
// than the ones that forgot.
type derivedFrom struct {
	// identity is fetchdomain.ArtefactIdentity.String(), or empty when this scan
	// analysed no fetched artefact.
	identity string
	// sourceHash is the content hash of the fetch record identity came from.
	sourceHash string
}

// derivedFromFact reads the measurement a fact record describes.
//
// A record carrying no hashes at all yields the zero derivedFrom rather than an
// error: it records nothing about an artefact, which is a thing a fetch record is
// allowed to be, and a vuln scan must not fail a whole walk over provenance it
// can honestly report as absent. A hash that is present but malformed is still an
// error — corrupt must never read as absent.
func derivedFromFact(fact fetchdomain.FactRecord) (derivedFrom, error) {
	identity, err := fetchdomain.ArtefactIdentityOf(fact)
	if err != nil {
		return derivedFrom{}, fmt.Errorf("deriving artefact identity for %s: %w", fact.Coordinate(), err)
	}
	if identity.IsZero() {
		return derivedFrom{}, nil
	}
	return derivedFrom{identity: identity.String(), sourceHash: fact.ContentHash}, nil
}

// stamp writes the measurement onto a record. It is a no-op for the zero
// derivedFrom, which leaves both fields empty — "not recorded", the honest answer
// for a verdict reached without reading any fetched bytes.
func (d derivedFrom) stamp(r *domain.VulnerabilityRecord) {
	r.ArtefactIdentity = d.identity
	r.SourceContentHash = d.sourceHash
}
