// Package fetchfacts reads a module's recorded origin from the fetch ledger so
// an SBOM can carry references to where the bytes actually came from instead of
// URLs assembled from the module path.
package fetchfacts

import (
	"context"
	"fmt"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	sbomports "github.com/eitanity/kanonarion/internal/sbom/ports"
)

// Reader answers what the fetch ledger recorded about a module's origin.
type Reader struct {
	facts fetchports.FactStore
}

// New returns a Reader over the given fact store.
func New(facts fetchports.FactStore) *Reader {
	return &Reader{facts: facts}
}

// ModuleOrigin implements sbomports.ModuleOriginReader.
//
// It answers from the composed record — the strongest cache-eligible
// measurement of the artefact — and it answers only for a module whose zip was
// positively cross-verified against its repository.
//
// The gate is deliberately that narrow. A fact record can carry a git URL that
// nothing confirmed: the URL is inferred from the module path when the proxy
// supplies no Origin metadata, and a record whose VCS leg could not run keeps
// that inferred URL beside a status saying the check never answered. Emitting
// it would put the guess back into the document under the appearance of a
// measurement. Only VerificationStatus Verified means the bytes in this
// component were read out of that repository at that commit, which is the
// claim an external VCS reference makes.
//
// Not found is the ordinary case, not a failure: the local main module is never
// fetched, an offline run has no VCS leg, and --skip-vcs-verify removes it on
// purpose. Each of those means the document says nothing about that module's
// origin.
func (r *Reader) ModuleOrigin(ctx context.Context, coord coordinate.ModuleCoordinate) (sbomports.ModuleOrigin, bool, error) {
	rec, found, err := fetchports.ComposedFetchRecord(ctx, r.facts, coord)
	if err != nil {
		return sbomports.ModuleOrigin{}, false, fmt.Errorf("reading fetch record for %s: %w", coord, err)
	}
	if !found {
		return sbomports.ModuleOrigin{}, false, nil
	}
	if fetchdomain.VerificationStatus(rec.VerificationStatus) != fetchdomain.Verified {
		return sbomports.ModuleOrigin{}, false, nil
	}
	if rec.GitURL == "" || rec.GitCommitHash == "" {
		return sbomports.ModuleOrigin{}, false, nil
	}
	return sbomports.ModuleOrigin{
		VCSURL:    rec.GitURL,
		VCSRef:    rec.GitRef,
		VCSCommit: rec.GitCommitHash,
	}, true, nil
}
