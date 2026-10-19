package domain

import (
	"fmt"

	"github.com/eitanity/kanonarion/internal/coordinate"
)

// SupersededLocalGenerations splits the measurements of coord into the ones a
// read composes and the ones it leaves out.
//
// A tree read from disk is recorded at <path>@local, so a local-source row under
// a published coordinate can only predate that identity: it describes a
// directory, not the published bytes, and composing it with them reads as a
// divergence. The row stays in the ledger and is reported, never composed.
func SupersededLocalGenerations(coord coordinate.ModuleCoordinate, records []FactRecord) (kept, superseded []FactRecord) {
	if coord.IsLocal() {
		return records, nil
	}
	for _, r := range records {
		if VerificationStatus(r.VerificationStatus) == LocalSource {
			superseded = append(superseded, r)
			continue
		}
		kept = append(kept, r)
	}
	return kept, superseded
}

// SupersededLocalArtefacts is the artefact identities of coord that the ledger
// holds only as local-source measurements: records derived from them describe
// a directory, so a read of the published coordinate leaves them out too. An
// identity a published measurement also carries is not superseded.
func SupersededLocalArtefacts(coord coordinate.ModuleCoordinate, records []FactRecord) (map[string]bool, error) {
	kept, superseded := SupersededLocalGenerations(coord, records)
	if len(superseded) == 0 {
		return nil, nil
	}
	published := make(map[string]bool, len(kept))
	for _, r := range kept {
		id, err := ArtefactIdentityOf(r)
		if err != nil {
			return nil, err
		}
		published[id.String()] = true
	}
	out := map[string]bool{}
	for _, r := range superseded {
		id, err := ArtefactIdentityOf(r)
		if err != nil {
			return nil, err
		}
		if !published[id.String()] {
			out[id.String()] = true
		}
	}
	return out, nil
}

// SupersededOnlyStatement is how every surface says that a published
// coordinate holds generations and none answers: all n derive from a directory
// read under it before local code had its own identity.
func SupersededOnlyStatement(n int, coord coordinate.ModuleCoordinate) string {
	return fmt.Sprintf("the store holds %d generation(s) of %s, all derived from a directory read under this published coordinate and superseded by identity", n, coord)
}
