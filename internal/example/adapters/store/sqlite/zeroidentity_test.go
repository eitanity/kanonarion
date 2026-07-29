package sqlite_test

import (
	"context"
	"testing"

	domain2 "github.com/eitanity/kanonarion/internal/example/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
)

// TestRefusesZeroArtefactIdentity pins the write-leg rule at this store.
//
// Every record it holds comes from an extraction that read a fetched artefact,
// so one that cannot name which artefact is a fault in the stage. It matters
// more than the zero-coordinate refusal beside it: composition reads the
// identity to decide which records describe the same bytes, so a zero identity
// does not merely record nothing — it groups together every record that also
// recorded nothing.
//
// Deliberately one-legged. The read path must keep serving records written
// before the field existed, which carry an empty identity legitimately.
func TestRefusesZeroArtefactIdentity(t *testing.T) {
	s := openTestStore(t)
	rec := buildRecord(t, mustCoord(t, "example.com/mod", "v1.0.0"), 1, domain2.ExampleStatusFound)
	rec.ArtefactIdentity = ""

	fetchtest.AssertRefusesZeroIdentity(t, "PutExampleRecord", func() error {
		return s.PutExampleRecord(context.Background(), rec)
	})
}
