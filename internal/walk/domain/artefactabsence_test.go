package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/walk/domain"
)

// Three resolution sources name a module that no fetch ever acquired bytes for.
// A consumer looking a fetch record up for one of them can only miss, and a miss
// there is an absence by construction rather than something that went wrong.
func TestHasFetchedArtefact(t *testing.T) {
	unfetched := map[domain.ResolutionSource]string{
		domain.ResolutionLocalMainModule: "local main module",
		domain.ResolutionLocalReplace:    "local replace",
		domain.ResolutionStdlib:          "Go standard library",
	}
	for source, noun := range unfetched {
		if source.HasFetchedArtefact() {
			t.Errorf("%q has no fetched artefact", source)
		}
		if got := source.ArtefactAbsenceNoun(); got != noun {
			t.Errorf("%q: want noun %q, got %q", source, noun, got)
		}
	}

	// Everything else owes an artefact — including a value this build does not
	// recognise, so a genuine miss is reported rather than silently exempted.
	for _, source := range []domain.ResolutionSource{
		domain.ResolutionTarget,
		domain.ResolutionMVS,
		domain.ResolutionReplace,
		domain.ResolutionLocalAnalysed,
		domain.ResolutionFetchFailed,
		domain.ResolutionParseFailed,
		domain.ResolutionSource("added after this build"),
	} {
		if !source.HasFetchedArtefact() {
			t.Errorf("%q owes an artefact", source)
		}
		if got := source.ArtefactAbsenceNoun(); got != "" {
			t.Errorf("%q owns an artefact, so it names no absence; got %q", source, got)
		}
	}
}
