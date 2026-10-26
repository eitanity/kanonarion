package cli

import (
	"errors"
	"fmt"
	"testing"

	"code.eitanity.com/kanonarion/internal/fetch/fetchtest"
	fetchports "code.eitanity.com/kanonarion/internal/fetch/ports"
)

func testRefusal(value string) *fetchports.BlobTamperedError {
	return &fetchports.BlobTamperedError{Identity: fetchtest.Blob(fetchports.BlobKindZip, fetchtest.H1(value)), Observed: "h1:other"}
}

// A refused stored artefact is evidence in doubt, and it outranks the code a
// command chose for the gap it left: a policy verdict or a partial copy made
// over refused bytes is not the answer.
func TestExitCodeForError_ARefusedArtefactIsEvidenceInDoubt(t *testing.T) {
	refusal := testRefusal("x")
	for name, err := range map[string]error{
		"bare":                 refusal,
		"wrapped":              fmt.Errorf("extracting license: %w", refusal),
		"beside a policy exit": errors.Join(&exitError{code: ExitPolicy, msg: "blocked"}, refusal),
		"a child's text":       fmt.Errorf("callgraph stage: %w: line", fetchports.ErrBlobTampered),
	} {
		if got := ExitCodeForError(err); got != ExitIntegrity {
			t.Errorf("%s: exit %d, want %d", name, got, ExitIntegrity)
		}
	}
}

// The run's answer is the refusal's own sentence, from the error chain when a
// reader returned it and from the store's record when a reader absorbed it; a
// refusal a later write replaced no longer stands.
func TestSurfaceBlobRefusal(t *testing.T) {
	t.Cleanup(blobRefusals.reset)
	refusal := testRefusal("chain")

	got := surfaceBlobRefusal(fmt.Errorf("extracting: %w", refusal))
	if got.Error() != refusal.Error() || !errors.Is(got, fetchports.ErrBlobTampered) {
		t.Errorf("a refusal in the chain renders %q", got)
	}
	child := fmt.Errorf("callgraph stage: %w: line", fetchports.ErrBlobTampered)
	if rewritten := surfaceBlobRefusal(child); rewritten.Error() != child.Error() {
		t.Errorf("a child's refusal was rewritten: %v", rewritten)
	}
	if clean := surfaceBlobRefusal(nil); clean != nil {
		t.Errorf("a clean run became %v", clean)
	}

	absorbed := testRefusal("absorbed")
	blobRefusals.observe(absorbed.Identity, absorbed)
	got = surfaceBlobRefusal(nil)
	if got == nil || got.Error() != absorbed.Error() || ExitCodeForError(got) != ExitIntegrity {
		t.Fatalf("an absorbed refusal surfaced as %v", got)
	}
	other := errors.New("the command's own failure")
	if both := surfaceBlobRefusal(other); !errors.Is(both, other) || !errors.Is(both, fetchports.ErrBlobTampered) {
		t.Errorf("the command's error and the refusal must both stay on the chain: %v", both)
	}

	blobRefusals.observe(absorbed.Identity, nil)
	if withdrawn := surfaceBlobRefusal(nil); withdrawn != nil {
		t.Errorf("a replaced artefact's refusal still stands: %v", withdrawn)
	}
}

// use exits on a refused artefact rather than on how much of the selection
// reached the cache.
func TestUseCopyExit_ARefusalOutranksTheCount(t *testing.T) {
	refusal := testRefusal("use")
	tally := useTally{outcomes: []useOutcome{
		{kind: useCopied},
		{kind: useFailed, err: errors.New("no record")},
		{kind: useFailed, err: fmt.Errorf("copying: %w", refusal)},
	}}
	if err := useCopyExit(tally); !errors.Is(err, fetchports.ErrBlobTampered) {
		t.Errorf("useCopyExit = %v, want the refusal", err)
	}
}
