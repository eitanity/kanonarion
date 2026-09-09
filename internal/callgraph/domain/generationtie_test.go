package domain_test

import (
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
)

// Composition is handed generations in append order, and when two of them share
// extracted_at that position is what decides which is newer. The ledger is
// append-only, so the later append is the later run.
//
// Both orders are asserted because a content-hash tiebreak — what the ladder
// fell through to before — is order-independent and would satisfy one of them by
// chance.
func TestCompose_TiedTimestampsServeTheLaterAppend(t *testing.T) {
	t.Parallel()
	tied := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	spec := func(symbol string) composeSpec {
		return composeSpec{
			source: domain.AnalysisSourceWorktree, worktree: "wt-a",
			scanDigest: "scan-a", root: "/trees/a",
			completeness: domain.CompletenessBuiltWithBodies,
			extractedAt:  tied, symbol: symbol,
		}
	}
	for _, order := range [][2]string{{"Foo", "Bar"}, {"Bar", "Foo"}} {
		first := composeRecord(t, spec(order[0]))
		second := composeRecord(t, spec(order[1]))
		// Composed repeatedly over the same input: the answer is the sequence's,
		// not whichever record the pass happened to visit first.
		for i := range 20 {
			got, err := domain.Compose([]domain.CallGraphRecord{first, second}, domain.ComposeRequest{})
			if err != nil {
				t.Fatalf("Compose: %v", err)
			}
			if got.ContentHash != second.ContentHash {
				t.Fatalf("composition %d of [%s %s] served the earlier append", i, order[0], order[1])
			}
		}
	}
}

// The rank itself, stated directly: append order sits below recency and above
// the content hash, and a higher position wins.
func TestGenerationRank_AppendOrderIsTheTiebreakBelowRecency(t *testing.T) {
	t.Parallel()
	earlier := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	later := earlier.Add(time.Second)

	tiedFirst := domain.GenerationRank{ExtractedAt: earlier, AppendOrder: 1, ContentHash: "sha256:a"}
	tiedSecond := domain.GenerationRank{ExtractedAt: earlier, AppendOrder: 2, ContentHash: "sha256:z"}
	if !tiedSecond.ServesBefore(tiedFirst) {
		t.Error("the later append does not outrank the earlier one on a tied timestamp")
	}
	if tiedFirst.ServesBefore(tiedSecond) {
		t.Error("the earlier append outranks the later one; the content hash is still deciding")
	}

	// Recency is above it: an earlier append with a later timestamp still wins.
	newerButEarlierAppend := domain.GenerationRank{ExtractedAt: later, AppendOrder: 1}
	olderButLaterAppend := domain.GenerationRank{ExtractedAt: earlier, AppendOrder: 9}
	if !newerButEarlierAppend.ServesBefore(olderButLaterAppend) {
		t.Error("append order overruled recency; it is the tiebreak below it, not above it")
	}

	// And the content hash still decides when neither position is known, which is
	// what a caller with no append order supplies.
	a := domain.GenerationRank{ExtractedAt: earlier, ContentHash: "sha256:a"}
	z := domain.GenerationRank{ExtractedAt: earlier, ContentHash: "sha256:z"}
	if !a.ServesBefore(z) {
		t.Error("with no append order the content hash no longer decides; the order is not total")
	}
}
