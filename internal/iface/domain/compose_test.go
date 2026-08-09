package domain_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/iface/domain"
)

// composed is one record on the ledger, spelled short because these tests are
// about which of several records a reader gets and never about their contents.
type composed struct {
	status    domain.InterfaceStatus
	artefact  string
	hash      string
	at        time.Time
	funcName  string
	local     bool
	srcHash   string
	pipeline  string
	coordPath string
}

func composedRecord(t *testing.T, c composed) domain.InterfaceRecord {
	t.Helper()
	path := c.coordPath
	if path == "" {
		path = "example.com/mod"
	}
	coord := coordinatetest.MustNew(path, "v1.0.0")
	if c.local {
		var err error
		coord, err = coordinate.NewLocalCoordinate(path)
		if err != nil {
			t.Fatal(err)
		}
	}
	rec := domain.InterfaceRecord{
		Coordinate:        coord,
		OverallStatus:     c.status,
		ArtefactIdentity:  c.artefact,
		ContentHash:       c.hash,
		ExtractedAt:       c.at,
		SourceContentHash: c.srcHash,
		PipelineVersion:   c.pipeline,
	}
	if c.funcName != "" {
		rec.Packages = []domain.PackageInterface{
			pkg(path, withFunc(c.funcName, "func "+c.funcName+"()")),
		}
	}
	return rec
}

// Composing nothing has no meaningful answer, and the absence of a record is the
// store's word, not composition's.
func TestCompose_NoRecordsIsAProgrammingError(t *testing.T) {
	got, err := domain.Compose(nil)
	if !errors.Is(err, domain.ErrNoRecordsToCompose) {
		t.Errorf("err = %v, want ErrNoRecordsToCompose", err)
	}
	if got.ContentHash != "" {
		t.Errorf("a record was returned alongside the refusal: %+v", got)
	}
}

// A local version pins no content: the records are a sequence of observations of
// a changing tree, so the LAST one is the only correct answer even when an
// earlier one is the stronger measurement. Serving the earlier one would hand
// back an API the tree no longer has.
func TestCompose_LocalServesTheLastObservation(t *testing.T) {
	early := composedRecord(t, composed{
		local: true, status: domain.InterfaceStatusExtracted, hash: "sha256:early", funcName: "Old",
	})
	late := composedRecord(t, composed{
		local: true, status: domain.InterfaceStatusPartial, hash: "sha256:late", funcName: "New",
	})

	got, err := domain.Compose([]domain.InterfaceRecord{early, late})
	if err != nil {
		t.Fatal(err)
	}
	if got.ContentHash != "sha256:late" {
		t.Errorf("served %q, want the last observation of the tree", got.ContentHash)
	}
}

// A complete extraction outranks a Partial one regardless of which was written
// later: a Partial record missed a package to a parse failure, so it is a weaker
// measurement of the same API rather than a competing answer.
func TestCompose_StatusOutranksRecency(t *testing.T) {
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	newer := old.Add(24 * time.Hour)

	partialLater := composedRecord(t, composed{
		status: domain.InterfaceStatusPartial, artefact: "zip:h1:aaa", hash: "sha256:partial", at: newer,
	})
	completeEarlier := composedRecord(t, composed{
		status: domain.InterfaceStatusExtracted, artefact: "zip:h1:aaa", hash: "sha256:complete", at: old,
	})

	got, err := domain.Compose([]domain.InterfaceRecord{partialLater, completeEarlier})
	if err != nil {
		t.Fatal(err)
	}
	if got.ContentHash != "sha256:complete" {
		t.Errorf("served %q, want the complete extraction", got.ContentHash)
	}
}

// Recency is the tiebreaker within one rung, and the content hash the last
// resort — present so the served record does not depend on the order rows came
// back in, and claimed as nothing more.
func TestCompose_RecencyThenContentHashBreakTies(t *testing.T) {
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	newer := old.Add(time.Hour)

	t.Run("recency", func(t *testing.T) {
		a := composedRecord(t, composed{status: domain.InterfaceStatusExtracted, artefact: "zip:h1:aaa", hash: "sha256:a", at: old})
		b := composedRecord(t, composed{status: domain.InterfaceStatusExtracted, artefact: "zip:h1:aaa", hash: "sha256:b", at: newer})
		got, err := domain.Compose([]domain.InterfaceRecord{a, b})
		if err != nil {
			t.Fatal(err)
		}
		if got.ContentHash != "sha256:b" {
			t.Errorf("served %q, want the more recent record", got.ContentHash)
		}
	})

	t.Run("content hash", func(t *testing.T) {
		a := composedRecord(t, composed{status: domain.InterfaceStatusExtracted, artefact: "zip:h1:aaa", hash: "sha256:zzz", at: old})
		b := composedRecord(t, composed{status: domain.InterfaceStatusExtracted, artefact: "zip:h1:aaa", hash: "sha256:aaa", at: old})
		got, err := domain.Compose([]domain.InterfaceRecord{a, b})
		if err != nil {
			t.Fatal(err)
		}
		if got.ContentHash != "sha256:aaa" {
			t.Errorf("served %q, want the deterministic pick", got.ContentHash)
		}
	})
}

// Once a measurement exists that says which bytes it read, it is the
// better-evidenced answer and the records that name no artefact stop competing
// with it — even when one of them is the stronger extraction.
func TestCompose_IdentifiedRecordsWinOverUnidentifiedOnes(t *testing.T) {
	unidentified := composedRecord(t, composed{
		status: domain.InterfaceStatusExtracted, hash: "sha256:unidentified",
	})
	identified := composedRecord(t, composed{
		status: domain.InterfaceStatusPartial, artefact: "zip:h1:aaa", hash: "sha256:identified",
	})

	got, err := domain.Compose([]domain.InterfaceRecord{unidentified, identified})
	if err != nil {
		t.Fatal(err)
	}
	if got.ContentHash != "sha256:identified" {
		t.Errorf("served %q, want the record that names its artefact", got.ContentHash)
	}
}

// When none of them names an artefact there is nothing to prefer, and the ladder
// runs over all of them rather than over an empty set.
func TestCompose_NoneIdentifiedFallsBackToAllOfThem(t *testing.T) {
	a := composedRecord(t, composed{status: domain.InterfaceStatusPartial, hash: "sha256:a"})
	b := composedRecord(t, composed{status: domain.InterfaceStatusExtracted, hash: "sha256:b"})

	got, err := domain.Compose([]domain.InterfaceRecord{a, b})
	if err != nil {
		t.Fatal(err)
	}
	if got.ContentHash != "sha256:b" {
		t.Errorf("served %q, want the complete extraction", got.ContentHash)
	}
}

// Two identities for one pinned module version means the same module at the same
// version yielded two different sets of bytes. There is no ladder between
// answers about different bytes, so composition refuses rather than picks.
func TestCompose_ArtefactIdentityDisagreementIsAConflict(t *testing.T) {
	a := composedRecord(t, composed{
		status: domain.InterfaceStatusExtracted, artefact: "zip:h1:aaa", hash: "sha256:a", pipeline: "iface/1",
	})
	b := composedRecord(t, composed{
		status: domain.InterfaceStatusExtracted, artefact: "zip:h1:bbb", hash: "sha256:b", pipeline: "iface/1",
	})

	_, err := domain.Compose([]domain.InterfaceRecord{a, b})
	var conflict domain.InterfaceConflict
	if !errors.As(err, &conflict) {
		t.Fatalf("err = %v, want an InterfaceConflict", err)
	}
	if conflict.Field != "artefact_identity" {
		t.Errorf("conflict field = %q", conflict.Field)
	}
	if len(conflict.Values) != 2 || conflict.Values[0] != "zip:h1:aaa" || conflict.Values[1] != "zip:h1:bbb" {
		t.Errorf("values = %v, want both identities sorted", conflict.Values)
	}
	if len(conflict.ContentHashes) != 2 || conflict.ContentHashes[0] != "sha256:a" {
		t.Errorf("hashes = %v, want the record carrying each value", conflict.ContentHashes)
	}
	// The error renders as a message the store can return directly.
	for _, want := range []string{"conflicting interface records", "artefact_identity", "iface/1"} {
		if !strings.Contains(conflict.Error(), want) {
			t.Errorf("conflict message %q missing %q", conflict.Error(), want)
		}
	}
}

// Two records describing the SAME artefact at the SAME status that disagree
// about the exported API is evidence of non-determinism in the extractor, and is
// surfaced rather than absorbed.
func TestCompose_SameArtefactSameStatusAPIDisagreementIsAConflict(t *testing.T) {
	a := composedRecord(t, composed{
		status: domain.InterfaceStatusExtracted, artefact: "zip:h1:aaa", hash: "sha256:a", funcName: "One",
	})
	b := composedRecord(t, composed{
		status: domain.InterfaceStatusExtracted, artefact: "zip:h1:aaa", hash: "sha256:b", funcName: "Two",
	})

	_, err := domain.Compose([]domain.InterfaceRecord{a, b})
	var conflict domain.InterfaceConflict
	if !errors.As(err, &conflict) {
		t.Fatalf("err = %v, want an InterfaceConflict", err)
	}
	if conflict.Field != "public_api" {
		t.Errorf("conflict field = %q, want public_api", conflict.Field)
	}
}

// The ladder resolves what it can resolve. A Partial extraction that disagrees
// with a complete one about the API is a refinement, not a finding — reporting
// it would make every "partial, then complete" pair look like non-determinism.
func TestCompose_LadderSeparatesDisagreeingStatuses(t *testing.T) {
	partial := composedRecord(t, composed{
		status: domain.InterfaceStatusPartial, artefact: "zip:h1:aaa", hash: "sha256:partial", funcName: "One",
	})
	complete := composedRecord(t, composed{
		status: domain.InterfaceStatusExtracted, artefact: "zip:h1:aaa", hash: "sha256:complete", funcName: "Two",
	})

	got, err := domain.Compose([]domain.InterfaceRecord{partial, complete})
	if err != nil {
		t.Fatalf("a refinement was reported as a conflict: %v", err)
	}
	if got.ContentHash != "sha256:complete" {
		t.Errorf("served %q, want the complete extraction", got.ContentHash)
	}
}

// A failed or cancelled extraction makes no claim about the API at all, so it
// cannot contradict one that does — and two of them tied at rank 0 are not a
// disagreement either.
func TestCompose_RecordsThatClaimNothingCannotConflict(t *testing.T) {
	t.Run("a failure does not contradict a claim", func(t *testing.T) {
		failed := composedRecord(t, composed{
			status: domain.InterfaceStatusExtractionFailed, artefact: "zip:h1:aaa", hash: "sha256:failed",
		})
		complete := composedRecord(t, composed{
			status: domain.InterfaceStatusExtracted, artefact: "zip:h1:aaa", hash: "sha256:complete", funcName: "One",
		})
		got, err := domain.Compose([]domain.InterfaceRecord{failed, complete})
		if err != nil {
			t.Fatalf("a failed extraction was treated as a competing answer: %v", err)
		}
		if got.ContentHash != "sha256:complete" {
			t.Errorf("served %q", got.ContentHash)
		}
	})

	t.Run("two records that claim nothing", func(t *testing.T) {
		failed := composedRecord(t, composed{
			status: domain.InterfaceStatusExtractionFailed, artefact: "zip:h1:aaa", hash: "sha256:failed",
		})
		cancelled := composedRecord(t, composed{
			status: domain.InterfaceStatusCancelled, artefact: "zip:h1:aaa", hash: "sha256:cancelled", funcName: "One",
		})
		if _, err := domain.Compose([]domain.InterfaceRecord{failed, cancelled}); err != nil {
			t.Fatalf("two records that make no API claim were reported as disagreeing: %v", err)
		}
	})

	t.Run("an unknown status is worth nothing as evidence", func(t *testing.T) {
		unknown := composedRecord(t, composed{
			status: domain.InterfaceStatus(99), artefact: "zip:h1:aaa", hash: "sha256:unknown", funcName: "One",
		})
		complete := composedRecord(t, composed{
			status: domain.InterfaceStatusExtracted, artefact: "zip:h1:aaa", hash: "sha256:complete", funcName: "Two",
		})
		got, err := domain.Compose([]domain.InterfaceRecord{unknown, complete})
		if err != nil {
			t.Fatalf("a status outside the enum was ranked as evidence: %v", err)
		}
		if got.ContentHash != "sha256:complete" {
			t.Errorf("served %q", got.ContentHash)
		}
	})
}

// One record cannot disagree with anything, and a record whose artefact identity
// is empty contributes no value to disagree about.
func TestCompose_NothingToDisagreeWith(t *testing.T) {
	t.Run("a single record", func(t *testing.T) {
		only := composedRecord(t, composed{status: domain.InterfaceStatusExtracted, hash: "sha256:only"})
		got, err := domain.Compose([]domain.InterfaceRecord{only})
		if err != nil {
			t.Fatal(err)
		}
		if got.ContentHash != "sha256:only" {
			t.Errorf("served %q", got.ContentHash)
		}
	})

	t.Run("a single identified record beside unidentified ones", func(t *testing.T) {
		identified := composedRecord(t, composed{
			status: domain.InterfaceStatusExtracted, artefact: "zip:h1:aaa", hash: "sha256:identified", funcName: "One",
		})
		unidentified := composedRecord(t, composed{
			status: domain.InterfaceStatusExtracted, hash: "sha256:unidentified", funcName: "Two",
		})
		got, err := domain.Compose([]domain.InterfaceRecord{identified, unidentified})
		if err != nil {
			t.Fatalf("an unidentified record was allowed to conflict: %v", err)
		}
		if got.ContentHash != "sha256:identified" {
			t.Errorf("served %q", got.ContentHash)
		}
	})
}

// APIDigest hashes what a record says about the exported API and nothing else:
// two runs a second apart that produced the identical API agree, and a record
// that describes a different API does not.
func TestAPIDigest_CoversTheClaimAndNotTheProvenance(t *testing.T) {
	base := composedRecord(t, composed{
		status: domain.InterfaceStatusExtracted, artefact: "zip:h1:aaa",
		hash: "sha256:a", srcHash: "sha256:fetch-a", funcName: "One",
		at: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	remeasured := composedRecord(t, composed{
		status: domain.InterfaceStatusExtracted, artefact: "zip:h1:aaa",
		hash: "sha256:b", srcHash: "sha256:fetch-b", funcName: "One",
		at: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
	})
	different := composedRecord(t, composed{
		status: domain.InterfaceStatusExtracted, artefact: "zip:h1:aaa",
		hash: "sha256:a", srcHash: "sha256:fetch-a", funcName: "Two",
		at: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})

	if domain.APIDigest(base) != domain.APIDigest(remeasured) {
		t.Error("two measurements of the identical API disagreed on provenance alone")
	}
	if domain.APIDigest(base) == domain.APIDigest(different) {
		t.Error("two different exported APIs produced the same digest")
	}
	if got := domain.APIDigest(base); len(got) < 8 || got[:7] != "sha256:" {
		t.Errorf("digest = %q, want a sha256-prefixed hash", got)
	}
}
