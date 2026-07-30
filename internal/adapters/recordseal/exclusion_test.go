package recordseal_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/recordseal"

	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

// TestVulnerabilityRecord_WithFirstScannedAt_IsSelfConsistent pins the case the
// shared verifier's premise does not cover on its own.
//
// The premise is that a record's seal is the hash of its stored JSON with the
// top-level content_hash blanked. The vulnerability record breaks it: its recipe
// also zeroes FirstScannedAt before hashing — deliberately, because a first-seen
// anchor is provenance rather than verdict — while the field is tagged omitzero
// rather than omitted, so a populated anchor IS in the stored blob and was NOT
// in the sealed bytes.
//
// A record that has never been re-scanned carries a zero anchor, which omitzero
// drops from the encoding, so it verifies and the divergence stays invisible.
// Only a re-scanned record — the common case in a live store — diverges, and
// Classify then reports intact bytes in the wording reserved for altered ones.
func TestVulnerabilityRecord_WithFirstScannedAt_IsSelfConsistent(t *testing.T) {
	t.Parallel()

	var h vulndomain.VulnerabilityRecordHasher
	rec, err := h.SetContentHash(vulndomain.VulnerabilityRecord{
		FirstScannedAt: time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("sealing a vulnerability record: %v", err)
	}
	raw, err := h.Marshal(rec)
	if err != nil {
		t.Fatalf("marshalling a vulnerability record: %v", err)
	}

	consistent, err := recordseal.Excluding(h.SealExcludes()...).SelfConsistent(raw, rec.ContentHash)
	if err != nil {
		t.Fatalf("SelfConsistent on a re-scanned vulnerability record: %v", err)
	}
	if !consistent {
		t.Errorf("recordseal rejects an intact vulnerability record carrying a first-seen anchor; " +
			"a record the verifier cannot classify is reported as altered rather than as old")
	}

	// The verifier told nothing must still reject it, and that is not a bug to
	// be fixed later: the seal really is over different bytes, so a reader that
	// has not been told which fields the recipe leaves out cannot reproduce it.
	// This assertion is what makes the exclusion load-bearing rather than
	// decorative — remove the wiring and this test says so.
	bare, err := recordseal.SelfConsistent(raw, rec.ContentHash)
	if err != nil {
		t.Fatalf("SelfConsistent without exclusions: %v", err)
	}
	if bare {
		t.Errorf("SelfConsistent accepts the record without being told about %v, so the exclusion "+
			"proves nothing; either the recipe stopped excluding the anchor or the field stopped "+
			"being stored", h.SealExcludes())
	}
}

// TestVulnerabilityRecord_ClassifyDoesNotCallARescannedRecordAltered states the
// consequence in the words a reader sees. Classify's whole purpose is to tell an
// old record apart from an altered one, and on this path it did neither: it
// returned the domain's raw mismatch, which is the wording reserved for bytes
// that have genuinely changed.
func TestVulnerabilityRecord_ClassifyDoesNotCallARescannedRecordAltered(t *testing.T) {
	t.Parallel()

	var h vulndomain.VulnerabilityRecordHasher
	rec, err := h.SetContentHash(vulndomain.VulnerabilityRecord{
		FirstScannedAt: time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("sealing a vulnerability record: %v", err)
	}
	raw, err := h.Marshal(rec)
	if err != nil {
		t.Fatalf("marshalling a vulnerability record: %v", err)
	}
	if verr := h.VerifyContentHash(rec); verr != nil {
		t.Fatalf("the domain's own verification rejects the record it just sealed: %v", verr)
	}

	// A record this build CAN reproduce never reaches Classify, so drive it the
	// way a genuinely unreproducible record would: with a non-nil verify error
	// over bytes that are nonetheless intact. The answer must be drift.
	classified := recordseal.Excluding(h.SealExcludes()...).
		Classify(raw, rec.ContentHash, errors.New("content hash mismatch"))
	if !errors.Is(classified, recordseal.ErrGenerationDrift) {
		t.Errorf("Classify does not report an intact re-scanned record as an earlier generation: %v",
			classified)
	}
}

// TestExclusions_RemovesTheMemberWhereverItSits covers the splice itself. The
// stored member may be anywhere in the object, and removing it must leave the
// remaining bytes exactly as the writing generation emitted them — one
// separating comma goes with it and nothing else moves.
//
// The nested case is the one that would fail silently: a byte search for the
// field name finds the first occurrence, and a canonical shape may well nest an
// object carrying the same key. Removing that one hashes over the wrong bytes
// and reports an intact record as altered, which is the bug this package was
// written to stop making.
func TestExclusions_RemovesTheMemberWhereverItSits(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		sealed string
		stored string
	}{
		"first member": {
			sealed: `{"content_hash":"","a":1,"b":"two"}`,
			stored: `{"anchor":"t","content_hash":%q,"a":1,"b":"two"}`,
		},
		"middle member": {
			sealed: `{"content_hash":"","a":1,"b":"two"}`,
			stored: `{"content_hash":%q,"a":1,"anchor":"t","b":"two"}`,
		},
		"last member": {
			sealed: `{"content_hash":"","a":1,"b":"two"}`,
			stored: `{"content_hash":%q,"a":1,"b":"two","anchor":"t"}`,
		},
		"sole member beside the seal": {
			sealed: `{"content_hash":""}`,
			stored: `{"content_hash":%q,"anchor":"t"}`,
		},
		"object value": {
			sealed: `{"content_hash":"","a":1}`,
			stored: `{"content_hash":%q,"anchor":{"when":"t","by":["x"]},"a":1}`,
		},
		"nested key of the same name is content, not an exclusion": {
			sealed: `{"content_hash":"","inner":{"anchor":"kept"},"a":1}`,
			stored: `{"content_hash":%q,"inner":{"anchor":"kept"},"anchor":"t","a":1}`,
		},
		"absent because it was zero": {
			sealed: `{"content_hash":"","a":1}`,
			stored: `{"content_hash":%q,"a":1}`,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, hash := seal(t, tc.sealed)
			stored := fmt.Appendf(nil, tc.stored, hash)

			consistent, err := recordseal.Excluding("anchor").SelfConsistent(stored, hash)
			if err != nil {
				t.Fatalf("SelfConsistent: %v", err)
			}
			if !consistent {
				t.Errorf("SelfConsistent rejects %s; removing the excluded member did not reconstruct "+
					"the bytes %s was sealed over", stored, tc.sealed)
			}
			if err := recordseal.Excluding("anchor").VerifyBlob(stored, hash); err != nil {
				t.Errorf("VerifyBlob rejects %s: %v", stored, err)
			}
		})
	}
}

// TestExclusions_AlteredBytesStayAltered pins the direction that matters more
// than the false positive it fixes. Removing a member before hashing must not
// remove the check: a record whose sealed content has changed is still reported
// as changed, whatever it carries in its excluded fields.
func TestExclusions_AlteredBytesStayAltered(t *testing.T) {
	t.Parallel()

	_, hash := seal(t, `{"content_hash":"","a":1}`)
	altered := fmt.Appendf(nil, `{"content_hash":%q,"anchor":"t","a":2}`, hash)

	consistent, err := recordseal.Excluding("anchor").SelfConsistent(altered, hash)
	if err != nil {
		t.Fatalf("SelfConsistent: %v", err)
	}
	if consistent {
		t.Error("SelfConsistent accepts bytes whose sealed content was changed")
	}
}
