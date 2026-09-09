package domain_test

import (
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
)

// A record measured at a whole second seals exactly as it always did.
//
// This is what lets the widening land without rehashing anything. Every
// generation written before it carries a whole second, so all of them take that
// branch and their stored content hashes still recompute. The maintainer's store
// holds 1,569 such records; an encoding that widened unconditionally would
// darken every one of them at once.
func TestCanonicalTime_WholeSecondRecordSealsUnchanged(t *testing.T) {
	t.Parallel()
	rec := composeRecord(t, composeSpec{
		source: domain.AnalysisSourceModuleZip, artefact: "zip:h1:a",
		completeness: domain.CompletenessBuiltWithBodies,
		extractedAt:  time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
	})
	if err := (domain.CallGraphRecordHasher{}).VerifyContentHash(rec); err != nil {
		t.Fatalf("a whole-second record does not verify: %v", err)
	}
	b, err := (domain.CallGraphRecordHasher{}).Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if want := `"extracted_at":"2026-01-01T12:00:00Z"`; !strings.Contains(string(b), want) {
		t.Errorf("sealed bytes do not carry %s; every stored record would fail its integrity check", want)
	}
}

// A sub-second extraction carries all nine digits, trailing zeros included. That
// is what makes two extractions within one second distinguishable in the ledger
// and what lines a record up against a log line without reconciling widths.
func TestCanonicalTime_SubSecondExtractionIsSealedAtFixedWidth(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 1, 1, 12, 0, 0, 500000000, time.UTC)
	rec := composeRecord(t, composeSpec{
		source: domain.AnalysisSourceModuleZip, artefact: "zip:h1:a",
		completeness: domain.CompletenessBuiltWithBodies,
		extractedAt:  at,
	})
	if err := (domain.CallGraphRecordHasher{}).VerifyContentHash(rec); err != nil {
		t.Fatalf("a sub-second record does not verify: %v", err)
	}
	b, err := (domain.CallGraphRecordHasher{}).Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if want := `"extracted_at":"2026-01-01T12:00:00.500000000Z"`; !strings.Contains(string(b), want) {
		t.Errorf("sealed bytes do not carry %s; the fraction was trimmed or truncated", want)
	}

	// Two extractions one nanosecond apart are two records, not one.
	other := composeRecord(t, composeSpec{
		source: domain.AnalysisSourceModuleZip, artefact: "zip:h1:a",
		completeness: domain.CompletenessBuiltWithBodies,
		extractedAt:  at.Add(1),
	})
	if rec.ContentHash == other.ContentHash {
		t.Error("two extractions one nanosecond apart share a content hash; they are indistinguishable in the ledger")
	}
}
