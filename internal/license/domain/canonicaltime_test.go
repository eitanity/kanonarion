package domain_test

import (
	"strings"
	"testing"
	"time"

	domain2 "github.com/eitanity/kanonarion/internal/license/domain"

	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// stampRecord is the smallest sealed licence record whose extraction time is the
// only thing under test.
func stampRecord(t *testing.T, at time.Time) domain2.LicenseRecord {
	t.Helper()
	r := domain2.LicenseRecord{
		SchemaVersion:     domain2.LicenseSchemaVersion,
		Ecosystem:         fetchdomain.EcosystemGo,
		Coordinate:        coordinatetest.MustNew("example.com/mod", "v1.0.0"),
		PrimarySPDX:       "MIT",
		PrimaryConfidence: 0.98,
		ExtractedAt:       at,
		PipelineVersion:   "0.1.0",
	}
	sealed, err := (domain2.LicenseRecordHasher{}).SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	return sealed
}

// A record extracted at a whole second seals exactly as it always did, which is
// what lets the widening land without rehashing anything: the maintainer's store
// holds 1,828 licence records and every one of them carries a whole second.
func TestCanonicalTime_WholeSecondRecordSealsUnchanged(t *testing.T) {
	t.Parallel()
	rec := stampRecord(t, time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC))
	if err := (domain2.LicenseRecordHasher{}).VerifyContentHash(rec); err != nil {
		t.Fatalf("a whole-second record does not verify: %v", err)
	}
	b, err := (domain2.LicenseRecordHasher{}).Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if want := `"extracted_at":"2026-01-01T12:00:00Z"`; !strings.Contains(string(b), want) {
		t.Errorf("sealed bytes do not carry %s; every stored record would fail its integrity check", want)
	}
}

// A sub-second extraction carries all nine digits, trailing zeros included.
func TestCanonicalTime_SubSecondExtractionIsSealedAtFixedWidth(t *testing.T) {
	t.Parallel()
	rec := stampRecord(t, time.Date(2026, 1, 1, 12, 0, 0, 500000000, time.UTC))
	if err := (domain2.LicenseRecordHasher{}).VerifyContentHash(rec); err != nil {
		t.Fatalf("a sub-second record does not verify: %v", err)
	}
	b, err := (domain2.LicenseRecordHasher{}).Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if want := `"extracted_at":"2026-01-01T12:00:00.500000000Z"`; !strings.Contains(string(b), want) {
		t.Errorf("sealed bytes do not carry %s; the fraction was trimmed or truncated", want)
	}
}
