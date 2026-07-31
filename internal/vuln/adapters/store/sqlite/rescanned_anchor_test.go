package sqlite_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

// anchoredRecord is a record of the shape a live store is mostly made of: one
// that has been scanned more than once, so its first-seen anchor is set to an
// earlier instant than the scan that last validated it.
func anchoredRecord() domain.VulnerabilityRecord {
	return domain.VulnerabilityRecord{
		Ecosystem:        fetchdomain.EcosystemGo,
		Coordinate:       coord("github.com/foo/anchored", "v1.0.0"),
		WalkID:           "walk-1",
		OverallStatus:    domain.StatusClean,
		DatabaseSnapshot: snap("govulndb", "v2026-07-30"),
		ScannedAt:        time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC),
		FirstScannedAt:   time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC),
		PipelineVersion:  "v15",
	}
}

// TestReadPath_RescannedRecordRoundTrips is the floor: a record carrying a
// first-seen anchor is written and read back without the store calling it an
// integrity failure.
func TestReadPath_RescannedRecordRoundTrips(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	rec := seal(t, anchoredRecord())
	if err := store.PutVulnerabilityRecord(ctx, rec); err != nil {
		t.Fatalf("PutVulnerabilityRecord: %v", err)
	}

	got, found, err := store.GetVulnerabilityRecord(ctx, rec.Coordinate, rec.PipelineVersion, rec.DatabaseSnapshot)
	if err != nil {
		t.Fatalf("GetVulnerabilityRecord on a re-scanned record: %v", err)
	}
	if !found {
		t.Fatal("GetVulnerabilityRecord did not find the record it just stored")
	}
	if !got.FirstScannedAt.Equal(rec.FirstScannedAt) {
		t.Errorf("first_scanned_at read back as %s, want %s", got.FirstScannedAt, rec.FirstScannedAt)
	}
}

// TestReadPath_DriftedRescannedRecordIsReportedAsDrift is where the defect
// actually bit, and it is why a unit test on the verifier alone would not have
// been enough.
//
// A record whose bytes this build can reproduce never reaches the classifier at
// all, so the divergence stayed invisible until a canonical shape moved. Then
// every re-scanned record — the normal state of a live store — was reported in
// the words reserved for altered bytes, because the seal covers the record
// WITHOUT its first-seen anchor while the stored blob carries it, and the
// classifier was recomputing over the stored bytes as they are. It broke a
// migration that way: rows were skipped for failing a self-consistency gate they
// could never pass.
//
// The row below is an intact record of an earlier generation: its blob carries a
// field today's struct does not know, so re-marshalling cannot reproduce it,
// while the bytes still hash to the seal they carry. The answer must be
// generation drift — re-extract it — and never alteration.
func TestReadPath_DriftedRescannedRecordIsReportedAsDrift(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	rec := seal(t, anchoredRecord())
	if err := store.PutVulnerabilityRecord(ctx, rec); err != nil {
		t.Fatalf("PutVulnerabilityRecord: %v", err)
	}

	blob, hash := earlierGenerationBlob(t, rec)

	// Overwrite the row with the earlier generation's bytes. Both the column and
	// the blob move, because a row whose two seals disagree is a different fault.
	db := store.InternalDB().DB()
	if _, err := db.ExecContext(ctx,
		`UPDATE vulnerability_records SET content_hash = ?, serialised = ?`, hash, blob); err != nil {
		t.Fatalf("seeding the earlier generation's row: %v", err)
	}

	_, _, err := store.GetVulnerabilityRecord(ctx, rec.Coordinate, rec.PipelineVersion, rec.DatabaseSnapshot)
	if !errors.Is(err, ports.ErrVulnIntegrity) {
		t.Fatalf("GetVulnerabilityRecord error = %v, want it wrapped in ErrVulnIntegrity", err)
	}
	if !errors.Is(err, recordseal.ErrGenerationDrift) {
		t.Errorf("an intact record carrying a first-seen anchor is reported as altered rather than as "+
			"an earlier generation: %v", err)
	}
}

// earlierGenerationBlob builds the stored bytes of a record written by a
// canonical shape this build does not have, carrying a populated first-seen
// anchor, and the seal those bytes hash to.
//
// The construction mirrors what the writing generation did, in the same order,
// which is the only way to get a blob that is genuinely self-consistent rather
// than one this test has declared to be:
//
//  1. the sealed bytes are the record's JSON with content_hash blank and the
//     anchor absent, because the recipe zeroes it and the tag is omitzero;
//  2. a field that generation had and this one does not is added to them;
//  3. the seal is the digest of that, spliced back into its own field;
//  4. the anchor is added afterwards — it is stored, and it is not sealed.
func earlierGenerationBlob(t *testing.T, rec domain.VulnerabilityRecord) (blob []byte, hash string) {
	t.Helper()

	unanchored := rec
	unanchored.FirstScannedAt = time.Time{}
	unanchored.ContentHash = ""
	sealedBytes, err := domain.VulnerabilityRecordHasher{}.Marshal(unanchored)
	if err != nil {
		t.Fatalf("marshalling the sealed bytes: %v", err)
	}

	sealedBytes = addMember(t, sealedBytes, `"a_field_this_build_does_not_have":"x"`)
	sum := sha256.Sum256(sealedBytes)
	hash = "sha256:" + hex.EncodeToString(sum[:])

	blob, _, err = recordseal.ReplaceTopLevelContentHash(sealedBytes, hash)
	if err != nil {
		t.Fatalf("writing the seal into the blob: %v", err)
	}
	blob = addMember(t, blob, `"first_scanned_at":"`+rec.FirstScannedAt.UTC().Format(time.RFC3339)+`"`)

	// The bytes must hash to their own seal once the anchor is discounted, or
	// this fixture is an altered record and the test below would pass for the
	// wrong reason.
	consistent, err := recordseal.
		Excluding(domain.VulnerabilityRecordHasher{}.SealExcludes()...).
		SelfConsistent(blob, hash)
	if err != nil {
		t.Fatalf("checking the fixture against its own seal: %v", err)
	}
	if !consistent {
		t.Fatal("the fixture does not hash to its own seal, so it is an altered record, not an old one")
	}
	return blob, hash
}

// addMember inserts a member at the head of a JSON object, leaving every other
// byte where it was.
func addMember(t *testing.T, object []byte, member string) []byte {
	t.Helper()
	if len(object) == 0 || object[0] != '{' {
		t.Fatalf("not a JSON object: %s", object)
	}
	out := append([]byte{'{'}, member...)
	out = append(out, ',')
	return append(out, object[1:]...)
}
