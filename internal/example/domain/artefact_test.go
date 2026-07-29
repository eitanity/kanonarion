package domain_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/example/domain"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
)

func artefactTestRecord(t *testing.T) domain.ExampleRecord {
	t.Helper()
	coord, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	return domain.ExampleRecord{
		SchemaVersion:   domain.ExampleSchemaVersion,
		Ecosystem:       fetchdomain.EcosystemGo,
		Coordinate:      coord,
		OverallStatus:   domain.ExampleStatusFound,
		ExtractedAt:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		PipelineVersion: "0.1.0",
	}
}

// TestArtefactFields_AbsentFromCanonicalJSONWhenEmpty is the compatibility
// proof the ticket's "no rehash, no purge" rests on. A record written before
// these fields existed must serialise to the same bytes it always did, or its
// stored content hash stops verifying and millions of rows become unreadable.
// Asserting the keys are absent asserts the mechanism, not the consequence.
func TestArtefactFields_AbsentFromCanonicalJSONWhenEmpty(t *testing.T) {
	t.Parallel()

	var h domain.ExampleRecordHasher
	raw, err := h.Marshal(artefactTestRecord(t))
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, key := range []string{`"artefact_identity"`, `"source_content_hash"`} {
		if bytes.Contains(raw, []byte(key)) {
			t.Errorf("canonical JSON of a record with no artefact recorded contains %s; pre-existing records would stop verifying:\n%s", key, raw)
		}
	}
}

// TestArtefactFields_CoveredByContentHash is what makes the provenance claim
// worth anything: "this record came from these bytes" must be as tamper-evident
// as the record itself, so re-pointing a record at a different artefact has to
// break its seal.
func TestArtefactFields_CoveredByContentHash(t *testing.T) {
	t.Parallel()

	var h domain.ExampleRecordHasher
	sealed, err := h.SetContentHash(withArtefact(artefactTestRecord(t), fetchtest.ZipArtefact("original=")))
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if err := h.VerifyContentHash(sealed); err != nil {
		t.Fatalf("VerifyContentHash of an untampered record: %v", err)
	}

	tampered := sealed
	tampered.ArtefactIdentity = fetchtest.ZipArtefact("substituted=").String()
	if err := h.VerifyContentHash(tampered); err == nil {
		t.Error("re-pointing the record at a different artefact left the content hash valid")
	}

	tampered = sealed
	tampered.SourceContentHash = "sha256:0000"
	if err := h.VerifyContentHash(tampered); err == nil {
		t.Error("re-pointing the record at a different fetch measurement left the content hash valid")
	}
}

// TestArtefactFields_SurviveTheStorageRoundTrip proves the fields are actually
// persisted rather than merely hashed — a field carried into the hash but
// dropped on the way back out would verify happily and answer nothing.
func TestArtefactFields_SurviveTheStorageRoundTrip(t *testing.T) {
	t.Parallel()

	want := fetchtest.GoModArtefact("gomod-only=")
	var h domain.ExampleRecordHasher
	sealed, err := h.SetContentHash(withArtefact(artefactTestRecord(t), want))
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	raw, err := h.Marshal(sealed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := h.Unmarshal(raw)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.ArtefactIdentity != sealed.ArtefactIdentity {
		t.Errorf("ArtefactIdentity = %q, want %q", got.ArtefactIdentity, sealed.ArtefactIdentity)
	}
	if got.SourceContentHash != sealed.SourceContentHash {
		t.Errorf("SourceContentHash = %q, want %q", got.SourceContentHash, sealed.SourceContentHash)
	}
	if err := h.VerifyContentHash(got); err != nil {
		t.Errorf("VerifyContentHash after a round trip: %v", err)
	}

	id, err := domain.RecordArtefactIdentity(got)
	if err != nil {
		t.Fatalf("RecordArtefactIdentity: %v", err)
	}
	if !id.Equal(want) {
		t.Errorf("RecordArtefactIdentity = %v, want %v", id, want)
	}
	// The go.mod depth survives, so a shallow measurement cannot read back as a
	// claim that the zip was seen.
	if !id.GoModOnly() {
		t.Error("a go.mod-only identity read back as a zip identity")
	}
}

// TestRecordArtefactIdentity_AbsenceIsNotCorruption pins the read-leg rule: a
// record that records no artefact answers with the zero identity and no error,
// while one whose field cannot be read is an error. Collapsing the two is how a
// corrupt column becomes a silently absent one.
func TestRecordArtefactIdentity_AbsenceIsNotCorruption(t *testing.T) {
	t.Parallel()

	id, err := domain.RecordArtefactIdentity(artefactTestRecord(t))
	if err != nil {
		t.Fatalf("RecordArtefactIdentity of a record with none recorded: %v", err)
	}
	if !id.IsZero() {
		t.Errorf("RecordArtefactIdentity = %v, want the zero identity", id)
	}

	corrupt := artefactTestRecord(t)
	corrupt.ArtefactIdentity = "tarball:h1:abc123="
	if _, err := domain.RecordArtefactIdentity(corrupt); err == nil {
		t.Error("an unreadable artefact identity was reported as absent")
	}
}

func withArtefact(r domain.ExampleRecord, id fetchdomain.ArtefactIdentity) domain.ExampleRecord {
	r.ArtefactIdentity = id.String()
	r.SourceContentHash = "sha256:fetchrecord"
	return r
}
