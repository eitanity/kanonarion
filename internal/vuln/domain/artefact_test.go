package domain_test

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

func artefactTestRecord(t *testing.T) domain.VulnerabilityRecord {
	t.Helper()
	coord, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	return domain.VulnerabilityRecord{
		Ecosystem:       fetchdomain.EcosystemGo,
		Coordinate:      coord,
		OverallStatus:   domain.StatusClean,
		ScannedAt:       time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		PipelineVersion: "0.1.0",
	}
}

// TestArtefactFields_AbsentFromJSONWhenEmpty is the compatibility proof the
// ticket's "no rehash, no purge" rests on. A record written before these fields
// existed must serialise to the same bytes it always did, or its stored content
// hash stops verifying. Asserting the keys are absent asserts the mechanism.
//
// It matters more here than in the extraction contexts: a vulnerability record
// legitimately names no artefact long after this change lands — a metadata-only
// match by coordinate reads no bytes at all — so the omission is a live path,
// not only a legacy one.
func TestArtefactFields_AbsentFromJSONWhenEmpty(t *testing.T) {
	t.Parallel()

	raw, err := json.Marshal(artefactTestRecord(t))
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, key := range []string{`"artefact_identity"`, `"source_content_hash"`} {
		if bytes.Contains(raw, []byte(key)) {
			t.Errorf("JSON of a record with no artefact recorded contains %s; pre-existing records would stop verifying:\n%s", key, raw)
		}
	}
}

// TestArtefactFields_ChangeTheContentHash proves the provenance claim is sealed
// rather than decorative: re-pointing a verdict at different bytes must not
// leave its identity untouched.
func TestArtefactFields_ChangeTheContentHash(t *testing.T) {
	t.Parallel()

	base := artefactTestRecord(t)

	withOriginal := base
	withOriginal.ArtefactIdentity = fetchtest.ZipArtefact("original=").String()
	withOriginal.SourceContentHash = "sha256:fetchrecord"

	substituted := withOriginal
	substituted.ArtefactIdentity = fetchtest.ZipArtefact("substituted=").String()

	none := marshalOrFail(t, base)
	original := marshalOrFail(t, withOriginal)
	other := marshalOrFail(t, substituted)

	if bytes.Equal(none, original) {
		t.Error("recording an artefact left the hashed bytes unchanged")
	}
	if bytes.Equal(original, other) {
		t.Error("substituting the artefact left the hashed bytes unchanged")
	}
}

// TestArtefactFields_SurviveTheStorageRoundTrip proves the fields are persisted
// rather than merely hashed, through the custom UnmarshalJSON the record uses.
func TestArtefactFields_SurviveTheStorageRoundTrip(t *testing.T) {
	t.Parallel()

	want := fetchtest.GoModArtefact("gomod-only=")
	rec := artefactTestRecord(t)
	rec.ArtefactIdentity = want.String()
	rec.SourceContentHash = "sha256:fetchrecord"

	var got domain.VulnerabilityRecord
	if err := json.Unmarshal(marshalOrFail(t, rec), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.ArtefactIdentity != rec.ArtefactIdentity {
		t.Errorf("ArtefactIdentity = %q, want %q", got.ArtefactIdentity, rec.ArtefactIdentity)
	}
	if got.SourceContentHash != rec.SourceContentHash {
		t.Errorf("SourceContentHash = %q, want %q", got.SourceContentHash, rec.SourceContentHash)
	}

	id, err := domain.RecordArtefactIdentity(got)
	if err != nil {
		t.Fatalf("RecordArtefactIdentity: %v", err)
	}
	if !id.Equal(want) {
		t.Errorf("RecordArtefactIdentity = %v, want %v", id, want)
	}
	if !id.GoModOnly() {
		t.Error("a go.mod-only identity read back as a zip identity")
	}
}

// TestRecordArtefactIdentity_AbsenceIsNotCorruption pins the read-leg rule. It
// carries more weight for vulnerability records than elsewhere: absence is a
// permanent, expected state here, so it must stay cheap to read and must still
// never launder a corrupt value into one.
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

func marshalOrFail(t *testing.T, r domain.VulnerabilityRecord) []byte {
	t.Helper()
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return raw
}
