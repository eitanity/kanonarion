package domain_test

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	coordinatetest "github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

func sampleRecord(t *testing.T) domain.VulnerabilityRecord {
	t.Helper()
	return domain.VulnerabilityRecord{
		Ecosystem:        fetchdomain.EcosystemGo,
		Coordinate:       coordinatetest.MustNew("github.com/foo/bar", "v1.0.0"),
		WalkID:           "walk-1",
		OverallStatus:    domain.StatusClean,
		DatabaseSnapshot: domain.DatabaseSnapshot{Source: "test", Version: "v1"},
		ScannedAt:        time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		PipelineVersion:  "v1",
	}
}

// TestVulnerabilityRecordHasher_Recipe pins the byte recipe against an
// independently written expectation rather than against the hasher's own
// output. Every record already stored was sealed with this recipe, so a change
// to it — a reordered struct field, a renamed JSON tag, a newly hashed field,
// or the "sha256:" prefix every other context uses and this one does not —
// makes every stored record fail verification on read. Reproducing the bytes
// by hand here is what makes that a test failure instead of a store-wide one.
func TestVulnerabilityRecordHasher_Recipe(t *testing.T) {
	rec := sampleRecord(t)
	// FirstScannedAt is excluded from the hash, so a value here must not appear
	// in the bytes below.
	rec.FirstScannedAt = time.Date(2023, 6, 1, 0, 0, 0, 0, time.UTC)

	// The wire form: struct field order, tags as declared, omitempty/omitzero
	// fields absent, and no content_hash content.
	wire := `{"ecosystem":"go",` +
		`"coordinate":"github.com/foo/bar@v1.0.0",` +
		`"walk_id":"walk-1",` +
		`"overall_status":"Clean",` +
		// The two verdict axes are derived and written by SetContentHash itself,
		// so they are part of the sealed bytes even though no caller set them.
		`"coverage_status":"Analysed",` +
		`"findings_status":"Clean",` +
		`"database_snapshot":{"source":"test","version":"v1","retrieved_at":"0001-01-01T00:00:00Z","content_hash":""},` +
		`"scanned_at":"2024-01-01T00:00:00Z",` +
		`"pipeline_version":"v1",` +
		`"content_hash":""}`
	sum := sha256.Sum256([]byte(wire))
	want := hex.EncodeToString(sum[:])

	sealed, err := domain.VulnerabilityRecordHasher{}.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash(): %v", err)
	}
	if sealed.ContentHash != want {
		t.Errorf("content hash = %q, want %q — the byte recipe changed, which invalidates every stored record", sealed.ContentHash, want)
	}
	if strings.HasPrefix(sealed.ContentHash, "sha256:") {
		t.Error("content hash carries a \"sha256:\" prefix; stored vuln records are bare hex")
	}
}

func TestVulnerabilityRecordHasher_ExcludesFirstScannedAt(t *testing.T) {
	base := sampleRecord(t)
	withAnchor := base
	withAnchor.FirstScannedAt = time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
	movedAnchor := base
	movedAnchor.FirstScannedAt = time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)

	// The first-seen anchor is provenance, not verdict: records that differ only
	// in FirstScannedAt must hash identically so reuse re-attribution keeps a
	// stable identity.
	var h domain.VulnerabilityRecordHasher
	a, err := h.SetContentHash(withAnchor)
	if err != nil {
		t.Fatalf("SetContentHash(withAnchor): %v", err)
	}
	b, err := h.SetContentHash(movedAnchor)
	if err != nil {
		t.Fatalf("SetContentHash(movedAnchor): %v", err)
	}
	if a.ContentHash != b.ContentHash {
		t.Errorf("content hash changed with FirstScannedAt: %s vs %s", a.ContentHash, b.ContentHash)
	}
	// The exclusion must hold on the verifying leg too, or a record read back
	// with a different anchor than it was written with fails verification.
	if verr := h.VerifyContentHash(b); verr != nil {
		t.Errorf("VerifyContentHash() on a moved anchor = %v, want nil", verr)
	}
}

// TestVulnerabilityRecordHasher_VerifyRejectsAlteredContent proves the seal
// does what it exists for: a record whose contents changed after sealing no
// longer verifies.
func TestVulnerabilityRecordHasher_VerifyRejectsAlteredContent(t *testing.T) {
	var h domain.VulnerabilityRecordHasher
	sealed, err := h.SetContentHash(sampleRecord(t))
	if err != nil {
		t.Fatalf("SetContentHash(): %v", err)
	}
	if verr := h.VerifyContentHash(sealed); verr != nil {
		t.Fatalf("VerifyContentHash() on an untouched record = %v, want nil", verr)
	}

	tampered := sealed
	tampered.OverallStatus = domain.StatusAffected
	if verr := h.VerifyContentHash(tampered); verr == nil {
		t.Error("VerifyContentHash() on an altered verdict = nil, want a mismatch")
	}

	unsealed := sampleRecord(t)
	if verr := h.VerifyContentHash(unsealed); verr == nil {
		t.Error("VerifyContentHash() on a record with no hash = nil, want a mismatch")
	}
}

// TestVulnerabilityRecordHasher_RoundTrip pins that a record survives
// Marshal/Unmarshal with its seal intact. The store verifies what it read back,
// not what it wrote, so a field that does not round-trip would fail every read.
func TestVulnerabilityRecordHasher_RoundTrip(t *testing.T) {
	var h domain.VulnerabilityRecordHasher
	rec := sampleRecord(t)
	rec.Findings = []domain.VulnerabilityFinding{{ID: "GO-2024-0001", Aliases: []string{"CVE-2024-0001"}}}
	rec.UnscanReason = domain.UnscanReasonLocalReplace
	rec.ArtefactIdentity = "zip:h1:abc="
	rec.SourceContentHash = "sha256:def"
	rec.FirstScannedAt = time.Date(2023, 6, 1, 0, 0, 0, 0, time.UTC)

	sealed, err := h.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash(): %v", err)
	}
	data, err := h.Marshal(sealed)
	if err != nil {
		t.Fatalf("Marshal(): %v", err)
	}
	got, err := h.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal(): %v", err)
	}
	if verr := h.VerifyContentHash(got); verr != nil {
		t.Errorf("VerifyContentHash() after round trip = %v, want nil", verr)
	}
	if !got.FirstScannedAt.Equal(sealed.FirstScannedAt) {
		t.Errorf("FirstScannedAt = %v, want %v", got.FirstScannedAt, sealed.FirstScannedAt)
	}
}

// TestVulnerabilityRecordHasher_MarshalFailure exercises the marshal-failure
// guard with a genuinely unmarshalable value — encoding/json rejects NaN/Inf
// floats — rather than an injected fake, so it proves the guard is actually
// reachable in production (a finding's CVSS Severity.Score is a plain float64),
// not just that the wrapping code is well-formed.
func TestVulnerabilityRecordHasher_MarshalFailure(t *testing.T) {
	rec := domain.VulnerabilityRecord{
		Findings: []domain.VulnerabilityFinding{
			{ID: "GO-2024-0001", Severity: &domain.Severity{Score: math.NaN()}},
		},
	}
	var h domain.VulnerabilityRecordHasher
	if _, err := h.SetContentHash(rec); err == nil {
		t.Error("SetContentHash() error = nil, want a marshal error for a NaN severity score")
	}
	if err := h.VerifyContentHash(rec); err == nil {
		t.Error("VerifyContentHash() error = nil, want a marshal error for a NaN severity score")
	}
	if _, err := h.Marshal(rec); err == nil {
		t.Error("Marshal() error = nil, want a marshal error for a NaN severity score")
	}
	if _, err := h.Unmarshal([]byte("{")); err == nil {
		t.Error("Unmarshal() error = nil, want a parse error for malformed JSON")
	}
}

func TestWalkScanRunHasher_SealVerifyRoundTrip(t *testing.T) {
	var h domain.WalkScanRunHasher
	run := domain.WalkScanRun{
		ID:     "vscan-walk-1-1700000000",
		WalkID: "walk-1",
		PerModuleResults: map[coordinate.ModuleCoordinate]string{
			coordinatetest.MustNew("github.com/foo/bar", "v1.0.0"): "abc",
		},
		StartedAt:       time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		CompletedAt:     time.Date(2024, 1, 1, 0, 1, 0, 0, time.UTC),
		PipelineVersion: "v14",
	}

	sealed, err := h.SetContentHash(run)
	if err != nil {
		t.Fatalf("SetContentHash(): %v", err)
	}
	if strings.HasPrefix(sealed.ContentHash, "sha256:") {
		t.Error("content hash carries a \"sha256:\" prefix; stored walk scan runs are bare hex")
	}
	if verr := h.VerifyContentHash(sealed); verr != nil {
		t.Fatalf("VerifyContentHash() = %v, want nil", verr)
	}

	data, err := h.Marshal(sealed)
	if err != nil {
		t.Fatalf("Marshal(): %v", err)
	}
	got, err := h.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal(): %v", err)
	}
	if verr := h.VerifyContentHash(got); verr != nil {
		t.Errorf("VerifyContentHash() after round trip = %v, want nil", verr)
	}

	tampered := sealed
	tampered.OverallStatus = domain.WalkStatusAffected
	if verr := h.VerifyContentHash(tampered); verr == nil {
		t.Error("VerifyContentHash() on an altered run = nil, want a mismatch")
	}
	if _, err := h.Unmarshal([]byte("{")); err == nil {
		t.Error("Unmarshal() error = nil, want a parse error for malformed JSON")
	}
}
