package domain_test

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"testing"

	domain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

func TestComputeArtifactDigests_MatchesStdlib(t *testing.T) {
	data := []byte("the quick brown fox")

	got := domain.ComputeArtifactDigests(data)

	s256 := sha256.Sum256(data)
	s384 := sha512.Sum384(data)
	s512 := sha512.Sum512(data)
	if want := hex.EncodeToString(s256[:]); got.SHA256 != want {
		t.Errorf("SHA256 = %q, want %q", got.SHA256, want)
	}
	if want := hex.EncodeToString(s384[:]); got.SHA384 != want {
		t.Errorf("SHA384 = %q, want %q", got.SHA384, want)
	}
	if want := hex.EncodeToString(s512[:]); got.SHA512 != want {
		t.Errorf("SHA512 = %q, want %q", got.SHA512, want)
	}
}

func TestComputeArtifactDigests_Deterministic(t *testing.T) {
	data := []byte("repeatable input")

	first := domain.ComputeArtifactDigests(data)
	second := domain.ComputeArtifactDigests(data)
	if first != second {
		t.Fatal("ComputeArtifactDigests not deterministic")
	}
	if first == domain.ComputeArtifactDigests([]byte("other")) {
		t.Fatal("distinct inputs produced identical digests")
	}
}

func TestComputeArtifactDigests_EmptyInputIsNotZero(t *testing.T) {
	// Empty bytes still hash to well-defined non-empty digests, so the result
	// is a real computation, not the "no digests recorded" zero value.
	got := domain.ComputeArtifactDigests(nil)
	if got.IsZero() {
		t.Fatal("digests of empty input reported as zero value")
	}
}

func TestRecordDigests_ProjectsFields(t *testing.T) {
	r := domain.FactRecord{ZipSHA256: "aa", ZipSHA384: "bb", ZipSHA512: "cc"}

	got := domain.RecordDigests(r)

	want := domain.ArtifactDigests{SHA256: "aa", SHA384: "bb", SHA512: "cc"}
	if got != want {
		t.Errorf("RecordDigests = %+v, want %+v", got, want)
	}
	if domain.RecordDigests(domain.FactRecord{}) != (domain.ArtifactDigests{}) {
		t.Error("RecordDigests of empty record is not the zero value")
	}
}

func TestCanonicalHasher_DigestsRoundTripAndCovered(t *testing.T) {
	var h domain.CanonicalHasher
	r := domain.FactRecord{
		SchemaVersion: domain.SchemaVersion,
		Ecosystem:     domain.EcosystemGo,
		ModulePath:    "example.com/mod",
		ModuleVersion: "v1.0.0",
		ZipSHA256:     "sha256value",
		ZipSHA384:     "sha384value",
		ZipSHA512:     "sha512value",
	}
	r, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}

	data, err := h.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	back, err := h.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if domain.RecordDigests(back) != domain.RecordDigests(r) {
		t.Errorf("digests did not round-trip: got %+v want %+v", domain.RecordDigests(back), domain.RecordDigests(r))
	}
	// The digests are part of the canonical hash: tampering with one must break
	// verification.
	tampered := back
	tampered.ZipSHA256 = "tampered"
	if err := h.VerifyContentHash(tampered); err == nil {
		t.Error("VerifyContentHash accepted a record with a tampered digest")
	}
}

func TestArtifactDigests_IsZero(t *testing.T) {
	var zero domain.ArtifactDigests
	if !zero.IsZero() {
		t.Error("zero value IsZero() = false, want true")
	}
	if (domain.ArtifactDigests{SHA256: "abc"}).IsZero() {
		t.Error("populated SHA256 IsZero() = true, want false")
	}
	if (domain.ArtifactDigests{SHA384: "abc"}).IsZero() {
		t.Error("populated SHA384 IsZero() = true, want false")
	}
	if (domain.ArtifactDigests{SHA512: "abc"}).IsZero() {
		t.Error("populated SHA512 IsZero() = true, want false")
	}
}
