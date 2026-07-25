package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
)

var sealCoord = coordinate.ModuleCoordinate{Path: "example.com/mod", Version: "v1.0.0"}

// Seal hashes at construction, so there is no window in which an unsealed record
// exists to be mislaid. Before this, the write path built a record, then hashed
// it, then persisted it, and every step in between held a record whose content
// hash did not describe its contents.
func TestSeal_HashesAtConstruction(t *testing.T) {
	sealed, err := domain.Seal(domain.FetchedModule{
		Coordinate:         sealCoord,
		ModuleHash:         domain.ModuleHash{Algorithm: "h1", Value: "zip=="},
		VerificationStatus: domain.Verified,
		PipelineVersion:    "0.1.0",
	})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if sealed.ContentHash() == "" {
		t.Fatal("a sealed record carries no content hash")
	}
	if err := domain.VerifyFactRecord(sealed.Record()); err != nil {
		t.Errorf("a freshly sealed record does not verify: %v", err)
	}
	if sealed.IsZero() {
		t.Error("a sealed record reports itself as the zero value")
	}
}

// Rehydrate fails closed on a record whose stored hash disagrees with its stored
// fields. It is the guard that stops a detected tamper being reconstructed as a
// usable value.
func TestRehydrate_RefusesATamperedRecord(t *testing.T) {
	tampered := fetchtest.Tampered(t,
		fetchtest.Coordinate(sealCoord),
		fetchtest.ModuleHash(fetchtest.H1("zip==")),
	)
	if _, err := domain.Rehydrate(tampered); err == nil {
		t.Error("a record whose body was altered after sealing was rehydrated; the tamper check does not hold")
	}
}

// An unsealed record — one that never carried a hash at all — is refused on the
// same terms.
func TestRehydrate_RefusesAnUnsealedRecord(t *testing.T) {
	unsealed := fetchtest.Unsealed(t,
		fetchtest.Coordinate(sealCoord),
		fetchtest.ModuleHash(fetchtest.H1("zip==")),
	)
	if _, err := domain.Rehydrate(unsealed); err == nil {
		t.Error("a record with no content hash was rehydrated")
	}
}

// A valid record round-trips, so the guard is not simply refusing everything.
func TestRehydrate_AcceptsAValidRecord(t *testing.T) {
	valid := fetchtest.Record(t,
		fetchtest.Coordinate(sealCoord),
		fetchtest.ModuleHash(fetchtest.H1("zip==")),
	)
	sealed, err := domain.Rehydrate(valid)
	if err != nil {
		t.Fatalf("Rehydrate of a valid record: %v", err)
	}
	if sealed.ContentHash() != valid.ContentHash {
		t.Errorf("ContentHash = %q, want %q", sealed.ContentHash(), valid.ContentHash)
	}
	if sealed.Coordinate() != sealCoord {
		t.Errorf("Coordinate = %v, want %v", sealed.Coordinate(), sealCoord)
	}
}

// A record's identity is its zip hash when it has one and its go.mod hash when
// it does not, and the two never collide even at equal hash values.
func TestArtefactIdentityOf(t *testing.T) {
	full := fetchtest.Record(t,
		fetchtest.Coordinate(sealCoord),
		fetchtest.ModuleHash(fetchtest.H1("same==")),
		fetchtest.GoModHash(fetchtest.H1("mod==")),
	)
	shallow := fetchtest.Record(t,
		fetchtest.Coordinate(sealCoord),
		fetchtest.GoModOnly("m"),
		fetchtest.GoModHash(fetchtest.H1("same==")),
	)

	fullID, err := domain.ArtefactIdentityOf(full)
	if err != nil {
		t.Fatalf("ArtefactIdentityOf(full): %v", err)
	}
	shallowID, err := domain.ArtefactIdentityOf(shallow)
	if err != nil {
		t.Fatalf("ArtefactIdentityOf(shallow): %v", err)
	}

	if fullID.GoModOnly {
		t.Error("a record carrying a zip hash was identified as go.mod-only")
	}
	if !shallowID.GoModOnly {
		t.Error("a record with no zip hash was not identified as go.mod-only")
	}
	// Both hold the h1 value "same==", so only the depth keeps them apart.
	if fullID.Equal(shallowID) {
		t.Error("a zip and a go.mod of equal hash collided into one identity")
	}
	if fullID.String() == shallowID.String() {
		t.Errorf("identity strings collide: %q", fullID.String())
	}
}

// Absence is tested with IsZero, never by string comparison. A zero hash
// persists as the bare ":" separator, so comparing the stored string would
// collide every go.mod-only record of every module into one bucket.
func TestArtefactIdentityOf_ReadsThePersistedZeroHash(t *testing.T) {
	r := fetchtest.Record(t,
		fetchtest.Coordinate(sealCoord),
		fetchtest.GoModOnly("m"),
		fetchtest.GoModHash(fetchtest.H1("mod==")),
	)
	if r.ModuleHash != domain.ZeroString {
		t.Fatalf("fixture module hash = %q, want the persisted zero form %q", r.ModuleHash, domain.ZeroString)
	}
	id, err := domain.ArtefactIdentityOf(r)
	if err != nil {
		t.Fatalf("ArtefactIdentityOf could not read the persisted zero hash: %v", err)
	}
	if !id.GoModOnly || id.Hash.Value != "mod==" {
		t.Errorf("identity = %v, want the go.mod hash", id)
	}
}

// A malformed hash is an error, never a silently zero identity: a corrupt value
// must not be mistaken for a recorded absence.
func TestArtefactIdentityOf_MalformedHashIsAnError(t *testing.T) {
	r := fetchtest.Record(t, fetchtest.Coordinate(sealCoord))
	r.ModuleHash = "not-a-hash"
	if _, err := domain.ArtefactIdentityOf(r); err == nil {
		t.Error("a malformed module hash produced an identity instead of an error")
	}
}
