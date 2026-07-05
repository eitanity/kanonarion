package domain_test

import (
	"errors"
	"testing"

	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// hashed returns sampleRecord with a valid canonical content hash set.
func hashed(t *testing.T) domain2.FactRecord {
	t.Helper()
	r, err := domain2.CanonicalHasher{}.SetContentHash(sampleRecord())
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	return r
}

func TestVerifyFactRecord_Valid(t *testing.T) {
	if err := domain2.VerifyFactRecord(hashed(t)); err != nil {
		t.Fatalf("VerifyFactRecord on a valid record: %v", err)
	}
}

func TestVerifyFactRecord_WrongEcosystem(t *testing.T) {
	r := hashed(t)
	r.Ecosystem = "npm"
	err := domain2.VerifyFactRecord(r)
	if !errors.Is(err, domain2.ErrUnsupportedEcosystem) {
		t.Fatalf("want ErrUnsupportedEcosystem, got %v", err)
	}
}

func TestVerifyFactRecord_MissingSchemaVersion(t *testing.T) {
	// Re-hash after clearing SchemaVersion so the failure is the schema check,
	// not an incidental content-hash mismatch.
	r := sampleRecord()
	r.SchemaVersion = ""
	r, err := domain2.CanonicalHasher{}.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if err := domain2.VerifyFactRecord(r); !errors.Is(err, domain2.ErrMissingSchemaVersion) {
		t.Fatalf("want ErrMissingSchemaVersion, got %v", err)
	}
}

func TestVerifyFactRecord_TamperedContentHash(t *testing.T) {
	// A record whose body changed after hashing: the keyless tamper-evidence
	// check must fail.
	r := hashed(t)
	r.VerificationStatus = "UnverifiedHashMismatch"
	err := domain2.VerifyFactRecord(r)
	if err == nil {
		t.Fatal("want content-hash mismatch error, got nil")
	}
	if errors.Is(err, domain2.ErrUnsupportedEcosystem) || errors.Is(err, domain2.ErrMissingSchemaVersion) {
		t.Fatalf("expected a content-hash error, got %v", err)
	}
}

func TestVerifyFactRecord_EcosystemCheckedBeforeHash(t *testing.T) {
	// A record with both a bad ecosystem and a stale hash reports the ecosystem
	// failure first, pinning the documented ordering.
	r := hashed(t)
	r.Ecosystem = ""
	if err := domain2.VerifyFactRecord(r); !errors.Is(err, domain2.ErrUnsupportedEcosystem) {
		t.Fatalf("want ErrUnsupportedEcosystem first, got %v", err)
	}
}
