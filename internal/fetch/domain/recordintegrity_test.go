package domain_test

import (
	"errors"
	"testing"

	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
)

func TestVerifyFactRecord_Valid(t *testing.T) {
	if err := domain2.VerifyFactRecord(fetchtest.Record(t)); err != nil {
		t.Fatalf("VerifyFactRecord on a valid record: %v", err)
	}
}

func TestVerifyFactRecord_WrongEcosystem(t *testing.T) {
	r := fetchtest.Record(t, fetchtest.Ecosystem("npm"))
	err := domain2.VerifyFactRecord(r)
	if !errors.Is(err, domain2.ErrUnsupportedEcosystem) {
		t.Fatalf("want ErrUnsupportedEcosystem, got %v", err)
	}
}

func TestVerifyFactRecord_MissingSchemaVersion(t *testing.T) {
	// Sealed without a SchemaVersion so the failure is the schema check, not an
	// incidental content-hash mismatch.
	r := fetchtest.Record(t, fetchtest.SchemaVersion(""))
	if err := domain2.VerifyFactRecord(r); !errors.Is(err, domain2.ErrMissingSchemaVersion) {
		t.Fatalf("want ErrMissingSchemaVersion, got %v", err)
	}
}

func TestVerifyFactRecord_TamperedContentHash(t *testing.T) {
	// A record whose body changed after hashing: the keyless tamper-evidence
	// check must fail.
	r := fetchtest.Tampered(t)
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
	r := fetchtest.Tampered(t, fetchtest.Ecosystem(""))
	if err := domain2.VerifyFactRecord(r); !errors.Is(err, domain2.ErrUnsupportedEcosystem) {
		t.Fatalf("want ErrUnsupportedEcosystem first, got %v", err)
	}
}
