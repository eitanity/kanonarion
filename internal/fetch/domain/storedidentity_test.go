package domain_test

import (
	"errors"
	"testing"

	"github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
)

// TestStoredArtefactIdentity_EmptyIsAbsentNotCorrupt pins the distinction the
// helper exists to draw. ParseArtefactIdentity refuses the empty string on
// purpose; a derived record written before the identity field existed carries
// exactly that, and there are millions of them. Reading one must yield "not
// recorded", not an error, or every legacy record becomes unreadable.
func TestStoredArtefactIdentity_EmptyIsAbsentNotCorrupt(t *testing.T) {
	t.Parallel()

	got, err := domain.StoredArtefactIdentity("")
	if err != nil {
		t.Fatalf("StoredArtefactIdentity(%q) error = %v, want nil", "", err)
	}
	if !got.IsZero() {
		t.Fatalf("StoredArtefactIdentity(%q) = %v, want the zero identity", "", got)
	}

	// The parser it delegates to still refuses the same input, so the tolerance
	// is this helper's and is not smuggled into the parser.
	if _, perr := domain.ParseArtefactIdentity(""); !errors.Is(perr, domain.ErrZeroIdentity) {
		t.Fatalf("ParseArtefactIdentity(%q) error = %v, want %v", "", perr, domain.ErrZeroIdentity)
	}
}

// TestStoredArtefactIdentity_RoundTripsThePersistedForm proves the helper reads
// back exactly what String writes, at both artefact depths.
func TestStoredArtefactIdentity_RoundTripsThePersistedForm(t *testing.T) {
	t.Parallel()

	for _, want := range []domain.ArtefactIdentity{
		fetchtest.ZipArtefact("abc123="),
		fetchtest.GoModArtefact("abc123="),
	} {
		got, err := domain.StoredArtefactIdentity(want.String())
		if err != nil {
			t.Fatalf("StoredArtefactIdentity(%q) error = %v", want.String(), err)
		}
		if !got.Equal(want) {
			t.Errorf("StoredArtefactIdentity(%q) = %v, want %v", want.String(), got, want)
		}
	}

	// The two depths do not collide even when they carry the same hash value:
	// that is what the prefix is for, and it is the reason a stored identity is
	// not just a bare hash.
	zip := fetchtest.ZipArtefact("same=")
	goMod := fetchtest.GoModArtefact("same=")
	if zip.String() == goMod.String() {
		t.Fatalf("zip and go.mod identities of the same hash share a persisted form: %q", zip.String())
	}
}

// TestStoredArtefactIdentity_CorruptIsStillAnError is the other half of the
// distinction: tolerating absence must not tolerate a value that cannot be read.
// A corrupt column silently read as "no artefact" is how every record that
// recorded nothing gets grouped together by the composition that keys on it.
func TestStoredArtefactIdentity_CorruptIsStillAnError(t *testing.T) {
	t.Parallel()

	for _, s := range []string{
		"h1:abc123=",         // no depth prefix
		"tarball:h1:abc123=", // unknown depth
		"zip:nonsense",       // unreadable hash
		"zip:h1:",            // hash present in form only
		" zip:h1:abc123=",    // not the canonical spelling
	} {
		if _, err := domain.StoredArtefactIdentity(s); err == nil {
			t.Errorf("StoredArtefactIdentity(%q) error = nil, want a refusal", s)
		}
	}
}
