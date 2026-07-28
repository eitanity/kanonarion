package ports_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

// A blob identity is persisted: its String is what the content_location and
// go_mod_location columns of every fact record hold. The two refusals below are
// the whole point of the constructor — each closes a shape that renders to a
// string no reader can read back, and neither is reachable any longer through a
// struct literal.
func TestNewBlobIdentity_RefusesAKindThatNamesNoArtefact(t *testing.T) {
	for _, kind := range []ports.BlobKind{"", "tarball", "ZIP"} {
		identity, err := ports.NewBlobIdentity(kind, fetchtest.H1("some-artefact"))
		if !errors.Is(err, ports.ErrUnknownBlobKind) {
			t.Errorf("NewBlobIdentity(%q, hash) error = %v, want ErrUnknownBlobKind", kind, err)
		}
		if !identity.IsZero() {
			t.Errorf("NewBlobIdentity(%q, hash) returned a usable identity %q alongside its refusal", kind, identity)
		}
	}
}

func TestNewBlobIdentity_RefusesAZeroHash(t *testing.T) {
	identity, err := ports.NewBlobIdentity(ports.BlobKindZip, domain.ModuleHash{})
	if !errors.Is(err, domain.ErrZeroIdentity) {
		t.Errorf("NewBlobIdentity(zip, zero hash) error = %v, want ErrZeroIdentity", err)
	}
	if !identity.IsZero() {
		t.Errorf("NewBlobIdentity(zip, zero hash) returned %q, want the zero identity", identity)
	}
}

// The kind is what stops a store holding both artefacts of a module version
// serving one for the other when their h1 values coincide.
func TestNewBlobIdentity_KindSeparatesArtefactsOfEqualHash(t *testing.T) {
	hash := fetchtest.H1("identical-bytes")

	zip, err := ports.NewBlobIdentity(ports.BlobKindZip, hash)
	if err != nil {
		t.Fatalf("NewBlobIdentity(zip): %v", err)
	}
	goMod, err := ports.NewBlobIdentity(ports.BlobKindGoMod, hash)
	if err != nil {
		t.Fatalf("NewBlobIdentity(gomod): %v", err)
	}

	if zip.String() == goMod.String() {
		t.Fatalf("zip and go.mod of equal hash both render as %q; a store keyed on the rendering collides them", zip)
	}
	if got, want := zip.String(), "zip:"+hash.String(); got != want {
		t.Errorf("zip identity renders as %q, want %q", got, want)
	}
	if got, want := goMod.String(), "gomod:"+hash.String(); got != want {
		t.Errorf("go.mod identity renders as %q, want %q", got, want)
	}
	if zip.Kind() != ports.BlobKindZip || !zip.Hash().Equal(hash) {
		t.Errorf("zip identity reads back as (%q, %q), want (%q, %q)", zip.Kind(), zip.Hash(), ports.BlobKindZip, hash)
	}
}

// The zero identity addresses nothing and renders to the empty string, which is
// how a record that never recorded a location is spelled. That is why the
// constructor refuses to produce one.
func TestBlobIdentity_ZeroRendersAsAbsence(t *testing.T) {
	var identity ports.BlobIdentity
	if !identity.IsZero() {
		t.Error("the zero BlobIdentity reports IsZero() = false")
	}
	if got := identity.String(); got != "" {
		t.Errorf("the zero BlobIdentity renders as %q, want the empty string", got)
	}
}

// ZipIdentity and GoModIdentity are the ordinary route: a reader that has a
// record derives the address from the hashes on it rather than building one.
func TestZipAndGoModIdentity_DeriveFromTheRecordsHashes(t *testing.T) {
	zipHash := fetchtest.H1("zip-bytes")
	goModHash := fetchtest.H1("go-mod-bytes")
	record := fetchtest.Record(t,
		fetchtest.ModuleHash(zipHash),
		fetchtest.GoModHash(goModHash),
	)

	zip, ok, err := ports.ZipIdentity(record)
	if err != nil || !ok {
		t.Fatalf("ZipIdentity: ok=%v err=%v, want a derived identity", ok, err)
	}
	if got, want := zip.String(), "zip:"+zipHash.String(); got != want {
		t.Errorf("ZipIdentity rendered %q, want %q", got, want)
	}

	goMod, ok, err := ports.GoModIdentity(record)
	if err != nil || !ok {
		t.Fatalf("GoModIdentity: ok=%v err=%v, want a derived identity", ok, err)
	}
	if got, want := goMod.String(), "gomod:"+goModHash.String(); got != want {
		t.Errorf("GoModIdentity rendered %q, want %q", got, want)
	}
}

// Absence is not an error: a go.mod-only measurement has no zip to address, and
// the caller is told so rather than handed an identity that names nothing.
func TestZipIdentity_ReportsAbsenceOnAGoModOnlyRecord(t *testing.T) {
	record := fetchtest.Record(t,
		fetchtest.ModuleHash(domain.ModuleHash{}),
		fetchtest.GoModHash(fetchtest.H1("go-mod-bytes")),
	)

	identity, ok, err := ports.ZipIdentity(record)
	if err != nil {
		t.Fatalf("ZipIdentity on a go.mod-only record: %v", err)
	}
	if ok {
		t.Errorf("ZipIdentity reported %q on a record with no zip", identity)
	}
	if !identity.IsZero() {
		t.Errorf("ZipIdentity returned %q alongside ok=false", identity)
	}
}

// A stored hash the domain cannot read fails closed. It must not degrade to an
// absent zip, which would silently drop the artefact from every consumer that
// asks for its bytes.
func TestZipIdentity_FailsClosedOnAMalformedStoredHash(t *testing.T) {
	record := fetchtest.Record(t)
	record.ModuleHash = "not-an-algorithm-value-pair"

	if _, ok, err := ports.ZipIdentity(record); err == nil {
		t.Errorf("ZipIdentity on a malformed stored hash: ok=%v err=nil, want a refusal", ok)
	} else if !strings.Contains(err.Error(), "deriving zip identity") {
		t.Errorf("ZipIdentity error = %v, want it to name the derivation it refused", err)
	}
}
