package domain_test

import (
	"errors"
	"testing"

	"github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
)

// ParseArtefactIdentity is the reader for the form String writes, so the pair
// has to round-trip: an identity persisted by a writer and read back by another
// context must name the same artefact at the same depth. A zip and a go.mod of
// equal hash differ only by the prefix, which is precisely what the round trip
// has to preserve.
func TestParseArtefactIdentity_RoundTripsTheStringForm(t *testing.T) {
	for _, want := range []domain.ArtefactIdentity{
		fetchtest.ZipArtefact("same=="),
		fetchtest.GoModArtefact("same=="),
	} {
		t.Run(want.String(), func(t *testing.T) {
			got, err := domain.ParseArtefactIdentity(want.String())
			if err != nil {
				t.Fatalf("ParseArtefactIdentity(%q): %v", want.String(), err)
			}
			if !got.Equal(want) {
				t.Errorf("ParseArtefactIdentity(%q) = %v, want %v", want.String(), got, want)
			}
			if got.Hash().Value() != "same==" || got.GoModOnly() != want.GoModOnly() {
				t.Errorf("read back %+v, want the hash and depth it was written with", got)
			}
		})
	}
}

// A value the reader cannot read is not evidence of an artefact that was never
// measured. Every malformed spelling below must be an error rather than a zero
// identity, because a zero identity read out of a corrupt column would be
// indistinguishable from a record that legitimately names nothing.
func TestParseArtefactIdentity_FailsClosed(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "empty", input: ""},
		{name: "no depth prefix", input: "h1:abc=="},
		{name: "unknown depth prefix", input: "tarball:h1:abc=="},
		{name: "prefix only", input: "zip:"},
		{name: "zero hash", input: "zip::"},
		{name: "hash with no value", input: "zip:h1:"},
		{name: "hash with no algorithm", input: "gomod::abc=="},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := domain.ParseArtefactIdentity(tt.input)
			if err == nil {
				t.Fatalf("ParseArtefactIdentity(%q) = %v, want an error", tt.input, got)
			}
			if !got.IsZero() {
				t.Errorf("refused identity = %v, want the zero identity", got)
			}
		})
	}
}

// The two spellings of "this names no artefact" are refused with
// ErrZeroIdentity specifically, so a caller can tell an identity that is absent
// from one that is corrupt without matching on error text.
func TestParseArtefactIdentity_ZeroIsRefusedWithErrZeroIdentity(t *testing.T) {
	for _, input := range []string{"", "zip::"} {
		_, err := domain.ParseArtefactIdentity(input)
		if !errors.Is(err, domain.ErrZeroIdentity) {
			t.Errorf("ParseArtefactIdentity(%q) error = %v, want %v", input, err, domain.ErrZeroIdentity)
		}
	}
}

// The zero identity is what String renders as the empty string, and reading
// that back is refused. The pair is what makes ErrZeroIdentity a fact rather
// than a doc comment.
func TestArtefactIdentity_ZeroValue(t *testing.T) {
	var zero domain.ArtefactIdentity
	if !zero.IsZero() {
		t.Error("the zero ArtefactIdentity does not report IsZero")
	}
	if got := zero.String(); got != "" {
		t.Errorf("zero identity String() = %q, want the empty string", got)
	}
	if !zero.Hash().IsZero() || zero.GoModOnly() {
		t.Errorf("zero identity reads as %+v, want no hash at no depth", zero)
	}
}

// A measurement's identity and its record's identity must agree: the record is
// written from the measurement, and a satellite table keyed on one is read
// against the other. Deriving both from the same rule is what keeps them from
// drifting, so the test asserts them equal rather than asserting each shape
// separately.
func TestArtefactIdentityOfMeasurement_AgreesWithTheRecord(t *testing.T) {
	tests := []struct {
		name          string
		measurement   domain.FetchedModule
		record        []fetchtest.Option
		wantGoModOnly bool
	}{
		{
			name: "zip fetched",
			measurement: domain.FetchedModule{
				ModuleHash: fetchtest.H1("zip=="),
				GoModHash:  fetchtest.H1("mod=="),
			},
			record: []fetchtest.Option{
				fetchtest.ModuleHash(fetchtest.H1("zip==")),
				fetchtest.GoModHash(fetchtest.H1("mod==")),
			},
		},
		{
			name: "go.mod only",
			measurement: domain.FetchedModule{
				GoModHash: fetchtest.H1("mod=="),
			},
			record: []fetchtest.Option{
				fetchtest.GoModOnly("m"),
				fetchtest.GoModHash(fetchtest.H1("mod==")),
			},
			wantGoModOnly: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := domain.ArtefactIdentityOfMeasurement(tt.measurement)
			if got.GoModOnly() != tt.wantGoModOnly {
				t.Errorf("GoModOnly() = %v, want %v", got.GoModOnly(), tt.wantGoModOnly)
			}
			want, err := domain.ArtefactIdentityOf(fetchtest.Record(t, tt.record...))
			if err != nil {
				t.Fatalf("ArtefactIdentityOf: %v", err)
			}
			if !got.Equal(want) {
				t.Errorf("measurement identity = %v, record identity = %v; they must agree", got, want)
			}
		})
	}
}
