package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
)

// The upgrade path — a go.mod-only measurement followed by a full one — is NOT a
// divergence. They agree on the hash they share and only one carries a zip hash,
// so they describe one artefact at two depths.
//
// This is the case that decides the rule. Measured on the maintainer's store, a
// naive "more than one artefact hash for a coordinate" rule fires on 90
// legitimate upgrade pairs; the shared-hash rule fires on none.
func TestFindDivergence_GoModOnlyThenFullIsSilent(t *testing.T) {
	coord := coordinate.ModuleCoordinate{Path: "example.com/mod", Version: "v1.0.0"}
	goModOnly := fetchtest.Record(t,
		fetchtest.Coordinate(coord),
		fetchtest.GoModOnly("gomod"),
		fetchtest.GoModHash(fetchtest.H1("mod==")),
	)
	full := fetchtest.Record(t,
		fetchtest.Coordinate(coord),
		fetchtest.ModuleHash(fetchtest.H1("zip==")),
		fetchtest.GoModHash(fetchtest.H1("mod==")),
	)

	if d := domain.FindDivergence([]domain.FactRecord{goModOnly, full}); d != nil {
		t.Errorf("the ordinary upgrade path was reported as a divergence: %v", d)
	}
}

// Two records disagreeing on a hash they BOTH carry is the same pinned version
// described by two different artefacts.
func TestFindDivergence_DisagreementOnASharedHash(t *testing.T) {
	coord := coordinate.ModuleCoordinate{Path: "example.com/mod", Version: "v1.0.0"}
	for _, tc := range []struct {
		name  string
		a, b  []fetchtest.Option
		field string
	}{
		{
			name:  "different zip hashes",
			a:     []fetchtest.Option{fetchtest.ModuleHash(fetchtest.H1("zip-a=="))},
			b:     []fetchtest.Option{fetchtest.ModuleHash(fetchtest.H1("zip-b=="))},
			field: "module_hash",
		},
		{
			name:  "different go.mod hashes",
			a:     []fetchtest.Option{fetchtest.GoModOnly("m"), fetchtest.GoModHash(fetchtest.H1("mod-a=="))},
			b:     []fetchtest.Option{fetchtest.GoModOnly("m"), fetchtest.GoModHash(fetchtest.H1("mod-b=="))},
			field: "go_mod_hash",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := fetchtest.Record(t, append([]fetchtest.Option{fetchtest.Coordinate(coord)}, tc.a...)...)
			b := fetchtest.Record(t, append([]fetchtest.Option{fetchtest.Coordinate(coord)}, tc.b...)...)

			d := domain.FindDivergence([]domain.FactRecord{a, b})
			if d == nil {
				t.Fatal("two records describing different artefacts were not reported as a divergence")
			}
			if d.Field != tc.field {
				t.Errorf("Field = %q, want %q", d.Field, tc.field)
			}
			if len(d.ContentHashes) != 2 {
				t.Errorf("the divergence names %d records, want 2 so an operator can find them", len(d.ContentHashes))
			}
		})
	}
}

// A local coordinate is exempt. A local version pins no content, so successive
// measurements of it are a sequence rather than competing claims, and the walker
// deliberately re-reads the working tree on every walk.
func TestFindDivergence_LocalCoordinateIsExempt(t *testing.T) {
	local := coordinate.ModuleCoordinate{Path: "example.com/proj", Version: coordinate.LocalVersion}
	a := fetchtest.Record(t, fetchtest.Coordinate(local), fetchtest.ModuleHash(fetchtest.H1("tree-a==")))
	b := fetchtest.Record(t, fetchtest.Coordinate(local), fetchtest.ModuleHash(fetchtest.H1("tree-b==")))

	if d := domain.FindDivergence([]domain.FactRecord{a, b}); d != nil {
		t.Errorf("two observations of a changing working tree were reported as a divergence: %v", d)
	}
}

// Repeated measurements of one artefact are silent however many there are. The
// maintainer's audit log holds 44 measurements of a single coordinate; they
// agree on every hash, so none of them contradicts another.
func TestFindDivergence_RepeatedMeasurementsOfOneArtefactAreSilent(t *testing.T) {
	coord := coordinate.ModuleCoordinate{Path: "gopkg.in/yaml.v3", Version: "v3.0.1"}
	var records []domain.FactRecord
	for i := range 44 {
		records = append(records, fetchtest.Record(t,
			fetchtest.Coordinate(coord),
			fetchtest.ModuleHash(fetchtest.H1("zip==")),
			fetchtest.GoModHash(fetchtest.H1("mod==")),
			fetchtest.Detail(string(rune('a'+i%26))), // a different record each time
		))
	}
	if d := domain.FindDivergence(records); d != nil {
		t.Errorf("44 measurements of one artefact were reported as a divergence: %v", d)
	}
}
