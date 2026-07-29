package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/fetch/domain"
)

// TestFactRecord_Coordinate_RefusesToInventAModule covers the reconstruction
// leg of FactRecord.Coordinate.
//
// The record stores the coordinate taken apart into two strings, so reading it
// back puts them through the validating constructor. A record whose stored
// fields are not a coordinate was persisted from something that never was one,
// and the zero coordinate is the right answer: it renders as "@", which is
// visibly not a module, where a half-built coordinate would render as a
// plausible one and be looked up as though it existed.
func TestFactRecord_Coordinate_RefusesToInventAModule(t *testing.T) {
	valid := domain.FactRecord{ModulePath: "example.com/mod", ModuleVersion: "v1.0.0"}
	if got := valid.Coordinate(); got.Path() != "example.com/mod" || got.Version() != "v1.0.0" {
		t.Fatalf("Coordinate() = %v, want example.com/mod@v1.0.0", got)
	}

	for _, tc := range []struct {
		name   string
		record domain.FactRecord
	}{
		{"version is not a version", domain.FactRecord{ModulePath: "example.com/mod", ModuleVersion: "not-semver"}},
		{"no version at all", domain.FactRecord{ModulePath: "example.com/mod"}},
		{"no path", domain.FactRecord{ModuleVersion: "v1.0.0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.record.Coordinate()
			if !got.IsZero() {
				t.Errorf("Coordinate() = %v, want the zero coordinate rather than a plausible-looking module", got)
			}
			if got.String() != "@" {
				t.Errorf("String() = %q, want %q so it is visibly not a module", got.String(), "@")
			}
		})
	}
}
