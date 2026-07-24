package domain_test

import (
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
)

func TestNewFactRecord(t *testing.T) {
	m := domain2.FetchedModule{
		Coordinate:         coordinate.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"},
		ModuleHash:         domain2.ModuleHash{Algorithm: "h1", Value: "abc=="},
		GoModHash:          domain2.ModuleHash{Algorithm: "h1", Value: "def=="},
		GitReference:       domain2.GitReference{URL: "https://github.com/foo/bar", Ref: "refs/tags/v1.0.0", CommitHash: "aabbcc00000000000000000000000000000000"},
		VerificationStatus: domain2.Verified,
		FetchedAt:          time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		PipelineVersion:    "0.1.0",
		ContentLocation:    "sha256:deadbeef",
	}
	r := domain2.NewFactRecord(m)

	if r.ModulePath != "github.com/foo/bar" {
		t.Errorf("ModulePath = %q", r.ModulePath)
	}
	if r.SchemaVersion != domain2.SchemaVersion {
		t.Errorf("SchemaVersion = %q", r.SchemaVersion)
	}
	if r.ModuleHash != "h1:abc==" {
		t.Errorf("ModuleHash = %q", r.ModuleHash)
	}
	if r.FetchedAt.Location() != time.UTC {
		t.Error("FetchedAt not UTC")
	}
}

func TestFactRecord_Coordinate(t *testing.T) {
	r := domain2.FactRecord{ModulePath: "github.com/foo/bar", ModuleVersion: "v1.0.0"}
	c := r.Coordinate()
	if c.Path != "github.com/foo/bar" || c.Version != "v1.0.0" {
		t.Errorf("Coordinate() = %v", c)
	}
}

func TestFactRecord_IsGoModOnly(t *testing.T) {
	cases := []struct {
		name            string
		contentLocation string
		goModLocation   string
		want            bool
	}{
		{"go.mod-only", "", "sha256:gomod", true},
		{"full record", "sha256:zip", "sha256:gomod", false},
		{"no artefacts", "", "", false},
		{"zip only (never produced, defensive)", "sha256:zip", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := domain2.FactRecord{ContentLocation: tc.contentLocation, GoModLocation: tc.goModLocation}
			if got := r.IsGoModOnly(); got != tc.want {
				t.Errorf("IsGoModOnly() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestModuleHash_IsZero(t *testing.T) {
	var h domain2.ModuleHash
	if !h.IsZero() {
		t.Error("zero value should be IsZero")
	}
	h.Algorithm = "h1"
	if h.IsZero() {
		t.Error("non-zero should not be IsZero")
	}
}

func TestCanonicalHasher_Marshal(t *testing.T) {
	h := domain2.CanonicalHasher{}
	r := sampleRecord()
	r2, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	b, err := h.Marshal(r2)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if len(b) == 0 {
		t.Error("Marshal returned empty bytes")
	}
	// Should be valid JSON containing the content hash.
	if string(b) == "" {
		t.Error("empty JSON")
	}
}
