package domain

import (
	"reflect"
	"testing"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

func TestNormaliseExclusions(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"nil", nil, nil},
		{"all blank", []string{"", ""}, nil},
		{"sort and dedup", []string{"z/m", "a/m", "z/m", ""}, []string{"a/m", "z/m"}},
		{"single", []string{"github.com/some/huge/package"}, []string{"github.com/some/huge/package"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := NormaliseExclusions(tc.in); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("NormaliseExclusions(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestNormaliseExclusions_CopiesInput(t *testing.T) {
	in := []string{"b/m", "a/m"}
	out := NormaliseExclusions(in)
	in[0] = "mutated"
	if out[0] != "a/m" || out[1] != "b/m" {
		t.Errorf("NormaliseExclusions must not alias caller slice; got %v", out)
	}
}

func TestIsModuleExcluded(t *testing.T) {
	list := []string{"github.com/some/huge/package", "", "example.com/x"}
	if !IsModuleExcluded("example.com/x", list) {
		t.Error("expected example.com/x to be excluded")
	}
	if IsModuleExcluded("example.com/y", list) {
		t.Error("example.com/y must not be excluded")
	}
	if IsModuleExcluded("", list) {
		t.Error("empty module path must never match a blank list entry")
	}
	if IsModuleExcluded("example.com/x", nil) {
		t.Error("nil list excludes nothing")
	}
}

func TestNewExcludedRecord(t *testing.T) {
	coord := fetchdomain.ModuleCoordinate{Path: "example.com/x", Version: "v1.0.0"}
	r := NewExcludedRecord(coord, AlgorithmCHA, []string{"a/m", "example.com/x"})
	if r.OverallStatus != CallGraphStatusExcludedByConfig {
		t.Errorf("status = %s, want ExcludedByConfig", r.OverallStatus)
	}
	if r.ExclusionReason != ExclusionReasonConfig {
		t.Errorf("reason = %q, want %q", r.ExclusionReason, ExclusionReasonConfig)
	}
	if r.SchemaVersion != CallGraphSchemaVersion {
		t.Errorf("schema = %q, want %q", r.SchemaVersion, CallGraphSchemaVersion)
	}
	if len(r.Nodes) != 0 || len(r.Edges) != 0 {
		t.Error("excluded record must carry no nodes/edges")
	}
}

func TestExcludedRecord_HashRoundTrip(t *testing.T) {
	var h CallGraphRecordHasher
	coord := fetchdomain.ModuleCoordinate{Path: "example.com/x", Version: "v1.0.0"}
	r := NewExcludedRecord(coord, AlgorithmCHA, []string{"example.com/x", "a/m"})
	r.PipelineVersion = "0.1.0"
	r.Sort()
	r, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if err := h.VerifyContentHash(r); err != nil {
		t.Fatalf("VerifyContentHash: %v", err)
	}
	blob, err := h.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := h.Unmarshal(blob)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.ExclusionReason != ExclusionReasonConfig {
		t.Errorf("round-trip reason = %q, want %q", got.ExclusionReason, ExclusionReasonConfig)
	}
	if !reflect.DeepEqual(got.ExclusionList, []string{"a/m", "example.com/x"}) {
		t.Errorf("round-trip list = %v, want sorted [a/m example.com/x]", got.ExclusionList)
	}
	if got.OverallStatus != CallGraphStatusExcludedByConfig {
		t.Errorf("round-trip status = %s, want ExcludedByConfig", got.OverallStatus)
	}
}
