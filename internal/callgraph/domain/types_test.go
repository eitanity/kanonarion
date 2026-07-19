package domain_test

import (
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

func TestCallGraphStatusString(t *testing.T) {
	cases := []struct {
		status domain.CallGraphStatus
		want   string
	}{
		{domain.CallGraphStatusUnknown, "Unknown"},
		{domain.CallGraphStatusExtracted, "Extracted"},
		{domain.CallGraphStatusPartial, "Partial"},
		{domain.CallGraphStatusLoadFailed, "LoadFailed"},
		{domain.CallGraphStatusOutOfMemory, "OutOfMemory"},
		{domain.CallGraphStatusCancelled, "Cancelled"},
		{domain.CallGraphStatusExtractionFailed, "ExtractionFailed"},
		{domain.CallGraphStatus(99), "Unknown"},
	}
	for _, tc := range cases {
		if got := tc.status.String(); got != tc.want {
			t.Errorf("CallGraphStatus(%d).String() = %q, want %q", int(tc.status), got, tc.want)
		}
	}
}

func TestMigrateConfidence(t *testing.T) {
	cases := []struct {
		name        string
		stored      string
		want        domain.EdgeConfidence
		wantReflect bool
	}{
		{"legacy dynamic dispatch folds to CHA-overapprox", "DynamicDispatch", domain.ConfidenceCHAOverapprox, false},
		{"legacy reflection folds to Unknown with reflect origin", "Reflection", domain.ConfidenceUnknown, true},
		{"direct passes through", "Direct", domain.ConfidenceDirect, false},
		{"CHA-overapprox passes through", "CHA-overapprox", domain.ConfidenceCHAOverapprox, false},
		{"VTA passes through", "VTA", domain.ConfidenceVTA, false},
		{"framework passes through", "Framework", domain.ConfidenceFramework, false},
		{"unknown passes through", "Unknown", domain.ConfidenceUnknown, false},
		{"unrecognised value passes through verbatim", "Something", domain.EdgeConfidence("Something"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, gotReflect := domain.MigrateConfidence(tc.stored)
			if got != tc.want || gotReflect != tc.wantReflect {
				t.Errorf("MigrateConfidence(%q) = (%q, %t), want (%q, %t)",
					tc.stored, got, gotReflect, tc.want, tc.wantReflect)
			}
		})
	}
}

func TestCallGraphRecordSort(t *testing.T) {
	coord, _ := fetchdomain.NewModuleCoordinate("example.com/mod", "v1.0.0")
	r := domain.CallGraphRecord{
		Coordinate: coord,
		Nodes: []domain.CallNode{
			{ID: "example.com/mod.Gamma"},
			{ID: "example.com/mod.Alpha"},
			{ID: "example.com/mod.Beta"},
		},
		Edges: []domain.CallEdge{
			{FromID: "example.com/mod.Beta", ToID: "example.com/mod.Gamma", CallSite: domain.SourcePosition{File: "b.go", Line: 10}},
			{FromID: "example.com/mod.Alpha", ToID: "example.com/mod.Beta", CallSite: domain.SourcePosition{File: "a.go", Line: 5}},
			{FromID: "example.com/mod.Alpha", ToID: "example.com/mod.Beta", CallSite: domain.SourcePosition{File: "a.go", Line: 3}},
		},
	}
	r.Sort()

	if r.Nodes[0].ID != "example.com/mod.Alpha" {
		t.Errorf("first node after sort = %q, want Alpha", r.Nodes[0].ID)
	}
	if r.Nodes[2].ID != "example.com/mod.Gamma" {
		t.Errorf("last node after sort = %q, want Gamma", r.Nodes[2].ID)
	}
	// Edges: Alpha→Beta@3, Alpha→Beta@5, Beta→Gamma@10
	if r.Edges[0].FromID != "example.com/mod.Alpha" || r.Edges[0].CallSite.Line != 3 {
		t.Errorf("first edge after sort = %+v", r.Edges[0])
	}
	if r.Edges[2].FromID != "example.com/mod.Beta" {
		t.Errorf("last edge after sort = %+v", r.Edges[2])
	}
}

func makeTestRecord() domain.CallGraphRecord {
	coord, _ := fetchdomain.NewModuleCoordinate("example.com/mod", "v1.0.0")
	return domain.CallGraphRecord{
		SchemaVersion: domain.CallGraphSchemaVersion,
		Ecosystem:     fetchdomain.EcosystemGo,
		Coordinate:    coord,
		Algorithm:     domain.AlgorithmCHA,
		Nodes: []domain.CallNode{
			{
				ID:            "example.com/mod.Alpha",
				Module:        "example.com/mod",
				Package:       "example.com/mod",
				Symbol:        "Alpha",
				IsExportedAPI: true,
				Position:      domain.SourcePosition{File: "a.go", Line: 3},
			},
		},
		Edges: []domain.CallEdge{
			{
				FromID:     "example.com/mod.Alpha",
				ToID:       "example.com/mod.Beta",
				CallSite:   domain.SourcePosition{File: "a.go", Line: 5},
				Confidence: domain.ConfidenceDirect,
			},
		},
		OverallStatus:   domain.CallGraphStatusExtracted,
		NodeCount:       1,
		EdgeCount:       1,
		ExtractedAt:     time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		PipelineVersion: "0.1.0",
	}
}
