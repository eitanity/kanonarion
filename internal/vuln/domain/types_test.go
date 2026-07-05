package domain_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

func TestVulnerabilityStatus_Values(t *testing.T) {
	statuses := []domain.VulnerabilityStatus{
		domain.StatusClean,
		domain.StatusAffected,
		domain.StatusUnscannable,
		domain.StatusScanFailed,
	}
	for _, s := range statuses {
		if s == "" {
			t.Errorf("status constant must not be empty")
		}
	}
}

func TestWalkScanStatus_Values(t *testing.T) {
	statuses := []domain.WalkScanStatus{
		domain.WalkStatusAllClean,
		domain.WalkStatusAffected,
		domain.WalkStatusPartial,
		domain.WalkStatusFailed,
	}
	for _, s := range statuses {
		if s == "" {
			t.Errorf("walk scan status constant must not be empty")
		}
	}
}

func TestReachabilityConfidence_Values(t *testing.T) {
	levels := []domain.ReachabilityConfidence{
		domain.ConfidenceHigh,
		domain.ConfidenceMedium,
		domain.ConfidenceLow,
		domain.ConfidenceUnknown,
	}
	for _, l := range levels {
		if l == "" {
			t.Errorf("confidence constant must not be empty")
		}
	}
}

func TestVulnerabilityRecord_ZeroFindings(t *testing.T) {
	rec := domain.VulnerabilityRecord{
		Coordinate:      fetchdomain.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"},
		WalkID:          "walk-1",
		OverallStatus:   domain.StatusClean,
		ScannedAt:       time.Now(),
		PipelineVersion: "v1",
	}
	if len(rec.Findings) != 0 {
		t.Errorf("expected zero findings, got %d", len(rec.Findings))
	}
}

func TestVulnerabilityRecord_EcosystemPresentAfterRoundTrip(t *testing.T) {
	rec := domain.VulnerabilityRecord{
		Ecosystem:       fetchdomain.EcosystemGo,
		Coordinate:      fetchdomain.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"},
		OverallStatus:   domain.StatusClean,
		PipelineVersion: "v1",
	}
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !bytes.Contains(data, []byte(`"ecosystem":"go"`)) {
		t.Errorf("canonical JSON missing ecosystem field: %s", data)
	}
	var got domain.VulnerabilityRecord
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.Ecosystem != fetchdomain.EcosystemGo {
		t.Errorf("Ecosystem after round-trip = %q, want %q", got.Ecosystem, fetchdomain.EcosystemGo)
	}
}

func TestVulnerabilityRecord_RejectsForeignEcosystem(t *testing.T) {
	var got domain.VulnerabilityRecord
	if err := json.Unmarshal([]byte(`{"ecosystem":"npm","coordinate":{"path":"x","version":"v1.0.0"}}`), &got); !errors.Is(err, fetchdomain.ErrUnsupportedEcosystem) {
		t.Errorf("expected ErrUnsupportedEcosystem for npm, got %v", err)
	}
}

func TestVulnerabilityRecord_RejectsAbsentEcosystem(t *testing.T) {
	var got domain.VulnerabilityRecord
	if err := json.Unmarshal([]byte(`{"coordinate":{"path":"x","version":"v1.0.0"}}`), &got); !errors.Is(err, fetchdomain.ErrUnsupportedEcosystem) {
		t.Errorf("expected ErrUnsupportedEcosystem for absent field, got %v", err)
	}
}

func TestVulnerabilityFinding_Aliases(t *testing.T) {
	f := domain.VulnerabilityFinding{
		ID:      "GO-2024-0001",
		Aliases: []string{"CVE-2024-0001", "GHSA-xxxx-yyyy-zzzz"},
		Summary: "test vulnerability",
	}
	if len(f.Aliases) != 2 {
		t.Errorf("expected 2 aliases, got %d", len(f.Aliases))
	}
}

func TestDatabaseSnapshot_Fields(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	s := domain.DatabaseSnapshot{
		Source:      "govulndb",
		Version:     "v2024-01-01",
		RetrievedAt: now,
		ContentHash: "abc123",
	}
	if s.Source == "" || s.Version == "" || s.ContentHash == "" {
		t.Error("snapshot fields must not be empty")
	}
	if !s.RetrievedAt.Equal(now) {
		t.Errorf("retrieved_at: got %v, want %v", s.RetrievedAt, now)
	}
}

func TestWalkScanRun_PerModuleResults(t *testing.T) {
	coord := fetchdomain.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}
	run := domain.WalkScanRun{
		ID:     "run-1",
		WalkID: "walk-1",
		PerModuleResults: map[fetchdomain.ModuleCoordinate]string{
			coord: "hash-abc",
		},
	}
	if hash, ok := run.PerModuleResults[coord]; !ok || hash != "hash-abc" {
		t.Errorf("per-module result not stored correctly")
	}
}

func TestVulnerabilityFinding_FixDisplay(t *testing.T) {
	cases := []struct {
		name    string
		fixedIn string
		want    string
	}{
		{"with fix", "v1.7.4", "fixed in v1.7.4"},
		{"no fix", "", "no fix available"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := domain.VulnerabilityFinding{FixedIn: tc.fixedIn}
			if got := f.FixDisplay(); got != tc.want {
				t.Errorf("FixDisplay() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSortFindings_OrdersByID(t *testing.T) {
	findings := []domain.VulnerabilityFinding{
		{ID: "GO-2025-0003"},
		{ID: "GO-2025-0001"},
		{ID: "GO-2025-0002"},
	}
	domain.SortFindings(findings)
	want := []string{"GO-2025-0001", "GO-2025-0002", "GO-2025-0003"}
	for i, w := range want {
		if findings[i].ID != w {
			t.Errorf("findings[%d].ID = %q, want %q", i, findings[i].ID, w)
		}
	}
}
