package ports_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	"github.com/eitanity/kanonarion/internal/walk/ports"
)

func TestWalkSummaryJSONSnakeCase(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	s := ports.WalkSummary{
		ID:            "abc123",
		Target:        coordinate.ModuleCoordinate{Path: "example.com/mod", Version: "v1.0.0"},
		StartedAt:     now,
		CompletedAt:   now.Add(time.Minute),
		OverallStatus: walkdomain.WalkSucceeded,
		NodeCount:     5,
		FailureCount:  0,
	}

	data, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	got := string(data)

	for _, key := range []string{`"id"`, `"target"`, `"started_at"`, `"completed_at"`, `"overall_status"`, `"node_count"`, `"failure_count"`} {
		if !strings.Contains(got, key) {
			t.Errorf("JSON output missing snake_case key %s\ngot: %s", key, got)
		}
	}

	for _, bad := range []string{`"ID"`, `"Target"`, `"StartedAt"`, `"CompletedAt"`, `"OverallStatus"`, `"NodeCount"`, `"FailureCount"`} {
		if strings.Contains(got, bad) {
			t.Errorf("JSON output contains PascalCase key %s (want snake_case)\ngot: %s", bad, got)
		}
	}
}

func TestWalkSummarySliceJSONSnakeCase(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	summaries := []ports.WalkSummary{
		{
			ID:            "id1",
			Target:        coordinate.ModuleCoordinate{Path: "example.com/a", Version: "v1.0.0"},
			StartedAt:     now,
			OverallStatus: walkdomain.WalkSucceeded,
			NodeCount:     3,
		},
		{
			ID:            "id2",
			Target:        coordinate.ModuleCoordinate{Path: "example.com/b", Version: "v2.0.0"},
			StartedAt:     now,
			OverallStatus: walkdomain.WalkFailed,
			NodeCount:     1,
			FailureCount:  1,
		},
	}

	data, err := json.Marshal(summaries)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	got := string(data)

	if !strings.Contains(got, `"overall_status"`) {
		t.Errorf("JSON slice missing snake_case key overall_status\ngot: %s", got)
	}
	if strings.Contains(got, `"OverallStatus"`) {
		t.Errorf("JSON slice contains PascalCase OverallStatus\ngot: %s", got)
	}
}
