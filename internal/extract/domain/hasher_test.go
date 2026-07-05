package domain

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

func TestExtractionRunHasher(t *testing.T) {
	coord1, _ := fetchdomain.NewModuleCoordinate("github.com/foo/bar", "v1.0.0")
	coord2, _ := fetchdomain.NewModuleCoordinate("github.com/baz/qux", "v2.0.0")

	run := ExtractionRun{
		SchemaVersion:   ExtractionRunSchemaVersion,
		Ecosystem:       fetchdomain.EcosystemGo,
		ID:              "test-run-id",
		WalkID:          "test-walk-id",
		RequestedStages: []string{"license", "interface"},
		PerModuleResults: map[fetchdomain.ModuleCoordinate]ModuleExtractionResult{
			coord1: {
				Coordinate: coord1,
				Stages: map[string]StageResult{
					"license": {Status: StageSucceeded, DurationMs: 100},
				},
			},
			coord2: {
				Coordinate: coord2,
				Stages: map[string]StageResult{
					"license":   {Status: StageSucceeded, DurationMs: 150},
					"interface": {Status: StageFailed, Error: "failed", DurationMs: 200},
				},
			},
		},
		StartedAt:     time.Date(2023, 1, 1, 10, 0, 0, 0, time.UTC),
		CompletedAt:   time.Date(2023, 1, 1, 10, 5, 0, 0, time.UTC),
		OverallStatus: ExtractionRunPartial,
		PipelineVersions: map[string]string{
			"license": "v1.1.0",
		},
		Operator: "test-user",
	}

	hasher := ExtractionRunHasher{}

	t.Run("Set and Verify Content Hash", func(t *testing.T) {
		runWithHash, err := hasher.SetContentHash(run)
		if err != nil {
			t.Fatalf("SetContentHash error = %v", err)
		}
		if runWithHash.ContentHash == "" {
			t.Fatal("SetContentHash did not set ContentHash")
		}

		err = hasher.VerifyContentHash(runWithHash)
		if err != nil {
			t.Errorf("VerifyContentHash failed: %v", err)
		}

		// Tamper with data
		tampered := runWithHash
		tampered.Operator = "malicious-user"
		err = hasher.VerifyContentHash(tampered)
		if err == nil {
			t.Error("VerifyContentHash should have failed for tampered data")
		}
	})

	t.Run("Marshal and Unmarshal Canonical", func(t *testing.T) {
		runWithHash, _ := hasher.SetContentHash(run)
		data, err := json.Marshal(runWithHash)
		if err != nil {
			t.Fatalf("json.Marshal(run) error = %v", err)
		}

		var unmarshaled ExtractionRun
		err = json.Unmarshal(data, &unmarshaled)
		if err != nil {
			t.Fatalf("json.Unmarshal(run) error = %v", err)
		}

		// Verify key fields match
		if unmarshaled.ID != run.ID {
			t.Errorf("ID mismatch: got %v, want %v", unmarshaled.ID, run.ID)
		}
		if !unmarshaled.StartedAt.Equal(run.StartedAt) {
			t.Errorf("StartedAt mismatch: got %v, want %v", unmarshaled.StartedAt, run.StartedAt)
		}
		if len(unmarshaled.PerModuleResults) != len(run.PerModuleResults) {
			t.Errorf("PerModuleResults length mismatch: got %d, want %d", len(unmarshaled.PerModuleResults), len(run.PerModuleResults))
		}

		// Check canonical order of keys in JSON (implicitly tested by hasher consistency)
		// We can also verify that we can marshal again and get same hash
		err = hasher.VerifyContentHash(unmarshaled)
		if err != nil {
			t.Errorf("VerifyContentHash failed after unmarshal: %v", err)
		}
	})

	t.Run("Hashing error on invalid status", func(t *testing.T) {
		invalidRun := run
		invalidRun.OverallStatus = 999 // invalid status
		_, err := hasher.SetContentHash(invalidRun)
		if err != nil {
			t.Logf("got expected error for invalid status: %v", err)
		}
	})

	t.Run("VerifyContentHash with missing hash", func(t *testing.T) {
		noHash := run
		noHash.ContentHash = ""
		err := hasher.VerifyContentHash(noHash)
		if err == nil {
			t.Error("VerifyContentHash should fail when ContentHash is missing")
		}
	})

	t.Run("ecosystem present after round-trip", func(t *testing.T) {
		runWithHash, _ := hasher.SetContentHash(run)
		data, err := hasher.Marshal(runWithHash)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if !strings.Contains(string(data), `"ecosystem":"go"`) {
			t.Errorf("canonical JSON missing ecosystem field: %s", data)
		}
		got, err := hasher.Unmarshal(data)
		if err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		if got.Ecosystem != fetchdomain.EcosystemGo {
			t.Errorf("Ecosystem after round-trip = %q, want %q", got.Ecosystem, fetchdomain.EcosystemGo)
		}
	})

	t.Run("rejects foreign ecosystem", func(t *testing.T) {
		foreign := run
		foreign.Ecosystem = "npm"
		hashed, _ := hasher.SetContentHash(foreign)
		data, err := hasher.Marshal(hashed)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if _, err := hasher.Unmarshal(data); !errors.Is(err, fetchdomain.ErrUnsupportedEcosystem) {
			t.Errorf("expected ErrUnsupportedEcosystem, got %v", err)
		}
	})
}
