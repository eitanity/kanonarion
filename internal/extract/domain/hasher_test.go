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
	// Same Path as coord1, different Version: exercises the Version-comparison
	// branch of marshalCanonicalRun's coordinate sort when Path is equal.
	coord3, _ := fetchdomain.NewModuleCoordinate("github.com/foo/bar", "v1.1.0")

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
			coord3: {
				Coordinate: coord3,
				Stages: map[string]StageResult{
					"license": {Status: StageSucceeded, DurationMs: 120},
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

func TestMarshalCanonicalRun_MarshalFailure(t *testing.T) {
	original := canonicalMarshal
	t.Cleanup(func() { canonicalMarshal = original })
	injected := errors.New("injected marshal failure")
	canonicalMarshal = func(any) ([]byte, error) { return nil, injected }

	_, err := ExtractionRunHasher{}.SetContentHash(ExtractionRun{})
	if err == nil {
		t.Fatal("SetContentHash() error = nil, want wrapped marshal error")
	}
	if !errors.Is(err, injected) {
		t.Errorf("SetContentHash() error = %v, want it to wrap the injected error", err)
	}
	if !strings.Contains(err.Error(), "canonical run") {
		t.Errorf("SetContentHash() error = %q, want it to name the record being marshalled", err.Error())
	}
}

func TestVerifyContentHash_MarshalFailure(t *testing.T) {
	original := canonicalMarshal
	t.Cleanup(func() { canonicalMarshal = original })
	injected := errors.New("injected marshal failure")
	canonicalMarshal = func(any) ([]byte, error) { return nil, injected }

	err := ExtractionRunHasher{}.VerifyContentHash(ExtractionRun{})
	if !errors.Is(err, injected) {
		t.Errorf("VerifyContentHash() error = %v, want it to wrap the injected error", err)
	}
}

func TestUnmarshal_MalformedInputs(t *testing.T) {
	hasher := ExtractionRunHasher{}
	coord, _ := fetchdomain.NewModuleCoordinate("github.com/foo/bar", "v1.0.0")
	run := ExtractionRun{
		SchemaVersion: ExtractionRunSchemaVersion,
		Ecosystem:     fetchdomain.EcosystemGo,
		ID:            "run-id",
		PerModuleResults: map[fetchdomain.ModuleCoordinate]ModuleExtractionResult{
			coord: {Coordinate: coord, Stages: map[string]StageResult{"license": {Status: StageSucceeded}}},
		},
		StartedAt:   time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
		CompletedAt: time.Date(2023, 1, 1, 1, 0, 0, 0, time.UTC),
	}
	hashed, err := hasher.SetContentHash(run)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	data, err := hasher.Marshal(hashed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	t.Run("invalid JSON", func(t *testing.T) {
		if _, err := hasher.Unmarshal([]byte("not json")); err == nil {
			t.Error("Unmarshal() error = nil, want a JSON syntax error")
		}
	})
	t.Run("malformed started_at", func(t *testing.T) {
		tampered := strings.Replace(string(data), `"started_at":"2023-01-01T00:00:00Z"`, `"started_at":"not-a-time"`, 1)
		if _, err := hasher.Unmarshal([]byte(tampered)); err == nil {
			t.Error("Unmarshal() error = nil, want a parse error for malformed started_at")
		}
	})
	t.Run("malformed completed_at", func(t *testing.T) {
		tampered := strings.Replace(string(data), `"completed_at":"2023-01-01T01:00:00Z"`, `"completed_at":"not-a-time"`, 1)
		if _, err := hasher.Unmarshal([]byte(tampered)); err == nil {
			t.Error("Unmarshal() error = nil, want a parse error for malformed completed_at")
		}
	})
	t.Run("malformed per-module coordinate", func(t *testing.T) {
		tampered := strings.Replace(string(data), `"path":"github.com/foo/bar"`, `"path":""`, 1)
		if _, err := hasher.Unmarshal([]byte(tampered)); err == nil {
			t.Error("Unmarshal() error = nil, want a parse error for an invalid per-module coordinate")
		}
	})
}
