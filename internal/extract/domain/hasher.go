package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// ExtractionRunHasher computes and embeds a content hash into an ExtractionRun.
type ExtractionRunHasher struct{}

type canonicalExtractionRun struct {
	CompletedAt      string                  `json:"completed_at"`
	ContentHash      string                  `json:"content_hash"`
	Ecosystem        string                  `json:"ecosystem"`
	ID               string                  `json:"id"`
	Operator         string                  `json:"operator"`
	OverallStatus    int                     `json:"overall_status"`
	PerModuleResults []canonicalModuleResult `json:"per_module_results"`
	PipelineVersions map[string]string       `json:"pipeline_versions"`
	RequestedStages  []string                `json:"requested_stages"`
	SchemaVersion    string                  `json:"schema_version"`
	StartedAt        string                  `json:"started_at"`
	WalkID           string                  `json:"walk_id"`
}

type canonicalModuleResult struct {
	Coordinate canonicalCoord         `json:"coordinate"`
	Stages     []canonicalStageResult `json:"stages"`
}

type canonicalCoord struct {
	Path    string `json:"path"`
	Version string `json:"version"`
}

type canonicalStageResult struct {
	Name       string `json:"name"`
	Status     int    `json:"status"`
	RecordID   string `json:"record_id,omitzero"`
	Error      string `json:"error,omitzero"`
	DurationMs int64  `json:"duration_ms"`
}

func (ExtractionRunHasher) SetContentHash(r ExtractionRun) (ExtractionRun, error) {
	r.ContentHash = ""
	data, err := marshalCanonicalRun(r)
	if err != nil {
		return ExtractionRun{}, fmt.Errorf("marshalling for hash: %w", err)
	}
	sum := sha256.Sum256(data)
	r.ContentHash = "sha256:" + hex.EncodeToString(sum[:])
	return r, nil
}

func (ExtractionRunHasher) VerifyContentHash(r ExtractionRun) error {
	saved := r.ContentHash
	r.ContentHash = ""
	data, err := marshalCanonicalRun(r)
	if err != nil {
		return fmt.Errorf("marshalling for verification: %w", err)
	}
	sum := sha256.Sum256(data)
	expected := "sha256:" + hex.EncodeToString(sum[:])
	if saved != expected {
		return fmt.Errorf("content hash mismatch: stored %q, computed %q", saved, expected)
	}
	return nil
}

func (ExtractionRunHasher) Marshal(r ExtractionRun) ([]byte, error) {
	return marshalCanonicalRun(r)
}

func (ExtractionRunHasher) Unmarshal(data []byte) (ExtractionRun, error) {
	var c canonicalExtractionRun
	if err := json.Unmarshal(data, &c); err != nil {
		return ExtractionRun{}, fmt.Errorf("failed to unmarshal canonical run: %w", err)
	}
	if c.Ecosystem != fetchdomain.EcosystemGo {
		return ExtractionRun{}, fmt.Errorf("%w: got %q, want %q", fetchdomain.ErrUnsupportedEcosystem, c.Ecosystem, fetchdomain.EcosystemGo)
	}

	startedAt, err := time.Parse(time.RFC3339, c.StartedAt)
	if err != nil {
		return ExtractionRun{}, fmt.Errorf("parsing started_at %q: %w", c.StartedAt, err)
	}

	completedAt, err := time.Parse(time.RFC3339, c.CompletedAt)
	if err != nil {
		return ExtractionRun{}, fmt.Errorf("parsing completed_at %q: %w", c.CompletedAt, err)
	}

	perModule := make(map[fetchdomain.ModuleCoordinate]ModuleExtractionResult)
	for _, cm := range c.PerModuleResults {
		coord, err := fetchdomain.NewModuleCoordinate(cm.Coordinate.Path, cm.Coordinate.Version)
		if err != nil {
			return ExtractionRun{}, fmt.Errorf("parsing coordinate: %w", err)
		}
		stages := make(map[string]StageResult)
		for _, cs := range cm.Stages {
			stages[cs.Name] = StageResult{
				Status:     StageStatus(cs.Status),
				RecordID:   cs.RecordID,
				Error:      cs.Error,
				DurationMs: cs.DurationMs,
			}
		}
		perModule[coord] = ModuleExtractionResult{
			Coordinate: coord,
			Stages:     stages,
		}
	}

	return ExtractionRun{
		SchemaVersion:    c.SchemaVersion,
		Ecosystem:        c.Ecosystem,
		ID:               c.ID,
		WalkID:           c.WalkID,
		RequestedStages:  c.RequestedStages,
		PerModuleResults: perModule,
		StartedAt:        startedAt.UTC(),
		CompletedAt:      completedAt.UTC(),
		OverallStatus:    ExtractionRunStatus(c.OverallStatus),
		PipelineVersions: c.PipelineVersions,
		Operator:         c.Operator,
		ContentHash:      c.ContentHash,
	}, nil
}

func marshalCanonicalRun(r ExtractionRun) ([]byte, error) {
	requested := make([]string, len(r.RequestedStages))
	copy(requested, r.RequestedStages)
	sort.Strings(requested)

	coords := make([]fetchdomain.ModuleCoordinate, 0, len(r.PerModuleResults))
	for c := range r.PerModuleResults {
		coords = append(coords, c)
	}
	sort.Slice(coords, func(i, j int) bool {
		if coords[i].Path != coords[j].Path {
			return coords[i].Path < coords[j].Path
		}
		return coords[i].Version < coords[j].Version
	})

	cResults := make([]canonicalModuleResult, len(coords))
	for i, coord := range coords {
		res := r.PerModuleResults[coord]
		stageNames := make([]string, 0, len(res.Stages))
		for name := range res.Stages {
			stageNames = append(stageNames, name)
		}
		sort.Strings(stageNames)

		cStages := make([]canonicalStageResult, len(stageNames))
		for j, name := range stageNames {
			s := res.Stages[name]
			cStages[j] = canonicalStageResult{
				Name:       name,
				Status:     int(s.Status),
				RecordID:   s.RecordID,
				Error:      s.Error,
				DurationMs: s.DurationMs,
			}
		}
		cResults[i] = canonicalModuleResult{
			Coordinate: canonicalCoord{Path: coord.Path, Version: coord.Version},
			Stages:     cStages,
		}
	}

	c := canonicalExtractionRun{
		CompletedAt:      r.CompletedAt.UTC().Format(time.RFC3339),
		ContentHash:      r.ContentHash,
		Ecosystem:        r.Ecosystem,
		ID:               r.ID,
		Operator:         r.Operator,
		OverallStatus:    int(r.OverallStatus),
		PerModuleResults: cResults,
		PipelineVersions: r.PipelineVersions,
		RequestedStages:  requested,
		SchemaVersion:    r.SchemaVersion,
		StartedAt:        r.StartedAt.UTC().Format(time.RFC3339),
		WalkID:           r.WalkID,
	}

	data, err := canonicalMarshal(c)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal canonical run: %w", err)
	}
	return data, nil
}

// canonicalMarshal is a seam over json.Marshal used to test the
// marshal-failure guard's wrapping and propagation logic. No field in
// canonicalExtractionRun can currently make json.Marshal fail (no NaN/Inf
// floats, no unsupported types), so this proves the guard's error handling
// is correct, not that the guard is reachable with a real value today — it
// exists for the never-silent-failure invariant, not a known failure mode.
var canonicalMarshal = json.Marshal
