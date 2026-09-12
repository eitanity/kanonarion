package domain

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/failurecause"
)

// ExtractionRunStatus summarises the overall outcome of an ExtractionRun.
type ExtractionRunStatus int

const (
	// ExtractionRunSucceeded means all requested stages for all modules completed.
	ExtractionRunSucceeded ExtractionRunStatus = iota
	// ExtractionRunPartial means some modules or stages failed, but some succeeded.
	ExtractionRunPartial
	// ExtractionRunFailed means the run failed to start or hit a catastrophic error.
	ExtractionRunFailed
	// ExtractionRunCancelled means the context was cancelled during the run.
	ExtractionRunCancelled
	// ExtractionRunInProgress means the run had not finished when this record was
	// written. It is the only status a run can carry that describes the record
	// rather than the outcome, and it exists because the worst failure mode was
	// the one that recorded nothing about itself: a run persisted only on
	// completion leaves no trace at all when the operating system ends it, and
	// the modules it never reached are indistinguishable from modules that do not
	// exist.
	//
	// A run that still says this once its process is gone did not finish. What it
	// completed before then is in PerModuleResults and is true; CompletedAt is
	// zero, because it never did.
	ExtractionRunInProgress
)

func (s ExtractionRunStatus) String() string {
	switch s {
	case ExtractionRunSucceeded:
		return "succeeded"
	case ExtractionRunPartial:
		return "partial"
	case ExtractionRunFailed:
		return "failed"
	case ExtractionRunCancelled:
		return "cancelled"
	case ExtractionRunInProgress:
		return "in_progress"
	default:
		return fmt.Sprintf("ExtractionRunStatus(%d)", int(s))
	}
}

// MarshalJSON implements json.Marshaler for ExtractionRunStatus.
func (s ExtractionRunStatus) MarshalJSON() ([]byte, error) {
	return fmt.Appendf(nil, "%q", s.String()), nil
}

// UnmarshalJSON implements json.Unmarshaler for ExtractionRunStatus.
func (s *ExtractionRunStatus) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return fmt.Errorf("failed to unmarshal ExtractionRunStatus: %w", err)
	}
	switch str {
	case "succeeded":
		*s = ExtractionRunSucceeded
	case "partial":
		*s = ExtractionRunPartial
	case "failed":
		*s = ExtractionRunFailed
	case "cancelled":
		*s = ExtractionRunCancelled
	case "in_progress":
		*s = ExtractionRunInProgress
	default:
		return fmt.Errorf("invalid ExtractionRunStatus: %q", str)
	}
	return nil
}

// StageStatus reflects the outcome of a single extraction stage for a module.
type StageStatus int

const (
	StageSucceeded StageStatus = iota
	StageFailed
	StageSkipped
)

func (s StageStatus) String() string {
	switch s {
	case StageSucceeded:
		return "succeeded"
	case StageFailed:
		return "failed"
	case StageSkipped:
		return "skipped"
	default:
		return fmt.Sprintf("StageStatus(%d)", int(s))
	}
}

// MarshalJSON implements json.Marshaler for StageStatus.
func (s StageStatus) MarshalJSON() ([]byte, error) {
	return fmt.Appendf(nil, "%q", s.String()), nil
}

// UnmarshalJSON implements json.Unmarshaler for StageStatus.
func (s *StageStatus) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return fmt.Errorf("failed to unmarshal StageStatus: %w", err)
	}
	switch str {
	case "succeeded":
		*s = StageSucceeded
	case "failed":
		*s = StageFailed
	case "skipped":
		*s = StageSkipped
	default:
		return fmt.Errorf("invalid StageStatus: %q", str)
	}
	return nil
}

// ModuleExtractionResult summarizes which stages were run for a single module.
type ModuleExtractionResult struct {
	Coordinate coordinate.ModuleCoordinate `json:"coordinate"`
	Stages     map[string]StageResult      `json:"stages"`
}

// StageResult captures the outcome and record ID of a single stage.
type StageResult struct {
	Status   StageStatus `json:"status"`
	RecordID string      `json:"record_id,omitzero"`
	Error    string      `json:"error,omitzero"`
	// Cause says what a failed stage is a statement about: the module, or this
	// host. It is omitzero and absent from every stage recorded before it
	// existed, so those records seal to the bytes they always did — and an
	// absent cause is read as "not stated", never as the module's fault.
	Cause      failurecause.Cause `json:"cause,omitzero"`
	DurationMs int64              `json:"duration_ms"`
}

// ExtractionRunSchemaVersion is the schema version for ExtractionRun JSON.
// v2 adds the ecosystem scope marker.
const ExtractionRunSchemaVersion = "2"

// ExtractionRun is the aggregate root for a coordinated extraction operation.
type ExtractionRun struct {
	SchemaVersion string `json:"schema_version"`
	// Ecosystem declares the schema's scope; always fetchdomain.EcosystemGo.
	Ecosystem        string                                                 `json:"ecosystem"`
	ID               string                                                 `json:"id"`
	WalkID           string                                                 `json:"walk_id"`
	RequestedStages  []string                                               `json:"requested_stages"`
	PerModuleResults map[coordinate.ModuleCoordinate]ModuleExtractionResult `json:"per_module_results"`
	StartedAt        time.Time                                              `json:"started_at"`
	CompletedAt      time.Time                                              `json:"completed_at"`
	OverallStatus    ExtractionRunStatus                                    `json:"overall_status"`
	PipelineVersions map[string]string                                      `json:"pipeline_versions"`
	Operator         string                                                 `json:"operator"`
	ContentHash      string                                                 `json:"content_hash"`
}

// MarshalJSON implements json.Marshaler for ExtractionRun.
// It uses the canonical representation to avoid issues with map[ModuleCoordinate].
func (r ExtractionRun) MarshalJSON() ([]byte, error) {
	return ExtractionRunHasher{}.Marshal(r)
}

// UnmarshalJSON implements json.Unmarshaler for ExtractionRun.
func (r *ExtractionRun) UnmarshalJSON(data []byte) error {
	res, err := ExtractionRunHasher{}.Unmarshal(data)
	if err != nil {
		return fmt.Errorf("failed to unmarshal ExtractionRun: %w", err)
	}
	*r = res
	return nil
}
