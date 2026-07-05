package domain

import (
	"encoding/json"
	"fmt"
	"time"

	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// WalkStatus summarises the overall outcome of a Walk operation.
type WalkStatus int

const (
	// WalkSucceeded means every module in the closure was fetched successfully.
	WalkSucceeded WalkStatus = iota
	// WalkPartial means the target was fetched but at least one dependency failed.
	WalkPartial
	// WalkFailed means the target module itself could not be fetched.
	WalkFailed
	// WalkCancelled means the context was cancelled before the walk completed.
	WalkCancelled
)

func (s WalkStatus) String() string {
	switch s {
	case WalkSucceeded:
		return "succeeded"
	case WalkPartial:
		return "partial"
	case WalkFailed:
		return "failed"
	case WalkCancelled:
		return "cancelled"
	default:
		return fmt.Sprintf("WalkStatus(%d)", int(s))
	}
}

// MarshalJSON implements json.Marshaler for WalkStatus.
func (s WalkStatus) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("%q", s.String())), nil
}

// UnmarshalJSON implements json.Unmarshaler for WalkStatus.
func (s *WalkStatus) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return fmt.Errorf("failed to unmarshal WalkStatus: %w", err)
	}
	switch str {
	case "succeeded":
		*s = WalkSucceeded
	case "partial":
		*s = WalkPartial
	case "failed":
		*s = WalkFailed
	case "cancelled":
		*s = WalkCancelled
	default:
		return fmt.Errorf("invalid WalkStatus: %q", str)
	}
	return nil
}

// NodeStatus summarises the fetch outcome for a single module in the graph.
type NodeStatus int

const (
	// NodeSucceeded means the module was fetched (or found in cache) successfully.
	NodeSucceeded NodeStatus = iota
	// NodeFetchFailed means a fetch or storage error occurred.
	NodeFetchFailed
	// NodeInternalPanic means a worker goroutine panicked; the walk continued.
	NodeInternalPanic
	// NodeLocalReplace means the node represents a require redirected to a
	// local filesystem path by a replace directive; no remote artefact exists
	// to fetch. The walk is not partial because of these nodes.
	NodeLocalReplace
)

func (s NodeStatus) String() string {
	switch s {
	case NodeSucceeded:
		return "succeeded"
	case NodeFetchFailed:
		return "fetch_failed"
	case NodeInternalPanic:
		return "internal_panic"
	case NodeLocalReplace:
		return "local_replace"
	default:
		return fmt.Sprintf("NodeStatus(%d)", int(s))
	}
}

// StoredError is a serialisation-stable error representation. Wrapped error
// chains are flattened at store time since errors.Is chains don't survive JSON.
type StoredError struct {
	// Type is a stable string discriminator (e.g. "fetch_failed", "internal_panic").
	Type    string `json:"type"`
	Message string `json:"message"`
}

func (e *StoredError) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("[%s] %s", e.Type, e.Message)
}

// NodeResult is the per-module outcome of a Walk operation.
type NodeResult struct {
	Coordinate  domain2.ModuleCoordinate
	FetchRecord *domain2.FactRecord // nil on failure
	Status      NodeStatus
	Error       *StoredError // nil on success
	FromCache   bool
	DurationMs  int64
}

// WalkOutcome is the complete result of a Walk operation.
type WalkOutcome struct {
	Target         domain2.ModuleCoordinate
	Graph          Graph
	PerNodeResults map[domain2.ModuleCoordinate]NodeResult
	StartedAt      time.Time
	CompletedAt    time.Time
	OverallStatus  WalkStatus
}
