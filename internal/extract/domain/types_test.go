package domain

import (
	"encoding/json"
	"testing"
)

func TestExtractionRunStatus_String(t *testing.T) {
	tests := []struct {
		status ExtractionRunStatus
		want   string
	}{
		{ExtractionRunSucceeded, "succeeded"},
		{ExtractionRunPartial, "partial"},
		{ExtractionRunFailed, "failed"},
		{ExtractionRunCancelled, "cancelled"},
		{ExtractionRunStatus(99), "ExtractionRunStatus(99)"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.status.String(); got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractionRunStatus_JSON(t *testing.T) {
	tests := []struct {
		status ExtractionRunStatus
		json   string
	}{
		{ExtractionRunSucceeded, `"succeeded"`},
		{ExtractionRunPartial, `"partial"`},
		{ExtractionRunFailed, `"failed"`},
		{ExtractionRunCancelled, `"cancelled"`},
	}
	for _, tt := range tests {
		t.Run(tt.json, func(t *testing.T) {
			// Marshal
			data, err := json.Marshal(tt.status)
			if err != nil {
				t.Fatalf("MarshalJSON() error = %v", err)
			}
			if string(data) != tt.json {
				t.Errorf("MarshalJSON() = %s, want %s", string(data), tt.json)
			}

			// Unmarshal
			var got ExtractionRunStatus
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("UnmarshalJSON() error = %v", err)
			}
			if got != tt.status {
				t.Errorf("UnmarshalJSON() = %v, want %v", got, tt.status)
			}
		})
	}

	t.Run("Invalid", func(t *testing.T) {
		var got ExtractionRunStatus
		if err := json.Unmarshal([]byte(`"invalid"`), &got); err == nil {
			t.Error("UnmarshalJSON() expected error for invalid status, got nil")
		}
	})
}

func TestStageStatus_String(t *testing.T) {
	tests := []struct {
		status StageStatus
		want   string
	}{
		{StageSucceeded, "succeeded"},
		{StageFailed, "failed"},
		{StageSkipped, "skipped"},
		{StageStatus(99), "StageStatus(99)"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.status.String(); got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStageStatus_JSON(t *testing.T) {
	tests := []struct {
		status StageStatus
		json   string
	}{
		{StageSucceeded, `"succeeded"`},
		{StageFailed, `"failed"`},
		{StageSkipped, `"skipped"`},
	}
	for _, tt := range tests {
		t.Run(tt.json, func(t *testing.T) {
			// Marshal
			data, err := json.Marshal(tt.status)
			if err != nil {
				t.Fatalf("MarshalJSON() error = %v", err)
			}
			if string(data) != tt.json {
				t.Errorf("MarshalJSON() = %s, want %s", string(data), tt.json)
			}

			// Unmarshal
			var got StageStatus
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("UnmarshalJSON() error = %v", err)
			}
			if got != tt.status {
				t.Errorf("UnmarshalJSON() = %v, want %v", got, tt.status)
			}
		})
	}

	t.Run("Invalid", func(t *testing.T) {
		var got StageStatus
		if err := json.Unmarshal([]byte(`"invalid"`), &got); err == nil {
			t.Error("UnmarshalJSON() expected error for invalid status, got nil")
		}
	})
}
