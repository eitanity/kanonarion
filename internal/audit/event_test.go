package audit_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/audit"
)

func TestEventType_Known(t *testing.T) {
	known := []audit.EventType{
		audit.EventFactRecordWritten,
		audit.EventReplaceDirectiveObserved,
		audit.EventExcludeDirectiveObserved,
		audit.EventGoDebugSettingObserved,
		audit.EventVendorTreeGenerated,
		audit.EventFIPSAssessment,
		audit.EventVerificationFailed,
		audit.EventRecordReadVerified,
		audit.EventVulnScanCompleted,
		audit.EventVulnFindingObserved,
		audit.EventLicenseExtracted,
		audit.EventWalkCompleted,
	}
	for _, et := range known {
		if !et.Known() {
			t.Errorf("EventType %q should be known", et)
		}
	}
	unknown := []audit.EventType{"", "made_up_type", "FACT_RECORD_WRITTEN"}
	for _, et := range unknown {
		if et.Known() {
			t.Errorf("EventType %q should not be known", et)
		}
	}
}

func TestEvent_Validate_KnownType(t *testing.T) {
	e := audit.Event{Type: audit.EventFactRecordWritten, Payload: map[string]any{"k": "v"}}
	if err := e.Validate(); err != nil {
		t.Errorf("known event type should validate cleanly, got: %v", err)
	}
}

func TestEvent_Validate_UnknownType(t *testing.T) {
	e := audit.Event{Type: "nonexistent_type"}
	if err := e.Validate(); err == nil {
		t.Error("unknown event type must fail Validate")
	}
}

func TestEvent_Validate_EmptyType(t *testing.T) {
	e := audit.Event{Type: ""}
	if err := e.Validate(); err == nil {
		t.Error("empty event type must fail Validate")
	}
}
