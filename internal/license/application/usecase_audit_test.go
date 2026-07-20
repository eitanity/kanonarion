package application_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/audit"

	"github.com/eitanity/kanonarion/internal/license/application"
	domain2 "github.com/eitanity/kanonarion/internal/license/domain"
	"github.com/eitanity/kanonarion/internal/license/ports"
)

// recordingAuditSink captures every event appended during extraction so a test
// can assert exactly which assurance-log facts a run emitted.
type recordingAuditSink struct {
	events []audit.Event
}

func (s *recordingAuditSink) RecordEvent(e audit.Event) error {
	s.events = append(s.events, e)
	return nil
}

func (s *recordingAuditSink) ofType(t audit.EventType) []audit.Event {
	var out []audit.Event
	for _, e := range s.events {
		if e.Type == t {
			out = append(out, e)
		}
	}
	return out
}

// extractWithAudit builds a use case wired to sink, seeds a fetch record and a
// module zip carrying the given files, then runs extraction with det.
func extractWithAudit(
	t *testing.T,
	coord coordinate.ModuleCoordinate,
	files map[string]string,
	det ports.LicenseDetector,
	sink ports.AuditSink,
) application.ExtractResult {
	t.Helper()
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	licenseStore := &fakeLicenseStore{}

	zipData := buildModuleZip(t, coord, files)
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	uc := buildUseCaseWithDetector(t, factStore, blobStore, licenseStore, det).WithAudit(sink)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	return result
}

// TestExecute_EmitsLicenseExtracted is the regression test for wiring extraction
// to the assurance log: a module with a detected licence and one with an
// undetermined (Unclassified) status must each append exactly one
// license_extracted event carrying the resolved SPDX and status.
func TestExecute_EmitsLicenseExtracted(t *testing.T) {
	t.Run("detected licence", func(t *testing.T) {
		coord := mustCoord(t, "example.com/detected", "v1.0.0")
		sink := &recordingAuditSink{}
		det := &fakeDetector{match: ports.LicenseMatch{SPDX: "MIT", Confidence: 0.98}}

		result := extractWithAudit(t, coord, map[string]string{"LICENSE": "MIT License text"}, det, sink)
		if result.Record.OverallStatus != domain2.LicenseStatusDetected {
			t.Fatalf("OverallStatus: got %v, want Detected", result.Record.OverallStatus)
		}

		assertOneLicenseEvent(t, sink, coord, "MIT", domain2.LicenseStatusDetected)
	})

	t.Run("undetermined status", func(t *testing.T) {
		coord := mustCoord(t, "example.com/unclassified", "v2.0.0")
		sink := &recordingAuditSink{}
		// A root-level licence file whose content matches no known SPDX yields
		// Unclassified (distinct from None, where no licence file exists at all).
		det := &fakeDetector{match: ports.LicenseMatch{SPDX: "", Confidence: 0}}

		result := extractWithAudit(t, coord, map[string]string{"LICENSE": "All rights reserved."}, det, sink)
		if result.Record.OverallStatus != domain2.LicenseStatusUnclassified {
			t.Fatalf("OverallStatus: got %v, want Unclassified", result.Record.OverallStatus)
		}

		assertOneLicenseEvent(t, sink, coord, "", domain2.LicenseStatusUnclassified)
	})
}

// assertOneLicenseEvent verifies the sink recorded exactly one valid
// license_extracted event with the expected coordinate, SPDX and status.
func assertOneLicenseEvent(
	t *testing.T,
	sink *recordingAuditSink,
	coord coordinate.ModuleCoordinate,
	wantSPDX string,
	wantStatus domain2.LicenseStatus,
) {
	t.Helper()
	for _, e := range sink.events {
		if err := e.Validate(); err != nil {
			t.Errorf("emitted event failed validation: %v", err)
		}
	}
	events := sink.ofType(audit.EventLicenseExtracted)
	if len(events) != 1 {
		t.Fatalf("expected 1 license_extracted event, got %d", len(events))
	}
	p := events[0].Payload
	if got := p["module"]; got != coord.Path {
		t.Errorf("module = %v, want %v", got, coord.Path)
	}
	if got := p["version"]; got != coord.Version {
		t.Errorf("version = %v, want %v", got, coord.Version)
	}
	if got := p["primary_spdx"]; got != wantSPDX {
		t.Errorf("primary_spdx = %v, want %q", got, wantSPDX)
	}
	if got := p["overall_status"]; got != wantStatus.String() {
		t.Errorf("overall_status = %v, want %v", got, wantStatus.String())
	}
	if got := p["source"]; got != "scanner" {
		t.Errorf("source = %v, want scanner", got)
	}
}

// TestExecute_NilAuditSink verifies emission is optional: extraction with no
// audit sink wired completes normally and simply appends nothing.
func TestExecute_NilAuditSink(t *testing.T) {
	coord := mustCoord(t, "example.com/noaudit", "v1.0.0")
	det := &fakeDetector{match: ports.LicenseMatch{SPDX: "MIT", Confidence: 0.98}}
	// extractWithAudit passes the sink through WithAudit; a nil sink must be a
	// no-op, so this simply must not panic or error.
	result := extractWithAudit(t, coord, map[string]string{"LICENSE": "MIT License text"}, det, nil)
	if result.Record.OverallStatus != domain2.LicenseStatusDetected {
		t.Fatalf("OverallStatus: got %v, want Detected", result.Record.OverallStatus)
	}
}

// TestExecute_CacheHitEmitsNothing verifies a cache hit re-serves the stored
// record without re-extracting, so it appends no license_extracted event.
func TestExecute_CacheHitEmitsNothing(t *testing.T) {
	coord := mustCoord(t, "example.com/cached", "v1.0.0")
	factStore := &fakeFactStore{}
	licenseStore := &fakeLicenseStore{}
	putFact(t, factStore, coord, "blob:fakecontent")

	existing := domain2.LicenseRecord{
		SchemaVersion:   domain2.LicenseSchemaVersion,
		Coordinate:      coord,
		PrimarySPDX:     "MIT",
		OverallStatus:   domain2.LicenseStatusDetected,
		PipelineVersion: application.PipelineVersion,
	}
	var h domain2.LicenseRecordHasher
	existing, err := h.SetContentHash(existing)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if err := licenseStore.PutLicenseRecord(context.Background(), existing); err != nil {
		t.Fatalf("PutLicenseRecord: %v", err)
	}

	sink := &recordingAuditSink{}
	uc := buildUseCase(t, factStore, nil, licenseStore).WithAudit(sink)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !result.FromCache {
		t.Fatal("expected FromCache = true")
	}
	if got := len(sink.ofType(audit.EventLicenseExtracted)); got != 0 {
		t.Errorf("cache hit must emit no license_extracted event, got %d", got)
	}
}
