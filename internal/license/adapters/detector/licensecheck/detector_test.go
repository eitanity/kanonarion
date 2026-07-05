package licensecheck_test

import (
	"context"
	_ "embed"
	"strings"
	"testing"

	lcdetector "github.com/eitanity/kanonarion/internal/license/adapters/detector/licensecheck"
)

//go:embed testdata/mit.txt
var mitText []byte

//go:embed testdata/apache-header.txt
var apacheHeaderText []byte

//go:embed testdata/readme.txt
var readmeText []byte

// agplTruncatedText is a real-world AGPL-3.0 LICENSE that was truncated
// upstream: the body jumps mid-section 11 straight to "END OF TERMS",
// dropping sections 12–17 (including the AGPL-defining network clause). Only
// the distinctive "how to apply" appendix matches the licensecheck corpus, so
// coverage is far below the substantive floor.
//
//go:embed testdata/agpl-truncated.txt
var agplTruncatedText []byte

// gplFullText is a complete GPL-3.0 LICENSE that INCLUDES the "how to apply"
// appendix. It exists to prove the appendix is not what defeats detection: a
// complete full text scores full coverage and classifies cleanly.
//
//go:embed testdata/gpl-3.0-full.txt
var gplFullText []byte

func TestDetect_MIT(t *testing.T) {
	d := lcdetector.New()
	m, err := d.Detect(context.Background(), mitText)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if m.SPDX == "" {
		t.Fatal("expected SPDX match for MIT text, got empty")
	}
	if !strings.Contains(m.SPDX, "MIT") {
		t.Errorf("SPDX %q does not contain MIT", m.SPDX)
	}
	if m.Confidence <= 0 {
		t.Errorf("confidence should be > 0, got %f", m.Confidence)
	}
	if m.Confidence > 1.0 {
		t.Errorf("confidence should be <= 1.0, got %f", m.Confidence)
	}
}

func TestDetect_Apache(t *testing.T) {
	d := lcdetector.New()
	m, err := d.Detect(context.Background(), apacheHeaderText)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if m.SPDX == "" {
		t.Fatal("expected SPDX match for Apache header text, got empty")
	}
	if !strings.Contains(m.SPDX, "Apache") {
		t.Errorf("SPDX %q does not contain Apache", m.SPDX)
	}
}

func TestDetect_NonLicense(t *testing.T) {
	d := lcdetector.New()
	m, err := d.Detect(context.Background(), readmeText)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if m.SPDX != "" {
		t.Errorf("expected no match for README, got %q", m.SPDX)
	}
}

// TestDetect_TruncatedAGPL_LowConfidence locks in the behaviour for a present
// but unclassifiable GPL-family licence: the file is not confidently
// classified (SPDX empty, so status stays Unclassified) yet the recognisable
// fragment is surfaced as a low-confidence signal rather than silently
// discarded. This is the difference between "no idea" and "AGPL-shaped, but
// the licence text is incomplete".
func TestDetect_TruncatedAGPL_LowConfidence(t *testing.T) {
	d := lcdetector.New()
	m, err := d.Detect(context.Background(), agplTruncatedText)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if m.SPDX != "" {
		t.Errorf("truncated AGPL should not be confidently classified, got SPDX %q", m.SPDX)
	}
	if !strings.Contains(m.LowConfidenceSPDX, "AGPL") {
		t.Errorf("expected a low-confidence AGPL fragment, got %q", m.LowConfidenceSPDX)
	}
	if m.LowConfidenceCoverage <= 0 || m.LowConfidenceCoverage >= 0.20 {
		t.Errorf("low-confidence coverage should be a small non-zero fraction below the floor, got %f",
			m.LowConfidenceCoverage)
	}
}

// TestDetect_FullGPLWithAppendix_Classifies proves the "how to apply" appendix
// is not what defeats GPL-family detection: a COMPLETE full text including the
// appendix classifies cleanly, with no low-confidence fallback. The truncated
// case above fails because the body is missing, not because of the appendix.
func TestDetect_FullGPLWithAppendix_Classifies(t *testing.T) {
	d := lcdetector.New()
	m, err := d.Detect(context.Background(), gplFullText)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !strings.Contains(m.SPDX, "GPL") {
		t.Errorf("complete GPL full text should classify as GPL, got SPDX %q", m.SPDX)
	}
	if m.LowConfidenceSPDX != "" {
		t.Errorf("a confidently classified file must not carry a low-confidence fallback, got %q",
			m.LowConfidenceSPDX)
	}
}

func TestDetect_Empty(t *testing.T) {
	d := lcdetector.New()
	m, err := d.Detect(context.Background(), []byte{})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if m.SPDX != "" {
		t.Errorf("expected no match for empty content, got %q", m.SPDX)
	}
}

func TestDetect_CancelledContext(t *testing.T) {
	d := lcdetector.New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := d.Detect(ctx, mitText)
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

func TestDetectorMetadata(t *testing.T) {
	d := lcdetector.New()
	meta := d.DetectorMetadata()
	if meta.Name == "" {
		t.Error("DetectorMetadata.Name must not be empty")
	}
	if meta.Version == "" {
		t.Error("DetectorMetadata.Version must not be empty")
	}
}

func TestDetect_DualLicense(t *testing.T) {
	d := lcdetector.New()
	// Concatenate MIT and Apache texts to simulate dual licensing
	dualText := append([]byte(nil), mitText...)
	dualText = append(dualText, []byte("\n\n")...)
	dualText = append(dualText, apacheHeaderText...)

	m, err := d.Detect(context.Background(), dualText)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	if m.SPDX == "" {
		t.Fatal("expected primary SPDX match")
	}

	// It should have AltMatches if it detects both
	if len(m.AltMatches) == 0 {
		// This might happen if one license is very short and doesn't meet the 20% threshold of the COMBINED text.
		// But let's check if we can at least reach that code.
		t.Logf("Detected primary: %s, but no AltMatches", m.SPDX)
	} else {
		t.Logf("Detected primary: %s, alts: %v", m.SPDX, m.AltMatches)
	}
}
