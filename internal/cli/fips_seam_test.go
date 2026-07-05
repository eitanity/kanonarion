package cli

import (
	"bytes"
	"context"
	"testing"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	fipsdomain "github.com/eitanity/kanonarion/internal/fips/domain"
)

// A clean assessment (no findings) renders and exits 0.
func TestFipsWith_CleanExitsZero(t *testing.T) {
	defer func(prev bool) { jsonOut = prev }(jsonOut)
	jsonOut = false

	ctr := &Container{ExtractFIPS: &testfakes.FakeExtractFIPS{
		Result: fipsdomain.Record{ProjectModulePath: "example.com/proj", ComplianceAssessment: "eligible"},
	}}
	var out bytes.Buffer
	if err := fipsWith(context.Background(), ctr, "go.mod", &out); err != nil {
		t.Fatalf("clean assessment should exit 0, got: %v", err)
	}
	if out.Len() == 0 {
		t.Error("expected rendered FIPS table")
	}
}

// A policy-blocking finding gates the build in BOTH text and JSON modes — the
// handler-level contract that JSON output does not silently drop the non-zero
// exit. (fipsBlockingErr's mapping itself is unit-tested separately.)
func TestFipsWith_BlockingExitsInBothModes(t *testing.T) {
	blocking := fipsdomain.Record{
		ProjectModulePath: "example.com/proj",
		Findings: []fipsdomain.Finding{{
			Kind:           fipsdomain.FindingToolchain,
			ToolchainRaw:   "go1.26",
			PolicyBlocking: true,
		}},
	}
	ctr := &Container{ExtractFIPS: &testfakes.FakeExtractFIPS{Result: blocking}}

	for _, json := range []bool{false, true} {
		func() {
			defer func(prev bool) { jsonOut = prev }(jsonOut)
			jsonOut = json
			var out bytes.Buffer
			err := fipsWith(context.Background(), ctr, "go.mod", &out)
			requireExit(t, err, ExitConfig)
			if out.Len() == 0 {
				t.Errorf("json=%v: expected output to still be rendered alongside the blocking exit", json)
			}
		}()
	}
}
