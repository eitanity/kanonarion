package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	licapp "github.com/eitanity/kanonarion/internal/license/application"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// requireExit asserts err is an *exitError with the given code.
func requireExit(t *testing.T, err error, code int) {
	t.Helper()
	var ee *exitError
	if !errors.As(err, &ee) {
		t.Fatalf("want *exitError with code %d, got %v", code, err)
	}
	if ee.code != code {
		t.Errorf("want exit code %d, got %d (%q)", code, ee.code, ee.msg)
	}
}

func compatCoord() fetchdomain.ModuleCoordinate {
	return fetchdomain.ModuleCoordinate{Path: "example.com/m", Version: "v1.0.0"}
}

// containerWithWalk returns a Container whose walk store holds one walk for
// coord and whose compatibility check returns the given report/err.
func containerWithWalk(coord fetchdomain.ModuleCoordinate, report licdomain.ClosureCompatibilityReport, checkErr error) *Container {
	fqw := testfakes.NewFakeQueryWalks()
	fqw.SetSummaries([]walkports.WalkSummary{{ID: "W1", Target: coord}})
	return &Container{
		QueryWalks:         fqw,
		CheckCompatibility: &testfakes.FakeCheckCompatibility{Report: report, Err: checkErr},
	}
}

// licenseCompatWith covers the handler-level orchestration that the
// helper-level tests in license_compat_test.go cannot reach (they exercise
// compatExitCode / printCompat* directly). The no-walk path here is the real
// one that TestWalkNotFoundError could only simulate before the seam.

// No walk record for the root => ExitNotFound directing the user to run walk.
func TestLicenseCompatWith_NoWalk(t *testing.T) {
	ctr := &Container{QueryWalks: testfakes.NewFakeQueryWalks()} // empty
	var out bytes.Buffer
	err := licenseCompatWith(context.Background(), ctr, compatCoord(), "Apache-2.0", &out)
	requireExit(t, err, ExitNotFound)
	if !strings.Contains(err.Error(), "no walk record found") {
		t.Errorf("missing walk diagnostic: %v", err)
	}
}

// Implicit-target on an un-analysed root => ExitNotFound with an intent-aware
// hint naming the command that analyses the licence (unknown is not zero).
func TestLicenseCompatWith_RootNotAnalysed(t *testing.T) {
	ctr := containerWithWalk(compatCoord(), licdomain.ClosureCompatibilityReport{}, licapp.ErrRootLicenceNotAnalysed)
	var out bytes.Buffer
	err := licenseCompatWith(context.Background(), ctr, compatCoord(), "", &out)
	requireExit(t, err, ExitNotFound)
	if !strings.Contains(err.Error(), "kanonarion license") {
		t.Errorf("diagnostic should name the license command: %v", err)
	}
}

// A root with a licence record but no SPDX identity cannot be an implicit
// target => ExitFailed directing the user to pass --target.
func TestLicenseCompatWith_RootNoSPDX(t *testing.T) {
	ctr := containerWithWalk(compatCoord(), licdomain.ClosureCompatibilityReport{}, licapp.ErrRootLicenceNoSPDX)
	var out bytes.Buffer
	err := licenseCompatWith(context.Background(), ctr, compatCoord(), "", &out)
	requireExit(t, err, ExitFailed)
	if !strings.Contains(err.Error(), "--target") {
		t.Errorf("diagnostic should suggest --target: %v", err)
	}
}

// Clean closure => exit 0 and a rendered report.
func TestLicenseCompatWith_Clean(t *testing.T) {
	report := licdomain.ClosureCompatibilityReport{TargetSPDX: "Apache-2.0", Clean: true}
	ctr := containerWithWalk(compatCoord(), report, nil)
	var out bytes.Buffer
	if err := licenseCompatWith(context.Background(), ctr, compatCoord(), "Apache-2.0", &out); err != nil {
		t.Fatalf("clean closure should exit 0, got: %v", err)
	}
	if out.Len() == 0 {
		t.Error("expected a rendered report for a clean closure")
	}
}

// A report with conflicts must propagate through to the exit code: an
// unmodelled pair yields ExitFailed (priority over a plain incompatibility).
// The exit-code mapping itself is unit-tested in license_compat_test.go; this
// asserts the handler wires the report into compatExitCode.
func TestLicenseCompatWith_ConflictPropagates(t *testing.T) {
	report := licdomain.ClosureCompatibilityReport{
		TargetSPDX: "Apache-2.0",
		Conflicts: []licdomain.CompatibilityConflict{
			{ModulePath: "example.com/a", Verdict: licdomain.VerdictIncompatible},
			{ModulePath: "example.com/b", Verdict: licdomain.VerdictUnknownPair},
		},
	}
	ctr := containerWithWalk(compatCoord(), report, nil)
	var out bytes.Buffer
	err := licenseCompatWith(context.Background(), ctr, compatCoord(), "Apache-2.0", &out)
	requireExit(t, err, ExitFailed)
}
