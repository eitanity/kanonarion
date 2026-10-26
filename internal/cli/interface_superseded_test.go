package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/coordinate"

	ifaceapp "code.eitanity.com/kanonarion/internal/iface/application"
	ifacedomain "code.eitanity.com/kanonarion/internal/iface/domain"
	ifaceports "code.eitanity.com/kanonarion/internal/iface/ports"

	"code.eitanity.com/kanonarion/internal/cli/testfakes"
)

// A pipeline bump stops the store's existing records being served. That reads
// at the query as an absent record, exactly like a coordinate nobody has ever
// extracted, and the two have opposite remedies: check the coordinate, or run
// the extraction again. These tests hold the two apart.

const supersededPipeline = "0.0.1-superseded"

func supersededCoord(t *testing.T) coordinate.ModuleCoordinate {
	t.Helper()
	c, err := coordinate.NewModuleCoordinate("example.com/held", "v1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// storeHoldingOnlySuperseded returns a fake whose ledger holds coord, and holds
// it only under extraction logic this build no longer serves.
func storeHoldingOnlySuperseded(t *testing.T) (*testfakes.FakeQueryInterface, coordinate.ModuleCoordinate) {
	t.Helper()
	coord := supersededCoord(t)
	uc := testfakes.NewFakeQueryInterface()
	uc.SetList([]ifaceports.InterfaceSummary{
		{
			ModulePath: coord.Path(), ModuleVersion: coord.Version(),
			PipelineVersion: supersededPipeline, PackageCount: 2,
			OverallStatus: ifacedomain.InterfaceStatusExtracted,
		},
	})
	// Deliberately no record at ifaceapp.PipelineVersion: GetInterfaceRecord
	// misses, which is the condition under test.
	return uc, coord
}

func TestInterfaceRecordMiss_SupersededPipelineIsNotACoordinateMismatch(t *testing.T) {
	uc, coord := storeHoldingOnlySuperseded(t)

	var stderr bytes.Buffer
	err := interfaceRecordMiss(context.Background(), uc, coord, false, &stderr)
	if err == nil {
		t.Fatal("a miss must not be reported as success")
	}
	msg := err.Error()

	for _, want := range []string{
		"superseded extraction logic",
		"this build serves pipeline " + ifaceapp.PipelineVersion,
		"the store holds this coordinate at pipeline " + supersededPipeline,
		"kanonarion interface " + coord.String(),
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("the superseded statement is missing %q, got:\n%s", want, msg)
		}
	}
	// The coordinate matched a stored record, so nothing may send the reader
	// after a spelling error or into the listing to hunt for one.
	for _, unwanted := range []string{
		"compared for exact equality",
		"kanonarion interface-list",
	} {
		if strings.Contains(msg, unwanted) {
			t.Errorf("the statement teaches a cause that did not happen (%q):\n%s", unwanted, msg)
		}
	}
}

func TestInterfaceRecordMiss_AbsentAtEveryVersionKeepsTheCoordinateStatement(t *testing.T) {
	uc, held := storeHoldingOnlySuperseded(t)
	absent, err := coordinate.NewModuleCoordinate("example.com/never", "v9.9.9")
	if err != nil {
		t.Fatal(err)
	}

	var stderr bytes.Buffer
	mErr := interfaceRecordMiss(context.Background(), uc, absent, false, &stderr)
	if mErr == nil {
		t.Fatal("a miss must not be reported as success")
	}
	msg := mErr.Error()

	if strings.Contains(msg, "superseded") {
		t.Errorf("a coordinate the store has never held is not superseded:\n%s", msg)
	}
	for _, want := range []string{
		"compared for exact equality",
		"kanonarion interface-list",
		absent.String(),
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("the coordinate statement is missing %q, got:\n%s", want, msg)
		}
	}
	if !strings.Contains(msg, held.Path()) {
		t.Errorf("the corpus example naming a stored coordinate is missing:\n%s", msg)
	}
}

func TestBuildInterface_SupersededSectionIsNotNotRun(t *testing.T) {
	uc, coord := storeHoldingOnlySuperseded(t)

	out := buildInterface(context.Background(), coord, uc, true, "")
	if out.Status != sectionStatusSuperseded {
		t.Fatalf("Status = %q, want %q — a record that exists and is not served has not merely 'not run'",
			out.Status, sectionStatusSuperseded)
	}
	if !strings.Contains(out.Error, "superseded extraction logic") {
		t.Errorf("the section does not say why it is empty: %q", out.Error)
	}
	if !strings.Contains(out.Error, "kanonarion interface "+coord.String()) {
		t.Errorf("the section names no remedy: %q", out.Error)
	}
}

func TestBuildInterface_NeverExtractedStaysNotRun(t *testing.T) {
	uc, _ := storeHoldingOnlySuperseded(t)
	absent, err := coordinate.NewModuleCoordinate("example.com/never", "v9.9.9")
	if err != nil {
		t.Fatal(err)
	}
	out := buildInterface(context.Background(), absent, uc, true, "")
	if out.Status != sectionStatusNotRun {
		t.Errorf("Status = %q, want %q", out.Status, sectionStatusNotRun)
	}
}

func TestPrintInterfaceList_MarksRecordsThisBuildWillNotServe(t *testing.T) {
	sums := []ifaceports.InterfaceSummary{
		{
			ModulePath: "example.com/held", ModuleVersion: "v1.2.3",
			PipelineVersion: supersededPipeline, PackageCount: 2,
			OverallStatus: ifacedomain.InterfaceStatusExtracted,
		},
		{
			ModulePath: "example.com/fresh", ModuleVersion: "v1.0.0",
			PipelineVersion: ifaceapp.PipelineVersion, PackageCount: 1,
			OverallStatus: ifacedomain.InterfaceStatusExtracted,
		},
	}

	var stdout, stderr bytes.Buffer
	// The rows only reach the page together under --all-generations; the
	// default asks the store for the served generation alone.
	if err := printInterfaceList(sums, false, 0, 0, interfaceListGeneration(true), listZeroScope{}, &stdout, &stderr); err != nil {
		t.Fatalf("printInterfaceList: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "[superseded generation "+supersededPipeline+"]") {
		t.Errorf("a listed record this build will not serve is not marked:\n%s", out)
	}
	if !strings.Contains(out, "1 of 2 listed record(s) were extracted at a superseded pipeline version") {
		t.Errorf("the listing does not count what it will not answer from:\n%s", out)
	}
	fresh := ""
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "example.com/fresh") {
			fresh = line
		}
	}
	if strings.Contains(fresh, "superseded") {
		t.Errorf("a served record must not be marked superseded: %q", fresh)
	}
}

// TestSupersededInterfaceRecord_AbsentUseCaseIsNotAFault: the refinement is a
// diagnostic, and a diagnostic must not become the failure. A caller wired
// without this use case — a seam built for one command — keeps the statement it
// already had rather than panicking on the way to a better one.
func TestSupersededInterfaceRecord_AbsentUseCaseIsNotAFault(t *testing.T) {
	failing := testfakes.NewFakeQueryInterface()
	failing.Err = errStoreUnreadable
	coord := supersededCoord(t)
	if _, superseded := supersededInterfacePipelines(coord, nil); superseded {
		t.Error("no summaries cannot establish that a record is superseded")
	}
	// Same rule for the scoped read the callers actually use.
	if _, superseded := supersededInterfaceRecord(context.Background(), nil, coord); superseded {
		t.Error("an absent use case cannot establish that a record is superseded")
	}
	if _, superseded := supersededInterfaceRecord(context.Background(), failing, coord); superseded {
		t.Error("an unreadable store cannot establish that a record is superseded")
	}
}

var errStoreUnreadable = errors.New("store unreadable")
