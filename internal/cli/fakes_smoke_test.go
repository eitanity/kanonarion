package cli

// Smoke tests for all unused testfakes — call each method at least once so
// coverage counters are non-zero. These tests validate that fakes work at
// all; functional correctness is covered by the deeper run* tests.

import (
	"bytes"
	"context"
	"testing"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	configdomain "github.com/eitanity/kanonarion/internal/config/domain"
	exapp "github.com/eitanity/kanonarion/internal/example/application"
	exdomain "github.com/eitanity/kanonarion/internal/example/domain"
	exports "github.com/eitanity/kanonarion/internal/example/ports"
	extractapp "github.com/eitanity/kanonarion/internal/extract/application"
	extractdomain "github.com/eitanity/kanonarion/internal/extract/domain"
	extractports "github.com/eitanity/kanonarion/internal/extract/ports"
	fetchapp "github.com/eitanity/kanonarion/internal/fetch/application"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	fipsdomain "github.com/eitanity/kanonarion/internal/fips/domain"
	ifaceapp "github.com/eitanity/kanonarion/internal/iface/application"
	ifacedomain "github.com/eitanity/kanonarion/internal/iface/domain"
	ifaceports "github.com/eitanity/kanonarion/internal/iface/ports"
	licapp "github.com/eitanity/kanonarion/internal/license/application"
	licenseports "github.com/eitanity/kanonarion/internal/license/ports"
	sbomapp "github.com/eitanity/kanonarion/internal/sbom/application"
	sbomdomain "github.com/eitanity/kanonarion/internal/sbom/domain"
	vulnapp "github.com/eitanity/kanonarion/internal/vuln/application"
	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	walkapp "github.com/eitanity/kanonarion/internal/walk/application"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

func coord(t *testing.T, path, version string) fetchdomain.ModuleCoordinate {
	t.Helper()
	c, err := fetchdomain.NewModuleCoordinate(path, version)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestFakeFetchModule_Execute(t *testing.T) {
	f := &testfakes.FakeFetchModule{Result: fetchapp.FetchResult{}}
	_, err := f.Execute(context.Background(), fetchapp.FetchRequest{})
	if err != nil {
		t.Fatal(err)
	}
	f2 := &testfakes.FakeFetchModule{Err: errTest}
	_, err = f2.Execute(context.Background(), fetchapp.FetchRequest{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestFakeQueryFetch_GetFetchRecord(t *testing.T) {
	f := testfakes.NewFakeQueryFetch()
	c := coord(t, "example.com/a", "v1.0.0")
	f.Add(c, "0.1.0", fetchdomain.FactRecord{ModulePath: c.Path})
	rec, ok, err := f.GetFetchRecord(context.Background(), c, "0.1.0")
	if err != nil || !ok || rec.ModulePath != c.Path {
		t.Fatalf("expected record, got ok=%v err=%v", ok, err)
	}
	_, ok2, _ := f.GetFetchRecord(context.Background(), c, "0.2.0")
	if ok2 {
		t.Fatal("expected not found for wrong version")
	}
	f.Err = errTest
	_, _, err = f.GetFetchRecord(context.Background(), c, "0.1.0")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestFakeExecuteWalk_Execute(t *testing.T) {
	f := &testfakes.FakeExecuteWalk{Result: walkapp.ExecuteWalkResult{
		Record: walkdomain.WalkRecord{ID: "W1"},
	}}
	ctx := context.Background()
	res, err := f.Execute(ctx, walkapp.WalkRequest{})
	if err != nil || res.Record.ID != "W1" {
		t.Fatalf("unexpected result: %v %v", res, err)
	}
}

func TestFakeQueryWalks_GetWalkError(t *testing.T) {
	f := testfakes.NewFakeQueryWalks()
	f.GetErr = errTest
	_, err := f.GetWalk(context.Background(), "any")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestFakeExtract_Execute(t *testing.T) {
	f := &testfakes.FakeExtract{Result: extractdomain.ExtractionRun{ID: "R1"}}
	res, err := f.Execute(context.Background(), extractapp.ExtractRequest{})
	if err != nil || res.ID != "R1" {
		t.Fatalf("unexpected: %v %v", res, err)
	}
}

func TestFakeQueryExtraction_AllMethods(t *testing.T) {
	f := testfakes.NewFakeQueryExtraction()
	run := extractdomain.ExtractionRun{ID: "R1", WalkID: "W1"}
	f.AddRun(run)

	got, err := f.GetExtractionRun(context.Background(), "R1")
	if err != nil || got.ID != "R1" {
		t.Fatalf("GetExtractionRun: %v %v", got, err)
	}

	_, err = f.GetExtractionRun(context.Background(), "MISSING")
	if err == nil {
		t.Fatal("expected not-found error")
	}

	list, err := f.ListExtractionRuns(context.Background(), extractports.ExtractionRunFilter{})
	if err != nil || list != nil {
		t.Fatalf("ListExtractionRuns: %v %v", list, err)
	}

	f.Err = errTest
	_, err = f.GetExtractionRun(context.Background(), "R1")
	if err == nil {
		t.Fatal("expected error")
	}
	_, err = f.ListExtractionRuns(context.Background(), extractports.ExtractionRunFilter{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestFakeExtractLicense_Execute(t *testing.T) {
	f := &testfakes.FakeExtractLicense{Result: licapp.ExtractResult{}}
	_, err := f.Execute(context.Background(), licapp.ExtractRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if f.GetLicenseStore() != nil {
		t.Fatal("expected nil license store")
	}
}

func TestFakeQueryLicense_ListLicenseRecords(t *testing.T) {
	f := testfakes.NewFakeQueryLicense()
	list, err := f.ListLicenseRecords(context.Background(), licenseports.LicenseFilter{})
	if err != nil || list != nil {
		t.Fatalf("unexpected: %v %v", list, err)
	}
}

func TestFakeExtractInterface_Execute(t *testing.T) {
	f := &testfakes.FakeExtractInterface{Result: ifaceapp.ExtractResult{}}
	_, err := f.Execute(context.Background(), ifaceapp.ExtractRequest{})
	if err != nil {
		t.Fatal(err)
	}
}

func TestFakeQueryInterface_AllMethods(t *testing.T) {
	f := testfakes.NewFakeQueryInterface()
	c := coord(t, "example.com/iface", "v1.0.0")

	_, found, err := f.GetInterfaceRecord(context.Background(), c, "0.1.0")
	if err != nil || found {
		t.Fatalf("expected not-found: %v %v", found, err)
	}

	list, err := f.ListInterfaceRecords(context.Background(), ifaceports.InterfaceFilter{})
	if err != nil || list != nil {
		t.Fatalf("ListInterfaceRecords: %v %v", list, err)
	}

	refs, err := f.FindSymbol(context.Background(), "example.com/iface", "Do")
	if err != nil || refs != nil {
		t.Fatalf("FindSymbol: %v %v", refs, err)
	}

	f.Err = errTest
	_, _, err = f.GetInterfaceRecord(context.Background(), c, "0.1.0")
	if err == nil {
		t.Fatal("expected error")
	}
	_, err = f.ListInterfaceRecords(context.Background(), ifaceports.InterfaceFilter{})
	if err == nil {
		t.Fatal("expected error")
	}
	_, err = f.FindSymbol(context.Background(), "", "")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestFakeExtractCallGraph_Execute(t *testing.T) {
	rec := cgdomain.CallGraphRecord{Coordinate: coord(t, "example.com/cg", "v1.0.0")}
	f := &testfakes.FakeExtractCallGraph{Result: cgapp.ExtractResult{Record: rec}}
	res, err := f.Execute(context.Background(), cgapp.ExtractRequest{})
	if err != nil || res.Record.Coordinate.Path != "example.com/cg" {
		t.Fatalf("unexpected: %v %v", res, err)
	}
}

func TestFakeQueryCallGraph_AllMethods(t *testing.T) {
	f := testfakes.NewFakeQueryCallGraph()
	c := coord(t, "example.com/cg", "v1.0.0")

	_, found, err := f.GetCallGraphRecord(context.Background(), c, "0.1.0")
	if err != nil || found {
		t.Fatalf("expected not-found: %v %v", found, err)
	}

	list, err := f.ListCallGraphRecords(context.Background(), cgports.CallGraphFilter{})
	if err != nil || list != nil {
		t.Fatalf("ListCallGraphRecords: %v %v", list, err)
	}

	callers, err := f.FindCallers(context.Background(), "sym", "0.1.0")
	if err != nil || callers != nil {
		t.Fatalf("FindCallers: %v %v", callers, err)
	}

	callees, err := f.FindCallees(context.Background(), "sym", "0.1.0")
	if err != nil || callees != nil {
		t.Fatalf("FindCallees: %v %v", callees, err)
	}

	edges, nodes, err := f.TraverseCallers(context.Background(), "sym", "0.1.0", 5)
	if err != nil || edges != nil || nodes != nil {
		t.Fatalf("TraverseCallers: %v %v %v", edges, nodes, err)
	}

	edges, nodes, err = f.TraverseCallees(context.Background(), "sym", "0.1.0", 5)
	if err != nil || edges != nil || nodes != nil {
		t.Fatalf("TraverseCallees: %v %v %v", edges, nodes, err)
	}

	f.Err = errTest
	_, _, err = f.GetCallGraphRecord(context.Background(), c, "0.1.0")
	if err == nil {
		t.Fatal("expected error")
	}
	_, err = f.ListCallGraphRecords(context.Background(), cgports.CallGraphFilter{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestFakeExtractExample_Execute(t *testing.T) {
	f := &testfakes.FakeExtractExample{Result: exapp.ExtractResult{}}
	_, err := f.Execute(context.Background(), exapp.ExtractRequest{})
	if err != nil {
		t.Fatal(err)
	}
}

func TestFakeQueryExamples_AllMethods(t *testing.T) {
	f := testfakes.NewFakeQueryExamples()
	c := coord(t, "example.com/ex", "v1.0.0")

	_, found, err := f.GetExampleRecord(context.Background(), c, "0.1.0")
	if err != nil || found {
		t.Fatalf("unexpected: %v %v", found, err)
	}

	list, err := f.ListExampleRecords(context.Background(), exports.ExampleFilter{})
	if err != nil || list != nil {
		t.Fatalf("ListExampleRecords: %v %v", list, err)
	}

	refs, err := f.FindBySymbol(context.Background(), "example.com/ex", "Func")
	if err != nil || refs != nil {
		t.Fatalf("FindBySymbol: %v %v", refs, err)
	}

	// non-nil refs when set
	f2 := testfakes.NewFakeQueryExamples()
	_ = exdomain.ExampleRecord{}
	_ = ifacedomain.InterfaceRecord{}
	f2.Err = errTest
	_, _, err = f2.GetExampleRecord(context.Background(), c, "0.1.0")
	if err == nil {
		t.Fatal("expected error")
	}
	_, err = f2.ListExampleRecords(context.Background(), exports.ExampleFilter{})
	if err == nil {
		t.Fatal("expected error")
	}
	_, err = f2.FindBySymbol(context.Background(), "", "")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestFakeScanModule_Scan(t *testing.T) {
	c := coord(t, "example.com/app", "v1.0.0")
	f := &testfakes.FakeScanModule{Result: vulndomain.VulnerabilityRecord{Coordinate: c}}
	res, err := f.Scan(context.Background(), vulnapp.ScanModuleParams{})
	if err != nil || res.Coordinate.Path != "example.com/app" {
		t.Fatalf("unexpected: %v %v", res, err)
	}
}

func TestFakeScanWalk_Scan(t *testing.T) {
	f := &testfakes.FakeScanWalk{Result: vulndomain.WalkScanRun{ID: "SR1"}}
	res, err := f.Scan(context.Background(), vulnapp.ScanWalkParams{})
	if err != nil || res.ID != "SR1" {
		t.Fatalf("unexpected: %v %v", res, err)
	}
}

func TestFakeRescanWalk_Rescan(t *testing.T) {
	f := &testfakes.FakeRescanWalk{Result: vulndomain.WalkScanRun{ID: "SR2"}}
	res, err := f.Rescan(context.Background(), vulnapp.RescanRequest{})
	if err != nil || res.ID != "SR2" {
		t.Fatalf("unexpected: %v %v", res, err)
	}
}

func TestFakeQueryVuln_AllMethods(t *testing.T) {
	c := coord(t, "example.com/vuln", "v1.0.0")
	f := testfakes.NewFakeQueryVuln()
	rec := vulndomain.VulnerabilityRecord{Coordinate: c, OverallStatus: vulndomain.StatusClean}
	f.AddRecord(c, rec)

	got, found, err := f.GetRecord(context.Background(), c, "0.1.0", vulndomain.DatabaseSnapshot{})
	if err != nil || !found || got.OverallStatus != vulndomain.StatusClean {
		t.Fatalf("GetRecord: %v %v %v", got, found, err)
	}

	got, found, err = f.GetLatestRecord(context.Background(), c, "0.1.0")
	if err != nil || !found {
		t.Fatalf("GetLatestRecord: %v %v %v", got, found, err)
	}

	got, found, err = f.GetLatestRecordForWalk(context.Background(), c, "W1", "0.1.0")
	if err != nil || !found {
		t.Fatalf("GetLatestRecordForWalk: %v %v %v", got, found, err)
	}

	list, err := f.ListRecordsForModule(context.Background(), c, "0.1.0")
	if err != nil || len(list) != 1 {
		t.Fatalf("ListRecordsForModule: %v %v", list, err)
	}

	byID, err := f.ListRecordsByFindingID(context.Background(), "GO-2024-001")
	if err != nil || byID != nil {
		t.Fatalf("ListRecordsByFindingID: %v %v", byID, err)
	}

	empty, _ := fetchdomain.NewModuleCoordinate("example.com/z", "v1.0.0")
	list2, err := f.ListRecordsForModule(context.Background(), empty, "0.1.0")
	if err != nil || list2 != nil {
		t.Fatalf("empty ListRecordsForModule: %v %v", list2, err)
	}

	f.Err = errTest
	_, _, err = f.GetRecord(context.Background(), c, "0.1.0", vulndomain.DatabaseSnapshot{})
	if err == nil {
		t.Fatal("expected error")
	}
	_, _, err = f.GetLatestRecord(context.Background(), c, "0.1.0")
	if err == nil {
		t.Fatal("expected error")
	}
	_, _, err = f.GetLatestRecordForWalk(context.Background(), c, "W1", "0.1.0")
	if err == nil {
		t.Fatal("expected error")
	}
	_, err = f.ListRecordsForModule(context.Background(), c, "0.1.0")
	if err == nil {
		t.Fatal("expected error")
	}
	_, err = f.ListRecordsByFindingID(context.Background(), "")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestFakeQueryScanRuns_AllMethods(t *testing.T) {
	f := testfakes.NewFakeQueryScanRuns()
	run := vulndomain.WalkScanRun{ID: "SR1", WalkID: "W1"}
	f.AddRun(run)

	got, found, err := f.GetRun(context.Background(), "SR1")
	if err != nil || !found || got.ID != "SR1" {
		t.Fatalf("GetRun: %v %v %v", got, found, err)
	}
	_, found2, _ := f.GetRun(context.Background(), "MISSING")
	if found2 {
		t.Fatal("expected not found")
	}

	runs, err := f.ListRunsForWalk(context.Background(), "W1")
	if err != nil || len(runs) != 1 {
		t.Fatalf("ListRunsForWalk: %v %v", runs, err)
	}
	empty, _ := f.ListRunsForWalk(context.Background(), "OTHER")
	if empty != nil {
		t.Fatalf("expected nil for different walk: %v", empty)
	}

	all, err := f.ListAllRuns(context.Background())
	if err != nil || len(all) != 1 {
		t.Fatalf("ListAllRuns: %v %v", all, err)
	}

	snaps, err := f.ListSnapshots(context.Background())
	if err != nil || snaps != nil {
		t.Fatalf("ListSnapshots: %v %v", snaps, err)
	}

	_, found3, err := f.GetLatestSnapshot(context.Background())
	if err != nil || found3 {
		t.Fatalf("GetLatestSnapshot (empty): %v %v", found3, err)
	}

	f.GetErr = errTest
	_, _, err = f.GetRun(context.Background(), "SR1")
	if err == nil {
		t.Fatal("expected error")
	}
	f.GetErr = nil
	f.ListErr = errTest
	_, err = f.ListRunsForWalk(context.Background(), "W1")
	if err == nil {
		t.Fatal("expected error")
	}
	_, err = f.ListAllRuns(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	_, err = f.ListSnapshots(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	_, _, err = f.GetLatestSnapshot(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestFakeDiffScanRuns_Diff(t *testing.T) {
	f := &testfakes.FakeDiffScanRuns{Result: vulndomain.ScanRunDiff{}}
	_, err := f.Diff(context.Background(), "A", "B")
	if err != nil {
		t.Fatal(err)
	}
}

func TestFakeGenerateSBOM_Generate(t *testing.T) {
	f := &testfakes.FakeGenerateSBOM{Result: sbomdomain.SBOMRecord{ID: "S1"}}
	res, err := f.Generate(context.Background(), sbomapp.SBOMRequest{})
	if err != nil || res.ID != "S1" {
		t.Fatalf("unexpected: %v %v", res, err)
	}
}

func TestFakeQuerySBOM_AllMethods(t *testing.T) {
	f := testfakes.NewFakeQuerySBOM()

	_, _ = f.GetSBOMRecord(context.Background(), "MISSING")

	list, err := f.ListSBOMRecords(context.Background(), "W1")
	if err != nil || list != nil {
		t.Fatalf("ListSBOMRecords: %v %v", list, err)
	}

	f.Err = errTest
	_, err = f.GetSBOMRecord(context.Background(), "X")
	if err == nil {
		t.Fatal("expected error")
	}
	_, err = f.ListSBOMRecords(context.Background(), "W1")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestFakeExtractFIPS_Execute(t *testing.T) {
	rec := fipsdomain.Record{
		ProjectModulePath: "example.com/proj",
		ToolchainCapable:  true,
		ToolchainVariant:  "boringcrypto",
	}
	f := &testfakes.FakeExtractFIPS{Result: rec}
	got, err := f.Extract(context.Background(), "go.mod", configdomain.FIPSPolicy{Required: true})
	if err != nil || got.ProjectModulePath != "example.com/proj" {
		t.Fatalf("unexpected: %v %v", got, err)
	}
	f2 := &testfakes.FakeExtractFIPS{Err: errTest}
	_, err = f2.Extract(context.Background(), "go.mod", configdomain.FIPSPolicy{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestFakeQueryFIPS_AllMethods(t *testing.T) {
	f := testfakes.NewFakeQueryFIPS()
	rec := fipsdomain.Record{
		ProjectModulePath: "example.com/proj",
		ToolchainCapable:  true,
		ToolchainVariant:  "boringcrypto",
	}
	f.Add("example.com/proj", rec)

	got, found, err := f.Get(context.Background(), "example.com/proj")
	if err != nil || !found || got.ToolchainVariant != "boringcrypto" {
		t.Fatalf("Get: %v %v %v", got, found, err)
	}

	_, found2, err := f.Get(context.Background(), "example.com/never-scanned")
	if err != nil || found2 {
		t.Fatalf("missing: found=%v err=%v", found2, err)
	}

	f.Err = errTest
	_, _, err = f.Get(context.Background(), "example.com/proj")
	if err == nil {
		t.Fatal("expected error")
	}
}

// RunExtract_EmptyStore covers the error path of runExtract (walk not found).
func TestRunExtract_EmptyStore(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Run([]string{"extract", "NONEXISTENT-WALK-ID", "--store-root", t.TempDir()}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for missing walk ID")
	}
}

// TestRunSBOMShow_EmptyStore covers the error path of runSBOMShow.
func TestRunSBOMShow_EmptyStore(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Run([]string{"sbom-show", "NONEXISTENT-SBOM-ID", "--store-root", t.TempDir()}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for missing SBOM ID")
	}
}

func TestRunPolicyValidateDir_Empty(t *testing.T) {
	var buf bytes.Buffer
	err := runPolicyValidateDir(context.Background(), t.TempDir(), &buf)
	if err != nil {
		t.Fatal(err)
	}
	if !containsStr(buf.String(), "no policy files found") {
		t.Errorf("expected 'no policy files found', got: %q", buf.String())
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}
