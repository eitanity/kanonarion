// Package testfakes provides in-memory fakes for all CLI use-case interfaces.
// Import this package from cli tests to exercise run* functions without opening
// a real SQLite database.
package testfakes

import (
	"context"
	"sync"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	configdomain "github.com/eitanity/kanonarion/internal/config/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
	directivedomain "github.com/eitanity/kanonarion/internal/directive/domain"
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
	licensedomain "github.com/eitanity/kanonarion/internal/license/domain"
	licenseports "github.com/eitanity/kanonarion/internal/license/ports"
	sbomapp "github.com/eitanity/kanonarion/internal/sbom/application"
	sbomdomain "github.com/eitanity/kanonarion/internal/sbom/domain"
	vulnapp "github.com/eitanity/kanonarion/internal/vuln/application"
	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	walkapp "github.com/eitanity/kanonarion/internal/walk/application"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// ---- fetch context ----

// FakeFetchModule implements cli.FetchModuleUseCase.
type FakeFetchModule struct {
	Err    error
	Result fetchapp.FetchResult
}

func (f *FakeFetchModule) Execute(_ context.Context, _ fetchapp.FetchRequest) (fetchapp.FetchResult, error) {
	return f.Result, f.Err
}

// FakeQueryFetch implements cli.QueryFetchUseCase.
type FakeQueryFetch struct {
	mu      sync.Mutex
	records map[string]fetchdomain.FactRecord
	Err     error
}

func NewFakeQueryFetch() *FakeQueryFetch {
	return &FakeQueryFetch{records: make(map[string]fetchdomain.FactRecord)}
}

func (f *FakeQueryFetch) Add(coord coordinate.ModuleCoordinate, pipelineVersion string, rec fetchdomain.FactRecord) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records[coord.String()+"|"+pipelineVersion] = rec
}

func (f *FakeQueryFetch) GetFetchRecord(_ context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (fetchdomain.FactRecord, bool, error) {
	if f.Err != nil {
		return fetchdomain.FactRecord{}, false, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.records[coord.String()+"|"+pipelineVersion]
	return rec, ok, nil
}

// ---- walk context ----

// FakeExecuteWalk implements cli.ExecuteWalkUseCase. LastRequest captures the
// most recent request so tests can assert how the CLI translated flags into a
// WalkRequest.
type FakeExecuteWalk struct {
	Err         error
	Result      walkapp.ExecuteWalkResult
	LastRequest walkapp.WalkRequest
}

func (f *FakeExecuteWalk) Execute(_ context.Context, req walkapp.WalkRequest) (walkapp.ExecuteWalkResult, error) {
	f.LastRequest = req
	return f.Result, f.Err
}

// FakeQueryWalks implements cli.QueryWalksUseCase.
type FakeQueryWalks struct {
	mu        sync.Mutex
	walks     map[string]walkdomain.WalkRecord
	summaries []walkports.WalkSummary
	GetErr    error
	ListErr   error
}

func NewFakeQueryWalks() *FakeQueryWalks {
	return &FakeQueryWalks{walks: make(map[string]walkdomain.WalkRecord)}
}

func (f *FakeQueryWalks) AddWalk(rec walkdomain.WalkRecord) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.walks[rec.ID] = rec
}

func (f *FakeQueryWalks) SetSummaries(s []walkports.WalkSummary) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.summaries = s
}

func (f *FakeQueryWalks) GetWalk(_ context.Context, id string) (walkdomain.WalkRecord, error) {
	if f.GetErr != nil {
		return walkdomain.WalkRecord{}, f.GetErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.walks[id]
	if !ok {
		return walkdomain.WalkRecord{}, walkports.ErrWalkNotFound
	}
	return rec, nil
}

func (f *FakeQueryWalks) ListWalks(_ context.Context, filter walkports.WalkFilter) ([]walkports.WalkSummary, error) {
	if f.ListErr != nil {
		return nil, f.ListErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.summaries
	if filter.Scope != nil {
		var filtered []walkports.WalkSummary
		for _, s := range out {
			if s.Scope == *filter.Scope {
				filtered = append(filtered, s)
			}
		}
		out = filtered
	}
	if filter.Target != nil {
		var filtered []walkports.WalkSummary
		for _, s := range out {
			if s.Target == *filter.Target {
				filtered = append(filtered, s)
			}
		}
		out = filtered
	}
	if filter.OverallStatus != nil {
		var filtered []walkports.WalkSummary
		for _, s := range out {
			if s.OverallStatus == *filter.OverallStatus {
				filtered = append(filtered, s)
			}
		}
		out = filtered
	}
	if filter.Limit > 0 && len(out) > filter.Limit {
		out = out[:filter.Limit]
	}
	return out, nil
}

// FakeDiffWalks implements cli.DiffWalksUseCase.
type FakeDiffWalks struct {
	Err    error
	Result walkapp.WalkDiff
}

func (f *FakeDiffWalks) Diff(_ context.Context, _, _ string) (walkapp.WalkDiff, error) {
	return f.Result, f.Err
}

// ---- extract context ----

// FakeExtract implements cli.ExtractUseCase. It records each request so tests
// can assert which stages ran and whether force was set.
type FakeExtract struct {
	Err    error
	Result extractdomain.ExtractionRun
	Calls  []extractapp.ExtractRequest
}

func (f *FakeExtract) Execute(_ context.Context, req extractapp.ExtractRequest) (extractdomain.ExtractionRun, error) {
	f.Calls = append(f.Calls, req)
	return f.Result, f.Err
}

// FakeQueryExtraction implements cli.QueryExtractionUseCase.
type FakeQueryExtraction struct {
	mu   sync.Mutex
	runs map[string]extractdomain.ExtractionRun
	list []extractports.ExtractionRunSummary
	Err  error
}

func NewFakeQueryExtraction() *FakeQueryExtraction {
	return &FakeQueryExtraction{runs: make(map[string]extractdomain.ExtractionRun)}
}

func (f *FakeQueryExtraction) AddRun(run extractdomain.ExtractionRun) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.runs[run.ID] = run
}

func (f *FakeQueryExtraction) GetExtractionRun(_ context.Context, id string) (extractdomain.ExtractionRun, error) {
	if f.Err != nil {
		return extractdomain.ExtractionRun{}, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	run, ok := f.runs[id]
	if !ok {
		return extractdomain.ExtractionRun{}, extractports.ErrExtractionRunNotFound
	}
	return run, nil
}

func (f *FakeQueryExtraction) ListExtractionRuns(_ context.Context, _ extractports.ExtractionRunFilter) ([]extractports.ExtractionRunSummary, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.list, nil
}

// ---- license context ----

// FakeExtractLicense implements cli.ExtractLicenseUseCase.
type FakeExtractLicense struct {
	Err    error
	Result licapp.ExtractResult
}

func (f *FakeExtractLicense) Execute(_ context.Context, _ licapp.ExtractRequest) (licapp.ExtractResult, error) {
	return f.Result, f.Err
}

func (f *FakeExtractLicense) GetLicenseStore() licenseports.LicenseStore {
	return nil
}

// FakeQueryLicense implements cli.QueryLicenseUseCase.
type FakeQueryLicense struct {
	mu            sync.Mutex
	records       map[string]licensedomain.LicenseRecord
	list          []licenseports.LicenseSummary
	resolveResult []licapp.DepLicenseResult
	Err           error
}

func NewFakeQueryLicense() *FakeQueryLicense {
	return &FakeQueryLicense{records: make(map[string]licensedomain.LicenseRecord)}
}

func (f *FakeQueryLicense) AddRecord(coord coordinate.ModuleCoordinate, pipelineVersion string, rec licensedomain.LicenseRecord) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records[coord.String()+"|"+pipelineVersion] = rec
}

func (f *FakeQueryLicense) SetList(summaries []licenseports.LicenseSummary) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.list = summaries
}

func (f *FakeQueryLicense) SetResolveResult(results []licapp.DepLicenseResult) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resolveResult = results
}

func (f *FakeQueryLicense) GetLicenseRecord(_ context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (licensedomain.LicenseRecord, bool, error) {
	if f.Err != nil {
		return licensedomain.LicenseRecord{}, false, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.records[coord.String()+"|"+pipelineVersion]
	return rec, ok, nil
}

func (f *FakeQueryLicense) ListLicenseRecords(_ context.Context, _ licenseports.LicenseFilter) ([]licenseports.LicenseSummary, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.list, nil
}

func (f *FakeQueryLicense) ResolveForWalk(_ context.Context, _ string, _ coordinate.ModuleCoordinate, _ func(context.Context, coordinate.ModuleCoordinate) (licensedomain.LicenseRecord, error)) ([]licapp.DepLicenseResult, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.resolveResult, nil
}

// FakeCheckCompatibility implements cli.CheckCompatibilityUseCase.
type FakeCheckCompatibility struct {
	Report licensedomain.ClosureCompatibilityReport
	Err    error
}

func (f *FakeCheckCompatibility) CheckCompatibilityForWalk(_ context.Context, _ string, _ coordinate.ModuleCoordinate, _ string) (licensedomain.ClosureCompatibilityReport, error) {
	return f.Report, f.Err
}

// FakeDiffLicense implements cli.DiffLicenseUseCase.
type FakeDiffLicense struct {
	Result licensedomain.LicenseDiff
	Err    error
}

func (f *FakeDiffLicense) Diff(_ context.Context, _, _ coordinate.ModuleCoordinate) (licensedomain.LicenseDiff, error) {
	return f.Result, f.Err
}

// FakeGenerateNotice implements cli.GenerateNoticeUseCase.
type FakeGenerateNotice struct {
	Result licapp.NoticeResult
	Err    error
}

func (f *FakeGenerateNotice) Generate(_ context.Context, _ licapp.NoticeRequest) (licapp.NoticeResult, error) {
	return f.Result, f.Err
}

// ---- directive context ----

// FakeQueryDirectives implements cli.QueryDirectivesUseCase.
type FakeQueryDirectives struct {
	Scan    directivedomain.Record
	Found   bool
	Scans   []directivedomain.Record
	GetErr  error
	ListErr error
}

func (f *FakeQueryDirectives) GetScan(_ context.Context, _ string) (directivedomain.Record, bool, error) {
	if f.GetErr != nil {
		return directivedomain.Record{}, false, f.GetErr
	}
	return f.Scan, f.Found, nil
}

func (f *FakeQueryDirectives) ListScans(_ context.Context, _ string, _ int) ([]directivedomain.Record, error) {
	return f.Scans, f.ListErr
}

// FakeDiffDirectives implements cli.DiffDirectivesUseCase.
type FakeDiffDirectives struct {
	Result directivedomain.DirectiveDiff
	Err    error
}

func (f *FakeDiffDirectives) Diff(_ context.Context, _, _ string) (directivedomain.DirectiveDiff, error) {
	return f.Result, f.Err
}

// ---- iface context ----

// FakeExtractInterface implements cli.ExtractInterfaceUseCase.
type FakeExtractInterface struct {
	Err    error
	Result ifaceapp.ExtractResult
}

func (f *FakeExtractInterface) Execute(_ context.Context, _ ifaceapp.ExtractRequest) (ifaceapp.ExtractResult, error) {
	return f.Result, f.Err
}

// FakeQueryInterface implements cli.QueryInterfaceUseCase.
type FakeQueryInterface struct {
	mu      sync.Mutex
	records map[string]ifacedomain.InterfaceRecord
	list    []ifaceports.InterfaceSummary
	symbols []ifaceports.SymbolRef
	Err     error
}

func NewFakeQueryInterface() *FakeQueryInterface {
	return &FakeQueryInterface{records: make(map[string]ifacedomain.InterfaceRecord)}
}

func (f *FakeQueryInterface) GetInterfaceRecord(_ context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (ifacedomain.InterfaceRecord, bool, error) {
	if f.Err != nil {
		return ifacedomain.InterfaceRecord{}, false, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.records[coord.String()+"|"+pipelineVersion]
	return rec, ok, nil
}

func (f *FakeQueryInterface) ListInterfaceRecords(_ context.Context, _ ifaceports.InterfaceFilter) ([]ifaceports.InterfaceSummary, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.list, nil
}

func (f *FakeQueryInterface) FindSymbol(_ context.Context, _, _ string) ([]ifaceports.SymbolRef, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.symbols, nil
}

// ---- callgraph context ----

// FakeExtractCallGraph implements cli.ExtractCallGraphUseCase.
type FakeExtractCallGraph struct {
	Err    error
	Result cgapp.ExtractResult
}

func (f *FakeExtractCallGraph) Execute(_ context.Context, _ cgapp.ExtractRequest) (cgapp.ExtractResult, error) {
	return f.Result, f.Err
}

// FakeQueryCallGraph implements cli.QueryCallGraphUseCase.
type FakeQueryCallGraph struct {
	mu                  sync.Mutex
	records             map[string]cgdomain.CallGraphRecord
	list                []cgports.CallGraphSummary
	callers             []cgports.CallEdgeRef
	callees             []cgports.CallEdgeRef
	traverseCallers     []cgports.CallEdgeRef
	traverseCallerNodes []string
	traverseCallees     []cgports.CallEdgeRef
	traverseCalleeNodes []string
	Err                 error
}

func NewFakeQueryCallGraph() *FakeQueryCallGraph {
	return &FakeQueryCallGraph{records: make(map[string]cgdomain.CallGraphRecord)}
}

func (f *FakeQueryCallGraph) AddRecord(coord coordinate.ModuleCoordinate, pipelineVersion string, rec cgdomain.CallGraphRecord) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records[coord.String()+"|"+pipelineVersion] = rec
}

func (f *FakeQueryCallGraph) SetList(summaries []cgports.CallGraphSummary) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.list = summaries
}

func (f *FakeQueryCallGraph) GetCallGraphRecord(_ context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (cgdomain.CallGraphRecord, bool, error) {
	if f.Err != nil {
		return cgdomain.CallGraphRecord{}, false, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.records[coord.String()+"|"+pipelineVersion]
	return rec, ok, nil
}

func (f *FakeQueryCallGraph) ListCallGraphRecords(_ context.Context, _ cgports.CallGraphFilter) ([]cgports.CallGraphSummary, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.list, nil
}

func (f *FakeQueryCallGraph) SetCallers(refs []cgports.CallEdgeRef) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.callers = refs
}

func (f *FakeQueryCallGraph) SetCallees(refs []cgports.CallEdgeRef) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.callees = refs
}

func (f *FakeQueryCallGraph) FindCallers(_ context.Context, _, _ string) ([]cgports.CallEdgeRef, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.callers, nil
}

func (f *FakeQueryCallGraph) FindCallees(_ context.Context, _, _ string) ([]cgports.CallEdgeRef, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.callees, nil
}

func (f *FakeQueryCallGraph) SetTraverseCallers(edges []cgports.CallEdgeRef, nodes []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.traverseCallers = edges
	f.traverseCallerNodes = nodes
}

func (f *FakeQueryCallGraph) SetTraverseCallees(edges []cgports.CallEdgeRef, nodes []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.traverseCallees = edges
	f.traverseCalleeNodes = nodes
}

func (f *FakeQueryCallGraph) TraverseCallers(_ context.Context, _, _ string, _ int) ([]cgports.CallEdgeRef, []string, error) {
	if f.Err != nil {
		return nil, nil, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.traverseCallers, f.traverseCallerNodes, nil
}

func (f *FakeQueryCallGraph) TraverseCallees(_ context.Context, _, _ string, _ int) ([]cgports.CallEdgeRef, []string, error) {
	if f.Err != nil {
		return nil, nil, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.traverseCallees, f.traverseCalleeNodes, nil
}

// ---- example context ----

// FakeExtractExample implements cli.ExtractExampleUseCase.
type FakeExtractExample struct {
	Err    error
	Result exapp.ExtractResult
}

func (f *FakeExtractExample) Execute(_ context.Context, _ exapp.ExtractRequest) (exapp.ExtractResult, error) {
	return f.Result, f.Err
}

// FakeQueryExamples implements cli.QueryExamplesUseCase.
type FakeQueryExamples struct {
	mu      sync.Mutex
	records map[string]exdomain.ExampleRecord
	list    []exports.ExampleSummary
	refs    []exports.ExampleRef
	Err     error
}

func NewFakeQueryExamples() *FakeQueryExamples {
	return &FakeQueryExamples{records: make(map[string]exdomain.ExampleRecord)}
}

func (f *FakeQueryExamples) AddRecord(coord coordinate.ModuleCoordinate, pipelineVersion string, rec exdomain.ExampleRecord) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records[coord.String()+"|"+pipelineVersion] = rec
}

func (f *FakeQueryExamples) SetList(sums []exports.ExampleSummary) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.list = sums
}

func (f *FakeQueryExamples) SetRefs(refs []exports.ExampleRef) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refs = refs
}

func (f *FakeQueryExamples) GetExampleRecord(_ context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (exdomain.ExampleRecord, bool, error) {
	if f.Err != nil {
		return exdomain.ExampleRecord{}, false, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.records[coord.String()+"|"+pipelineVersion]
	return rec, ok, nil
}

func (f *FakeQueryExamples) ListExampleRecords(_ context.Context, _ exports.ExampleFilter) ([]exports.ExampleSummary, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.list, nil
}

func (f *FakeQueryExamples) FindBySymbol(_ context.Context, _, _ string) ([]exports.ExampleRef, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.refs, nil
}

func (f *FakeQueryExamples) FindBySymbolInModule(_ context.Context, coord coordinate.ModuleCoordinate, _, _ string) ([]exports.ExampleRef, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	// Return refs that match the given module coordinate.
	var out []exports.ExampleRef
	for _, ref := range f.refs {
		if ref.ModulePath == coord.Path && ref.ModuleVersion == coord.Version {
			out = append(out, ref)
		}
	}
	return out, nil
}

// ---- vuln context ----

// FakeScanModule implements cli.ScanModuleUseCase.
type FakeScanModule struct {
	Err    error
	Result vulndomain.VulnerabilityRecord
}

func (f *FakeScanModule) Scan(_ context.Context, _ vulnapp.ScanModuleParams) (vulndomain.VulnerabilityRecord, error) {
	return f.Result, f.Err
}

// FakeScanWalk implements cli.ScanWalkUseCase.
type FakeScanWalk struct {
	Err    error
	Result vulndomain.WalkScanRun
	// ProgressRecords are delivered to the Progress callback (if set) before
	// the result is returned. Use this to test output routing in callers.
	ProgressRecords []FakeScanWalkProgress
}

// FakeScanWalkProgress is one entry delivered to the Progress callback.
type FakeScanWalkProgress struct {
	Coord  coordinate.ModuleCoordinate
	Record vulndomain.VulnerabilityRecord
	Index  int // 1-based; 0 means use slice position
	Total  int // 0 means use len(ProgressRecords)
}

func (f *FakeScanWalk) Scan(_ context.Context, params vulnapp.ScanWalkParams) (vulndomain.WalkScanRun, error) {
	if params.Progress != nil {
		total := len(f.ProgressRecords)
		for i, p := range f.ProgressRecords {
			idx := p.Index
			if idx == 0 {
				idx = i + 1
			}
			tot := p.Total
			if tot == 0 {
				tot = total
			}
			params.Progress(p.Coord, p.Record, idx, tot)
		}
	}
	return f.Result, f.Err
}

// FakeRescanWalk implements cli.RescanWalkUseCase.
type FakeRescanWalk struct {
	Err    error
	Result vulndomain.WalkScanRun
}

func (f *FakeRescanWalk) Rescan(_ context.Context, _ vulnapp.RescanRequest) (vulndomain.WalkScanRun, error) {
	return f.Result, f.Err
}

// FakeQueryVuln implements cli.QueryVulnUseCase.
type FakeQueryVuln struct {
	mu      sync.Mutex
	records map[string]vulndomain.VulnerabilityRecord
	byID    []vulndomain.VulnerabilityRecord
	Err     error
	// ForceLatestRecordForWalkNotFound makes GetLatestRecordForWalk always return
	// (zero, false, nil) regardless of the records map. Use this to exercise the
	// fallback path that checks GetLatestRecord for a ScanFailed status.
	ForceLatestRecordForWalkNotFound bool
}

func NewFakeQueryVuln() *FakeQueryVuln {
	return &FakeQueryVuln{records: make(map[string]vulndomain.VulnerabilityRecord)}
}

func (f *FakeQueryVuln) AddRecord(coord coordinate.ModuleCoordinate, rec vulndomain.VulnerabilityRecord) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records[coord.String()] = rec
}

func (f *FakeQueryVuln) GetRecord(_ context.Context, coord coordinate.ModuleCoordinate, _ string, _ vulndomain.DatabaseSnapshot) (vulndomain.VulnerabilityRecord, bool, error) {
	if f.Err != nil {
		return vulndomain.VulnerabilityRecord{}, false, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.records[coord.String()]
	return rec, ok, nil
}

func (f *FakeQueryVuln) GetLatestRecord(_ context.Context, coord coordinate.ModuleCoordinate, _ string) (vulndomain.VulnerabilityRecord, bool, error) {
	if f.Err != nil {
		return vulndomain.VulnerabilityRecord{}, false, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.records[coord.String()]
	return rec, ok, nil
}

func (f *FakeQueryVuln) GetLatestRecordForWalk(_ context.Context, coord coordinate.ModuleCoordinate, _, _ string) (vulndomain.VulnerabilityRecord, bool, error) {
	if f.Err != nil {
		return vulndomain.VulnerabilityRecord{}, false, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ForceLatestRecordForWalkNotFound {
		return vulndomain.VulnerabilityRecord{}, false, nil
	}
	rec, ok := f.records[coord.String()]
	return rec, ok, nil
}

func (f *FakeQueryVuln) ListRecordsForModule(_ context.Context, coord coordinate.ModuleCoordinate, _ string) ([]vulndomain.VulnerabilityRecord, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if rec, ok := f.records[coord.String()]; ok {
		return []vulndomain.VulnerabilityRecord{rec}, nil
	}
	return nil, nil
}

func (f *FakeQueryVuln) SetByID(recs []vulndomain.VulnerabilityRecord) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.byID = recs
}

func (f *FakeQueryVuln) ListRecordsByFindingID(_ context.Context, _ string) ([]vulndomain.VulnerabilityRecord, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.byID, nil
}

// FakeQueryScanRuns implements cli.QueryScanRunsUseCase.
type FakeQueryScanRuns struct {
	mu        sync.Mutex
	runs      map[string]vulndomain.WalkScanRun
	allRuns   []vulndomain.WalkScanRun
	snapshots []vulndomain.DatabaseSnapshot
	GetErr    error
	ListErr   error
}

func NewFakeQueryScanRuns() *FakeQueryScanRuns {
	return &FakeQueryScanRuns{runs: make(map[string]vulndomain.WalkScanRun)}
}

func (f *FakeQueryScanRuns) AddRun(run vulndomain.WalkScanRun) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.runs[run.ID] = run
	f.allRuns = append(f.allRuns, run)
}

func (f *FakeQueryScanRuns) AddSnapshot(snap vulndomain.DatabaseSnapshot) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.snapshots = append(f.snapshots, snap)
}

func (f *FakeQueryScanRuns) GetRun(_ context.Context, id string) (vulndomain.WalkScanRun, bool, error) {
	if f.GetErr != nil {
		return vulndomain.WalkScanRun{}, false, f.GetErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	run, ok := f.runs[id]
	return run, ok, nil
}

func (f *FakeQueryScanRuns) ListRunsForWalk(_ context.Context, walkID string) ([]vulndomain.WalkScanRun, error) {
	if f.ListErr != nil {
		return nil, f.ListErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []vulndomain.WalkScanRun
	for _, r := range f.allRuns {
		if r.WalkID == walkID {
			out = append(out, r)
		}
	}
	return out, nil
}

func (f *FakeQueryScanRuns) ListAllRuns(_ context.Context) ([]vulndomain.WalkScanRun, error) {
	if f.ListErr != nil {
		return nil, f.ListErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.allRuns, nil
}

func (f *FakeQueryScanRuns) ListSnapshots(_ context.Context) ([]vulndomain.DatabaseSnapshot, error) {
	if f.ListErr != nil {
		return nil, f.ListErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.snapshots, nil
}

func (f *FakeQueryScanRuns) GetLatestSnapshot(_ context.Context) (vulndomain.DatabaseSnapshot, bool, error) {
	if f.ListErr != nil {
		return vulndomain.DatabaseSnapshot{}, false, f.ListErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.snapshots) == 0 {
		return vulndomain.DatabaseSnapshot{}, false, nil
	}
	return f.snapshots[len(f.snapshots)-1], true, nil
}

// FakeDiffScanRuns implements cli.DiffScanRunsUseCase.
type FakeDiffScanRuns struct {
	Err    error
	Result vulndomain.ScanRunDiff
}

func (f *FakeDiffScanRuns) Diff(_ context.Context, _, _ string) (vulndomain.ScanRunDiff, error) {
	return f.Result, f.Err
}

// ---- sbom context ----

// FakeGenerateSBOM implements cli.GenerateSBOMUseCase.
type FakeGenerateSBOM struct {
	Err         error
	Result      sbomdomain.SBOMRecord
	LastRequest sbomapp.SBOMRequest
}

func (f *FakeGenerateSBOM) Generate(_ context.Context, req sbomapp.SBOMRequest) (sbomdomain.SBOMRecord, error) {
	f.LastRequest = req
	return f.Result, f.Err
}

// FakeQuerySBOM implements cli.QuerySBOMUseCase.
type FakeQuerySBOM struct {
	mu      sync.Mutex
	records map[string]sbomdomain.SBOMRecord
	list    []sbomdomain.SBOMRecord
	Err     error
}

func NewFakeQuerySBOM() *FakeQuerySBOM {
	return &FakeQuerySBOM{records: make(map[string]sbomdomain.SBOMRecord)}
}

func (f *FakeQuerySBOM) GetSBOMRecord(_ context.Context, id string) (sbomdomain.SBOMRecord, error) {
	if f.Err != nil {
		return sbomdomain.SBOMRecord{}, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.records[id]
	if !ok {
		return sbomdomain.SBOMRecord{}, f.Err
	}
	return rec, nil
}

func (f *FakeQuerySBOM) ListSBOMRecords(_ context.Context, _ string) ([]sbomdomain.SBOMRecord, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.list, nil
}

// ---- fips context ----

// FakeExtractFIPS implements cli.ExtractFIPSUseCase.
type FakeExtractFIPS struct {
	Err    error
	Result fipsdomain.Record
}

func (f *FakeExtractFIPS) Extract(_ context.Context, _ string, _ configdomain.FIPSPolicy) (fipsdomain.Record, error) {
	return f.Result, f.Err
}

// FakeQueryFIPS implements cli.QueryFIPSUseCase.
type FakeQueryFIPS struct {
	mu      sync.Mutex
	records map[string]fipsdomain.Record
	Err     error
}

func NewFakeQueryFIPS() *FakeQueryFIPS {
	return &FakeQueryFIPS{records: make(map[string]fipsdomain.Record)}
}

func (f *FakeQueryFIPS) Add(projectModulePath string, rec fipsdomain.Record) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records[projectModulePath] = rec
}

func (f *FakeQueryFIPS) Get(_ context.Context, projectModulePath string) (fipsdomain.Record, bool, error) {
	if f.Err != nil {
		return fipsdomain.Record{}, false, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.records[projectModulePath]
	return rec, ok, nil
}
