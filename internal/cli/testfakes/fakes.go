// Package testfakes provides in-memory fakes for all CLI use-case interfaces.
// Import this package from cli tests to exercise run* functions without opening
// a real SQLite database.
package testfakes

import (
	"context"
	"fmt"
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
	vulnports "github.com/eitanity/kanonarion/internal/vuln/ports"
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
	// Calls counts Execute invocations, so a test can assert that a refused
	// flag combination never reached the walk at all.
	Calls int
}

func (f *FakeExecuteWalk) Execute(_ context.Context, req walkapp.WalkRequest) (walkapp.ExecuteWalkResult, error) {
	f.LastRequest = req
	f.Calls++
	return f.Result, f.Err
}

// FakeQueryWalks implements cli.QueryWalksUseCase.
type FakeQueryWalks struct {
	// ListCalls counts calls to this fake's listing method, so a test can
	// assert that a listing which returned rows read the store exactly once and
	// did not also pay the survey read the zero-result notice needs.
	ListCalls int
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
	f.ListCalls++
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
	if filter.BuildEnv != nil {
		// Mirrors the adapter's `goos = ? AND goarch = ?`: exact on both axes,
		// with the empty string selecting the unrecorded frame rather than any.
		var filtered []walkports.WalkSummary
		for _, s := range out {
			if s.GOOS == filter.BuildEnv.GOOS && s.GOARCH == filter.BuildEnv.GOARCH {
				filtered = append(filtered, s)
			}
		}
		out = filtered
	}
	if filter.Toolchain != nil {
		// Mirrors the adapter's `go_version = ?`: exact, with the empty string
		// selecting the walks that recorded no toolchain rather than any.
		var filtered []walkports.WalkSummary
		for _, s := range out {
			if s.GoVersion == *filter.Toolchain {
				filtered = append(filtered, s)
			}
		}
		out = filtered
	}
	if filter.Offset > 0 {
		if filter.Offset >= len(out) {
			return nil, nil
		}
		out = out[filter.Offset:]
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
	// ListCalls counts calls to this fake's listing method, so a test can
	// assert that a listing which returned rows read the store exactly once and
	// did not also pay the survey read the zero-result notice needs.
	ListCalls int
	mu        sync.Mutex
	runs      map[string]extractdomain.ExtractionRun
	list      []extractports.ExtractionRunSummary
	Err       error
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

// SetList sets the summaries ListExtractionRuns pages over.
func (f *FakeQueryExtraction) SetList(sums []extractports.ExtractionRunSummary) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.list = sums
}

func (f *FakeQueryExtraction) ListExtractionRuns(_ context.Context, filter extractports.ExtractionRunFilter) ([]extractports.ExtractionRunSummary, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ListCalls++
	out := f.list
	if filter.Offset > 0 {
		if filter.Offset >= len(out) {
			return nil, nil
		}
		out = out[filter.Offset:]
	}
	if filter.Limit > 0 && len(out) > filter.Limit {
		out = out[:filter.Limit]
	}
	return out, nil
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
	// ListCalls counts calls to this fake's listing method, so a test can
	// assert that a listing which returned rows read the store exactly once and
	// did not also pay the survey read the zero-result notice needs.
	ListCalls     int
	mu            sync.Mutex
	records       map[string]licensedomain.LicenseRecord
	history       map[string][]licensedomain.LicenseRecord
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

// History is the generation list LicenseHistory returns, keyed by
// "coordinate|pipelineVersion" like records.
func (f *FakeQueryLicense) SetHistory(coord coordinate.ModuleCoordinate, pipelineVersion string, recs []licensedomain.LicenseRecord) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.history == nil {
		f.history = map[string][]licensedomain.LicenseRecord{}
	}
	f.history[coord.String()+"|"+pipelineVersion] = recs
}

func (f *FakeQueryLicense) LicenseHistory(_ context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) ([]licensedomain.LicenseRecord, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.history[coord.String()+"|"+pipelineVersion], nil
}

// ListLicenseRecords applies the filter the SQLite adapter applies: exact
// equality on the primary SPDX identifier, then the offset, then the limit.
func (f *FakeQueryLicense) ListLicenseRecords(_ context.Context, filter licenseports.LicenseFilter) ([]licenseports.LicenseSummary, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ListCalls++
	// nil, not an empty slice, when nothing matches, as the adapter does.
	var out []licenseports.LicenseSummary
	for _, s := range f.list {
		if filter.SPDX != "" && s.PrimarySPDX != filter.SPDX {
			continue
		}
		out = append(out, s)
	}
	if filter.Offset > 0 {
		if filter.Offset >= len(out) {
			return nil, nil
		}
		out = out[filter.Offset:]
	}
	if filter.Limit > 0 && len(out) > filter.Limit {
		out = out[:filter.Limit]
	}
	return out, nil
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
	// ReportByWalk answers per walk id, so a test can give two walks of one
	// target genuinely different licence positions — which is the whole point of
	// being able to pin one. A walk id absent from the map falls back to Report.
	ReportByWalk map[string]licensedomain.ClosureCompatibilityReport
	Err          error
	// AskedWalkIDs records, in order, the walks the command asked about.
	AskedWalkIDs []string
}

func (f *FakeCheckCompatibility) CheckCompatibilityForWalk(_ context.Context, walkID string, _ coordinate.ModuleCoordinate, _ string, _ licensedomain.LicenseOverrideSet) (licensedomain.ClosureCompatibilityReport, error) {
	f.AskedWalkIDs = append(f.AskedWalkIDs, walkID)
	if rep, ok := f.ReportByWalk[walkID]; ok {
		return rep, f.Err
	}
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

// FakeDiffInterface implements cli.DiffInterfaceUseCase.
type FakeDiffInterface struct {
	Result ifacedomain.InterfaceDiff
	Err    error
}

func (f *FakeDiffInterface) Diff(_ context.Context, _, _ coordinate.ModuleCoordinate) (ifacedomain.InterfaceDiff, error) {
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
	// StoreScans is how many scans the whole store holds, across every project.
	// Zero means "the same as Scans": the common fixture has one project and no
	// reason to distinguish the two, and a fixture that wants a store holding
	// scans for OTHER projects sets it explicitly.
	StoreScans int
	CountErr   error
	// ListCalls counts calls to ListScans, so a test can assert that a listing
	// which returned rows read the store once and did not also pay the
	// zero-result survey.
	ListCalls int
}

func (f *FakeQueryDirectives) GetScan(_ context.Context, _ string) (directivedomain.Record, bool, error) {
	if f.GetErr != nil {
		return directivedomain.Record{}, false, f.GetErr
	}
	return f.Scan, f.Found, nil
}

func (f *FakeQueryDirectives) ListScans(_ context.Context, _ string, limit, offset int) ([]directivedomain.Record, error) {
	f.ListCalls++
	if f.ListErr != nil {
		return nil, f.ListErr
	}
	out := f.Scans
	// Paging is honoured as the adapter honours it: a fake that ignored the
	// offset could not fail a listing that never passed one on.
	if offset > 0 {
		if offset >= len(out) {
			return nil, nil
		}
		out = out[offset:]
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (f *FakeQueryDirectives) CountScans(context.Context) (int, error) {
	if f.CountErr != nil {
		return 0, f.CountErr
	}
	if f.StoreScans > 0 {
		return f.StoreScans, nil
	}
	return len(f.Scans), nil
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
	// ListCalls counts calls to this fake's listing method, so a test can
	// assert that a listing which returned rows read the store exactly once and
	// did not also pay the survey read the zero-result notice needs.
	ListCalls int
	mu        sync.Mutex
	records   map[string]ifacedomain.InterfaceRecord
	history   map[string][]ifacedomain.InterfaceRecord
	list      []ifaceports.InterfaceSummary
	symbols   []ifaceports.SymbolRef
	Err       error
}

func NewFakeQueryInterface() *FakeQueryInterface {
	return &FakeQueryInterface{
		records: make(map[string]ifacedomain.InterfaceRecord),
		history: make(map[string][]ifacedomain.InterfaceRecord),
	}
}

// SetInterfaceHistory sets the generations InterfaceHistory returns for a
// coordinate.
func (f *FakeQueryInterface) SetInterfaceHistory(coord coordinate.ModuleCoordinate, pipelineVersion string, recs []ifacedomain.InterfaceRecord) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.history[coord.String()+"|"+pipelineVersion] = recs
}

func (f *FakeQueryInterface) InterfaceHistory(_ context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) ([]ifacedomain.InterfaceRecord, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.history[coord.String()+"|"+pipelineVersion], nil
}

// AddRecord sets the composed record GetInterfaceRecord returns for a coordinate.
func (f *FakeQueryInterface) AddRecord(coord coordinate.ModuleCoordinate, pipelineVersion string, rec ifacedomain.InterfaceRecord) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records[coord.String()+"|"+pipelineVersion] = rec
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

// SetList sets the summaries ListInterfaceRecords pages over.
func (f *FakeQueryInterface) SetList(sums []ifaceports.InterfaceSummary) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.list = sums
}

func (f *FakeQueryInterface) ListInterfaceRecords(_ context.Context, filter ifaceports.InterfaceFilter) ([]ifaceports.InterfaceSummary, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ListCalls++
	// Paging is honoured as the adapter honours it. A fake that ignored the
	// limit could not fail a listing that mis-states how much it withheld.
	out := f.list
	if filter.Offset > 0 {
		if filter.Offset >= len(out) {
			return nil, nil
		}
		out = out[filter.Offset:]
	}
	if filter.Limit > 0 && len(out) > filter.Limit {
		out = out[:filter.Limit]
	}
	return out, nil
}

func (f *FakeQueryInterface) FindSymbol(_ context.Context, _, _ string, scope coordinate.ModuleSet) ([]ifaceports.SymbolRef, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !scope.IsRestricted() {
		return f.symbols, nil
	}
	out := make([]ifaceports.SymbolRef, 0, len(f.symbols))
	for _, r := range f.symbols {
		if scope.ContainsPathVersion(r.ModulePath, r.ModuleVersion) {
			out = append(out, r)
		}
	}
	return out, nil
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
	// ListCalls counts calls to this fake's listing method, so a test can
	// assert that a listing which returned rows read the store exactly once and
	// did not also pay the survey read the zero-result notice needs.
	ListCalls int
	// CoordinateListCalls counts calls to the column-only listing, and RecordReads
	// every composed record read.
	//
	// They are counted separately from ListCalls because the difference between
	// them IS the behaviour: an edge query asks which modules the store has
	// analysed, which is a question about coordinates, and answering it through
	// the composing listing decodes every generation of every multi-generation
	// coordinate in the store to read fields no part of the answer looks at.
	CoordinateListCalls int
	RecordReads         int
	mu                  sync.Mutex
	records             map[string]cgdomain.CallGraphRecord
	list                []cgports.CallGraphSummary
	callers             []cgports.CallEdgeRef
	callersBySymbol     map[string][]cgports.CallEdgeRef
	callees             []cgports.CallEdgeRef
	traverseCallers     []cgports.CallEdgeRef
	traverseCallerNodes []string
	traverseCallees     []cgports.CallEdgeRef
	traverseCalleeNodes []string
	history             map[string][]cgdomain.CallGraphRecord
	getErr              error
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

// SetGetErr makes record reads fail while listing still succeeds, so a caller
// that must surface a store failure rather than report an empty answer can be
// tested at the point the read happens.
func (f *FakeQueryCallGraph) SetGetErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.getErr = err
}

func (f *FakeQueryCallGraph) GetCallGraphRecord(_ context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (cgdomain.CallGraphRecord, bool, error) {
	if f.Err != nil {
		return cgdomain.CallGraphRecord{}, false, f.Err
	}
	if f.getErr != nil {
		return cgdomain.CallGraphRecord{}, false, f.getErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.RecordReads++
	rec, ok := f.records[coord.String()+"|"+pipelineVersion]
	return rec, ok, nil
}

// AddGeneration appends a record to the coordinate's history without changing
// what GetCallGraphRecord serves, so a test can set up a ledger holding several
// generations and a composed answer independently.
func (f *FakeQueryCallGraph) AddGeneration(coord coordinate.ModuleCoordinate, pipelineVersion string, rec cgdomain.CallGraphRecord) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := coord.String() + "|" + pipelineVersion
	if f.history == nil {
		f.history = make(map[string][]cgdomain.CallGraphRecord)
	}
	f.history[key] = append(f.history[key], rec)
}

func (f *FakeQueryCallGraph) GetCallGraphRecordFrom(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string, req cgdomain.ComposeRequest) (cgdomain.CallGraphRecord, bool, error) {
	rec, found, err := f.GetCallGraphRecord(ctx, coord, pipelineVersion)
	if err != nil || !found {
		return rec, found, err
	}
	if req.Source != cgdomain.AnalysisSourceUnrecorded && rec.AnalysisSource != req.Source {
		return cgdomain.CallGraphRecord{}, false, nil
	}
	if req.Toolchain.Recorded() && cgdomain.RecordToolchain(rec).Version != req.Toolchain {
		return cgdomain.CallGraphRecord{}, false, nil
	}
	return rec, true, nil
}

func (f *FakeQueryCallGraph) CallGraphHistory(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) ([]cgdomain.CallGraphRecord, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	f.mu.Lock()
	key := coord.String() + "|" + pipelineVersion
	gens := append([]cgdomain.CallGraphRecord(nil), f.history[key]...)
	f.mu.Unlock()
	if len(gens) > 0 {
		return gens, nil
	}
	// No explicit history was staged, so the single served record IS the history.
	// A fake that returned nothing here would make "the ledger holds one
	// generation" indistinguishable from "the store keeps no history at all".
	rec, ok, err := f.GetCallGraphRecord(ctx, coord, pipelineVersion)
	if err != nil || !ok {
		return nil, err
	}
	return []cgdomain.CallGraphRecord{rec}, nil
}

// ListCallGraphRecords applies the filter the SQLite adapter applies: exact
// equality on the module path, then offset, then limit. A fake that returned
// everything regardless would let a filter defect pass every test that used it.
func (f *FakeQueryCallGraph) ListCallGraphRecords(_ context.Context, filter cgports.CallGraphFilter) ([]cgports.CallGraphSummary, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ListCalls++
	return f.filteredSummaries(filter), nil
}

// filteredSummaries is the filter itself, without the call counting, so the two
// listings can be told apart by a test that counts them.
//
// The caller holds f.mu.
func (f *FakeQueryCallGraph) filteredSummaries(filter cgports.CallGraphFilter) []cgports.CallGraphSummary {
	// nil, not an empty slice, when nothing matches: the store's own adapter
	// returns nil and every caller is written against that.
	var out []cgports.CallGraphSummary
	for _, s := range f.list {
		if filter.ModulePath != "" && s.ModulePath != filter.ModulePath {
			continue
		}
		if filter.PipelineVersion != "" && s.PipelineVersion != filter.PipelineVersion {
			continue
		}
		out = append(out, s)
	}
	if filter.Offset > 0 {
		if filter.Offset >= len(out) {
			return nil
		}
		out = out[filter.Offset:]
	}
	if filter.Limit > 0 && len(out) > filter.Limit {
		out = out[:filter.Limit]
	}
	return out
}

// ListCallGraphCoordinates projects the same filtered listing onto the ledger's
// keys.
//
// The two flags are read off the RECORDS the fake holds, not off the summaries.
// A real store reads them from denormalised columns that a write puts there from
// the record itself, so the two can never disagree; in the fake they are set
// independently, and deriving the flags from the summary would let a test whose
// summary says nothing hide a Partial record the resolution helpers must see.
func (f *FakeQueryCallGraph) ListCallGraphCoordinates(_ context.Context, filter cgports.CallGraphFilter) ([]cgports.CallGraphCoordinate, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.CoordinateListCalls++
	sums := f.filteredSummaries(filter)
	var out []cgports.CallGraphCoordinate
	for _, s := range sums {
		c := cgports.CallGraphCoordinate{
			ModulePath:      s.ModulePath,
			ModuleVersion:   s.ModuleVersion,
			PipelineVersion: s.PipelineVersion,
			AnyPartial:      s.OverallStatus == cgdomain.CallGraphStatusPartial,
			AnyBelowFull: s.Completeness != cgdomain.CompletenessUnknown &&
				!s.Completeness.IsBuiltWithBodies(),
		}
		coord, cErr := coordinate.NewModuleCoordinate(s.ModulePath, s.ModuleVersion)
		if s.ModuleVersion == coordinate.LocalVersion {
			coord, cErr = coordinate.NewLocalCoordinate(s.ModulePath)
		}
		if cErr == nil {
			key := coord.String() + "|" + s.PipelineVersion
			gens := append([]cgdomain.CallGraphRecord(nil), f.history[key]...)
			if rec, ok := f.records[key]; ok {
				gens = append(gens, rec)
			}
			for _, rec := range gens {
				if rec.OverallStatus == cgdomain.CallGraphStatusPartial {
					c.AnyPartial = true
				}
				if rec.Completeness != cgdomain.CompletenessUnknown && !rec.Completeness.IsBuiltWithBodies() {
					c.AnyBelowFull = true
				}
			}
		}
		out = append(out, c)
	}
	return out, nil
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

// SetCallersFor answers one symbol specifically. A command that queries several
// symbols in one run needs the fake to tell them apart; SetCallers alone would
// return the same edges for every one of them, and a join that queried the wrong
// symbol would still pass.
func (f *FakeQueryCallGraph) SetCallersFor(symbolID string, refs []cgports.CallEdgeRef) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.callersBySymbol == nil {
		f.callersBySymbol = make(map[string][]cgports.CallEdgeRef)
	}
	f.callersBySymbol[symbolID] = refs
}

func (f *FakeQueryCallGraph) FindCallers(_ context.Context, symbolID, _ string, scope coordinate.ModuleSet, opts cgports.EdgeQueryOptions) ([]cgports.CallEdgeRef, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.callersBySymbol != nil {
		return scopeEdgeRefs(f.callersBySymbol[symbolID], scope), nil
	}
	return scopeEdgeRefs(f.callers, scope), nil
}

func (f *FakeQueryCallGraph) FindCallees(_ context.Context, _, _ string, scope coordinate.ModuleSet, opts cgports.EdgeQueryOptions) ([]cgports.CallEdgeRef, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return scopeEdgeRefs(f.callees, scope), nil
}

// scopeEdgeRefs mirrors the real store's scope filter so a CLI test can observe
// whether the scope reached the query at all — a fake that ignored the argument
// would pass whether or not the command plumbed it.
func scopeEdgeRefs(refs []cgports.CallEdgeRef, scope coordinate.ModuleSet) []cgports.CallEdgeRef {
	if !scope.IsRestricted() {
		return refs
	}
	out := make([]cgports.CallEdgeRef, 0, len(refs))
	for _, r := range refs {
		if scope.ContainsPathVersion(r.ModulePath, r.ModuleVersion) {
			out = append(out, r)
		}
	}
	return out
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

func (f *FakeQueryCallGraph) TraverseCallers(_ context.Context, _, _ string, _ int, scope coordinate.ModuleSet, opts cgports.EdgeQueryOptions) ([]cgports.CallEdgeRef, []string, error) {
	if f.Err != nil {
		return nil, nil, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return scopeEdgeRefs(f.traverseCallers, scope), f.traverseCallerNodes, nil
}

func (f *FakeQueryCallGraph) TraverseCallees(_ context.Context, _, _ string, _ int, scope coordinate.ModuleSet, opts cgports.EdgeQueryOptions) ([]cgports.CallEdgeRef, []string, error) {
	if f.Err != nil {
		return nil, nil, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return scopeEdgeRefs(f.traverseCallees, scope), f.traverseCalleeNodes, nil
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
	// ListCalls counts calls to this fake's listing method, so a test can
	// assert that a listing which returned rows read the store exactly once and
	// did not also pay the survey read the zero-result notice needs.
	ListCalls int
	mu        sync.Mutex
	records   map[string]exdomain.ExampleRecord
	history   map[string][]exdomain.ExampleRecord
	list      []exports.ExampleSummary
	refs      []exports.ExampleRef
	Err       error
}

func NewFakeQueryExamples() *FakeQueryExamples {
	return &FakeQueryExamples{
		records: make(map[string]exdomain.ExampleRecord),
		history: make(map[string][]exdomain.ExampleRecord),
	}
}

// SetHistory sets the generations ExampleHistory returns for a coordinate.
func (f *FakeQueryExamples) SetHistory(coord coordinate.ModuleCoordinate, pipelineVersion string, recs []exdomain.ExampleRecord) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.history[coord.String()+"|"+pipelineVersion] = recs
}

func (f *FakeQueryExamples) ExampleHistory(_ context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) ([]exdomain.ExampleRecord, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.history[coord.String()+"|"+pipelineVersion], nil
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

func (f *FakeQueryExamples) ListExampleRecords(_ context.Context, filter exports.ExampleFilter) ([]exports.ExampleSummary, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ListCalls++
	out := f.list
	if filter.Offset > 0 {
		if filter.Offset >= len(out) {
			return nil, nil
		}
		out = out[filter.Offset:]
	}
	if filter.Limit > 0 && len(out) > filter.Limit {
		out = out[:filter.Limit]
	}
	return out, nil
}

func (f *FakeQueryExamples) FindBySymbol(_ context.Context, _, _ string, _ coordinate.ModuleSet) ([]exports.ExampleRef, error) {
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
		if ref.ModulePath == coord.Path() && ref.ModuleVersion == coord.Version() {
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

	// ReusableRunResult and ReusableRunFound are what ReusableRun reports. The
	// zero value reports no reusable run, so a fake that says nothing about reuse
	// drives the measuring path, which is what most callers want.
	ReusableRunResult vulndomain.WalkScanRun
	ReusableRunFound  bool
	ReusableRunErr    error
	// ReusableRunWalkID records the walk the last ReusableRun call asked about,
	// so a test can prove the reuse question was asked about the walk the run
	// executed rather than some other walk of the same target.
	ReusableRunWalkID string
	// ReusableRunProjectDir records the project directory the last ReusableRun
	// call was told about. Whether a stored run may be served depends on that
	// directory still building what the walk resolved, so a caller that asks the
	// reuse question without naming the tree it would have scanned bypasses the
	// check; this records what was named.
	ReusableRunProjectDir string
	// ReusableRunProjectDirSet reports that ReusableRun was called at all, so a
	// test can tell "asked with no directory" from "never asked".
	ReusableRunProjectDirSet bool
	// ServedRuns records every (run id, surface) pair ServeReusableRun was told
	// about, so a test can prove a served answer was witnessed exactly once and
	// attributed to the surface that asked. ServeReusableRunErr fails the append.
	ServedRuns          []ServedRun
	ServeReusableRunErr error
	// ScanCalls counts Scan invocations, so a test can prove a served run did not
	// re-measure.
	ScanCalls int

	// RefreshSnapshotResult and RefreshSnapshotErr are what RefreshSnapshot
	// reports; RefreshSnapshotCalls counts the calls, so a test can prove a run
	// checked the advisory database exactly once — or not at all.
	RefreshSnapshotResult vulnapp.SnapshotRefresh
	RefreshSnapshotErr    error
	RefreshSnapshotCalls  int
	// RefreshSnapshotWalkID records the walk the last refresh restricted its
	// advisory comparison to.
	RefreshSnapshotWalkID string

	// ToolchainAdvisories is what the seeded snapshot is taken to say under its
	// toolchain key; ToolchainErr fails the read instead. JudgeToolchain runs the
	// real domain judgment over them, so a test seeds advisories rather than a
	// verdict and the fake cannot disagree with the shipped ranking.
	ToolchainAdvisories vulndomain.ToolchainAdvisorySet
	ToolchainErr        error
	// ToolchainVersion records the version the last judgment was asked about, so
	// a test can prove which of the walk's two toolchain versions was read.
	ToolchainVersion string
}

// FakeScanWalkProgress is one entry delivered to the Progress callback.
type FakeScanWalkProgress struct {
	Coord  coordinate.ModuleCoordinate
	Record vulndomain.VulnerabilityRecord
	Index  int // 1-based; 0 means use slice position
	Total  int // 0 means use len(ProgressRecords)
}

// ReusableRun reports the seeded reusable run, if any.
func (f *FakeScanWalk) ReusableRun(_ context.Context, walkID, projectDir string) (vulndomain.WalkScanRun, bool, error) {
	f.ReusableRunWalkID = walkID
	f.ReusableRunProjectDir = projectDir
	f.ReusableRunProjectDirSet = true
	if f.ReusableRunErr != nil {
		return vulndomain.WalkScanRun{}, false, f.ReusableRunErr
	}
	return f.ReusableRunResult, f.ReusableRunFound, nil
}

// ServedRun is one witnessed serving of a stored scan run.
type ServedRun struct {
	RunID   string
	WalkID  string
	Surface string
}

// ServeReusableRun records the serving the caller witnessed.
func (f *FakeScanWalk) ServeReusableRun(run vulndomain.WalkScanRun, surface string) error {
	if f.ServeReusableRunErr != nil {
		return f.ServeReusableRunErr
	}
	f.ServedRuns = append(f.ServedRuns, ServedRun{RunID: run.ID, WalkID: run.WalkID, Surface: surface})
	return nil
}

// RefreshSnapshot reports the seeded refresh outcome and counts the call.
func (f *FakeScanWalk) RefreshSnapshot(_ context.Context, walkID string) (vulnapp.SnapshotRefresh, error) {
	f.RefreshSnapshotCalls++
	f.RefreshSnapshotWalkID = walkID
	if f.RefreshSnapshotErr != nil {
		return vulnapp.SnapshotRefresh{}, f.RefreshSnapshotErr
	}
	return f.RefreshSnapshotResult, nil
}

// JudgeToolchain judges the seeded toolchain advisories with the real domain
// rule.
func (f *FakeScanWalk) JudgeToolchain(_ context.Context, snapshot vulndomain.DatabaseSnapshot, toolchainVersion string) (vulndomain.ToolchainJudgment, error) {
	f.ToolchainVersion = toolchainVersion
	if f.ToolchainErr != nil {
		return vulndomain.ToolchainJudgment{}, f.ToolchainErr
	}
	return vulndomain.JudgeToolchain(toolchainVersion, snapshot, f.ToolchainAdvisories), nil
}

func (f *FakeScanWalk) Scan(_ context.Context, params vulnapp.ScanWalkParams) (vulndomain.WalkScanRun, error) {
	f.ScanCalls++
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
	// byIDForWalk holds the walk-scoped answers for ListRecordsByFindingID. A
	// walk with no entry is unknown to the store, which is an error rather than
	// an empty result — the same distinction the sqlite adapter makes.
	// recordLedger holds every generation for a coordinate, for the reads that
	// pick between analysis frames rather than taking the composed answer.
	recordLedger map[string][]vulndomain.VulnerabilityRecord
	// runRecords holds the records a given scan run wrote.
	runRecords   map[string][]vulndomain.VulnerabilityRecord
	byIDForWalk  map[string][]vulndomain.VulnerabilityRecord
	byIDWalkSeen string
	Err          error
	// ForceLatestRecordForWalkNotFound empties the walk-scoped candidate read
	// regardless of the records map. Use this to exercise the fallback path that
	// checks GetLatestRecord for a ScanFailed status.
	ForceLatestRecordForWalkNotFound bool
	// supersededLedger holds records the store has at a generation this build's
	// keyed reads cannot see. They are returned only by the all-generations read,
	// which is the shape of the real store after a pipeline bump: the keyed reads
	// go empty while the rows are still there.
	supersededLedger map[string][]vulndomain.VulnerabilityRecord
	// generations is the store census: which pipeline versions this coordinate
	// is held at, whatever version a read asks for. It is seeded independently
	// of the records maps because the condition it exists to reproduce is
	// exactly a coordinate whose records no read returns.
	generations map[string][]vulnports.VulnerabilityRecordGeneration
}

// SetRecordGenerations seeds the store census for a coordinate.
func (f *FakeQueryVuln) SetRecordGenerations(coord coordinate.ModuleCoordinate, gens []vulnports.VulnerabilityRecordGeneration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.generations == nil {
		f.generations = make(map[string][]vulnports.VulnerabilityRecordGeneration)
	}
	f.generations[coord.String()] = gens
}

// ListRecordGenerationsForModule answers the census. An unseeded coordinate
// holds nothing, which is the "never scanned" case.
func (f *FakeQueryVuln) ListRecordGenerationsForModule(_ context.Context, coord coordinate.ModuleCoordinate) ([]vulnports.VulnerabilityRecordGeneration, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.generations[coord.String()], nil
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

// ListRecordsForModuleInWalk returns the walk's candidate records for a
// coordinate: the ledger's generations when one has been seeded, otherwise the
// single record the map holds. ForceLatestRecordForWalkNotFound empties it, the
// same way it empties the composed read below.
func (f *FakeQueryVuln) ListRecordsForModuleInWalk(_ context.Context, coord coordinate.ModuleCoordinate, _, _ string) ([]vulndomain.VulnerabilityRecord, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ForceLatestRecordForWalkNotFound {
		return nil, nil
	}
	if recs, ok := f.recordLedger[coord.String()]; ok {
		return recs, nil
	}
	if rec, ok := f.records[coord.String()]; ok {
		return []vulndomain.VulnerabilityRecord{rec}, nil
	}
	return nil, nil
}

// AddRecords seeds every generation the ledger holds for one coordinate, which
// is what a frame-aware read consults. The first is also the coordinate's
// single-record answer, so a test that seeds a ledger does not have to seed the
// composed read separately.
func (f *FakeQueryVuln) AddRecords(coord coordinate.ModuleCoordinate, recs ...vulndomain.VulnerabilityRecord) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.recordLedger == nil {
		f.recordLedger = make(map[string][]vulndomain.VulnerabilityRecord)
	}
	f.recordLedger[coord.String()] = recs
	if len(recs) > 0 {
		f.records[coord.String()] = recs[0]
	}
}

func (f *FakeQueryVuln) ListRecordsForModule(_ context.Context, coord coordinate.ModuleCoordinate, _ string) ([]vulndomain.VulnerabilityRecord, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if recs, ok := f.recordLedger[coord.String()]; ok {
		return recs, nil
	}
	if rec, ok := f.records[coord.String()]; ok {
		return []vulndomain.VulnerabilityRecord{rec}, nil
	}
	return nil, nil
}

// ListRecordsForModuleAllGenerations returns what the keyed read returns plus
// the rows seeded through AddSupersededRecords, which no other read here sees.
// The superseded rows come last: the fake seeds no timestamps of its own, and a
// listing that puts them first would pass a test the real newest-first ordering
// would fail.
func (f *FakeQueryVuln) ListRecordsForModuleAllGenerations(ctx context.Context, coord coordinate.ModuleCoordinate) ([]vulndomain.VulnerabilityRecord, error) {
	served, err := f.ListRecordsForModule(ctx, coord, "")
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return append(served, f.supersededLedger[coord.String()]...), nil
}

// AddSupersededRecords seeds records the store holds at a generation this build
// does not serve. Only ListRecordsForModuleAllGenerations returns them, so a
// test can reproduce a coordinate whose whole history is dark to the keyed
// reads while the rows are still in the store.
func (f *FakeQueryVuln) AddSupersededRecords(coord coordinate.ModuleCoordinate, recs ...vulndomain.VulnerabilityRecord) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.supersededLedger == nil {
		f.supersededLedger = make(map[string][]vulndomain.VulnerabilityRecord)
	}
	f.supersededLedger[coord.String()] = recs
}

// SetRunRecords seeds the records one scan run wrote, which is what a served
// run's report is rebuilt from.
func (f *FakeQueryVuln) SetRunRecords(runID string, recs []vulndomain.VulnerabilityRecord) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.runRecords == nil {
		f.runRecords = make(map[string][]vulndomain.VulnerabilityRecord)
	}
	f.runRecords[runID] = recs
}

func (f *FakeQueryVuln) ListRecordsForRun(_ context.Context, runID string) ([]vulndomain.VulnerabilityRecord, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.runRecords[runID], nil
}

func (f *FakeQueryVuln) SetByID(recs []vulndomain.VulnerabilityRecord) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.byID = recs
}

// SetByIDForWalk seeds the answer a walk-scoped vuln-by-id query gets. Walks
// with no entry are reported as never scanned.
func (f *FakeQueryVuln) SetByIDForWalk(walkID string, recs []vulndomain.VulnerabilityRecord) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.byIDForWalk == nil {
		f.byIDForWalk = make(map[string][]vulndomain.VulnerabilityRecord)
	}
	f.byIDForWalk[walkID] = recs
}

// ByIDWalkSeen returns the walk ID the last ListRecordsByFindingID call carried,
// so a test can prove the flag reached the use case rather than being dropped.
func (f *FakeQueryVuln) ByIDWalkSeen() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.byIDWalkSeen
}

func (f *FakeQueryVuln) ListRecordsByFindingID(_ context.Context, _, walkID string) ([]vulndomain.VulnerabilityRecord, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.byIDWalkSeen = walkID
	if walkID == "" {
		return f.byID, nil
	}
	recs, ok := f.byIDForWalk[walkID]
	if !ok {
		return nil, fmt.Errorf("no vulnerability scan run for walk %s", walkID)
	}
	return recs, nil
}

// FakeQueryScanRuns implements cli.QueryScanRunsUseCase.
type FakeQueryScanRuns struct {
	// ListCalls counts calls to this fake's listing method, so a test can
	// assert that a listing which returned rows read the store exactly once and
	// did not also pay the survey read the zero-result notice needs.
	ListCalls int
	mu        sync.Mutex
	runs      map[string]vulndomain.WalkScanRun
	allRuns   []vulndomain.WalkScanRun
	snapshots []vulndomain.DatabaseSnapshot
	GetErr    error
	ListErr   error
	// AbsentWalks are the walk ids this store no longer holds — the runs naming
	// them have inputs that cannot be resolved. Empty (the default) means every
	// seeded run's walk resolves, which is the healthy store.
	AbsentWalks map[string]bool
	// PresenceErr, when set, is what the walk-presence probe fails with. A reader
	// that cannot check must not answer, so commands surface it rather than
	// rendering the run as ordinary.
	PresenceErr error
}

func NewFakeQueryScanRuns() *FakeQueryScanRuns {
	return &FakeQueryScanRuns{runs: make(map[string]vulndomain.WalkScanRun)}
}

// MarkWalkAbsent seeds a walk id as purged from the store, so the runs naming it
// are the dangling ones.
func (f *FakeQueryScanRuns) MarkWalkAbsent(walkID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.AbsentWalks == nil {
		f.AbsentWalks = make(map[string]bool)
	}
	f.AbsentWalks[walkID] = true
}

// UnresolvedWalks names the walks among runs that this fake reports as absent.
func (f *FakeQueryScanRuns) UnresolvedWalks(
	_ context.Context, runs []vulndomain.WalkScanRun,
) (map[string]bool, error) {
	if f.PresenceErr != nil {
		return nil, f.PresenceErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]bool)
	for _, r := range runs {
		if f.AbsentWalks[r.WalkID] {
			out[r.WalkID] = true
		}
	}
	return out, nil
}

// WalkPresent reports whether walkID is still held.
func (f *FakeQueryScanRuns) WalkPresent(_ context.Context, walkID string) (bool, error) {
	if f.PresenceErr != nil {
		return false, f.PresenceErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return !f.AbsentWalks[walkID], nil
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

// ListRunsForWalk returns the seeded runs for walkID. ListErr is returned
// ALONGSIDE them, not instead of them: the real store reports the rows it could
// not verify while still handing back the ones it could, and a fake that
// withheld them would let a survey command pass a test it fails in production.
func (f *FakeQueryScanRuns) ListRunsForWalk(_ context.Context, walkID string) ([]vulndomain.WalkScanRun, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ListCalls++
	var out []vulndomain.WalkScanRun
	for _, r := range f.allRuns {
		if r.WalkID == walkID {
			out = append(out, r)
		}
	}
	return out, f.ListErr
}

// ListAllRuns returns every seeded run, on the same partial-result terms as
// ListRunsForWalk.
func (f *FakeQueryScanRuns) ListAllRuns(_ context.Context) ([]vulndomain.WalkScanRun, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ListCalls++
	return f.allRuns, f.ListErr
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
