package cli

import (
	"context"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	callgraphdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	configdomain "github.com/eitanity/kanonarion/internal/config/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
	directivedomain "github.com/eitanity/kanonarion/internal/directive/domain"
	exapp "github.com/eitanity/kanonarion/internal/example/application"
	exampledomain "github.com/eitanity/kanonarion/internal/example/domain"
	exampleports "github.com/eitanity/kanonarion/internal/example/ports"
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

// --- fetch context ---

// FetchModuleUseCase is the interface for executing a module fetch.
type FetchModuleUseCase interface {
	Execute(ctx context.Context, req fetchapp.FetchRequest) (fetchapp.FetchResult, error)
}

// QueryFetchUseCase is the interface for querying fetch records.
type QueryFetchUseCase interface {
	GetFetchRecord(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (fetchdomain.FactRecord, bool, error)
}

// --- walk context ---

// ExecuteWalkUseCase is the interface for running a dependency walk.
type ExecuteWalkUseCase interface {
	Execute(ctx context.Context, req walkapp.WalkRequest) (walkapp.ExecuteWalkResult, error)
}

// QueryWalksUseCase is the interface for querying walk records.
type QueryWalksUseCase interface {
	GetWalk(ctx context.Context, id string) (walkdomain.WalkRecord, error)
	ListWalks(ctx context.Context, filter walkports.WalkFilter) ([]walkports.WalkSummary, error)
}

// DiffWalksUseCase is the interface for diffing two walk records.
type DiffWalksUseCase interface {
	Diff(ctx context.Context, idA, idB string) (walkapp.WalkDiff, error)
}

// --- extract context ---

// ExtractUseCase is the interface for running extraction stages.
type ExtractUseCase interface {
	Execute(ctx context.Context, req extractapp.ExtractRequest) (extractdomain.ExtractionRun, error)
}

// QueryExtractionUseCase is the interface for querying extraction runs.
type QueryExtractionUseCase interface {
	GetExtractionRun(ctx context.Context, id string) (extractdomain.ExtractionRun, error)
	ListExtractionRuns(ctx context.Context, filter extractports.ExtractionRunFilter) ([]extractports.ExtractionRunSummary, error)
}

// --- license context ---

// ExtractLicenseUseCase is the interface for extracting license information.
type ExtractLicenseUseCase interface {
	Execute(ctx context.Context, req licapp.ExtractRequest) (licapp.ExtractResult, error)
	GetLicenseStore() licenseports.LicenseStore
}

// QueryLicenseUseCase is the interface for querying license records.
type QueryLicenseUseCase interface {
	GetLicenseRecord(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (licensedomain.LicenseRecord, bool, error)
	ListLicenseRecords(ctx context.Context, filter licenseports.LicenseFilter) ([]licenseports.LicenseSummary, error)
	ResolveForWalk(ctx context.Context, walkID string, target coordinate.ModuleCoordinate, extractFn func(context.Context, coordinate.ModuleCoordinate) (licensedomain.LicenseRecord, error)) ([]licapp.DepLicenseResult, error)
}

// GenerateNoticeUseCase is the interface for generating THIRD-PARTY-LICENSES attribution documents.
type GenerateNoticeUseCase interface {
	Generate(ctx context.Context, req licapp.NoticeRequest) (licapp.NoticeResult, error)
}

// CheckCompatibilityUseCase is the interface for the license compatibility engine.
type CheckCompatibilityUseCase interface {
	CheckCompatibilityForWalk(ctx context.Context, walkID string, root coordinate.ModuleCoordinate, targetSPDX string) (licensedomain.ClosureCompatibilityReport, error)
}

// DiffLicenseUseCase is the interface for diffing two stored license records.
type DiffLicenseUseCase interface {
	Diff(ctx context.Context, coordA, coordB coordinate.ModuleCoordinate) (licensedomain.LicenseDiff, error)
}

// QueryDirectivesUseCase is the interface for reading stored directive scans.
type QueryDirectivesUseCase interface {
	GetScan(ctx context.Context, scanID string) (directivedomain.Record, bool, error)
	ListScans(ctx context.Context, projectModulePath string, limit int) ([]directivedomain.Record, error)
}

// DiffDirectivesUseCase is the interface for diffing two directive scans.
type DiffDirectivesUseCase interface {
	Diff(ctx context.Context, scanIDA, scanIDB string) (directivedomain.DirectiveDiff, error)
}

// --- iface context ---

// ExtractInterfaceUseCase is the interface for extracting module interfaces.
type ExtractInterfaceUseCase interface {
	Execute(ctx context.Context, req ifaceapp.ExtractRequest) (ifaceapp.ExtractResult, error)
}

// QueryInterfaceUseCase is the interface for querying interface records.
type QueryInterfaceUseCase interface {
	GetInterfaceRecord(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (ifacedomain.InterfaceRecord, bool, error)
	ListInterfaceRecords(ctx context.Context, filter ifaceports.InterfaceFilter) ([]ifaceports.InterfaceSummary, error)
	FindSymbol(ctx context.Context, symbolName, pipelineVersion string) ([]ifaceports.SymbolRef, error)
}

// --- callgraph context ---

// ExtractCallGraphUseCase is the interface for extracting call graphs.
type ExtractCallGraphUseCase interface {
	Execute(ctx context.Context, req cgapp.ExtractRequest) (cgapp.ExtractResult, error)
}

// ExtractLocalCallGraphUseCase is the interface for extracting the call
// graph of a local working tree.
type ExtractLocalCallGraphUseCase interface {
	Execute(ctx context.Context, req cgapp.LocalExtractRequest) (cgapp.ExtractResult, error)
}

// QueryCallGraphUseCase is the interface for querying call graph records.
type QueryCallGraphUseCase interface {
	GetCallGraphRecord(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (callgraphdomain.CallGraphRecord, bool, error)
	ListCallGraphRecords(ctx context.Context, filter cgports.CallGraphFilter) ([]cgports.CallGraphSummary, error)
	FindCallers(ctx context.Context, symbolID, pipelineVersion string) ([]cgports.CallEdgeRef, error)
	FindCallees(ctx context.Context, symbolID, pipelineVersion string) ([]cgports.CallEdgeRef, error)
	TraverseCallers(ctx context.Context, symbolID, pipelineVersion string, maxDepth int) (edges []cgports.CallEdgeRef, nodes []string, err error)
	TraverseCallees(ctx context.Context, symbolID, pipelineVersion string, maxDepth int) (edges []cgports.CallEdgeRef, nodes []string, err error)
}

// --- example context ---

// ExtractExampleUseCase is the interface for extracting examples.
type ExtractExampleUseCase interface {
	Execute(ctx context.Context, req exapp.ExtractRequest) (exapp.ExtractResult, error)
}

// QueryExamplesUseCase is the interface for querying example records.
type QueryExamplesUseCase interface {
	GetExampleRecord(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (exampledomain.ExampleRecord, bool, error)
	ListExampleRecords(ctx context.Context, filter exampleports.ExampleFilter) ([]exampleports.ExampleSummary, error)
	FindBySymbol(ctx context.Context, symbol, pipelineVersion string) ([]exampleports.ExampleRef, error)
	FindBySymbolInModule(ctx context.Context, coord coordinate.ModuleCoordinate, symbol, pipelineVersion string) ([]exampleports.ExampleRef, error)
}

// --- vuln context ---

// ScanModuleUseCase is the interface for scanning a single module.
type ScanModuleUseCase interface {
	Scan(ctx context.Context, params vulnapp.ScanModuleParams) (vulndomain.VulnerabilityRecord, error)
}

// ScanWalkUseCase is the interface for scanning a full walk.
type ScanWalkUseCase interface {
	Scan(ctx context.Context, params vulnapp.ScanWalkParams) (vulndomain.WalkScanRun, error)
}

// RescanWalkUseCase is the interface for re-gating a walk against a new snapshot.
type RescanWalkUseCase interface {
	Rescan(ctx context.Context, req vulnapp.RescanRequest) (vulndomain.WalkScanRun, error)
}

// QueryVulnUseCase is the interface for querying vulnerability records.
type QueryVulnUseCase interface {
	GetRecord(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string, snapshot vulndomain.DatabaseSnapshot) (vulndomain.VulnerabilityRecord, bool, error)
	GetLatestRecord(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (vulndomain.VulnerabilityRecord, bool, error)
	GetLatestRecordForWalk(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string, walkID string) (vulndomain.VulnerabilityRecord, bool, error)
	ListRecordsForModule(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) ([]vulndomain.VulnerabilityRecord, error)
	ListRecordsByFindingID(ctx context.Context, findingID string) ([]vulndomain.VulnerabilityRecord, error)
}

// QueryScanRunsUseCase is the interface for querying scan runs and snapshots.
type QueryScanRunsUseCase interface {
	GetRun(ctx context.Context, id string) (vulndomain.WalkScanRun, bool, error)
	ListRunsForWalk(ctx context.Context, walkID string) ([]vulndomain.WalkScanRun, error)
	ListAllRuns(ctx context.Context) ([]vulndomain.WalkScanRun, error)
	ListSnapshots(ctx context.Context) ([]vulndomain.DatabaseSnapshot, error)
	GetLatestSnapshot(ctx context.Context) (vulndomain.DatabaseSnapshot, bool, error)
}

// DiffScanRunsUseCase is the interface for diffing two scan runs.
type DiffScanRunsUseCase interface {
	Diff(ctx context.Context, runIDA, runIDB string) (vulndomain.ScanRunDiff, error)
}

// --- sbom context ---

// GenerateSBOMUseCase is the interface for generating SBOMs.
type GenerateSBOMUseCase interface {
	Generate(ctx context.Context, req sbomapp.SBOMRequest) (sbomdomain.SBOMRecord, error)
}

// QuerySBOMUseCase is the interface for querying SBOM records.
type QuerySBOMUseCase interface {
	GetSBOMRecord(ctx context.Context, id string) (sbomdomain.SBOMRecord, error)
	ListSBOMRecords(ctx context.Context, walkID string) ([]sbomdomain.SBOMRecord, error)
}

// --- fips context ---

// ExtractFIPSUseCase is the interface for running a FIPS assessment.
type ExtractFIPSUseCase interface {
	Extract(ctx context.Context, goModPath string, policy configdomain.FIPSPolicy) (fipsdomain.Record, error)
}

// QueryFIPSUseCase is the interface for querying stored FIPS records.
type QueryFIPSUseCase interface {
	Get(ctx context.Context, projectModulePath string) (fipsdomain.Record, bool, error)
}
