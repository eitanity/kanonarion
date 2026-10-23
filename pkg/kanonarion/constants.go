package kanonarion

import (
	"github.com/eitanity/kanonarion/internal/audit"
	callgraphdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	configdomain "github.com/eitanity/kanonarion/internal/config/domain"
	directivedomain "github.com/eitanity/kanonarion/internal/directive/domain"
	exampledomain "github.com/eitanity/kanonarion/internal/example/domain"
	extractdomain "github.com/eitanity/kanonarion/internal/extract/domain"
	"github.com/eitanity/kanonarion/internal/failurecause"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	fipsdomain "github.com/eitanity/kanonarion/internal/fips/domain"
	godebugdomain "github.com/eitanity/kanonarion/internal/godebug/domain"
	"github.com/eitanity/kanonarion/internal/gotoolchain"
	ifacedomain "github.com/eitanity/kanonarion/internal/iface/domain"
	licensedomain "github.com/eitanity/kanonarion/internal/license/domain"
	nativedomain "github.com/eitanity/kanonarion/internal/native/domain"
	sbomdomain "github.com/eitanity/kanonarion/internal/sbom/domain"
	stdlibdomain "github.com/eitanity/kanonarion/internal/stdlib/domain"
	vendordomain "github.com/eitanity/kanonarion/internal/vendortree/domain"
	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// Values of the published enumeration types. A store in another module decodes
// records into these types, so it needs every value the internal package
// defines; TestPublishedPortsNameOnlyPublishedTypes keeps the set complete.

// The values of AnalyserProvenance, as the internal package defines them.
//
// Stability: supporting constants of the AnalyserProvenance type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	AnalyserInferred             = callgraphdomain.AnalyserInferred
	AnalyserObserved             = callgraphdomain.AnalyserObserved
	AnalyserProvenanceUnrecorded = callgraphdomain.AnalyserProvenanceUnrecorded
)

// The values of AnalyserVersion, as the internal package defines them.
//
// Stability: supporting constants of the AnalyserVersion type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	AnalyserVersionUnrecorded = callgraphdomain.AnalyserUnrecorded
)

// The values of AnalysisSource, as the internal package defines them.
//
// Stability: supporting constants of the AnalysisSource type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	AnalysisSourceModuleZip       = callgraphdomain.AnalysisSourceModuleZip
	AnalysisSourceToolchainSource = callgraphdomain.AnalysisSourceToolchainSource
	AnalysisSourceUnrecorded      = callgraphdomain.AnalysisSourceUnrecorded
	AnalysisSourceWorktree        = callgraphdomain.AnalysisSourceWorktree
)

// The values of AnalysisSurface, as the internal package defines them.
//
// Stability: supporting constants of the AnalysisSurface type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	AnalysisSurfaceFetched  = vulndomain.AnalysisSurfaceFetched
	AnalysisSurfaceVendored = vulndomain.AnalysisSurfaceVendored
)

// The values of ArtifactKind, as the internal package defines them.
//
// Stability: supporting constants of the ArtifactKind type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	ArtifactApplication    = callgraphdomain.ArtifactApplication
	ArtifactLibrary        = callgraphdomain.ArtifactLibrary
	ArtifactNotEstablished = callgraphdomain.ArtifactNotEstablished
)

// The values of AuditEventType, as the internal package defines them.
//
// Stability: supporting constants of the AuditEventType type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	AuditEventAdvisorySnapshotRecorded = audit.EventAdvisorySnapshotRecorded
	AuditEventCallGraphExtracted       = audit.EventCallGraphExtracted
	AuditEventExamplesExtracted        = audit.EventExamplesExtracted
	AuditEventExcludeDirectiveObserved = audit.EventExcludeDirectiveObserved
	AuditEventExtractionRunCompleted   = audit.EventExtractionRunCompleted
	AuditEventFIPSAssessment           = audit.EventFIPSAssessment
	AuditEventFactRecordDowngraded     = audit.EventFactRecordDowngraded
	AuditEventFactRecordWriteRefused   = audit.EventFactRecordWriteRefused
	AuditEventFactRecordWritten        = audit.EventFactRecordWritten
	AuditEventGoDebugSettingObserved   = audit.EventGoDebugSettingObserved
	AuditEventInterfaceExtracted       = audit.EventInterfaceExtracted
	AuditEventLicenseExtracted         = audit.EventLicenseExtracted
	AuditEventNativeComponentsRecorded = audit.EventNativeComponentsRecorded
	AuditEventRecordReadVerified       = audit.EventRecordReadVerified
	AuditEventReplaceDirectiveObserved = audit.EventReplaceDirectiveObserved
	AuditEventSBOMGenerated            = audit.EventSBOMGenerated
	AuditEventSBOMServed               = audit.EventSBOMServed
	AuditEventStdlibCustodyRecorded    = audit.EventStdlibCustodyRecorded
	AuditEventVendorTreeGenerated      = audit.EventVendorTreeGenerated
	AuditEventVerificationFailed       = audit.EventVerificationFailed
	AuditEventVulnFindingObserved      = audit.EventVulnFindingObserved
	AuditEventVulnScanCompleted        = audit.EventVulnScanCompleted
	AuditEventVulnScanServed           = audit.EventVulnScanServed
	AuditEventWalkCompleted            = audit.EventWalkCompleted
)

// The values of CallGraphAlgorithm, as the internal package defines them.
//
// Stability: supporting constants of the CallGraphAlgorithm type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	CallGraphAlgorithmCHA    = callgraphdomain.AlgorithmCHA
	CallGraphAlgorithmRTA    = callgraphdomain.AlgorithmRTA
	CallGraphAlgorithmStatic = callgraphdomain.AlgorithmStatic
)

// The values of CallGraphStatus, as the internal package defines them.
//
// Stability: supporting constants of the CallGraphStatus type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	CallGraphStatusCancelled        = callgraphdomain.CallGraphStatusCancelled
	CallGraphStatusExcludedByConfig = callgraphdomain.CallGraphStatusExcludedByConfig
	CallGraphStatusExtracted        = callgraphdomain.CallGraphStatusExtracted
	CallGraphStatusExtractionFailed = callgraphdomain.CallGraphStatusExtractionFailed
	CallGraphStatusLoadFailed       = callgraphdomain.CallGraphStatusLoadFailed
	CallGraphStatusOutOfMemory      = callgraphdomain.CallGraphStatusOutOfMemory
	CallGraphStatusPartial          = callgraphdomain.CallGraphStatusPartial
	CallGraphStatusUnknown          = callgraphdomain.CallGraphStatusUnknown
)

// The values of ChainOfTitleConfidence, as the internal package defines them.
//
// Stability: supporting constants of the ChainOfTitleConfidence type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	ChainOfTitleHigh        = licensedomain.ChainOfTitleHigh
	ChainOfTitleLow         = licensedomain.ChainOfTitleLow
	ChainOfTitleMedium      = licensedomain.ChainOfTitleMedium
	ChainOfTitleNotAnalysed = licensedomain.ChainOfTitleNotAnalysed
)

// The values of CompletenessLevel, as the internal package defines them.
//
// Stability: supporting constants of the CompletenessLevel type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	CompletenessBuiltWithBodies = callgraphdomain.CompletenessBuiltWithBodies
	CompletenessFailed          = callgraphdomain.CompletenessFailed
	CompletenessMetadataOnly    = callgraphdomain.CompletenessMetadataOnly
	CompletenessTypeOnly        = callgraphdomain.CompletenessTypeOnly
	CompletenessUnknown         = callgraphdomain.CompletenessUnknown
)

// The values of CopyrightStatus, as the internal package defines them.
//
// Stability: supporting constants of the CopyrightStatus type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	CopyrightStatusExtractionFailed = licensedomain.CopyrightStatusExtractionFailed
	CopyrightStatusFound            = licensedomain.CopyrightStatusFound
	CopyrightStatusNoneFound        = licensedomain.CopyrightStatusNoneFound
	CopyrightStatusNotAnalysed      = licensedomain.CopyrightStatusNotAnalysed
)

// The values of CoverageStatus, as the internal package defines them.
//
// Stability: supporting constants of the CoverageStatus type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	CoverageComplete = vulndomain.CoverageComplete
	CoverageFailed   = vulndomain.CoverageFailed
	CoveragePartial  = vulndomain.CoveragePartial
)

// The values of DirectiveKind, as the internal package defines them.
//
// Stability: supporting constants of the DirectiveKind type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	DirectiveKindExclude = directivedomain.KindExclude
	DirectiveKindReplace = directivedomain.KindReplace
)

// The values of DispatchKind, as the internal package defines them.
//
// Stability: supporting constants of the DispatchKind type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	DispatchDirect       = vulndomain.DispatchDirect
	DispatchFramework    = vulndomain.DispatchFramework
	DispatchInterface    = vulndomain.DispatchInterface
	DispatchNotAnnotated = vulndomain.DispatchNotAnnotated
	DispatchReference    = vulndomain.DispatchReference
	DispatchReflect      = vulndomain.DispatchReflect
	DispatchRouteEntry   = vulndomain.DispatchRouteEntry
	DispatchUnrecorded   = vulndomain.DispatchUnrecorded
	DispatchUnresolved   = vulndomain.DispatchUnresolved
)

// The values of EdgeConfidence, as the internal package defines them.
//
// Stability: supporting constants of the EdgeConfidence type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	EdgeConfidenceCHAOverapprox = callgraphdomain.ConfidenceCHAOverapprox
	EdgeConfidenceDirect        = callgraphdomain.ConfidenceDirect
	EdgeConfidenceFramework     = callgraphdomain.ConfidenceFramework
	EdgeConfidenceUnknown       = callgraphdomain.ConfidenceUnknown
	EdgeConfidenceVTA           = callgraphdomain.ConfidenceVTA
)

// The values of EdgeKind, as the internal package defines them.
//
// Stability: supporting constants of the EdgeKind type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	EdgeKindCall             = callgraphdomain.EdgeKindCall
	EdgeKindCompilerInserted = callgraphdomain.EdgeKindCompilerInserted
	EdgeKindLinkname         = callgraphdomain.EdgeKindLinkname
	EdgeKindReference        = callgraphdomain.EdgeKindReference
)

// The values of ExampleStatus, as the internal package defines them.
//
// Stability: supporting constants of the ExampleStatus type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	ExampleStatusCancelled        = exampledomain.ExampleStatusCancelled
	ExampleStatusExtractionFailed = exampledomain.ExampleStatusExtractionFailed
	ExampleStatusFound            = exampledomain.ExampleStatusFound
	ExampleStatusNone             = exampledomain.ExampleStatusNone
	ExampleStatusUnknown          = exampledomain.ExampleStatusUnknown
)

// The values of ExportKind, as the internal package defines them.
//
// Stability: supporting constants of the ExportKind type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	ExportC         = callgraphdomain.ExportC
	ExportInterrupt = callgraphdomain.ExportInterrupt
	ExportWasm      = callgraphdomain.ExportWasm
)

// The values of HandlerKind, as the internal package defines them.
//
// Stability: supporting constants of the HandlerKind type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	HandlerInterruptNew = callgraphdomain.HandlerInterruptNew
)

// The values of ExtractionRunStatus, as the internal package defines them.
//
// Stability: supporting constants of the ExtractionRunStatus type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	ExtractionRunCancelled  = extractdomain.ExtractionRunCancelled
	ExtractionRunFailed     = extractdomain.ExtractionRunFailed
	ExtractionRunInProgress = extractdomain.ExtractionRunInProgress
	ExtractionRunPartial    = extractdomain.ExtractionRunPartial
	ExtractionRunSucceeded  = extractdomain.ExtractionRunSucceeded
)

// The values of FIPSCategory, as the internal package defines them.
//
// Stability: supporting constants of the FIPSCategory type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	FIPSCategoryCompliant = fipsdomain.CategoryCompliant
	FIPSCategoryDeviation = fipsdomain.CategoryDeviation
	FIPSCategoryUnknown   = fipsdomain.CategoryUnknown
)

// The values of FIPSFindingKind, as the internal package defines them.
//
// Stability: supporting constants of the FIPSFindingKind type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	FIPSFindingAlgorithm    = fipsdomain.FindingAlgorithm
	FIPSFindingCgoCrypto    = fipsdomain.FindingCgoCrypto
	FIPSFindingDirectRandom = fipsdomain.FindingDirectRandom
	FIPSFindingToolchain    = fipsdomain.FindingToolchain
)

// The values of FailureCause, as the internal package defines them.
//
// Stability: supporting constants of the FailureCause type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	FailureCauseEnvironment = failurecause.Environment
	FailureCauseModule      = failurecause.Module
	FailureCauseUnrecorded  = failurecause.Unrecorded
)

// The values of FindingsStatus, as the internal package defines them.
//
// Stability: supporting constants of the FindingsStatus type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	FindingsAffected     = vulndomain.FindingsAffected
	FindingsClean        = vulndomain.FindingsClean
	FindingsInconclusive = vulndomain.FindingsInconclusive
)

// The values of GateOutcome, as the internal package defines them.
//
// Stability: supporting constants of the GateOutcome type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	GateOutcomeBypassed   = callgraphdomain.GateOutcomeBypassed
	GateOutcomeConsulted  = callgraphdomain.GateOutcomeConsulted
	GateOutcomeUnrecorded = callgraphdomain.GateOutcomeUnrecorded
)

// The values of GoDebugTier, as the internal package defines them.
//
// Stability: supporting constants of the GoDebugTier type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	GoDebugTierAmber   = godebugdomain.TierAmber
	GoDebugTierGreen   = godebugdomain.TierGreen
	GoDebugTierRed     = godebugdomain.TierRed
	GoDebugTierUnknown = godebugdomain.TierUnknown
)

// The values of InterfaceStatus, as the internal package defines them.
//
// Stability: supporting constants of the InterfaceStatus type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	InterfaceStatusCancelled        = ifacedomain.InterfaceStatusCancelled
	InterfaceStatusExtracted        = ifacedomain.InterfaceStatusExtracted
	InterfaceStatusExtractionFailed = ifacedomain.InterfaceStatusExtractionFailed
	InterfaceStatusPartial          = ifacedomain.InterfaceStatusPartial
	InterfaceStatusUnknown          = ifacedomain.InterfaceStatusUnknown
)

// The values of InterfaceTypeKind, as the internal package defines them.
//
// Stability: supporting constants of the InterfaceTypeKind type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	InterfaceTypeKindAlias     = ifacedomain.TypeKindAlias
	InterfaceTypeKindDefined   = ifacedomain.TypeKindDefined
	InterfaceTypeKindGeneric   = ifacedomain.TypeKindGeneric
	InterfaceTypeKindInterface = ifacedomain.TypeKindInterface
	InterfaceTypeKindStruct    = ifacedomain.TypeKindStruct
	InterfaceTypeKindUnknown   = ifacedomain.TypeKindUnknown
)

// The values of LegProvenance, as the internal package defines them.
//
// Stability: supporting constants of the LegProvenance type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	LegAbsent        = fetchdomain.LegAbsent
	LegInherited     = fetchdomain.LegInherited
	LegRechecked     = fetchdomain.LegRechecked
	LegUnavailable   = fetchdomain.LegUnavailable
	LegPrivateModule = fetchdomain.LegPrivateModule
)

// The values of LicenseCoverage, as the internal package defines them.
//
// Stability: supporting constants of the LicenseCoverage type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	LicenseCoverageAttributionOnly  = licensedomain.CoverageAttributionOnly
	LicenseCoverageBundledComponent = licensedomain.CoverageBundledComponent
	LicenseCoverageDocumentation    = licensedomain.CoverageDocumentation
	LicenseCoverageModuleCode       = licensedomain.CoverageModuleCode
	LicenseCoverageNotDetermined    = licensedomain.CoverageNotDetermined
)

// The values of LicenseStatus, as the internal package defines them.
//
// Stability: supporting constants of the LicenseStatus type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	LicenceStatusAmbiguous        = licensedomain.LicenceStatusAmbiguous
	LicenceStatusUnknown          = licensedomain.LicenceStatusUnknown
	LicenseStatusCancelled        = licensedomain.LicenseStatusCancelled
	LicenseStatusDetected         = licensedomain.LicenseStatusDetected
	LicenseStatusExtractionFailed = licensedomain.LicenseStatusExtractionFailed
	LicenseStatusMultiple         = licensedomain.LicenseStatusMultiple
	LicenseStatusNone             = licensedomain.LicenseStatusNone
	LicenseStatusPerFile          = licensedomain.LicenseStatusPerFile
	LicenseStatusUnclassified     = licensedomain.LicenseStatusUnclassified
)

// The values of NativeConfidence, as the internal package defines them.
//
// Stability: supporting constants of the NativeConfidence type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	NativeConfidenceDeclared = nativedomain.ConfidenceDeclared
)

// The values of NativeLinkedLibraryKind, as the internal package defines them.
//
// Stability: supporting constants of the NativeLinkedLibraryKind type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	NativeLinkedLibraryExternal = nativedomain.LinkedLibraryExternal
	NativeLinkedLibrarySystem   = nativedomain.LinkedLibrarySystem
)

// The values of NativePresence, as the internal package defines them.
//
// Stability: supporting constants of the NativePresence type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	NativePresenceAbsent           = nativedomain.PresenceAbsent
	NativePresenceIdentified       = nativedomain.PresenceIdentified
	NativePresenceLinkedNotShipped = nativedomain.PresenceLinkedNotShipped
	NativePresenceUnidentified     = nativedomain.PresenceUnidentified
)

// The values of NodeStatus, as the internal package defines them.
//
// Stability: supporting constants of the NodeStatus type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	NodeFetchFailed   = walkdomain.NodeFetchFailed
	NodeInternalPanic = walkdomain.NodeInternalPanic
	NodeLocalReplace  = walkdomain.NodeLocalReplace
	NodeSucceeded     = walkdomain.NodeSucceeded
)

// The values of PolicyOutcome, as the internal package defines them.
//
// Stability: supporting constants of the PolicyOutcome type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	PolicyOutcomeAllow       = configdomain.PolicyOutcomeAllow
	PolicyOutcomeNotify      = configdomain.PolicyOutcomeNotify
	PolicyOutcomeUnevaluated = configdomain.PolicyOutcomeUnevaluated
	PolicyOutcomeWarn        = configdomain.PolicyOutcomeWarn
)

// The values of ProvenanceSignal, as the internal package defines them.
//
// Stability: supporting constants of the ProvenanceSignal type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	ProvenanceSignalAuthorsFile      = licensedomain.ProvenanceSignalAuthorsFile
	ProvenanceSignalCLARequired      = licensedomain.ProvenanceSignalCLARequired
	ProvenanceSignalContributorsFile = licensedomain.ProvenanceSignalContributorsFile
	ProvenanceSignalDCORequired      = licensedomain.ProvenanceSignalDCORequired
	ProvenanceSignalInboundOutbound  = licensedomain.ProvenanceSignalInboundOutbound
	ProvenanceSignalPatentsFile      = licensedomain.ProvenanceSignalPatentsFile
)

// The values of ReachabilityConfidence, as the internal package defines them.
//
// Stability: supporting constants of the ReachabilityConfidence type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	ReachabilityConfidenceHigh    = vulndomain.ConfidenceHigh
	ReachabilityConfidenceLow     = vulndomain.ConfidenceLow
	ReachabilityConfidenceMedium  = vulndomain.ConfidenceMedium
	ReachabilityConfidenceUnknown = vulndomain.ConfidenceUnknown
)

// The values of ReachabilityInstrument, as the internal package defines them.
//
// Stability: supporting constants of the ReachabilityInstrument type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	ReachabilityInstrumentCallGraphBFS = vulndomain.AnalyserCallGraphBFS
	ReachabilityInstrumentGovulncheck  = vulndomain.AnalyserGovulncheck
	ReachabilityInstrumentUnrecorded   = vulndomain.AnalyserUnrecorded
)

// The values of RecordCoverageStatus, as the internal package defines them.
//
// Stability: supporting constants of the RecordCoverageStatus type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	RecordCoverageAnalysed    = vulndomain.CoverageAnalysed
	RecordCoverageFailedScan  = vulndomain.CoverageFailedScan
	RecordCoverageUnscannable = vulndomain.CoverageUnscannable
)

// The values of RecordFindingsStatus, as the internal package defines them.
//
// Stability: supporting constants of the RecordFindingsStatus type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	FindingsRecordAffected     = vulndomain.FindingsRecordAffected
	FindingsRecordClean        = vulndomain.FindingsRecordClean
	FindingsRecordInconclusive = vulndomain.FindingsRecordInconclusive
	FindingsRecordWithdrawn    = vulndomain.FindingsRecordWithdrawn
)

// The values of ReferenceScope, as the internal package defines them.
//
// Stability: supporting constants of the ReferenceScope type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	ReferenceScopeAnalysed = callgraphdomain.ReferenceScopeAnalysed
	ReferenceScopeUnknown  = callgraphdomain.ReferenceScopeUnknown
)

// The values of ResolutionSource, as the internal package defines them.
//
// Stability: supporting constants of the ResolutionSource type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	ResolutionDepthBounded         = walkdomain.ResolutionDepthBounded
	ResolutionFetchFailed          = walkdomain.ResolutionFetchFailed
	ResolutionLocalAnalysed        = walkdomain.ResolutionLocalAnalysed
	ResolutionLocalMainModule      = walkdomain.ResolutionLocalMainModule
	ResolutionLocalReplace         = walkdomain.ResolutionLocalReplace
	ResolutionLocalWorkspaceMember = walkdomain.ResolutionLocalWorkspaceMember
	ResolutionMVS                  = walkdomain.ResolutionMVS
	ResolutionParseFailed          = walkdomain.ResolutionParseFailed
	ResolutionReplace              = walkdomain.ResolutionReplace
	ResolutionStdlib               = walkdomain.ResolutionStdlib
	ResolutionTarget               = walkdomain.ResolutionTarget
	ResolutionTinyGo               = walkdomain.ResolutionTinyGo
)

// The values of TinyGoAnchor, as the internal package defines them.
//
// Stability: supporting constants of the TinyGoAnchor type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	TinyGoAnchorModule  = walkdomain.TinyGoAnchorModule
	TinyGoAnchorRelease = walkdomain.TinyGoAnchorRelease
)

// The values of TinyGoReleaseOutcome, as the internal package defines them.
//
// Stability: supporting constants of the TinyGoReleaseOutcome type; unstable
// pre-v1. Values may be added within a major version; treat an unrecognised
// value conservatively (§4).
const (
	TinyGoReleaseAssetAbsent    = walkdomain.TinyGoReleaseAssetAbsent
	TinyGoReleaseDigestMatched  = walkdomain.TinyGoReleaseDigestMatched
	TinyGoReleaseDigestMismatch = walkdomain.TinyGoReleaseDigestMismatch
	TinyGoReleaseNoDigest       = walkdomain.TinyGoReleaseNoDigest
	TinyGoReleaseUnavailable    = walkdomain.TinyGoReleaseUnavailable
)

// The values of ReuseGate, as the internal package defines them.
//
// Stability: supporting constants of the ReuseGate type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	ReuseGateLedger     = callgraphdomain.ReuseGateLedger
	ReuseGateUnrecorded = callgraphdomain.ReuseGateUnrecorded
	ReuseGateWorktree   = callgraphdomain.ReuseGateWorktree
)

// The values of RiskClass, as the internal package defines them.
//
// Stability: supporting constants of the RiskClass type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	RiskHigh    = directivedomain.RiskHigh
	RiskHighest = directivedomain.RiskHighest
	RiskLow     = directivedomain.RiskLow
	RiskMedium  = directivedomain.RiskMedium
	RiskUnknown = directivedomain.RiskUnknown
)

// The values of SBOMFormat, as the internal package defines them.
//
// Stability: supporting constants of the SBOMFormat type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	SBOMFormatCycloneDX16 = sbomdomain.CycloneDX16
)

// The values of StageStatus, as the internal package defines them.
//
// Stability: supporting constants of the StageStatus type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	StageFailed    = extractdomain.StageFailed
	StageSkipped   = extractdomain.StageSkipped
	StageSucceeded = extractdomain.StageSucceeded
)

// The values of StdlibAcquisitionRoute, as the internal package defines them.
//
// Stability: supporting constants of the StdlibAcquisitionRoute type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	StdlibRouteGoDev          = stdlibdomain.RouteGoDev
	StdlibRouteLocalToolchain = stdlibdomain.RouteLocalToolchain
	StdlibRouteUnrecorded     = stdlibdomain.RouteUnrecorded
)

// The values of StdlibVerificationStatus, as the internal package defines them.
//
// Stability: supporting constants of the StdlibVerificationStatus type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	GoDevChecksumMismatch       = stdlibdomain.GoDevChecksumMismatch
	UnverifiedGoDevNotPublished = stdlibdomain.UnverifiedGoDevNotPublished
	UnverifiedGoDevUnavailable  = stdlibdomain.UnverifiedGoDevUnavailable
	VerifiedGoDevChecksum       = stdlibdomain.VerifiedGoDevChecksum
	VerifiedLocalToolchain      = stdlibdomain.VerifiedLocalToolchain
)

// The values of SubjectKind, as the internal package defines them.
//
// Stability: supporting constants of the SubjectKind type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	SubjectBlob = fetchdomain.SubjectBlob
	SubjectFact = fetchdomain.SubjectFact
)

// The values of SumDBUnavailability, as the internal package defines them.
//
// Stability: supporting constants of the SumDBUnavailability type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	SumDBUnavailabilityFailure = fetchports.SumDBUnavailabilityFailure
	SumDBUnavailabilityNone    = fetchports.SumDBUnavailabilityNone
	SumDBUnavailabilityPolicy  = fetchports.SumDBUnavailabilityPolicy
)

// The values of TestScope, as the internal package defines them.
//
// Stability: supporting constants of the TestScope type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	TestScopeAnalysed = callgraphdomain.TestScopeAnalysed
	TestScopeExcluded = callgraphdomain.TestScopeExcluded
	TestScopeUnknown  = callgraphdomain.TestScopeUnknown
)

// The values of ToolchainVersion, as the internal package defines them.
//
// Stability: supporting constants of the ToolchainVersion type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	ToolchainVersionUnrecorded = gotoolchain.Unrecorded
)

// The values of UnknownLicensePolicy, as the internal package defines them.
//
// Stability: supporting constants of the UnknownLicensePolicy type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	UnknownLicenseAllow  = configdomain.UnknownLicenseAllow
	UnknownLicenseBlock  = configdomain.UnknownLicenseBlock
	UnknownLicenseNotify = configdomain.UnknownLicenseNotify
	UnknownLicenseWarn   = configdomain.UnknownLicenseWarn
)

// The values of UnscanReason, as the internal package defines them.
//
// Stability: supporting constants of the UnscanReason type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	UnscanReasonAbsentFromVendor                = vulndomain.UnscanReasonAbsentFromVendor
	UnscanReasonBuildIncompatible               = vulndomain.UnscanReasonBuildIncompatible
	UnscanReasonCHeadersMissing                 = vulndomain.UnscanReasonCHeadersMissing
	UnscanReasonGeneratedAssets                 = vulndomain.UnscanReasonGeneratedAssets
	UnscanReasonGoModOnly                       = vulndomain.UnscanReasonGoModOnly
	UnscanReasonGoWorkMonorepo                  = vulndomain.UnscanReasonGoWorkMonorepo
	UnscanReasonIncompleteScanCache             = vulndomain.UnscanReasonIncompleteScanCache
	UnscanReasonLocalProjectSource              = vulndomain.UnscanReasonLocalProjectSource
	UnscanReasonLocalReplace                    = vulndomain.UnscanReasonLocalReplace
	UnscanReasonMissingGoSum                    = vulndomain.UnscanReasonMissingGoSum
	UnscanReasonNoGoMod                         = vulndomain.UnscanReasonNoGoMod
	UnscanReasonOOMKilled                       = vulndomain.UnscanReasonOOMKilled
	UnscanReasonPackageDeclarationsMissing      = vulndomain.UnscanReasonPackageDeclarationsMissing
	UnscanReasonProjectBuildDiverged            = vulndomain.UnscanReasonProjectBuildDiverged
	UnscanReasonProjectDirUnavailable           = vulndomain.UnscanReasonProjectDirUnavailable
	UnscanReasonProjectNoGoMod                  = vulndomain.UnscanReasonProjectNoGoMod
	UnscanReasonRelativeReplace                 = vulndomain.UnscanReasonRelativeReplace
	UnscanReasonSourceNotInStore                = vulndomain.UnscanReasonSourceNotInStore
	UnscanReasonStdlibMetadata                  = vulndomain.UnscanReasonStdlibMetadata
	UnscanReasonTargetLoadFailed                = vulndomain.UnscanReasonTargetLoadFailed
	UnscanReasonVersionNotInToolchain           = vulndomain.UnscanReasonVersionNotInToolchain
	UnscanReasonVersionNotInToolchainUnverified = vulndomain.UnscanReasonVersionNotInToolchainUnverified
	UnscanReasonWindowsOnly                     = vulndomain.UnscanReasonWindowsOnly
	UnscanReasonWorkspaceMode                   = vulndomain.UnscanReasonWorkspaceMode
)

// The values of ValidationLegKind, as the internal package defines them.
//
// Stability: supporting constants of the ValidationLegKind type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	LegSumDB = fetchdomain.LegSumDB
	LegVCS   = fetchdomain.LegVCS
)

// The values of VendorFindingKind, as the internal package defines them.
//
// Stability: supporting constants of the VendorFindingKind type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	VendorFindingDrift                 = vendordomain.FindingDrift
	VendorFindingExtraInVendor         = vendordomain.FindingExtraInVendor
	VendorFindingMissingFromModulesTxt = vendordomain.FindingMissingFromModulesTxt
	VendorFindingMissingFromVendor     = vendordomain.FindingMissingFromVendor
	VendorFindingUnverified            = vendordomain.FindingUnverified
	VendorFindingVersionMismatch       = vendordomain.FindingVersionMismatch
)

// The values of VerificationStatus, as the internal package defines them.
//
// Stability: supporting constants of the VerificationStatus type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	VerifiedByGoSum = fetchdomain.VerifiedByGoSum
)

// The values of VulnRooting, as the internal package defines them.
//
// Stability: supporting constants of the VulnRooting type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	RootingIsolated     = vulndomain.RootingIsolated
	RootingTargetRooted = vulndomain.RootingTargetRooted
	RootingUnrecorded   = vulndomain.RootingUnrecorded
)

// The values of VulnerabilityStatus, as the internal package defines them.
//
// Stability: supporting constants of the VulnerabilityStatus type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	VulnerabilityStatusAffected     = vulndomain.StatusAffected
	VulnerabilityStatusClean        = vulndomain.StatusClean
	VulnerabilityStatusInconclusive = vulndomain.StatusInconclusive
	VulnerabilityStatusScanFailed   = vulndomain.StatusScanFailed
	VulnerabilityStatusUnscannable  = vulndomain.StatusUnscannable
	VulnerabilityStatusWithdrawn    = vulndomain.StatusWithdrawn
)

// The values of WalkDepth, as the internal package defines them.
//
// Stability: supporting constants of the WalkDepth type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	WalkDepthFull    = walkdomain.WalkDepthFull
	WalkDepthShallow = walkdomain.WalkDepthShallow
)

// The values of WalkScanStatus, as the internal package defines them.
//
// Stability: supporting constants of the WalkScanStatus type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	WalkStatusAffected     = vulndomain.WalkStatusAffected
	WalkStatusAllClean     = vulndomain.WalkStatusAllClean
	WalkStatusFailed       = vulndomain.WalkStatusFailed
	WalkStatusPartial      = vulndomain.WalkStatusPartial
	WalkStatusInconclusive = vulndomain.WalkStatusInconclusive
)

// The values of WalkScope, as the internal package defines them.
//
// Stability: supporting constants of the WalkScope type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	WalkScopeCode     = walkdomain.WalkScopeCode
	WalkScopeComplete = walkdomain.WalkScopeComplete
	WalkScopeTool     = walkdomain.WalkScopeTool
)

// The values of WalkStatus, as the internal package defines them.
//
// Stability: supporting constants of the WalkStatus type; unstable pre-v1.
// Values may be added within a major version; treat an unrecognised value
// conservatively (§4).
const (
	WalkCancelled = walkdomain.WalkCancelled
	WalkFailed    = walkdomain.WalkFailed
	WalkPartial   = walkdomain.WalkPartial
	WalkSucceeded = walkdomain.WalkSucceeded
)
