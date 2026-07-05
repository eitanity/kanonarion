package domain

import (
	"sort"
	"time"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// LicenseSchemaVersion is the version of the LicenseRecord JSON schema. Bump
// when the serialisation format changes in a backwards-incompatible way.
// v4 adds the ecosystem scope marker. v5 adds the per-file low-confidence
// match fields (a recognisable but sub-threshold licence fragment).
const LicenseSchemaVersion = "5"

// LicenseStatus describes the outcome of license extraction for a module.
type LicenseStatus int

const (
	// LicenceStatusUnknown is the zero value and should never appear in a
	// persisted record.
	LicenceStatusUnknown LicenseStatus = iota
	// LicenseStatusDetected means a single unambiguous primary license was
	// identified at the module root.
	LicenseStatusDetected
	// LicenceStatusAmbiguous means the primary license file produced multiple
	// candidate identifications with similar confidence.
	LicenceStatusAmbiguous
	// LicenseStatusMultiple means multiple root-level license files were found
	// with distinct SPDX identifiers.
	LicenseStatusMultiple
	// LicenseStatusNone means no license files were found at the module root.
	LicenseStatusNone
	// LicenseStatusUnclassified means root-level license-named files were found
	// but none could be matched to a known SPDX identifier. Typical causes:
	// custom commercial license text, "All rights reserved" notices, or
	// proprietary agreements. Distinct from LicenseStatusNone (no files at all).
	LicenseStatusUnclassified
	// LicenseStatusExtractionFailed means the module zip could not be read or
	// a fatal error prevented extraction. FailureDetail describes the cause.
	LicenseStatusExtractionFailed
	// LicenseStatusCancelled means the extraction was interrupted by context
	// cancellation before completing.
	LicenseStatusCancelled
	// LicenseStatusPerFile means no dedicated license file was found at the
	// module root, but per-file SPDX headers or copyright blocks were detected
	// in source files (only populated when --per-file extraction is enabled).
	LicenseStatusPerFile
)

// String returns the human-readable name of the status.
func (s LicenseStatus) String() string {
	switch s {
	case LicenseStatusDetected:
		return "Detected"
	case LicenceStatusAmbiguous:
		return "Ambiguous"
	case LicenseStatusMultiple:
		return "Multiple"
	case LicenseStatusNone:
		return "None"
	case LicenseStatusUnclassified:
		return "Unclassified"
	case LicenseStatusExtractionFailed:
		return "ExtractionFailed"
	case LicenseStatusCancelled:
		return "Cancelled"
	case LicenseStatusPerFile:
		return "PerFile"
	default:
		return "Unknown"
	}
}

// AltMatch is an alternative license identification for a file, reported when
// the detector produced multiple candidates.
type AltMatch struct {
	SPDX       string
	Confidence float64
}

// LicenseFileEntry records a single license-named file found in a module zip.
type LicenseFileEntry struct {
	Path                string  // relative to module root (e.g. "LICENSE" or "vendor/dep/LICENSE")
	SPDX                string  // SPDX identifier; empty if the file could not be classified
	Confidence          float64 // 0.0–1.0; 0 when unclassified
	FileHash            string  // "sha256:<hex>" over file contents
	FileSize            int64
	IsVendored          bool
	IsPerFile           bool                 // true when license was found in a source file header, not a dedicated license file
	AltMatches          []AltMatch           // non-empty when detector produced multiple candidates; sorted by Confidence desc
	CopyrightStatements []CopyrightStatement // sorted by Verbatim; nil when copyright extraction has not run
	// LowConfidenceSPDX records a recognisable licence fragment found below the
	// detector's substantive coverage floor. SPDX above stays empty (the file
	// is Unclassified) but this preserves the partial signal — e.g. a truncated
	// AGPL-3.0 whose only matching span is the "how to apply" appendix — so a
	// consumer is told "licence present, low-confidence AGPL-3.0 match" rather
	// than being shown bare absence.
	LowConfidenceSPDX     string
	LowConfidenceCoverage float64 // coverage fraction (0.0–1.0) of the low-confidence match; 0 when none
}

// EmbeddedComponent represents a distinct third-party component bundled within
// a module (e.g. a vendored library under vendor/).
type EmbeddedComponent struct {
	PathPrefix string   // directory prefix relative to module root (e.g. "vendor/github.com/google/snappy")
	SPDXs      []string // distinct SPDX identifiers found under this prefix (sorted)
}

// EffectiveLicenseSet captures the union of root-level and embedded-component
// licenses for a module. It is derived from LicenseFiles and not stored
// separately — recomputed after deserialization so it is always consistent.
type EffectiveLicenseSet struct {
	RootSPDXs  []string            // distinct SPDX IDs from root-level non-vendored license files (sorted)
	Components []EmbeddedComponent // per vendored embedded component (sorted by PathPrefix)
	AllSPDXs   []string            // union of root + component SPDXs (sorted, deduped)
}

// PackageLicense describes the license that governs a specific non-root
// sub-package directory within the module (first-party code, not vendored).
// Only packages whose directory contains its own license file are represented;
// packages that inherit the module root license do not appear here.
type PackageLicense struct {
	PackagePath string  // directory path relative to module root (e.g. "cmd/foo")
	SPDX        string  // SPDX identifier; empty if the file could not be classified
	Confidence  float64 // 0.0–1.0; 0 when unclassified
	SourceFile  string  // license file that determined this (e.g. "cmd/foo/LICENSE")
}

// LicenseRoleRootDeclaration marks a record extracted from the project-walk
// root: the licence the project itself DECLARES outbound (the grant its
// author makes to others, plus the copyright they assert), as opposed to the
// inbound obligations a dependency's licence imposes. Consumers must treat a
// root-declaration record as the TARGET — the licence the closure is checked
// against, the SBOM primary component's licence — never as a constraint to
// satisfy. A proprietary root resolving to Unclassified plus copyright
// statements is a correct, honest outcome for this role, not a failure.
const LicenseRoleRootDeclaration = "root_declaration"

// LicenseRecord is the aggregate root for a module's license extraction result.
// It is immutable once ContentHash is set.
type LicenseRecord struct {
	SchemaVersion string
	// Ecosystem declares the schema's scope; always fetchdomain.EcosystemGo.
	Ecosystem  string
	Coordinate fetchdomain.ModuleCoordinate
	// Role distinguishes what the extracted facts MEAN for the subject.
	// Empty for a dependency (inbound obligations);
	// LicenseRoleRootDeclaration for the project-walk root (outbound
	// declaration).
	Role              string
	PrimarySPDX       string // kept for backward compatibility; Expression is the canonical representation
	Expression        string // SPDX license expression (e.g. "MIT", "MIT OR Apache-2.0", "BSD-3-Clause AND MIT")
	PrimaryConfidence float64
	LicenseFiles      []LicenseFileEntry  // sorted by Path
	EffectiveSet      EffectiveLicenseSet // derived from LicenseFiles; not hashed
	PackageLicenses   []PackageLicense    // per-package licenses for non-root sub-packages; derived, not hashed
	OverallStatus     LicenseStatus
	CopyrightStatus   CopyrightStatus   // NotAnalysed ≠ NoneFound
	Provenance        ProvenanceSummary // contribution-licensing chain-of-title
	FailureDetail     string            // non-empty when OverallStatus == ExtractionFailed
	ExtractedAt       time.Time
	PipelineVersion   string
	ContentHash       string
}

// SortFiles sorts LicenseFiles lexicographically by Path; within each entry,
// sorts AltMatches by Confidence descending and CopyrightStatements by
// Verbatim. Call after construction, before hashing.
func (r *LicenseRecord) SortFiles() {
	sort.Slice(r.LicenseFiles, func(i, j int) bool {
		return r.LicenseFiles[i].Path < r.LicenseFiles[j].Path
	})
	for i := range r.LicenseFiles {
		f := &r.LicenseFiles[i]
		sort.Slice(f.AltMatches, func(a, b int) bool {
			return f.AltMatches[a].Confidence > f.AltMatches[b].Confidence
		})
		sort.Slice(f.CopyrightStatements, func(a, b int) bool {
			return f.CopyrightStatements[a].Verbatim < f.CopyrightStatements[b].Verbatim
		})
	}
}
