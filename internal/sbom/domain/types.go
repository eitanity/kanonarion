package domain

import (
	"errors"
	"time"
)

// EcosystemGo is the only ecosystem kanonarion records describe. The ecosystem
// field declares the schema's scope — kanonarion is fitted for Go — rather than
// enabling polyglot mode. There is deliberately no "npm" or "cargo".
const EcosystemGo = "go"

// ErrUnsupportedEcosystem is returned when a stored SBOM record's ecosystem is
// absent or holds a value other than EcosystemGo.
var ErrUnsupportedEcosystem = errors.New("unsupported ecosystem: kanonarion records are Go-only")

// ErrNonGoComponent is returned by the SBOM generator when a component's
// package URL does not start with "pkg:golang/". Every component kanonarion
// emits describes a Go module; a non-Go purl indicates a generator bug.
var ErrNonGoComponent = errors.New("non-Go component: purl must start with pkg:golang/")

// SBOMFormat identifies the serialisation format of an SBOM document.
type SBOMFormat string

const (
	// CycloneDX16 is CycloneDX JSON version 1.6.
	CycloneDX16 SBOMFormat = "cyclonedx-1.6"
)

// SBOMRecord is the aggregate root for a generated SBOM.
type SBOMRecord struct {
	// ID is the unique identifier for this SBOM record.
	ID string
	// Ecosystem declares the schema's scope; always EcosystemGo. It is record
	// metadata and is not part of ContentHash (which digests Content).
	Ecosystem string
	// WalkID is the walk this SBOM was generated from.
	WalkID string
	// WalkScanRunID is the optional scan run that contributed vulnerability data.
	// Nil when the SBOM was generated without vulnerability inclusion.
	WalkScanRunID *string
	// Format is the serialisation format of the SBOM document.
	Format SBOMFormat
	// Content is the canonical SBOM document bytes.
	Content []byte
	// ContentHash is the SHA-256 hex digest of Content.
	ContentHash string
	// GeneratedAt is when this record was created.
	GeneratedAt time.Time
	// PipelineVersion is the kanonarion version that produced this record.
	PipelineVersion string
	// Operator is the identity that requested generation.
	Operator string
	// LicensesIncomplete is true when at least one module had no licence data.
	LicensesIncomplete bool
}
