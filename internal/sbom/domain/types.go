package domain

import (
	"errors"
	"time"
)

// EcosystemGo is the only ecosystem kanonarion records describe. The ecosystem
// field declares the schema's scope — kanonarion is fitted for Go — rather than
// enabling polyglot mode. There is deliberately no "npm" or "cargo".
const EcosystemGo = "go"

// EcosystemNative marks a component that is not a package in any ecosystem
// kanonarion resolves: a C, C++, Objective-C or Fortran library whose source a
// Go module ships inside its own published zip and compiles into the binary
// through cgo.
//
// It does NOT open polyglot mode, and it is not a sibling of EcosystemGo above.
// Kanonarion still resolves one dependency graph, the Go one; this names a
// component found INSIDE a Go module's artefact, which has no package identity
// of its own to resolve. There is still deliberately no "npm" and no "cargo".
const EcosystemNative = "native"

// ErrUnsupportedEcosystem is returned when a stored SBOM record's ecosystem is
// absent or holds a value other than EcosystemGo.
var ErrUnsupportedEcosystem = errors.New("unsupported ecosystem: kanonarion records are Go-only")

// ErrNonGoComponent is returned by the SBOM generator when a component built
// from a walk graph node does not carry a "pkg:golang/" package URL. Every such
// component describes a Go module; a non-Go purl there indicates a generator
// bug.
//
// It is scoped to the components assembled from the graph. A native component
// is built on its own path, from a native-component record rather than a graph
// node, and is held to ErrNonGenericComponent instead — so neither half of the
// list can quietly start emitting the other's scheme.
var ErrNonGoComponent = errors.New("non-Go component: purl must start with pkg:golang/")

// ErrNonGenericComponent is returned when a component built from a
// native-component record does not carry a "pkg:generic/" package URL. A
// library that is not published in a registry has no registry identity, and
// naming it under a registry's purl type would tell a reader to look it up
// somewhere it cannot be found.
var ErrNonGenericComponent = errors.New("non-generic native component: purl must start with pkg:generic/")

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
	// Format is the serialisation format of the SBOM document.
	Format SBOMFormat
	// Content is the canonical SBOM document bytes.
	Content []byte
	// ContentHash is the SHA-256 hex digest of Content.
	ContentHash string
	// GeneratedAt is when the document this record holds was created, and is the
	// value its metadata timestamp carries. It is the caller-supplied creation
	// time when one was given, and otherwise the newest licence extraction time
	// among the document's inputs — a derived value the document labels as such
	// rather than passing off as a clock reading.
	GeneratedAt time.Time
	// PipelineVersion is the kanonarion version that produced this record.
	PipelineVersion string
	// Operator is the identity that requested generation.
	Operator string
	// LicensesIncomplete is true when at least one component in the document
	// carries no licence identity — either no licence record was found for it,
	// or the record that was found identified no SPDX licence.
	LicensesIncomplete bool
}
