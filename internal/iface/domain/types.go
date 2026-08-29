package domain

import (
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/gotoolchain"
)

// InterfaceSchemaVersion is the version of the InterfaceRecord JSON schema.
// Bump when the serialisation format changes in a backwards-incompatible way.
// v2 adds the ecosystem scope marker.
const InterfaceSchemaVersion = "2"

// InterfaceStatus describes the outcome of interface extraction for a module.
type InterfaceStatus int

const (
	// InterfaceStatusUnknown is the zero value and should never appear in a
	// persisted record.
	InterfaceStatusUnknown InterfaceStatus = iota
	// InterfaceStatusExtracted means all packages were parsed without error.
	InterfaceStatusExtracted
	// InterfaceStatusPartial means at least one package or file had a parse
	// error but extraction continued with the remaining sources.
	InterfaceStatusPartial
	// InterfaceStatusExtractionFailed means a fatal error prevented extraction.
	// FailureDetail describes the cause.
	InterfaceStatusExtractionFailed
	// InterfaceStatusCancelled means extraction was interrupted by context cancellation.
	InterfaceStatusCancelled
)

// String returns the human-readable name of the status.
func (s InterfaceStatus) String() string {
	switch s {
	case InterfaceStatusExtracted:
		return "Extracted"
	case InterfaceStatusPartial:
		return "Partial"
	case InterfaceStatusExtractionFailed:
		return "ExtractionFailed"
	case InterfaceStatusCancelled:
		return "Cancelled"
	default:
		return "Unknown"
	}
}

// TypeKind classifies the form of a type declaration.
type TypeKind int

const (
	TypeKindUnknown   TypeKind = iota
	TypeKindStruct             // struct { ... }
	TypeKindInterface          // interface { ... }
	TypeKindAlias              // type A = B
	TypeKindDefined            // type A B (new named type)
	TypeKindGeneric            // type A[T any] ...
)

// String returns the human-readable name of the kind.
func (k TypeKind) String() string {
	switch k {
	case TypeKindStruct:
		return "struct"
	case TypeKindInterface:
		return "interface"
	case TypeKindAlias:
		return "alias"
	case TypeKindDefined:
		return "defined"
	case TypeKindGeneric:
		return "generic"
	default:
		return "unknown"
	}
}

// BuildFrame names the build configuration a public API was measured in.
//
// A Go package can declare the same exported symbol several times, once per
// mutually exclusive build constraint, and only one of those declarations is in
// any given build. An API measured at linux/amd64 and one measured at
// windows/386 are therefore different facts about the same module version, and a
// record that does not say which one it holds cannot be compared with another —
// a reader cannot tell a symbol that was removed from a symbol that was never
// built here.
//
// The zero value means "not recorded", which is the true value for records
// written before the extractor evaluated build constraints at all: those hold
// every variant of every file at once and belong to no build. It never reads as
// a frame in its own right.
type BuildFrame struct {
	GOOS   string
	GOARCH string
	// CgoEnabled is part of the frame because the "cgo" build tag selects
	// files, so two runs that disagree about it measure different packages.
	CgoEnabled bool
}

// IsZero reports whether the frame was never recorded.
func (f BuildFrame) IsZero() bool { return f.GOOS == "" && f.GOARCH == "" }

// String renders the frame as "goos/goarch" plus the cgo state, or
// "unrecorded" when nothing was measured.
func (f BuildFrame) String() string {
	if f.IsZero() {
		return "unrecorded"
	}
	cgo := "cgo off"
	if f.CgoEnabled {
		cgo = "cgo on"
	}
	return f.GOOS + "/" + f.GOARCH + " (" + cgo + ")"
}

// SourcePosition identifies a location in a source file.
type SourcePosition struct {
	File string // relative to module root
	Line int
}

// TypeParam represents a type parameter in a generic declaration.
type TypeParam struct {
	Name       string // e.g. "T"
	Constraint string // e.g. "any" or "comparable"
}

// FieldDecl describes an exported struct field.
type FieldDecl struct {
	Name        string
	Type        string
	Tag         string // raw struct tag, e.g. `json:"foo"`
	Doc         string
	Embedded    bool
	Position    SourcePosition
	IsGenerated bool
}

// MethodDecl describes an exported method on a type.
type MethodDecl struct {
	Name        string
	Signature   string // canonical go/printer output, receiver omitted
	Doc         string
	Position    SourcePosition
	PtrReceiver bool // true if the receiver is a pointer
}

// TypeDecl describes an exported type.
type TypeDecl struct {
	Name          string
	Kind          TypeKind
	Signature     string // canonical go/printer output
	Doc           string
	TypeParams    []TypeParam
	Fields        []FieldDecl // non-nil only for structs
	Methods       []MethodDecl
	EmbeddedTypes []string // interface embedding names
	Position      SourcePosition
	IsGenerated   bool // declared in a file with "Code generated … DO NOT EDIT."
}

// FuncDecl describes an exported package-level function (not a method).
type FuncDecl struct {
	Name        string
	Signature   string
	Doc         string
	TypeParams  []TypeParam
	Position    SourcePosition
	IsGenerated bool
}

// ValueDecl describes an exported constant or variable.
type ValueDecl struct {
	Name        string
	Type        string // may be empty for untyped constants
	Doc         string
	Position    SourcePosition
	IsGenerated bool
}

// ParseFailure records a source file that could not be parsed.
type ParseFailure struct {
	File  string
	Error string
}

// PackageInterface captures the full exported API of a single package.
type PackageInterface struct {
	ImportPath    string
	Name          string
	Doc           string
	Types         []TypeDecl
	Funcs         []FuncDecl
	Consts        []ValueDecl
	Vars          []ValueDecl
	ParseFailures []ParseFailure
	IsInternal    bool // import path contains "/internal/"
	IsMain        bool // package name == "main"
	// OutOfFrame is true when the directory holds Go source but none of it is
	// in the record's BuildFrame — a package that exists in the module and not
	// in this build. The package is kept, empty, rather than dropped, so the
	// difference between "this module has no such package" and "this build has
	// no such package" survives into the record.
	OutOfFrame bool
}

// InterfaceRecord is the aggregate root for a module's interface extraction
// result. It is immutable once ContentHash is set.
type InterfaceRecord struct {
	SchemaVersion string
	// Ecosystem declares the schema's scope; always fetchdomain.EcosystemGo.
	Ecosystem     string
	Coordinate    coordinate.ModuleCoordinate
	Packages      []PackageInterface // sorted by ImportPath
	OverallStatus InterfaceStatus
	FailureDetail string
	// BuildFrame names the build configuration the packages were measured in.
	// Zero on records written before the extractor evaluated build constraints;
	// see BuildFrame's own documentation for why that is not a frame.
	BuildFrame BuildFrame
	// Toolchain is the Go toolchain whose RELEASE TAGS decided which files this
	// record's API was read from ("go1.26.6"). A //go:build go1.27 file enters or
	// leaves the public API with the toolchain, and the frame cannot say which
	// tags were in force: it states GOOS, GOARCH and cgo, which the extractor
	// takes from the frame precisely so the extracting host cannot change a stored
	// API — and then takes the release tags from the host, which is the one leak
	// this closes.
	//
	// It is a DIMENSION, not a ladder position — see gotoolchain.Version.
	// Composition names a toolchain difference as a conflict before it compares
	// two APIs, exactly as it does a frame difference.
	//
	// Empty on records written before the field existed, which reads as "not
	// recorded" and never as the reading host's toolchain.
	Toolchain       gotoolchain.Version
	ExtractedAt     time.Time
	PipelineVersion string
	ContentHash     string
	// ArtefactIdentity names the fetched artefact this record was derived from,
	// in the "zip:h1:..." / "gomod:h1:..." form fetchdomain.ArtefactIdentity
	// renders. It answers the question the coordinate cannot: which bytes
	// produced this finding. A coordinate names a module version, and the fetch
	// record for that coordinate may since have been re-measured, so a link by
	// coordinate is a link by convention; this one is by fact, and is covered by
	// ContentHash, so the claim is as tamper-evident as the finding itself.
	//
	// Empty on records written before the field existed, and on records derived
	// from no fetched artefact at all. Both read as "not recorded", never as
	// "derived from nothing". Read it back through RecordArtefactIdentity,
	// which draws that distinction; never hand this field to
	// ParseArtefactIdentity directly.
	ArtefactIdentity string
	// SourceContentHash is the content hash of the fetch record that supplied
	// those bytes. ArtefactIdentity says which artefact; this says which
	// measurement of it, so a reader can fetch that record and check the claim
	// against it. Empty exactly when ArtefactIdentity is.
	SourceContentHash string
}

// Sort puts all collections in the record into a canonical, deterministic
// order. Must be called before hashing. The comparators live in ordering.go;
// each is a total order, so the result is a function of the record's contents
// and not of the order the extractor emitted them in.
func (r *InterfaceRecord) Sort() {
	sortPackages(r.Packages)
}
