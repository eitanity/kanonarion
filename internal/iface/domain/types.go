package domain

import (
	"sort"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
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
}

// InterfaceRecord is the aggregate root for a module's interface extraction
// result. It is immutable once ContentHash is set.
type InterfaceRecord struct {
	SchemaVersion string
	// Ecosystem declares the schema's scope; always fetchdomain.EcosystemGo.
	Ecosystem       string
	Coordinate      coordinate.ModuleCoordinate
	Packages        []PackageInterface // sorted by ImportPath
	OverallStatus   InterfaceStatus
	FailureDetail   string
	ExtractedAt     time.Time
	PipelineVersion string
	ContentHash     string
}

// Sort puts all collections in the record into a canonical, deterministic
// order. Must be called before hashing.
func (r *InterfaceRecord) Sort() {
	sort.Slice(r.Packages, func(i, j int) bool {
		return r.Packages[i].ImportPath < r.Packages[j].ImportPath
	})
	for i := range r.Packages {
		sortPackage(&r.Packages[i])
	}
}

func sortPackage(p *PackageInterface) {
	sort.Slice(p.Types, func(i, j int) bool { return p.Types[i].Name < p.Types[j].Name })
	sort.Slice(p.Funcs, func(i, j int) bool { return p.Funcs[i].Name < p.Funcs[j].Name })
	sort.Slice(p.Consts, func(i, j int) bool { return p.Consts[i].Name < p.Consts[j].Name })
	sort.Slice(p.Vars, func(i, j int) bool { return p.Vars[i].Name < p.Vars[j].Name })
	sort.Slice(p.ParseFailures, func(i, j int) bool { return p.ParseFailures[i].File < p.ParseFailures[j].File })
	for i := range p.Types {
		t := &p.Types[i]
		sort.Slice(t.Fields, func(a, b int) bool { return t.Fields[a].Name < t.Fields[b].Name })
		sort.Slice(t.Methods, func(a, b int) bool { return t.Methods[a].Name < t.Methods[b].Name })
		sort.Strings(t.EmbeddedTypes)
		sort.Slice(t.TypeParams, func(a, b int) bool { return t.TypeParams[a].Name < t.TypeParams[b].Name })
	}
	for i := range p.Funcs {
		sort.Slice(p.Funcs[i].TypeParams, func(a, b int) bool {
			return p.Funcs[i].TypeParams[a].Name < p.Funcs[i].TypeParams[b].Name
		})
	}
}
