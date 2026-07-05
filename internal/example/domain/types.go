package domain

import (
	"sort"
	"strings"
	"time"
	"unicode"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// ExampleSchemaVersion is the version of the ExampleRecord JSON schema. Bump
// when the serialisation format changes in a backwards-incompatible way.
// v2 adds the ecosystem scope marker.
const ExampleSchemaVersion = "2"

// ExampleStatus describes the outcome of example extraction for a module.
type ExampleStatus int

const (
	// ExampleStatusUnknown is the zero value and should never appear in a
	// persisted record.
	ExampleStatusUnknown ExampleStatus = iota
	// ExampleStatusFound means at least one Example* function was harvested.
	ExampleStatusFound
	// ExampleStatusNone means no Example* functions were found in any _test.go file.
	ExampleStatusNone
	// ExampleStatusExtractionFailed means a fatal error prevented extraction.
	// FailureDetail describes the cause.
	ExampleStatusExtractionFailed
	// ExampleStatusCancelled means extraction was interrupted by context cancellation.
	ExampleStatusCancelled
)

// String returns the human-readable name of the status.
func (s ExampleStatus) String() string {
	switch s {
	case ExampleStatusFound:
		return "Found"
	case ExampleStatusNone:
		return "None"
	case ExampleStatusExtractionFailed:
		return "ExtractionFailed"
	case ExampleStatusCancelled:
		return "Cancelled"
	default:
		return "Unknown"
	}
}

// SourcePosition identifies a location in a source file.
type SourcePosition struct {
	File string // relative to module root (e.g. "client_test.go" or "sub/client_test.go")
	Line int
}

// ExampleEntry records a single Example* function found in a _test.go file.
type ExampleEntry struct {
	Name             string   // the full function name, e.g. "ExampleClient_Do"
	Package          string   // sub-directory path within the module (e.g. "apiv1"), unique per module
	AssociatedSymbol string   // derived from Name: "ExampleClient_Do" → "Client.Do"
	SubExample       string   // non-empty for suffixed examples: "ExampleFoo_adv" → "adv"
	Body             string   // canonical source of the function body (between { and })
	Output           string   // text after "// Output:" or "// Unordered output:", empty if absent
	Imports          []string // import paths used by this example, sorted
	Doc              string   // doc comment on the Example* function
	Position         SourcePosition
	Validates        bool // true when an Output: comment is present (go test would validate)
}

// ParseFailure records a _test.go file that could not be parsed.
type ParseFailure struct {
	File  string
	Error string
}

// ExampleRecord is the aggregate root for a module's example extraction result.
// It is immutable once ContentHash is set.
type ExampleRecord struct {
	SchemaVersion string
	// Ecosystem declares the schema's scope; always fetchdomain.EcosystemGo.
	Ecosystem       string
	Coordinate      fetchdomain.ModuleCoordinate
	Examples        []ExampleEntry // sorted by (Package, AssociatedSymbol, Name)
	ParseFailures   []ParseFailure // files that failed AST parsing
	OverallStatus   ExampleStatus
	FailureDetail   string // non-empty when OverallStatus == ExtractionFailed
	ExtractedAt     time.Time
	PipelineVersion string
	ContentHash     string
}

// SortExamples sorts r.Examples by (Package, AssociatedSymbol, Name) for determinism.
// Sort ParseFailures by File as well.
func (r *ExampleRecord) SortExamples() {
	sort.Slice(r.Examples, func(i, j int) bool {
		a, b := r.Examples[i], r.Examples[j]
		if a.Package != b.Package {
			return a.Package < b.Package
		}
		if a.AssociatedSymbol != b.AssociatedSymbol {
			return a.AssociatedSymbol < b.AssociatedSymbol
		}
		return a.Name < b.Name
	})
	sort.Slice(r.ParseFailures, func(i, j int) bool {
		return r.ParseFailures[i].File < r.ParseFailures[j].File
	})
}

// DeriveAssociatedSymbol parses a Go example function name to produce the
// associated symbol and sub-example name, following the convention described
// at pkg.go.dev/testing#hdr-Examples.
//
// - "ExampleFoo" → symbol "Foo", sub ""
// - "ExampleClient_Do" → symbol "Client.Do", sub ""
// - "ExampleClient_Do_adv" → symbol "Client.Do", sub "adv"
//
// Parts after the "Example" prefix are split on "_". Consecutive parts whose
// first rune is uppercase become symbol components joined by ".". Any part
// whose first rune is lowercase (and all subsequent parts) form the
// sub-example name, joined by "_".
func DeriveAssociatedSymbol(funcName string) (symbol, sub string) {
	after, ok := strings.CutPrefix(funcName, "Example")
	if !ok || after == "" {
		return funcName, ""
	}

	parts := strings.Split(after, "_")
	var symParts []string
	var subParts []string
	hitLower := false
	for _, p := range parts {
		if p == "" {
			continue
		}
		runes := []rune(p)
		if !hitLower && unicode.IsUpper(runes[0]) {
			symParts = append(symParts, p)
		} else {
			hitLower = true
			subParts = append(subParts, p)
		}
	}
	return strings.Join(symParts, "."), strings.Join(subParts, "_")
}
