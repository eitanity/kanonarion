package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// ExampleRecordHasher computes and embeds a content hash into an ExampleRecord.
// The hash covers the canonical JSON serialisation with ContentHash zeroed.
type ExampleRecordHasher struct{}

// canonical structs use alphabetically sorted JSON keys for deterministic output.

type canonicalExampleRecord struct {
	ContentHash     string                  `json:"content_hash"`
	Coordinate      canonicalExampleCoord   `json:"coordinate"`
	Ecosystem       string                  `json:"ecosystem"`
	Examples        []canonicalExampleEntry `json:"examples"`
	ExtractedAt     string                  `json:"extracted_at"`
	FailureDetail   string                  `json:"failure_detail"`
	OverallStatus   int                     `json:"overall_status"`
	ParseFailures   []canonicalParseFailure `json:"parse_failures"`
	PipelineVersion string                  `json:"pipeline_version"`
	SchemaVersion   string                  `json:"schema_version"`
}

type canonicalExampleCoord struct {
	Path    string `json:"path"`
	Version string `json:"version"`
}

type canonicalExampleEntry struct {
	AssociatedSymbol string       `json:"associated_symbol"`
	Body             string       `json:"body"`
	Doc              string       `json:"doc"`
	Imports          []string     `json:"imports"`
	Name             string       `json:"name"`
	Output           string       `json:"output"`
	Package          string       `json:"package"`
	Position         canonicalPos `json:"position"`
	SubExample       string       `json:"sub_example"`
	Validates        bool         `json:"validates"`
}

type canonicalPos struct {
	File string `json:"file"`
	Line int    `json:"line"`
}

type canonicalParseFailure struct {
	Error string `json:"error"`
	File  string `json:"file"`
}

// SetContentHash computes the canonical hash of r (with ContentHash zeroed),
// sets r.ContentHash, and returns the updated record.
func (ExampleRecordHasher) SetContentHash(r ExampleRecord) (ExampleRecord, error) {
	r.ContentHash = ""
	data, err := marshalCanonicalExample(r)
	if err != nil {
		return ExampleRecord{}, fmt.Errorf("marshalling for hash: %w", err)
	}
	sum := sha256.Sum256(data)
	r.ContentHash = "sha256:" + hex.EncodeToString(sum[:])
	return r, nil
}

// VerifyContentHash re-computes the canonical hash and checks it matches
// r.ContentHash. Returns nil if valid.
func (ExampleRecordHasher) VerifyContentHash(r ExampleRecord) error {
	saved := r.ContentHash
	r.ContentHash = ""
	data, err := marshalCanonicalExample(r)
	if err != nil {
		return fmt.Errorf("marshalling for verification: %w", err)
	}
	sum := sha256.Sum256(data)
	expected := "sha256:" + hex.EncodeToString(sum[:])
	if saved != expected {
		return fmt.Errorf("content hash mismatch: stored %q, computed %q", saved, expected)
	}
	return nil
}

// Marshal returns the canonical JSON bytes for an ExampleRecord, including its
// ContentHash field. Call SetContentHash before this.
func (ExampleRecordHasher) Marshal(r ExampleRecord) ([]byte, error) {
	return marshalCanonicalExample(r)
}

// Unmarshal parses an ExampleRecord from its canonical JSON representation.
func (ExampleRecordHasher) Unmarshal(data []byte) (ExampleRecord, error) {
	var c canonicalExampleRecord
	if err := json.Unmarshal(data, &c); err != nil {
		return ExampleRecord{}, fmt.Errorf("unmarshalling canonical example record: %w", err)
	}
	if c.Ecosystem != fetchdomain.EcosystemGo {
		return ExampleRecord{}, fmt.Errorf("%w: got %q, want %q", fetchdomain.ErrUnsupportedEcosystem, c.Ecosystem, fetchdomain.EcosystemGo)
	}

	extractedAt, err := time.Parse(time.RFC3339, c.ExtractedAt)
	if err != nil {
		return ExampleRecord{}, fmt.Errorf("parsing extracted_at %q: %w", c.ExtractedAt, err)
	}

	coord, err := fetchdomain.NewModuleCoordinate(c.Coordinate.Path, c.Coordinate.Version)
	if err != nil {
		return ExampleRecord{}, fmt.Errorf("parsing coordinate: %w", err)
	}

	examples := make([]ExampleEntry, len(c.Examples))
	for i, ce := range c.Examples {
		imports := make([]string, len(ce.Imports))
		copy(imports, ce.Imports)
		examples[i] = ExampleEntry{
			Name:             ce.Name,
			Package:          ce.Package,
			AssociatedSymbol: ce.AssociatedSymbol,
			SubExample:       ce.SubExample,
			Body:             ce.Body,
			Output:           ce.Output,
			Imports:          imports,
			Doc:              ce.Doc,
			Position: SourcePosition{
				File: ce.Position.File,
				Line: ce.Position.Line,
			},
			Validates: ce.Validates,
		}
	}

	failures := make([]ParseFailure, len(c.ParseFailures))
	for i, cf := range c.ParseFailures {
		failures[i] = ParseFailure{File: cf.File, Error: cf.Error}
	}

	return ExampleRecord{
		SchemaVersion:   c.SchemaVersion,
		Ecosystem:       c.Ecosystem,
		Coordinate:      coord,
		Examples:        examples,
		ParseFailures:   failures,
		OverallStatus:   ExampleStatus(c.OverallStatus),
		FailureDetail:   c.FailureDetail,
		ExtractedAt:     extractedAt.UTC(),
		PipelineVersion: c.PipelineVersion,
		ContentHash:     c.ContentHash,
	}, nil
}

func marshalCanonicalExample(r ExampleRecord) ([]byte, error) {
	// Sort for determinism even if caller omitted SortExamples.
	examples := make([]ExampleEntry, len(r.Examples))
	copy(examples, r.Examples)
	sort.Slice(examples, func(i, j int) bool {
		a, b := examples[i], examples[j]
		if a.Package != b.Package {
			return a.Package < b.Package
		}
		if a.AssociatedSymbol != b.AssociatedSymbol {
			return a.AssociatedSymbol < b.AssociatedSymbol
		}
		return a.Name < b.Name
	})

	failures := make([]ParseFailure, len(r.ParseFailures))
	copy(failures, r.ParseFailures)
	sort.Slice(failures, func(i, j int) bool {
		return failures[i].File < failures[j].File
	})

	cExamples := make([]canonicalExampleEntry, len(examples))
	for i, e := range examples {
		imports := make([]string, len(e.Imports))
		copy(imports, e.Imports)
		sort.Strings(imports)
		cExamples[i] = canonicalExampleEntry{
			AssociatedSymbol: e.AssociatedSymbol,
			Body:             e.Body,
			Doc:              e.Doc,
			Imports:          imports,
			Name:             e.Name,
			Output:           e.Output,
			Package:          e.Package,
			Position:         canonicalPos{File: e.Position.File, Line: e.Position.Line},
			SubExample:       e.SubExample,
			Validates:        e.Validates,
		}
	}

	cFailures := make([]canonicalParseFailure, len(failures))
	for i, f := range failures {
		cFailures[i] = canonicalParseFailure{File: f.File, Error: f.Error}
	}

	c := canonicalExampleRecord{
		ContentHash: r.ContentHash,
		Coordinate: canonicalExampleCoord{
			Path:    r.Coordinate.Path,
			Version: r.Coordinate.Version,
		},
		Ecosystem:       r.Ecosystem,
		Examples:        cExamples,
		ExtractedAt:     r.ExtractedAt.UTC().Format(time.RFC3339),
		FailureDetail:   r.FailureDetail,
		OverallStatus:   int(r.OverallStatus),
		ParseFailures:   cFailures,
		PipelineVersion: r.PipelineVersion,
		SchemaVersion:   r.SchemaVersion,
	}

	b, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("marshalling canonical example record: %w", err)
	}
	return b, nil
}
