package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// InterfaceRecordHasher computes and embeds a content hash into an InterfaceRecord.
// The hash covers the canonical JSON serialisation with ContentHash zeroed.
type InterfaceRecordHasher struct{}

// SetContentHash computes the canonical hash of r (with ContentHash zeroed),
// sets r.ContentHash, and returns the updated record.
func (InterfaceRecordHasher) SetContentHash(r InterfaceRecord) (InterfaceRecord, error) {
	r.ContentHash = ""
	data, err := marshalCanonical(r)
	if err != nil {
		return InterfaceRecord{}, fmt.Errorf("marshalling for hash: %w", err)
	}
	sum := sha256.Sum256(data)
	r.ContentHash = "sha256:" + hex.EncodeToString(sum[:])
	return r, nil
}

// VerifyContentHash re-computes the canonical hash and checks it matches
// r.ContentHash. Returns nil if valid.
func (InterfaceRecordHasher) VerifyContentHash(r InterfaceRecord) error {
	saved := r.ContentHash
	r.ContentHash = ""
	data, err := marshalCanonical(r)
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

// Marshal returns the canonical JSON bytes for an InterfaceRecord, including
// its ContentHash field. Call SetContentHash before this.
func (InterfaceRecordHasher) Marshal(r InterfaceRecord) ([]byte, error) {
	return marshalCanonical(r)
}

// Unmarshal parses an InterfaceRecord from its canonical JSON representation.
func (InterfaceRecordHasher) Unmarshal(data []byte) (InterfaceRecord, error) {
	var c canonicalRecord
	if err := json.Unmarshal(data, &c); err != nil {
		return InterfaceRecord{}, fmt.Errorf("unmarshalling canonical interface record: %w", err)
	}
	if c.Ecosystem != fetchdomain.EcosystemGo {
		return InterfaceRecord{}, fmt.Errorf("%w: got %q, want %q", fetchdomain.ErrUnsupportedEcosystem, c.Ecosystem, fetchdomain.EcosystemGo)
	}

	extractedAt, err := time.Parse(time.RFC3339, c.ExtractedAt)
	if err != nil {
		return InterfaceRecord{}, fmt.Errorf("parsing extracted_at %q: %w", c.ExtractedAt, err)
	}

	coord, err := coordinate.NewModuleCoordinate(c.Coordinate.Path, c.Coordinate.Version)
	if err != nil {
		return InterfaceRecord{}, fmt.Errorf("parsing coordinate: %w", err)
	}

	pkgs := make([]PackageInterface, len(c.Packages))
	for i, cp := range c.Packages {
		pkgs[i] = fromCanonicalPackage(cp)
	}

	var frame BuildFrame
	if c.BuildFrame != nil {
		frame = BuildFrame{GOOS: c.BuildFrame.GOOS, GOARCH: c.BuildFrame.GOARCH, CgoEnabled: c.BuildFrame.Cgo}
	}

	return InterfaceRecord{
		SchemaVersion:     c.SchemaVersion,
		BuildFrame:        frame,
		Ecosystem:         c.Ecosystem,
		Coordinate:        coord,
		Packages:          pkgs,
		OverallStatus:     InterfaceStatus(c.OverallStatus),
		FailureDetail:     c.FailureDetail,
		ExtractedAt:       extractedAt.UTC(),
		PipelineVersion:   c.PipelineVersion,
		ContentHash:       c.ContentHash,
		ArtefactIdentity:  c.ArtefactIdentity,
		SourceContentHash: c.SourceContentHash,
	}, nil
}

// -- canonical wire types --

// canonicalFrame is the wire shape of BuildFrame. The whole object is omitted
// when the frame was never recorded, so records written before the extractor
// evaluated build constraints keep the content hash they were stored with.
type canonicalFrame struct {
	Cgo    bool   `json:"cgo_enabled"`
	GOARCH string `json:"goarch"`
	GOOS   string `json:"goos"`
}

type canonicalCoord struct {
	Path    string `json:"path"`
	Version string `json:"version"`
}

type canonicalRecord struct {
	// ArtefactIdentity and SourceContentHash are omitted when empty so
	// records that predate them keep their stored content hash verifiable,
	// on the same terms every additive field on this shape has used.
	ArtefactIdentity  string          `json:"artefact_identity,omitempty"`
	BuildFrame        *canonicalFrame `json:"build_frame,omitempty"`
	ContentHash       string          `json:"content_hash"`
	Coordinate        canonicalCoord  `json:"coordinate"`
	Ecosystem         string          `json:"ecosystem"`
	ExtractedAt       string          `json:"extracted_at"`
	FailureDetail     string          `json:"failure_detail"`
	OverallStatus     int             `json:"overall_status"`
	Packages          []canonicalPkg  `json:"packages"`
	PipelineVersion   string          `json:"pipeline_version"`
	SchemaVersion     string          `json:"schema_version"`
	SourceContentHash string          `json:"source_content_hash,omitempty"`
}

type canonicalPkg struct {
	Consts        []canonicalValue   `json:"consts"`
	Doc           string             `json:"doc"`
	Funcs         []canonicalFunc    `json:"funcs"`
	ImportPath    string             `json:"import_path"`
	IsInternal    bool               `json:"is_internal"`
	IsMain        bool               `json:"is_main"`
	OutOfFrame    bool               `json:"out_of_frame,omitempty"`
	Name          string             `json:"name"`
	ParseFailures []canonicalFailure `json:"parse_failures"`
	Types         []canonicalType    `json:"types"`
	Vars          []canonicalValue   `json:"vars"`
}

type canonicalType struct {
	Doc           string            `json:"doc"`
	EmbeddedTypes []string          `json:"embedded_types"`
	Fields        []canonicalField  `json:"fields"`
	IsGenerated   bool              `json:"is_generated"`
	Kind          int               `json:"kind"`
	Methods       []canonicalMethod `json:"methods"`
	Name          string            `json:"name"`
	Position      canonicalPos      `json:"position"`
	Signature     string            `json:"signature"`
	TypeParams    []canonicalTP     `json:"type_params"`
}

type canonicalFunc struct {
	Doc         string        `json:"doc"`
	IsGenerated bool          `json:"is_generated"`
	Name        string        `json:"name"`
	Position    canonicalPos  `json:"position"`
	Signature   string        `json:"signature"`
	TypeParams  []canonicalTP `json:"type_params"`
}

type canonicalValue struct {
	Doc         string       `json:"doc"`
	IsGenerated bool         `json:"is_generated"`
	Name        string       `json:"name"`
	Position    canonicalPos `json:"position"`
	Type        string       `json:"type"`
}

type canonicalField struct {
	Doc         string       `json:"doc"`
	Embedded    bool         `json:"embedded"`
	IsGenerated bool         `json:"is_generated"`
	Name        string       `json:"name"`
	Position    canonicalPos `json:"position"`
	Tag         string       `json:"tag"`
	Type        string       `json:"type"`
}

type canonicalMethod struct {
	Doc         string       `json:"doc"`
	Name        string       `json:"name"`
	Position    canonicalPos `json:"position"`
	PtrReceiver bool         `json:"ptr_receiver"`
	Signature   string       `json:"signature"`
}

type canonicalTP struct {
	Constraint string `json:"constraint"`
	Name       string `json:"name"`
}

type canonicalPos struct {
	File string `json:"file"`
	Line int    `json:"line"`
}

type canonicalFailure struct {
	Error string `json:"error"`
	File  string `json:"file"`
}

func marshalCanonical(r InterfaceRecord) ([]byte, error) {
	// Sort for determinism regardless of whether caller called Sort.
	pkgs := make([]PackageInterface, len(r.Packages))
	copy(pkgs, r.Packages)
	for i := range pkgs {
		sortPackage(&pkgs[i])
	}
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].ImportPath < pkgs[j].ImportPath })

	cPkgs := make([]canonicalPkg, len(pkgs))
	for i, p := range pkgs {
		cPkgs[i] = toCanonicalPackage(p)
	}

	var frame *canonicalFrame
	if !r.BuildFrame.IsZero() {
		frame = &canonicalFrame{Cgo: r.BuildFrame.CgoEnabled, GOARCH: r.BuildFrame.GOARCH, GOOS: r.BuildFrame.GOOS}
	}

	c := canonicalRecord{
		ArtefactIdentity:  r.ArtefactIdentity,
		BuildFrame:        frame,
		ContentHash:       r.ContentHash,
		Coordinate:        canonicalCoord{Path: r.Coordinate.Path(), Version: r.Coordinate.Version()},
		Ecosystem:         r.Ecosystem,
		ExtractedAt:       r.ExtractedAt.UTC().Format(time.RFC3339),
		FailureDetail:     r.FailureDetail,
		OverallStatus:     int(r.OverallStatus),
		Packages:          cPkgs,
		PipelineVersion:   r.PipelineVersion,
		SchemaVersion:     r.SchemaVersion,
		SourceContentHash: r.SourceContentHash,
	}

	b, err := canonicalMarshal(c)
	if err != nil {
		return nil, fmt.Errorf("marshalling canonical interface record: %w", err)
	}
	return b, nil
}

// canonicalMarshal is a seam over json.Marshal used to test the
// marshal-failure guard's wrapping and propagation logic. No field in
// canonicalRecord can currently make json.Marshal fail (no NaN/Inf floats,
// no unsupported types), so this proves the guard's error handling is
// correct, not that the guard is reachable with a real value today — it
// exists for the never-silent-failure invariant, not a known failure mode.
var canonicalMarshal = json.Marshal

func toCanonicalPackage(p PackageInterface) canonicalPkg {
	types := make([]canonicalType, len(p.Types))
	for i, t := range p.Types {
		fields := make([]canonicalField, len(t.Fields))
		for j, f := range t.Fields {
			fields[j] = canonicalField{
				Doc:         f.Doc,
				Embedded:    f.Embedded,
				IsGenerated: f.IsGenerated,
				Name:        f.Name,
				Position:    canonicalPos{File: f.Position.File, Line: f.Position.Line},
				Tag:         f.Tag,
				Type:        f.Type,
			}
		}
		methods := make([]canonicalMethod, len(t.Methods))
		for j, m := range t.Methods {
			methods[j] = canonicalMethod{
				Doc:         m.Doc,
				Name:        m.Name,
				Position:    canonicalPos{File: m.Position.File, Line: m.Position.Line},
				PtrReceiver: m.PtrReceiver,
				Signature:   m.Signature,
			}
		}
		tps := make([]canonicalTP, len(t.TypeParams))
		for j, tp := range t.TypeParams {
			tps[j] = canonicalTP{Constraint: tp.Constraint, Name: tp.Name}
		}
		embedded := make([]string, len(t.EmbeddedTypes))
		copy(embedded, t.EmbeddedTypes)
		sort.Strings(embedded)
		types[i] = canonicalType{
			Doc:           t.Doc,
			EmbeddedTypes: embedded,
			Fields:        fields,
			IsGenerated:   t.IsGenerated,
			Kind:          int(t.Kind),
			Methods:       methods,
			Name:          t.Name,
			Position:      canonicalPos{File: t.Position.File, Line: t.Position.Line},
			Signature:     t.Signature,
			TypeParams:    tps,
		}
	}

	funcs := make([]canonicalFunc, len(p.Funcs))
	for i, f := range p.Funcs {
		tps := make([]canonicalTP, len(f.TypeParams))
		for j, tp := range f.TypeParams {
			tps[j] = canonicalTP{Constraint: tp.Constraint, Name: tp.Name}
		}
		funcs[i] = canonicalFunc{
			Doc:         f.Doc,
			IsGenerated: f.IsGenerated,
			Name:        f.Name,
			Position:    canonicalPos{File: f.Position.File, Line: f.Position.Line},
			Signature:   f.Signature,
			TypeParams:  tps,
		}
	}

	toValues := func(vs []ValueDecl) []canonicalValue {
		out := make([]canonicalValue, len(vs))
		for i, v := range vs {
			out[i] = canonicalValue{
				Doc:         v.Doc,
				IsGenerated: v.IsGenerated,
				Name:        v.Name,
				Position:    canonicalPos{File: v.Position.File, Line: v.Position.Line},
				Type:        v.Type,
			}
		}
		return out
	}

	failures := make([]canonicalFailure, len(p.ParseFailures))
	for i, f := range p.ParseFailures {
		failures[i] = canonicalFailure{File: f.File, Error: f.Error}
	}

	return canonicalPkg{
		Consts:        toValues(p.Consts),
		Doc:           p.Doc,
		Funcs:         funcs,
		ImportPath:    p.ImportPath,
		IsInternal:    p.IsInternal,
		IsMain:        p.IsMain,
		OutOfFrame:    p.OutOfFrame,
		Name:          p.Name,
		ParseFailures: failures,
		Types:         types,
		Vars:          toValues(p.Vars),
	}
}

func fromCanonicalPackage(cp canonicalPkg) PackageInterface {
	types := make([]TypeDecl, len(cp.Types))
	for i, ct := range cp.Types {
		fields := make([]FieldDecl, len(ct.Fields))
		for j, f := range ct.Fields {
			fields[j] = FieldDecl{
				Doc:         f.Doc,
				Embedded:    f.Embedded,
				IsGenerated: f.IsGenerated,
				Name:        f.Name,
				Position:    SourcePosition{File: f.Position.File, Line: f.Position.Line},
				Tag:         f.Tag,
				Type:        f.Type,
			}
		}
		methods := make([]MethodDecl, len(ct.Methods))
		for j, m := range ct.Methods {
			methods[j] = MethodDecl{
				Doc:         m.Doc,
				Name:        m.Name,
				Position:    SourcePosition{File: m.Position.File, Line: m.Position.Line},
				PtrReceiver: m.PtrReceiver,
				Signature:   m.Signature,
			}
		}
		tps := make([]TypeParam, len(ct.TypeParams))
		for j, tp := range ct.TypeParams {
			tps[j] = TypeParam{Name: tp.Name, Constraint: tp.Constraint}
		}
		embedded := make([]string, len(ct.EmbeddedTypes))
		copy(embedded, ct.EmbeddedTypes)
		types[i] = TypeDecl{
			Doc:           ct.Doc,
			EmbeddedTypes: embedded,
			Fields:        fields,
			IsGenerated:   ct.IsGenerated,
			Kind:          TypeKind(ct.Kind),
			Methods:       methods,
			Name:          ct.Name,
			Position:      SourcePosition{File: ct.Position.File, Line: ct.Position.Line},
			Signature:     ct.Signature,
			TypeParams:    tps,
		}
	}

	funcs := make([]FuncDecl, len(cp.Funcs))
	for i, f := range cp.Funcs {
		tps := make([]TypeParam, len(f.TypeParams))
		for j, tp := range f.TypeParams {
			tps[j] = TypeParam{Name: tp.Name, Constraint: tp.Constraint}
		}
		funcs[i] = FuncDecl{
			Doc:         f.Doc,
			IsGenerated: f.IsGenerated,
			Name:        f.Name,
			Position:    SourcePosition{File: f.Position.File, Line: f.Position.Line},
			Signature:   f.Signature,
			TypeParams:  tps,
		}
	}

	fromValues := func(cvs []canonicalValue) []ValueDecl {
		out := make([]ValueDecl, len(cvs))
		for i, v := range cvs {
			out[i] = ValueDecl{
				Doc:         v.Doc,
				IsGenerated: v.IsGenerated,
				Name:        v.Name,
				Position:    SourcePosition{File: v.Position.File, Line: v.Position.Line},
				Type:        v.Type,
			}
		}
		return out
	}

	failures := make([]ParseFailure, len(cp.ParseFailures))
	for i, f := range cp.ParseFailures {
		failures[i] = ParseFailure{File: f.File, Error: f.Error}
	}

	return PackageInterface{
		Consts:        fromValues(cp.Consts),
		Doc:           cp.Doc,
		Funcs:         funcs,
		ImportPath:    cp.ImportPath,
		IsInternal:    cp.IsInternal,
		IsMain:        cp.IsMain,
		OutOfFrame:    cp.OutOfFrame,
		Name:          cp.Name,
		ParseFailures: failures,
		Types:         types,
		Vars:          fromValues(cp.Vars),
	}
}
