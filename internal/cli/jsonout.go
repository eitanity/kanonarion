package cli

import ifacedomain "github.com/eitanity/kanonarion/internal/iface/domain"

// This file holds curated, snake_case JSON DTOs for the CLI public surface.
// Raw domain structs must never be marshalled directly: their Go field names
// (PascalCase) leak internal implementation detail and produce an inconsistent
// schema across commands. Mapping through these DTOs keeps the machine-
// readable output stable and uniform.

type sourcePositionJSON struct {
	File string `json:"file,omitempty"`
	Line int    `json:"line,omitempty"`
}

type typeParamJSON struct {
	Name       string `json:"name"`
	Constraint string `json:"constraint"`
}

type fieldDeclJSON struct {
	Name        string             `json:"name"`
	Type        string             `json:"type"`
	Tag         string             `json:"tag,omitempty"`
	Doc         string             `json:"doc,omitempty"`
	Embedded    bool               `json:"embedded"`
	Position    sourcePositionJSON `json:"position"`
	IsGenerated bool               `json:"is_generated"`
}

type methodDeclJSON struct {
	Name        string             `json:"name"`
	Signature   string             `json:"signature"`
	Doc         string             `json:"doc,omitempty"`
	Position    sourcePositionJSON `json:"position"`
	PtrReceiver bool               `json:"ptr_receiver"`
}

type typeDeclJSON struct {
	Name          string             `json:"name"`
	Kind          string             `json:"kind"`
	Signature     string             `json:"signature"`
	Doc           string             `json:"doc,omitempty"`
	TypeParams    []typeParamJSON    `json:"type_params,omitempty"`
	Fields        []fieldDeclJSON    `json:"fields,omitempty"`
	Methods       []methodDeclJSON   `json:"methods,omitempty"`
	EmbeddedTypes []string           `json:"embedded_types,omitempty"`
	Position      sourcePositionJSON `json:"position"`
	IsGenerated   bool               `json:"is_generated"`
}

type funcDeclJSON struct {
	Name        string             `json:"name"`
	Signature   string             `json:"signature"`
	Doc         string             `json:"doc,omitempty"`
	TypeParams  []typeParamJSON    `json:"type_params,omitempty"`
	Position    sourcePositionJSON `json:"position"`
	IsGenerated bool               `json:"is_generated"`
}

type valueDeclJSON struct {
	Name        string             `json:"name"`
	Type        string             `json:"type,omitempty"`
	Doc         string             `json:"doc,omitempty"`
	Position    sourcePositionJSON `json:"position"`
	IsGenerated bool               `json:"is_generated"`
}

type parseFailureJSON struct {
	File  string `json:"file"`
	Error string `json:"error"`
}

type packageInterfaceJSON struct {
	ImportPath    string             `json:"import_path"`
	Name          string             `json:"name"`
	Doc           string             `json:"doc,omitempty"`
	Types         []typeDeclJSON     `json:"types"`
	Funcs         []funcDeclJSON     `json:"funcs"`
	Consts        []valueDeclJSON    `json:"consts"`
	Vars          []valueDeclJSON    `json:"vars"`
	ParseFailures []parseFailureJSON `json:"parse_failures,omitempty"`
	IsInternal    bool               `json:"is_internal"`
	IsMain        bool               `json:"is_main"`
}

type interfaceRecordJSON struct {
	SchemaVersion   string                 `json:"schema_version"`
	Coordinate      coordinateJSON         `json:"coordinate"`
	Packages        []packageInterfaceJSON `json:"packages"`
	OverallStatus   string                 `json:"overall_status"`
	FailureDetail   string                 `json:"failure_detail,omitempty"`
	ExtractedAt     string                 `json:"extracted_at"`
	PipelineVersion string                 `json:"pipeline_version"`
	ContentHash     string                 `json:"content_hash"`
}

func toPosJSON(p ifacedomain.SourcePosition) sourcePositionJSON {
	return sourcePositionJSON{File: p.File, Line: p.Line}
}

func toTypeParamsJSON(ps []ifacedomain.TypeParam) []typeParamJSON {
	if len(ps) == 0 {
		return nil
	}
	out := make([]typeParamJSON, 0, len(ps))
	for _, p := range ps {
		out = append(out, typeParamJSON{Name: p.Name, Constraint: p.Constraint})
	}
	return out
}

func toInterfaceRecordJSON(r ifacedomain.InterfaceRecord) interfaceRecordJSON {
	pkgs := make([]packageInterfaceJSON, 0, len(r.Packages))
	for _, p := range r.Packages {
		types := make([]typeDeclJSON, 0, len(p.Types))
		for _, t := range p.Types {
			fields := make([]fieldDeclJSON, 0, len(t.Fields))
			for _, f := range t.Fields {
				fields = append(fields, fieldDeclJSON{
					Name: f.Name, Type: f.Type, Tag: f.Tag, Doc: f.Doc,
					Embedded: f.Embedded, Position: toPosJSON(f.Position), IsGenerated: f.IsGenerated,
				})
			}
			methods := make([]methodDeclJSON, 0, len(t.Methods))
			for _, m := range t.Methods {
				methods = append(methods, methodDeclJSON{
					Name: m.Name, Signature: m.Signature, Doc: m.Doc,
					Position: toPosJSON(m.Position), PtrReceiver: m.PtrReceiver,
				})
			}
			types = append(types, typeDeclJSON{
				Name: t.Name, Kind: t.Kind.String(), Signature: t.Signature, Doc: t.Doc,
				TypeParams: toTypeParamsJSON(t.TypeParams), Fields: fields, Methods: methods,
				EmbeddedTypes: t.EmbeddedTypes, Position: toPosJSON(t.Position), IsGenerated: t.IsGenerated,
			})
		}
		funcs := make([]funcDeclJSON, 0, len(p.Funcs))
		for _, f := range p.Funcs {
			funcs = append(funcs, funcDeclJSON{
				Name: f.Name, Signature: f.Signature, Doc: f.Doc,
				TypeParams: toTypeParamsJSON(f.TypeParams), Position: toPosJSON(f.Position), IsGenerated: f.IsGenerated,
			})
		}
		consts := make([]valueDeclJSON, 0, len(p.Consts))
		for _, c := range p.Consts {
			consts = append(consts, valueDeclJSON{Name: c.Name, Type: c.Type, Doc: c.Doc, Position: toPosJSON(c.Position), IsGenerated: c.IsGenerated})
		}
		vars := make([]valueDeclJSON, 0, len(p.Vars))
		for _, v := range p.Vars {
			vars = append(vars, valueDeclJSON{Name: v.Name, Type: v.Type, Doc: v.Doc, Position: toPosJSON(v.Position), IsGenerated: v.IsGenerated})
		}
		var pfs []parseFailureJSON
		for _, pf := range p.ParseFailures {
			pfs = append(pfs, parseFailureJSON{File: pf.File, Error: pf.Error})
		}
		pkgs = append(pkgs, packageInterfaceJSON{
			ImportPath: p.ImportPath, Name: p.Name, Doc: p.Doc,
			Types: types, Funcs: funcs, Consts: consts, Vars: vars,
			ParseFailures: pfs, IsInternal: p.IsInternal, IsMain: p.IsMain,
		})
	}
	return interfaceRecordJSON{
		SchemaVersion:   r.SchemaVersion,
		Coordinate:      coordinateJSON{Path: r.Coordinate.Path, Version: r.Coordinate.Version},
		Packages:        pkgs,
		OverallStatus:   r.OverallStatus.String(),
		FailureDetail:   r.FailureDetail,
		ExtractedAt:     isoTime(r.ExtractedAt),
		PipelineVersion: r.PipelineVersion,
		ContentHash:     r.ContentHash,
	}
}
