package cli

import (
	"context"
	"path/filepath"
	"strings"
	"time"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	"github.com/eitanity/kanonarion/internal/coordinate"
	exapp "github.com/eitanity/kanonarion/internal/example/application"
	exdomain "github.com/eitanity/kanonarion/internal/example/domain"
	fetchapp "github.com/eitanity/kanonarion/internal/fetch/application"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	ifaceapp "github.com/eitanity/kanonarion/internal/iface/application"
	licapp "github.com/eitanity/kanonarion/internal/license/application"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

func buildCommandsWithWalk(coord coordinate.ModuleCoordinate, walkID string) contextCommands {
	mod := coord.Path + "@" + coord.Version
	vulnCmd := "kanonarion vuln-show " + mod
	if walkID != "" {
		vulnCmd = "kanonarion vuln-scan " + walkID
	}
	return contextCommands{
		Interface:       "kanonarion interface-show " + mod,
		CallGraph:       "kanonarion callgraph-show " + mod,
		CallGraphNav:    "kanonarion callers <symbol> | kanonarion callees <symbol>",
		Examples:        "kanonarion examples-find <symbol> | kanonarion examples-show " + mod + " <name>",
		Vulnerabilities: vulnCmd,
		License:         "kanonarion license " + mod,
		Dependents:      "kanonarion dependents " + mod,
	}
}

func isoTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func buildVerification(ctx context.Context, coord coordinate.ModuleCoordinate, uc QueryFetchUseCase) contextVerification {
	rec, found, err := uc.GetFetchRecord(ctx, coord, fetchapp.PipelineVersion)
	if err != nil {
		return contextVerification{Status: sectionStatusReadError, Error: err.Error()}
	}
	if !found {
		return contextVerification{Status: sectionStatusNotFetched}
	}
	return contextVerification{
		ExtractedAt: isoTime(rec.FetchedAt),
		Status:      rec.VerificationStatus,
		GitURL:      rec.GitURL,
		Retracted:   rec.Retracted,
	}
}

// buildProvenance runs the name-path fork heuristic over the module path.
// The heuristic is a pure function of the coordinate, so the section is
// always analysed here — its status is never "not_analysed".
func buildProvenance(coord coordinate.ModuleCoordinate) contextProvenance {
	fp := fetchdomain.InferForkProvenance(coord.Path)
	out := contextForkHeuristic{
		Status:           fp.Status.String(),
		CatalogueVersion: fp.CatalogueVersion,
	}
	for _, ind := range fp.Indicators {
		out.ForkIndicators = append(out.ForkIndicators, contextForkIndicator{
			Canonical: ind.Canonical,
			Statement: ind.Statement,
		})
	}
	return contextProvenance{ForkHeuristic: out}
}

func buildDependencies(ctx context.Context, coord coordinate.ModuleCoordinate, walkUC QueryWalksUseCase) contextDependencies {
	walks, err := walkUC.ListWalks(ctx, walkports.WalkFilter{Target: &coord, Limit: 1})
	if err != nil {
		return contextDependencies{Status: sectionStatusReadError, Error: err.Error()}
	}
	if len(walks) == 0 {
		return contextDependencies{Status: sectionStatusNotRun}
	}

	rec, err := walkUC.GetWalk(ctx, walks[0].ID)
	if err != nil {
		return contextDependencies{Status: sectionStatusReadError, Error: err.Error()}
	}

	var deps []contextDependency
	for _, node := range rec.Graph.Nodes {
		if !node.DirectDependency {
			continue
		}
		deps = append(deps, contextDependency{
			Path:    node.Coordinate.Path,
			Version: node.Coordinate.Version,
		})
	}
	// Graph.Nodes is sorted lexicographically by (Path, Version) after Sort.

	return contextDependencies{
		Status:       rec.OverallStatus.String(),
		WalkID:       rec.ID,
		Count:        len(deps),
		Partial:      rec.Graph.Partial,
		Dependencies: deps,
	}
}

func buildLicense(ctx context.Context, coord coordinate.ModuleCoordinate, uc QueryLicenseUseCase) contextLicense {
	rec, found, err := uc.GetLicenseRecord(ctx, coord, licapp.PipelineVersion)
	if err != nil {
		return contextLicense{Status: sectionStatusReadError, Error: err.Error()}
	}
	if !found {
		return contextLicense{Status: sectionStatusNotRun}
	}
	l := contextLicense{
		ExtractedAt:     isoTime(rec.ExtractedAt),
		SPDX:            rec.PrimarySPDX,
		Status:          rec.OverallStatus.String(),
		CopyrightStatus: rec.CopyrightStatus.String(),
		Error:           rec.FailureDetail,
	}
	// When the root licence could not be classified, surface any recognisable
	// but sub-threshold fragment (highest-coverage root-level match) so the
	// consumer sees "licence present, low-confidence X" rather than blank.
	if rec.PrimarySPDX == "" {
		for _, f := range rec.LicenseFiles {
			if f.IsVendored || f.LowConfidenceSPDX == "" {
				continue
			}
			if f.LowConfidenceCoverage > l.LowConfidenceCoverage {
				l.LowConfidenceSPDX = f.LowConfidenceSPDX
				l.LowConfidenceCoverage = f.LowConfidenceCoverage
			}
		}
	}
	if rec.CopyrightStatus == licdomain.CopyrightStatusFound {
		var stmts []contextCopyrightStatement
		seen := make(map[string]struct{})
		for _, f := range rec.LicenseFiles {
			for _, s := range f.CopyrightStatements {
				if _, dup := seen[s.Verbatim]; dup {
					continue
				}
				seen[s.Verbatim] = struct{}{}
				stmts = append(stmts, contextCopyrightStatement{
					Verbatim: s.Verbatim,
					Holders:  s.Holders,
					Years:    s.Years,
					Source:   s.Source,
				})
			}
		}
		l.CopyrightStatements = stmts
	}
	if rec.PrimarySPDX != "" {
		ob := licdomain.LookupObligations(rec.PrimarySPDX)
		l.Obligations = &contextLicenseObligations{
			Status:              ob.Status.String(),
			IncludeNotice:       ob.IncludeNotice,
			IncludeLicenseText:  ob.IncludeLicenseText,
			StateChanges:        ob.StateChanges,
			DiscloseSource:      ob.DiscloseSource,
			SameLicense:         ob.SameLicense.String(),
			NetworkUseTrigger:   ob.NetworkUseTrigger,
			NoTrademarkUse:      ob.NoTrademarkUse,
			ExplicitPatentGrant: ob.ExplicitPatentGrant,
			CatalogueVersion:    licdomain.ObligationCatalogueVersion,
		}
	}
	return l
}

func buildInterface(ctx context.Context, coord coordinate.ModuleCoordinate, uc QueryInterfaceUseCase, compact bool, pkgFilter string) contextInterface {
	rec, found, err := uc.GetInterfaceRecord(ctx, coord, ifaceapp.PipelineVersion)
	if err != nil {
		return contextInterface{Status: sectionStatusReadError, Error: err.Error()}
	}
	if !found {
		return contextInterface{Status: sectionStatusNotRun}
	}
	out := contextInterface{
		ExtractedAt: isoTime(rec.ExtractedAt),
		Status:      rec.OverallStatus.String(),
		Error:       rec.FailureDetail,
	}
	for _, pkg := range rec.Packages {
		if pkg.IsInternal || pkg.IsMain {
			continue
		}
		if pkgFilter != "" && pkg.ImportPath != pkgFilter {
			continue
		}
		cp := contextPackage{ImportPath: pkg.ImportPath}
		for _, t := range pkg.Types {
			sig := t.Signature
			if compact {
				sig = stripDocComment(sig)
			}
			cp.Types = append(cp.Types, sig)
		}
		for _, fn := range pkg.Funcs {
			sig := fn.Signature
			if compact {
				sig = stripDocComment(sig)
			}
			cp.Funcs = append(cp.Funcs, sig)
		}
		for _, c := range pkg.Consts {
			name := c.Name
			if c.Type != "" {
				name = name + " " + c.Type
			}
			cp.Consts = append(cp.Consts, name)
		}
		for _, v := range pkg.Vars {
			name := v.Name
			if v.Type != "" {
				name = name + " " + v.Type
			}
			cp.Vars = append(cp.Vars, name)
		}
		out.Packages = append(out.Packages, cp)
	}
	return out
}

func buildCallGraph(ctx context.Context, coord coordinate.ModuleCoordinate, uc QueryCallGraphUseCase, entryPointsFull bool, pkgFilter string) contextCallGraph {
	rec, found, err := uc.GetCallGraphRecord(ctx, coord, cgapp.PipelineVersion)
	if err != nil {
		return contextCallGraph{Status: sectionStatusReadError, Error: err.Error()}
	}
	if !found {
		return contextCallGraph{Status: sectionStatusNotRun}
	}
	out := contextCallGraph{
		ExtractedAt: isoTime(rec.ExtractedAt),
		Status:      rec.OverallStatus.String(),
		Algorithm:   string(rec.Algorithm),
		NodeCount:   rec.NodeCount,
		EdgeCount:   rec.EdgeCount,
		Error:       rec.FailureDetail,
	}
	if pkgFilter != "" {
		pkgNodeIDs := make(map[string]struct{}, len(rec.Nodes))
		filteredNodes := 0
		for _, n := range rec.Nodes {
			if n.Package == pkgFilter {
				pkgNodeIDs[n.ID] = struct{}{}
				filteredNodes++
			}
		}
		filteredEdges := 0
		for _, e := range rec.Edges {
			if _, ok := pkgNodeIDs[e.FromID]; ok {
				filteredEdges++
			}
		}
		out.NodeCount = filteredNodes
		out.EdgeCount = filteredEdges
	}
	byPkg := make(map[string]int)
	for _, n := range rec.Nodes {
		if n.IsExportedAPI && !n.IsExternal {
			if pkgFilter != "" && n.Package != pkgFilter {
				continue
			}
			byPkg[n.Package]++
			if entryPointsFull {
				out.EntryPoints = append(out.EntryPoints, n.ID)
			}
		}
	}
	if pkgFilter != "" {
		out.EntryPointCount = byPkg[pkgFilter]
	} else if len(byPkg) > 0 {
		out.EntryPointsByPackage = byPkg
	}
	return out
}

const compactExampleBodyLimit = 500

func buildExamples(ctx context.Context, coord coordinate.ModuleCoordinate, uc QueryExamplesUseCase, compact bool, pkgFilter string) contextExamples {
	rec, found, err := uc.GetExampleRecord(ctx, coord, exapp.PipelineVersion)
	if err != nil {
		return contextExamples{Status: sectionStatusReadError, Error: err.Error()}
	}
	if !found {
		return contextExamples{Status: sectionStatusNotRun}
	}
	out := contextExamples{
		ExtractedAt: isoTime(rec.ExtractedAt),
		Status:      rec.OverallStatus.String(),
		Error:       rec.FailureDetail,
	}

	// Derive the module-relative subdirectory for the filtered package so we
	// can match ExampleEntry.Position.File without relying on the short package
	// name, which handles multi-level paths (e.g. sumdb/note) correctly.
	var pkgSubdir string
	if pkgFilter != "" {
		if pkgFilter == coord.Path {
			pkgSubdir = "."
		} else {
			pkgSubdir = strings.TrimPrefix(pkgFilter, coord.Path+"/")
		}
	}

	for _, ex := range rec.Examples {
		if pkgFilter != "" && filepath.Dir(ex.Position.File) != pkgSubdir {
			continue
		}
		out.Examples = append(out.Examples, exampleToContext(ex, compact))
	}
	out.Count = len(out.Examples)
	// "Found" means the module had examples, but after filtering to a specific
	// package the result may be empty — report "None" so consumers aren't misled.
	if pkgFilter != "" && out.Count == 0 && out.Status == "Found" {
		out.Status = "None"
	}
	return out
}

func exampleToContext(ex exdomain.ExampleEntry, compact bool) contextExample {
	body := ex.Body
	doc := ex.Doc
	if compact {
		if len(body) > compactExampleBodyLimit {
			body = body[:compactExampleBodyLimit] + "…"
		}
		doc = ""
	}
	return contextExample{
		Name:   ex.Name,
		Symbol: ex.AssociatedSymbol,
		Body:   body,
		Output: ex.Output,
		Doc:    doc,
	}
}

// stripDocComment removes leading // comment lines from a Go declaration
// signature, returning just the declaration itself.
func stripDocComment(sig string) string {
	lines := strings.Split(sig, "\n")
	for i, line := range lines {
		if !strings.HasPrefix(strings.TrimSpace(line), "//") {
			return strings.Join(lines[i:], "\n")
		}
	}
	return sig
}
