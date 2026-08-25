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
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	ifaceapp "github.com/eitanity/kanonarion/internal/iface/application"
	licapp "github.com/eitanity/kanonarion/internal/license/application"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

func buildCommandsWithWalk(coord coordinate.ModuleCoordinate, walkID string) contextCommands {
	mod := coord.Path() + "@" + coord.Version()
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
	rec, found, err := uc.ComposeFetchRecord(ctx, coord)
	if err != nil {
		// A divergence is named as such rather than folded into a generic read
		// error. This command inspects the store, so it reports the contradiction
		// and still exits 0; the commands that consume the records fail closed.
		if msg, ok := divergenceMessage(err); ok {
			return contextVerification{Status: sectionStatusReadError, Error: msg}
		}
		return contextVerification{Status: sectionStatusReadError, Error: err.Error()}
	}
	if !found {
		return contextVerification{Status: sectionStatusNotFetched}
	}
	return contextVerification{
		// First seen, not last measured: a revalidation re-establishes the anchors
		// but does not make the artefact newer.
		ExtractedAt: isoTime(rec.FirstFetchedAt),
		Status:      rec.VerificationStatus,
		GitURL:      rec.GitURL,
		Retracted:   rec.Retracted,
	}
}

// buildProvenance runs the name-path fork heuristic over the module path.
// The heuristic is a pure function of the coordinate, so the section is
// always analysed here — its status is never "not_analysed".
func buildProvenance(coord coordinate.ModuleCoordinate) contextProvenance {
	fp := fetchdomain.InferForkProvenance(coord.Path())
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

// buildDependencies lists the module's direct dependencies as one walk resolved
// them.
//
// Which walk is a choice wherever the store holds more than one of this target,
// and the different walks carry different sets: two scopes of one project select
// different modules, and two platforms select different files and so different
// modules again. The choice therefore runs the same rule every other defaulting
// read runs — prefer a walk whose recorded resolution still agrees with the
// manifest it was taken from, fall back to recency — rather than taking whatever
// is newest.
//
// The rule is applied but not narrated here. This section is a JSON field of a
// document with no prose channel, and the pin the notice would advertise does
// not exist for this command: `context --walk-id` means "emit a document per
// module of that walk", not "answer this module in that walk". What the document
// does carry is WalkID and Frame, so the walk that answered is always nameable
// from the answer.
func buildDependencies(ctx context.Context, coord coordinate.ModuleCoordinate, walkUC QueryWalksUseCase) contextDependencies {
	walks, err := walkUC.ListWalks(ctx, walkports.WalkFilter{Target: &coord})
	if err != nil {
		return contextDependencies{Status: sectionStatusReadError, Error: err.Error()}
	}
	if len(walks) == 0 {
		return contextDependencies{Status: sectionStatusNotRun}
	}

	rec, err := chooseWalk(ctx, walkUC, walks, "").walkRecord(ctx, walkUC)
	if err != nil {
		return contextDependencies{Status: sectionStatusReadError, Error: err.Error()}
	}

	var deps []contextDependency
	for _, node := range rec.Graph.Nodes {
		if !node.DirectDependency {
			continue
		}
		deps = append(deps, contextDependency{
			Path:    node.Coordinate.Path(),
			Version: node.Coordinate.Version(),
		})
	}
	// Graph.Nodes is sorted lexicographically by (Path, Version) after Sort.

	// "(no direct dependencies)" under a +incompatible coordinate is the exact
	// sentence this caveat exists to qualify: the module system never resolved
	// any, so the list is empty for a reason that has nothing to do with the
	// module's real dependency set.
	return contextDependencies{
		Status:           rec.OverallStatus.String(),
		WalkID:           rec.ID,
		Frame:            rec.Graph.Frame().Text,
		FrameBasis:       string(rec.Graph.Frame().Basis),
		Count:            len(deps),
		Partial:          rec.Graph.Partial,
		Dependencies:     deps,
		PreModulesCaveat: preModulesCaveatFor(append(preModulesNodesIn(rec.Graph), coord)...),
	}
}

func buildLicense(
	ctx context.Context,
	coord coordinate.ModuleCoordinate,
	uc QueryLicenseUseCase,
	custody StdlibCustodyReader,
) contextLicense {
	// The standard library is never fetched or extracted, so it holds no licence
	// record and an absent one here said not_run — "nothing looked" — about a
	// licence the same store serves to audit and the SBOM. Its identity comes
	// off the chain of custody instead.
	if isStdlibCoordinate(coord) {
		return buildStdlibLicense(ctx, coord, custody)
	}
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
			if l.LowConfidenceCoverage == nil || f.LowConfidenceCoverage > *l.LowConfidenceCoverage {
				coverage := f.LowConfidenceCoverage
				l.LowConfidenceSPDX = f.LowConfidenceSPDX
				l.LowConfidenceCoverage = &coverage
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

// buildStdlibLicense answers the licence section for the standard-library
// coordinate from its recorded chain of custody.
//
// The status word is the one audit prints for the same node: Detected when the
// identifier was extracted from the acquired source, Known when it is the
// published BSD-3-Clause and no measurement carried one. Neither is not_run,
// which is reserved for a section nothing has looked at.
func buildStdlibLicense(ctx context.Context, coord coordinate.ModuleCoordinate, custody StdlibCustodyReader) contextLicense {
	answer, err := resolveStdlibLicence(ctx, coord, custody)
	if err != nil {
		return contextLicense{Status: sectionStatusReadError, Error: err.Error()}
	}

	status := "Known"
	if answer.Basis == stdlibLicenceBasisTarball {
		status = licdomain.LicenseStatusDetected.String()
	}
	l := contextLicense{
		ExtractedAt: isoTime(answer.AcquiredAt),
		SPDX:        answer.SPDX,
		Status:      status,
		Custody: &contextLicenseCustody{
			Basis:        answer.Basis,
			Verification: answer.Verification,
			Detail:       answer.Detail,
			Route:        answer.Route,
			SourceURL:    answer.SourceURL,
			VCSURL:       answer.VCSURL,
			VCSRef:       answer.VCSRef,
			VCSCommit:    answer.VCSCommit,
			SHA256:       answer.SHA256,
			AcquiredAt:   isoTime(answer.AcquiredAt),
			Statement:    answer.basisStatement(),
		},
	}
	ob := licdomain.LookupObligations(answer.SPDX)
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
	return l
}

func buildInterface(ctx context.Context, coord coordinate.ModuleCoordinate, uc QueryInterfaceUseCase, compact bool, pkgFilter string) contextInterface {
	rec, found, err := uc.GetInterfaceRecord(ctx, coord, ifaceapp.PipelineVersion)
	if err != nil {
		return contextInterface{Status: sectionStatusReadError, Error: err.Error()}
	}
	if !found {
		// "Never extracted" and "extracted under logic this build no longer
		// serves" both read as an absent record here, and the section's remedy
		// differs: one is still waiting to be run, the other has been run and
		// must be run again. Reported with the reason rather than as a bare
		// not_run, which a reader would take as "nobody has looked yet".
		if pipelines, superseded := supersededInterfacePipelines(coord, storedInterfaceSummaries(ctx, uc)); superseded {
			return contextInterface{
				Status: sectionStatusSuperseded,
				Error:  supersededInterfaceLine(coord, pipelines),
			}
		}
		return contextInterface{Status: sectionStatusNotRun}
	}
	out := contextInterface{
		ExtractedAt: isoTime(rec.ExtractedAt),
		Status:      rec.OverallStatus.String(),
		BuildFrame:  rec.BuildFrame.String(),
		Error:       rec.FailureDetail,
	}
	for _, pkg := range rec.Packages {
		if pkg.IsInternal || pkg.IsMain {
			continue
		}
		// A package the build does not contain carries no declarations, and
		// listing it empty here would read as a package with no public API.
		if pkg.OutOfFrame {
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
			for _, m := range t.Methods {
				msig := m.Signature
				if compact {
					msig = stripDocComment(msig)
				}
				cp.Methods = append(cp.Methods, msig)
			}
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
		count := byPkg[pkgFilter]
		out.EntryPointCount = &count
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
		if pkgFilter == coord.Path() {
			pkgSubdir = "."
		} else {
			pkgSubdir = strings.TrimPrefix(pkgFilter, coord.Path()+"/")
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
