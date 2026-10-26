package cli

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	fetchsqlite "code.eitanity.com/kanonarion/internal/adapters/factstore/sqlite"
	cgapp "code.eitanity.com/kanonarion/internal/callgraph/application"
	cgdomain "code.eitanity.com/kanonarion/internal/callgraph/domain"
	cgports "code.eitanity.com/kanonarion/internal/callgraph/ports"
	"code.eitanity.com/kanonarion/internal/coordinate"
	exsqlite "code.eitanity.com/kanonarion/internal/example/adapters/store/sqlite"
	exapp "code.eitanity.com/kanonarion/internal/example/application"
	exdomain "code.eitanity.com/kanonarion/internal/example/domain"
	exampleports "code.eitanity.com/kanonarion/internal/example/ports"
	fetchdomain "code.eitanity.com/kanonarion/internal/fetch/domain"
	ifaceapp "code.eitanity.com/kanonarion/internal/iface/application"
	ifacedomain "code.eitanity.com/kanonarion/internal/iface/domain"
	ifaceports "code.eitanity.com/kanonarion/internal/iface/ports"
	licsqlite "code.eitanity.com/kanonarion/internal/license/adapters/store/sqlite"
	licapp "code.eitanity.com/kanonarion/internal/license/application"
	licdomain "code.eitanity.com/kanonarion/internal/license/domain"
	licenceports "code.eitanity.com/kanonarion/internal/license/ports"
	vuldomain "code.eitanity.com/kanonarion/internal/vuln/domain"
	walkdomain "code.eitanity.com/kanonarion/internal/walk/domain"
	walkports "code.eitanity.com/kanonarion/internal/walk/ports"
)

func buildCommandsWithWalk(coord coordinate.ModuleCoordinate, walkID string, verification contextVerification, basis basisWalk) contextCommands {
	mod := coord.Path() + "@" + coord.Version()
	cmds := contextProducers(coord, verification.Status != sectionStatusNotFetched, basisDir(coord, basis))
	cmds.CallGraphNav = "kanonarion callers <symbol> | kanonarion callees <symbol>"
	cmds.Vulnerabilities = vulnProducer(coord, walkID, basis)
	cmds.Dependents = "kanonarion dependents " + mod
	return cmds
}

// vulnProducer scans the walk the document reads, or one rooted at coord; with
// neither, inspect walks and scans the coordinate itself. A working tree or the
// standard library outside any walk has no single invocation, so it gets none.
func vulnProducer(coord coordinate.ModuleCoordinate, walkID string, basis basisWalk) string {
	switch {
	case walkID != "":
		return "kanonarion vuln-scan " + walkID
	case basis.held():
		return "kanonarion vuln-scan " + basis.rec.ID
	case cgdomain.IsReFetchable(coord):
		return "kanonarion inspect " + coord.String()
	}
	return ""
}

// contextProducers names the invocation that produces each record a section
// reports not run. Every producer refuses a module the store has not acquired,
// so the acquisition leads where it is missing; "" where nothing here acquires it.
func contextProducers(coord coordinate.ModuleCoordinate, fetched bool, dir string) contextCommands {
	var cmds contextCommands
	if line, ok := cgdomain.ReanalysisCommand(coord, dir, false); ok {
		cmds.CallGraph = line + targetFlagHint()
	}
	licenseLine := "kanonarion license " + coord.String()
	var acquire string
	switch {
	case fetched:
	case cgdomain.IsReFetchable(coord):
		acquire = "kanonarion fetch " + coord.String()
	case coord.IsLocal() && dir != "":
		acquire = "kanonarion walk --gomod " + filepath.Join(dir, "go.mod") + " --analyse-root"
	default:
		// The standard library's licence comes off its custody chain, not a fetch.
		cmds.License = licenseLine
		return cmds
	}
	ifaceLine := "kanonarion interface " + coord.String()
	examplesLine := "kanonarion examples " + coord.String()
	cmds.Interface, cmds.Examples, cmds.License = andThen(acquire, ifaceLine), andThen(acquire, examplesLine), andThen(acquire, licenseLine)
	return cmds
}

// andThen runs then after first, or alone when there is no first.
func andThen(first, then string) string {
	if first == "" {
		return then
	}
	return first + " && " + then
}

// basisDir is the working tree behind a local coordinate when the document's
// walk was rooted at it, and "" otherwise.
func basisDir(coord coordinate.ModuleCoordinate, basis basisWalk) string {
	if !coord.IsLocal() || !basis.held() || basis.rec.Target != coord {
		return ""
	}
	return basis.rec.ProjectDir
}

func isoTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func buildVerification(ctx context.Context, coord coordinate.ModuleCoordinate, uc QueryFetchUseCase) contextVerification {
	rec, found, err := uc.ComposeFetchRecord(ctx, coord)
	aside, none := sectionSetAside(fetchsqlite.RecordKind, coord, err)
	if none {
		return contextVerification{Status: sectionStatusSetAside, Error: aside.statement(), SetAside: aside.json()}
	}
	if err != nil {
		// A divergence is named as such rather than folded into a generic read
		// error. This command inspects the store, so it reports the contradiction
		// and still exits 0; the commands that consume the records fail closed.
		if msg, ok := divergenceMessage(err); ok {
			return contextVerification{Status: sectionStatusDivergent, Error: msg}
		}
		return contextVerification{Status: sectionStatusReadError, Error: err.Error()}
	}
	if !found {
		return contextVerification{Status: sectionStatusNotFetched}
	}
	return contextVerification{
		// First seen, not last measured: a revalidation re-establishes the anchors
		// but does not make the artefact newer.
		ExtractedAt: ledgerStamp(rec.FirstFetchedAt),
		Status:      rec.VerificationStatus,
		GitURL:      rec.GitURL,
		Retracted:   rec.Retracted,
		SetAside:    aside.json(),
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

// basisWalk is the walk a context document is based on: the build every section
// of that document answers in. It is resolved once per document and handed to
// the sections, never re-selected by one of them.
//
// A section that ran its own selection could return a different walk from the
// one the document names, which is the same document reporting two builds. The
// dependency section did exactly that — it looked only at walks rooted at the
// queried module, so a module a project walk holds had its dependencies reported
// as unmeasured one line above the walk that resolved them.
type basisWalk struct {
	rec *walkdomain.WalkRecord
	// err is the store fault that stopped a NAMED basis walk being read. A
	// section may not answer in another build because this one was unreadable, so
	// it reports the fault instead.
	err error
}

// held reports whether a basis walk was named and read.
func (b basisWalk) held() bool { return b.rec != nil }

// resolveBasisWalk reads the walk a document is based on. A caller that names no
// walk gets the zero value, which is not an error: the document then has no
// basis, and the sections say what they can from their own reads.
func resolveBasisWalk(ctx context.Context, walkUC QueryWalksUseCase, walkID string) basisWalk {
	if walkID == "" {
		return basisWalk{}
	}
	rec, err := walkUC.GetWalk(ctx, walkID)
	if err != nil {
		return basisWalk{err: fmt.Errorf("reading the walk this report is based on (%s): %w", walkID, err)}
	}
	return basisWalk{rec: &rec}
}

// walkAsBasis wraps a walk record the caller already holds — `context --walk-id`
// and the size-only path both load the walk before anything else, and the report
// is about that walk.
func walkAsBasis(rec walkdomain.WalkRecord) basisWalk { return basisWalk{rec: &rec} }

// buildDependencies lists the module's direct dependencies as the walk this
// document is based on resolved them.
//
// The basis walk answers wherever it holds the module, and the section names it.
// One document therefore reports one build, and the count is that build's: a
// module's dependency set differs between frames by scope and by resolved
// version — measured, 15 in a module's own walk against 10 in a consumer's,
// where the consumer build drops three test-only dependencies and MVS raises a
// fourth from v1.7.0 to v1.10.0.
//
// With no basis walk — a document whose other sections named no build — the
// section falls back to the walks rooted at the queried module and runs the same
// rule every other defaulting read runs: prefer a walk whose recorded resolution
// still agrees with the manifest it was taken from, fall back to recency. There
// is no basis line for that choice to contradict.
//
// Either way the answering walk is named rather than left to be inferred:
// WalkID, Frame and Rooting travel on the section, and the summary line prints
// the walk and its frame beside the count.
func buildDependencies(ctx context.Context, coord coordinate.ModuleCoordinate, walkUC QueryWalksUseCase, basis basisWalk) contextDependencies {
	if basis.err != nil {
		return contextDependencies{Status: sectionStatusReadError, Error: basis.err.Error()}
	}
	if basis.held() {
		return dependenciesInWalk(coord, *basis.rec)
	}

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
	return dependenciesInWalk(coord, rec)
}

// dependenciesInWalk answers the section out of one walk's graph, and names that
// walk.
//
// A walk that does not hold the module is reported as exactly that. It is not
// not_run: the module has not been left unmeasured, it was not part of the build
// this document is about, and the remedy for the two is different.
func dependenciesInWalk(coord coordinate.ModuleCoordinate, rec walkdomain.WalkRecord) contextDependencies {
	out := contextDependencies{
		WalkID:     rec.ID,
		Frame:      rec.Graph.Frame().Text,
		FrameBasis: string(rec.Graph.Frame().Basis),
	}
	if !rec.Target.IsZero() {
		out.Rooting = string(vuldomain.TargetRootedAt(rec.Target))
	}

	direct, held := rec.Graph.DirectDependenciesOf(coord)
	if !held {
		out.Status = sectionStatusNotInWalk
		return out
	}

	deps := make([]contextDependency, 0, len(direct))
	for _, d := range direct {
		deps = append(deps, contextDependency{Path: d.Path(), Version: d.Version()})
	}

	// "(no direct dependencies)" under a +incompatible coordinate is the exact
	// sentence this caveat exists to qualify: the module system never resolved
	// any, so the list is empty for a reason that has nothing to do with the
	// module's real dependency set.
	out.Status = rec.OverallStatus.String()
	out.Count = len(deps)
	out.Partial = rec.Graph.Partial
	out.PreModulesCaveat = preModulesCaveatFor(append(preModulesNodesIn(rec.Graph), coord)...)
	if len(deps) > 0 {
		out.Dependencies = deps
	}
	return out
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
	aside, none := sectionSetAside(licsqlite.RecordKind, coord, err)
	if none {
		return contextLicense{Status: sectionStatusSetAside, Error: aside.statement(), SetAside: aside.json()}
	}
	if err != nil {
		return contextLicense{Status: failedReadStatus(err, licenceports.ErrLicenceConflict), Error: err.Error()}
	}
	if !found {
		if line := supersededLicenceLine(ctx, uc, coord); line != "" {
			return contextLicense{Status: sectionStatusSuperseded, Error: line}
		}
		return contextLicense{Status: sectionStatusNotRun}
	}
	// The section names the licence covering the module's code, read through
	// what each of the record's licences covers — never a bundled font's or a
	// documentation licence, which is what `spdx` used to be able to hold.
	covered := licdomain.ReadCoverage(rec)
	l := contextLicense{
		ExtractedAt:     ledgerStamp(rec.ExtractedAt),
		SPDX:            covered.PrimarySPDX,
		Status:          rec.OverallStatus.String(),
		CopyrightStatus: rec.CopyrightStatus.String(),
		Error:           rec.FailureDetail,
		SetAside:        aside.json(),
	}
	// When the root licence could not be classified, surface any recognisable
	// but sub-threshold fragment (highest-coverage root-level match) so the
	// consumer sees "licence present, low-confidence X" rather than blank.
	if covered.PrimarySPDX == "" {
		noteLowConfidenceFragment(&l, rec)
	}
	if rec.CopyrightStatus == licdomain.CopyrightStatusFound {
		stmts := contextCopyrightStatements(rec)
		l.CopyrightStatements = stmts
	}
	// A conjunctive expression names several licences, and PrimarySPDX is a
	// backward-compatibility shim holding one of them: deriving from it alone
	// reported a fraction of the duties as though it were the set. What may be
	// said instead turns on the record's own basis — see readLicenceObligations.
	reading := readLicenceObligations(rec)
	if covered.PrimarySPDX != "" || len(reading.Arms) > 0 {
		l.Obligations = contextObligationsOf(reading.Set)
	}
	if len(reading.Arms) > 0 {
		l.BindingObligations = make(map[string]*contextLicenseObligations, len(reading.Arms))
		for _, arm := range reading.Arms {
			l.BindingObligations[arm] = contextObligationsOf(licdomain.LookupObligations(arm))
		}
		l.ArmGrants = reading.Grants
		if reading.Maximal {
			l.ObligationsReading = obligationsReadingMaximal
		}
	}
	return l
}

// noteLowConfidenceFragment records the highest-coverage sub-threshold match
// among the non-vendored licence files.
func noteLowConfidenceFragment(l *contextLicense, rec licdomain.LicenseRecord) {
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

// contextCopyrightStatements is every distinct copyright statement the
// record's licence files carry, in file order.
func contextCopyrightStatements(rec licdomain.LicenseRecord) []contextCopyrightStatement {
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
	return stmts
}

// contextObligationsOf projects an obligation set onto the context document.
// One projection for every obligations section the document carries, so the
// union, the per-arm sets and the standard library's cannot drift in how they
// spell the same fact.
func contextObligationsOf(ob licdomain.Obligations) *contextLicenseObligations {
	return &contextLicenseObligations{
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
	// answer.SPDX is walkdomain.StdlibLicense's resolution — one identifier,
	// never an expression — so a single lookup is the whole answer here.
	l.Obligations = contextObligationsOf(licdomain.LookupObligations(answer.SPDX))
	return l
}

func buildInterface(ctx context.Context, coord coordinate.ModuleCoordinate, uc QueryInterfaceUseCase, compact bool, pkgFilter string) contextInterface {
	rec, found, err := uc.GetInterfaceRecord(ctx, coord, ifaceapp.PipelineVersion)
	if err != nil {
		return contextInterface{Status: failedReadStatus(err, ifaceports.ErrInterfaceConflict), Error: err.Error()}
	}
	if !found {
		// "Never extracted" and "extracted under logic this build no longer
		// serves" both read as an absent record here, and the section's remedy
		// differs: one is still waiting to be run, the other has been run and
		// must be run again. Reported with the reason rather than as a bare
		// not_run, which a reader would take as "nobody has looked yet".
		if pipelines, superseded := supersededInterfaceRecord(ctx, uc, coord); superseded {
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
		// Carried whatever --package names: a filtered view is still short of them.
		AnalyserLimit: toAnalyserLimitJSON(rec.AnalyserLimit),
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
		cp := contextPackageOf(pkg, compact)
		out.Packages = append(out.Packages, cp)
	}
	return out
}

// contextPackageOf lists one package's exported declarations, doc comments
// stripped when compact.
func contextPackageOf(pkg ifacedomain.PackageInterface, compact bool) contextPackage {
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
	return cp
}

// contextCallGraphMiss is the section for a coordinate no graph is served
// for: held under other frames, held only at superseded pipelines, or not run.
// Both reads are the coordinate's own key columns.
func contextCallGraphMiss(ctx context.Context, coord coordinate.ModuleCoordinate, uc QueryCallGraphUseCase) contextCallGraph {
	unserved, err := uc.UnservedCoordinates(ctx, []coordinate.ModuleCoordinate{coord}, cgapp.PipelineVersion)
	if err != nil || len(unserved) == 0 {
		return contextCallGraph{Status: sectionStatusNotRun}
	}
	u := unserved[0]
	if len(u.Frames) > 0 {
		frames, flags := cgdomain.HeldFrames(frameRecords(u.Frames), cgdomain.BuildFrame{})
		return contextCallGraph{Status: sectionStatusOtherFrame, HeldFrames: frames, ReadWith: flags}
	}
	if len(u.Pipelines) > 0 && !slices.Contains(u.Pipelines, cgapp.PipelineVersion) {
		return contextCallGraph{Status: sectionStatusSuperseded, Error: supersededRecordLine("call graph", coord,
			cgapp.PipelineVersion, u.Pipelines, "Re-analyse", frameReanalysis(coord, u.AnalysisRoot))}
	}
	return contextCallGraph{Status: sectionStatusNotRun}
}

// buildCallGraph answers the call-graph section and the capability section
// derived from the same record, so the graph is loaded once per coordinate.
func buildCallGraph(ctx context.Context, coord coordinate.ModuleCoordinate, uc QueryCallGraphUseCase, entryPointsFull bool, pkgFilter string) (contextCallGraph, contextCapability) {
	rec, found, err := uc.GetCallGraphRecord(ctx, coord, cgapp.PipelineVersion)
	if err != nil {
		cg := contextCallGraph{Status: failedReadStatus(err, cgports.ErrCallGraphConflict), Error: err.Error()}
		return cg, capabilityFollowing(cg)
	}
	if !found {
		cg := contextCallGraphMiss(ctx, coord, uc)
		return cg, capabilityFollowing(cg)
	}
	out := contextCallGraph{
		ExtractedAt: ledgerStamp(rec.ExtractedAt),
		Status:      rec.OverallStatus.String(),
		Algorithm:   string(rec.Algorithm),
		NodeCount:   rec.NodeCount,
		EdgeCount:   rec.EdgeCount,
		Error:       rec.FailureDetail,
	}
	if pkgFilter != "" {
		out.NodeCount, out.EdgeCount = packageGraphCounts(rec, pkgFilter)
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
	return out, buildCapability(coord, rec)
}

// packageGraphCounts is the number of nodes in pkgFilter and of edges leaving
// them.
func packageGraphCounts(rec cgdomain.CallGraphRecord, pkgFilter string) (int, int) {
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
	return filteredNodes, filteredEdges
}

const compactExampleBodyLimit = 500

func buildExamples(ctx context.Context, coord coordinate.ModuleCoordinate, uc QueryExamplesUseCase, compact bool, pkgFilter string) contextExamples {
	rec, found, err := uc.GetExampleRecord(ctx, coord, exapp.PipelineVersion)
	aside, none := sectionSetAside(exsqlite.RecordKind, coord, err)
	if none {
		return contextExamples{Status: sectionStatusSetAside, Error: aside.statement(), SetAside: aside.json()}
	}
	if err != nil {
		return contextExamples{Status: failedReadStatus(err, exampleports.ErrExampleConflict), Error: err.Error()}
	}
	if !found {
		if line := supersededExamplesLine(ctx, uc, coord); line != "" {
			return contextExamples{Status: sectionStatusSuperseded, Error: line}
		}
		return contextExamples{Status: sectionStatusNotRun}
	}
	out := contextExamples{
		ExtractedAt: isoTime(rec.ExtractedAt),
		Status:      rec.OverallStatus.String(),
		Error:       rec.FailureDetail,
		SetAside:    aside.json(),
		// Carried whatever --package names: an unread file may be in that package.
		AnalyserLimit: toAnalyserLimitJSON(rec.AnalyserLimit),
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

// failedReadStatus is the section status for a record read that failed with
// err: conflict when it carries the store's disagreement sentinel, so the
// section states the dispute rather than calling the store unreadable, and
// read_error otherwise.
func failedReadStatus(err, conflict error) string {
	if errors.Is(err, conflict) {
		return sectionStatusConflict
	}
	return sectionStatusReadError
}
