package application

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	"code.eitanity.com/kanonarion/internal/callgraph/domain"
	cgports "code.eitanity.com/kanonarion/internal/callgraph/ports"
	"code.eitanity.com/kanonarion/internal/coordinate"
	"code.eitanity.com/kanonarion/internal/versionorder"
)

// ImplementersRequest asks which concrete types satisfy an interface.
type ImplementersRequest struct {
	// InterfaceID is the interface, "pkg/path.Name", or one of its methods,
	// "pkg/path.(Name).Method".
	InterfaceID string
	// PipelineVersion selects which generation of each module's graph answers;
	// empty is PipelineVersion.
	PipelineVersion string
	// Scope restricts the search to these module versions; the zero ModuleSet
	// searches every analysed version.
	Scope coordinate.ModuleSet
	// Opts drops test implementations and prefers one toolchain's graphs.
	Opts cgports.EdgeQueryOptions
}

// Implementer is one concrete type satisfying the interface, with the record
// it was found in.
type Implementer struct {
	Implementation domain.InterfaceImplementation
	ModulePath     string
	ModuleVersion  string
	// NodeID is the concrete method satisfying the requested method; empty when
	// the request named the interface type.
	NodeID string
	// Foreign is the module the type belongs to when that is not the module
	// whose record holds it; zero for the searched module's own types.
	Foreign domain.ForeignModule
}

// ImplementersResult is an implementers answer. The relation is computed over
// the declaring module's own types: ModulePath is that module, and a type in
// another module that satisfies the interface is never looked at.
type ImplementersResult struct {
	InterfaceID string
	// Method is the method the request named; empty for the interface type.
	Method       string
	Interface    domain.InterfaceType
	ModulePath   string
	Implementers []Implementer
	// Answer is RESOLVED-PRESENT when an implementer was found, and
	// RESOLVED-ABSENT only when nothing about the analysis leaves room for a
	// missing one.
	Answer domain.Answer
	// NotSearched names the module's coordinates whose graphs are only at a
	// superseded pipeline, so they were not searched.
	NotSearched []cgports.UnservedCoordinate
}

// InterfaceNotDeclaredError is Implementers' answer when no record it may
// serve declares the interface.
type InterfaceNotDeclaredError struct {
	InterfaceID string
	// ModulePath is the analysed module the interface's path falls in, empty
	// when it falls in none.
	ModulePath     string
	ModuleAnalysed bool
	// ServedAny is whether any record of that module was served, so an
	// undeclared interface can be told from an unsearched one.
	ServedAny bool
	// AnalysedVersions are the module's analysed versions, newest first.
	AnalysedVersions []string
}

func (e *InterfaceNotDeclaredError) Error() string {
	if e.ModulePath == "" {
		return fmt.Sprintf("%q belongs to no module with a call graph in the store", e.InterfaceID)
	}
	return fmt.Sprintf("%q is not an interface declared by a served call graph of module %q", e.InterfaceID, e.ModulePath)
}

// SupersededModuleError is Implementers' answer when every stored graph of the
// interface's module is at a superseded pipeline: there is nothing to search,
// which is not the same as nothing implementing it.
type SupersededModuleError struct {
	InterfaceID     string
	ModulePath      string
	PipelineVersion string
	// Stored is every coordinate the store holds for the module.
	Stored []cgports.CallGraphCoordinate
}

func (e *SupersededModuleError) Error() string {
	return fmt.Sprintf("%q belongs to module %q, whose every stored call graph is at a superseded pipeline (this build serves %s); re-analyse the module",
		e.InterfaceID, e.ModulePath, e.PipelineVersion)
}

// Implementers lists the concrete types of the interface's own module whose
// method sets satisfy it, across every in-scope analysed version of that
// module, deduplicated on the type.
func (uc *QueryCallGraphUseCase) Implementers(ctx context.Context, req ImplementersRequest) (ImplementersResult, error) {
	return FindImplementers(ctx, uc, req)
}

// ImplementersReader is the part of QueryCallGraphUseCase an implementers
// answer reads.
type ImplementersReader interface {
	ListCallGraphCoordinates(ctx context.Context, filter cgports.CallGraphFilter) ([]cgports.CallGraphCoordinate, error)
	GetCallGraphRecordFrom(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string, req domain.ComposeRequest) (domain.CallGraphRecord, bool, error)
	UnservedCoordinates(ctx context.Context, coords []coordinate.ModuleCoordinate, pipelineVersion string) ([]cgports.UnservedCoordinate, error)
}

// FindImplementers is Implementers over r, so the implementers command and the
// library read one implementation.
func FindImplementers(ctx context.Context, r ImplementersReader, req ImplementersRequest) (ImplementersResult, error) {
	pv := servedPipeline(req.PipelineVersion)
	interfaceID, method, perMethod := domain.ParseInterfaceMethodID(req.InterfaceID)
	if !perMethod {
		interfaceID = req.InterfaceID
	}
	found, err := gatherImplementers(ctx, r, interfaceID, pv, req)
	if err != nil {
		return ImplementersResult{}, err
	}
	if !found.declared {
		return ImplementersResult{}, &InterfaceNotDeclaredError{
			InterfaceID: interfaceID, ModulePath: found.modulePath, ModuleAnalysed: found.moduleAnalysed,
			ServedAny: found.servedAny, AnalysedVersions: found.analysedVersions,
		}
	}
	if perMethod && !slices.Contains(found.iface.Methods, method) {
		return ImplementersResult{}, fmt.Errorf(
			"interface %q declares no method %q; its methods are %s",
			interfaceID, method, strings.Join(found.iface.Methods, ", "))
	}
	notSearched, err := r.UnservedCoordinates(ctx, found.supersededCoords, pv)
	if err != nil {
		return ImplementersResult{}, fmt.Errorf("naming the call graphs this answer could not read: %w", err)
	}

	impls := found.implementations
	if req.Opts.ExcludeTests {
		impls = slices.DeleteFunc(impls, func(im Implementer) bool { return im.Implementation.IsTest })
	}
	if perMethod {
		for i := range impls {
			impls[i].NodeID = methodNodeID(impls[i].Implementation, method)
		}
	} else {
		method = ""
	}
	return ImplementersResult{
		InterfaceID: interfaceID, Method: method, Interface: found.iface, ModulePath: found.modulePath,
		Implementers: impls, Answer: found.verdict(len(impls) > 0, req.Opts), NotSearched: notSearched,
	}, nil
}

// implementerLookup is the outcome of searching the in-scope records for an
// interface, with the soundness signals bearing on an empty answer.
type implementerLookup struct {
	iface            domain.InterfaceType
	declared         bool
	modulePath       string
	moduleAnalysed   bool
	analysedVersions []string
	implementations  []Implementer
	belowFull        domain.CompletenessLevel
	testScope        domain.TestScope
	testScopeDetail  string
	partialPkg       string
	partialDetail    string
	// supersededCoords are the module's coordinates held only at a superseded
	// pipeline: each would have been searched had it been re-derived.
	supersededCoords []coordinate.ModuleCoordinate
	servedAny        bool
}

// verdict classifies the answer. Presence is never downgraded: an implementer
// found is a type-level fact go/types decided exactly. An empty answer is a
// measurement only when nothing about the analysis leaves room for a missing
// one.
func (l implementerLookup) verdict(present bool, opts cgports.EdgeQueryOptions) domain.Answer {
	if present {
		return domain.Answer{Outcome: domain.AnswerResolvedPresent}
	}
	var sinks []domain.SoundnessSink
	if l.partialPkg != "" {
		// Its own kind, as callers and callees report it: a dropped package is a
		// build failure inside the analysed artefact, not a chosen level.
		sinks = append(sinks, domain.SoundnessSink{
			Kind:   domain.SinkDroppedPackageEdges,
			Site:   l.iface.ID,
			Detail: "package " + l.partialPkg + " " + domain.DroppedPackageReason(l.partialDetail) + ", so its edges were dropped",
		})
	}
	if l.belowFull != domain.CompletenessUnknown && !l.belowFull.IsBuiltWithBodies() {
		sinks = append(sinks, domain.SoundnessSink{
			Kind:   domain.SinkTypeOnlyCallee,
			Site:   l.iface.ID,
			Detail: "module completeness " + l.belowFull.String(),
		})
	}
	if !l.testScope.IsMeasured() && !opts.ExcludeTests {
		detail := l.testScopeDetail
		if detail == "" {
			detail = "_test.go declarations were not analysed for this module"
		}
		sinks = append(sinks, domain.SoundnessSink{
			Kind:   domain.SinkTestScopeUnmeasured,
			Site:   l.iface.ID,
			Detail: detail,
		})
	}
	if len(sinks) == 0 {
		return domain.Answer{Outcome: domain.AnswerResolvedAbsent}
	}
	return domain.Answer{Outcome: domain.AnswerUnresolved, Sinks: sinks}
}

// gatherImplementers searches every in-scope analysed record of the module
// owning interfaceID. A module analysed at several versions contributes each,
// and the result is their union deduplicated on the type ID: the same
// declaration at two versions is one answer to "what must change".
func gatherImplementers(ctx context.Context, r ImplementersReader, interfaceID, pv string, req ImplementersRequest) (implementerLookup, error) {
	var out implementerLookup
	out.testScope = domain.TestScopeAnalysed

	// Resolution reads everything the store holds so a module analysed only
	// under superseded logic is still recognised as owning the interface; the
	// answer itself is drawn only from what this pipeline serves.
	stored, err := coordinatesIn(ctx, r, req.Scope, cgports.CallGraphFilter{})
	if err != nil {
		return out, err
	}
	coords, err := coordinatesIn(ctx, r, req.Scope, cgports.CallGraphFilter{PipelineVersion: pv})
	if err != nil {
		return out, err
	}
	paths := make([]string, 0, len(stored))
	for _, c := range stored {
		paths = append(paths, c.ModulePath)
	}
	modulePath, ok := domain.ResolveSymbolModule(interfaceID, paths)
	if !ok {
		return out, nil
	}
	if !slices.ContainsFunc(coords, func(c cgports.CallGraphCoordinate) bool { return c.ModulePath == modulePath }) {
		// Empty here would read as "nothing implements this interface", a claim
		// about the code rather than about what has been measured.
		return out, &SupersededModuleError{InterfaceID: interfaceID, ModulePath: modulePath, PipelineVersion: pv, Stored: stored}
	}
	out.modulePath = modulePath
	out.moduleAnalysed = true
	out.analysedVersions = AnalysedVersions(modulePath, coords)
	if out.supersededCoords, err = supersededCoordinatesOf(modulePath, stored, coords); err != nil {
		return out, err
	}

	seen := make(map[string]struct{})
	for _, s := range coords {
		if s.ModulePath != modulePath {
			continue
		}
		coord, cErr := coordinate.NewModuleCoordinate(s.ModulePath, s.ModuleVersion)
		if cErr != nil {
			return out, fmt.Errorf("call graph record %s@%s names no module: %w", s.ModulePath, s.ModuleVersion, cErr)
		}
		rec, ok, gErr := r.GetCallGraphRecordFrom(ctx, coord, s.PipelineVersion, domain.ComposeRequest{ToolchainPreference: req.Opts.Toolchain})
		if gErr != nil {
			return out, fmt.Errorf("loading call graph for %s: %w", coord, gErr)
		}
		if !ok {
			continue
		}
		out.servedAny = true
		out.collect(rec, s, interfaceID, seen)
	}
	sort.Slice(out.implementations, func(i, j int) bool {
		return out.implementations[i].Implementation.TypeID < out.implementations[j].Implementation.TypeID
	})
	return out, nil
}

// collect adds what rec, the record at s, says about interfaceID: the
// declaration, each implementer not already seen, and the record's
// qualifications.
func (out *implementerLookup) collect(rec domain.CallGraphRecord, s cgports.CallGraphCoordinate, interfaceID string, seen map[string]struct{}) {
	iface, declared := domain.InterfaceByID(rec, interfaceID)
	if !declared {
		return
	}
	if !out.declared {
		out.iface = iface
		out.declared = true
	}
	impls, _ := domain.ImplementersOf(rec, interfaceID)
	for _, im := range impls {
		if _, dup := seen[im.TypeID]; dup {
			continue
		}
		seen[im.TypeID] = struct{}{}
		// A record can hold a nested module's declarations, built with bodies
		// under the parent's path prefix; naming the module the type belongs to
		// keeps it from reading as the searched module's own. Read off the
		// record, because this answer is the record.
		fm, _ := domain.ForeignModuleOwning(rec.ForeignModulesBuilt, im.TypeID)
		out.implementations = append(out.implementations, Implementer{
			Implementation: im, ModulePath: s.ModulePath, ModuleVersion: s.ModuleVersion, Foreign: fm,
		})
	}
	noteRecordQualifications(out, rec, interfaceID)
}

// coordinatesIn lists the analysed coordinates filter selects, restricted to
// scope.
func coordinatesIn(ctx context.Context, r ImplementersReader, scope coordinate.ModuleSet, filter cgports.CallGraphFilter) ([]cgports.CallGraphCoordinate, error) {
	coords, err := r.ListCallGraphCoordinates(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("listing analysed modules: %w", err)
	}
	if !scope.IsRestricted() {
		return coords, nil
	}
	return slices.DeleteFunc(coords, func(c cgports.CallGraphCoordinate) bool {
		return !scope.ContainsPathVersion(c.ModulePath, c.ModuleVersion)
	}), nil
}

// noteRecordQualifications records the first partial package, below-full
// completeness and unmeasured test scope a contributing record carries.
func noteRecordQualifications(out *implementerLookup, rec domain.CallGraphRecord, interfaceID string) {
	if rec.OverallStatus == domain.CallGraphStatusPartial && out.partialPkg == "" {
		if fp, hit := domain.SymbolFailedPackage(interfaceID, rec.FailedPackages); hit {
			out.partialPkg = fp
			out.partialDetail = rec.FailureDetail
		}
	}
	if out.belowFull == domain.CompletenessUnknown &&
		rec.Completeness != domain.CompletenessUnknown && !rec.Completeness.IsBuiltWithBodies() {
		out.belowFull = rec.Completeness
	}
	if !rec.TestScope.IsMeasured() && out.testScope.IsMeasured() {
		out.testScope = rec.TestScope
		out.testScopeDetail = rec.TestScopeDetail
	}
}

// AnalysedVersions are the versions of modulePath among coords, newest first.
func AnalysedVersions(modulePath string, coords []cgports.CallGraphCoordinate) []string {
	seen := make(map[string]bool)
	var out []string
	for _, c := range coords {
		if c.ModulePath != modulePath || seen[c.ModuleVersion] {
			continue
		}
		seen[c.ModuleVersion] = true
		out = append(out, c.ModuleVersion)
	}
	sort.Slice(out, func(i, j int) bool {
		return versionorder.CompareModuleVersions(out[i], out[j]) > 0
	})
	return out
}

// supersededCoordinatesOf lists the coordinates of modulePath that stored holds
// and served does not: the generations an implementers answer could not read.
func supersededCoordinatesOf(modulePath string, stored, served []cgports.CallGraphCoordinate) ([]coordinate.ModuleCoordinate, error) {
	isServed := map[string]bool{}
	for _, s := range served {
		isServed[s.ModulePath+"@"+s.ModuleVersion] = true
	}
	var out []coordinate.ModuleCoordinate
	for _, s := range stored {
		if s.ModulePath != modulePath || isServed[s.ModulePath+"@"+s.ModuleVersion] {
			continue
		}
		c, err := coordinate.NewModuleCoordinate(s.ModulePath, s.ModuleVersion)
		if err != nil {
			return nil, fmt.Errorf("call graph record %s@%s names no module: %w", s.ModulePath, s.ModuleVersion, err)
		}
		out = append(out, c)
	}
	return out, nil
}

// methodNodeID returns the concrete node implementing method, or "" when the
// implementation records none.
func methodNodeID(impl domain.InterfaceImplementation, method string) string {
	for _, m := range impl.Methods {
		if m.Method == method {
			return m.NodeID
		}
	}
	return ""
}
