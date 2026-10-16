package cli

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"golang.org/x/mod/semver"

	"github.com/eitanity/kanonarion/internal/coordinate"

	ifaceapp "github.com/eitanity/kanonarion/internal/iface/application"
	ifaceports "github.com/eitanity/kanonarion/internal/iface/ports"
)

// Telling "never extracted" from "extracted under superseded logic".
//
// A record is served only at the pipeline version this build produces — that is
// what a pipeline bump means. Both conditions read as an absent record at the
// query, and they have opposite remedies: one is a coordinate to check, the
// other is a re-extraction to run. A reader sent after the first when the cause
// was the second goes hunting for a spelling error that does not exist.
//
// This mirrors the call graph's supersededPipelineError, deliberately: it is one
// condition, and one binary must not describe it two ways.

// supersededInterfaceRecord answers, for ONE coordinate, whether the store holds
// it only under extraction logic this build no longer serves.
//
// The read is filtered to the coordinate because that is the question. Asking it
// with a whole-store listing made the diagnostic cost the composition of every
// multi-generation key in the ledger, once per module, and `context --gomod` on
// a project whose records are all superseded spent minutes discarding rows.
func supersededInterfaceRecord(ctx context.Context, uc QueryInterfaceUseCase, coord coordinate.ModuleCoordinate) ([]string, bool) {
	if uc == nil {
		return nil, false
	}
	sums, err := uc.ListInterfaceRecords(ctx, ifaceports.InterfaceFilter{Coordinate: &coord})
	if err != nil {
		return nil, false
	}
	return supersededInterfacePipelines(coord, sums)
}

// supersededInterfacePipelines returns the pipeline versions the store holds for
// coord, none of which this build serves. The second result is false when the
// store holds nothing for the coordinate at all, or holds a record this build
// does serve — neither is this diagnostic's case.
func supersededInterfacePipelines(coord coordinate.ModuleCoordinate, stored []ifaceports.InterfaceSummary) ([]string, bool) {
	seen := make(map[string]bool)
	for _, s := range stored {
		if s.ModulePath != coord.Path() || s.ModuleVersion != coord.Version() {
			continue
		}
		if s.PipelineVersion == ifaceapp.PipelineVersion {
			// Served at this version: whatever emptied the answer, it was not
			// the pipeline version.
			return nil, false
		}
		seen[s.PipelineVersion] = true
	}
	if len(seen) == 0 {
		return nil, false
	}
	return sortedKeys(seen), true
}

// supersededInterfaceLine is the statement for one coordinate the store holds
// only under superseded extraction logic. It names the versions held and the
// version this build serves, because "re-extract" is only actionable against a
// coordinate and the reader has no other way to see why the record went dark.
func supersededInterfaceLine(coord coordinate.ModuleCoordinate, pipelines []string) string {
	return fmt.Sprintf(
		"the interface record for %s was produced by superseded extraction logic: this build "+
			"serves pipeline %s and the store holds this coordinate at pipeline %s. A superseded "+
			"record is not served, so this answer is empty for want of a measurement of this "+
			"module, not because the coordinate is wrong. Re-extract it:\n  kanonarion interface %s",
		coord, ifaceapp.PipelineVersion, strings.Join(pipelines, ", "), coord)
}

// symbolQuery is a symbol lookup's argument. A Go identifier holds no dot, so
// a dotted argument is a qualified name: the name is what follows the last
// dot, and the qualifier before it names the package, the receiver type, or
// both, in any of the forms a reader meets — the full import path the lookups
// print (github.com/google/uuid.UUID.String), the package name a Go caller
// writes (uuid.NewString, uuid.UUID.String), or the receiver alone as the
// name column prints it (UUID.String).
type symbolQuery struct {
	qualifier, name string
}

// parseSymbolQuery splits a qualified argument at its last dot. A bare name, or
// a dotted one with an empty half or no dot after its last slash, stays bare.
func parseSymbolQuery(arg string) symbolQuery {
	dot := strings.LastIndex(arg, ".")
	if dot <= strings.LastIndex(arg, "/") || dot == 0 || dot == len(arg)-1 {
		return symbolQuery{name: arg}
	}
	return symbolQuery{qualifier: arg[:dot], name: arg[dot+1:]}
}

// packageName is the name a Go caller writes for an import path: its last
// element, less a major-version element (/v2) or suffix (yaml.v3).
func packageName(importPath string) string {
	elems := strings.Split(importPath, "/")
	last := elems[len(elems)-1]
	if isMajorVersion(last) && len(elems) > 1 {
		last = elems[len(elems)-2]
	}
	if dot := strings.LastIndex(last, "."); dot > 0 && isMajorVersion(last[dot+1:]) {
		last = last[:dot]
	}
	return last
}

// isMajorVersion reports a "v<N>" element.
func isMajorVersion(elem string) bool {
	if len(elem) < 2 || elem[0] != 'v' {
		return false
	}
	for _, c := range elem[1:] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// namesPackage reports whether a package qualifier names the package: its import
// path, or its package name.
func namesPackage(qualifier, importPath string) bool {
	return qualifier == importPath || qualifier == packageName(importPath)
}

// matches reports whether a ref is one the qualifier names.
func (q symbolQuery) matches(r ifaceports.SymbolRef) bool {
	if q.qualifier == "" || namesPackage(q.qualifier, r.PackagePath) {
		return true
	}
	if r.ParentType == "" {
		return false
	}
	if q.qualifier == r.ParentType {
		return true
	}
	pkg, ok := strings.CutSuffix(q.qualifier, "."+r.ParentType)
	return ok && namesPackage(pkg, r.PackagePath)
}

// keep narrows refs to the ones the qualifier names, in a new slice.
func (q symbolQuery) keep(refs []ifaceports.SymbolRef) []ifaceports.SymbolRef {
	if q.qualifier == "" {
		return refs
	}
	var out []ifaceports.SymbolRef
	for _, r := range refs {
		if q.matches(r) {
			out = append(out, r)
		}
	}
	return out
}

// owns reports whether a module could hold a package the qualifier names. The
// census reads module keys, not packages, so only an import-path qualifier can
// rule a module out: one inside the module, or the module inside it. A
// qualifier without a slash — a package name or a receiver type — can name a
// subpackage or a type of any module, so every module could hold it.
func (q symbolQuery) owns(modulePath string) bool {
	if !strings.Contains(q.qualifier, "/") {
		return true
	}
	candidates := []string{q.qualifier}
	if dot := strings.LastIndex(q.qualifier, "."); dot > strings.LastIndex(q.qualifier, "/") {
		candidates = append(candidates, q.qualifier[:dot])
	}
	for _, pkg := range candidates {
		if pkg == modulePath || strings.HasPrefix(pkg, modulePath+"/") {
			return true
		}
	}
	return false
}

// writeExcluded keeps a qualified miss from reading as definitive: when the
// bare name is exported by packages the qualifier did not name, it names one
// or two of them on stderr.
func (q symbolQuery) writeExcluded(stderr io.Writer, all []ifaceports.SymbolRef) error {
	if q.qualifier == "" || len(all) == 0 {
		return nil
	}
	var pkgs []string
	seen := map[string]bool{}
	for _, r := range all {
		if !seen[r.PackagePath] {
			seen[r.PackagePath] = true
			pkgs = append(pkgs, r.PackagePath)
		}
	}
	sort.Strings(pkgs)
	named := pkgs[:min(2, len(pkgs))]
	more := ""
	if extra := len(pkgs) - len(named); extra > 0 {
		more = fmt.Sprintf(" and %d other package(s)", extra)
	}
	if _, err := fmt.Fprintf(stderr, "notice: %q is exported by %s%s, which the qualifier %q did not match; "+
		"kanonarion symbol-find %s lists them\n",
		q.name, strings.Join(named, ", "), more, q.qualifier, q.name); err != nil {
		return fmt.Errorf("writing qualifier notice: %w", err)
	}
	return nil
}

// unreadInterfaceModules is what a symbol lookup could not read: the modules
// that could answer it but are held only at a superseded interface pipeline.
// The symbol index is keyed on the pipeline version, so the lookup never saw them.
type unreadInterfaceModules struct {
	// stored counts the interface records the store holds, every generation.
	stored int
	// modules are the unread coordinates, by path then newest version first;
	// pipelines are the generations they are held at.
	modules   []coordinate.ModuleCoordinate
	pipelines []string
	// storeWide reports that the store serves no interface record at all and
	// the lookup was not narrowed, so the statement is about the whole store.
	storeWide bool
}

// unreadModulesNamed is how many unread coordinates a statement names before it
// counts them instead.
const unreadModulesNamed = 10

// readInterfaceCensus takes the census from one whole-ledger read: which
// modules in scope that could hold the query's package are held only at a
// superseded pipeline.
func readInterfaceCensus(ctx context.Context, uc QueryInterfaceUseCase, scope coordinate.ModuleSet, q symbolQuery) (unreadInterfaceModules, error) {
	stored, err := uc.ListInterfaceGenerations(ctx)
	if err != nil {
		return unreadInterfaceModules{}, fmt.Errorf("listing interface generations for the superseded census: %w", err)
	}
	return interfaceCensus(stored, scope, q), nil
}

// interfaceCensus is readInterfaceCensus over summaries already read.
func interfaceCensus(stored []ifaceports.InterfaceGeneration, scope coordinate.ModuleSet, q symbolQuery) unreadInterfaceModules {
	served := map[coordinate.ModuleCoordinate]bool{}
	held := map[coordinate.ModuleCoordinate][]string{}
	storeServes := false
	for _, s := range stored {
		storeServes = storeServes || s.PipelineVersion == ifaceapp.PipelineVersion
		if !scope.ContainsPathVersion(s.ModulePath, s.ModuleVersion) || !q.owns(s.ModulePath) {
			continue
		}
		c, cerr := coordinate.NewModuleCoordinate(s.ModulePath, s.ModuleVersion)
		if cerr != nil {
			continue
		}
		if s.PipelineVersion == ifaceapp.PipelineVersion {
			served[c] = true
		} else {
			held[c] = append(held[c], s.PipelineVersion)
		}
	}
	out := unreadInterfaceModules{
		stored:    len(stored),
		storeWide: !storeServes && !scope.IsRestricted() && q.qualifier == "",
	}
	var pipelines []string
	for c, ps := range held {
		if !served[c] {
			out.modules = append(out.modules, c)
			pipelines = append(pipelines, ps...)
		}
	}
	sort.Slice(out.modules, func(i, j int) bool {
		a, b := out.modules[i], out.modules[j]
		if a.Path() != b.Path() {
			return a.Path() < b.Path()
		}
		return semver.Compare(a.Version(), b.Version()) > 0
	})
	out.pipelines = distinctGenerations(pipelines)
	return out
}

// statement says which modules were not read, naming them when there are few.
func (u unreadInterfaceModules) statement() string {
	var line string
	if u.storeWide {
		line = fmt.Sprintf("none of the %d interface record(s) the store holds is at pipeline %s, "+
			"the version this build serves (held at %s)",
			u.stored, ifaceapp.PipelineVersion, strings.Join(u.pipelines, ", "))
	} else {
		line = fmt.Sprintf("%d module(s) that could answer are held only at a superseded interface "+
			"pipeline (%s; this build serves %s), so this answer did not read them",
			len(u.modules), strings.Join(u.pipelines, ", "), ifaceapp.PipelineVersion)
	}
	if len(u.modules) <= unreadModulesNamed {
		names := make([]string, len(u.modules))
		for i, c := range u.modules {
			names[i] = c.String()
		}
		line += ": " + strings.Join(names, ", ")
	}
	return line
}

// generalRemedy re-extracts any one module, and lists the modules held.
func (u unreadInterfaceModules) generalRemedy() string {
	return "Re-extract a module:\n  kanonarion interface <module>@<version>\n" +
		"List the modules held:\n  kanonarion interface-list --all-generations"
}

// coordinateRemedy names the coordinate to re-extract when the lookup knows the
// module: an import-path qualifier names it, or only one module is unread. Of
// several versions it names the newest and says the others are held.
func (u unreadInterfaceModules) coordinateRemedy(q symbolQuery) string {
	var owner string
	for _, c := range u.modules {
		if strings.Contains(q.qualifier, "/") && len(c.Path()) > len(owner) {
			owner = c.Path()
		}
	}
	if owner == "" && len(u.modules) > 0 && u.modules[0].Path() == u.modules[len(u.modules)-1].Path() {
		owner = u.modules[0].Path()
	}
	if owner == "" {
		return u.generalRemedy()
	}
	var versions []coordinate.ModuleCoordinate
	for _, c := range u.modules {
		if c.Path() == owner {
			versions = append(versions, c)
		}
	}
	remedy := "Re-extract it:\n  kanonarion interface " + versions[0].String()
	if others := len(versions) - 1; others > 0 {
		remedy += fmt.Sprintf("\n(%d other version(s) of %s are held; kanonarion interface-list --all-generations lists them)",
			others, owner)
	}
	return remedy
}

// missError is a lookup that found nothing while modules that could answer
// went unread: exit 4, since the remedy produces the record that would answer.
func (u unreadInterfaceModules) missError(symbolName, remedy string) error {
	return &exitError{code: ExitNotFound, msg: fmt.Sprintf(
		"symbol %q cannot be resolved: %s. A superseded record is not served, so this answer is "+
			"empty for want of a measurement, not because nothing exports this name. %s",
		symbolName, u.statement(), remedy)}
}

// writeNotice keeps an answer from being silent about what it did not read.
func (u unreadInterfaceModules) writeNotice(stderr io.Writer, remedy string) error {
	if len(u.modules) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(stderr, "notice: %s. %s\n", u.statement(), remedy); err != nil {
		return fmt.Errorf("writing superseded-module notice: %w", err)
	}
	return nil
}

// emptyInterfaceStoreError is a lookup over a store that holds no interface
// record in any generation.
func emptyInterfaceStoreError(symbolName string) error {
	return &exitError{code: ExitNotFound, msg: fmt.Sprintf(
		"symbol %q cannot be resolved: the interface store is empty, nothing "+
			"has been analysed. Analyse a module first, e.g.:\n"+
			"  kanonarion interface <module>@<version>\n"+
			"  kanonarion local .   # for this project's own symbols",
		symbolName)}
}
