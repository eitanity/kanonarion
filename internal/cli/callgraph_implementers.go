package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/spf13/cobra"
)

func newImplementersCmd(stdout, stderr io.Writer) *cobra.Command {
	var excludeTests bool
	var scopeFlags buildScopeFlags

	cmd := &cobra.Command{
		Use:   "implementers <interface-id>",
		Short: "List the concrete types satisfying an interface",
		Long: `List the concrete types in the analysed module whose method sets satisfy an
interface it declares.

This is the type question a port-signature change actually raises: which method
sets must change together. The edge queries cannot answer it — an interface
method has no callers, because calls go to implementations — and a text grep for
the method name cannot tell an implementation from a call, and misses embedded
and wrapper implementations entirely.

Two forms are accepted:

  the interface type      pkg/path.Name
  one interface method    pkg/path.(Name).Method

The method form lists the concrete method each implementer supplies, as node IDs
the callers and callees queries also accept.`,
		Example: `  kanonarion implementers 'github.com/eitanity/kanonarion/internal/vuln/ports.VulnerabilityStore'
  kanonarion implementers 'github.com/eitanity/kanonarion/internal/vuln/ports.(VulnerabilityStore).PutVulnerabilityRecord'
  kanonarion implementers 'github.com/eitanity/kanonarion/internal/license/ports.LicenseStore' --exclude-tests`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageErr(cmd)
			}
			scopeFlags.bind(cmd)
			logger := buildLogger(logLevel, stderr)
			ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
			if err != nil {
				return fmt.Errorf("initialising store: %w", err)
			}
			defer func() { _ = cleanup() }()
			sc, err := scopeFlags.resolve(cmd.Context(), ctr.QueryWalks)
			if err != nil {
				return err
			}
			return runImplementers(cmd.Context(), args[0], jsonOut, ctr.QueryCallGraph, stdout, sc,
				ports.EdgeQueryOptions{ExcludeTests: excludeTests})
		},
	}

	registerEdgeScopeFlag(cmd, &excludeTests)
	registerBuildScopeFlags(cmd, &scopeFlags)
	cmd.Flags().Lookup("gomod").NoOptDefVal = defaultGoModPath

	return cmd
}

// implementerJSON is the curated shape of one implementer.
type implementerJSON struct {
	TypeID        string `json:"type_id"`
	Package       string `json:"package"`
	ModulePath    string `json:"module_path"`
	ModuleVersion string `json:"module_version"`
	IsTest        bool   `json:"is_test"`
	// NodeID is the concrete method satisfying the queried interface method.
	// Empty when the query named the interface type rather than one method.
	NodeID string `json:"node_id,omitempty"`
	File   string `json:"file,omitempty"`
	Line   int    `json:"line,omitempty"`
}

type implementersResult struct {
	InterfaceID  string            `json:"interface_id"`
	Method       string            `json:"method,omitempty"`
	Count        int               `json:"count"`
	Implementers []implementerJSON `json:"implementers"`
	Verdict      string            `json:"verdict"`
	VerdictWhy   string            `json:"verdict_reason,omitempty"`
	// Scope names what the measurement covered, so an empty list is read as the
	// answer to the question that was actually asked.
	Scope string `json:"scope"`
}

// runImplementers answers an implementers query and renders it with the same
// three-valued verdict the edge queries use: an empty result must be
// distinguishable from one the analysis could not decide.
func runImplementers(ctx context.Context, queryID string, jsonOut bool, uc QueryCallGraphUseCase, stdout io.Writer, sc buildScope, opts ports.EdgeQueryOptions) error {
	interfaceID, method, perMethod := domain.ParseInterfaceMethodID(queryID)
	if !perMethod {
		interfaceID = queryID
	}

	if err := checkSymbolInScope(ctx, interfaceID, uc, sc); err != nil {
		return err
	}

	found, err := gatherImplementers(ctx, interfaceID, uc, sc.modules)
	if err != nil {
		return err
	}
	if !found.declared {
		return implementersUnknownError(interfaceID, found.modulePath, found.moduleAnalysed)
	}
	if perMethod && !found.hasMethod(method) {
		return fmt.Errorf(
			"interface %q declares no method %q; its methods are %s",
			interfaceID, method, strings.Join(found.iface.Methods, ", "))
	}

	impls := found.implementations
	if opts.ExcludeTests {
		kept := impls[:0:0]
		for _, im := range impls {
			if !im.impl.IsTest {
				kept = append(kept, im)
			}
		}
		impls = kept
	}

	verdict := found.verdict(len(impls) > 0, opts)
	scopeLine := implementersScopeLine(found.modulePath, opts)

	if jsonOut {
		return writeImplementersJSON(stdout, interfaceID, method, perMethod, impls, verdict, scopeLine)
	}
	return writeImplementersText(stdout, queryID, method, perMethod, impls, verdict, scopeLine, sc)
}

// scopedImplementer is one implementation plus the record it was measured in.
type scopedImplementer struct {
	impl          domain.InterfaceImplementation
	modulePath    string
	moduleVersion string
}

// implementerLookup is the outcome of searching the in-scope records for an
// interface: whether the module was analysed, whether it declares the
// interface, the implementations found, and the soundness signals bearing on an
// empty answer.
type implementerLookup struct {
	iface           domain.InterfaceType
	declared        bool
	modulePath      string
	moduleAnalysed  bool
	implementations []scopedImplementer
	belowFull       domain.CompletenessLevel
	testScope       domain.TestScope
	testScopeDetail string
	partialPkg      string
}

func (l implementerLookup) hasMethod(method string) bool {
	return slices.Contains(l.iface.Methods, method)
}

// verdict classifies the answer. Presence is never downgraded: an implementer
// found is a type-level fact go/types decided exactly. An empty answer is a
// measurement only when nothing about the analysis leaves room for a missing
// one.
func (l implementerLookup) verdict(present bool, opts ports.EdgeQueryOptions) domain.Verdict {
	if present {
		return domain.Verdict{Outcome: domain.VerdictResolvedPresent}
	}
	var sinks []domain.SoundnessSink
	if l.partialPkg != "" {
		sinks = append(sinks, domain.SoundnessSink{
			Kind:   domain.SinkTypeOnlyCallee,
			Site:   l.iface.ID,
			Detail: "package " + l.partialPkg + " did not typecheck",
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
		return domain.Verdict{Outcome: domain.VerdictResolvedAbsent}
	}
	return domain.Verdict{Outcome: domain.VerdictUnresolved, Sinks: sinks}
}

// gatherImplementers searches every in-scope analysed record of the module
// owning interfaceID. A module analysed at several versions contributes each of
// them, and the result is the union — deduplicated on the type ID, because the
// same declaration at two versions is one answer to "what must change".
func gatherImplementers(ctx context.Context, interfaceID string, uc QueryCallGraphUseCase, scope coordinate.ModuleSet) (implementerLookup, error) {
	var out implementerLookup
	out.testScope = domain.TestScopeAnalysed

	sums, err := listScopedSummaries(ctx, uc, scope)
	if err != nil {
		return out, err
	}
	paths := make([]string, 0, len(sums))
	for _, s := range sums {
		paths = append(paths, s.ModulePath)
	}
	modulePath, ok := domain.ResolveSymbolModule(interfaceID, paths)
	if !ok {
		return out, nil
	}
	out.modulePath = modulePath
	out.moduleAnalysed = true

	seen := make(map[string]struct{})
	for _, s := range sums {
		if s.ModulePath != modulePath {
			continue
		}
		coord, cErr := coordinate.NewModuleCoordinate(s.ModulePath, s.ModuleVersion)
		if cErr != nil {
			return out, fmt.Errorf("call graph record %s@%s names no module: %w", s.ModulePath, s.ModuleVersion, cErr)
		}
		rec, ok, gErr := uc.GetCallGraphRecord(ctx, coord, s.PipelineVersion)
		if gErr != nil {
			return out, fmt.Errorf("loading call graph for %s: %w", coord, gErr)
		}
		if !ok {
			continue
		}
		iface, declared := domain.InterfaceByID(rec, interfaceID)
		if !declared {
			continue
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
			out.implementations = append(out.implementations, scopedImplementer{
				impl:          im,
				modulePath:    s.ModulePath,
				moduleVersion: s.ModuleVersion,
			})
		}
		if rec.OverallStatus == domain.CallGraphStatusPartial && out.partialPkg == "" {
			if fp, hit := symbolFailedPackage(interfaceID, rec.FailedPackages); hit {
				out.partialPkg = fp
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
	sort.Slice(out.implementations, func(i, j int) bool {
		return out.implementations[i].impl.TypeID < out.implementations[j].impl.TypeID
	})
	return out, nil
}

// implementersScopeLine states what the measurement covered. It is printed on
// every answer, not only an empty one: the relation is computed over the
// declaring module's own types, and a reader who assumes otherwise would take a
// complete answer for a narrower question as an incomplete answer to a wider
// one.
func implementersScopeLine(modulePath string, opts ports.EdgeQueryOptions) string {
	if modulePath == "" {
		return ""
	}
	line := "scope: concrete types declared in " + modulePath +
		"; types in other modules that satisfy this interface are not measured"
	if opts.ExcludeTests {
		line += "; test implementations omitted (--" + testScopeFlagName + " was given)"
	}
	return line
}

func writeImplementersJSON(stdout io.Writer, interfaceID, method string, perMethod bool, impls []scopedImplementer, v domain.Verdict, scopeLine string) error {
	out := make([]implementerJSON, 0, len(impls))
	for _, im := range impls {
		entry := implementerJSON{
			TypeID:        im.impl.TypeID,
			Package:       im.impl.Package,
			ModulePath:    im.modulePath,
			ModuleVersion: im.moduleVersion,
			IsTest:        im.impl.IsTest,
			File:          im.impl.Position.File,
			Line:          im.impl.Position.Line,
		}
		if perMethod {
			entry.NodeID = methodNodeID(im.impl, method)
		}
		out = append(out, entry)
	}
	res := implementersResult{
		InterfaceID:  interfaceID,
		Count:        len(out),
		Implementers: out,
		Verdict:      string(v.Outcome),
		VerdictWhy:   v.Reason(),
		Scope:        scopeLine,
	}
	if perMethod {
		res.Method = method
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(res); err != nil {
		return fmt.Errorf("encoding JSON: %w", err)
	}
	return nil
}

func writeImplementersText(stdout io.Writer, queryID, method string, perMethod bool, impls []scopedImplementer, v domain.Verdict, scopeLine string, sc buildScope) error {
	if err := writeScopeNotice(stdout, sc); err != nil {
		return err
	}
	if len(impls) == 0 {
		if _, err := fmt.Fprintf(stdout, "No implementers found for %s\n", queryID); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	} else {
		if _, err := fmt.Fprintf(stdout, "%s of %s:\n", countImplementers(len(impls)), queryID); err != nil {
			return fmt.Errorf("writing header: %w", err)
		}
		for _, im := range impls {
			shown := im.impl.TypeID
			promoted := ""
			if perMethod {
				if id := methodNodeID(im.impl, method); id != "" {
					shown = id
					// A promoted method is declared on an embedded type, so two
					// implementers can share one declaration. Naming the type that
					// satisfies the interface keeps the row distinguishable — and
					// tells the reader that editing that one declaration covers both.
					if !strings.HasPrefix(id, im.impl.TypeID+".") {
						promoted = "  (promoted into " + im.impl.TypeID + ")"
					}
				}
			}
			testTag := ""
			if im.impl.IsTest {
				testTag = "  [test]"
			}
			if _, err := fmt.Fprintf(stdout, "  %s%s%s  (%s@%s)\n",
				shown, testTag, promoted, im.modulePath, im.moduleVersion); err != nil {
				return fmt.Errorf("writing implementer: %w", err)
			}
		}
	}
	if scopeLine != "" {
		if _, err := fmt.Fprintln(stdout, scopeLine); err != nil {
			return fmt.Errorf("writing scope: %w", err)
		}
	}
	switch v.Outcome {
	case domain.VerdictResolvedPresent:
		if _, err := fmt.Fprintf(stdout,
			"verdict: RESOLVED-PRESENT — %s %s %s\n", countConcreteTypes(len(impls)), satisfyVerb(len(impls)), queryID); err != nil {
			return fmt.Errorf("writing verdict: %w", err)
		}
	case domain.VerdictUnresolved:
		if _, err := fmt.Fprintf(stdout,
			"verdict: UNRESOLVED — implementers of %s cannot be confirmed absent: %s\n",
			queryID, v.Reason()); err != nil {
			return fmt.Errorf("writing verdict: %w", err)
		}
	default:
		if _, err := fmt.Fprintf(stdout,
			"verdict: RESOLVED-ABSENT — no type in %s satisfies %s\n",
			moduleOfScopeLine(scopeLine), queryID); err != nil {
			return fmt.Errorf("writing verdict: %w", err)
		}
	}
	return nil
}

// countImplementers and countConcreteTypes render a count with the right
// number, so a single answer does not read as a broken sentence.
func countImplementers(n int) string {
	if n == 1 {
		return "1 implementer"
	}
	return fmt.Sprintf("%d implementers", n)
}

func countConcreteTypes(n int) string {
	if n == 1 {
		return "1 concrete type"
	}
	return fmt.Sprintf("%d concrete types", n)
}

func satisfyVerb(n int) string {
	if n == 1 {
		return "satisfies"
	}
	return "satisfy"
}

// moduleOfScopeLine recovers the module path from the scope line so the absent
// verdict names the set it measured rather than claiming a universal absence.
func moduleOfScopeLine(scopeLine string) string {
	const prefix = "scope: concrete types declared in "
	rest, ok := strings.CutPrefix(scopeLine, prefix)
	if !ok {
		return "the analysed module"
	}
	if before, _, ok := strings.Cut(rest, ";"); ok {
		return before
	}
	return rest
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

// implementersUnknownError distinguishes the three ways an interface ID can
// fail to resolve, so the caller learns which one applies rather than reading
// an empty list.
func implementersUnknownError(interfaceID, modulePath string, moduleAnalysed bool) error {
	if !moduleAnalysed {
		return unresolvedSymbolError(interfaceID)
	}
	return fmt.Errorf(
		"%q is not an interface declared by the analysed module %q: it may be a typo, "+
			"a concrete type, or an interface declared in a dependency (only the "+
			"analysed module's own interfaces are measured). List what was analysed:\n"+
			"  kanonarion callgraph-show %s",
		interfaceID, modulePath, modulePath)
}
