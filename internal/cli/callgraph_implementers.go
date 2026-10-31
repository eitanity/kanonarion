package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	cgapp "code.eitanity.com/kanonarion/internal/callgraph/application"
	"code.eitanity.com/kanonarion/internal/callgraph/domain"
	"code.eitanity.com/kanonarion/internal/callgraph/ports"
	"code.eitanity.com/kanonarion/internal/coordinate"
	"github.com/spf13/cobra"
)

func newImplementersCmd(stdout, stderr io.Writer) *cobra.Command {
	var excludeTests bool
	var scopeFlags buildScopeFlags

	cmd := &cobra.Command{
		Use: "implementers <interface-id>",
		Annotations: map[string]string{
			annotationStoreIntent: StoreIntentRead,
			annotationNetworkUse:  NetworkNever,
		},
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
		Example: `  kanonarion implementers 'code.eitanity.com/kanonarion/internal/vuln/ports.VulnerabilityStore'
  kanonarion implementers 'code.eitanity.com/kanonarion/internal/vuln/ports.(VulnerabilityStore).PutVulnerabilityRecord'
  kanonarion implementers 'code.eitanity.com/kanonarion/internal/license/ports.LicenseStore' --exclude-tests`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageErr(cmd)
			}
			if berr := scopeFlags.bindCallGraphRead(cmd); berr != nil {
				return berr
			}
			logger := buildLogger(logLevel, stderr)
			ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
			if err != nil {
				return fmt.Errorf("initialising store: %w", err)
			}
			defer releaseStore(cleanup)
			if aerr := adoptNamedWalkFrame(cmd.Context(), ctr.QueryWalks, scopeFlags.walkID); aerr != nil {
				return aerr
			}
			sc, err := scopeFlags.resolve(cmd.Context(), ctr.QueryWalks)
			if err != nil {
				return err
			}
			return runImplementers(cmd.Context(), args[0], jsonOut, ctr.QueryCallGraph, stdout, sc,
				ports.EdgeQueryOptions{ExcludeTests: excludeTests, Toolchain: sc.toolchain})
		},
	}

	registerEdgeScopeFlag(cmd, &excludeTests)
	registerBuildScopeFlags(cmd, &scopeFlags)

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
	Answer       string            `json:"answer"`
	AnswerWhy    string            `json:"answer_reason,omitempty"`
	// Scope names what the measurement covered, so an empty list is read as the
	// answer to the question that was actually asked. It is one English sentence,
	// which is why the four fields below field the same limits: `count` reads as
	// the set of implementers, and only this sentence said it was the set declared
	// in one module.
	Scope string `json:"scope"`
	// SearchedModule is the module whose own declarations were searched. The
	// relation is computed over one module's types, so the count answers for that
	// module and not for the build.
	SearchedModule string `json:"searched_module"`
	// CrossModuleTypesMeasured is false on every answer: a type in another module
	// that satisfies this interface was never looked at. It is stated as a field
	// rather than left to the sentence because it is the limit a consumer is most
	// likely to read past — an answer that is complete for a narrower question
	// looks exactly like a complete answer to the wider one.
	CrossModuleTypesMeasured bool `json:"cross_module_types_measured"`
	// TestsExcluded says whether test implementations were dropped, and
	// TestsExcludeFlag names the flag that drops them. The flag is fielded nowhere
	// else in this document, so without it a consumer holding a count cannot tell
	// which of the two questions it was the answer to, nor ask the other one.
	TestsExcluded    bool   `json:"tests_excluded"`
	TestsExcludeFlag string `json:"tests_exclude_flag"`
	// AnswerForeignModules names the modules OTHER than the searched one that own
	// implementers in this answer, because the record that held them built their
	// packages with bodies under its own path prefix. Absent means every row is
	// the searched module's own declaration — see domain.ForeignModule for why
	// the distinction is not cosmetic.
	AnswerForeignModules []foreignModuleJSON `json:"answer_foreign_modules,omitempty"`
	// SetAside names the stored call graph generations the reads behind this
	// document left out because this build cannot reproduce them.
	SetAside []setAsideJSON `json:"set_aside,omitempty"`
	// NotSearched names the coordinates of the searched module whose graphs are
	// only at a superseded pipeline, and under a build scope every module
	// version in it with no served graph.
	NotSearched []notSearchedJSON `json:"not_searched,omitempty"`
}

// runImplementers answers an implementers query and renders it with the same
// three-valued verdict the edge queries use: an empty result must be
// distinguishable from one the analysis could not decide.
func runImplementers(ctx context.Context, queryID string, jsonOut bool, uc QueryCallGraphUseCase, stdout io.Writer, sc buildScope, opts ports.EdgeQueryOptions) error {
	interfaceID, _, perMethod := domain.ParseInterfaceMethodID(queryID)
	if !perMethod {
		interfaceID = queryID
	}

	if err := checkSymbolInScope(ctx, interfaceID, uc, sc); err != nil {
		return err
	}

	res, err := cgapp.FindImplementers(ctx, uc, cgapp.ImplementersRequest{
		InterfaceID: queryID, PipelineVersion: cgapp.PipelineVersion, Scope: sc.modules, Opts: opts,
	})
	if miss, ok := errors.AsType[*cgapp.InterfaceNotDeclaredError](err); ok {
		return implementersMiss(ctx, uc, miss)
	}
	if sup, ok := errors.AsType[*cgapp.SupersededModuleError](err); ok {
		return supersededPipelineError(sup.InterfaceID, sup.ModulePath, sup.Stored)
	}
	if err != nil {
		return err //nolint:wrapcheck // the use case's errors name what failed
	}
	if err := reportNotSearched(ctx, uc, sc, res.NotSearched); err != nil {
		return err
	}

	scopeLine := implementersScopeLine(res.ModulePath, opts)
	if jsonOut {
		return writeImplementersJSON(stdout, res, perMethod, scopeLine, opts, foreignDrawOfImplementers(res.Implementers))
	}
	// The implementer relation is read out of the served record, so the same
	// routing question applies: which working tree's types are these.
	if err := writeWorktreeNotice(ctx, interfaceID, uc, stdout, sc.modules); err != nil {
		return err
	}
	return writeImplementersText(stdout, queryID, res, perMethod, scopeLine, sc, foreignDrawOfImplementers(res.Implementers))
}

// implementersMiss refuses an interface no served record declares. One sought
// only in records the read frame serves, where none was served, is a frame miss.
func implementersMiss(ctx context.Context, uc QueryCallGraphUseCase, miss *cgapp.InterfaceNotDeclaredError) error {
	if !miss.ModuleAnalysed {
		stored, err := listStoredCoordinates(ctx, uc, coordinate.ModuleSet{})
		if err != nil {
			return err
		}
		if frame := stdlibFrameMiss(ctx, uc, miss.InterfaceID, stored); frame != nil {
			return frame
		}
	}
	if miss.ModuleAnalysed && !miss.ServedAny {
		if frame := moduleFrameMiss(ctx, uc, miss.ModulePath, miss.AnalysedVersions); frame != nil {
			return frame
		}
	}
	return implementersUnknownError(miss.InterfaceID, miss.ModulePath, miss.ModuleAnalysed, miss.AnalysedVersions)
}

// foreignDrawOfImplementers classifies an implementers answer the way
// foreignDrawOfEdges classifies an edge answer: how many of its rows are types
// belonging to a module the record that holds them is not about.
func foreignDrawOfImplementers(impls []cgapp.Implementer) foreignDraw {
	d := foreignDraw{total: len(impls)}
	modules := map[domain.ForeignModule]struct{}{}
	holders := map[string]struct{}{}
	for _, im := range impls {
		if im.Foreign.Path == "" {
			continue
		}
		d.rows++
		modules[im.Foreign] = struct{}{}
		holders[im.ModulePath+"@"+im.ModuleVersion] = struct{}{}
	}
	d.modules, d.holders = sortedForeignModules(modules), sortedLabels(holders)
	return d
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

func writeImplementersJSON(stdout io.Writer, res cgapp.ImplementersResult, perMethod bool, scopeLine string, opts ports.EdgeQueryOptions, foreign foreignDraw) error {
	out := make([]implementerJSON, 0, len(res.Implementers))
	for _, im := range res.Implementers {
		out = append(out, implementerJSON{
			TypeID:        im.Implementation.TypeID,
			Package:       im.Implementation.Package,
			ModulePath:    im.ModulePath,
			ModuleVersion: im.ModuleVersion,
			IsTest:        im.Implementation.IsTest,
			NodeID:        im.NodeID,
			File:          im.Implementation.Position.File,
			Line:          im.Implementation.Position.Line,
		})
	}
	doc := implementersResult{
		InterfaceID:  res.InterfaceID,
		Count:        len(out),
		Implementers: out,
		Answer:       string(res.Answer.Outcome),
		AnswerWhy:    res.Answer.Reason(),
		Scope:        scopeLine,

		SearchedModule: res.ModulePath,
		// Never true, and it is a field rather than a constant in the prose so the
		// day the measurement widens is a day this value changes.
		CrossModuleTypesMeasured: false,
		TestsExcluded:            opts.ExcludeTests,
		TestsExcludeFlag:         "--" + testScopeFlagName,
		AnswerForeignModules:     foreign.foreignModuleJSONs(),
	}
	if perMethod {
		doc.Method = res.Method
	}
	doc.SetAside = storeSetAside.take().json()
	doc.NotSearched = storeNotSearched.take().json()
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("encoding JSON: %w", err)
	}
	return nil
}

func writeImplementersText(stdout io.Writer, queryID string, res cgapp.ImplementersResult, perMethod bool, scopeLine string, sc buildScope, foreign foreignDraw) error {
	impls, v := res.Implementers, res.Answer
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
			if err := writeImplementerRow(stdout, im, perMethod); err != nil {
				return err
			}
		}
	}
	if scopeLine != "" {
		if _, err := fmt.Fprintln(stdout, scopeLine); err != nil {
			return fmt.Errorf("writing scope: %w", err)
		}
	}
	switch v.Outcome {
	case domain.AnswerResolvedPresent:
		if _, err := fmt.Fprintf(stdout,
			"answer: RESOLVED-PRESENT — %s %s %s%s\n",
			countConcreteTypes(len(impls)), satisfyVerb(len(impls)), queryID,
			foreign.clause("implementers")); err != nil {
			return fmt.Errorf("writing answer: %w", err)
		}
	case domain.AnswerUnresolved:
		if _, err := fmt.Fprintf(stdout,
			"answer: UNRESOLVED — implementers of %s cannot be confirmed absent: %s\n",
			queryID, v.Reason()); err != nil {
			return fmt.Errorf("writing answer: %w", err)
		}
	default:
		if _, err := fmt.Fprintf(stdout,
			"answer: RESOLVED-ABSENT — no type in %s satisfies %s\n",
			moduleOfScopeLine(scopeLine), queryID); err != nil {
			return fmt.Errorf("writing answer: %w", err)
		}
	}
	return nil
}

// writeImplementerRow writes one implementer, or its method when the query
// named one.
func writeImplementerRow(stdout io.Writer, im cgapp.Implementer, perMethod bool) error {
	shown := im.Implementation.TypeID
	promoted := ""
	if perMethod && im.NodeID != "" {
		shown = im.NodeID
		// A promoted method is declared on an embedded type, so two
		// implementers can share one declaration. Naming the type that
		// satisfies the interface keeps the row distinguishable — and
		// tells the reader that editing that one declaration covers both.
		if !strings.HasPrefix(im.NodeID, im.Implementation.TypeID+".") {
			promoted = "  (promoted into " + im.Implementation.TypeID + ")"
		}
	}
	testTag := ""
	if im.Implementation.IsTest {
		testTag = "  [test]"
	}
	if _, err := fmt.Fprintf(stdout, "  %s%s%s  (%s@%s)\n",
		shown, testTag, promoted, im.ModulePath, im.ModuleVersion); err != nil {
		return fmt.Errorf("writing implementer: %w", err)
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

// implementersUnknownError distinguishes the three ways an interface ID can
// fail to resolve, so the caller learns which one applies rather than reading
// an empty list.
//
// versions are the analysed versions of the module, newest first: callgraph-show
// takes a coordinate, so the line needs one, and where several were analysed the
// reader is told which.
//
// It stays on ExitConfig: the command it names lists what was analysed so the
// reader can correct the interface they typed, which is a diagnostic rather than
// a remedy that produces the missing record.
func implementersUnknownError(interfaceID, modulePath string, moduleAnalysed bool, versions []string) error {
	if !moduleAnalysed || len(versions) == 0 {
		return unresolvedSymbolError(interfaceID)
	}
	held := ""
	if len(versions) > 1 {
		held = fmt.Sprintf(" (analysed versions in the store are %s)", strings.Join(versions, ", "))
	}
	return fmt.Errorf(
		"%q is not an interface declared by the analysed module %q: it may be a typo, "+
			"a concrete type, or an interface declared in a dependency (only the "+
			"analysed module's own interfaces are measured)%s. List what was analysed:\n"+
			"  kanonarion callgraph-show %s@%s",
		interfaceID, modulePath, held, modulePath, versions[0])
}
