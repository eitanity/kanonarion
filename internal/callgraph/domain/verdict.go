package domain

import (
	"fmt"
	"sort"
	"strings"
)

// VerdictOutcome is the three-valued soundness verdict for a callers/callees/
// reachability query. It replaces the implicit two-valued "some edges" vs
// "empty" answer, which silently conflated a proven absence with an absence
// caused by an unresolved dispatch on the path. An empty answer is a confident
// negative only when no dispatch/edge-level soundness sink lies on the queried
// node or an examined path; otherwise the absence is UNRESOLVED — an edge may be
// missing, not proven absent.
//
// This composes with, and sits above, the module-level resolution gate
// (ResolveSymbolModule) and the failed-package caveat: a verdict is a confident
// negative only when the module gate resolves, no failed-package caveat fires,
// and this dispatch gate reports RESOLVED-ABSENT.
type VerdictOutcome string

const (
	// VerdictResolvedPresent is a query that found at least one edge: the
	// relationship is present. Presence is never downgraded — an over-approximated
	// edge only ever adds callers/callees, so a non-empty answer stands.
	VerdictResolvedPresent VerdictOutcome = "RESOLVED-PRESENT"
	// VerdictResolvedAbsent is an empty answer across a fully-built path with no
	// soundness sink: a provably-absent edge. This is the only outcome that may be
	// reported as a confident "not reachable" / "no callers".
	VerdictResolvedAbsent VerdictOutcome = "RESOLVED-ABSENT"
	// VerdictUnresolved is an empty answer with a soundness sink on the queried
	// node or an examined path: an unresolved interface dispatch, an edge into a
	// module not built with bodies, an unresolved/reflect edge, or a leaf carrying
	// a documented soundness sink. The absence is not proven — an edge may simply
	// be missing.
	VerdictUnresolved VerdictOutcome = "UNRESOLVED"
)

// IsConfidentNegative reports whether the outcome may be presented as a
// trustworthy "no edge" answer. Only RESOLVED-ABSENT qualifies.
func (o VerdictOutcome) IsConfidentNegative() bool {
	return o == VerdictResolvedAbsent
}

// SinkKind names a specific dispatch/edge-level reason a negative call-graph
// verdict cannot be trusted.
type SinkKind string

const (
	// SinkInterfaceDispatch is an over-approximated or unresolved interface invoke
	// site that dispatches on the queried method's name. CHA may have failed to
	// bind it to the queried method (the implementer's method was absent from the
	// built SSA set), so the absence of an edge is not proof of absence.
	SinkInterfaceDispatch SinkKind = "interface-dispatch"
	// SinkTypeOnlyCallee is an edge into, or a queried node within, a module
	// analysed below BUILT_WITH_BODIES: method bodies were never built, so call
	// edges out of them are simply absent.
	SinkTypeOnlyCallee SinkKind = "type-only-callee"
	// SinkUnresolvedEdge is an edge the analyser could not resolve to a concrete
	// callee (ConfidenceUnknown), excluding reflect edges, which are reported as
	// SinkReflectDispatch.
	SinkUnresolvedEdge SinkKind = "unresolved-edge"
	// SinkReflectDispatch is an edge resolved through reflection: the callee set is
	// not statically knowable.
	SinkReflectDispatch SinkKind = "reflect-dispatch"
	// SinkUnsafePointerLeaf is a node whose body performs an unsafe.Pointer
	// conversion — a documented soundness sink that can defeat static edge
	// resolution on paths through it.
	SinkUnsafePointerLeaf SinkKind = "unsafe-pointer-leaf"
	// SinkAssemblyOrLinknameLeaf is a node implemented in assembly or via
	// //go:linkname: it has no Go body, so no edges out of it are visible.
	SinkAssemblyOrLinknameLeaf SinkKind = "assembly-or-linkname-leaf"
	// SinkPluginLeaf is a node whose body loads code through the Go plugin
	// package (plugin.Open / (*Plugin).Lookup): the loaded targets are resolved
	// at runtime and are never present in the static graph.
	SinkPluginLeaf SinkKind = "plugin-leaf"
	// SinkReferenceScopeUnmeasured is a record whose analysis never looked for
	// function-value references. A method registered with a router is passed,
	// not called, so a graph built from call instructions alone cannot witness
	// what drives it — and an empty callers answer over such a record covers
	// calls only. Absence may be claimed when both kinds of edge were
	// measurable; over a record that measured one, it may not.
	SinkReferenceScopeUnmeasured SinkKind = "reference-scope-unmeasured"
	// SinkTestHarnessEntry is a test, benchmark, fuzz or example entry point.
	// The `go test` harness invokes it through a main package the analysis never
	// sees, so nothing in the graph calls it and nothing ever will — reporting
	// that as a measured absence claims a function certainly invoked is
	// unreached. It is named rather than hidden: the entry point is real, and so
	// is the fact that its caller is outside the graph.
	SinkTestHarnessEntry SinkKind = "test-harness-entry"
	// SinkDroppedPackageEdges is the queried symbol's own package failing to
	// typecheck, so the analyser built no SSA for it and every edge with an end
	// in that package was dropped.
	//
	// It is its own kind rather than a flavour of type-only, because it is a
	// different gap with a different owner: a type-only module was analysed at a
	// level someone chose, while a dropped package is a build failure inside the
	// analysed artefact — often a dependency's, which the reader of the answer
	// has no tree to fix.
	SinkDroppedPackageEdges SinkKind = "dropped-package-edges"
	// SinkTestScopeUnmeasured is a module whose _test.go declarations were not
	// part of the analysis. Test fakes and table-driven callers are a systematic
	// part of what calls a port, so an empty answer over such a module measures
	// production code only — and saying so is worth more than a clean-looking
	// absent that quietly means something narrower than it reads.
	SinkTestScopeUnmeasured SinkKind = "test-scope-unmeasured"
)

// SoundnessSink is a single reason an empty verdict was downgraded to
// UNRESOLVED, with enough provenance for a reviewer to act on it.
type SoundnessSink struct {
	// Kind is the category of sink.
	Kind SinkKind
	// Site is the symbol ID the sink was found at — the invoke site, the callee
	// node, or the leaf node.
	Site string
	// Detail is an optional human-readable specific (e.g. the module's
	// completeness level, or the method name an interface site dispatches on).
	Detail string
}

// Describe renders the sink as a single deterministic line naming the kind, the
// site, and any detail.
func (s SoundnessSink) Describe() string {
	line := fmt.Sprintf("%s at %s", s.Kind, s.Site)
	if s.Detail != "" {
		line += " (" + s.Detail + ")"
	}
	return line
}

// Verdict bundles the outcome with the sinks that justify it. For a
// RESOLVED-PRESENT or RESOLVED-ABSENT verdict Sinks is empty.
type Verdict struct {
	Outcome VerdictOutcome
	Sinks   []SoundnessSink
}

// Reason renders a deterministic, human-readable justification for the verdict:
// empty for a confident present/absent answer, and the semicolon-joined sink
// descriptions for an UNRESOLVED one.
func (v Verdict) Reason() string {
	if len(v.Sinks) == 0 {
		return ""
	}
	parts := make([]string, 0, len(v.Sinks))
	for _, s := range v.Sinks {
		parts = append(parts, s.Describe())
	}
	return strings.Join(parts, "; ")
}

// SymbolMethodName extracts the short method or function name from a call-graph
// symbol ID: the trailing identifier after the final '.'. It returns "" for an
// empty ID or one ending in '.'. Examples: "pkg.(*T).M" -> "M", "pkg.Fn" -> "Fn".
func SymbolMethodName(symbolID string) string {
	i := strings.LastIndex(symbolID, ".")
	if i < 0 {
		return symbolID
	}
	return symbolID[i+1:]
}

// NegativeVerdictInputs carries the soundness signals gathered about an empty
// callers/callees answer so the queried node's absence can be classified.
type NegativeVerdictInputs struct {
	// MethodName is the short name of the queried symbol's method/function, used
	// to match interface invoke sites that dispatch on the same name.
	MethodName string
	// QueriedNode is the node the query is rooted at; the zero value when the
	// symbol is not a node in any analysed graph (Found is false).
	QueriedNode CallNode
	// Found reports whether QueriedNode was located.
	Found bool
	// ModuleLevel is the completeness level of the module owning the queried
	// symbol. Below BUILT_WITH_BODIES (and not Unknown) it is itself a sink.
	ModuleLevel CompletenessLevel
	// Edges are the edges of the owning module's graph, scanned for interface
	// invoke sites when ScanDispatch is set.
	Edges []CallEdge
	// NodesByID indexes the owning module's nodes by ID, so an invoke site's
	// callee method name can be read.
	NodesByID map[string]CallNode
	// ScanDispatch enables the interface-dispatch scan. It applies to a callers
	// query, where a missing invoke->target edge hides a caller; a callees query
	// cannot observe an empty bound-implementer set from stored edges, so it
	// leaves this false.
	ScanDispatch bool
	// TestScope is the owning module's test-scope axis. Anything other than
	// Analysed means the answer covers production code only.
	TestScope TestScope
	// TestScopeDetail explains an excluded test scope, when the record recorded
	// a reason.
	TestScopeDetail string
	// ReferenceScope is the owning module's reference axis. Anything other than
	// Analysed means the answer covers call edges only, which cannot see a
	// symbol reached by having its value registered somewhere.
	ReferenceScope ReferenceScope
	// DroppedEdgePackage names the package owning the queried symbol whose
	// typecheck failed, when one did: its edges were dropped wholesale, so an
	// empty answer over it is unmeasured rather than absent. Empty when the
	// symbol's own package typechecked.
	DroppedEdgePackage string
	// TestsExcludedByRequest is set when the caller asked for the test surface
	// to be dropped. It is not a soundness sink — the scope was chosen, not
	// missed — but it still narrows what an empty answer means, so it is named
	// on the verdict line rather than left implicit.
	TestsExcludedByRequest bool
}

// ClassifyNegativeVerdict classifies an empty callers/callees answer into
// RESOLVED-ABSENT or UNRESOLVED, collecting the sinks that force a downgrade.
// The sinks are deterministically ordered and de-duplicated.
func ClassifyNegativeVerdict(in NegativeVerdictInputs) Verdict {
	var sinks []SoundnessSink

	// The queried module was built below full fidelity: dispatch edges out of it
	// are absent, so an empty answer is unproven regardless of the node facts.
	if in.ModuleLevel != CompletenessUnknown && !in.ModuleLevel.IsBuiltWithBodies() {
		site := in.QueriedNode.ID
		if site == "" {
			site = in.MethodName
		}
		sinks = append(sinks, SoundnessSink{
			Kind:   SinkTypeOnlyCallee,
			Site:   site,
			Detail: "module completeness " + in.ModuleLevel.String(),
		})
	}

	// The queried symbol's own package never produced SSA, so no edge with an end
	// in it survived. Nothing about an empty answer here is a measurement.
	if in.DroppedEdgePackage != "" {
		site := in.QueriedNode.ID
		if site == "" {
			site = in.MethodName
		}
		sinks = append(sinks, SoundnessSink{
			Kind:   SinkDroppedPackageEdges,
			Site:   site,
			Detail: "package " + in.DroppedEdgePackage + " did not typecheck, so its edges were dropped",
		})
	}

	// The queried node itself carries a documented leaf sink.
	if in.Found {
		sinks = append(sinks, leafSinks(in.QueriedNode)...)
	}

	// The module's test declarations were never analysed, so a test-only caller
	// could not have produced an edge. That is an unmeasured axis, not a
	// measured absence.
	if !in.TestScope.IsMeasured() && !in.TestsExcludedByRequest {
		site := in.QueriedNode.ID
		if site == "" {
			site = in.MethodName
		}
		detail := in.TestScopeDetail
		if detail == "" {
			detail = "_test.go declarations were not analysed for this module"
		}
		sinks = append(sinks, SoundnessSink{
			Kind:   SinkTestScopeUnmeasured,
			Site:   site,
			Detail: detail,
		})
	}

	// The analysis never looked for function values, so a symbol registered with
	// a router rather than called could not have produced an edge of any kind.
	if !in.ReferenceScope.IsMeasured() {
		site := in.QueriedNode.ID
		if site == "" {
			site = in.MethodName
		}
		sinks = append(sinks, SoundnessSink{
			Kind:   SinkReferenceScopeUnmeasured,
			Site:   site,
			Detail: "function-value references were not extracted for this module, so a registered-but-uncalled symbol has no edge to find",
		})
	}

	// The queried symbol is a test entry point. The harness that runs it is
	// synthesised by the go command and is not in the graph, so no edge into it
	// can exist and its absence proves nothing.
	if in.Found && IsTestHarnessEntry(in.QueriedNode) {
		sinks = append(sinks, SoundnessSink{
			Kind:   SinkTestHarnessEntry,
			Site:   in.QueriedNode.ID,
			Detail: "the go test harness invokes it through a synthesised main package that is not part of the analysed graph",
		})
	}

	// An over-approximated or unresolved interface invoke site dispatches on the
	// queried method's name: CHA may have failed to bind it to the queried
	// method, so no caller edge does not prove no caller.
	if in.ScanDispatch {
		sinks = append(sinks, interfaceDispatchSinks(in.MethodName, in.Edges, in.NodesByID)...)
	}

	sinks = dedupeSinks(sinks)
	if len(sinks) == 0 {
		return Verdict{Outcome: VerdictResolvedAbsent}
	}
	return Verdict{Outcome: VerdictUnresolved, Sinks: sinks}
}

// leafSinks returns the documented leaf sinks a node carries in its body.
func leafSinks(n CallNode) []SoundnessSink {
	var out []SoundnessSink
	if n.UsesUnsafePointer {
		out = append(out, SoundnessSink{Kind: SinkUnsafePointerLeaf, Site: n.ID})
	}
	if n.IsAssemblyOrLinkname {
		out = append(out, SoundnessSink{Kind: SinkAssemblyOrLinknameLeaf, Site: n.ID})
	}
	if n.UsesPlugin {
		out = append(out, SoundnessSink{Kind: SinkPluginLeaf, Site: n.ID})
	}
	return out
}

// interfaceDispatchSinks scans edges for over-approximated (CHA-overapprox) or
// unresolved (Unknown, including reflect) invoke sites whose callee dispatches on
// methodName. Each such site is a reason an empty `callers` answer for a method
// of that name is unproven. Returns nothing when methodName is empty.
func interfaceDispatchSinks(methodName string, edges []CallEdge, nodesByID map[string]CallNode) []SoundnessSink {
	if methodName == "" {
		return nil
	}
	var out []SoundnessSink
	for _, e := range edges {
		if !isUnresolvedDispatch(e.Confidence) {
			continue
		}
		callee, ok := nodesByID[e.ToID]
		if !ok || callee.Symbol != methodName {
			continue
		}
		out = append(out, SoundnessSink{
			Kind:   SinkInterfaceDispatch,
			Site:   e.FromID,
			Detail: "dispatches on " + methodName + " via " + string(e.Confidence),
		})
	}
	return out
}

// isUnresolvedDispatch reports whether a confidence tier represents an interface
// dispatch that was not narrowed to a unique concrete callee — an
// over-approximation or an outright unresolved edge.
func isUnresolvedDispatch(c EdgeConfidence) bool {
	return c == ConfidenceCHAOverapprox || c == ConfidenceUnknown
}

// dedupeSinks removes sinks that share a (Kind, Site) pair and returns them in a
// deterministic order: by Kind, then Site, then Detail.
func dedupeSinks(sinks []SoundnessSink) []SoundnessSink {
	seen := make(map[string]bool, len(sinks))
	out := make([]SoundnessSink, 0, len(sinks))
	for _, s := range sinks {
		key := string(s.Kind) + "\x00" + s.Site
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, s)
	}
	// (Kind, Site) is unique after de-duplication, so it is a total order.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Site < out[j].Site
	})
	return out
}

// IsTestHarnessEntry reports whether a node is a function the `go test` harness
// invokes: a Test/Benchmark/Fuzz/Example function, or TestMain, declared in test
// scope with no receiver.
//
// It exists because such a node's caller is real and is not in the graph. The go
// command synthesises a main package that calls every one of them, and that
// package is deliberately not analysed — it is generated build output, not the
// module's code. The consequence is that every test function looks exactly like
// dead code to an edge query, and the three-valued verdict must say so rather
// than report a confident absence for a function that runs on every `go test`.
//
// The name test is the whole test, which is what the go command itself uses, and
// the receiver test is what keeps a method named Test on a fake — reached by
// dispatch, not by the harness — out of it.
func IsTestHarnessEntry(n CallNode) bool {
	if !n.IsTest || n.Receiver != "" {
		return false
	}
	if n.Symbol == "TestMain" {
		return true
	}
	for _, prefix := range []string{"Test", "Benchmark", "Fuzz", "Example"} {
		rest, ok := strings.CutPrefix(n.Symbol, prefix)
		if !ok {
			continue
		}
		// "Test" alone is not a test function, and "Testing" is not one either:
		// the go command requires the next rune to be non-lower-case.
		if rest == "" {
			return prefix == "Example"
		}
		r := rune(rest[0])
		if r < 'a' || r > 'z' {
			return true
		}
	}
	return false
}
