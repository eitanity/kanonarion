package domain_test

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
)

func TestVerdictOutcome_IsConfidentNegative(t *testing.T) {
	cases := map[domain.VerdictOutcome]bool{
		domain.VerdictResolvedPresent: false,
		domain.VerdictResolvedAbsent:  true,
		domain.VerdictUnresolved:      false,
	}
	for outcome, want := range cases {
		if got := outcome.IsConfidentNegative(); got != want {
			t.Errorf("%s.IsConfidentNegative()=%v, want %v", outcome, got, want)
		}
	}
}

func TestSoundnessSink_Describe(t *testing.T) {
	withDetail := domain.SoundnessSink{Kind: domain.SinkInterfaceDispatch, Site: "pkg.Caller", Detail: "dispatches on M via CHA-overapprox"}
	if got := withDetail.Describe(); got != "interface-dispatch at pkg.Caller (dispatches on M via CHA-overapprox)" {
		t.Errorf("unexpected describe with detail: %q", got)
	}
	noDetail := domain.SoundnessSink{Kind: domain.SinkUnsafePointerLeaf, Site: "pkg.Leaf"}
	if got := noDetail.Describe(); got != "unsafe-pointer-leaf at pkg.Leaf" {
		t.Errorf("unexpected describe without detail: %q", got)
	}
}

func TestVerdict_Reason(t *testing.T) {
	// No sinks: empty reason.
	if r := (domain.Verdict{Outcome: domain.VerdictResolvedAbsent}).Reason(); r != "" {
		t.Errorf("expected empty reason, got %q", r)
	}
	v := domain.Verdict{
		Outcome: domain.VerdictUnresolved,
		Sinks: []domain.SoundnessSink{
			{Kind: domain.SinkReflectDispatch, Site: "a.F"},
			{Kind: domain.SinkUnsafePointerLeaf, Site: "b.G"},
		},
	}
	got := v.Reason()
	if !strings.Contains(got, "reflect-dispatch at a.F") || !strings.Contains(got, "unsafe-pointer-leaf at b.G") {
		t.Errorf("reason missing a sink: %q", got)
	}
	if !strings.Contains(got, "; ") {
		t.Errorf("expected semicolon-joined reason, got %q", got)
	}
}

func TestSymbolMethodName(t *testing.T) {
	cases := map[string]string{
		"pkg/path.(*T).Method": "Method",
		"pkg/path.Fn":          "Fn",
		"NoDot":                "NoDot",
		"":                     "",
		"trailing.":            "",
	}
	for in, want := range cases {
		if got := domain.SymbolMethodName(in); got != want {
			t.Errorf("SymbolMethodName(%q)=%q, want %q", in, got, want)
		}
	}
}

// TestClassifyNegativeVerdict_GenuineAbsence: a fully-built module, node found,
// no leaf sink, no unresolved dispatch — a confident RESOLVED-ABSENT.
func TestClassifyNegativeVerdict_GenuineAbsence(t *testing.T) {
	in := domain.NegativeVerdictInputs{
		MethodName:  "Root",
		QueriedNode: domain.CallNode{ID: "m.Root", Symbol: "Root"},
		Found:       true,
		ModuleLevel: domain.CompletenessBuiltWithBodies,
	}
	v := domain.ClassifyNegativeVerdict(in)
	if v.Outcome != domain.VerdictResolvedAbsent {
		t.Fatalf("outcome=%s, want RESOLVED-ABSENT", v.Outcome)
	}
	if len(v.Sinks) != 0 || v.Reason() != "" {
		t.Errorf("expected no sinks, got %v", v.Sinks)
	}
	if !v.Outcome.IsConfidentNegative() {
		t.Error("genuine absence should be a confident negative")
	}
}

// TestClassifyNegativeVerdict_UnknownLevelIsNotDowngraded: a legacy record with
// no completeness level does not by itself force UNRESOLVED.
func TestClassifyNegativeVerdict_UnknownLevelIsNotDowngraded(t *testing.T) {
	in := domain.NegativeVerdictInputs{
		MethodName:  "Root",
		QueriedNode: domain.CallNode{ID: "m.Root", Symbol: "Root"},
		Found:       true,
		ModuleLevel: domain.CompletenessUnknown,
	}
	if got := domain.ClassifyNegativeVerdict(in).Outcome; got != domain.VerdictResolvedAbsent {
		t.Errorf("unknown level should stay RESOLVED-ABSENT, got %s", got)
	}
}

// TestClassifyNegativeVerdict_TypeOnlyModule: a module built below full fidelity
// downgrades to UNRESOLVED, using the node ID as the site when found.
func TestClassifyNegativeVerdict_TypeOnlyModule(t *testing.T) {
	in := domain.NegativeVerdictInputs{
		MethodName:  "Root",
		QueriedNode: domain.CallNode{ID: "m.Root", Symbol: "Root"},
		Found:       true,
		ModuleLevel: domain.CompletenessTypeOnly,
	}
	v := domain.ClassifyNegativeVerdict(in)
	if v.Outcome != domain.VerdictUnresolved {
		t.Fatalf("outcome=%s, want UNRESOLVED", v.Outcome)
	}
	if len(v.Sinks) != 1 || v.Sinks[0].Kind != domain.SinkTypeOnlyCallee || v.Sinks[0].Site != "m.Root" {
		t.Fatalf("unexpected sink: %+v", v.Sinks)
	}
	if !strings.Contains(v.Sinks[0].Detail, "TYPE_ONLY") {
		t.Errorf("detail should name the level, got %q", v.Sinks[0].Detail)
	}
}

// TestClassifyNegativeVerdict_TypeOnlyModuleNodeAbsent: the queried symbol never
// became a node (its package was type-only), so the sink site falls back to the
// method name.
func TestClassifyNegativeVerdict_TypeOnlyModuleNodeAbsent(t *testing.T) {
	in := domain.NegativeVerdictInputs{
		MethodName:  "Ghost",
		Found:       false,
		ModuleLevel: domain.CompletenessMetadataOnly,
	}
	v := domain.ClassifyNegativeVerdict(in)
	if v.Outcome != domain.VerdictUnresolved {
		t.Fatalf("outcome=%s, want UNRESOLVED", v.Outcome)
	}
	if v.Sinks[0].Site != "Ghost" {
		t.Errorf("site fallback should be method name, got %q", v.Sinks[0].Site)
	}
}

// TestClassifyNegativeVerdict_LeafSinks: a found node carrying unsafe.Pointer
// and/or asm/linkname leaf facts downgrades, and only a found node is inspected.
func TestClassifyNegativeVerdict_LeafSinks(t *testing.T) {
	in := domain.NegativeVerdictInputs{
		MethodName: "Leaf",
		QueriedNode: domain.CallNode{
			ID: "m.Leaf", Symbol: "Leaf",
			UsesUnsafePointer:    true,
			IsAssemblyOrLinkname: true,
			UsesPlugin:           true,
		},
		Found:       true,
		ModuleLevel: domain.CompletenessBuiltWithBodies,
	}
	v := domain.ClassifyNegativeVerdict(in)
	if v.Outcome != domain.VerdictUnresolved {
		t.Fatalf("outcome=%s, want UNRESOLVED", v.Outcome)
	}
	kinds := map[domain.SinkKind]bool{}
	for _, s := range v.Sinks {
		kinds[s.Kind] = true
	}
	if !kinds[domain.SinkUnsafePointerLeaf] || !kinds[domain.SinkAssemblyOrLinknameLeaf] || !kinds[domain.SinkPluginLeaf] {
		t.Errorf("expected all three leaf sinks, got %+v", v.Sinks)
	}

	// The same facts on a not-found node are ignored (there is no node to inspect).
	in.Found = false
	if got := domain.ClassifyNegativeVerdict(in).Outcome; got != domain.VerdictResolvedAbsent {
		t.Errorf("leaf facts on absent node must be ignored, got %s", got)
	}
}

// TestClassifyNegativeVerdict_PluginLeafSink covers a node whose only sink is a
// plugin-load boundary: an empty verdict over it must be UNRESOLVED with the
// plugin site named, since the loaded targets are absent from the static graph.
func TestClassifyNegativeVerdict_PluginLeafSink(t *testing.T) {
	in := domain.NegativeVerdictInputs{
		MethodName: "Load",
		QueriedNode: domain.CallNode{
			ID: "m.Load", Symbol: "Load",
			UsesPlugin: true,
		},
		Found:       true,
		ModuleLevel: domain.CompletenessBuiltWithBodies,
	}
	v := domain.ClassifyNegativeVerdict(in)
	if v.Outcome != domain.VerdictUnresolved {
		t.Fatalf("outcome=%s, want UNRESOLVED", v.Outcome)
	}
	found := false
	for _, s := range v.Sinks {
		if s.Kind == domain.SinkPluginLeaf {
			if s.Site != "m.Load" {
				t.Errorf("plugin sink site=%q, want m.Load", s.Site)
			}
			found = true
		}
	}
	if !found {
		t.Errorf("expected a plugin leaf sink, got %+v", v.Sinks)
	}
}

// TestClassifyNegativeVerdict_InterfaceDispatchScan reproduces the zenbpm hop: an
// over-approximated invoke site dispatches on the queried method name while the
// queried method received no caller edge. A callers query (ScanDispatch) must
// report UNRESOLVED naming the invoke site; a callees query must not scan.
func TestClassifyNegativeVerdict_InterfaceDispatchScan(t *testing.T) {
	edges := []domain.CallEdge{
		// An interface dispatch that CHA over-approximated to another implementer.
		{FromID: "m.Client", ToID: "m.(*OtherImpl).Do", Confidence: domain.ConfidenceCHAOverapprox},
		// A resolved direct edge on the same method name is not a sink.
		{FromID: "m.Direct", ToID: "m.(*Bound).Do", Confidence: domain.ConfidenceDirect},
		// An unresolved dispatch on a different method name is irrelevant.
		{FromID: "m.Other", ToID: "m.(*X).Nope", Confidence: domain.ConfidenceUnknown},
	}
	nodes := map[string]domain.CallNode{
		"m.(*OtherImpl).Do": {ID: "m.(*OtherImpl).Do", Symbol: "Do"},
		"m.(*Bound).Do":     {ID: "m.(*Bound).Do", Symbol: "Do"},
		"m.(*X).Nope":       {ID: "m.(*X).Nope", Symbol: "Nope"},
	}
	base := domain.NegativeVerdictInputs{
		MethodName:  "Do",
		QueriedNode: domain.CallNode{ID: "m.(*Target).Do", Symbol: "Do"},
		Found:       true,
		ModuleLevel: domain.CompletenessBuiltWithBodies,
		Edges:       edges,
		NodesByID:   nodes,
	}

	// callers query: scans dispatch, finds the over-approx site.
	callers := base
	callers.ScanDispatch = true
	v := domain.ClassifyNegativeVerdict(callers)
	if v.Outcome != domain.VerdictUnresolved {
		t.Fatalf("callers outcome=%s, want UNRESOLVED", v.Outcome)
	}
	if len(v.Sinks) != 1 || v.Sinks[0].Kind != domain.SinkInterfaceDispatch || v.Sinks[0].Site != "m.Client" {
		t.Fatalf("expected one interface-dispatch sink at m.Client, got %+v", v.Sinks)
	}

	// callees query: no dispatch scan, so a genuine absence.
	callees := base
	callees.ScanDispatch = false
	if got := domain.ClassifyNegativeVerdict(callees).Outcome; got != domain.VerdictResolvedAbsent {
		t.Errorf("callees must not scan dispatch, got %s", got)
	}
}

// TestClassifyNegativeVerdict_UnknownEdgeUnindexedCallee: an unresolved edge whose
// callee is not in the node index cannot be confirmed to dispatch on the method,
// so it contributes no sink.
func TestClassifyNegativeVerdict_UnknownEdgeUnindexedCallee(t *testing.T) {
	in := domain.NegativeVerdictInputs{
		MethodName:   "Do",
		Found:        true,
		QueriedNode:  domain.CallNode{ID: "m.(*Target).Do", Symbol: "Do"},
		ModuleLevel:  domain.CompletenessBuiltWithBodies,
		ScanDispatch: true,
		Edges:        []domain.CallEdge{{FromID: "m.C", ToID: "m.Missing", Confidence: domain.ConfidenceUnknown}},
		NodesByID:    map[string]domain.CallNode{}, // callee not indexed
	}
	if got := domain.ClassifyNegativeVerdict(in).Outcome; got != domain.VerdictResolvedAbsent {
		t.Errorf("unindexed callee must not produce a sink, got %s", got)
	}
}

// TestClassifyNegativeVerdict_EmptyMethodNameNoScan: an empty method name yields
// no interface-dispatch sinks even with ScanDispatch set.
func TestClassifyNegativeVerdict_EmptyMethodNameNoScan(t *testing.T) {
	in := domain.NegativeVerdictInputs{
		MethodName:   "",
		Found:        true,
		QueriedNode:  domain.CallNode{ID: "m.Root"},
		ModuleLevel:  domain.CompletenessBuiltWithBodies,
		ScanDispatch: true,
		Edges:        []domain.CallEdge{{FromID: "m.C", ToID: "m.T", Confidence: domain.ConfidenceCHAOverapprox}},
		NodesByID:    map[string]domain.CallNode{"m.T": {ID: "m.T", Symbol: ""}},
	}
	if got := domain.ClassifyNegativeVerdict(in).Outcome; got != domain.VerdictResolvedAbsent {
		t.Errorf("empty method name must not scan, got %s", got)
	}
}

// TestClassifyNegativeVerdict_DedupeAndOrder: duplicate sinks (same kind+site)
// collapse and the result is deterministically ordered by kind then site.
func TestClassifyNegativeVerdict_DedupeAndOrder(t *testing.T) {
	edges := []domain.CallEdge{
		{FromID: "m.Client", ToID: "m.(*A).Do", Confidence: domain.ConfidenceCHAOverapprox},
		{FromID: "m.Client", ToID: "m.(*B).Do", Confidence: domain.ConfidenceUnknown}, // same site, deduped
		{FromID: "m.Aaa", ToID: "m.(*C).Do", Confidence: domain.ConfidenceCHAOverapprox},
	}
	nodes := map[string]domain.CallNode{
		"m.(*A).Do": {Symbol: "Do"},
		"m.(*B).Do": {Symbol: "Do"},
		"m.(*C).Do": {Symbol: "Do"},
	}
	in := domain.NegativeVerdictInputs{
		MethodName:   "Do",
		Found:        true,
		QueriedNode:  domain.CallNode{ID: "m.(*Target).Do", Symbol: "Do", UsesUnsafePointer: true},
		ModuleLevel:  domain.CompletenessBuiltWithBodies,
		ScanDispatch: true,
		Edges:        edges,
		NodesByID:    nodes,
	}
	v := domain.ClassifyNegativeVerdict(in)
	// Two interface-dispatch sites (m.Aaa, m.Client) + one unsafe-pointer leaf.
	if len(v.Sinks) != 3 {
		t.Fatalf("expected 3 sinks after dedupe, got %d: %+v", len(v.Sinks), v.Sinks)
	}
	// Ordered by kind then site: interface-dispatch (m.Aaa, m.Client) before
	// unsafe-pointer-leaf.
	if v.Sinks[0].Site != "m.Aaa" || v.Sinks[1].Site != "m.Client" {
		t.Errorf("interface-dispatch sinks not ordered by site: %+v", v.Sinks)
	}
	if v.Sinks[2].Kind != domain.SinkUnsafePointerLeaf {
		t.Errorf("leaf sink should sort last: %+v", v.Sinks)
	}
}
