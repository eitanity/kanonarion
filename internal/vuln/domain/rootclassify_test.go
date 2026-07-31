package domain_test

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// appRoute is a two-hop route rooted in the application module, which is what a
// target-rooted govulncheck answer produces: the main module's frames carry no
// version, because a main module has none in a Go build.
func appRoute() domain.ReachabilityRoute {
	return domain.ReachabilityRoute{
		{ModulePath: "example.com/app", Package: "example.com/app/handlers", Receiver: "*Server", Symbol: "ServeHTTP"},
		{ModulePath: "example.com/dep", ModuleVersion: "v1.2.0", Package: "example.com/dep", Symbol: "Parse"},
	}
}

func targetRooted() domain.Rooting {
	return domain.TargetRootedAt(coordinatetest.MustNew("example.com/app", "local"))
}

// TestClassifyRouteRoot_Kinds pins the classification of each of the five kinds
// AND the order they are asked in. The order is the substance: a test helper is
// frequently also exported, and an entry point frequently also has callers, so a
// rule set that tested them in any other order would answer exported-api for a
// route that never runs in production.
func TestClassifyRouteRoot_Kinds(t *testing.T) {
	tests := []struct {
		name       string
		facts      domain.RootFacts
		wantKind   domain.RootKind
		wantReason string
	}{
		{
			name: "ingress from an entry point the node identity witnesses",
			facts: domain.RootFacts{
				Resolved: true, NodeID: "n", IsExportedAPI: true,
				ExternalInvocation: "an http.Handler implementation",
			},
			wantKind:   domain.RootIngress,
			wantReason: "an http.Handler implementation",
		},
		{
			name: "exported-api when the project itself calls nothing into it",
			facts: domain.RootFacts{
				Resolved: true, NodeID: "n", IsExportedAPI: true, InProjectCallers: 0,
			},
			wantKind:   domain.RootExportedAPI,
			wantReason: "a consumer could drive it",
		},
		{
			name: "internal when the project drives it",
			facts: domain.RootFacts{
				Resolved: true, NodeID: "n", IsExportedAPI: true, InProjectCallers: 3,
			},
			wantKind:   domain.RootInternal,
			wantReason: "(3 callers)",
		},
		{
			name: "test scope wins over exported and over ingress",
			facts: domain.RootFacts{
				Resolved: true, NodeID: "n", IsTest: true, IsExportedAPI: true,
				ExternalInvocation: "an http.Handler implementation",
			},
			wantKind:   domain.RootTest,
			wantReason: "not a production one",
		},
		{
			name: "unrooted names the reason it could not say",
			facts: domain.RootFacts{
				Unavailable: "no call graph is stored for example.com/app@local",
			},
			wantKind:   domain.RootUnrooted,
			wantReason: "no call graph is stored",
		},
		{
			name: "unexported with nothing recorded entering it is internal, and says so",
			facts: domain.RootFacts{
				Resolved: true, NodeID: "n",
			},
			wantKind:   domain.RootInternal,
			wantReason: "nothing in the graph says what enters it",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := domain.ClassifyRouteRoot(appRoute(), targetRooted(), "example.com/app", tt.facts)
			if got.Kind != tt.wantKind {
				t.Fatalf("Kind = %q, want %q (reason %q)", got.Kind, tt.wantKind, got.Reason)
			}
			if !strings.Contains(got.Reason, tt.wantReason) {
				t.Errorf("Reason = %q, want it to contain %q", got.Reason, tt.wantReason)
			}
			if got.Reason == "" {
				t.Error("every classification owes a reason; a bare kind is a label, not a measurement")
			}
		})
	}
}

// TestClassifyRouteRoot_EveryKindIsProducible fails if a value in the published
// set cannot be produced by any input, which would leave the renderer branching
// on a state nothing can reach.
func TestClassifyRouteRoot_EveryKindIsProducible(t *testing.T) {
	produced := map[domain.RootKind]bool{}
	inputs := []domain.RootFacts{
		{Resolved: true, ExternalInvocation: "the process entry point"},
		{Resolved: true, IsExportedAPI: true},
		{Resolved: true, InProjectCallers: 1},
		{Resolved: true, IsTest: true},
		{Unavailable: "no graph"},
	}
	for _, f := range inputs {
		produced[domain.ClassifyRouteRoot(appRoute(), targetRooted(), "example.com/app", f).Kind] = true
	}
	for _, k := range domain.RootKinds() {
		if !produced[k] {
			t.Errorf("no input produces %q — a kind nothing can answer is not a classification", k)
		}
	}
}

// TestClassifyRouteRoot_NoRouteIsNotClassified holds the line KN's package-level
// work drew: an absent route is already explained by the advisory naming no
// symbols, and answering "unrooted" for it would offer a missing root as the
// reason for a search that was never possible.
func TestClassifyRouteRoot_NoRouteIsNotClassified(t *testing.T) {
	got := domain.ClassifyRouteRoot(nil, targetRooted(), "example.com/app", domain.RootFacts{Resolved: true})
	if got.IsRecorded() {
		t.Fatalf("a route with no frames was classified as %q", got.Kind)
	}
	if got.String() != "root not classified" {
		t.Errorf("String() = %q, want the uncomputed case named rather than blank", got.String())
	}
}

// TestClassifyRouteRoot_ClosureRooted covers the --gomod case the ticket names:
// where the analysis was not rooted at the application, the answer says so and
// names the command that would root it there, instead of presenting a
// dependency's own entry point as the project's.
func TestClassifyRouteRoot_ClosureRooted(t *testing.T) {
	depRoute := domain.ReachabilityRoute{
		{ModulePath: "example.com/dep", ModuleVersion: "v1.2.0", Package: "example.com/dep", Symbol: "Parse"},
		{ModulePath: "example.com/other", ModuleVersion: "v0.1.0", Package: "example.com/other", Symbol: "Read"},
	}
	facts := domain.RootFacts{Resolved: true, NodeID: "n", IsExportedAPI: true}

	tests := []struct {
		name       string
		route      domain.ReachabilityRoute
		rooting    domain.Rooting
		rootModule string
		want       bool
	}{
		{
			name:  "an isolated scan had no application to be rooted at",
			route: depRoute, rooting: domain.RootingIsolated, want: true,
		},
		{
			name:  "an unrecorded frame states no root at all",
			route: depRoute, rooting: domain.RootingUnrecorded, want: true,
		},
		{
			name:  "a target-rooted route beginning in a dependency skipped the application",
			route: depRoute, rooting: targetRooted(), rootModule: "example.com/app", want: true,
		},
		{
			name:  "a target-rooted route beginning in the target is not closure-rooted",
			route: appRoute(), rooting: targetRooted(), rootModule: "example.com/app", want: false,
		},
		{
			name: "a bare target-rooted frame names no target, so nothing is asserted",
			// It states an application WAS the root and merely does not say which;
			// claiming closure-rooted would be a claim about a build the record does
			// not describe.
			route: depRoute, rooting: domain.RootingTargetRooted, want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := domain.ClassifyRouteRoot(tt.route, tt.rooting, tt.rootModule, facts)
			if got.ClosureRooted != tt.want {
				t.Fatalf("ClosureRooted = %v, want %v", got.ClosureRooted, tt.want)
			}
			if !tt.want {
				return
			}
			if got.Remedy == "" {
				t.Error("a closure-rooted answer owes the command that would root the analysis at the application")
			}
			if !strings.Contains(got.String(), "closure-rooted") {
				t.Errorf("String() = %q, want the closure-rooted caveat rendered", got.String())
			}
			if !got.Kind.IsClassified() {
				t.Error("closure-rooted qualifies a kind; it does not replace one")
			}
		})
	}
}

// TestClassifyRouteRoot_InternalNamesTheNextStep exists because "internal" is
// the answer for the case the ticket's own evidence wanted closed by hand: the
// route begins several hops below the handler that drives it. The classification
// must hand the reader the command that walks those hops, or it has replaced one
// dead end with another.
func TestClassifyRouteRoot_InternalNamesTheNextStep(t *testing.T) {
	got := domain.ClassifyRouteRoot(appRoute(), targetRooted(), "example.com/app", domain.RootFacts{
		Resolved: true, NodeID: "example.com/app/handlers.(*Server).handle", InProjectCallers: 1,
	})
	if got.Kind != domain.RootInternal {
		t.Fatalf("Kind = %q, want internal", got.Kind)
	}
	if !strings.Contains(got.Remedy, "kanonarion callers") {
		t.Errorf("Remedy = %q, want the callers query that walks the hops above the route", got.Remedy)
	}
	if !strings.Contains(got.Reason, "(1 caller)") {
		t.Errorf("Reason = %q, want a singular caller count rather than %q", got.Reason, "1 callers")
	}
}

// TestClassifyRouteRoot_UnrootedKeepsItsOwnRemedy checks that an unresolvable
// root does not have its remedy overwritten by the closure-rooted one: the
// operator's next step is to build the graph, not to re-root the scan.
func TestClassifyRouteRoot_UnrootedKeepsItsOwnRemedy(t *testing.T) {
	got := domain.ClassifyRouteRoot(appRoute(), domain.RootingIsolated, "", domain.RootFacts{
		Unavailable:       "no call graph is stored for example.com/app@local",
		UnavailableRemedy: "kanonarion callgraph example.com/app@local",
	})
	if got.Kind != domain.RootUnrooted {
		t.Fatalf("Kind = %q, want unrooted", got.Kind)
	}
	if got.Remedy != "kanonarion callgraph example.com/app@local" {
		t.Errorf("Remedy = %q, want the graph the classification actually needs", got.Remedy)
	}
}

// TestRootKindStringNamesTheZeroValue keeps the uncomputed case from rendering
// as a blank column, which reads as missing data rather than as an unasked
// question.
func TestRootKindStringNamesTheZeroValue(t *testing.T) {
	if got := domain.RootUnclassified.String(); got != "not classified" {
		t.Errorf("String() = %q, want %q", got, "not classified")
	}
	if domain.RootUnclassified.IsClassified() {
		t.Error("the zero value must not report itself as a classification")
	}
}
