package domain_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
)

func TestIsInitSymbol(t *testing.T) {
	cases := []struct {
		symbol string
		want   bool
	}{
		{"init", true},
		{"init#1", true},
		{"init#42", true},
		{"initialise", false},
		{"Init", false},
		{"main", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := domain.IsInitSymbol(tc.symbol); got != tc.want {
			t.Errorf("IsInitSymbol(%q) = %v, want %v", tc.symbol, got, tc.want)
		}
	}
}

func TestSelectReachabilityRoots_ExportedUnionInit(t *testing.T) {
	// Exported API and package init are both roots; unexported non-init and
	// external nodes are not. Results are sorted.
	got := domain.SelectReachabilityRoots([]domain.RootCandidate{
		{ID: "m.Exported", Symbol: "Exported", IsExportedAPI: true},
		{ID: "m.init", Symbol: "init"},
		{ID: "m.init#1", Symbol: "init#1"},
		{ID: "m.helper", Symbol: "helper"},
		{ID: "ext.Init", Symbol: "init", IsExternal: true},
	}, domain.ArtifactLibrary)
	want := []string{"m.Exported", "m.init", "m.init#1"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("SelectReachabilityRoots = %v, want %v", got, want)
	}
}

func TestSelectReachabilityRoots_InitOnly(t *testing.T) {
	// A module whose only root is package init (no exported API) still roots at
	// init rather than falling back to every owned node.
	got := domain.SelectReachabilityRoots([]domain.RootCandidate{
		{ID: "m.init", Symbol: "init"},
		{ID: "m.helper", Symbol: "helper"},
	}, domain.ArtifactLibrary)
	if want := []string{"m.init"}; !reflect.DeepEqual(got, want) {
		t.Errorf("SelectReachabilityRoots = %v, want %v", got, want)
	}
}

func TestSelectReachabilityRoots_FallsBackToOwned(t *testing.T) {
	// No exported API and no init: fall back to every owned (non-external) node.
	got := domain.SelectReachabilityRoots([]domain.RootCandidate{
		{ID: "m.b", Symbol: "b"},
		{ID: "m.a", Symbol: "a"},
		{ID: "ext.Fn", Symbol: "Fn", IsExternal: true},
	}, domain.ArtifactLibrary)
	if want := []string{"m.a", "m.b"}; !reflect.DeepEqual(got, want) {
		t.Errorf("SelectReachabilityRoots = %v, want %v", got, want)
	}
}

func TestSelectReachabilityRoots_ApplicationRootsAllOwnedCode(t *testing.T) {
	// An application that also has an exported API still roots every owned node:
	// its unexported handlers are entered by framework dispatch, so rooting only
	// the exported API would leave their capabilities unwitnessed. External nodes
	// remain excluded, and results are sorted.
	got := domain.SelectReachabilityRoots([]domain.RootCandidate{
		{ID: "m.Exported", Symbol: "Exported", IsExportedAPI: true},
		{ID: "m.handler", Symbol: "handler"},
		{ID: "m.init", Symbol: "init"},
		{ID: "ext.Fn", Symbol: "Fn", IsExternal: true, IsExportedAPI: true},
	}, domain.ArtifactApplication)
	want := []string{"m.Exported", "m.handler", "m.init"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("SelectReachabilityRoots = %v, want %v", got, want)
	}
}

func TestSelectReachabilityRoots_LibraryLeavesDynamicOnlyCodeUnrooted(t *testing.T) {
	// The same candidate set as an application, classified as a library: the
	// unexported, non-init handler is not a root. This is the behaviour the
	// artifact kind switches between, so the two cases are asserted as a pair.
	got := domain.SelectReachabilityRoots([]domain.RootCandidate{
		{ID: "m.Exported", Symbol: "Exported", IsExportedAPI: true},
		{ID: "m.handler", Symbol: "handler"},
		{ID: "m.init", Symbol: "init"},
		{ID: "ext.Fn", Symbol: "Fn", IsExternal: true, IsExportedAPI: true},
	}, domain.ArtifactLibrary)
	want := []string{"m.Exported", "m.init"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("SelectReachabilityRoots = %v, want %v", got, want)
	}
}

func TestSelectReachabilityRoots_ApplicationAllExternal(t *testing.T) {
	// No owned node means no root, whatever the artifact kind.
	got := domain.SelectReachabilityRoots([]domain.RootCandidate{
		{ID: "ext.Fn", Symbol: "Fn", IsExternal: true, IsExportedAPI: true},
	}, domain.ArtifactApplication)
	if len(got) != 0 {
		t.Errorf("SelectReachabilityRoots = %v, want empty", got)
	}
}

func TestSelectReachabilityRoots_UnsetKindIsLibrary(t *testing.T) {
	// A record persisted before the artifact kind existed decodes to the zero
	// value, which must keep the original library rooting rather than silently
	// widening every stored graph to whole-graph roots.
	candidates := []domain.RootCandidate{
		{ID: "m.Exported", Symbol: "Exported", IsExportedAPI: true},
		{ID: "m.handler", Symbol: "handler"},
	}
	var unset domain.ArtifactKind
	got := domain.SelectReachabilityRoots(candidates, unset)
	want := domain.SelectReachabilityRoots(candidates, domain.ArtifactLibrary)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("unset kind = %v, want library rooting %v", got, want)
	}
}

func TestSelectReachabilityRoots_AllExternal(t *testing.T) {
	got := domain.SelectReachabilityRoots([]domain.RootCandidate{
		{ID: "ext.Fn", Symbol: "Fn", IsExternal: true, IsExportedAPI: true},
		{ID: "ext.init", Symbol: "init", IsExternal: true},
	}, domain.ArtifactLibrary)
	if len(got) != 0 {
		t.Errorf("SelectReachabilityRoots = %v, want empty", got)
	}
}

// TestExternalEntryPointReason pins both what the predicate witnesses and what
// it deliberately does not. The negatives matter more than the positives: a
// registered route is invisible in a node's identity, and a predicate that
// guessed at one would assert an entry the graph never recorded.
func TestExternalEntryPointReason(t *testing.T) {
	tests := []struct {
		name     string
		symbol   string
		receiver string
		wantIn   string
	}{
		{name: "package init", symbol: "init", wantIn: "package initialisation"},
		{name: "generated package init", symbol: "init#1", wantIn: "package initialisation"},
		{name: "process entry point", symbol: "main", wantIn: "process entry point"},
		{name: "http handler method", symbol: "ServeHTTP", receiver: "*Server", wantIn: "http.Handler"},

		{name: "a method named main is not the entry point", symbol: "main", receiver: "*App"},
		{name: "a free function named ServeHTTP is not a handler method", symbol: "ServeHTTP"},
		{name: "an init-like name is not init", symbol: "initialise"},
		{name: "an ordinary exported method", symbol: "CompleteUserAuth", receiver: "*Handler"},
		{name: "a closure registered as a route is not witnessed here", symbol: "MountHttpRoutes$1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := domain.ExternalEntryPointReason(tt.symbol, tt.receiver)
			if tt.wantIn == "" {
				if got != "" {
					t.Fatalf("ExternalEntryPointReason(%q, %q) = %q, want no entry-point claim",
						tt.symbol, tt.receiver, got)
				}
				return
			}
			if !strings.Contains(got, tt.wantIn) {
				t.Fatalf("ExternalEntryPointReason(%q, %q) = %q, want it to contain %q",
					tt.symbol, tt.receiver, got, tt.wantIn)
			}
		})
	}
}
