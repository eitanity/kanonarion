package domain_test

import (
	"reflect"
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
	})
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
	})
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
	})
	if want := []string{"m.a", "m.b"}; !reflect.DeepEqual(got, want) {
		t.Errorf("SelectReachabilityRoots = %v, want %v", got, want)
	}
}

func TestSelectReachabilityRoots_AllExternal(t *testing.T) {
	got := domain.SelectReachabilityRoots([]domain.RootCandidate{
		{ID: "ext.Fn", Symbol: "Fn", IsExternal: true, IsExportedAPI: true},
		{ID: "ext.init", Symbol: "init", IsExternal: true},
	})
	if len(got) != 0 {
		t.Errorf("SelectReachabilityRoots = %v, want empty", got)
	}
}
