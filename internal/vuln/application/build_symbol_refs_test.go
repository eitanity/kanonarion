package application_test

import (
	"reflect"
	"testing"

	"github.com/eitanity/kanonarion/internal/vuln/application"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

func TestBuildSymbolRefs(t *testing.T) {
	cases := []struct {
		name    string
		module  string
		symbols []string
		want    []ports.SymbolReference
	}{
		{
			name:    "nil symbols yields empty non-nil slice",
			module:  "example.com/m",
			symbols: nil,
			want:    []ports.SymbolReference{},
		},
		{
			name:    "empty symbols yields empty slice",
			module:  "example.com/m",
			symbols: []string{},
			want:    []ports.SymbolReference{},
		},
		{
			name:    "single symbol",
			module:  "example.com/m",
			symbols: []string{"Foo"},
			want:    []ports.SymbolReference{{Module: "example.com/m", Symbol: "Foo"}},
		},
		{
			name:    "multiple symbols preserve order",
			module:  "example.com/m",
			symbols: []string{"Foo", "Bar", "Baz"},
			want: []ports.SymbolReference{
				{Module: "example.com/m", Symbol: "Foo"},
				{Module: "example.com/m", Symbol: "Bar"},
				{Module: "example.com/m", Symbol: "Baz"},
			},
		},
		{
			name:    "duplicate symbols are preserved",
			module:  "example.com/m",
			symbols: []string{"Foo", "Foo"},
			want: []ports.SymbolReference{
				{Module: "example.com/m", Symbol: "Foo"},
				{Module: "example.com/m", Symbol: "Foo"},
			},
		},
		{
			name:    "empty module is still set on each ref",
			module:  "",
			symbols: []string{"Foo"},
			want:    []ports.SymbolReference{{Module: "", Symbol: "Foo"}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := application.BuildSymbolRefs(tc.module, tc.symbols)
			if got == nil {
				t.Fatal("expected non-nil slice")
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("BuildSymbolRefs(%q, %v) = %+v, want %+v",
					tc.module, tc.symbols, got, tc.want)
			}
			// Package is never populated by this helper.
			for i, r := range got {
				if r.Package != "" {
					t.Errorf("ref[%d].Package = %q, want empty", i, r.Package)
				}
			}
		})
	}
}
