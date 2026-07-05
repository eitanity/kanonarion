package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
)

func TestResolveSymbolModule(t *testing.T) {
	analysed := []string{
		"example.com/m",
		"example.com/m/sub",
		"github.com/eitanity/kanonarion",
	}

	cases := []struct {
		name      string
		symbolID  string
		wantMatch string
		wantOK    bool
	}{
		{"package under module", "example.com/m/pkg.Fn", "example.com/m", true},
		{"longest-prefix wins", "example.com/m/sub/pkg.Fn", "example.com/m/sub", true},
		{"method receiver form", "github.com/eitanity/kanonarion/internal/cli.(*X).Y", "github.com/eitanity/kanonarion", true},
		{"prefix but not a path boundary", "example.com/much.Fn", "", false},
		{"stdlib symbol — no module", "fmt.Errorf", "", false},
		{"module not analysed", "other.com/z/pkg.Fn", "", false},
		{"empty analysed set", "example.com/m/pkg.Fn", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			set := analysed
			if tc.name == "empty analysed set" {
				set = nil
			}
			got, ok := domain.ResolveSymbolModule(tc.symbolID, set)
			if ok != tc.wantOK || got != tc.wantMatch {
				t.Errorf("ResolveSymbolModule(%q) = (%q, %v), want (%q, %v)",
					tc.symbolID, got, ok, tc.wantMatch, tc.wantOK)
			}
		})
	}
}
