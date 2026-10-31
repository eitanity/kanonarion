package domain_test

import (
	"testing"

	"code.eitanity.com/kanonarion/internal/callgraph/domain"
)

func TestResolveSymbolModule(t *testing.T) {
	analysed := []string{
		"example.com/m",
		"example.com/m/sub",
		"code.eitanity.com/kanonarion",
	}

	cases := []struct {
		name      string
		symbolID  string
		wantMatch string
		wantOK    bool
	}{
		{"package under module", "example.com/m/pkg.Fn", "example.com/m", true},
		{"longest-prefix wins", "example.com/m/sub/pkg.Fn", "example.com/m/sub", true},
		{"method receiver form", "code.eitanity.com/kanonarion/internal/cli.(*X).Y", "code.eitanity.com/kanonarion", true},
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

func TestSymbolFailedPackage(t *testing.T) {
	failed := []string{"example.com/app/broken", "example.com/app/other"}
	cases := []struct {
		symbol string
		want   string
	}{
		{"example.com/app/broken.Broken", "example.com/app/broken"},
		{"example.com/app/broken.(*T).M", "example.com/app/broken"},
		{"example.com/app/broken/sub.Fn", ""}, // sub-package is a different package
		{"example.com/app.Clean", ""},
		{"example.com/app/brokenish.Fn", ""}, // prefix but not a package boundary
	}
	for _, tc := range cases {
		got, hit := domain.SymbolFailedPackage(tc.symbol, failed)
		if tc.want == "" && hit {
			t.Errorf("SymbolFailedPackage(%q) = %q, want no hit", tc.symbol, got)
		}
		if tc.want != "" && got != tc.want {
			t.Errorf("SymbolFailedPackage(%q) = %q, want %q", tc.symbol, got, tc.want)
		}
	}
}
