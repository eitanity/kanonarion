package goenv_test

import (
	"slices"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/goenv"
)

func clearPrivateEnv(t *testing.T) {
	t.Helper()
	noEnvFile(t)
	for _, k := range []string{"GOPRIVATE", "GONOPROXY", "GONOSUMDB", "GONOSUMCHECK"} {
		t.Setenv(k, "")
	}
}

// TestNoProxy_FollowsGoPrecedence: GONOPROXY decides the proxy leg when it is
// set, GOPRIVATE otherwise, and the answer names which one decided it.
func TestNoProxy_FollowsGoPrecedence(t *testing.T) {
	cases := []struct {
		name, private, noproxy, path string
		want                         string
		ok                           bool
	}{
		{"nothing set", "", "", "corp.example.com/a", "", false},
		{"GOPRIVATE prefix", "corp.example.com", "", "corp.example.com/a", "GOPRIVATE", true},
		{"GOPRIVATE exact", "corp.example.com/a", "", "corp.example.com/a", "GOPRIVATE", true},
		{"GOPRIVATE is a path prefix, not a string prefix", "corp.example.com/a", "", "corp.example.com/ab", "", false},
		{"GOPRIVATE list", "x.test, corp.example.com", "", "corp.example.com/a/v2", "GOPRIVATE", true},
		{"GOPRIVATE host glob, module under the host", "*.example.com", "", "corp.example.com/a", "GOPRIVATE", true},
		{"GOPRIVATE host glob, the host itself", "*.example.com", "", "corp.example.com", "GOPRIVATE", true},
		{"GOPRIVATE host glob does not match the bare domain", "*.example.com", "", "example.com", "", false},
		{"GOPRIVATE host glob mismatch", "*.example.com", "", "example.org/pub", "", false},
		{"GOPRIVATE element glob", "github.com/acme/*", "", "github.com/acme/tool/v2", "GOPRIVATE", true},
		{"GOPRIVATE mismatch", "corp.example.com", "", "example.org/pub", "", false},
		{"GONOPROXY wins", "corp.example.com", "other.test", "corp.example.com/a", "", false},
		{"GONOPROXY=none routes everything through the proxy", "corp.example.com", "none", "corp.example.com/a", "", false},
		{"GONOPROXY alone", "", "corp.example.com", "corp.example.com/a", "GONOPROXY", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearPrivateEnv(t)
			t.Setenv("GOPRIVATE", tc.private)
			t.Setenv("GONOPROXY", tc.noproxy)
			got, ok := goenv.NoProxy(tc.path)
			if got != tc.want || ok != tc.ok {
				t.Errorf("NoProxy(%q) = %q, %v; want %q, %v", tc.path, got, ok, tc.want, tc.ok)
			}
			if has := goenv.HasNoProxyPatterns(); has != (tc.private != "" && tc.noproxy == "" || tc.noproxy != "") {
				t.Errorf("HasNoProxyPatterns() = %v with GOPRIVATE=%q GONOPROXY=%q", has, tc.private, tc.noproxy)
			}
		})
	}
}

// TestNoProxy_ReadsTheEnvFile: a pattern written with `go env -w` is honoured
// exactly as an exported one is.
func TestNoProxy_ReadsTheEnvFile(t *testing.T) {
	clearPrivateEnv(t)
	writeEnvFile(t, "GOPRIVATE=corp.example.com\n")
	if got, ok := goenv.NoProxy("corp.example.com/a"); !ok || got != "GOPRIVATE" {
		t.Errorf("NoProxy = %q, %v; want GOPRIVATE from the env file", got, ok)
	}
}

// TestNoSumDB_NamesTheVariableInForce: the checksum leg skips the union of the
// three variables and names the one that matched, GONOSUMDB first.
func TestNoSumDB_NamesTheVariableInForce(t *testing.T) {
	cases := []struct {
		name, private, nosumdb, nosumcheck string
		want                               string
		ok                                 bool
	}{
		{"none", "", "", "", "", false},
		{"GOPRIVATE", "corp.example.com", "", "", "GOPRIVATE", true},
		{"GONOSUMDB", "", "corp.example.com", "", "GONOSUMDB", true},
		{"GONOSUMDB before GOPRIVATE", "corp.example.com", "corp.example.com", "", "GONOSUMDB", true},
		{"GONOSUMCHECK pattern", "", "", "corp.example.com", "GONOSUMCHECK", true},
		{"GONOSUMCHECK boolean is not a pattern", "", "", "1", "", false},
		{"GONOPROXY=none leaves GOPRIVATE on the checksum leg", "corp.example.com", "", "", "GOPRIVATE", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearPrivateEnv(t)
			t.Setenv("GOPRIVATE", tc.private)
			t.Setenv("GONOSUMDB", tc.nosumdb)
			t.Setenv("GONOSUMCHECK", tc.nosumcheck)
			t.Setenv("GONOPROXY", "none")
			got, ok := goenv.NoSumDB("corp.example.com/a")
			if got != tc.want || ok != tc.ok {
				t.Errorf("NoSumDB = %q, %v; want %q, %v", got, ok, tc.want, tc.ok)
			}
		})
	}
}

// TestNoSumDBPatterns_SkipsEmptyEntriesAndTheBooleanForm.
func TestNoSumDBPatterns_SkipsEmptyEntriesAndTheBooleanForm(t *testing.T) {
	clearPrivateEnv(t)
	t.Setenv("GOPRIVATE", "a.test,, b.test")
	t.Setenv("GONOSUMCHECK", "yes")
	t.Setenv("GONOSUMDB", "c.test")
	if got, want := goenv.NoSumDBPatterns(), []string{"a.test", "b.test", "c.test"}; !slices.Equal(got, want) {
		t.Errorf("NoSumDBPatterns() = %v, want %v", got, want)
	}
}

// TestIsBooleanTrue covers every spelling Go accepts and a pattern list.
func TestIsBooleanTrue(t *testing.T) {
	for _, v := range []string{"1", "t", "TRUE", "y", "yes", " on "} {
		if !goenv.IsBooleanTrue(v) {
			t.Errorf("IsBooleanTrue(%q) = false", v)
		}
	}
	for _, v := range []string{"", "0", "corp.example.com", "off"} {
		if goenv.IsBooleanTrue(v) {
			t.Errorf("IsBooleanTrue(%q) = true", v)
		}
	}
}
