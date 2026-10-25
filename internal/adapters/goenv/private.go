package goenv

import (
	"slices"
	"strings"
	"sync"

	"golang.org/x/mod/module"
)

// The private-module matcher. Go decides the proxy leg by GONOPROXY, else
// GOPRIVATE, and the checksum leg by GONOSUMDB, else GOPRIVATE; every
// kanonarion leg that names a module path to a third party asks here.

// NoProxy reports whether path must never be named to a module proxy, and the
// variable whose pattern said so: GONOPROXY when it is set, else GOPRIVATE.
func NoProxy(path string) (string, bool) {
	if Value("GONOPROXY") != "" {
		return matchVariable(path, "GONOPROXY")
	}
	return matchVariable(path, "GOPRIVATE")
}

// HasNoProxyPatterns reports whether NoProxy can match any path at all, so a
// caller can skip wiring a route no module will take.
func HasNoProxyPatterns() bool {
	if Value("GONOPROXY") != "" {
		return len(patternsOf("GONOPROXY")) > 0
	}
	return len(patternsOf("GOPRIVATE")) > 0
}

// NoSumDB reports whether the checksum database is skipped for path, and the
// variable whose pattern said so. It skips the union of GONOSUMDB, GONOSUMCHECK
// (in its pattern form) and GOPRIVATE, which is stricter than Go's either-or.
func NoSumDB(path string) (string, bool) {
	for _, name := range []string{"GONOSUMDB", "GONOSUMCHECK", "GOPRIVATE"} {
		if v, ok := matchVariable(path, name); ok {
			return v, true
		}
	}
	return "", false
}

// NoSumDBPatterns returns every pattern NoSumDB matches against.
func NoSumDBPatterns() []string {
	var out []string
	for _, name := range []string{"GOPRIVATE", "GONOSUMCHECK", "GONOSUMDB"} {
		out = append(out, patternsOf(name)...)
	}
	return out
}

// IsBooleanTrue reports whether v is one of the spellings of "yes" Go's own
// boolean variables accept; GONOSUMCHECK in that form is not a pattern list.
func IsBooleanTrue(v string) bool {
	return slices.Contains([]string{"1", "t", "true", "y", "yes", "on"}, strings.ToLower(strings.TrimSpace(v)))
}

// MatchesPathPattern reports whether path matches pattern under the go
// command's own rule: a path.Match glob over the path's leading elements.
func MatchesPathPattern(pattern, path string) bool {
	return module.MatchPrefixPatterns(pattern, path)
}

func matchVariable(path, name string) (string, bool) {
	for _, p := range patternsOf(name) {
		if MatchesPathPattern(p, path) {
			return name, true
		}
	}
	return "", false
}

var (
	patternMu    sync.Mutex
	patternCache = map[string][]string{}
)

// patternsOf parses a variable's pattern list once per value it takes, so the
// list a process routes by is read once and a test that changes it is seen.
func patternsOf(name string) []string {
	raw := Value(name)
	// GONOSUMCHECK=1 switches the checksum database off for every module; read
	// as a pattern it would match only the module path "1".
	if name == "GONOSUMCHECK" && IsBooleanTrue(raw) {
		return nil
	}
	key := name + "=" + raw
	patternMu.Lock()
	defer patternMu.Unlock()
	if p, ok := patternCache[key]; ok {
		return p
	}
	var out []string
	for p := range strings.SplitSeq(raw, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	patternCache[key] = out
	return out
}
