package goenv

import (
	"fmt"
	"sort"
)

// ModCache is the cache path the fetched-with-modcache posture is stated
// against; the producer under test is called with this value so the table and
// the assertion cannot drift apart.
const ModCache = "/kanonarion-posture/modcache"

// Posture is one analysis environment stated as the variables the Go child must
// see and the variables the producer must leave exactly as its caller had them.
type Posture struct {
	Name    string
	Require map[string]string
	Forbid  []string
}

// postures is the single statement of every analysis environment in this
// repository. It is asserted against the producers rather than against a call
// site, and a producer whose variable set drifts from its entry fails here.
var postures = map[string]Posture{
	// isolatedModuleEnv: the workspace isolation on its own. Everything else the
	// extracted-module analysis needs is layered on top of it.
	"extracted-module": {
		Require: map[string]string{"GOWORK": "off"},
		Forbid:  []string{"GOPROXY", "GOSUMDB", "GOTOOLCHAIN", "GOFLAGS", "GOMODCACHE", "GOGC"},
	},
	"extracted-module-analysis": {
		Require: map[string]string{
			"GOWORK": "off", "GOPROXY": "off", "GOSUMDB": "off",
			"GOTOOLCHAIN": "local", "GOFLAGS": "-mod=mod",
		},
		Forbid: []string{"GOMODCACHE", "GOGC"},
	},
	// -mod=readonly on both worktree postures. The tree belongs to the developer,
	// and -mod=mod lets the go command close a missing go.sum entry from the
	// module cache rather than report it.
	"worktree": {
		Require: map[string]string{
			"GOWORK": "off", "GOPROXY": "off", "GOSUMDB": "off",
			"GOTOOLCHAIN": "local", "GOFLAGS": "-mod=readonly",
		},
		Forbid: []string{"GOMODCACHE", "GOGC"},
	},
	"worktree-workspace": {
		Require: map[string]string{
			"GOPROXY": "off", "GOSUMDB": "off",
			"GOTOOLCHAIN": "local", "GOFLAGS": "-mod=readonly",
		},
		Forbid: []string{"GOWORK", "GOMODCACHE", "GOGC"},
	},
	// The vendored surface reads no module cache and runs no MVS, so it leaves
	// the checksum database on and the toolchain unpinned: it completes a
	// toolchain switch offline from cached data, and pinning it would break
	// projects that resolve today.
	"scan-vendored": {
		Require: map[string]string{
			"GOGC": "30", "GOWORK": "off", "GOFLAGS": "-mod=vendor", "GOPROXY": "off",
		},
		Forbid: []string{"GOSUMDB", "GOTOOLCHAIN", "GOMODCACHE"},
	},
	"scan-fetched": {
		Require: map[string]string{"GOGC": "30", "GOWORK": "off"},
		Forbid:  []string{"GOFLAGS", "GOPROXY", "GOSUMDB", "GOTOOLCHAIN", "GOMODCACHE"},
	},
	"scan-fetched-modcache": {
		Require: map[string]string{
			"GOGC": "30", "GOWORK": "off", "GOMODCACHE": ModCache,
			"GOFLAGS": "-mod=mod", "GOSUMDB": "off", "GOTOOLCHAIN": "local", "GOPROXY": "off",
		},
	},
	// The one escalation any of the three pinned analysis postures may take: the
	// installed toolchain is older than the analysed module's go directive and a
	// toolchain that satisfies it is already unpacked on this host, so the
	// selection moves from `local` to `path`. This posture is stated against the
	// UNESCALATED environment as its base, so the Forbid list says what the
	// escalation must leave exactly where it found it: the network stays off, the
	// workspace stays isolated, the module flag stays as its own posture chose.
	// PATH is absent from both lists because moving it is the whole mechanism.
	"on-disk-toolchain": {
		Require: map[string]string{"GOTOOLCHAIN": "path"},
		Forbid:  []string{"GOPROXY", "GOSUMDB", "GOWORK", "GOFLAGS", "GOMODCACHE", "GOGC"},
	},
	// A project that has a vendor tree and a caller declining it: Go selects
	// -mod=vendor from the tree's mere presence, so the fetched surface has to
	// say otherwise, and that flag is refused in workspace mode.
	"project-fetched-over-vendor": {
		Require: map[string]string{"GOGC": "30", "GOWORK": "off", "GOFLAGS": "-mod=mod"},
		Forbid:  []string{"GOPROXY", "GOSUMDB", "GOTOOLCHAIN", "GOMODCACHE"},
	},
}

// EnvBuilders is the closed set of functions allowed to build a process
// environment by appending to os.Environ(), keyed "<package dir> <function>".
// A new one is a new posture nothing states, which is the shape all three prior
// defects had.
var EnvBuilders = map[string]string{
	"internal/callgraph/adapters/analyser/staticcha isolatedModuleEnv": "extracted-module",
	"internal/adapters/proxy/modcache download":                        "not an analysis child: populates a module cache",
	"internal/staleness/adapters/golist childEnv":                      "not an analysis child: an update probe that must reach a proxy",
}

// For returns the named posture. Absent means the caller named one that does not
// exist, which must fail rather than assert nothing.
func For(name string) (Posture, bool) {
	p, ok := postures[name]
	if !ok {
		return Posture{}, false
	}
	p.Name = name
	return p, true
}

// Verify reports every way the environment got departs from p. base is what the
// producer was given, so a forbidden variable is one the producer itself added
// or changed rather than one the caller already carried.
func Verify(p Posture, base, got []string) []string {
	var out []string
	for _, k := range sortedKeys(p.Require) {
		v, ok := lastValue(got, k)
		if !ok || v != p.Require[k] {
			out = append(out, fmt.Sprintf("%s: child sees %s=%q (set=%t), want %q", p.Name, k, v, ok, p.Require[k]))
		}
	}
	for _, k := range p.Forbid {
		bv, bok := lastValue(base, k)
		gv, gok := lastValue(got, k)
		if bok != gok || bv != gv {
			out = append(out, fmt.Sprintf("%s: producer set %s=%q (set=%t); this posture must leave it at %q (set=%t)",
				p.Name, k, gv, gok, bv, bok))
		}
	}
	return out
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
