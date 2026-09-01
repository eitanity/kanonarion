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
	// The project surface with no vendor tree, and the one posture in this table
	// that overrides nothing about resolution. It analyses a live working tree
	// the caller named, so the build it must measure is the one the go command
	// produces in that tree — which is defined by the caller's own environment.
	//
	// The toolchain and the network are therefore left exactly as the caller has
	// them, and that is a decision rather than an omission. Pinning GOTOOLCHAIN
	// would refuse a project whose go directive exceeds the installed toolchain,
	// which is the class two closed defects have already had to undo; pinning
	// GOPROXY would refuse a build whose dependency is not yet in the module
	// cache. Both are builds the developer has and the scan would not.
	//
	// GOWORK is forbidden for the same reason, and it is the one this posture had
	// wrong: a workspace in scope IS the tree's build configuration, and
	// disabling it made the scan resolve a different module graph from the one
	// the walk resolved and the developer compiles.
	//
	// GOGC is the single exception, and it is not resolution: govulncheck holds
	// the whole package graph live, and the default pacing costs the host memory
	// the analysis does not need to spend.
	"scan-project": {
		Require: map[string]string{"GOGC": "30"},
		Forbid:  []string{"GOWORK", "GOFLAGS", "GOPROXY", "GOSUMDB", "GOTOOLCHAIN", "GOMODCACHE"},
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

// Variables is every environment variable this table states an answer about, in
// sorted order. A variable is "stated" by being required or forbidden by any one
// posture; the table is then held to answering for it on all of them.
func Variables() []string { return variables(postures) }

// VerifyTable reports every way the table itself is incomplete, independently of
// any producer.
//
// The rule is the one thing per-surface assertions cannot check: a variable that
// matters on one surface has to be answered on every surface, either as a value
// the child must see or as a value the producer must leave alone. Silence is not
// an answer — it is what a reader cannot tell apart from a decision, and it is
// how each of the four closed defects in this class spread. A fifth variable
// added to one producer's posture and to no other fails here, which is the whole
// reason the table exists rather than nine independent assertions.
//
// PATH is stated by no posture and so is asked of none: the toolchain escalation
// moves it deliberately, and a table that forbade it would forbid the mechanism.
func VerifyTable() []string { return verifyTable(postures) }

// verifyTable is VerifyTable against a given table, so a test can plant a
// misstatement in a copy and watch this catch it rather than asserting that the
// shipped table happens to be right today.
func verifyTable(table map[string]Posture) []string {
	all := variables(table)
	var out []string
	for _, name := range sortedNames(table) {
		p := table[name]
		forbidden := map[string]bool{}
		for _, k := range p.Forbid {
			forbidden[k] = true
		}
		for _, k := range all {
			_, required := p.Require[k]
			switch {
			case required && forbidden[k]:
				out = append(out, fmt.Sprintf("%s: states %s both as a value the child must see and as one the producer must not set", name, k))
			case !required && !forbidden[k]:
				out = append(out, fmt.Sprintf("%s: says nothing about %s, which another posture states; every surface must answer for it, "+
					"as a required value or as one this surface leaves alone", name, k))
			}
		}
	}
	return out
}

// variables is the union of everything table states, sorted.
func variables(table map[string]Posture) []string {
	seen := map[string]bool{}
	for _, p := range table {
		for k := range p.Require {
			seen[k] = true
		}
		for _, k := range p.Forbid {
			seen[k] = true
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// sortedNames lists a table's posture names in a fixed order, so a failure reads
// the same way on every run.
func sortedNames(table map[string]Posture) []string {
	out := make([]string, 0, len(table))
	for name := range table {
		out = append(out, name)
	}
	sort.Strings(out)
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
