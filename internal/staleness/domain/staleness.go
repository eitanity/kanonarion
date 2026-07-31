// Package domain holds the staleness bounded context: what "how far behind is
// this dependency" means, and the module-path arithmetic that answering it
// honestly requires.
//
// Staleness is deliberately TWO facts, never one. The same-major latest answers
// "what is the newest version of this exact module path". The newer-major probe
// answers "does a newer major line exist at all", which lives at a DIFFERENT
// path and is therefore invisible to the first question. A module pinned several
// majors behind resolves to its own path's newest version and would otherwise be
// reported with the strongest answer the column has — current — while being the
// most stale kind of dependency there is. The two are kept as separate fields so
// no rendering can collapse them.
package domain

import (
	"strconv"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

// Record is one module path's cached upstream-latest facts.
//
// It is a dated cache of what a module proxy said, not an extracted fact: there
// is nothing in it to verify, and it is expected to be overwritten. That is why
// it carries no content hash and no pipeline version — the only thing that makes
// it trustworthy is LookedUpAt, and every consumer is required to state it.
type Record struct {
	// ModulePath is the path as written in go.mod. It is the ledger key.
	ModulePath string

	// LatestVersion is the newest version published at ModulePath itself.
	LatestVersion string
	// LatestPublishedAt is that version's publication time. Zero when the proxy
	// did not supply one — a date is never fabricated for a module that has none.
	LatestPublishedAt time.Time

	// NewerMajor is the separate major-line fact. See NewerMajor.
	NewerMajor NewerMajor

	// LookedUpAt is when the proxy was asked. It is what the TTL is measured
	// against and what the output must state.
	LookedUpAt time.Time
}

// NewerMajor is the result of probing major-suffixed paths above the pinned
// major.
//
// Probed separates "nobody has asked" from "asked, and there is none". Without
// it a row written by a same-major-only resolution would read as a negative
// answer, which is the exact failure this context exists to prevent — an unasked
// question rendered as a clean one.
type NewerMajor struct {
	// Probed is true when the probe ran to completion. When false every other
	// field is meaningless.
	Probed bool
	// FromMajor is the major the probe started at (pinned major + 1). A cached
	// probe is only reusable for a request that would start at the same major:
	// the same bare path pinned at v1 and at v2+incompatible start at /v2 and
	// /v3, and the first stops on a gap the second steps over.
	FromMajor int
	// Path is the newest major path that resolved. Empty when Probed and none
	// resolved — a recorded negative, which is a real answer and is cacheable.
	Path string
	// Version is the newest version at Path.
	Version string
	// PublishedAt is that version's publication time; zero when unsupplied.
	PublishedAt time.Time
}

// Exists reports whether a newer major line was found.
func (n NewerMajor) Exists() bool { return n.Probed && n.Path != "" }

// FreshAt reports whether the record may be served instead of re-querying the
// proxy. A zero or negative ttl means never serve.
func (r Record) FreshAt(now time.Time, ttl time.Duration) bool {
	if ttl <= 0 || r.LookedUpAt.IsZero() {
		return false
	}
	return now.Sub(r.LookedUpAt) < ttl
}

// Age is how long ago the proxy was asked.
func (r Record) Age(now time.Time) time.Duration { return now.Sub(r.LookedUpAt) }

// Family decomposes a module path into the stem every major version of the
// module shares and the major the path itself names.
type Family struct {
	stem string
	// sep is the separator the module's major suffix uses: "/v" for the standard
	// convention, ".v" for gopkg.in. Rebuilding with the wrong one produces a
	// path that cannot exist (gopkg.in/yaml.v3/v4), so it is carried rather than
	// assumed.
	sep string
	// major is the major the path names, or 0 when the path names none.
	major int
}

// Stem returns the path stem shared by every major of the module.
func (f Family) Stem() string { return f.stem }

// Major returns the major the original path named, or 0 for an unsuffixed path.
func (f Family) Major() int { return f.major }

// PathForMajor renders the module path for major n. n < 2 is never a suffixed
// path in Go, so it renders as the stem.
func (f Family) PathForMajor(n int) string {
	if n < 2 {
		return f.stem
	}
	return f.stem + f.sep + strconv.Itoa(n)
}

// ParseFamily decomposes a module path. An unrecognised shape yields a family
// whose stem is the whole path and whose major is 0, which is the correct
// reading of an unsuffixed path.
func ParseFamily(path string) Family {
	if stem, n, ok := splitSuffix(path, "/v"); ok {
		return Family{stem: stem, sep: "/v", major: n}
	}
	// gopkg.in encodes the major as ".vN" on the last element. Only recognised
	// under that host: a ".v2" suffix elsewhere is part of the name.
	if strings.HasPrefix(path, "gopkg.in/") {
		if stem, n, ok := splitSuffix(path, ".v"); ok {
			return Family{stem: stem, sep: ".v", major: n}
		}
		return Family{stem: path, sep: ".v"}
	}
	return Family{stem: path, sep: "/v"}
}

// splitSuffix splits path on the final sep followed by digits only.
func splitSuffix(path, sep string) (string, int, bool) {
	i := strings.LastIndex(path, sep)
	if i < 0 {
		return "", 0, false
	}
	digits := path[i+len(sep):]
	if digits == "" {
		return "", 0, false
	}
	n, err := strconv.Atoi(digits)
	if err != nil || n < 2 {
		return "", 0, false
	}
	return path[:i], n, true
}

// ProbeStartMajor returns the first major to probe for a module pinned at
// pinnedVersion.
//
// It is derived from the pinned version's own major and not from the path
// suffix alone. A +incompatible pin carries its major in the version while
// living at the unsuffixed path — Masterminds/sprig v2.22.0+incompatible is the
// case — so a suffix-derived probe would start at /v2, find nothing (v2 was
// never published under a suffixed path), stop on that gap and never see /v3.
// Taking the larger of the two majors starts above whichever carries it.
//
// pinnedVersion may be empty, which reads as major 1: the caller has no pin and
// the probe starts at /v2, per the bare-path rule.
func ProbeStartMajor(path, pinnedVersion string) int {
	fam := ParseFamily(path)
	base := fam.Major()
	if m := majorOf(pinnedVersion); m > base {
		base = m
	}
	if base < 1 {
		base = 1
	}
	return base + 1
}

// majorOf reads the semver major of a version string, ignoring any
// +incompatible build tag. Returns 0 when unreadable.
func majorOf(version string) int {
	if version == "" {
		return 0
	}
	if !strings.HasPrefix(version, "v") {
		version = "v" + version
	}
	maj := semver.Major(version)
	if maj == "" {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimPrefix(maj, "v"))
	if err != nil {
		return 0
	}
	return n
}
