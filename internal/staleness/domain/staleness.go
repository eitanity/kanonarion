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

	// Republication is the module's OWN major published at its /vN path. It is a
	// third fact, not a variant of the second. See Republication.
	Republication Republication

	// Deprecation is the module author's own "this module is obsolete"
	// declaration. It is a FOURTH fact and never merged into the other three.
	// See Deprecation.
	Deprecation Deprecation

	// LookedUpAt is when the proxy was asked. It is what the TTL is measured
	// against and what the output must state.
	LookedUpAt time.Time
}

// NewerMajor is the result of probing major-suffixed paths ABOVE the pinned
// major.
//
// It carries the upward walk's answer and nothing else. A +incompatible pin's
// own major republished at /vN is NOT one of these: the major number is
// unchanged there and only the path moved, which is a different piece of work
// with a different risk, and it lives in Republication.
//
// Probed separates "nobody has asked" from "asked, and there is none". Without
// it a row written by a same-major-only resolution would read as a negative
// answer, which is the exact failure this context exists to prevent — an unasked
// question rendered as a clean one.
type NewerMajor struct {
	// Probed is true when the probe ran to completion. When false every other
	// field is meaningless.
	Probed bool
	// FromMajor is the major the upward walk started at (pinned major + 1); see
	// PlanProbe, which is the only place that decides it. A cached probe is only
	// reusable for a request that would start at the same major: the same bare
	// path pinned at v1 and at v2+incompatible start at /v2 and /v3, and the
	// first stops on a gap the second steps over.
	//
	// A +incompatible pin also asks about its own major before the walk, and
	// that question rides on the same start: it is asked by exactly the pins
	// whose walk starts above a bare path's major, so a row carrying its answer
	// can never be served to a pin that did not ask it.
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

// Republication is the module's own major published at its /vN path — the
// answer to the extra question a +incompatible pin asks before the upward walk.
//
// It is a separate type from NewerMajor because it is a separate fact. +incompatible
// is what a module looks like BEFORE it adopts the /vN path, so /vN carries the
// SAME major number the project is already on: moving to it is a path migration,
// not a major upgrade. Reported as a newer major it told a reader to budget for
// a breaking change where chi v3.3.4+incompatible -> chi/v3@v3.3.5 is a patch.
//
// The two facts can both hold at once, and both are then reported, this one
// first — it is the nearer move and the likelier action for a stuck pin.
type Republication struct {
	// Asked is true when the probe put the question. It is put only for a
	// +incompatible pin on a bare path; see ProbePlan. False means the question
	// does not apply to this module, NOT that the answer was no — the same
	// distinction NewerMajor.Probed draws for the walk.
	Asked bool
	// Path is the /vN path that resolved. Empty when Asked and none did — a
	// recorded negative, which is a real answer and is cacheable.
	Path string
	// Version is the newest version at Path.
	Version string
	// PublishedAt is that version's publication time; zero when unsupplied.
	PublishedAt time.Time
}

// Exists reports whether the module's own major was found republished at /vN.
func (p Republication) Exists() bool { return p.Asked && p.Path != "" }

// Deprecation is the module's own deprecation notice — the `// Deprecated:`
// comment on the `module` directive in its go.mod, which the go command reports
// alongside the latest-version answer.
//
// It is a SEPARATE fact from NewerMajor and Republication, and reporting it
// beside them rather than folded into them is the whole point: the successor a
// notice names is frequently at a path the /vN walk structurally cannot reach —
// google.golang.org/protobuf succeeds github.com/golang/protobuf on a different
// host entirely — while a module with a newer major is usually not deprecated
// at all. They are different claims by different mechanisms.
//
// The notice is reproduced, never interpreted. kanonarion does not decide
// whether the named successor is a good idea, does not rewrite the sentence, and
// above all does not GUESS a successor from name similarity: aws-sdk-go-v2 is
// the successor of aws-sdk-go because its author said so in machine-readable
// form, not because the strings look alike.
type Deprecation struct {
	// Checked is true when the question was ANSWERED. When false, Notice is
	// meaningless and the module's deprecation state is not established — which
	// is a different thing from "not deprecated" and must never render as one.
	//
	// It is false for every answer obtained one path at a time: a proxy @latest
	// lookup returns a version and a date and says nothing about deprecation, so
	// a row resolved that way has not been asked.
	Checked bool
	// Notice is the declaration verbatim, or empty when Checked and the module
	// declares none — a recorded negative, and a real answer.
	Notice string
}

// Deprecated reports whether the module declares itself deprecated. It is false
// both for a module that declares nothing and for one nobody asked about; the
// two are told apart by Checked, which every renderer states.
func (d Deprecation) Deprecated() bool { return d.Checked && d.Notice != "" }

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

// ProbePlan is the set of module paths a newer-major probe visits for one
// pinned module: the ordinary upward walk, and — for a +incompatible pin — the
// suffixed publication of the module's OWN major, asked first.
//
// The two are separate because only one of them can be settled by absence.
// Walking upward from N+1 asks "is there a major line above this one", and an
// absent N+1 settles it: majors are published in sequence, so a gap is the end.
// Asking about /vN asks something else — "has this major been republished at a
// versioned path" — and an absent /vN settles nothing about N+1, which is why
// it is not a step of the walk and never ends it.
type ProbePlan struct {
	// start is the first major of the upward walk. It is what NewerMajor.FromMajor
	// records, and its meaning has not changed: the walk never looks at or below
	// the major already in use.
	start int
	// sameMajor is the module's own major, to be asked about before the walk, or
	// 0 when there is nothing to ask. Non-zero only for a +incompatible pin on a
	// bare path.
	sameMajor int
}

// Start returns the first major of the upward walk.
func (p ProbePlan) Start() int { return p.start }

// SameMajor returns the module's own major to probe before the walk, and
// whether there is one. An absence there is the expected case and must not end
// the walk.
func (p ProbePlan) SameMajor() (int, bool) { return p.sameMajor, p.sameMajor != 0 }

// PlanProbe returns the probe plan for a module pinned at pinnedVersion.
//
// The walk's start is derived from the pinned version's own major and not from
// the path suffix alone. A +incompatible pin carries its major in the VERSION
// while living at the unsuffixed path — Masterminds/sprig v2.22.0+incompatible
// is the case — so a suffix-derived walk would start at /v2, find nothing (v2
// was never published under a suffixed path), stop on that gap and never see
// /v3. Taking the larger of the two majors starts above whichever carries it.
//
// That same shape is why a +incompatible pin gets the extra same-major
// question. +incompatible is what a module looks like BEFORE it adopts the /vN
// path, so "this major is now published properly at /vN" is the migration the
// pin most needs to hear about, and it lives at a path the same-major latest
// question can never see: gavv/httpexpect v2.0.0+incompatible has /v2 published
// and no /v3 at all, and the walk alone reports it as having nowhere to go.
//
// When both exist — a republished /vN and a genuine next major — the walk still
// runs and BOTH are reported, in separate fields, the republication first.
// go-chi/chi v3.3.4+incompatible is the case: /v3@v3.3.5 is a patch-level move
// to the correctly-published path and /v5@v5.3.1 is a two-major migration, and a
// row that reported only the higher dropped the cheaper answer entirely.
//
// A module already pinned to a /vN path is asked nothing extra. Its own major
// is the path it is already on, so probing it would ask whether the module the
// caller is using exists, and the answer would name the pin as its own upgrade.
//
// pinnedVersion may be empty, which reads as major 1: the caller has no pin and
// the walk starts at /v2, per the bare-path rule.
func PlanProbe(path, pinnedVersion string) ProbePlan {
	fam := ParseFamily(path)
	pinned := majorOf(pinnedVersion)

	base := fam.Major()
	if pinned > base {
		base = pinned
	}
	if base < 1 {
		base = 1
	}
	plan := ProbePlan{start: base + 1}

	// Only a bare path can carry its major in the version, and only a major at
	// or above 2 has a suffixed path to be republished at. A /vN path names its
	// own major and must never re-probe it.
	if fam.Major() == 0 && pinned >= 2 && isIncompatible(pinnedVersion) {
		plan.sameMajor = pinned
	}
	return plan
}

// ProbeStartMajor returns the first major of the upward walk. It is the value
// stored in NewerMajor.FromMajor, and comparing it against a stored row is how
// a reusable cached probe is told from one that started somewhere else.
func ProbeStartMajor(path, pinnedVersion string) int {
	return PlanProbe(path, pinnedVersion).Start()
}

// isIncompatible reports whether version carries the +incompatible build tag —
// the marker that the major is the version's and not the path's.
func isIncompatible(version string) bool {
	if version == "" {
		return false
	}
	if !strings.HasPrefix(version, "v") {
		version = "v" + version
	}
	return semver.Build(version) == "+incompatible"
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

// PinPosition is where a pinned version sits relative to the newest version
// published at the module's own path.
//
// It exists because "is the pin the latest" was answered by string equality,
// which has only two outcomes and therefore reports the third — a pin that
// sorts ABOVE @latest — as "behind". A pin can be ahead for ordinary reasons:
// a pseudo-version taken after the last tag, or a pre-modules +incompatible
// major published above the newest version the proxy will serve from the
// unsuffixed path. In both cases the version @latest names is a DOWNGRADE, and
// offering it as an upgrade target drives the decision backwards.
type PinPosition int

const (
	// PinBehind: @latest names a newer version than the pin. This is the only
	// position that has an upgrade target, and the only one an age figure means
	// anything for — the age is how long the project has been behind.
	PinBehind PinPosition = iota - 1
	// PinLevel: the pin is the newest version at this path.
	PinLevel
	// PinAhead: the pin sorts above @latest. There is nothing at this path to
	// move to. It is NOT the same as PinLevel — the pin is not the newest
	// PUBLISHED version, it is simply above it — and it is not "current" either,
	// because a newer major line may still exist at another path. That second
	// fact is NewerMajor's, stated beside this one and never folded into it.
	PinAhead
)

// CanSortAboveTag reports whether a version could possibly sort ABOVE the
// newest release tag at its own path.
//
// Only two shapes can: a prerelease (which includes every pseudo-version, whose
// -0.YYYYMMDDHHMMSS-abcdef suffix is prerelease metadata) and a +incompatible
// version, whose major lives in the version while the path serves a lower one.
// A plain release version cannot be above the newest release tag, because it IS
// one.
//
// It exists to narrow a lookup, never to answer a question. A batched source
// that resolves within the pin's own major reports "no update" both for a pin
// that is the newest release and for one sitting above the last tag, and the
// two have to be told apart by asking the path's @latest. Asking for every
// module would restore the per-module sweep; this says which pins could
// possibly be in the second state, and the answer for those is still MEASURED
// by asking. A false positive costs one request. A false negative would report
// an ahead pin as current, which is why the predicate is deliberately loose:
// every prerelease and every +incompatible is asked, not the subset that looks
// like a pseudo-version.
//
// It is a syntactic reading of a version string and nothing more. Nothing is
// concluded from it; it only decides what to go and measure.
func CanSortAboveTag(version string) bool {
	if version == "" {
		return false
	}
	if !strings.HasPrefix(version, "v") {
		version = "v" + version
	}
	if !semver.IsValid(version) {
		// Unreadable by semver, so nothing can be ruled out. Ask.
		return true
	}
	return semver.Prerelease(version) != "" || semver.Build(version) == "+incompatible"
}

// ComparePin places pinned against the path's @latest answer.
//
// Ordering is semver's, not the string's, so v10.0.0 sorts above v9.0.0 and a
// pseudo-version sorts above the tag it was taken after. Build metadata is not
// ordering information in semver, so a +incompatible pin and the same version
// without the tag are level — which is the honest answer, and one string
// equality got wrong in the other direction.
//
// A version either side cannot read as semver yields PinBehind when the two
// differ: the comparison could not be made, and the pre-existing reading — the
// proxy's answer is what is newest — is kept rather than upgraded into a claim
// that the pin is ahead. Nothing here can order two strings semver cannot read.
func ComparePin(pinned, latest string) PinPosition {
	if pinned == latest {
		return PinLevel
	}
	if !semver.IsValid(pinned) || !semver.IsValid(latest) {
		return PinBehind
	}
	switch c := semver.Compare(pinned, latest); {
	case c < 0:
		return PinBehind
	case c > 0:
		return PinAhead
	}
	return PinLevel
}
