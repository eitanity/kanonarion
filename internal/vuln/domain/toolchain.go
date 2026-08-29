package domain

import (
	"sort"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

// ToolchainModulePath is the key the Go advisory database lists toolchain
// advisories under. It is disjoint from the stdlib key: stdlib advisories name
// packages a project imports, while toolchain advisories name cmd/* — the go
// command, the compiler, the linker — which no project imports and which no
// symbol-reachability analysis of scanned code can therefore ever reach. The
// stdlib walk node is not a proxy for it, so the key is asked for by name.
const ToolchainModulePath = "toolchain"

// ToolchainRange is one affected interval an advisory states for the toolchain,
// as the OSV record's introduced/fixed events describe it. Versions are the
// database's own bare form ("1.25.10", "1.26.0-0"); an Introduced of "0" is the
// zero version and opens an interval with no lower bound, and an empty Fixed is
// an interval with no upper bound (no released fix).
type ToolchainRange struct {
	Introduced string
	Fixed      string
}

// ToolchainAdvisory is one advisory the database lists under the toolchain key,
// carrying only what judging a toolchain version against it needs: its id, the
// intervals it covers, and whether it has been retracted.
type ToolchainAdvisory struct {
	// ID is the advisory identifier, e.g. "GO-2026-4984".
	ID string
	// Summary is the advisory's own one-line description, empty when the record
	// carried none.
	Summary string
	// Ranges are the affected intervals stated for the toolchain package.
	Ranges []ToolchainRange
	// WithdrawnAt is the OSV retraction timestamp, zero when the advisory stands.
	WithdrawnAt time.Time
}

// IsWithdrawn reports whether the advisory has been retracted by the database
// that published it. It is the same word, and the same test, the module findings
// axis uses: a retracted advisory still matched, so it is never silently dropped
// and never counted as a live finding either.
func (a ToolchainAdvisory) IsWithdrawn() bool { return !a.WithdrawnAt.IsZero() }

// FixedFor returns the version that fixes this advisory for the release branch
// version is on: the upper bound of the interval that covers it. Empty when no
// interval covers version, or when the one that does has no fix yet.
//
// The branch matters, and reporting the advisory's lowest fix instead would
// misdirect. GO-2026-4984 is fixed at 1.25.10 on the 1.25 line and 1.26.3 on the
// 1.26 line; a reader on go1.26.2 who moved to 1.25.10 would be moving backwards
// into a toolchain the advisory still covers.
func (a ToolchainAdvisory) FixedFor(version string) string {
	v := toolchainSemver(version)
	if !semver.IsValid(v) {
		return ""
	}
	for _, r := range a.Ranges {
		if toolchainCovered(v, []ToolchainRange{r}) {
			return r.Fixed
		}
	}
	return ""
}

// ToolchainAdvisorySet is what a stored snapshot says about the toolchain key.
//
// KeyPresent is carried separately from the advisories because the two absences
// are different facts: a snapshot whose index has no toolchain key cannot judge
// a toolchain at all, while a snapshot that has the key and lists advisories
// none of which cover this version is a measurement that came back clear. A
// single empty slice would make the first read as the second.
type ToolchainAdvisorySet struct {
	KeyPresent bool
	Advisories []ToolchainAdvisory
}

// ToolchainJudgmentStatus is the toolchain axis's own vocabulary. It borrows the
// findings words rather than inventing new ones — a matched-but-retracted
// advisory is Withdrawn here for the same reason it is Withdrawn on a module
// record — and adds the one word the module axis has no need for: a judgment
// that could not be made at all.
type ToolchainJudgmentStatus string

const (
	// ToolchainClear: the snapshot's toolchain advisories were read and none of
	// them covers this toolchain version.
	ToolchainClear ToolchainJudgmentStatus = "clear"
	// ToolchainAffected: at least one advisory that still stands covers it.
	ToolchainAffected ToolchainJudgmentStatus = "affected"
	// ToolchainWithdrawn: advisories cover it but every one of them has been
	// retracted by the database that published it.
	ToolchainWithdrawn ToolchainJudgmentStatus = "withdrawn"
	// ToolchainUnjudged: no judgment was made, and Reason says what stopped it.
	// It is never rendered as an absence — a toolchain that could not be judged
	// is a fact about the evidence, not a quiet clear.
	ToolchainUnjudged ToolchainJudgmentStatus = "unjudged"
)

// ToolchainJudgment is the derived answer to "does the advisory database's
// toolchain key say anything about the toolchain that built this walk".
//
// It is derived at report time from the stored snapshot and the walk's recorded
// build toolchain, and it is recorded nowhere: no record shape carries it, so
// every walk already taken is classified by it immediately and every judgment
// improves as snapshots advance.
//
// It is an axis of its own. It is never merged into module findings and never
// counted in the affected/clean roll-ups: the toolchain is not a dependency of
// the artefact, and a reader counting affected modules must get the same number
// whether or not this judgment was made.
type ToolchainJudgment struct {
	// Version is the toolchain version judged, as the walk recorded it.
	Version string
	// Snapshot is the advisory database generation it was judged against.
	Snapshot DatabaseSnapshot
	// Status is the judgment.
	Status ToolchainJudgmentStatus
	// Covering are the advisories whose ranges cover Version and that still
	// stand, sorted by id.
	Covering []ToolchainAdvisory
	// WithdrawnCovering are the advisories whose ranges cover Version but which
	// have been retracted, sorted by id.
	WithdrawnCovering []ToolchainAdvisory
	// Judged is how many toolchain advisories the snapshot listed, so a clear
	// says what it was measured against rather than only its conclusion.
	Judged int
	// Reason is why no judgment could be made; set only when Status is
	// ToolchainUnjudged.
	Reason string
}

// Reasons a toolchain judgment cannot be made. Each names the missing input
// rather than the conclusion, because the remedy differs: a walk with no
// recorded toolchain is re-walked, a snapshot with no toolchain key is
// refreshed, and an incomparable version is a build nobody can judge by version
// at all.
const (
	ToolchainReasonNoVersion    = "the walk recorded no build toolchain version"
	ToolchainReasonNoSnapshot   = "no advisory database snapshot is stored"
	ToolchainReasonNoKey        = "the snapshot's module index carries no toolchain key"
	ToolchainReasonUncomparable = "the recorded toolchain version is not comparable to the database's version ranges"
)

// JudgeToolchain derives the judgment: which of the snapshot's toolchain
// advisories cover this toolchain version.
//
// version is the toolchain the walk recorded building under, in the form
// `go env GOVERSION` reports ("go1.26.5"); the database states its ranges bare
// ("1.26.3"), and both are normalised to a comparable semantic version here.
// A version that cannot be normalised is reported unjudged rather than
// compared, because the alternative — the conservative "assume affected" a
// module scan uses to avoid dropping a known hit — would here manufacture a
// finding against a toolchain nothing was measured about.
func JudgeToolchain(version string, snapshot DatabaseSnapshot, set ToolchainAdvisorySet) ToolchainJudgment {
	j := ToolchainJudgment{Version: version, Snapshot: snapshot, Judged: len(set.Advisories)}
	switch {
	case strings.TrimSpace(version) == "":
		j.Status, j.Reason = ToolchainUnjudged, ToolchainReasonNoVersion
		return j
	case snapshot.IsZero():
		j.Status, j.Reason = ToolchainUnjudged, ToolchainReasonNoSnapshot
		return j
	case !set.KeyPresent:
		j.Status, j.Reason = ToolchainUnjudged, ToolchainReasonNoKey
		return j
	}

	v := toolchainSemver(version)
	if !semver.IsValid(v) {
		j.Status, j.Reason = ToolchainUnjudged, ToolchainReasonUncomparable
		return j
	}

	for _, adv := range set.Advisories {
		if !toolchainCovered(v, adv.Ranges) {
			continue
		}
		if adv.IsWithdrawn() {
			j.WithdrawnCovering = append(j.WithdrawnCovering, adv)
			continue
		}
		j.Covering = append(j.Covering, adv)
	}
	sortToolchainAdvisories(j.Covering)
	sortToolchainAdvisories(j.WithdrawnCovering)

	// One advisory that still stands decides the axis. A retraction is reported
	// only when nothing live matched, exactly as the module findings axis ranks
	// it: Withdrawn is a finding word and must not collapse to clear.
	switch {
	case len(j.Covering) > 0:
		j.Status = ToolchainAffected
	case len(j.WithdrawnCovering) > 0:
		j.Status = ToolchainWithdrawn
	default:
		j.Status = ToolchainClear
	}
	return j
}

// ToolchainAdvisoryLess is the canonical ordering for ToolchainAdvisory slices.
// The identifier leads; the summary, the withdrawal timestamp and the affected
// intervals follow, so two advisories reaching this list under one identifier —
// one database serving a revised entry beside the original — still have a
// defined order.
func ToolchainAdvisoryLess(a, b ToolchainAdvisory) bool {
	if a.ID != b.ID {
		return a.ID < b.ID
	}
	if a.Summary != b.Summary {
		return a.Summary < b.Summary
	}
	if !a.WithdrawnAt.Equal(b.WithdrawnAt) {
		return a.WithdrawnAt.Before(b.WithdrawnAt)
	}
	if len(a.Ranges) != len(b.Ranges) {
		return len(a.Ranges) < len(b.Ranges)
	}
	for i := range a.Ranges {
		if a.Ranges[i].Introduced != b.Ranges[i].Introduced {
			return a.Ranges[i].Introduced < b.Ranges[i].Introduced
		}
		if a.Ranges[i].Fixed != b.Ranges[i].Fixed {
			return a.Ranges[i].Fixed < b.Ranges[i].Fixed
		}
	}
	return false
}

func sortToolchainAdvisories(advs []ToolchainAdvisory) {
	sort.Slice(advs, func(i, j int) bool { return ToolchainAdvisoryLess(advs[i], advs[j]) })
}

// toolchainCovered walks the advisory's intervals and reports whether v — a
// valid, v-prefixed semantic version — falls inside any of them. Each range is
// the half-open interval [introduced, fixed), and an interval whose fixed bound
// is absent runs to infinity.
//
// A range with no introduced bound at all is read as opening at the zero
// version: the database writes an explicit introduced "0" for that case, but a
// record that omits it still describes versions below its fix.
func toolchainCovered(v string, ranges []ToolchainRange) bool {
	for _, r := range ranges {
		if r.Introduced != "" && r.Introduced != "0" {
			lo := toolchainSemver(r.Introduced)
			if !semver.IsValid(lo) || semver.Compare(v, lo) < 0 {
				continue
			}
		}
		if r.Fixed == "" {
			return true
		}
		hi := toolchainSemver(r.Fixed)
		if !semver.IsValid(hi) {
			continue
		}
		if semver.Compare(v, hi) < 0 {
			return true
		}
	}
	return false
}

// toolchainSemver normalises a Go toolchain version onto the semantic version
// grammar semver.Compare reads. `go env GOVERSION` reports "go1.26.5" and the
// advisory database states "1.26.3"; both become "v1.26.5" / "v1.26.3".
//
// It does not attempt to rewrite a release-candidate toolchain ("go1.27rc1")
// into a semantic pre-release: that string is not a version this function can
// claim to have understood, so it is returned in a form semver.IsValid rejects
// and the caller reports the version unjudged.
func toolchainSemver(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "go")
	if v == "" {
		return ""
	}
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	return v
}
