package domain

import (
	"strings"

	"github.com/eitanity/kanonarion/internal/coordinate"
)

// Rooting names the analysis frame a vulnerability record was produced in.
//
// It is a DIMENSION, not a ladder. An isolated scan and a target-rooted scan of
// the same module against the same advisory snapshot are both correct and
// neither supersedes the other, because they answer different questions:
// "does this module, examined as its own main module, carry a reachable
// advisory" and "is that advisory reachable in the build we actually ship".
// A reachability finding is therefore never carried across a rooting boundary.
//
// Until this field existed the frame was discarded by the record's identity:
// the key was (coordinate, pipeline, snapshot), so a target-rooted scan and an
// isolated scan of one coordinate overwrote each other, and the surviving row
// was whichever ran last. Both kinds are written in production — a walk rooted
// at a project or a target module produces the first, and its per-module worker
// pool produces the second whenever the target cannot be analysed as a whole —
// so the loss was silent and routine.
type Rooting string

const (
	// RootingUnrecorded is the zero value: the record states no frame.
	//
	// It means "not recorded", never "rooted at nothing". Every record written
	// before this field existed carries it, and so do the records that describe
	// a module no analysis was ever rooted at — a local-replace node the scan
	// pool never opened. Composition treats it as absence: a frame-scoped read
	// prefers the records that state a frame, and falls back to the unrecorded
	// ones only when no record in the group states one at all, so a store that
	// has not been re-scanned since this field landed still answers.
	RootingUnrecorded Rooting = ""

	// RootingIsolated is a scan of one module as its own main module, resolved
	// and built alone. It is what the walk's per-module worker pool produces —
	// including as the fallback when a target cannot be analysed as a whole.
	RootingIsolated Rooting = "isolated"

	// RootingTargetRooted is a per-module record derived from a single scan
	// rooted at a walk's target — a local project's working tree, or a target
	// module's own build — WITHOUT recording which target that was.
	//
	// It is not what a producer writes. TargetRootedAt is, and it names the root.
	// This bare value exists because the frame was briefly recorded without one,
	// and a row that says "target-rooted, root unstated" must keep saying that
	// rather than be read as any particular root.
	RootingTargetRooted Rooting = "target-rooted"
)

// rootingTargetPrefix marks a frame rooted at a named target. What follows is
// the target's coordinate.
const rootingTargetPrefix = "target-rooted:"

// TargetRootedAt returns the frame of a record derived from an analysis rooted
// at target.
//
// The target is part of the frame, not a note beside it, because two
// target-rooted analyses of one dependency are two different questions whenever
// they are rooted at different targets: "is this advisory reachable in zenbpm"
// and "is it reachable in x/text's own build" have different answers, and the
// second is not an update of the first.
//
// That was measured rather than reasoned. With the root left out, a
// coordinate-rooted walk of golang.org/x/text@v0.37.0 landed in the same frame
// as a project walk of a consumer that reached it, and — running later and
// computing no reachability — displaced the consumer's "reachable" finding with
// one that had never asked the question. That is the failure the dimension rule
// names, reappearing inside the dimension.
func TargetRootedAt(target coordinate.ModuleCoordinate) Rooting {
	return Rooting(rootingTargetPrefix + target.String())
}

// IsRecorded reports whether the record states an analysis frame.
func (r Rooting) IsRecorded() bool { return r != RootingUnrecorded }

// IsTargetRooted reports whether the frame is an analysis rooted at a target,
// whether or not that target is named.
func (r Rooting) IsTargetRooted() bool {
	return r == RootingTargetRooted || strings.HasPrefix(string(r), rootingTargetPrefix)
}

// RootTarget returns the coordinate the analysis was rooted at, as recorded, or
// the empty string when the frame names none — an isolated scan, an unrecorded
// frame, or a target-rooted record from before the root was carried.
func (r Rooting) RootTarget() string {
	target, ok := strings.CutPrefix(string(r), rootingTargetPrefix)
	if !ok {
		return ""
	}
	return target
}

// String renders the frame for display, naming the unrecorded case rather than
// printing an empty column: a blank reads as a missing value, and "not
// recorded" is the fact.
func (r Rooting) String() string {
	if r == RootingUnrecorded {
		return "not recorded"
	}
	return string(r)
}

// RecordRooting projects a record onto the analysis frame it was reached in. It
// is a free function rather than a method because VulnerabilityRecord is
// aliased into pkg/kanonarion as a read-shaped result type, which may carry no
// behaviour.
func RecordRooting(r VulnerabilityRecord) Rooting { return r.Rooting }
