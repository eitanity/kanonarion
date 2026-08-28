// Package ports declares the staleness context's driven interfaces.
package ports

import (
	"context"
	"errors"
	"time"

	"github.com/eitanity/kanonarion/internal/staleness/domain"
)

// ErrPathAbsent reports that the proxy has no such module path at all.
//
// It is a definitive answer, not a failure, and the distinction is the whole
// bound on the major probe: an absent /vN is what tells the probe to stop, and
// it is a cacheable negative. A timeout or a 5xx is neither — those are
// failures, and a failure is never written to the ledger.
var ErrPathAbsent = errors.New("module path not published")

// ErrLookupFailed reports that the proxy could not be asked, or answered in a
// way that settles nothing: a timeout, a 5xx, a 429, an empty body.
//
// It is the OTHER half of the same distinction ErrPathAbsent draws, and it is a
// named error rather than "any error that is not ErrPathAbsent" so that the
// message an operator sees says the lookup failed. A probe of a /vN path that
// does not exist is the ordinary case for most modules and must never surface
// as a failure; a probe that could not be made is the one an operator can act
// on, and the two used to be told apart only by which error text happened to
// come back from the transport or the decoder.
var ErrLookupFailed = errors.New("module proxy lookup failed")

// LatestInfo is the proxy's @latest answer for one path.
type LatestInfo struct {
	Version string
	// Time is the publication time, zero when the proxy supplied none.
	Time time.Time
}

// LatestResolver resolves @latest for a module path. Implementations MUST
// report an unknown path as ErrPathAbsent (wrapped is fine) so the probe can
// tell absence from failure.
//
// Implementations MUST also be safe for concurrent use. The newer-major probe
// asks about one path per module in the dependency closure — almost all of them
// 404s — and it asks in bounded parallel rounds, so a resolver that keeps
// mutable state across calls will be exercised from several goroutines at once.
// Both shipped implementations are immutable after construction: the proxy
// bridge holds an *http.Client, and the retry decorator holds its schedule.
type LatestResolver interface {
	LatestInfo(ctx context.Context, path string) (LatestInfo, error)
}

// BatchLatest is one module's answer from a batched resolution: the same
// same-major latest a LatestResolver returns, plus the module's own deprecation
// notice, which the batch source reports at no extra cost and a per-path
// @latest lookup cannot see at all.
type BatchLatest struct {
	LatestInfo
	// Deprecated is the module's deprecation notice, verbatim, or empty when the
	// module declares none. Presence in the map is what says the question was
	// ANSWERED; empty here means "answered, not deprecated".
	Deprecated string

	// Updated reports whether the batch found a NEWER version than the one the
	// build list selected. It is not derivable from Version, which holds the
	// selected version when there is no update.
	//
	// It matters because the batched source answers within the pin's own major
	// and reports nothing when there is no higher version there — so "no update"
	// covers both "you are on the newest release" and "you are sitting ABOVE the
	// last tag on a pseudo-version". Only the second needs the module's @latest
	// tag looked up to place the pin, and without this field every row would
	// have to be looked up to find the few that do.
	Updated bool
}

// PinnedModule is one module in a caller's scope: the path to answer for, and
// the version the build list resolved for it.
//
// The VERSION is carried because the newer-major probe cannot be planned
// without it — a +incompatible pin carries its major in the version while
// living at the unsuffixed path, so the major the walk starts at is not
// derivable from the path alone. A batched resolution that only knew paths
// could resolve the latest and would still leave the probe with nothing to plan
// from until each module came round one at a time.
type PinnedModule struct {
	Path    string
	Version string
}

// BatchLatestResolver answers the same-major latest question for a whole set of
// module paths in ONE call.
//
// It is a different SHAPE from LatestResolver, not a faster implementation of
// it, and that is why it is a separate port. The latest-version fact for a set
// of modules is a batched question the go command answers in seconds; a
// LatestResolver can only be asked one path at a time, which is what made the
// same sweep take tens of minutes and lose answers to the request rate it
// provoked. Forcing a batch behind the per-path signature would have hidden the
// one property that matters — that the whole set is resolved together.
//
// The newer-major probe stays on LatestResolver: it asks about paths that are
// NOT in the build list, so no batched answer about the build list can contain
// them.
type BatchLatestResolver interface {
	// LatestBatch answers for the given module paths.
	//
	// The map holds ONLY the paths that were answered. A path absent from it was
	// NOT answered and must never be read as "this module is current" — an
	// implementation that cannot check for updates is required to return an
	// error rather than a map of every path with no update, because the two are
	// byte-identical in the underlying tool's output and only one of them is an
	// answer.
	LatestBatch(ctx context.Context, paths []string) (map[string]BatchLatest, error)
}

// Ledger persists resolved staleness rows, keyed on module path.
type Ledger interface {
	// GetStaleness returns the stored row for path. found is false, with no
	// error, when there is none.
	GetStaleness(ctx context.Context, path string) (domain.Record, bool, error)
	// PutStaleness inserts or replaces the row for rec.ModulePath.
	PutStaleness(ctx context.Context, rec domain.Record) error
}

// Clock supplies the wall-clock instant a lookup is stamped with and the TTL is
// measured against.
type Clock interface {
	Now() time.Time
}

// ProgressReporter receives staleness lookup progress so a long, otherwise
// silent probe can show proof of life. A probe that has to wait out a transient
// proxy failure spends most of a minute on one module, and a command documented
// as taking about a second cannot leave that unsaid: a user has no way to tell a
// slow probe from a hang.
//
// It deliberately does NOT report a running count the way the walk and extract
// reporters do. A retry is not "N of M done" — the reader's question is which
// module is being waited on, how many chances it has had and how many it gets —
// so the method carries those three and no denominator over the module set,
// which the resolver does not know here anyway.
//
// Implementations decide whether and how to surface the signal (e.g. a line on
// stderr); a nil reporter disables reporting entirely, which is what every
// caller that narrates nothing passes.
//
// RetryingLookup may be called concurrently: the newer-major probe asks in
// bounded parallel rounds, so implementations must be safe for that.
type ProgressReporter interface {
	// RetryingLookup reports that path's latest lookup failed transiently and
	// will be tried again. attempt is the attempt about to be made, counting the
	// first one, and maxAttempts is the budget it is bounded by — so the last
	// line a give-up emits reads as the last attempt of the budget rather than
	// stopping mid-count.
	RetryingLookup(path string, attempt, maxAttempts int)
}
