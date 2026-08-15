package cli

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/clock"
	proxyadapter "github.com/eitanity/kanonarion/internal/adapters/proxy/direct"
	staleproxy "github.com/eitanity/kanonarion/internal/staleness/adapters/proxy"
	stalesqlite "github.com/eitanity/kanonarion/internal/staleness/adapters/store/sqlite"
	staleapp "github.com/eitanity/kanonarion/internal/staleness/application"
	staledomain "github.com/eitanity/kanonarion/internal/staleness/domain"
	staleports "github.com/eitanity/kanonarion/internal/staleness/ports"
)

// newStalenessResolver wires the staleness resolver over an already-open ledger.
// ledger may be nil, which makes every lookup live and unwritten.
//
// latest is the port rather than the proxy adapter so the two wirings below can
// be tested for the one thing that distinguishes them: whether the ledger is
// read at all.
func newStalenessResolver(latest staleports.LatestResolver, ledger staleports.Ledger, ttl time.Duration, fresh bool) *staleapp.Resolver {
	return staleapp.NewResolver(latest, ledger, clock.System{}, ttl, fresh)
}

// newProxyLatestResolver wraps the module proxy as the port the staleness
// resolver asks for a module's latest version.
func newProxyLatestResolver(proxy *proxyadapter.Proxy) staleports.LatestResolver {
	return staleproxy.New(proxy)
}

// newAuditStalenessResolver builds the resolver behind an audit's latest column.
//
// It takes no fresh parameter. On audit the staleness TTL is what governs that
// column: the subject of `audit --fresh` is the advisory database, and the
// command whose subject IS the latest answer — `latest` — keeps its own --fresh
// for it. Leaving the parameter off is the point; a wiring that could pass it
// is a wiring that will.
func newAuditStalenessResolver(latest staleports.LatestResolver, ledger staleports.Ledger, ttl time.Duration) *staleapp.Resolver {
	return newStalenessResolver(latest, ledger, ttl, false)
}

// The vocabulary for a staleness answer that was NOT measured. It is shared by
// every command that reports staleness — `audit`, `latest` and `fetch` — because
// a reader parsing one of them must not have to learn a second set of words for
// the same absence, and because a per-command vocabulary is how one surface ends
// up rendering an unmeasured row as an affirmative answer while its neighbour
// states the truth.
const (
	// stalenessOfflineNoEntry: a fully offline run (--from-modcache) whose
	// ledger holds no lookup for this module inside the staleness TTL. Nothing
	// was asked and nothing recorded could be served.
	stalenessOfflineNoEntry = "offline_no_ledger_entry"
	// stalenessLookupFailed: the lookup was attempted and failed (proxy error,
	// probe failure with nothing cached behind it).
	stalenessLookupFailed = "lookup_failed"
	// stalenessToolchainPinned: the standard library, whose version is the build
	// toolchain's. There is no proxy "latest" for it, so the question does not
	// apply rather than resolving in the pin's favour.
	stalenessToolchainPinned = "toolchain_pinned"
	// stalenessNotAsked: the question was never put. A `fetch <module>@latest`
	// resolves the newest version and installs it, so there is no pin to compare
	// against; `latest <module>` with no pin is the same shape. "Current" is not
	// the answer to a question nobody asked — it is the absence of one.
	stalenessNotAsked = "not_asked"
)

// stalenessUnmeasuredLabel renders the machine reason as the phrase the tables,
// the coverage line and the fetch note show. An unrecognised reason is passed
// through rather than dropped: a reason nobody has taught this function is still
// more informative than none, and an unstated one still says "unmeasured".
func stalenessUnmeasuredLabel(reason string) string {
	switch reason {
	case "":
		return "unmeasured"
	case stalenessOfflineNoEntry:
		return "unmeasured (offline)"
	case stalenessLookupFailed:
		return "unmeasured (lookup failed)"
	case stalenessToolchainPinned:
		return "unmeasured (toolchain-pinned)"
	case stalenessNotAsked:
		return "unmeasured (not asked)"
	}
	return "unmeasured (" + reason + ")"
}

// stalenessLookup is what an audit row's staleness column is answered by. Two
// implementations satisfy it: the resolver that may ask the proxy, and the
// offline lookup below that may not. Naming the capability as an interface is
// what lets the offline mode be a different ANSWER rather than a skipped column
// silently rendered as the affirmative one.
type stalenessLookup interface {
	Resolve(ctx context.Context, path, pinnedVersion string) (staleapp.Answer, error)
}

// errStalenessOffline reports that an offline run had no recorded lookup it
// could serve for a module. It is not a failure — nothing went wrong and nothing
// is retryable offline — so callers render it as an unmeasured column rather
// than an error line per module.
var errStalenessOffline = errors.New("offline: no staleness lookup inside the TTL")

// offlineStalenessLookup answers the staleness column on a fully offline run
// (--from-modcache) from the ledger alone.
//
// A recorded lookup inside the TTL is a measurement and is served — with the
// answer's own date, so the caller can state its age. Anything else is
// errStalenessOffline. It NEVER writes: an offline run learns no new upstream
// fact, and it never probes, because a probe is a network call and the mode's
// contract is that there are none.
type offlineStalenessLookup struct {
	ledger staleports.Ledger
	clk    staleports.Clock
	ttl    time.Duration
}

func newOfflineStalenessLookup(ledger staleports.Ledger, ttl time.Duration) *offlineStalenessLookup {
	return &offlineStalenessLookup{ledger: ledger, clk: clock.System{}, ttl: ttl}
}

// Resolve serves path's ledger row when it is inside the TTL.
func (o *offlineStalenessLookup) Resolve(ctx context.Context, path, pinnedVersion string) (staleapp.Answer, error) {
	if o.ledger == nil {
		return staleapp.Answer{}, errStalenessOffline
	}
	rec, found, err := o.ledger.GetStaleness(ctx, path)
	if err != nil {
		return staleapp.Answer{}, fmt.Errorf("reading staleness ledger for %s: %w", path, err)
	}
	if !found || !rec.FreshAt(o.clk.Now(), o.ttl) {
		return staleapp.Answer{}, errStalenessOffline
	}

	out := staledomain.Record{
		ModulePath:        path,
		LatestVersion:     rec.LatestVersion,
		LatestPublishedAt: rec.LatestPublishedAt,
		LookedUpAt:        rec.LookedUpAt,
	}
	// The stored probe is reusable only when it started at the same major AND, for
	// a pin that asks the republication question, only when the stored row asked
	// it too — the same pair of rules the online resolver applies (see
	// domain.NewerMajor.FromMajor and domain.Republication.Asked). Otherwise it
	// stays unprobed here: MajorProbed false says "not asked", which is what an
	// offline run that cannot probe has to say. A row written before the
	// republication was a separate fact carries the module's own major under
	// newer_major_path, and serving it offline would keep printing the label this
	// change exists to remove.
	pin := pinnedVersion
	if pin == "" {
		pin = out.LatestVersion
	}
	plan := staledomain.PlanProbe(path, pin)
	if rec.NewerMajor.Probed && rec.NewerMajor.FromMajor == plan.Start() {
		if _, asks := plan.SameMajor(); !asks || rec.Republication.Asked {
			out.NewerMajor = rec.NewerMajor
			out.Republication = rec.Republication
		}
	}
	return staleapp.Answer{Record: out, Served: true}, nil
}

// openStalenessLedger opens the store purely for the staleness ledger.
//
// `latest` needs the ledger and nothing else, and building the whole container
// for it would drag in every adapter the command never touches. It goes through
// the same migrated-and-gated door as every other write path, so an older binary
// still refuses a newer store here.
func openStalenessLedger(storeRoot string) (staleports.Ledger, func() error, error) {
	dbHandle, err := openMigratedStore(filepath.Join(storeRoot, "mirror.db"))
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() error {
		if cerr := dbHandle.Close(); cerr != nil {
			return fmt.Errorf("closing database: %w", cerr)
		}
		return nil
	}
	return stalesqlite.New(dbHandle), cleanup, nil
}

// stalenessAsOf renders the lookup time a staleness answer came from.
//
// Every consumer prints it. A cached answer that does not say when it was
// measured is indistinguishable from a live one, and the whole point of dating
// the row is that the reader can tell.
func stalenessAsOf(lookedUpAt time.Time) string {
	if lookedUpAt.IsZero() {
		return ""
	}
	return lookedUpAt.UTC().Format("2006-01-02 15:04 MST")
}

// The labels the two major-line facts render under.
//
// They are constants shared by every command that prints them because the
// distinction between them is the whole point: a build where `latest` says
// "same major republished" and `audit` says "newer major" about the same module
// has contradicted itself, and two copies of a label string is how that starts.
const (
	newerMajorLabel = "newer major"
	// republicationLabel deliberately does not contain the word "major" on its
	// own. The major NUMBER is unchanged here; only the path moved.
	republicationLabel = "same major republished"
)

// majorClause renders one labelled path@version, with the publication date when
// there is one. A zero date prints no date rather than a fabricated one.
func majorClause(label, path, version string, publishedAt time.Time) string {
	if path == "" {
		return ""
	}
	if publishedAt.IsZero() {
		return fmt.Sprintf("%s: %s@%s", label, path, version)
	}
	return fmt.Sprintf("%s: %s@%s (%s)", label, path, version, publishedAt.UTC().Format("2006-01-02"))
}

// majorNotes renders the major-line facts as their own clauses.
//
// Neither is ever folded into the same-major status: "current" and "a newer
// major line exists" are both true at once for a module pinned behind a major
// bump, and merging them reports the module the way this context exists to stop
// reporting it.
//
// The republication comes FIRST when both hold. It is the nearer move — the
// same major number at the path the toolchain expects for it — and for a stuck
// +incompatible pin it is the likelier action; ordering the two-major migration
// ahead of it buries the cheaper answer behind the more alarming one.
func majorNotes(rep staledomain.Republication, nm staledomain.NewerMajor) string {
	var parts []string
	if rep.Exists() {
		parts = append(parts, majorClause(republicationLabel, rep.Path, rep.Version, rep.PublishedAt))
	}
	if nm.Exists() {
		parts = append(parts, majorClause(newerMajorLabel, nm.Path, nm.Version, nm.PublishedAt))
	}
	return strings.Join(parts, "; ")
}
