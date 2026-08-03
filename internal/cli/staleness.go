package cli

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
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
	// The stored probe is reusable only when it started at the same major, by the
	// same rule the online resolver applies (see domain.NewerMajor.FromMajor).
	// Otherwise it stays unprobed here: MajorProbed false says "not asked", which
	// is what an offline run that cannot probe has to say.
	pin := pinnedVersion
	if pin == "" {
		pin = out.LatestVersion
	}
	if rec.NewerMajor.Probed && rec.NewerMajor.FromMajor == staledomain.ProbeStartMajor(path, pin) {
		out.NewerMajor = rec.NewerMajor
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

// newerMajorNote renders the newer-major fact as its own clause.
//
// It is never folded into the same-major status. "current" and "a newer major
// line exists" are both true at once for a module pinned behind a major bump,
// and a rendering that merged them would report the module the way this whole
// change exists to stop reporting it.
func newerMajorNote(nm staledomain.NewerMajor) string {
	if !nm.Exists() {
		return ""
	}
	if nm.PublishedAt.IsZero() {
		return fmt.Sprintf("newer major: %s@%s", nm.Path, nm.Version)
	}
	return fmt.Sprintf("newer major: %s@%s (%s)", nm.Path, nm.Version, nm.PublishedAt.UTC().Format("2006-01-02"))
}
