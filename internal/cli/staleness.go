package cli

import (
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
func newStalenessResolver(proxy *proxyadapter.Proxy, ledger staleports.Ledger, ttl time.Duration, fresh bool) *staleapp.Resolver {
	return staleapp.NewResolver(staleproxy.New(proxy), ledger, clock.System{}, ttl, fresh)
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
