package composition

import (
	"fmt"
	"io"
	"log/slog"
	"time"

	"code.eitanity.com/kanonarion/internal/adapters/clock"
	proxyadapter "code.eitanity.com/kanonarion/internal/adapters/proxy/direct"
	configdomain "code.eitanity.com/kanonarion/internal/config/domain"
	"code.eitanity.com/kanonarion/internal/driver"
	fetchports "code.eitanity.com/kanonarion/internal/fetch/ports"
	stalegolist "code.eitanity.com/kanonarion/internal/staleness/adapters/golist"
	staleproxy "code.eitanity.com/kanonarion/internal/staleness/adapters/proxy"
	staleretry "code.eitanity.com/kanonarion/internal/staleness/adapters/proxy/retrying"
	staleapp "code.eitanity.com/kanonarion/internal/staleness/application"
	staleports "code.eitanity.com/kanonarion/internal/staleness/ports"
)

// StalenessResolverConfig is what a caller may supply to a staleness resolver. A zero
// field takes what `latest` uses.
type StalenessResolverConfig struct {
	// Upstream answers @latest per path. Nil asks the module proxy $GOPROXY
	// names, behind latest's re-ask schedule.
	Upstream staleports.LatestResolver
	// Clock stamps lookups and measures the TTL. Nil is the system clock.
	Clock fetchports.Clock
	// TTL is how long a ledger row is served. Zero is the store's
	// staleness.ttl, or the built-in default for a supplied ledger.
	TTL time.Duration
}

// NewStalenessResolver builds the per-module staleness resolver over ledger
// (nil: every lookup live and unwritten). A GONOPROXY/GOPRIVATE path is never
// asked of the upstream, as in `latest`.
func NewStalenessResolver(ledger staleports.Ledger, cfg StalenessResolverConfig) (*driver.StalenessResolver, error) {
	upstream := cfg.Upstream
	if upstream == nil {
		proxy, err := proxyadapter.New("", false)
		if err != nil {
			return nil, fmt.Errorf("building the staleness resolver's module proxy: %w", err)
		}
		upstream = staleretry.New(staleproxy.New(proxy), slog.New(slog.NewTextHandler(io.Discard, nil)))
	}
	var clk staleports.Clock = clock.System{}
	if cfg.Clock != nil {
		clk = cfg.Clock
	}
	ttl := cfg.TTL
	if ttl == 0 {
		ttl = configdomain.DefaultStalenessTTL
	}
	return driver.NewStalenessResolver(StalenessResolverOver(upstream, ledger, clk, ttl, false)), nil
}

// StalenessResolverOver is the per-path resolver every staleness answer comes
// from, the CLI's included: the private-path rule is wired here so no caller
// can build one without it.
func StalenessResolverOver(upstream staleports.LatestResolver, ledger staleports.Ledger, clk staleports.Clock, ttl time.Duration, fresh bool) *staleapp.Resolver {
	return staleapp.NewResolver(upstream, ledger, clk, ttl, fresh).
		WithPrivate(privateModulePath, stalegolist.NewPrivate("", ""))
}
