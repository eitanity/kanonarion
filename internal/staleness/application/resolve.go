// Package application resolves a module's staleness through the ledger.
package application

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/eitanity/kanonarion/internal/staleness/domain"
	"github.com/eitanity/kanonarion/internal/staleness/ports"
)

// maxProbeDepth bounds the major-suffix walk. The probe already stops at the
// first absent major, which ends it after one request for almost every module;
// the cap exists only so a pathological family (or a proxy that answers every
// path) cannot turn one module into an unbounded request loop.
const maxProbeDepth = 32

// Answer is a resolved staleness record together with how it was obtained.
type Answer struct {
	domain.Record
	// Served is true when the whole answer came from the ledger without asking
	// the proxy. A partially-served answer (cached latest, live probe) reports
	// false: the record's LookedUpAt is restamped, so it is a live answer.
	Served bool
}

// Resolver answers "how far behind is this module" from the ledger when a row
// is younger than the TTL, and from the proxy otherwise.
//
// Both halves of the answer — the same-major latest and the newer-major probe —
// go in one row. They are resolved together, they expire together, and keying
// them apart would double both the read and the write for a fact that is always
// wanted as a pair. What keeps them distinct is that they are separate fields
// with their own provenance (NewerMajor.Probed), not separate rows.
type Resolver struct {
	proxy  ports.LatestResolver
	ledger ports.Ledger
	clk    ports.Clock
	ttl    time.Duration
	fresh  bool
}

// NewResolver builds a Resolver. ledger may be nil, in which case every lookup
// is live and nothing is written — that is the shape a command with no store
// gets, not a silent degradation of the answer. fresh suppresses ledger READS
// only: a --fresh run still writes what it resolved, because a freshly measured
// fact is exactly what the next run should be served.
func NewResolver(proxy ports.LatestResolver, ledger ports.Ledger, clk ports.Clock, ttl time.Duration, fresh bool) *Resolver {
	return &Resolver{proxy: proxy, ledger: ledger, clk: clk, ttl: ttl, fresh: fresh}
}

// Resolve returns the staleness record for path, pinned at pinnedVersion.
//
// pinnedVersion may be empty (no pin, as in `latest <module>`); the resolved
// latest is then used to place the probe's starting major, so a bare path whose
// newest release is a +incompatible v2 is planned the same way an explicit
// +incompatible pin is: /v2 asked about first, then the walk from /v3.
func (r *Resolver) Resolve(ctx context.Context, path, pinnedVersion string) (Answer, error) {
	now := r.clk.Now()

	var stored domain.Record
	var haveFresh bool
	if r.ledger != nil && !r.fresh {
		rec, found, err := r.ledger.GetStaleness(ctx, path)
		if err != nil {
			return Answer{}, fmt.Errorf("reading staleness ledger for %s: %w", path, err)
		}
		if found && rec.FreshAt(now, r.ttl) {
			stored, haveFresh = rec, true
		}
	}

	out := domain.Record{ModulePath: path}
	if haveFresh {
		out.LatestVersion = stored.LatestVersion
		out.LatestPublishedAt = stored.LatestPublishedAt
		out.LookedUpAt = stored.LookedUpAt
	} else {
		info, err := r.proxy.LatestInfo(ctx, path)
		if err != nil {
			// Nothing is written: a failed lookup is not a cacheable fact, so a
			// transient proxy failure must not become an answer the next hour of
			// runs is served.
			return Answer{}, fmt.Errorf("resolving %s@latest: %w", path, err)
		}
		out.LatestVersion = info.Version
		out.LatestPublishedAt = info.Time
		out.LookedUpAt = now
	}

	pin := pinnedVersion
	if pin == "" {
		pin = out.LatestVersion
	}
	plan := domain.PlanProbe(path, pin)

	// The cached probe is reusable only when it started at the same major; see
	// NewerMajor.FromMajor. A plan that asks the same-major question additionally
	// needs a row that ASKED it: a row written before that question existed
	// carries Asked false, which says "not asked", and serving it would answer a
	// question the caller put with a row that never put it.
	if haveFresh && stored.NewerMajor.Probed && stored.NewerMajor.FromMajor == plan.Start() {
		if _, asks := plan.SameMajor(); !asks || stored.Republication.Asked {
			out.NewerMajor = stored.NewerMajor
			out.Republication = stored.Republication
			return Answer{Record: out, Served: true}, nil
		}
	}

	nm, rep, probeErr := r.probe(ctx, path, plan)
	out.NewerMajor = nm
	out.Republication = rep

	// LookedUpAt is deliberately NOT restamped when only the probe ran live: the
	// answer as a whole is no fresher than its oldest half, and a cached latest
	// re-dated to now is the "served answer mistaken for a live one" this ledger
	// exists to prevent. It also keeps the row expiring when its latest does,
	// so the pair stays reusable for the rest of the TTL rather than re-probing
	// on every command until the latest ages out.

	// Nothing is written when the probe failed on top of a cached latest: no new
	// fact was learned, and overwriting a stored probe with an unprobed one
	// would turn a measured answer back into an unasked question.
	if probeErr == nil || !haveFresh {
		if err := r.write(ctx, out); err != nil {
			return Answer{}, err
		}
	}
	return Answer{Record: out}, probeErr
}

// probe answers the plan: the same-major question first, when there is one,
// then the upward walk, stopping at the first absent major. An absent major in
// the walk is a definitive answer and yields a recorded negative; any other
// error leaves the probe unrecorded (Probed false), which reads as "not asked"
// rather than "none exists".
//
// The same-major question is not a step of the walk and its absence never ends
// one — see domain.ProbePlan. It costs one extra request, and only for a
// +incompatible pin: every other module's probe is unchanged.
//
// The two answers are returned SEPARATELY and neither overwrites the other. The
// same-major answer used to be seeded into the walk's variable, so a pin whose
// own major was republished and which also had a genuine next major kept only
// the last path that resolved — the higher one — and the nearer, cheaper move
// never reached the output. It also meant a pin with no next major reported its
// own republished major under the newer-major label, claiming a major number
// change that had not happened.
//
// That separation holds on the FAILURE path too, which it did not: a walk that
// failed used to zero the republication answer beside it, discarding a
// completely measured fact about one path because a request about a different
// one did not come back. The republication question is answered before the walk
// starts and does not depend on it, so it is kept and returned with the error.
func (r *Resolver) probe(ctx context.Context, path string, plan domain.ProbePlan) (domain.NewerMajor, domain.Republication, error) {
	fam := domain.ParseFamily(path)
	start := plan.Start()
	nm := domain.NewerMajor{Probed: true, FromMajor: start}
	var rep domain.Republication

	if m, ok := plan.SameMajor(); ok {
		rep.Asked = true
		candidate := fam.PathForMajor(m)
		info, err := r.proxy.LatestInfo(ctx, candidate)
		switch {
		case errors.Is(err, ports.ErrPathAbsent):
			// The ordinary case for a module that never adopted /vN. It says
			// nothing about the majors above, so the walk still runs.
		case err != nil:
			return domain.NewerMajor{}, domain.Republication{}, fmt.Errorf("probing %s for a republished major: %w", path, err)
		default:
			rep.Path = candidate
			rep.Version = info.Version
			rep.PublishedAt = info.Time
		}
	}

	for n := start; n < start+maxProbeDepth; n++ {
		candidate := fam.PathForMajor(n)
		info, err := r.proxy.LatestInfo(ctx, candidate)
		if errors.Is(err, ports.ErrPathAbsent) {
			return nm, rep, nil
		}
		if err != nil {
			// The walk's OWN answer cannot survive this: Probed means "ran to
			// completion", and a truncated walk carrying the highest major it
			// happened to reach would report a possibly-understated answer as a
			// complete one — and cache it for the TTL. What it must not do is
			// lose that half in silence, so a major already resolved is named in
			// the failure the caller reports.
			if nm.Path != "" {
				return domain.NewerMajor{}, rep, fmt.Errorf(
					"probing %s for a newer major: %s resolved before the walk failed: %w", path, nm.Path, err)
			}
			return domain.NewerMajor{}, rep, fmt.Errorf("probing %s for a newer major: %w", path, err)
		}
		nm.Path = candidate
		nm.Version = info.Version
		nm.PublishedAt = info.Time
	}
	return nm, rep, nil
}

func (r *Resolver) write(ctx context.Context, rec domain.Record) error {
	if r.ledger == nil {
		return nil
	}
	if err := r.ledger.PutStaleness(ctx, rec); err != nil {
		return fmt.Errorf("writing staleness ledger for %s: %w", rec.ModulePath, err)
	}
	return nil
}
