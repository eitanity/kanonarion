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

	// batch is the batched source for the same-major latest, when one is wired.
	// The newer-major probe never uses it: the probe asks about paths that are
	// not in the build list, so no batched answer about the build list can hold
	// them.
	batch ports.BatchLatestResolver
	// batchCoords is the caller's scope: the paths the batch is asked about, with
	// the versions the newer-major probe needs to plan its walk.
	batchCoords []ports.PinnedModule
	// concurrency bounds the prefetched probe. See prefetch.go.
	concurrency int
	// prefetched holds probe and tag answers obtained in rounds, concurrently,
	// before the per-module loop runs. A path ABSENT from it was not prefetched
	// and is asked live; absence is never an absent path.
	prefetched map[string]probeResult
	// batched is the primed answer, and batchPrimed says the call has been made.
	// A path ABSENT from batched was not answered and falls through to the
	// per-path resolver; it is never read as "current".
	batched     map[string]ports.BatchLatest
	batchPrimed bool
	// batchErr is the refusal or failure the priming call returned, kept so
	// every subsequent module gets the same answer instead of re-running a call
	// that has already failed once for the whole set.
	batchErr error
}

// ErrBatchUnavailable wraps a batched resolution that could not be made.
//
// It is a named error because the caller has to be able to stop the run on it.
// The batch answers for the WHOLE set in one call, so its failure is not one
// module's bad luck — it is the same answer for every module, and reporting it
// per row would print the identical failure once per dependency while quietly
// falling back to the per-path sweep this exists to remove.
var ErrBatchUnavailable = errors.New("batched latest resolution unavailable")

// NewResolver builds a Resolver. ledger may be nil, in which case every lookup
// is live and nothing is written — that is the shape a command with no store
// gets, not a silent degradation of the answer. fresh suppresses ledger READS
// only: a --fresh run still writes what it resolved, because a freshly measured
// fact is exactly what the next run should be served.
func NewResolver(proxy ports.LatestResolver, ledger ports.Ledger, clk ports.Clock, ttl time.Duration, fresh bool) *Resolver {
	return &Resolver{proxy: proxy, ledger: ledger, clk: clk, ttl: ttl, fresh: fresh}
}

// WithBatch configures r to obtain the same-major latest for paths from batch —
// one call for the whole set — instead of asking the per-path resolver once per
// module.
//
// The call is made LAZILY, on the first module that actually needs a live
// latest. A run whose rows are all inside the TTL is answered from the ledger
// and never shells out at all, which is what the ledger is for; priming eagerly
// would have put a fixed cost on the runs that had already paid it.
//
// The per-path resolver is still required and is still used: it answers the
// newer-major probe for every module, and it answers the latest for any path the
// batch did not report.
func (r *Resolver) WithBatch(batch ports.BatchLatestResolver, coords []ports.PinnedModule, concurrency int) *Resolver {
	r.batch = batch
	r.batchCoords = coords
	r.concurrency = concurrency
	return r
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
		out.Deprecation = stored.Deprecation
		out.LookedUpAt = stored.LookedUpAt
	} else {
		info, dep, err := r.latestFor(ctx, path)
		if err != nil {
			// Nothing is written: a failed lookup is not a cacheable fact, so a
			// transient proxy failure must not become an answer the next hour of
			// runs is served.
			return Answer{}, err
		}
		out.LatestVersion = info.Version
		out.LatestPublishedAt = info.Time
		out.Deprecation = dep
		out.LookedUpAt = now
		r.applyTagPosition(ctx, &out, pinnedVersion)
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

// applyTagPosition restores the pin-ahead answer the batched source cannot give.
//
// `go list -m -u` resolves within the pin's own major and reports nothing when
// there is no higher version there. A pin sitting ABOVE the last release tag —
// a pseudo-version taken after it, a prerelease, a pre-modules +incompatible
// major — therefore comes back with no update, and reading that as "you are on
// the newest version" is the answer the pin-ahead state exists to withhold: the
// row would say `current` about a version that is not published as a release at
// all.
//
// So the module's own @latest is looked up — from the prefetch, alongside the
// probe, never as a serial per-module request — and the tag is adopted ONLY
// when it places the pin ahead. That direction is deliberate. The go command's
// answer about what the build contains is correct by definition and is never
// overwritten; the only thing added is the third position it does not express.
// github.com/coreos/etcd@v3.3.10+incompatible has a real update to
// v3.3.27+incompatible and keeps it, while github.com/hashicorp/hcl@v1.0.1-vault-7
// has none and is placed above v1.0.0.
func (r *Resolver) applyTagPosition(ctx context.Context, out *domain.Record, pinnedVersion string) {
	if pinnedVersion == "" || r.batch == nil {
		return
	}
	b, answered := r.batched[out.ModulePath]
	if !answered || b.Updated || !domain.CanSortAboveTag(pinnedVersion) {
		return
	}
	tag, err := r.probeInfo(ctx, out.ModulePath)
	if err != nil || tag.Version == "" {
		// Not established. The batch's answer stands, unchanged: a lookup that
		// failed adds nothing, and it must not subtract the answer beside it.
		return
	}
	if domain.ComparePin(pinnedVersion, tag.Version) != domain.PinAhead {
		return
	}
	out.LatestVersion = tag.Version
	out.LatestPublishedAt = tag.Time
}

// latestFor answers the same-major latest for one path, from the batch when one
// is wired and from the per-path resolver otherwise.
//
// A path the batch did not report falls THROUGH to the per-path resolver rather
// than being answered from the batch's silence. That is the same distinction
// this context draws everywhere: the batch's map holds what it answered, and a
// path missing from it is an unasked question, not a module with no update.
//
// The deprecation notice rides on the batch answer only. A per-path @latest
// lookup returns a version and a date and cannot see the notice, so a row
// resolved that way reports the deprecation question as unchecked instead of
// reporting a negative it never established.
func (r *Resolver) latestFor(ctx context.Context, path string) (ports.LatestInfo, domain.Deprecation, error) {
	if r.batch != nil {
		if err := r.primeBatch(ctx); err != nil {
			return ports.LatestInfo{}, domain.Deprecation{}, err
		}
		if b, ok := r.batched[path]; ok {
			return b.LatestInfo, domain.Deprecation{Checked: true, Notice: b.Deprecated}, nil
		}
	}
	info, err := r.proxy.LatestInfo(ctx, path)
	if err != nil {
		return ports.LatestInfo{}, domain.Deprecation{}, fmt.Errorf("resolving %s@latest: %w", path, err)
	}
	return info, domain.Deprecation{}, nil
}

// primeBatch makes the batched call once, on first need, and remembers its
// outcome — including its failure, so a call that failed for the whole set is
// not re-attempted once per module.
func (r *Resolver) primeBatch(ctx context.Context) error {
	if r.batchPrimed {
		return r.batchErr
	}
	r.batchPrimed = true
	paths := make([]string, 0, len(r.batchCoords))
	for _, mod := range r.batchCoords {
		paths = append(paths, mod.Path)
	}
	answers, err := r.batch.LatestBatch(ctx, paths)
	if err != nil {
		r.batchErr = fmt.Errorf("%w: %w", ErrBatchUnavailable, err)
		return r.batchErr
	}
	r.batched = answers

	// The probe rides the same priming. It is a separate question from a
	// separate source, but it is the same SET, asked once, and asking it here
	// means the per-module loop below never blocks on a network round trip it
	// could have made alongside five hundred others.
	r.prefetchProbes(ctx, r.servedWhole(ctx))
	return nil
}

// servedWhole names the modules whose stored row answers both halves, so the
// prefetch does not ask about them.
//
// It repeats the freshness test Resolve applies per module, which is a second
// keyed read of a local table and costs microseconds. Skipping it would cost a
// network request per already-answered module on every partially warm run —
// the exact charge the ledger exists to remove.
func (r *Resolver) servedWhole(ctx context.Context) map[string]bool {
	skip := make(map[string]bool)
	if r.ledger == nil || r.fresh || r.ttl <= 0 {
		return skip
	}
	now := r.clk.Now()
	for _, mod := range r.batchCoords {
		rec, found, err := r.ledger.GetStaleness(ctx, mod.Path)
		if err != nil || !found || !rec.FreshAt(now, r.ttl) {
			continue
		}
		plan := domain.PlanProbe(mod.Path, mod.Version)
		if !rec.NewerMajor.Probed || rec.NewerMajor.FromMajor != plan.Start() {
			continue
		}
		if _, asks := plan.SameMajor(); asks && !rec.Republication.Asked {
			continue
		}
		skip[mod.Path] = true
	}
	return skip
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
		info, err := r.probeInfo(ctx, candidate)
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
		info, err := r.probeInfo(ctx, candidate)
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
