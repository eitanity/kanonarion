package application

import (
	"context"
	"fmt"
	"sync"

	"github.com/eitanity/kanonarion/internal/staleness/domain"
	"github.com/eitanity/kanonarion/internal/staleness/ports"
)

// This file holds the CONCURRENT half of a go.mod-scoped resolution.
//
// The batched source answers the same-major latest for the whole scope in one
// call. What it cannot answer is the newer-major question: `go list -m -u` does
// not cross a major boundary, so kanonarion still has to ask the proxy whether a
// path one major above each pin exists. That is one request per module in the
// closure — for almost every module a 404 — and asking them one at a time is
// what was left of the marathon after the latest half was batched away.
//
// So they are asked in ROUNDS, concurrently. Round one holds every module's
// first probe candidate, plus the republication question for the pins that ask
// it, plus the @latest tag lookup for the pins that could be sitting above one.
// Round two holds only the next major of the modules whose round-one candidate
// resolved, which on a real corpus is a few dozen of several hundred. The walk
// itself is unchanged and still stops at the first absent major; it just reads
// answers that are already in hand.
//
// The width is bounded and configurable, and the bound is not a performance
// dial — it is a correctness one. A throttled proxy does not refuse, it answers
// 200 with an empty body, and that is a LOST ANSWER rather than an error. The
// default is the measured knee; see domain.DefaultStalenessProbeConcurrency in
// the config package for the figures.

// probeResult is one prefetched answer, carrying the error as a value so an
// absent path — the ordinary case, and the thing that bounds the walk — is
// replayed to the walk exactly as a live call would have delivered it.
type probeResult struct {
	info ports.LatestInfo
	err  error
}

// probeInfo answers a probe candidate from the prefetch when it is there, and
// live otherwise.
//
// The fall-through is not a fast path, it is the correctness one: `latest
// <module>` names a path no scope prefetched, and a walk that climbed further
// than the rounds went has candidates nobody asked for. Neither may read a
// missing entry as an absent path — that would end a walk on silence.
func (r *Resolver) probeInfo(ctx context.Context, path string) (ports.LatestInfo, error) {
	if res, ok := r.prefetched[path]; ok {
		return res.info, res.err
	}
	info, err := r.proxy.LatestInfo(ctx, path)
	if err != nil {
		return ports.LatestInfo{}, fmt.Errorf("resolving %s@latest: %w", path, err)
	}
	return info, nil
}

// prefetchProbes fills r.prefetched for every module in the scope.
//
// skip names the modules whose stored row will be served whole, so their probe
// is not asked again: a partially warm run must not pay for the rows the ledger
// already answers, which is the entire reason the ledger exists.
func (r *Resolver) prefetchProbes(ctx context.Context, skip map[string]bool) {
	type walker struct {
		fam  domain.Family
		next int
	}

	r.prefetched = make(map[string]probeResult)
	var round []string
	var walkers []walker

	for _, mod := range r.batchCoords {
		if skip[mod.Path] {
			continue
		}
		plan := domain.PlanProbe(mod.Path, mod.Version)
		fam := domain.ParseFamily(mod.Path)

		if m, asks := plan.SameMajor(); asks {
			round = append(round, fam.PathForMajor(m))
		}
		round = append(round, fam.PathForMajor(plan.Start()))
		walkers = append(walkers, walker{fam: fam, next: plan.Start()})

		// The tag lookup, for the pins that can be sitting above one. See
		// tagCandidate.
		if r.tagCandidate(mod) {
			round = append(round, mod.Path)
		}
	}

	for depth := 0; depth < maxProbeDepth && len(round) > 0; depth++ {
		r.fetchRound(ctx, round)

		// Only a module whose current candidate RESOLVED continues: an absent
		// major ends the walk, and so does a failure, which leaves the walk
		// unprobed rather than truncated. That is the serial walk's own rule,
		// applied a round at a time.
		round = nil
		var next []walker
		for _, w := range walkers {
			res, ok := r.prefetched[w.fam.PathForMajor(w.next)]
			if !ok || res.err != nil {
				continue
			}
			w.next++
			next = append(next, w)
			round = append(round, w.fam.PathForMajor(w.next))
		}
		walkers = next
	}
}

// fetchRound asks for every path in one round, at most r.concurrency at a time.
func (r *Resolver) fetchRound(ctx context.Context, paths []string) {
	width := r.concurrency
	if width < 1 {
		width = 1
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, width)

	for _, path := range paths {
		mu.Lock()
		_, done := r.prefetched[path]
		mu.Unlock()
		if done {
			// Two modules of one family can plan the same candidate; asking twice
			// would spend a request to learn what is already known.
			continue
		}

		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			info, err := r.proxy.LatestInfo(ctx, p)
			mu.Lock()
			r.prefetched[p] = probeResult{info: info, err: err}
			mu.Unlock()
		}(path)
	}
	wg.Wait()
}

// tagCandidate reports whether this module's own @latest must be looked up
// despite the batch reporting no update.
//
// The batched source resolves within the pin's OWN major and reports nothing
// when there is no higher version in it. That covers two different states: the
// pin is the newest release, or the pin sits ABOVE the last tag — a
// pseudo-version taken after it, a prerelease, or a pre-modules +incompatible
// major above what the unsuffixed path serves. Read as one, the second renders
// as `current`, which is exactly the answer the pin-ahead state was added to
// stop giving.
//
// The narrowing is SYNTACTIC and is stated as such: a version can only sort
// above a release tag if it carries prerelease or +incompatible metadata, so
// only those pins are looked up. A plain release pin the go command reports no
// update for is the newest tag in its major by construction. This is an
// inference from the shape of the version string, not a measurement, and it is
// tested against every such row in the road-test corpus.
func (r *Resolver) tagCandidate(mod ports.PinnedModule) bool {
	b, ok := r.batched[mod.Path]
	if !ok || b.Updated {
		// No batched answer means the per-path resolver answers this module
		// anyway; an update means the go command named something newer, which is
		// the better answer and is kept.
		return false
	}
	return domain.CanSortAboveTag(mod.Version)
}
