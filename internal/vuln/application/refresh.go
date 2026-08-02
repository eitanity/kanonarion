package application

import (
	"context"
	"fmt"
	"slices"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// RefreshOutcome names what a refresh of the advisory database established.
type RefreshOutcome string

const (
	// RefreshUnchanged: the database publishes the generation the store already
	// holds. Nothing was transferred and nothing has changed.
	RefreshUnchanged RefreshOutcome = "unchanged"

	// RefreshIndexUnchanged: the database publishes a NEWER generation, and the
	// advisories it lists for every module in the walk are identical to the ones
	// the stored generation listed. The new generation changed something, but not
	// anything this walk is judged on. Nothing was transferred; the stored
	// snapshot stands.
	RefreshIndexUnchanged RefreshOutcome = "index-unchanged"

	// RefreshDownloaded: the database body was fetched and stored, either because
	// something this walk is judged on changed, or because the cheap checks could
	// not be made and the refresh failed closed into the full download.
	RefreshDownloaded RefreshOutcome = "downloaded"
)

// SnapshotRefresh states what a refresh of the advisory database established.
//
// It is the report of RefreshSnapshot, and exists because the outcome is the
// answer to a question the operator asked: they wanted the advisory database
// brought up to date, and each of the ways it can already be up to date is a
// different statement about a different thing. A caller that only got the
// snapshot back could not tell them apart, and would have to describe the
// refresh by what it hoped happened.
type SnapshotRefresh struct {
	// Outcome is which of the three things happened.
	Outcome RefreshOutcome

	// Snapshot is the database in force after the refresh: the newly downloaded
	// one, or the stored one the checks found still answering.
	Snapshot domain.DatabaseSnapshot

	// PriorVersion is the generation held before the refresh; empty when the
	// store held no snapshot at all.
	PriorVersion string

	// PublishedVersion is the generation the database publishes. Empty when it
	// could not be read.
	PublishedVersion string

	// ModulesCompared is how many module paths the index comparison covered. It
	// is the size of the claim RefreshIndexUnchanged makes, so it is reported
	// with it rather than left for the reader to assume.
	ModulesCompared int

	// StampErr is set when the published generation could not be read and the
	// refresh fell back to downloading the body.
	//
	// It is carried rather than returned because the refresh succeeded: the
	// operator got the live database they asked for. What they did not get is the
	// cheap check, and a refresh that silently degraded into a full download on a
	// network blip would be indistinguishable from one that found a new
	// generation.
	StampErr error

	// IndexErr is the same thing one level down: the generation had advanced, but
	// the two indexes could not be fetched or compared, so the refresh fell back
	// to the full download and a re-scan rather than assuming either answer.
	IndexErr error
}

// Downloaded reports whether the full database body was transferred.
func (r SnapshotRefresh) Downloaded() bool { return r.Outcome == RefreshDownloaded }

// RefreshSnapshot brings the advisory database up to date for the walk that is
// about to be judged against it, and reports what that took.
//
// Two checks stand between the operator's request and the multi-megabyte body,
// each answering a narrower question than the one before:
//
//  1. Has the database changed at all? The published generation stamp is one
//     small request, and the overwhelmingly common answer is no.
//  2. Has it changed anything THIS WALK is judged on? A new generation is
//     published whenever any advisory in the whole ecosystem moves; the walk is
//     judged on the advisories listed for its own modules. The standalone module
//     index — a fraction of the body's size — answers this exactly, by
//     comparing the entries listed for each of the walk's modules in the stored
//     generation and the published one.
//
// Only a difference the walk is actually judged on reaches the download. When
// the second check passes, the stored snapshot stays in force: the run judged
// against it was judged against the same advisories for these modules, and the
// caller's ordinary reuse predicate serves it, still naming the generation it was
// really judged against. The claim that it remains current is this refresh's
// finding, reported alongside it, not a rewrite of the run.
//
// Every failure falls through to the full download and a re-scan, and says so.
// A refresh the operator explicitly asked for must not turn into a cache hit
// because the network flickered — the one outcome that would let a stale
// database pass for a checked one.
func (uc *ScanWalkUseCase) RefreshSnapshot(ctx context.Context, walkID string) (SnapshotRefresh, error) {
	stored, ok, err := uc.vulnStore.GetLatestDatabaseSnapshot(ctx)
	if err != nil {
		return SnapshotRefresh{}, fmt.Errorf("checking stored snapshot: %w", err)
	}
	if !ok {
		// Nothing to compare against: the body is the only thing that answers.
		uc.logger.Info("advisory database refresh: no stored snapshot, downloading")
		return uc.downloadRefresh(ctx, SnapshotRefresh{})
	}

	base := SnapshotRefresh{PriorVersion: stored.Version()}

	published, verr := uc.moduleScanner.database.LatestVersion(ctx)
	if verr != nil {
		uc.logger.Warn("advisory database refresh: published generation unreadable, downloading",
			"error", verr, "stored_version", stored.Version())
		base.StampErr = verr
		return uc.downloadRefresh(ctx, base)
	}
	base.PublishedVersion = published

	if published == stored.Version() {
		uc.logger.Info("advisory database refresh: unchanged, keeping stored snapshot",
			"source", stored.Source(), "version", stored.Version())
		base.Outcome = RefreshUnchanged
		base.Snapshot = stored
		return base, nil
	}

	uc.logger.Info("advisory database refresh: new generation published, comparing the walk's advisories",
		"stored_version", stored.Version(), "published_version", published, "walk_id", walkID)

	changed, compared, ierr := uc.walkAdvisoriesChanged(ctx, walkID, stored)
	if ierr != nil {
		uc.logger.Warn("advisory database refresh: advisory comparison unavailable, downloading",
			"error", ierr, "walk_id", walkID)
		base.IndexErr = ierr
		return uc.downloadRefresh(ctx, base)
	}
	base.ModulesCompared = compared

	if changed {
		uc.logger.Info("advisory database refresh: the walk's advisories changed, downloading",
			"walk_id", walkID, "modules_compared", compared)
		return uc.downloadRefresh(ctx, base)
	}

	uc.logger.Info("advisory database refresh: the walk's advisories are unchanged, keeping stored snapshot",
		"stored_version", stored.Version(), "published_version", published, "modules_compared", compared)
	base.Outcome = RefreshIndexUnchanged
	base.Snapshot = stored
	return base, nil
}

// walkAdvisoriesChanged reports whether the published generation lists different
// advisories from the stored one for ANY module in walkID, and how many module
// paths that comparison covered.
//
// The comparison is restricted to the walk's own modules — the stdlib node
// among them, because the walk carries it as a node and it is judged like any
// other. Every other module in the ecosystem is out of the question this walk
// asks, and a generation that moved only for those moved nothing here.
func (uc *ScanWalkUseCase) walkAdvisoriesChanged(
	ctx context.Context, walkID string, stored domain.DatabaseSnapshot,
) (bool, int, error) {
	paths, err := uc.walkModulePaths(ctx, walkID)
	if err != nil {
		return false, 0, err
	}
	if len(paths) == 0 {
		return false, 0, fmt.Errorf("walk %q names no modules to compare advisories for", walkID)
	}

	storedIndex, err := uc.moduleScanner.database.SnapshotAdvisoryIndex(ctx, stored)
	if err != nil {
		return false, 0, fmt.Errorf("reading the stored generation's advisory index: %w", err)
	}
	publishedIndex, err := uc.moduleScanner.database.PublishedAdvisoryIndex(ctx)
	if err != nil {
		return false, 0, fmt.Errorf("reading the published advisory index: %w", err)
	}

	for _, path := range paths {
		if !slices.Equal(storedIndex[path], publishedIndex[path]) {
			uc.logger.Info("advisory database refresh: advisories changed for a walk module",
				"module_path", path,
				"stored_entries", len(storedIndex[path]), "published_entries", len(publishedIndex[path]))
			return true, len(paths), nil
		}
	}
	return false, len(paths), nil
}

// walkModulePaths returns the distinct module paths the walk holds, sorted, so
// the comparison covers the same set in the same order every run.
func (uc *ScanWalkUseCase) walkModulePaths(ctx context.Context, walkID string) ([]string, error) {
	if walkID == "" {
		return nil, fmt.Errorf("no walk named, so the advisory comparison has no module set to restrict to")
	}
	walk, err := uc.walkStore.GetWalk(ctx, walkID)
	if err != nil {
		return nil, fmt.Errorf("loading walk %q: %w", walkID, err)
	}
	seen := make(map[string]struct{}, len(walk.Graph.Nodes))
	paths := make([]string, 0, len(walk.Graph.Nodes))
	for _, node := range walk.Graph.Nodes {
		p := node.Coordinate.Path()
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		paths = append(paths, p)
	}
	slices.Sort(paths)
	return paths, nil
}

// downloadRefresh fetches and stores the full database, reporting the refresh it
// completed on top of whatever the checks above already established.
func (uc *ScanWalkUseCase) downloadRefresh(ctx context.Context, base SnapshotRefresh) (SnapshotRefresh, error) {
	s, err := uc.fetchAndPersistSnapshot(ctx, "resolving fresh snapshot", "persisting fresh database snapshot")
	if err != nil {
		return SnapshotRefresh{}, err
	}
	base.Outcome = RefreshDownloaded
	base.Snapshot = *s
	return base, nil
}
