package cli

import (
	"context"
	"fmt"
	"sort"

	"github.com/eitanity/kanonarion/internal/coordinate"

	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// vulnBatchCtx holds snapshot and scan-run data fetched once for a walk batch,
// eliminating redundant ListWalks / ListWalkScanRuns calls per module.
type vulnBatchCtx struct {
	hasSnapshot bool
	snap        vuldomain.DatabaseSnapshot
	// runs maps walkID → scan runs; populated for the walkLimit most recent walks.
	runs map[string][]vuldomain.WalkScanRun
	// windowCapped is true when the store held at least one walk beyond the
	// window. Measured by over-fetching one row, never assumed: on a store with
	// fewer walks than the cap the window IS the population, and a note saying
	// otherwise would hedge an answer that has nothing to hedge.
	windowCapped bool
	// window is the same walk set as runs, in the recency order ListWalks
	// returned it in, and it is what an unanchored read resolves a record's walk
	// against: a record measured outside this set has no run to read. runs stays
	// the lookup. The two are populated together: a batch carrying runs but no
	// window answers as though the window were empty, so only loadVulnBatchCtx
	// builds one outside tests.
	window []string
	// walkUC backs the lazy graph loader used to filter walk-level annotations
	// by transitive reachability. nil when no snapshot exists.
	walkUC QueryWalksUseCase
	// graphCache memoises GetWalk per walkID. A nil entry records a load failure
	// so a missing/broken walk is not re-fetched per module.
	graphCache map[string]*walkdomain.Graph
	// affectedCache memoises the affected-module set per walkID.
	affectedCache map[string]map[coordinate.ModuleCoordinate]struct{}
	// anchor is the build this batch reports on, when the caller named one — a
	// walk, or the project a go.mod declares. Set means every per-module verdict
	// is selected in that build's frame and read from that walk's runs alone.
	// Unset means the batch spans the walk window, as it always did.
	anchor   vulnFrameAnchor
	anchored bool
	// frameCache memoises each walk's analysis frame, which is what a per-module
	// verdict read for that walk selects on. Cached per walk rather than per
	// module: it costs one walk-record read and is asked for once per module.
	frameCache map[string]vulnFrameAnchor
}

// anchorTo fixes the build this batch answers for. Callers that know which walk
// the report is about — context in walk mode, and the go.mod modes through the
// project's own walk — call it, and every module's verdict is then read in that
// walk's frame instead of in whichever frame the walk window happened to hold.
func (b *vulnBatchCtx) anchorTo(ctx context.Context, walkID string) {
	if walkID == "" {
		return
	}
	b.anchor = b.frameFor(ctx, walkID)
	b.anchored = true
}

// frameFor returns the frame walkID's scans were rooted at. A walk whose record
// cannot be read yields a frameless anchor, which still pins the read to that
// walk's own records and selects a consumer frame within them.
func (b *vulnBatchCtx) frameFor(ctx context.Context, walkID string) vulnFrameAnchor {
	if b.frameCache == nil {
		return vulnFrameAnchor{walkID: walkID}
	}
	if a, ok := b.frameCache[walkID]; ok {
		return a
	}
	anchor := vulnFrameAnchor{walkID: walkID}
	if b.walkUC != nil {
		if rec, err := b.walkUC.GetWalk(ctx, walkID); err == nil {
			anchor = walkFrameAnchor(walkID, rec.Target)
		}
	}
	b.frameCache[walkID] = anchor
	return anchor
}

// vulnContextWalkWindow is how many of the newest walks a context report loads
// scan runs for.
//
// It is a recency window and it stays one: the alternative is reading every
// walk's runs on every context invocation, which is the friction the window
// exists to avoid. Unlike the containment search it cannot report a false
// absence — a module's verdict comes from the vulnerability ledger, not from
// this set — so what it owes is a stated basis, not a wider search. What the
// window does bound is the RUN CONTEXT attached to a verdict, and the surface
// says so whenever the bound bit.
const vulnContextWalkWindow = 10

func loadVulnBatchCtx(ctx context.Context, runsUC QueryScanRunsUseCase, walkUC QueryWalksUseCase) (*vulnBatchCtx, error) {
	snap, found, err := runsUC.GetLatestSnapshot(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading vuln snapshot: %w", err)
	}
	if !found {
		return &vulnBatchCtx{}, nil
	}
	// One walk more than the window keeps: the extra row is what tells the report
	// whether the window was the whole store or a slice of it.
	walks, err := walkUC.ListWalks(ctx, walkports.WalkFilter{Limit: truncationFetchLimit(vulnContextWalkWindow)})
	if err != nil {
		return nil, fmt.Errorf("listing walks: %w", err)
	}
	walks, capped := truncateList(walks, vulnContextWalkWindow)
	runsMap := make(map[string][]vuldomain.WalkScanRun, len(walks))
	// ListWalks returns the window in recency order and that order is preserved
	// here, because it is what an unanchored read answers in.
	window := make([]string, 0, len(walks))
	for _, w := range walks {
		runs, err := runsUC.ListRunsForWalk(ctx, w.ID)
		if err != nil {
			continue
		}
		runsMap[w.ID] = runs
		window = append(window, w.ID)
	}
	return &vulnBatchCtx{
		hasSnapshot:   true,
		snap:          snap,
		runs:          runsMap,
		window:        window,
		windowCapped:  capped,
		walkUC:        walkUC,
		graphCache:    make(map[string]*walkdomain.Graph),
		affectedCache: make(map[string]map[coordinate.ModuleCoordinate]struct{}),
		frameCache:    make(map[string]vulnFrameAnchor),
	}, nil
}

// graphFor lazily loads and caches the dependency graph for walkID. The second
// return is false when the graph cannot be loaded, in which case reachability
// filtering is skipped and the generic walk annotation is left intact.
func (b *vulnBatchCtx) graphFor(ctx context.Context, walkID string) (*walkdomain.Graph, bool) {
	if b.graphCache == nil || b.walkUC == nil {
		return nil, false
	}
	if g, ok := b.graphCache[walkID]; ok {
		return g, g != nil
	}
	rec, err := b.walkUC.GetWalk(ctx, walkID)
	if err != nil {
		b.graphCache[walkID] = nil
		return nil, false
	}
	g := rec.Graph
	b.graphCache[walkID] = &g
	return &g, true
}

// affectedFor lazily computes and caches the set of module coordinates that are
// Affected in the most recent scan run for walkID.
//
// A store read error is a fault, not a verdict: it is propagated, never
// fabricated into an Affected entry — presenting a peer as affected when the
// store could only not be read is the same absence/error-as-answer defect this
// codebase removes elsewhere. A not-found record is a coverage gap (the run
// lists the coordinate but nothing backs a verdict): it is no evidence of
// Affected, so it is skipped rather than fabricated. Only a real StatusAffected
// record adds a coordinate. A failed read is not cached, so a later read may
// still succeed.
func (b *vulnBatchCtx) affectedFor(ctx context.Context, walkID string, vulnUC QueryVulnUseCase) (map[coordinate.ModuleCoordinate]struct{}, error) {
	if b.affectedCache == nil {
		return nil, nil
	}
	if s, ok := b.affectedCache[walkID]; ok {
		return s, nil
	}
	runs := b.runs[walkID]
	affected := make(map[coordinate.ModuleCoordinate]struct{})
	if len(runs) > 0 {
		run := runs[0] // most recent (DESC by started_at)
		// Each peer's verdict is read in the walk's own frame. Read frame-blind,
		// a peer measured in another project's build could be reported affected —
		// or clean — in this walk's closure on the strength of a scan that never
		// looked at this build.
		anchor := b.frameFor(ctx, run.WalkID)
		for coord := range run.PerModuleResults {
			rec, found, err := recordInWalkFrame(ctx, vulnUC, coord, anchor)
			if err != nil {
				return nil, fmt.Errorf("reading walk-peer verdict for %s in walk %s: %w", coord, run.WalkID, err)
			}
			if !found {
				continue
			}
			// "Is this peer affected" is a findings question, so it is asked of the
			// findings axis. The collapsed word answers it only for a module that
			// was analysed: a metadata-only peer whose coordinate matched an advisory
			// carries the finding on the axis, and reading the word would have
			// dropped it from the closure the moment its coverage word won the
			// collapse.
			if _, findings := vuldomain.RecordAxes(rec); findings == vuldomain.FindingsRecordAffected {
				affected[coord] = struct{}{}
			}
		}
	}
	b.affectedCache[walkID] = affected
	return affected, nil
}

// filterWalkAnnotation names the affected peers that lie in coord's own
// transitive dependency closure, so the walk-level finding is surfaced only
// where it is actionable for this module.
//
// It is driven by the findings axis alone (run.FindingsStatus): a run that found
// vulnerabilities may carry an affected peer in this module's closure regardless
// of whether coverage was complete. Keying on the collapsed OverallStatus was
// the collapse defect — a single unscannable module made the run Partial, so this
// narrowing never ran and a reachable advisory in a direct dependency was
// silently dropped. The coverage axis is carried independently on
// result.WalkCoverage and rendered separately, so an incomplete-coverage run no
// longer suppresses a real finding. The graph is required to narrow to the
// closure; when it cannot be loaded there is no basis to narrow, so no peer is
// named.
func (b *vulnBatchCtx) filterWalkAnnotation(ctx context.Context, result *contextVulnerabilities, coord coordinate.ModuleCoordinate, run vuldomain.WalkScanRun, vulnUC QueryVulnUseCase) {
	if run.FindingsStatus != vuldomain.FindingsAffected {
		return
	}
	graph, ok := b.graphFor(ctx, run.WalkID)
	if !ok {
		return
	}

	reachable := graph.ReachableFrom(coord)
	affected, err := b.affectedFor(ctx, run.WalkID, vulnUC)
	if err != nil {
		// A peer's verdict could not be read. Do not fabricate an affected peer
		// from a store fault, and do not misattribute the fault to this module's
		// own verdict (which read fine) by turning the whole section into a read
		// error. Record the fault so the peer set reads as uncertain rather than
		// as a confident finding.
		result.WalkError = err.Error()
		return
	}

	var peers []string
	for ac := range affected {
		if ac == coord {
			continue
		}
		if _, inClosure := reachable[ac]; inClosure {
			peers = append(peers, ac.String())
		}
	}
	sort.Strings(peers)
	result.WalkAffected = peers
}

func buildVulnerabilitiesFromBatch(ctx context.Context, coord coordinate.ModuleCoordinate, vulnUC QueryVulnUseCase, batch *vulnBatchCtx) contextVulnerabilities {
	// Every generation the ledger holds for the coordinate, read once, rather
	// than one composed answer per scan run.
	//
	// context is asked about a module a build depends on, so it is a consumer's
	// question and it is selected for in a consumer's frame — the same read
	// reachability and vuln-show use. The composed store reads this replaces
	// name no frame: their ladder decides on call-graph completeness, a rung an
	// isolated scan wins by construction (it built the module alone, so it
	// records BUILT_WITH_BODIES, while a consumer-rooted analysis records no
	// completeness at all), so context headlined the isolated verdict for every
	// module a project-rooted scan had computed a route through.
	//
	// A store read failure must surface as read_error like every other section —
	// analysed-but-unreadable presented as not_run is the absence-as-answer
	// defect class.
	recs, err := vulnUC.ListRecordsForModule(ctx, coord, vulnPipelineVersion)
	if err != nil {
		return contextVulnerabilities{Status: sectionStatusReadError, Error: err.Error()}
	}
	if batch.anchored {
		return batch.anchoredVulnerabilities(ctx, coord, recs, vulnUC)
	}
	return batch.recordFirstVulnerabilities(ctx, coord, recs, vulnUC)
}

// anchoredVulnerabilities answers for the build the caller named. It looks at
// that walk's runs only: left to iterate the whole walk window it answered a
// walk-pinned report from whichever walk in that window covered the module
// first — measured on a real store, 20 of one project's 128 modules were
// reported in three other projects' frames, one of them inverting a
// reachability verdict.
func (b *vulnBatchCtx) anchoredVulnerabilities(ctx context.Context, coord coordinate.ModuleCoordinate, recs []vuldomain.VulnerabilityRecord, vulnUC QueryVulnUseCase) contextVulnerabilities {
	for _, run := range b.runs[b.anchor.walkID] {
		if _, ok := run.PerModuleResults[coord]; !ok {
			continue
		}
		// Narrowed to run.Snapshot (the snapshot the scan used), not the latest
		// snapshot, exactly as the per-run store read was keyed.
		atSnapshot := recordsAtSnapshot(recs, run.Snapshot)
		rec, found := b.selectForBatch(atSnapshot, coord)
		if !found {
			continue
		}
		result := vulnRecordToContext(&rec, string(run.OverallStatus), walkCoverageCaveat(run))
		b.filterWalkAnnotation(ctx, &result, coord, run, vulnUC)
		return result
	}
	// No run of the anchored walk covers the module with a readable record, so
	// the whole ledger answers — still in the anchored frame.
	rec, found := b.selectForBatch(recs, coord)
	if found {
		return vulnRecordToContext(&rec, "", "")
	}
	return contextVulnerabilities{Status: sectionStatusNotRun}
}

// recordFirstVulnerabilities answers an unanchored read: the best consumer-frame
// record the ledger holds is selected first, and the run context — status word,
// coverage caveat, peer annotation and the named basis — is then read from the
// walk that record was measured in.
//
// Selecting the run first put two builds under one heading: the window's newest
// covering walk gated the run while the record was ranked ledger-wide, so the
// verdict described one build and the peers-in-closure claim another. Keying
// everything to the record makes the whole section one build's answer, and it
// changes only when better evidence lands rather than whenever a neighbouring
// project walks a tree that happens to contain the module.
//
// The peer annotation therefore means "affected peers in the closure of the
// build that produced this verdict", not "in the newest build covering the
// module".
func (b *vulnBatchCtx) recordFirstVulnerabilities(ctx context.Context, coord coordinate.ModuleCoordinate, recs []vuldomain.VulnerabilityRecord, vulnUC QueryVulnUseCase) contextVulnerabilities {
	rec, found := b.selectForBatch(recs, coord)
	if !found {
		return contextVulnerabilities{Status: sectionStatusNotRun}
	}
	result := vulnRecordToContext(&rec, "", "")
	if run, ok := b.runThatProduced(rec, coord); ok {
		result = vulnRecordToContext(&rec, string(run.OverallStatus), walkCoverageCaveat(run))
		b.filterWalkAnnotation(ctx, &result, coord, run, vulnUC)
	}
	b.nameRecordBasis(ctx, &result, rec.WalkID)
	b.nameWindowBound(&result, rec.WalkID)
	return result
}

// nameWindowBound states the recency window when it, rather than the scan, is
// why this section carries no run context.
//
// Silent when the window covered every walk the store holds: that answer did
// exhaust the population, and saying so anyway would make the note unreadable in
// the case it exists for.
func (b *vulnBatchCtx) nameWindowBound(result *contextVulnerabilities, walkID string) {
	if !b.windowCapped || walkID == "" || b.inWindow(walkID) {
		return
	}
	result.WalkWindowNote = fmt.Sprintf(
		"no run context: this record was measured in a walk outside the %d most recent this report loaded runs for",
		vulnContextWalkWindow)
}

// runThatProduced returns the scan run the served record came out of: the run
// of the record's own walk that covers coord and judged it against the record's
// own advisory snapshot.
//
// It is resolved through the window, which is the set of walks whose runs this
// batch loaded. A record measured in a walk outside that set has no run context
// to read, and the section then states only what the record itself says rather
// than borrowing another build's status word.
func (b *vulnBatchCtx) runThatProduced(rec vuldomain.VulnerabilityRecord, coord coordinate.ModuleCoordinate) (vuldomain.WalkScanRun, bool) {
	if rec.WalkID == "" || !b.inWindow(rec.WalkID) {
		return vuldomain.WalkScanRun{}, false
	}
	for _, run := range b.runs[rec.WalkID] {
		if _, ok := run.PerModuleResults[coord]; !ok {
			continue
		}
		if !sameSnapshot(run.Snapshot, rec.DatabaseSnapshot) {
			continue
		}
		return run, true
	}
	return vuldomain.WalkScanRun{}, false
}

// inWindow reports whether walkID is one of the walks this batch loaded runs
// for.
func (b *vulnBatchCtx) inWindow(walkID string) bool {
	for _, id := range b.window {
		if id == walkID {
			return true
		}
	}
	return false
}

// sameSnapshot reports whether two records name the same advisory-database
// generation. Source and version are the whole of snapshot identity here, the
// same key the store's own per-snapshot read uses; the retrieval instant travels
// with the record and is not part of it.
func sameSnapshot(a, b vuldomain.DatabaseSnapshot) bool {
	return a.Source() == b.Source() && a.Version() == b.Version()
}

// nameRecordBasis states which walk an unanchored answer was read from, and the
// frame that walk was rooted at.
//
// The answer is a fact about one build: "affected via <peer>" is true in the
// walk that found the peer and says nothing about any other, and the verdict
// itself was measured there. Stated without the walk, it is a frame-dependent
// claim with the frame withheld. The walk named is always the served record's
// own, so the basis and the record's provenance cannot disagree. An anchored
// batch is silent here because its caller already names the build it pinned to.
func (b *vulnBatchCtx) nameRecordBasis(ctx context.Context, result *contextVulnerabilities, walkID string) {
	if b.anchored || walkID == "" {
		return
	}
	result.WalkBasisID = walkID
	if anchor := b.frameFor(ctx, walkID); anchor.rooting.IsRecorded() {
		result.WalkBasisFrame = string(anchor.rooting)
	}
}

// selectForBatch picks the record a batch report serves for one coordinate: in
// the anchored build's frame when the caller named a build, and frame-first
// among consumers when it did not.
func (b *vulnBatchCtx) selectForBatch(recs []vuldomain.VulnerabilityRecord, coord coordinate.ModuleCoordinate) (vuldomain.VulnerabilityRecord, bool) {
	if b.anchored && b.anchor.rooting.IsRecorded() {
		rec, _, _, ok := selectRecordInFrame(recs, b.anchor.rooting)
		return rec, ok
	}
	rec, _, _, ok := selectConsumerRecord(recs, coord)
	return rec, ok
}

// recordsAtSnapshot narrows a coordinate's generations to the ones reached
// against one advisory-database snapshot.
//
// Source and version are the whole of snapshot identity here because they are
// what the store's own per-snapshot read keys on; the retrieval instant travels
// with the record and is not part of the key.
func recordsAtSnapshot(recs []vuldomain.VulnerabilityRecord, snap vuldomain.DatabaseSnapshot) []vuldomain.VulnerabilityRecord {
	out := make([]vuldomain.VulnerabilityRecord, 0, len(recs))
	for _, r := range recs {
		if r.DatabaseSnapshot.Source() == snap.Source() && r.DatabaseSnapshot.Version() == snap.Version() {
			out = append(out, r)
		}
	}
	return out
}

// walkCoverageCaveat returns the coverage-axis annotation for a run when it left
// modules unanalysed, and empty when coverage is complete (or unknown, as on a
// legacy run whose CoverageStatus was never stored). It is independent of the
// findings axis: an incomplete-coverage run carries this caveat whether or not
// it also found a vulnerability.
func walkCoverageCaveat(run vuldomain.WalkScanRun) string {
	switch run.CoverageStatus {
	case vuldomain.CoveragePartial, vuldomain.CoverageFailed:
		return string(run.CoverageStatus)
	default:
		return ""
	}
}

func vulnRecordToContext(rec *vuldomain.VulnerabilityRecord, walkStatus, walkCoverage string) contextVulnerabilities {
	out := contextVulnerabilities{
		ExtractedAt:     isoTime(rec.ScannedAt),
		Status:          string(rec.OverallStatus),
		WalkStatus:      walkStatus,
		WalkCoverage:    walkCoverage,
		Reason:          rec.UnscannableReason,
		WalkID:          rec.WalkID,
		Frame:           string(vuldomain.RecordRooting(*rec)),
		LastValidatedAt: isoTime(rec.ScannedAt),
		SnapshotVersion: rec.DatabaseSnapshot.Version(),
		PipelineVersion: rec.PipelineVersion,
	}
	if !rec.FirstScannedAt.IsZero() {
		out.FirstValidatedAt = isoTime(rec.FirstScannedAt)
	}
	if !rec.DatabaseSnapshot.RetrievedAt().IsZero() {
		out.SnapshotRetrievedAt = isoTime(rec.DatabaseSnapshot.RetrievedAt())
		out.SnapshotAgeDays = vuldomain.SnapshotAgeDays(rec.ScannedAt, rec.DatabaseSnapshot.RetrievedAt())
	}
	for _, f := range rec.Findings {
		cve := contextCVE{
			ID:      f.ID,
			Aliases: f.Aliases,
			Summary: f.Summary,
			FixedIn: f.FixedIn,
		}
		if f.Severity != nil {
			cve.Score = f.Severity.Score
		}
		if f.IsWithdrawn() {
			cve.WithdrawnAt = isoTime(f.WithdrawnAt)
		}
		if f.Reachable != nil {
			r := f.Reachable.IsReachable
			cve.Reachable = &r
		}
		out.Findings = append(out.Findings, cve)
	}
	return out
}
