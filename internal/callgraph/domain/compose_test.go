package domain_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// composeSpec describes one generation to be laid down in a ledger.
type composeSpec struct {
	version      string
	source       domain.AnalysisSource
	completeness domain.CompletenessLevel
	artefact     string
	worktree     string
	extractedAt  time.Time
	// symbol varies the graph, so two records can be made to disagree about what
	// the module contains without differing on anything else.
	symbol string
	status domain.CallGraphStatus
}

func composeRecord(t *testing.T, spec composeSpec) domain.CallGraphRecord {
	t.Helper()
	version := spec.version
	if version == "" {
		version = "v1.0.0"
	}
	coord, err := coordinate.NewModuleCoordinate("example.com/mod", version)
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	at := spec.extractedAt
	if at.IsZero() {
		at = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	symbol := spec.symbol
	if symbol == "" {
		symbol = "Foo"
	}
	status := spec.status
	if status == domain.CallGraphStatusUnknown {
		status = domain.CallGraphStatusExtracted
	}
	r := domain.CallGraphRecord{
		SchemaVersion:    domain.CallGraphSchemaVersion,
		Ecosystem:        fetchdomain.EcosystemGo,
		Coordinate:       coord,
		Algorithm:        domain.AlgorithmCHA,
		Completeness:     spec.completeness,
		AnalysisSource:   spec.source,
		ArtefactIdentity: spec.artefact,
		WorktreeDigest:   spec.worktree,
		Nodes:            []domain.CallNode{{ID: "example.com/mod." + symbol, Symbol: symbol}},
		OverallStatus:    status,
		NodeCount:        1,
		ExtractedAt:      at,
		PipelineVersion:  "0.3.0",
	}
	var h domain.CallGraphRecordHasher
	sealed, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	return sealed
}

// TestCompose_HighestCompletenessOutranksRecency is the ticket's acceptance
// observable in unit form, using the two levels production actually writes.
//
// A weaker later measurement must not displace a stronger earlier one. It is the
// same rule the fetch ledger applies to verification anchors: recency is the last
// tiebreaker, never the authority.
func TestCompose_HighestCompletenessOutranksRecency(t *testing.T) {
	t.Parallel()
	built := composeRecord(t, composeSpec{
		source: domain.AnalysisSourceModuleZip, artefact: "zip:h1:a",
		completeness: domain.CompletenessBuiltWithBodies,
		extractedAt:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	// Deliberately the NEWER record on every other axis, so a pass can only come
	// from the completeness ladder.
	metadata := composeRecord(t, composeSpec{
		source: domain.AnalysisSourceModuleZip, artefact: "zip:h1:a",
		completeness: domain.CompletenessMetadataOnly,
		extractedAt:  time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		symbol:       "Foo", status: domain.CallGraphStatusLoadFailed,
	})

	got, err := domain.Compose([]domain.CallGraphRecord{built, metadata}, domain.ComposeRequest{})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if got.ContentHash != built.ContentHash {
		t.Fatalf("composition served the METADATA_ONLY record; a weaker later measurement displaced a stronger earlier one")
	}
}

// TestCompose_CompletenessRungCoversEveryLevel pins the local rung ladder to the
// published one. A level added to CompletenessLevels and not to the rung switch
// would silently fall to the bottom, which would let a better fidelity lose to an
// unrecorded one.
//
// The rung function is unexported, so the ordering is exercised through Compose:
// each level must beat the one below it.
func TestCompose_CompletenessRungCoversEveryLevel(t *testing.T) {
	t.Parallel()
	ladder := domain.CompletenessLevels()
	for i := 0; i+1 < len(ladder); i++ {
		better := composeRecord(t, composeSpec{
			source: domain.AnalysisSourceModuleZip, artefact: "zip:h1:a",
			completeness: ladder[i],
			extractedAt:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		})
		worse := composeRecord(t, composeSpec{
			source: domain.AnalysisSourceModuleZip, artefact: "zip:h1:a",
			completeness: ladder[i+1],
			extractedAt:  time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		})
		got, err := domain.Compose([]domain.CallGraphRecord{worse, better}, domain.ComposeRequest{})
		if err != nil {
			t.Fatalf("Compose(%s vs %s): %v", ladder[i], ladder[i+1], err)
		}
		if got.ContentHash != better.ContentHash {
			t.Fatalf("%s lost to %s — the rung ladder does not cover both levels", ladder[i], ladder[i+1])
		}
	}
}

// TestCompose_SourceIsADimensionNotALadder is the epic's rule for this table: a
// zip graph and a worktree graph answer different questions, so composition must
// never serve one for the other.
func TestCompose_SourceIsADimensionNotALadder(t *testing.T) {
	t.Parallel()
	// The worktree record is strictly better on the ladder AND newer, so if the
	// source were laddered it would win the unscoped read.
	zip := composeRecord(t, composeSpec{
		source: domain.AnalysisSourceModuleZip, artefact: "zip:h1:a",
		completeness: domain.CompletenessMetadataOnly,
		extractedAt:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	tree := composeRecord(t, composeSpec{
		source: domain.AnalysisSourceWorktree, worktree: "sha256:tree-a",
		completeness: domain.CompletenessBuiltWithBodies,
		extractedAt:  time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
	})

	got, err := domain.Compose([]domain.CallGraphRecord{zip, tree}, domain.ComposeRequest{})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if got.ContentHash != zip.ContentHash {
		t.Fatalf("unscoped read served the worktree graph; the default is the module zip, which is what a walk writes")
	}

	scoped, err := domain.Compose([]domain.CallGraphRecord{zip, tree},
		domain.ComposeRequest{Source: domain.AnalysisSourceWorktree})
	if err != nil {
		t.Fatalf("Compose(worktree): %v", err)
	}
	if scoped.ContentHash != tree.ContentHash {
		t.Fatal("naming the worktree source did not select the worktree record")
	}
}

// TestCompose_SourceScopedReadWithNoSuchSource reports an absence rather than
// inventing an answer from the other source.
func TestCompose_SourceScopedReadWithNoSuchSource(t *testing.T) {
	t.Parallel()
	zip := composeRecord(t, composeSpec{
		source: domain.AnalysisSourceModuleZip, artefact: "zip:h1:a",
		completeness: domain.CompletenessBuiltWithBodies,
	})
	_, err := domain.Compose([]domain.CallGraphRecord{zip},
		domain.ComposeRequest{Source: domain.AnalysisSourceWorktree})
	if !errors.Is(err, domain.ErrNoRecordsToCompose) {
		t.Fatalf("err = %v, want ErrNoRecordsToCompose", err)
	}
}

// TestCompose_WorktreeIsASequenceNotALadder is the defect the analysis-source
// field exists to prevent, in its real form.
//
// A working tree mutates, so its generations are successive observations of
// changing code rather than competing claims about one pinned artefact. Serving
// a higher-completeness EARLIER record would hand back a graph the tree no longer
// has — deleting a function would silently fail to register.
func TestCompose_WorktreeIsASequenceNotALadder(t *testing.T) {
	t.Parallel()
	older := composeRecord(t, composeSpec{
		version: coordinate.LocalVersion,
		source:  domain.AnalysisSourceWorktree, worktree: "sha256:tree-a",
		completeness: domain.CompletenessBuiltWithBodies,
		symbol:       "Old",
		extractedAt:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	// A later run of a tree that now fails to build fully. On the ladder it loses;
	// as a sequence it is the current state of the tree and must win.
	newer := composeRecord(t, composeSpec{
		version: coordinate.LocalVersion,
		source:  domain.AnalysisSourceWorktree, worktree: "sha256:tree-b",
		completeness: domain.CompletenessTypeOnly,
		symbol:       "New",
		extractedAt:  time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
	})

	got, err := domain.Compose([]domain.CallGraphRecord{older, newer},
		domain.ComposeRequest{Source: domain.AnalysisSourceWorktree})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if got.ContentHash != newer.ContentHash {
		t.Fatal("composition served an earlier observation of a mutating tree; the ledger must serve the last one")
	}
}

// TestCompose_WorktreeSequenceIsByPositionNotTimestamp pins the reason the store
// lists in insertion order.
//
// extracted_at persists at second precision, so two runs within one second carry
// the same timestamp and no clock comparison can order them. The ledger is
// append-only, so position is the sequence it actually has.
func TestCompose_WorktreeSequenceIsByPositionNotTimestamp(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	first := composeRecord(t, composeSpec{
		version: coordinate.LocalVersion,
		source:  domain.AnalysisSourceWorktree, worktree: "sha256:tree-a",
		completeness: domain.CompletenessBuiltWithBodies, symbol: "First", extractedAt: at,
	})
	second := composeRecord(t, composeSpec{
		version: coordinate.LocalVersion,
		source:  domain.AnalysisSourceWorktree, worktree: "sha256:tree-b",
		completeness: domain.CompletenessBuiltWithBodies, symbol: "Second", extractedAt: at,
	})
	if first.ExtractedAt != second.ExtractedAt {
		t.Fatal("premise broken: the two generations must share a timestamp for this test to mean anything")
	}
	got, err := domain.Compose([]domain.CallGraphRecord{first, second},
		domain.ComposeRequest{Source: domain.AnalysisSourceWorktree})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if got.ContentHash != second.ContentHash {
		t.Fatal("with equal timestamps the LAST appended observation must win")
	}
}

// TestCompose_DifferentArtefactsAreAConflict: one pinned version yielding two
// sets of bytes is not a ladder, it is a disagreement about what the module is.
func TestCompose_DifferentArtefactsAreAConflict(t *testing.T) {
	t.Parallel()
	a := composeRecord(t, composeSpec{
		source: domain.AnalysisSourceModuleZip, artefact: "zip:h1:a",
		completeness: domain.CompletenessBuiltWithBodies,
	})
	b := composeRecord(t, composeSpec{
		source: domain.AnalysisSourceModuleZip, artefact: "zip:h1:b",
		completeness: domain.CompletenessBuiltWithBodies,
	})
	_, err := domain.Compose([]domain.CallGraphRecord{a, b}, domain.ComposeRequest{})
	var conflict domain.CallGraphConflict
	if !errors.As(err, &conflict) {
		t.Fatalf("err = %v, want a CallGraphConflict", err)
	}
	if conflict.Field != "artefact_identity" {
		t.Fatalf("conflict field = %q, want artefact_identity", conflict.Field)
	}
	if len(conflict.ContentHashes) != 2 {
		t.Fatalf("conflict must name the record carrying each value, got %v", conflict.ContentHashes)
	}
}

// TestCompose_EqualCompletenessDisagreementIsNonDeterminism is the narrow case
// worth surfacing: same artefact, same fidelity, different graph.
func TestCompose_EqualCompletenessDisagreementIsNonDeterminism(t *testing.T) {
	t.Parallel()
	a := composeRecord(t, composeSpec{
		source: domain.AnalysisSourceModuleZip, artefact: "zip:h1:a",
		completeness: domain.CompletenessBuiltWithBodies, symbol: "Alpha",
	})
	b := composeRecord(t, composeSpec{
		source: domain.AnalysisSourceModuleZip, artefact: "zip:h1:a",
		completeness: domain.CompletenessBuiltWithBodies, symbol: "Beta",
	})
	_, err := domain.Compose([]domain.CallGraphRecord{a, b}, domain.ComposeRequest{})
	var conflict domain.CallGraphConflict
	if !errors.As(err, &conflict) {
		t.Fatalf("err = %v, want a CallGraphConflict", err)
	}
	if conflict.Field != "call_graph" {
		t.Fatalf("conflict field = %q, want call_graph", conflict.Field)
	}
}

// TestCompose_EqualCompletenessAgreementIsNotAConflict pins the false-positive
// case, and fails its own premise loudly if it stops being a real test.
//
// A re-analysis that produced the identical graph carries a DIFFERENT content
// hash, because the time of measurement is inside the hashed shape. A conflict
// check written on the content hash would therefore report every re-analysis as
// non-determinism; GraphDigest is what makes the comparison mean what it says.
func TestCompose_EqualCompletenessAgreementIsNotAConflict(t *testing.T) {
	t.Parallel()
	a := composeRecord(t, composeSpec{
		source: domain.AnalysisSourceModuleZip, artefact: "zip:h1:a",
		completeness: domain.CompletenessBuiltWithBodies,
		extractedAt:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	b := composeRecord(t, composeSpec{
		source: domain.AnalysisSourceModuleZip, artefact: "zip:h1:a",
		completeness: domain.CompletenessBuiltWithBodies,
		extractedAt:  time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC),
	})
	if a.ContentHash == b.ContentHash {
		t.Fatal("premise broken: two analyses a second apart must carry different content hashes, " +
			"or this test no longer proves that agreement is judged on the graph rather than the seal")
	}
	if domain.GraphDigest(a) != domain.GraphDigest(b) {
		t.Fatal("two records describing the identical graph carry different graph digests")
	}
	got, err := domain.Compose([]domain.CallGraphRecord{a, b}, domain.ComposeRequest{})
	if err != nil {
		t.Fatalf("Compose reported a conflict between two agreeing records: %v", err)
	}
	if got.ContentHash != b.ContentHash {
		t.Fatal("with equal completeness the more recent record should be served")
	}
}

// TestCompose_FailedRecordsCannotContradict: an extraction that produced no graph
// makes no claim about one, so pairing it with a real measurement is a refinement
// rather than a disagreement.
func TestCompose_FailedRecordsCannotContradict(t *testing.T) {
	t.Parallel()
	failedA := composeRecord(t, composeSpec{
		source: domain.AnalysisSourceModuleZip, artefact: "zip:h1:a",
		completeness: domain.CompletenessFailed, symbol: "Alpha",
		status: domain.CallGraphStatusLoadFailed,
	})
	failedB := composeRecord(t, composeSpec{
		source: domain.AnalysisSourceModuleZip, artefact: "zip:h1:a",
		completeness: domain.CompletenessFailed, symbol: "Beta",
		status: domain.CallGraphStatusLoadFailed,
	})
	if _, err := domain.Compose([]domain.CallGraphRecord{failedA, failedB}, domain.ComposeRequest{}); err != nil {
		t.Fatalf("two failed extractions reported as non-determinism: %v", err)
	}
}

// TestCompose_UnidentifiedRecordsAreSupersededByIdentifiedOnes: a record written
// before the artefact identity existed cannot be shown to describe the same bytes
// as one that names an artefact, so it stops competing once a better-evidenced
// measurement exists.
func TestCompose_UnidentifiedRecordsAreSupersededByIdentifiedOnes(t *testing.T) {
	t.Parallel()
	legacy := composeRecord(t, composeSpec{
		source: domain.AnalysisSourceModuleZip,
		// No artefact: the pre-field shape.
		completeness: domain.CompletenessBuiltWithBodies, symbol: "Legacy",
		extractedAt: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
	})
	identified := composeRecord(t, composeSpec{
		source: domain.AnalysisSourceModuleZip, artefact: "zip:h1:a",
		completeness: domain.CompletenessBuiltWithBodies, symbol: "Current",
		extractedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	got, err := domain.Compose([]domain.CallGraphRecord{identified, legacy}, domain.ComposeRequest{})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if got.ContentHash != identified.ContentHash {
		t.Fatal("a record naming no artefact outranked one that does")
	}
}

// TestCompose_UnrecordedSourceAnswersWhenNothingNamesOne keeps every pre-field
// record readable. Their source is unrecorded, which is neither zip nor
// worktree, and they must still be served when they are all the ledger holds.
func TestCompose_UnrecordedSourceAnswersWhenNothingNamesOne(t *testing.T) {
	t.Parallel()
	legacy := composeRecord(t, composeSpec{
		artefact:     "zip:h1:a",
		completeness: domain.CompletenessBuiltWithBodies,
	})
	got, err := domain.Compose([]domain.CallGraphRecord{legacy}, domain.ComposeRequest{})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if got.ContentHash != legacy.ContentHash {
		t.Fatal("a record predating the analysis-source field became unreadable")
	}
}

// TestCompose_ARecordNamingNoSourceIsLadderedNotSegregated is the regression
// guard on the upgrade path, and it is here because a road test caught the
// original code failing it on real data.
//
// Every record written before the analysis source existed names none. If those
// were treated as their own group, the FIRST re-analysis of any of them would
// land in a different group from the record it should be laddered against — and
// a failed re-analysis appended today would then displace a fully-built graph
// measured yesterday. That is exactly the "recency is not authority" defect the
// ledger exists to prevent, reintroduced by the fix for a different one.
func TestCompose_ARecordNamingNoSourceIsLadderedNotSegregated(t *testing.T) {
	t.Parallel()
	// The shape observed on the maintainer's store: a BUILT_WITH_BODIES record
	// predating the field, then a re-analysis that failed, appended after it.
	legacy := composeRecord(t, composeSpec{
		artefact:     "zip:h1:a",
		completeness: domain.CompletenessBuiltWithBodies, symbol: "Real",
		extractedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	failed := composeRecord(t, composeSpec{
		source: domain.AnalysisSourceModuleZip, artefact: "zip:h1:a",
		completeness: domain.CompletenessFailed, symbol: "None",
		status:      domain.CallGraphStatusLoadFailed,
		extractedAt: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
	})

	got, err := domain.Compose([]domain.CallGraphRecord{legacy, failed}, domain.ComposeRequest{})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if got.ContentHash != failed.ContentHash {
		return // the built graph won, which is the point
	}
	t.Fatal("a failed re-analysis displaced a fully-built graph, because the older record " +
		"named no analysis source and was segregated instead of laddered")
}

// TestCompose_SilentRecordsStepAsideWhenBothSourcesAreNamed: once the ledger
// holds a zip record AND a worktree record, a record that named neither cannot be
// attributed to either question, so it stops competing — the same reasoning
// identifiedOrAll applies to the artefact identity.
func TestCompose_SilentRecordsStepAsideWhenBothSourcesAreNamed(t *testing.T) {
	t.Parallel()
	silent := composeRecord(t, composeSpec{
		version: coordinate.LocalVersion, artefact: "zip:h1:a",
		completeness: domain.CompletenessBuiltWithBodies, symbol: "Silent",
		extractedAt: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
	})
	zip := composeRecord(t, composeSpec{
		version: coordinate.LocalVersion,
		source:  domain.AnalysisSourceModuleZip, artefact: "zip:h1:a",
		completeness: domain.CompletenessMetadataOnly, symbol: "FromZip",
		status:      domain.CallGraphStatusLoadFailed,
		extractedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	tree := composeRecord(t, composeSpec{
		version: coordinate.LocalVersion,
		source:  domain.AnalysisSourceWorktree, worktree: "sha256:tree-a",
		completeness: domain.CompletenessBuiltWithBodies, symbol: "FromTree",
		extractedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})

	got, err := domain.Compose([]domain.CallGraphRecord{silent, zip, tree}, domain.ComposeRequest{})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if got.ContentHash != zip.ContentHash {
		t.Fatal("with both sources named, the unscoped read must serve the module zip and " +
			"must not be answered by a record that named no source")
	}
}

// TestCompose_MergedGroupKeepsAppendOrder: a worktree group can hold records that
// named no source alongside ones that did, and composition serves the LAST
// observation of a mutating tree by position. Rebuilding the group by
// concatenating subsets would put a legacy record after a newer one and hand back
// a graph the tree no longer has.
func TestCompose_MergedGroupKeepsAppendOrder(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	// Appended first, naming no source: the pre-field local ingest.
	legacy := composeRecord(t, composeSpec{
		version: coordinate.LocalVersion,
		// Same timestamp throughout, so only position can order these.
		completeness: domain.CompletenessBuiltWithBodies, symbol: "Old", extractedAt: at,
	})
	current := composeRecord(t, composeSpec{
		version: coordinate.LocalVersion,
		source:  domain.AnalysisSourceWorktree, worktree: "sha256:tree-now",
		completeness: domain.CompletenessBuiltWithBodies, symbol: "New", extractedAt: at,
	})

	got, err := domain.Compose([]domain.CallGraphRecord{legacy, current}, domain.ComposeRequest{})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if got.ContentHash != current.ContentHash {
		t.Fatal("the merged group lost append order and served the earlier observation of the tree")
	}
}

// TestCompose_LegacyLocalRecordIsStillASequence: before the source field, a
// working-tree ingest was recognisable only by its coordinate. Those records must
// keep the sequence rule, or a branch switch would serve the graph of the tree
// that came before it.
func TestCompose_LegacyLocalRecordIsStillASequence(t *testing.T) {
	t.Parallel()
	older := composeRecord(t, composeSpec{
		version: coordinate.LocalVersion, artefact: "",
		completeness: domain.CompletenessBuiltWithBodies, symbol: "Old",
		extractedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	newer := composeRecord(t, composeSpec{
		version: coordinate.LocalVersion, artefact: "",
		completeness: domain.CompletenessMetadataOnly, symbol: "New",
		extractedAt: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
	})
	got, err := domain.Compose([]domain.CallGraphRecord{older, newer}, domain.ComposeRequest{})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if got.ContentHash != newer.ContentHash {
		t.Fatal("a legacy local ingest was laddered instead of sequenced")
	}
}

// TestCompose_NoRecords reports the programming error rather than an empty
// answer: absence is the store's word, not composition's.
func TestCompose_NoRecords(t *testing.T) {
	t.Parallel()
	if _, err := domain.Compose(nil, domain.ComposeRequest{}); !errors.Is(err, domain.ErrNoRecordsToCompose) {
		t.Fatalf("err = %v, want ErrNoRecordsToCompose", err)
	}
}

// TestCompose_UnknownSourceIsRefusedRatherThanGuessed: a record carrying a source
// this build does not define — written by a newer binary, or corrupt — must not
// be quietly grouped with one that is understood.
func TestCompose_UnknownSourceIsRefusedRatherThanGuessed(t *testing.T) {
	t.Parallel()
	alien := composeRecord(t, composeSpec{
		source:       domain.AnalysisSource("from-the-future"),
		artefact:     "zip:h1:a",
		completeness: domain.CompletenessBuiltWithBodies,
	})
	_, err := domain.Compose([]domain.CallGraphRecord{alien}, domain.ComposeRequest{})
	var conflict domain.CallGraphConflict
	if !errors.As(err, &conflict) {
		t.Fatalf("err = %v, want a CallGraphConflict naming the source", err)
	}
	if conflict.Field != "analysis_source" {
		t.Fatalf("conflict field = %q, want analysis_source", conflict.Field)
	}
	if !strings.Contains(conflict.Error(), "from-the-future") {
		t.Fatalf("the conflict must name the source it could not read: %s", conflict.Error())
	}
}

// TestGraphDigest_IgnoresProvenanceButNotTheGraph pins exactly which fields the
// agreement comparison blanks. Blanking too much would report two different
// graphs as agreeing, which is the failure that matters.
func TestGraphDigest_IgnoresProvenanceButNotTheGraph(t *testing.T) {
	t.Parallel()
	base := composeRecord(t, composeSpec{
		source: domain.AnalysisSourceModuleZip, artefact: "zip:h1:a",
		completeness: domain.CompletenessBuiltWithBodies, symbol: "Foo",
	})

	// Provenance-only differences must not change the digest.
	provenance := base
	provenance.ExtractedAt = base.ExtractedAt.Add(time.Hour)
	provenance.SourceContentHash = "sha256:some-other-fetch-measurement"
	provenance.ContentHash = ""
	if domain.GraphDigest(provenance) != domain.GraphDigest(base) {
		t.Error("a different measurement time or fetch record changed the graph digest")
	}

	// A different graph must.
	different := base
	different.Nodes = []domain.CallNode{{ID: "example.com/mod.Bar", Symbol: "Bar"}}
	if domain.GraphDigest(different) == domain.GraphDigest(base) {
		t.Error("a different node set produced the same graph digest")
	}

	// So must a different completeness: two records that analysed different
	// amounts of the module are not making the same claim.
	fidelity := base
	fidelity.Completeness = domain.CompletenessTypeOnly
	if domain.GraphDigest(fidelity) == domain.GraphDigest(base) {
		t.Error("a different completeness produced the same graph digest")
	}
}

// TestRecordAnalysisSource_DiscriminatorPerSource: what tells two records of the
// same source apart differs by source, and a record naming no source has neither.
func TestRecordAnalysisSource_DiscriminatorPerSource(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		spec     composeSpec
		wantSrc  domain.AnalysisSource
		wantDisc string
	}{
		{"zip discriminates on the artefact",
			composeSpec{source: domain.AnalysisSourceModuleZip, artefact: "zip:h1:a"},
			domain.AnalysisSourceModuleZip, "zip:h1:a"},
		{"worktree discriminates on the tree digest",
			composeSpec{source: domain.AnalysisSourceWorktree, worktree: "sha256:tree-a"},
			domain.AnalysisSourceWorktree, "sha256:tree-a"},
		{"an unrecorded source has no discriminator",
			composeSpec{artefact: "zip:h1:a"},
			domain.AnalysisSourceUnrecorded, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			src, disc := domain.RecordAnalysisSource(composeRecord(t, tc.spec))
			if src != tc.wantSrc || disc != tc.wantDisc {
				t.Fatalf("RecordAnalysisSource = (%q, %q), want (%q, %q)", src, disc, tc.wantSrc, tc.wantDisc)
			}
		})
	}
}

// TestAnalysisSource_StringNamesTheZeroValue: an empty source rendered as an
// empty string reads to an operator as an absence of source rather than as a
// record that did not say.
func TestAnalysisSource_StringNamesTheZeroValue(t *testing.T) {
	t.Parallel()
	if got := domain.AnalysisSourceUnrecorded.String(); got != "not recorded" {
		t.Errorf("zero value renders %q, want %q", got, "not recorded")
	}
	if got := domain.AnalysisSourceModuleZip.String(); got != "zip" {
		t.Errorf("zip renders %q", got)
	}
}

// TestCompose_LegacyRecordDoesNotConflictWithTheSourceItPredates is the
// regression: two records describing an IDENTICAL graph, differing only in that
// one predates the analysis-source field, must load.
//
// Measured on a working store — github.com/golang-jwt/jwt/v4@v4.5.1 at pipeline
// 0.3.0 held exactly this pair. A full diff of both records' contents showed the
// same 822 nodes, the same 1579 edges and the same BUILT_WITH_BODIES
// completeness; the only substantive difference was the absent field. The
// comparison hashed that field, so the two disagreed on the graph digest and the
// read refused the graph, which made every reachability query against the
// coordinate fail.
func TestCompose_LegacyRecordDoesNotConflictWithTheSourceItPredates(t *testing.T) {
	t.Parallel()
	legacy := composeRecord(t, composeSpec{
		artefact:     "zip:h1:a",
		completeness: domain.CompletenessBuiltWithBodies, symbol: "Same",
		extractedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	named := composeRecord(t, composeSpec{
		source: domain.AnalysisSourceModuleZip, artefact: "zip:h1:a",
		completeness: domain.CompletenessBuiltWithBodies, symbol: "Same",
		extractedAt: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
	})
	if legacy.ContentHash == named.ContentHash {
		t.Fatal("the two records seal to one hash, so this test would pass without exercising the comparison")
	}

	got, err := domain.Compose([]domain.CallGraphRecord{legacy, named}, domain.ComposeRequest{})
	if err != nil {
		t.Fatalf("Compose refused two records describing the same graph: %v", err)
	}
	// Recency is the last tiebreaker and both sit on the same rung, so the record
	// that names its source is the one served.
	if got.ContentHash != named.ContentHash {
		t.Errorf("served %q, want the later record %q", got.ContentHash, named.ContentHash)
	}
}

// TestCompose_LegacyRecordStillConflictsOnAMeasuredDisagreement is the other
// direction, and it is the one that keeps the narrowing honest.
//
// Resolving an absent analysis source must not make two records agree about
// anything they actually measured. Same coordinate, same completeness, same
// artefact — different graphs. That is non-determinism in the analyser, it was a
// conflict before, and it must fail closed still.
func TestCompose_LegacyRecordStillConflictsOnAMeasuredDisagreement(t *testing.T) {
	t.Parallel()
	legacy := composeRecord(t, composeSpec{
		artefact:     "zip:h1:a",
		completeness: domain.CompletenessBuiltWithBodies, symbol: "Foo",
		extractedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	named := composeRecord(t, composeSpec{
		source: domain.AnalysisSourceModuleZip, artefact: "zip:h1:a",
		completeness: domain.CompletenessBuiltWithBodies, symbol: "Bar",
		extractedAt: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
	})

	_, err := domain.Compose([]domain.CallGraphRecord{legacy, named}, domain.ComposeRequest{})
	var conflict domain.CallGraphConflict
	if !errors.As(err, &conflict) {
		t.Fatalf("two records disagreeing about the graph composed to an answer: err=%v", err)
	}
	if conflict.Field != "call_graph" {
		t.Errorf("conflict field %q, want call_graph", conflict.Field)
	}
}

// TestGraphDigest_ResolvesAnAbsentSourceToTheOneItPredates pins that absence is
// resolved to a source this domain already defines, chosen from the coordinate,
// rather than collapsed to a single value or represented by an invented one.
//
// A pinned version was fetched, so a graph built for it before the field existed
// was built from a module zip. The synthetic local version is never fetched, so a
// graph built for it was built from a working tree. Mapping both to one value
// would make a legacy local record compare equal to a zip record of the same
// graph, which are answers about different bytes.
func TestGraphDigest_ResolvesAnAbsentSourceToTheOneItPredates(t *testing.T) {
	t.Parallel()
	pinnedLegacy := composeRecord(t, composeSpec{artefact: "zip:h1:a", completeness: domain.CompletenessBuiltWithBodies})
	pinnedZip := composeRecord(t, composeSpec{
		source: domain.AnalysisSourceModuleZip, artefact: "zip:h1:a",
		completeness: domain.CompletenessBuiltWithBodies,
	})
	if domain.GraphDigest(pinnedLegacy) != domain.GraphDigest(pinnedZip) {
		t.Error("a legacy record at a pinned version did not ladder with the module-zip record it predates")
	}

	localLegacy := composeRecord(t, composeSpec{
		version: coordinate.LocalVersion, worktree: "sha256:tree",
		completeness: domain.CompletenessBuiltWithBodies,
	})
	localTree := composeRecord(t, composeSpec{
		version: coordinate.LocalVersion, source: domain.AnalysisSourceWorktree, worktree: "sha256:tree",
		completeness: domain.CompletenessBuiltWithBodies,
	})
	if domain.GraphDigest(localLegacy) != domain.GraphDigest(localTree) {
		t.Error("a legacy record at the local version did not ladder with the worktree record it predates")
	}

	localZip := localTree
	localZip.AnalysisSource = domain.AnalysisSourceModuleZip
	if domain.GraphDigest(localLegacy) == domain.GraphDigest(localZip) {
		t.Error("an absent source was collapsed to one value rather than resolved from the coordinate")
	}
}
