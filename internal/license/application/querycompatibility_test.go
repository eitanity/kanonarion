package application_test

import (
	"context"
	"errors"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"

	"github.com/eitanity/kanonarion/internal/license/application"
	"github.com/eitanity/kanonarion/internal/license/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// -- fakes --

type compatFakeLicenseStore struct {
	records map[string]domain.LicenseRecord // key = path@version
}

func (s *compatFakeLicenseStore) GetLicenseRecord(_ context.Context, coord coordinate.ModuleCoordinate, _ string) (domain.LicenseRecord, bool, error) {
	key := coord.Path() + "@" + coord.Version()
	r, ok := s.records[key]
	return r, ok, nil
}

type compatFakeWalkStore struct {
	walk    walkdomain.WalkRecord
	walkErr error
}

func (s *compatFakeWalkStore) PutWalk(_ context.Context, _ walkdomain.WalkRecord) error {
	return nil
}

func (s *compatFakeWalkStore) GetWalk(_ context.Context, _ string) (walkdomain.WalkRecord, error) {
	return s.walk, s.walkErr
}

func (s *compatFakeWalkStore) ListWalks(_ context.Context, _ walkports.WalkFilter) ([]walkports.WalkSummary, error) {
	return nil, nil
}

var _ walkports.WalkStore = (*compatFakeWalkStore)(nil)

// -- tests --

func makeCoord(path, version string) coordinate.ModuleCoordinate {
	return coordinatetest.MustNew(path, version)
}

// TestCheckCompatibilityForWalk_WalkNotFound verifies the resolved-vs-zero
// pair required by a missing walk is an error, not an empty clean report.
func TestCheckCompatibilityForWalk_WalkNotFound(t *testing.T) {
	t.Parallel()
	walkErr := errors.New("walk not found")
	uc := application.NewCheckCompatibilityUseCase(
		&compatFakeLicenseStore{},
		&compatFakeWalkStore{walkErr: walkErr},
	)
	_, err := uc.CheckCompatibilityForWalk(context.Background(), "missing-walk", makeCoord("example.com/root", "v1.0.0"), "Apache-2.0", domain.NewLicenseOverrideSet(nil))
	if err == nil {
		t.Fatal("expected error for missing walk, got nil (absence of walk must not produce a clean report)")
	}
	if !errors.Is(err, walkErr) {
		t.Errorf("error does not wrap walk error: %v", err)
	}
}

// TestCheckCompatibilityForWalk_PermissiveClosureIsClean verifies that a
// closure with only permissive deps produces a clean report.
func TestCheckCompatibilityForWalk_PermissiveClosureIsClean(t *testing.T) {
	t.Parallel()
	root := makeCoord("example.com/root", "v1.0.0")
	depA := makeCoord("example.com/dep-a", "v1.0.0")
	depB := makeCoord("example.com/dep-b", "v2.0.0")

	walkStore := &compatFakeWalkStore{
		walk: walkdomain.WalkRecord{
			ID: "walk-1",
			Graph: walkdomain.Graph{
				Nodes: []walkdomain.GraphNode{
					{Coordinate: root},
					{Coordinate: depA},
					{Coordinate: depB},
				},
			},
		},
	}
	licStore := &compatFakeLicenseStore{
		records: map[string]domain.LicenseRecord{
			"example.com/dep-a@v1.0.0": {PrimarySPDX: "MIT"},
			"example.com/dep-b@v2.0.0": {PrimarySPDX: "BSD-3-Clause"},
		},
	}

	uc := application.NewCheckCompatibilityUseCase(licStore, walkStore)
	report, err := uc.CheckCompatibilityForWalk(context.Background(), "walk-1", root, "Apache-2.0", domain.NewLicenseOverrideSet(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !report.Clean {
		t.Errorf("permissive closure should be clean, got conflicts: %v", report.Conflicts)
	}
}

// TestCheckCompatibilityForWalk_GPLConflict verifies that a GPL dep
// produces an incompatible conflict in the report.
func TestCheckCompatibilityForWalk_GPLConflict(t *testing.T) {
	t.Parallel()
	root := makeCoord("example.com/root", "v1.0.0")
	gplDep := makeCoord("example.com/gpl-lib", "v1.0.0")

	walkStore := &compatFakeWalkStore{
		walk: walkdomain.WalkRecord{
			ID: "walk-2",
			Graph: walkdomain.Graph{
				Nodes: []walkdomain.GraphNode{
					{Coordinate: root},
					{Coordinate: gplDep},
				},
			},
		},
	}
	licStore := &compatFakeLicenseStore{
		records: map[string]domain.LicenseRecord{
			"example.com/gpl-lib@v1.0.0": {PrimarySPDX: "GPL-2.0-only"},
		},
	}

	uc := application.NewCheckCompatibilityUseCase(licStore, walkStore)
	report, err := uc.CheckCompatibilityForWalk(context.Background(), "walk-2", root, "Apache-2.0", domain.NewLicenseOverrideSet(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.Clean {
		t.Error("closure with GPL dep should not be clean")
	}
	if len(report.Conflicts) != 1 {
		t.Fatalf("expected 1 conflict, got %d", len(report.Conflicts))
	}
	if report.Conflicts[0].Verdict != domain.VerdictIncompatible {
		t.Errorf("conflict verdict = %s, want incompatible", report.Conflicts[0].Verdict)
	}
}

// TestCheckCompatibilityForWalk_UnextractedLicenseIsUnknown is the
// regression pair: a dep whose license record has not been extracted (absent from
// store) must produce VerdictUnknownPair, not VerdictCompatible or be silently
// omitted.
func TestCheckCompatibilityForWalk_UnextractedLicenseIsUnknown(t *testing.T) {
	t.Parallel()
	root := makeCoord("example.com/root", "v1.0.0")
	unextracted := makeCoord("example.com/no-record", "v1.0.0")

	walkStore := &compatFakeWalkStore{
		walk: walkdomain.WalkRecord{
			ID: "walk-3",
			Graph: walkdomain.Graph{
				Nodes: []walkdomain.GraphNode{
					{Coordinate: root},
					{Coordinate: unextracted},
				},
			},
		},
	}
	// No license record for unextracted dep.
	licStore := &compatFakeLicenseStore{records: map[string]domain.LicenseRecord{}}

	uc := application.NewCheckCompatibilityUseCase(licStore, walkStore)
	report, err := uc.CheckCompatibilityForWalk(context.Background(), "walk-3", root, "Apache-2.0", domain.NewLicenseOverrideSet(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.Clean {
		t.Error("closure with un-extracted dep must not be clean (absence-as-answer defect class)")
	}
	if len(report.Conflicts) != 1 {
		t.Fatalf("expected 1 conflict for un-extracted dep, got %d", len(report.Conflicts))
	}
	c := report.Conflicts[0]
	if c.Verdict != domain.VerdictUnknownPair {
		t.Errorf("un-extracted dep verdict = %s, want unknown_pair", c.Verdict)
	}
	if c.ModulePath != unextracted.Path() {
		t.Errorf("conflict module = %q, want %q", c.ModulePath, unextracted.Path())
	}
}

// TestCheckCompatibilityForWalk_EmbeddedGPLConflict verifies that a dep
// whose EffectiveSet includes a GPL embedded component is flagged even when the
// module root is permissive.
func TestCheckCompatibilityForWalk_EmbeddedGPLConflict(t *testing.T) {
	t.Parallel()
	root := makeCoord("example.com/root", "v1.0.0")
	dep := makeCoord("example.com/bundle", "v1.0.0")

	walkStore := &compatFakeWalkStore{
		walk: walkdomain.WalkRecord{
			ID: "walk-5",
			Graph: walkdomain.Graph{
				Nodes: []walkdomain.GraphNode{
					{Coordinate: root},
					{Coordinate: dep},
				},
			},
		},
	}
	licStore := &compatFakeLicenseStore{
		records: map[string]domain.LicenseRecord{
			"example.com/bundle@v1.0.0": {
				PrimarySPDX: "MIT",
				EffectiveSet: domain.EffectiveLicenseSet{
					RootSPDXs: []string{"MIT"},
					Components: []domain.EmbeddedComponent{
						{PathPrefix: "vendor/gpl-lib", SPDXs: []string{"GPL-2.0-only"}},
					},
					AllSPDXs: []string{"GPL-2.0-only", "MIT"},
				},
			},
		},
	}

	uc := application.NewCheckCompatibilityUseCase(licStore, walkStore)
	report, err := uc.CheckCompatibilityForWalk(context.Background(), "walk-5", root, "Apache-2.0", domain.NewLicenseOverrideSet(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.Clean {
		t.Error("bundle with embedded GPL component must not be clean")
	}
	// Expect one conflict: GPL-2.0-only. MIT is compatible and must not conflict.
	var gplConflict *domain.CompatibilityConflict
	for i := range report.Conflicts {
		if report.Conflicts[i].DepSPDX == "GPL-2.0-only" {
			gplConflict = &report.Conflicts[i]
		}
	}
	if gplConflict == nil {
		t.Fatalf("expected a GPL-2.0-only conflict, got: %v", report.Conflicts)
	}
	if gplConflict.ModulePath != dep.Path() {
		t.Errorf("conflict module = %q, want %q", gplConflict.ModulePath, dep.Path())
	}
}

// TestCheckCompatibilityForWalk_ExpressionFallback verifies that when
// EffectiveSet is empty but Expression is set, resolveEffectiveSPDXs falls
// back to the Expression field.
func TestCheckCompatibilityForWalk_ExpressionFallback(t *testing.T) {
	t.Parallel()
	root := makeCoord("example.com/root", "v1.0.0")
	dep := makeCoord("example.com/expr-dep", "v1.0.0")

	walkStore := &compatFakeWalkStore{
		walk: walkdomain.WalkRecord{
			ID: "walk-6",
			Graph: walkdomain.Graph{
				Nodes: []walkdomain.GraphNode{
					{Coordinate: root},
					{Coordinate: dep},
				},
			},
		},
	}
	licStore := &compatFakeLicenseStore{
		records: map[string]domain.LicenseRecord{
			// Expression set, EffectiveSet empty — should fall back to Expression.
			"example.com/expr-dep@v1.0.0": {Expression: "MIT"},
		},
	}

	uc := application.NewCheckCompatibilityUseCase(licStore, walkStore)
	report, err := uc.CheckCompatibilityForWalk(context.Background(), "walk-6", root, "Apache-2.0", domain.NewLicenseOverrideSet(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !report.Clean {
		t.Errorf("MIT via Expression fallback should be clean, got conflicts: %v", report.Conflicts)
	}
}

// TestCheckCompatibilityForWalk_EmptyRecord verifies that a record with
// no EffectiveSet, Expression, or PrimarySPDX produces VerdictUnknownPair.
func TestCheckCompatibilityForWalk_EmptyRecord(t *testing.T) {
	t.Parallel()
	root := makeCoord("example.com/root", "v1.0.0")
	dep := makeCoord("example.com/empty-dep", "v1.0.0")

	walkStore := &compatFakeWalkStore{
		walk: walkdomain.WalkRecord{
			ID: "walk-7",
			Graph: walkdomain.Graph{
				Nodes: []walkdomain.GraphNode{
					{Coordinate: root},
					{Coordinate: dep},
				},
			},
		},
	}
	licStore := &compatFakeLicenseStore{
		records: map[string]domain.LicenseRecord{
			// Record exists but has no license info — should produce VerdictUnknownPair.
			"example.com/empty-dep@v1.0.0": {},
		},
	}

	uc := application.NewCheckCompatibilityUseCase(licStore, walkStore)
	report, err := uc.CheckCompatibilityForWalk(context.Background(), "walk-7", root, "Apache-2.0", domain.NewLicenseOverrideSet(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.Clean {
		t.Error("empty record must not be clean")
	}
	if len(report.Conflicts) != 1 || report.Conflicts[0].Verdict != domain.VerdictUnknownPair {
		t.Errorf("expected 1 VerdictUnknownPair, got: %v", report.Conflicts)
	}
}

// TestCheckCompatibilityForWalk_DeduplicatesWalkNodes verifies that
// duplicate nodes (a module appearing at multiple walk depths) are deduplicated
// and produce a single conflict, not one per occurrence.
func TestCheckCompatibilityForWalk_DeduplicatesWalkNodes(t *testing.T) {
	t.Parallel()
	root := makeCoord("example.com/root", "v1.0.0")
	dep := makeCoord("example.com/gpl-lib", "v1.0.0")

	walkStore := &compatFakeWalkStore{
		walk: walkdomain.WalkRecord{
			ID: "walk-4",
			Graph: walkdomain.Graph{
				Nodes: []walkdomain.GraphNode{
					{Coordinate: root},
					{Coordinate: dep},
					{Coordinate: dep}, // duplicate
				},
			},
		},
	}
	licStore := &compatFakeLicenseStore{
		records: map[string]domain.LicenseRecord{
			"example.com/gpl-lib@v1.0.0": {PrimarySPDX: "GPL-3.0-only"},
		},
	}

	uc := application.NewCheckCompatibilityUseCase(licStore, walkStore)
	report, err := uc.CheckCompatibilityForWalk(context.Background(), "walk-4", root, "Apache-2.0", domain.NewLicenseOverrideSet(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.Conflicts) != 1 {
		t.Errorf("duplicate walk node should produce 1 conflict, got %d", len(report.Conflicts))
	}
}

// An empty target adopts the root's own analysed licence record (its declared
// outbound licence) as the implicit compatibility target.
func TestCheckCompatibilityForWalk_EmptyTargetAdoptsRootLicence(t *testing.T) {
	t.Parallel()
	root := makeCoord("example.com/project", coordinate.LocalVersion)
	dep := makeCoord("example.com/dep", "v1.0.0")

	walkStore := &compatFakeWalkStore{
		walk: walkdomain.WalkRecord{
			ID: "walk-1",
			Graph: walkdomain.Graph{
				Target: root,
				Nodes: []walkdomain.GraphNode{
					{Coordinate: root},
					{Coordinate: dep},
				},
			},
		},
	}
	licStore := &compatFakeLicenseStore{records: map[string]domain.LicenseRecord{
		root.Path() + "@" + root.Version(): {
			Coordinate:  root,
			Role:        domain.LicenseRoleRootDeclaration,
			Expression:  "Apache-2.0",
			PrimarySPDX: "Apache-2.0",
		},
		dep.Path() + "@" + dep.Version(): {
			Coordinate:  dep,
			Expression:  "MIT",
			PrimarySPDX: "MIT",
			EffectiveSet: domain.EffectiveLicenseSet{
				RootSPDXs: []string{"MIT"},
				AllSPDXs:  []string{"MIT"},
			},
		},
	}}

	uc := application.NewCheckCompatibilityUseCase(licStore, walkStore)
	report, err := uc.CheckCompatibilityForWalk(context.Background(), "walk-1", root, "", domain.NewLicenseOverrideSet(nil))
	if err != nil {
		t.Fatalf("CheckCompatibilityForWalk: %v", err)
	}
	if report.TargetSPDX != "Apache-2.0" {
		t.Errorf("TargetSPDX = %q, want the root's declared Apache-2.0", report.TargetSPDX)
	}
	if !report.Clean {
		t.Errorf("report not clean: %+v", report.Conflicts)
	}
}

// An empty target with no root licence record is the un-analysed case, not a
// zero result: it must fail with a recognisable error.
func TestCheckCompatibilityForWalk_EmptyTargetWithoutRootRecordErrs(t *testing.T) {
	t.Parallel()
	root := makeCoord("example.com/project", coordinate.LocalVersion)
	uc := application.NewCheckCompatibilityUseCase(
		&compatFakeLicenseStore{},
		&compatFakeWalkStore{},
	)
	_, err := uc.CheckCompatibilityForWalk(context.Background(), "walk-1", root, "", domain.NewLicenseOverrideSet(nil))
	if !errors.Is(err, application.ErrRootLicenceNotAnalysed) {
		t.Fatalf("expected ErrRootLicenceNotAnalysed, got %v", err)
	}
}

// A proprietary root resolves to a record with no SPDX identity. That record
// is valid, but it cannot serve as an implicit SPDX target: the caller must
// pass --target explicitly.
func TestCheckCompatibilityForWalk_EmptyTargetWithUnclassifiedRootErrs(t *testing.T) {
	t.Parallel()
	root := makeCoord("example.com/project", coordinate.LocalVersion)
	licStore := &compatFakeLicenseStore{records: map[string]domain.LicenseRecord{
		root.Path() + "@" + root.Version(): {
			Coordinate:    root,
			Role:          domain.LicenseRoleRootDeclaration,
			OverallStatus: domain.LicenseStatusUnclassified,
		},
	}}
	uc := application.NewCheckCompatibilityUseCase(licStore, &compatFakeWalkStore{})
	_, err := uc.CheckCompatibilityForWalk(context.Background(), "walk-1", root, "", domain.NewLicenseOverrideSet(nil))
	if !errors.Is(err, application.ErrRootLicenceNoSPDX) {
		t.Fatalf("expected ErrRootLicenceNoSPDX, got %v", err)
	}
}

// The standard library carries its licence on the graph node (extracted from
// the source tarball's LICENSE file) rather than in a fetched licence record.
// The closure check must read that fact, so the module a project cannot build
// without is not reported as undetermined — the one class of result the licence
// gate is built to block.
func TestCheckCompatibilityForWalk_StdlibLicenceComesFromNodeFacts(t *testing.T) {
	t.Parallel()
	root := makeCoord("example.com/root", coordinate.LocalVersion)
	stdlib := makeCoord(walkdomain.StdlibModulePath, "v1.26.5")

	walkStore := &compatFakeWalkStore{
		walk: walkdomain.WalkRecord{
			ID: "walk-stdlib",
			Graph: walkdomain.Graph{
				Nodes: []walkdomain.GraphNode{
					{Coordinate: root},
					{
						Coordinate:       stdlib,
						ResolutionSource: walkdomain.ResolutionStdlib,
						Stdlib:           &walkdomain.StdlibFacts{LicenseSPDX: "BSD-3-Clause"},
					},
				},
			},
		},
	}
	// No licence record exists for stdlib — it is never fetched through the
	// proxy, so the store lookup is exactly the thing that must not decide.
	licStore := &compatFakeLicenseStore{records: map[string]domain.LicenseRecord{}}

	uc := application.NewCheckCompatibilityUseCase(licStore, walkStore)
	report, err := uc.CheckCompatibilityForWalk(context.Background(), "walk-stdlib", root, "Apache-2.0", domain.NewLicenseOverrideSet(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !report.Clean {
		t.Fatalf("stdlib under Apache-2.0 must be clean, got conflicts: %+v", report.Conflicts)
	}
}

// A legacy or offline walk carries no stdlib facts. The licence is still known
// — the Go project publishes it — so the constant answers, and the node is
// still not reported as undetermined.
func TestCheckCompatibilityForWalk_StdlibWithoutFactsUsesKnownConstant(t *testing.T) {
	t.Parallel()
	root := makeCoord("example.com/root", coordinate.LocalVersion)
	stdlib := makeCoord(walkdomain.StdlibModulePath, "v1.26.5")

	walkStore := &compatFakeWalkStore{
		walk: walkdomain.WalkRecord{
			ID: "walk-stdlib-legacy",
			Graph: walkdomain.Graph{
				Nodes: []walkdomain.GraphNode{
					{Coordinate: root},
					{Coordinate: stdlib, ResolutionSource: walkdomain.ResolutionStdlib},
				},
			},
		},
	}
	licStore := &compatFakeLicenseStore{records: map[string]domain.LicenseRecord{}}

	uc := application.NewCheckCompatibilityUseCase(licStore, walkStore)
	report, err := uc.CheckCompatibilityForWalk(context.Background(), "walk-stdlib-legacy", root, "Apache-2.0", domain.NewLicenseOverrideSet(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !report.Clean {
		t.Fatalf("factless stdlib node must resolve via the known constant, got conflicts: %+v", report.Conflicts)
	}
}

// The stdlib carve-out must not widen: an ordinary module with no licence
// record is genuinely undetermined and keeps reporting as an unknown pair.
func TestCheckCompatibilityForWalk_StdlibResolutionDoesNotCoverThirdParty(t *testing.T) {
	t.Parallel()
	root := makeCoord("example.com/root", coordinate.LocalVersion)
	stdlib := makeCoord(walkdomain.StdlibModulePath, "v1.26.5")
	undetermined := makeCoord("github.com/dgryski/dgoogauth", "v0.0.0-20190221195224-5a805980a5f3")

	walkStore := &compatFakeWalkStore{
		walk: walkdomain.WalkRecord{
			ID: "walk-mixed",
			Graph: walkdomain.Graph{
				Nodes: []walkdomain.GraphNode{
					{Coordinate: root},
					{
						Coordinate:       stdlib,
						ResolutionSource: walkdomain.ResolutionStdlib,
						Stdlib:           &walkdomain.StdlibFacts{LicenseSPDX: "BSD-3-Clause"},
					},
					{Coordinate: undetermined},
				},
			},
		},
	}
	licStore := &compatFakeLicenseStore{records: map[string]domain.LicenseRecord{}}

	uc := application.NewCheckCompatibilityUseCase(licStore, walkStore)
	report, err := uc.CheckCompatibilityForWalk(context.Background(), "walk-mixed", root, "Apache-2.0", domain.NewLicenseOverrideSet(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.Conflicts) != 1 {
		t.Fatalf("expected exactly the third-party module to be unknown, got %+v", report.Conflicts)
	}
	c := report.Conflicts[0]
	if c.ModulePath != undetermined.Path() {
		t.Errorf("unknown pair names %s, want %s", c.ModulePath, undetermined.Path())
	}
	if c.Verdict != domain.VerdictUnknownPair {
		t.Errorf("verdict = %s, want unknown pair", c.Verdict)
	}
	if c.DepSPDX != "" {
		t.Errorf("undetermined module reported SPDX %q, want empty", c.DepSPDX)
	}
}

// TestCheckCompatibilityForWalk_DualLicenceIsElectableNotIncompatible guards
// that a dep whose record carries a disjunctive expression (a dual licence,
// e.g. cronexpr's Apache-2.0 OR GPL-3.0) is evaluated per election: the GPL
// arm alone must not turn an electable module into a false incompatibility.
func TestCheckCompatibilityForWalk_DualLicenceIsElectableNotIncompatible(t *testing.T) {
	t.Parallel()
	root := makeCoord("example.com/root", "v1.0.0")
	dual := makeCoord("example.com/dual", "v1.0.0")

	walkStore := &compatFakeWalkStore{
		walk: walkdomain.WalkRecord{
			ID: "walk-dual",
			Graph: walkdomain.Graph{
				Nodes: []walkdomain.GraphNode{
					{Coordinate: root},
					{Coordinate: dual},
				},
			},
		},
	}
	licStore := &compatFakeLicenseStore{
		records: map[string]domain.LicenseRecord{
			"example.com/dual@v1.0.0": {
				PrimarySPDX:   "GPL-3.0-only",
				Expression:    "Apache-2.0 OR GPL-3.0-only",
				OverallStatus: domain.LicenseStatusMultiple,
				EffectiveSet: domain.EffectiveLicenseSet{
					RootSPDXs: []string{"Apache-2.0", "GPL-3.0-only"},
					AllSPDXs:  []string{"Apache-2.0", "GPL-3.0-only"},
				},
			},
		},
	}

	uc := application.NewCheckCompatibilityUseCase(licStore, walkStore)
	report, err := uc.CheckCompatibilityForWalk(context.Background(), "walk-dual", root, "Apache-2.0", domain.NewLicenseOverrideSet(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.Clean {
		t.Fatal("pending election must not report clean")
	}
	if len(report.Conflicts) != 1 {
		t.Fatalf("conflicts = %d, want 1 (one elective entry, not one per arm)", len(report.Conflicts))
	}
	c := report.Conflicts[0]
	if c.Verdict != domain.VerdictElectable {
		t.Errorf("verdict = %v, want electable (not a hard incompatibility)", c.Verdict)
	}
	if len(c.ElectableArms) != 1 || c.ElectableArms[0] != "Apache-2.0" {
		t.Errorf("ElectableArms = %v, want [Apache-2.0]", c.ElectableArms)
	}
}

// TestCheckCompatibilityForWalk_OverrideRecordsTheElection guards that a
// license_overrides entry — the operator's recorded election — settles the
// electable verdict: the module is evaluated under the elected arm alone.
func TestCheckCompatibilityForWalk_OverrideRecordsTheElection(t *testing.T) {
	t.Parallel()
	root := makeCoord("example.com/root", "v1.0.0")
	dual := makeCoord("example.com/dual", "v1.0.0")

	walkStore := &compatFakeWalkStore{
		walk: walkdomain.WalkRecord{
			ID: "walk-dual",
			Graph: walkdomain.Graph{
				Nodes: []walkdomain.GraphNode{
					{Coordinate: root},
					{Coordinate: dual},
				},
			},
		},
	}
	licStore := &compatFakeLicenseStore{
		records: map[string]domain.LicenseRecord{
			"example.com/dual@v1.0.0": {
				PrimarySPDX:   "GPL-3.0-only",
				Expression:    "Apache-2.0 OR GPL-3.0-only",
				OverallStatus: domain.LicenseStatusMultiple,
			},
		},
	}
	overrides := domain.NewLicenseOverrideSet(map[string]string{
		"example.com/dual": "Apache-2.0",
	})

	uc := application.NewCheckCompatibilityUseCase(licStore, walkStore)
	report, err := uc.CheckCompatibilityForWalk(context.Background(), "walk-dual", root, "Apache-2.0", overrides)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !report.Clean {
		t.Errorf("recorded election should settle clean, got conflicts: %v", report.Conflicts)
	}
}

// TestCheckCompatibilityForWalk_ElectionDoesNotHideEmbeddedComponents guards
// that a root election never absorbs an embedded component's licence: the
// component's obligations apply regardless of which root arm is elected.
func TestCheckCompatibilityForWalk_ElectionDoesNotHideEmbeddedComponents(t *testing.T) {
	t.Parallel()
	root := makeCoord("example.com/root", "v1.0.0")
	dual := makeCoord("example.com/dual", "v1.0.0")

	walkStore := &compatFakeWalkStore{
		walk: walkdomain.WalkRecord{
			ID: "walk-dual",
			Graph: walkdomain.Graph{
				Nodes: []walkdomain.GraphNode{
					{Coordinate: root},
					{Coordinate: dual},
				},
			},
		},
	}
	licStore := &compatFakeLicenseStore{
		records: map[string]domain.LicenseRecord{
			"example.com/dual@v1.0.0": {
				PrimarySPDX:   "MIT",
				Expression:    "Apache-2.0 OR MIT",
				OverallStatus: domain.LicenseStatusMultiple,
				EffectiveSet: domain.EffectiveLicenseSet{
					RootSPDXs: []string{"Apache-2.0", "MIT"},
					Components: []domain.EmbeddedComponent{
						{PathPrefix: "third_party/gpl", SPDXs: []string{"GPL-3.0-only"}},
					},
					AllSPDXs: []string{"Apache-2.0", "GPL-3.0-only", "MIT"},
				},
			},
		},
	}

	uc := application.NewCheckCompatibilityUseCase(licStore, walkStore)
	report, err := uc.CheckCompatibilityForWalk(context.Background(), "walk-dual", root, "Apache-2.0", domain.NewLicenseOverrideSet(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.Clean {
		t.Fatal("the embedded GPL component must still conflict")
	}
	if len(report.Conflicts) != 1 {
		t.Fatalf("conflicts = %d, want 1 (the component; the all-compatible root election is settled)", len(report.Conflicts))
	}
	if report.Conflicts[0].DepSPDX != "GPL-3.0-only" {
		t.Errorf("conflict DepSPDX = %q, want the embedded component's GPL-3.0-only", report.Conflicts[0].DepSPDX)
	}
}
