package application_test

import (
	"context"
	"errors"
	"testing"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/license/application"
	"github.com/eitanity/kanonarion/internal/license/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// -- fakes --

type compatFakeLicenseStore struct {
	records map[string]domain.LicenseRecord // key = path@version
}

func (s *compatFakeLicenseStore) GetLicenseRecord(_ context.Context, coord fetchdomain.ModuleCoordinate, _ string) (domain.LicenseRecord, bool, error) {
	key := coord.Path + "@" + coord.Version
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

func makeCoord(path, version string) fetchdomain.ModuleCoordinate {
	return fetchdomain.ModuleCoordinate{Path: path, Version: version}
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
	_, err := uc.CheckCompatibilityForWalk(context.Background(), "missing-walk", makeCoord("example.com/root", "v1.0.0"), "Apache-2.0")
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
	report, err := uc.CheckCompatibilityForWalk(context.Background(), "walk-1", root, "Apache-2.0")
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
	report, err := uc.CheckCompatibilityForWalk(context.Background(), "walk-2", root, "Apache-2.0")
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
	report, err := uc.CheckCompatibilityForWalk(context.Background(), "walk-3", root, "Apache-2.0")
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
	if c.ModulePath != unextracted.Path {
		t.Errorf("conflict module = %q, want %q", c.ModulePath, unextracted.Path)
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
	report, err := uc.CheckCompatibilityForWalk(context.Background(), "walk-5", root, "Apache-2.0")
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
	if gplConflict.ModulePath != dep.Path {
		t.Errorf("conflict module = %q, want %q", gplConflict.ModulePath, dep.Path)
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
	report, err := uc.CheckCompatibilityForWalk(context.Background(), "walk-6", root, "Apache-2.0")
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
	report, err := uc.CheckCompatibilityForWalk(context.Background(), "walk-7", root, "Apache-2.0")
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
	report, err := uc.CheckCompatibilityForWalk(context.Background(), "walk-4", root, "Apache-2.0")
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
	root := makeCoord("example.com/project", fetchdomain.LocalVersion)
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
		root.Path + "@" + root.Version: {
			Coordinate:  root,
			Role:        domain.LicenseRoleRootDeclaration,
			Expression:  "Apache-2.0",
			PrimarySPDX: "Apache-2.0",
		},
		dep.Path + "@" + dep.Version: {
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
	report, err := uc.CheckCompatibilityForWalk(context.Background(), "walk-1", root, "")
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
	root := makeCoord("example.com/project", fetchdomain.LocalVersion)
	uc := application.NewCheckCompatibilityUseCase(
		&compatFakeLicenseStore{},
		&compatFakeWalkStore{},
	)
	_, err := uc.CheckCompatibilityForWalk(context.Background(), "walk-1", root, "")
	if !errors.Is(err, application.ErrRootLicenceNotAnalysed) {
		t.Fatalf("expected ErrRootLicenceNotAnalysed, got %v", err)
	}
}

// A proprietary root resolves to a record with no SPDX identity. That record
// is valid, but it cannot serve as an implicit SPDX target: the caller must
// pass --target explicitly.
func TestCheckCompatibilityForWalk_EmptyTargetWithUnclassifiedRootErrs(t *testing.T) {
	t.Parallel()
	root := makeCoord("example.com/project", fetchdomain.LocalVersion)
	licStore := &compatFakeLicenseStore{records: map[string]domain.LicenseRecord{
		root.Path + "@" + root.Version: {
			Coordinate:    root,
			Role:          domain.LicenseRoleRootDeclaration,
			OverallStatus: domain.LicenseStatusUnclassified,
		},
	}}
	uc := application.NewCheckCompatibilityUseCase(licStore, &compatFakeWalkStore{})
	_, err := uc.CheckCompatibilityForWalk(context.Background(), "walk-1", root, "")
	if !errors.Is(err, application.ErrRootLicenceNoSPDX) {
		t.Fatalf("expected ErrRootLicenceNoSPDX, got %v", err)
	}
}
