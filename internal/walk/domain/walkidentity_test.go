package domain_test

import (
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	domain3 "github.com/eitanity/kanonarion/internal/walk/domain"
)

// identityOf is the identity hash of a record built from outcome, under the id,
// operator and timestamps given.
func identityOf(t testing.TB, id, operator string, outcome domain3.WalkOutcome) string {
	t.Helper()
	rec := domain3.NewWalkRecord(id, operator, "0.2.0",
		domain3.WalkScopeCode, domain3.WalkDepthFull, outcome, domain3.DefaultDepthPolicy(), "")
	h, err := domain3.WalkRecordHasher{}.IdentityHash(rec)
	if err != nil {
		t.Fatalf("IdentityHash: %v", err)
	}
	if h == "" {
		t.Fatal("IdentityHash returned the empty string, which names no analysis")
	}
	return h
}

// TestWalkIdentity_SurvivesTheRunScopedFields is the measurement behind the
// whole change. Two runs of an unchanged checkout differ in exactly these
// fields — the walk id, the three timestamps, the per-node fetch durations and
// cache flags, and the operator — and produced two content hashes, so nothing
// either run derived could be reused by the other.
func TestWalkIdentity_SurvivesTheRunScopedFields(t *testing.T) {
	first := buildOutcome(t)
	second := buildOutcome(t)

	// Everything a second run of the same tree moves.
	later := second.StartedAt.Add(17 * time.Minute)
	second.StartedAt = later
	second.CompletedAt = later.Add(3 * time.Second)
	second.Graph.ResolvedAt = later
	for coord, nr := range second.PerNodeResults {
		nr.DurationMs += 7
		nr.FromCache = !nr.FromCache
		second.PerNodeResults[coord] = nr
	}

	a := identityOf(t, "01ARZ3NDEKTSV4RRFFQ69G5FAV", "alice", first)
	b := identityOf(t, "01BX5ZZKBKACTAV9WEVGEMMVRZ", "bob", second)

	if a != b {
		t.Errorf("two runs of the same analysis have different identities:\n  %s\n  %s", a, b)
	}

	// The content hash must still tell them apart: it seals the record, and the
	// records genuinely differ. If this ever stops holding, the seal has stopped
	// covering the run.
	recA := domain3.NewWalkRecord("01ARZ3NDEKTSV4RRFFQ69G5FAV", "alice", "0.2.0",
		domain3.WalkScopeCode, domain3.WalkDepthFull, first, domain3.DefaultDepthPolicy(), "")
	recB := domain3.NewWalkRecord("01BX5ZZKBKACTAV9WEVGEMMVRZ", "bob", "0.2.0",
		domain3.WalkScopeCode, domain3.WalkDepthFull, second, domain3.DefaultDepthPolicy(), "")
	hasher := domain3.WalkRecordHasher{}
	recA, err := hasher.SetContentHash(recA)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	recB, err = hasher.SetContentHash(recB)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if recA.ContentHash == recB.ContentHash {
		t.Error("two different records share a content hash: the seal no longer covers the run")
	}
}

// TestWalkIdentity_ChangesWithTheModuleSet pins the other half: a walk that
// resolved something else is a different walk, and must not be served for one
// that did not.
func TestWalkIdentity_ChangesWithTheModuleSet(t *testing.T) {
	base := identityOf(t, "01ARZ3NDEKTSV4RRFFQ69G5FAV", "alice", buildOutcome(t))

	extra, err := coordinate.NewModuleCoordinate("github.com/example/added", "v1.4.0")
	if err != nil {
		t.Fatalf("coordinate: %v", err)
	}
	changed := buildOutcome(t)
	changed.Graph.Nodes = append(changed.Graph.Nodes, domain3.GraphNode{
		Coordinate:       extra,
		DirectDependency: true,
		ResolutionSource: domain3.ResolutionMVS,
	})

	if got := identityOf(t, "01ARZ3NDEKTSV4RRFFQ69G5FAV", "alice", changed); got == base {
		t.Errorf("adding a dependency did not change the walk identity: still %s", base)
	}
}

// TestWalkIdentity_ChangesWithAResolvedVersion is the case a coordinate set
// alone would miss: the same module at a different selected version.
func TestWalkIdentity_ChangesWithAResolvedVersion(t *testing.T) {
	base := identityOf(t, "01ARZ3NDEKTSV4RRFFQ69G5FAV", "alice", buildOutcome(t))

	bumped, err := coordinate.NewModuleCoordinate(depCoord.Path(), "v9.9.9")
	if err != nil {
		t.Fatalf("coordinate: %v", err)
	}
	changed := buildOutcome(t)
	for i, n := range changed.Graph.Nodes {
		if n.Coordinate == depCoord {
			changed.Graph.Nodes[i].Coordinate = bumped
		}
	}

	if got := identityOf(t, "01ARZ3NDEKTSV4RRFFQ69G5FAV", "alice", changed); got == base {
		t.Errorf("changing a resolved version did not change the walk identity: still %s", base)
	}
}

// TestWalkIdentity_ChangesWithANodeOutcome pins that a run which failed to fetch
// a module is not the same analysis as one that fetched it. Serving the failed
// walk for the successful run would report coverage that was never established.
func TestWalkIdentity_ChangesWithANodeOutcome(t *testing.T) {
	base := identityOf(t, "01ARZ3NDEKTSV4RRFFQ69G5FAV", "alice", buildOutcome(t))

	changed := buildOutcome(t)
	nr := changed.PerNodeResults[depCoord]
	nr.Status = domain3.NodeSucceeded
	nr.Error = nil
	changed.PerNodeResults[depCoord] = nr

	if got := identityOf(t, "01ARZ3NDEKTSV4RRFFQ69G5FAV", "alice", changed); got == base {
		t.Errorf("a node that stopped failing did not change the walk identity: still %s", base)
	}
}

// TestWalkIdentity_ChangesWithTheScope guards the reuse lookup's other key: the
// same project resolved under two dependency scopes is two analyses.
func TestWalkIdentity_ChangesWithTheScope(t *testing.T) {
	outcome := buildOutcome(t)
	hasher := domain3.WalkRecordHasher{}

	code := domain3.NewWalkRecord("01ARZ3NDEKTSV4RRFFQ69G5FAV", "alice", "0.2.0",
		domain3.WalkScopeCode, domain3.WalkDepthFull, outcome, domain3.DefaultDepthPolicy(), "")
	tool := domain3.NewWalkRecord("01ARZ3NDEKTSV4RRFFQ69G5FAV", "alice", "0.2.0",
		domain3.WalkScopeTool, domain3.WalkDepthFull, outcome, domain3.DefaultDepthPolicy(), "")

	a, err := hasher.IdentityHash(code)
	if err != nil {
		t.Fatalf("IdentityHash: %v", err)
	}
	b, err := hasher.IdentityHash(tool)
	if err != nil {
		t.Fatalf("IdentityHash: %v", err)
	}
	if a == b {
		t.Errorf("the code and tool scopes share a walk identity: %s", a)
	}
}

// TestWalkIdentity_IgnoresTheProjectDirectory keeps identity consistent with the
// seal on the one fact both exclude: where on a machine the walk was taken.
func TestWalkIdentity_IgnoresTheProjectDirectory(t *testing.T) {
	hasher := domain3.WalkRecordHasher{}
	outcome := buildOutcome(t)

	here := domain3.NewWalkRecord("01ARZ3NDEKTSV4RRFFQ69G5FAV", "alice", "0.2.0",
		domain3.WalkScopeCode, domain3.WalkDepthFull, outcome, domain3.DefaultDepthPolicy(), "")
	here.ProjectDir = "/home/alice/src/proj"
	there := domain3.NewWalkRecord("01ARZ3NDEKTSV4RRFFQ69G5FAV", "alice", "0.2.0",
		domain3.WalkScopeCode, domain3.WalkDepthFull, outcome, domain3.DefaultDepthPolicy(), "")
	there.ProjectDir = "/build/ci/proj"

	a, err := hasher.IdentityHash(here)
	if err != nil {
		t.Fatalf("IdentityHash: %v", err)
	}
	b, err := hasher.IdentityHash(there)
	if err != nil {
		t.Fatalf("IdentityHash: %v", err)
	}
	if a != b {
		t.Errorf("the project directory reached the walk identity:\n  %s\n  %s", a, b)
	}
}

// TestWalkIdentity_ChangesWithThePolicy pins that the parameters a walk ran
// under are part of what it is: a different depth policy resolves a different
// closure, and its record must not answer for one taken under another.
func TestWalkIdentity_ChangesWithThePolicy(t *testing.T) {
	hasher := domain3.WalkRecordHasher{}
	outcome := buildOutcome(t)

	base := domain3.NewWalkRecord("01ARZ3NDEKTSV4RRFFQ69G5FAV", "alice", "0.2.0",
		domain3.WalkScopeCode, domain3.WalkDepthFull, outcome, domain3.DefaultDepthPolicy(), "sha256:aaa")
	other := domain3.NewWalkRecord("01ARZ3NDEKTSV4RRFFQ69G5FAV", "alice", "0.2.0",
		domain3.WalkScopeCode, domain3.WalkDepthFull, outcome, domain3.DefaultDepthPolicy(), "sha256:bbb")

	a, err := hasher.IdentityHash(base)
	if err != nil {
		t.Fatalf("IdentityHash: %v", err)
	}
	b, err := hasher.IdentityHash(other)
	if err != nil {
		t.Fatalf("IdentityHash: %v", err)
	}
	if a == b {
		t.Errorf("two policies share a walk identity: %s", a)
	}
}
