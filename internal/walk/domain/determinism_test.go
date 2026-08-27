package domain_test

import (
	"math/rand"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	domain3 "github.com/eitanity/kanonarion/internal/walk/domain"
)

// determinismShuffles is how many independent input orders this guard puts
// through the canonical form. A comparator that is not a total order decides a
// tied pair by whatever the sort happened to do with the input order, so the
// guard has to supply many input orders; one or two would pass by luck.
const determinismShuffles = 50

// makeTiedWalkRecord builds a WalkRecord whose graph holds two DISTINCT nodes
// on one coordinate and two DISTINCT edges between one pair of coordinates.
// Both are reachable: a replace directive gives one selected coordinate two
// origins, and two requirements on one dependency give one edge two constraint
// versions.
func makeTiedWalkRecord() domain3.WalkRecord {
	target := mustCoord("example.com/mod", "v1.0.0")
	dep := mustCoord("example.com/dep", "v1.2.0")
	return domain3.WalkRecord{
		SchemaVersion: domain3.WalkSchemaVersion,
		Ecosystem:     fetchdomain.EcosystemGo,
		ID:            "walk-1",
		Target:        target,
		Scope:         domain3.WalkScopeComplete,
		Graph: domain3.Graph{
			Target: target,
			Nodes: []domain3.GraphNode{
				{Coordinate: target, DirectDependency: true, ResolutionSource: domain3.ResolutionTarget},
				{
					Coordinate:         dep,
					ResolutionSource:   domain3.ResolutionReplace,
					OriginalCoordinate: mustCoord("example.com/old", "v0.9.0"),
				},
				{
					Coordinate:         dep,
					ResolutionSource:   domain3.ResolutionReplace,
					OriginalCoordinate: mustCoord("example.com/older", "v0.8.0"),
				},
			},
			Edges: []domain3.GraphEdge{
				{From: target, To: dep, ConstraintVersion: "v1.1.0"},
				{From: target, To: dep, ConstraintVersion: "v1.2.0"},
			},
		},
		PerNodeResults: map[coordinate.ModuleCoordinate]domain3.NodeResult{
			target: {Coordinate: target, Status: domain3.NodeSucceeded},
			dep:    {Coordinate: dep, Status: domain3.NodeSucceeded},
		},
		StartedAt:       fixedTime,
		CompletedAt:     fixedTime,
		OverallStatus:   domain3.WalkSucceeded,
		PipelineVersion: "0.1.0",
	}
}

func shuffleWalkRecord(rng *rand.Rand, r *domain3.WalkRecord) {
	n, e := r.Graph.Nodes, r.Graph.Edges
	rng.Shuffle(len(n), func(i, j int) { n[i], n[j] = n[j], n[i] })
	rng.Shuffle(len(e), func(i, j int) { e[i], e[j] = e[j], e[i] })
}

// TestWalkRecord_ContentHashIsIndependentOfInputOrder is the determinism guard
// for the walk record.
func TestWalkRecord_ContentHashIsIndependentOfInputOrder(t *testing.T) {
	t.Parallel()

	var h domain3.WalkRecordHasher
	var wantContent, wantIdentity string
	for i := range determinismShuffles {
		r := makeTiedWalkRecord()
		shuffleWalkRecord(rand.New(rand.NewSource(int64(i))), &r) /* #nosec G404 -- a determinism guard needs a REPRODUCIBLE shuffle: the seed is the test's evidence, not a secret */
		sealed, err := h.SetContentHash(r)
		if err != nil {
			t.Fatalf("shuffle %d: SetContentHash: %v", i, err)
		}
		identity, err := h.IdentityHash(r)
		if err != nil {
			t.Fatalf("shuffle %d: IdentityHash: %v", i, err)
		}
		if i == 0 {
			wantContent, wantIdentity = sealed.ContentHash, identity
			continue
		}
		if sealed.ContentHash != wantContent {
			t.Fatalf("shuffle %d: content hash %s, shuffle 0 gave %s: the canonical order is not a function of the record alone",
				i, sealed.ContentHash, wantContent)
		}
		if identity != wantIdentity {
			t.Fatalf("shuffle %d: identity hash %s, shuffle 0 gave %s: the walk's name is not a function of the walk alone",
				i, identity, wantIdentity)
		}
	}
}

// TestGraph_SortIsIndependentOfInputOrder checks the graph's own Sort agrees
// with the hasher on the canonical order.
func TestGraph_SortIsIndependentOfInputOrder(t *testing.T) {
	t.Parallel()

	var h domain3.WalkRecordHasher
	var want string
	for i := range determinismShuffles {
		r := makeTiedWalkRecord()
		shuffleWalkRecord(rand.New(rand.NewSource(int64(i))), &r) /* #nosec G404 -- a determinism guard needs a REPRODUCIBLE shuffle: the seed is the test's evidence, not a secret */
		r.Graph.Sort()
		got, err := h.Marshal(r)
		if err != nil {
			t.Fatalf("shuffle %d: Marshal: %v", i, err)
		}
		if i == 0 {
			want = string(got)
			continue
		}
		if string(got) != want {
			t.Fatalf("shuffle %d: Graph.Sort produced a different canonical rendering than shuffle 0", i)
		}
	}
}

// assertOrders checks that less decides a pair differing in exactly one field,
// in both directions, and reports an element equal to itself. Together over
// every field the wire shape carries, that is what "total order" means: no two
// DISTINCT elements compare equal, so the sort has no tie to resolve.
func assertOrders[T any](t *testing.T, key string, less func(a, b T) bool, lower, upper T) {
	t.Helper()
	if !less(lower, upper) {
		t.Errorf("%s: the comparator does not order two elements differing only in this field", key)
	}
	if less(upper, lower) {
		t.Errorf("%s: the comparator is not antisymmetric", key)
	}
	if less(lower, lower) {
		t.Errorf("%s: the comparator reports an element less than itself", key)
	}
}

// TestOrdering_IsKeyedOnEveryWireField exercises each comparator against every
// field the canonical shape carries.
func TestOrdering_IsKeyedOnEveryWireField(t *testing.T) {
	t.Parallel()

	a := mustCoord("example.com/a", "v1.0.0")
	b := mustCoord("example.com/b", "v1.0.0")
	a2 := mustCoord("example.com/a", "v2.0.0")

	assertOrders(t, "coordinate.path", domain3.CoordinateLess, a, b)
	assertOrders(t, "coordinate.version", domain3.CoordinateLess, a, a2)

	assertOrders(t, "node.coordinate", domain3.GraphNodeLess,
		domain3.GraphNode{Coordinate: a}, domain3.GraphNode{Coordinate: b})
	assertOrders(t, "node.original_coordinate", domain3.GraphNodeLess,
		domain3.GraphNode{OriginalCoordinate: a}, domain3.GraphNode{OriginalCoordinate: b})
	assertOrders(t, "node.resolution_source", domain3.GraphNodeLess,
		domain3.GraphNode{ResolutionSource: domain3.ResolutionMVS},
		domain3.GraphNode{ResolutionSource: domain3.ResolutionReplace})
	assertOrders(t, "node.direct_dependency", domain3.GraphNodeLess,
		domain3.GraphNode{}, domain3.GraphNode{DirectDependency: true})
	assertOrders(t, "node.retracted", domain3.GraphNodeLess,
		domain3.GraphNode{}, domain3.GraphNode{Retracted: true})
	assertOrders(t, "node.local_path", domain3.GraphNodeLess,
		domain3.GraphNode{LocalPath: "a"}, domain3.GraphNode{LocalPath: "b"})
	assertOrders(t, "node.error_detail", domain3.GraphNodeLess,
		domain3.GraphNode{ErrorDetail: "a"}, domain3.GraphNode{ErrorDetail: "b"})
	assertOrders(t, "node.digests.sha256", domain3.GraphNodeLess,
		domain3.GraphNode{Digests: fetchdomain.ArtifactDigests{SHA256: "a"}},
		domain3.GraphNode{Digests: fetchdomain.ArtifactDigests{SHA256: "b"}})
	assertOrders(t, "node.digests.sha384", domain3.GraphNodeLess,
		domain3.GraphNode{Digests: fetchdomain.ArtifactDigests{SHA384: "a"}},
		domain3.GraphNode{Digests: fetchdomain.ArtifactDigests{SHA384: "b"}})
	assertOrders(t, "node.digests.sha512", domain3.GraphNodeLess,
		domain3.GraphNode{Digests: fetchdomain.ArtifactDigests{SHA512: "a"}},
		domain3.GraphNode{Digests: fetchdomain.ArtifactDigests{SHA512: "b"}})

	// The stdlib custody block: absent sorts before present, then field by
	// field. At most one node in a walk carries it, so these branches decide
	// nothing today and are keyed so that they never decide nothing silently.
	withStdlib := func(f domain3.StdlibFacts) domain3.GraphNode {
		return domain3.GraphNode{Stdlib: &f}
	}
	assertOrders(t, "node.stdlib absent before present", domain3.GraphNodeLess,
		domain3.GraphNode{}, withStdlib(domain3.StdlibFacts{}))
	assertOrders(t, "node.stdlib.license_spdx", domain3.GraphNodeLess,
		withStdlib(domain3.StdlibFacts{LicenseSPDX: "a"}), withStdlib(domain3.StdlibFacts{LicenseSPDX: "b"}))
	assertOrders(t, "node.stdlib.verification_status", domain3.GraphNodeLess,
		withStdlib(domain3.StdlibFacts{VerificationStatus: "a"}), withStdlib(domain3.StdlibFacts{VerificationStatus: "b"}))
	assertOrders(t, "node.stdlib.verification_detail", domain3.GraphNodeLess,
		withStdlib(domain3.StdlibFacts{VerificationDetail: "a"}), withStdlib(domain3.StdlibFacts{VerificationDetail: "b"}))
	assertOrders(t, "node.stdlib.published_sha256", domain3.GraphNodeLess,
		withStdlib(domain3.StdlibFacts{PublishedSHA256: "a"}), withStdlib(domain3.StdlibFacts{PublishedSHA256: "b"}))
	assertOrders(t, "node.stdlib.source_url", domain3.GraphNodeLess,
		withStdlib(domain3.StdlibFacts{SourceURL: "a"}), withStdlib(domain3.StdlibFacts{SourceURL: "b"}))
	assertOrders(t, "node.stdlib.vcs_url", domain3.GraphNodeLess,
		withStdlib(domain3.StdlibFacts{VCSURL: "a"}), withStdlib(domain3.StdlibFacts{VCSURL: "b"}))
	assertOrders(t, "node.stdlib.vcs_ref", domain3.GraphNodeLess,
		withStdlib(domain3.StdlibFacts{VCSRef: "a"}), withStdlib(domain3.StdlibFacts{VCSRef: "b"}))
	assertOrders(t, "node.stdlib.vcs_commit", domain3.GraphNodeLess,
		withStdlib(domain3.StdlibFacts{VCSCommit: "a"}), withStdlib(domain3.StdlibFacts{VCSCommit: "b"}))

	assertOrders(t, "edge.from", domain3.GraphEdgeLess,
		domain3.GraphEdge{From: a}, domain3.GraphEdge{From: b})
	assertOrders(t, "edge.to", domain3.GraphEdgeLess,
		domain3.GraphEdge{To: a}, domain3.GraphEdge{To: b})
	assertOrders(t, "edge.constraint_version", domain3.GraphEdgeLess,
		domain3.GraphEdge{ConstraintVersion: "v1.0.0"}, domain3.GraphEdge{ConstraintVersion: "v1.1.0"})
}
