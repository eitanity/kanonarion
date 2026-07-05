package domain_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	domain3 "github.com/eitanity/kanonarion/internal/walk/domain"
)

// fixtures for reuse across tests.
var (
	fixedTime = time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC)

	targetCoord = mustCoord("github.com/example/target", "v1.0.0")
	depCoord    = mustCoord("github.com/example/dep", "v2.3.0")

	sampleFactRecord = domain2.FactRecord{
		SchemaVersion:      "2",
		Ecosystem:          domain2.EcosystemGo,
		ModulePath:         "github.com/example/target",
		ModuleVersion:      "v1.0.0",
		ModuleHash:         "h1:abc",
		GoModHash:          "h1:def",
		VerificationStatus: "verified",
		FetchedAt:          fixedTime,
		PipelineVersion:    "0.2.0",
		ContentLocation:    "blobs/ab/abcdef",
		ContentHash:        "sha256:deadbeef",
	}
)

func mustCoord(path, version string) domain2.ModuleCoordinate {
	c, err := domain2.NewModuleCoordinate(path, version)
	if err != nil {
		panic(err)
	}
	return c
}

func buildOutcome() domain3.WalkOutcome {
	rec := sampleFactRecord
	graph := domain3.Graph{
		Target: targetCoord,
		Nodes: []domain3.GraphNode{
			{Coordinate: targetCoord, DirectDependency: false, ResolutionSource: domain3.ResolutionTarget},
			{Coordinate: depCoord, DirectDependency: true, ResolutionSource: domain3.ResolutionMVS},
		},
		Edges: []domain3.GraphEdge{
			{From: targetCoord, To: depCoord, ConstraintVersion: "v2.3.0"},
		},
		ResolvedAt:      fixedTime,
		PipelineVersion: "0.2.0",
	}

	return domain3.WalkOutcome{
		Target: targetCoord,
		Graph:  graph,
		PerNodeResults: map[domain2.ModuleCoordinate]domain3.NodeResult{
			targetCoord: {
				Coordinate:  targetCoord,
				FetchRecord: &rec,
				Status:      domain3.NodeSucceeded,
				FromCache:   false,
				DurationMs:  42,
			},
			depCoord: {
				Coordinate:  depCoord,
				FetchRecord: nil,
				Status:      domain3.NodeFetchFailed,
				Error:       &domain3.StoredError{Type: "fetch_failed", Message: "timeout"},
				DurationMs:  10,
			},
		},
		StartedAt:     fixedTime,
		CompletedAt:   fixedTime.Add(time.Second),
		OverallStatus: domain3.WalkPartial,
	}
}

func TestNewWalkRecord(t *testing.T) {
	outcome := buildOutcome()
	rec := domain3.NewWalkRecord("01ARZ3NDEKTSV4RRFFQ69G5FAV", "ci-bot", "0.2.0", domain3.WalkScopeCode, domain3.WalkDepthFull, outcome, domain3.DefaultDepthPolicy(), "")

	if rec.SchemaVersion != domain3.WalkSchemaVersion {
		t.Errorf("SchemaVersion = %q, want %q", rec.SchemaVersion, domain3.WalkSchemaVersion)
	}
	if rec.ID != "01ARZ3NDEKTSV4RRFFQ69G5FAV" {
		t.Errorf("ID = %q", rec.ID)
	}
	if rec.Operator != "ci-bot" {
		t.Errorf("Operator = %q", rec.Operator)
	}
	if rec.PipelineVersion != "0.2.0" {
		t.Errorf("PipelineVersion = %q", rec.PipelineVersion)
	}
	if rec.OverallStatus != domain3.WalkPartial {
		t.Errorf("OverallStatus = %v", rec.OverallStatus)
	}
	if rec.ContentHash != "" {
		t.Errorf("ContentHash must be empty before SetContentHash, got %q", rec.ContentHash)
	}
	if !rec.StartedAt.Equal(fixedTime) {
		t.Errorf("StartedAt = %v", rec.StartedAt)
	}
}

func TestWalkRecordHasher_SetAndVerify(t *testing.T) {
	hasher := domain3.WalkRecordHasher{}
	rec := domain3.NewWalkRecord("01ARZ3NDEKTSV4RRFFQ69G5FAV", "ci-bot", "0.2.0", domain3.WalkScopeCode, domain3.WalkDepthFull, buildOutcome(), domain3.DefaultDepthPolicy(), "")

	hashed, err := hasher.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if !strings.HasPrefix(hashed.ContentHash, "sha256:") {
		t.Fatalf("ContentHash = %q, want sha256: prefix", hashed.ContentHash)
	}

	if err := hasher.VerifyContentHash(hashed); err != nil {
		t.Fatalf("VerifyContentHash: %v", err)
	}
}

func TestWalkRecordHasher_Deterministic(t *testing.T) {
	hasher := domain3.WalkRecordHasher{}
	rec := domain3.NewWalkRecord("01ARZ3NDEKTSV4RRFFQ69G5FAV", "ci-bot", "0.2.0", domain3.WalkScopeCode, domain3.WalkDepthFull, buildOutcome(), domain3.DefaultDepthPolicy(), "")

	h1, err := hasher.SetContentHash(rec)
	if err != nil {
		t.Fatalf("first hash: %v", err)
	}
	h2, err := hasher.SetContentHash(rec)
	if err != nil {
		t.Fatalf("second hash: %v", err)
	}
	if h1.ContentHash != h2.ContentHash {
		t.Errorf("hashes differ: %q vs %q", h1.ContentHash, h2.ContentHash)
	}
}

func TestWalkRecordHasher_TamperDetected(t *testing.T) {
	hasher := domain3.WalkRecordHasher{}
	rec := domain3.NewWalkRecord("01ARZ3NDEKTSV4RRFFQ69G5FAV", "ci-bot", "0.2.0", domain3.WalkScopeCode, domain3.WalkDepthFull, buildOutcome(), domain3.DefaultDepthPolicy(), "")

	hashed, err := hasher.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}

	tampered := hashed
	tampered.Operator = "attacker"

	if err := hasher.VerifyContentHash(tampered); err == nil {
		t.Fatal("expected tamper detection but VerifyContentHash returned nil")
	}
}

func TestWalkRecordHasher_ContentHashZeroedBeforeHash(t *testing.T) {
	// Two records identical except one has a pre-set ContentHash. The computed
	// hash must be the same for both because ContentHash is zeroed before hashing.
	hasher := domain3.WalkRecordHasher{}
	base := domain3.NewWalkRecord("01ARZ3NDEKTSV4RRFFQ69G5FAV", "ci-bot", "0.2.0", domain3.WalkScopeCode, domain3.WalkDepthFull, buildOutcome(), domain3.DefaultDepthPolicy(), "")

	withPre := base
	withPre.ContentHash = "sha256:previousvalue"

	h1, err := hasher.SetContentHash(base)
	if err != nil {
		t.Fatalf("base hash: %v", err)
	}
	h2, err := hasher.SetContentHash(withPre)
	if err != nil {
		t.Fatalf("pre-set hash: %v", err)
	}
	if h1.ContentHash != h2.ContentHash {
		t.Errorf("ContentHash differs: %q vs %q — zeroing invariant violated", h1.ContentHash, h2.ContentHash)
	}
}

func TestWalkRecordHasher_MarshalRoundTrip(t *testing.T) {
	hasher := domain3.WalkRecordHasher{}
	rec, err := hasher.SetContentHash(
		domain3.NewWalkRecord("01ARZ3NDEKTSV4RRFFQ69G5FAV", "ci-bot", "0.2.0", domain3.WalkScopeCode, domain3.WalkDepthFull, buildOutcome(), domain3.DefaultDepthPolicy(), ""),
	)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}

	b, err := hasher.Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if len(b) == 0 {
		t.Fatal("Marshal returned empty bytes")
	}
	// ContentHash must appear in the marshalled output.
	if !strings.Contains(string(b), rec.ContentHash) {
		t.Errorf("marshalled JSON does not contain ContentHash %q", rec.ContentHash)
	}
}

func TestWalkRecord_EcosystemPresentAfterRoundTrip(t *testing.T) {
	hasher := domain3.WalkRecordHasher{}
	rec, err := hasher.SetContentHash(
		domain3.NewWalkRecord("01ARZ3NDEKTSV4RRFFQ69G5FAV", "ci-bot", "0.2.0", domain3.WalkScopeCode, domain3.WalkDepthFull, buildOutcome(), domain3.DefaultDepthPolicy(), ""),
	)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if rec.Ecosystem != domain2.EcosystemGo {
		t.Errorf("Ecosystem = %q, want %q", rec.Ecosystem, domain2.EcosystemGo)
	}

	data, err := hasher.Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !bytes.Contains(data, []byte(`"ecosystem":"go"`)) {
		t.Errorf("canonical JSON missing ecosystem field: %s", data)
	}

	back, err := hasher.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if back.Ecosystem != domain2.EcosystemGo {
		t.Errorf("Ecosystem after round-trip = %q, want %q", back.Ecosystem, domain2.EcosystemGo)
	}
}

func TestWalkRecord_RejectsForeignEcosystem(t *testing.T) {
	hasher := domain3.WalkRecordHasher{}
	rec, _ := hasher.SetContentHash(
		domain3.NewWalkRecord("01ARZ3NDEKTSV4RRFFQ69G5FAV", "ci-bot", "0.2.0", domain3.WalkScopeCode, domain3.WalkDepthFull, buildOutcome(), domain3.DefaultDepthPolicy(), ""),
	)
	rec.Ecosystem = "npm"
	data, err := hasher.Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if _, err := hasher.Unmarshal(data); !errors.Is(err, domain2.ErrUnsupportedEcosystem) {
		t.Errorf("expected ErrUnsupportedEcosystem, got %v", err)
	}
}

func TestWalkRecordHasher_NodeResultsOrdering(t *testing.T) {
	// Building the same outcome with nodes added in different order must produce
	// the same hash (PerNodeResults is a map; ordering must come from the hasher).
	hasher := domain3.WalkRecordHasher{}

	rec := domain2.FactRecord{
		SchemaVersion:      "2",
		Ecosystem:          domain2.EcosystemGo,
		ModulePath:         "github.com/example/target",
		ModuleVersion:      "v1.0.0",
		VerificationStatus: "verified",
		FetchedAt:          fixedTime,
		PipelineVersion:    "0.2.0",
		ContentHash:        "sha256:aabbcc",
	}

	makeOutcome := func(order1, order2 domain2.ModuleCoordinate) domain3.WalkOutcome {
		return domain3.WalkOutcome{
			Target:        targetCoord,
			Graph:         domain3.Graph{Target: targetCoord, ResolvedAt: fixedTime, PipelineVersion: "0.2.0"},
			StartedAt:     fixedTime,
			CompletedAt:   fixedTime.Add(time.Second),
			OverallStatus: domain3.WalkSucceeded,
			PerNodeResults: map[domain2.ModuleCoordinate]domain3.NodeResult{
				order1: {Coordinate: order1, FetchRecord: &rec, Status: domain3.NodeSucceeded},
				order2: {Coordinate: order2, FetchRecord: &rec, Status: domain3.NodeSucceeded},
			},
		}
	}

	extra := mustCoord("github.com/example/zzz", "v0.1.0")

	o1 := makeOutcome(targetCoord, extra)
	o2 := makeOutcome(extra, targetCoord)

	r1 := domain3.NewWalkRecord("AAAAAAAAAAAAAAAAAAAAAAAA", "bot", "0.2.0", domain3.WalkScopeCode, domain3.WalkDepthFull, o1, domain3.DefaultDepthPolicy(), "")
	r2 := domain3.NewWalkRecord("AAAAAAAAAAAAAAAAAAAAAAAA", "bot", "0.2.0", domain3.WalkScopeCode, domain3.WalkDepthFull, o2, domain3.DefaultDepthPolicy(), "")

	h1, err := hasher.SetContentHash(r1)
	if err != nil {
		t.Fatalf("hash r1: %v", err)
	}
	h2, err := hasher.SetContentHash(r2)
	if err != nil {
		t.Fatalf("hash r2: %v", err)
	}
	if h1.ContentHash != h2.ContentHash {
		t.Errorf("map ordering affected hash: %q vs %q", h1.ContentHash, h2.ContentHash)
	}
}

func TestWalkStatus_String(t *testing.T) {
	cases := []struct {
		s    domain3.WalkStatus
		want string
	}{
		{domain3.WalkSucceeded, "succeeded"},
		{domain3.WalkPartial, "partial"},
		{domain3.WalkFailed, "failed"},
		{domain3.WalkCancelled, "cancelled"},
		{domain3.WalkStatus(99), "WalkStatus(99)"},
	}
	for _, tc := range cases {
		if got := tc.s.String(); got != tc.want {
			t.Errorf("WalkStatus(%d).String() = %q, want %q", tc.s, got, tc.want)
		}
	}
}

func TestNodeStatus_String(t *testing.T) {
	cases := []struct {
		s    domain3.NodeStatus
		want string
	}{
		{domain3.NodeSucceeded, "succeeded"},
		{domain3.NodeFetchFailed, "fetch_failed"},
		{domain3.NodeInternalPanic, "internal_panic"},
		{domain3.NodeStatus(99), "NodeStatus(99)"},
	}
	for _, tc := range cases {
		if got := tc.s.String(); got != tc.want {
			t.Errorf("NodeStatus(%d).String() = %q, want %q", tc.s, got, tc.want)
		}
	}
}

func TestStoredError_Error(t *testing.T) {
	e := &domain3.StoredError{Type: "fetch_failed", Message: "timeout"}
	if got := e.Error(); got != "[fetch_failed] timeout" {
		t.Errorf("Error() = %q", got)
	}
	var nilErr *domain3.StoredError
	if got := nilErr.Error(); got != "" {
		t.Errorf("nil StoredError.Error() = %q, want empty", got)
	}
}

func TestWalkRecordHasher_Unmarshal_RoundTrip(t *testing.T) {
	hasher := domain3.WalkRecordHasher{}
	rec := domain3.NewWalkRecord("01ARZ3NDEKTSV4RRFFQ69G5FAV", "ci-bot", "0.2.0", domain3.WalkScopeCode, domain3.WalkDepthFull, buildOutcome(), domain3.DefaultDepthPolicy(), "")
	hashed, err := hasher.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}

	b, err := hasher.Marshal(hashed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	got, err := hasher.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.ID != hashed.ID {
		t.Errorf("ID: got %q, want %q", got.ID, hashed.ID)
	}
	if got.ContentHash != hashed.ContentHash {
		t.Errorf("ContentHash: got %q, want %q", got.ContentHash, hashed.ContentHash)
	}
	if got.Operator != hashed.Operator {
		t.Errorf("Operator: got %q, want %q", got.Operator, hashed.Operator)
	}
	if len(got.PerNodeResults) != len(hashed.PerNodeResults) {
		t.Errorf("PerNodeResults len: got %d, want %d", len(got.PerNodeResults), len(hashed.PerNodeResults))
	}
	if len(got.Graph.Nodes) != len(hashed.Graph.Nodes) {
		t.Errorf("Graph.Nodes len: got %d, want %d", len(got.Graph.Nodes), len(hashed.Graph.Nodes))
	}
	if len(got.Graph.Edges) != len(hashed.Graph.Edges) {
		t.Errorf("Graph.Edges len: got %d, want %d", len(got.Graph.Edges), len(hashed.Graph.Edges))
	}
}

// Regression: a walk whose target fetch failed has an empty graph
// (no Graph.Target). Such a record must still round-trip — previously Unmarshal
// rejected the empty graph target as "module path must not be empty", making
// every failed-target walk permanently unreadable.
func TestWalkRecordHasher_Unmarshal_FailedWalkEmptyGraphTarget(t *testing.T) {
	hasher := domain3.WalkRecordHasher{}
	outcome := domain3.WalkOutcome{
		Target:        targetCoord,
		Graph:         domain3.Graph{}, // zero value: no graph resolved
		StartedAt:     fixedTime,
		CompletedAt:   fixedTime.Add(time.Second),
		OverallStatus: domain3.WalkFailed,
		PerNodeResults: map[domain2.ModuleCoordinate]domain3.NodeResult{
			targetCoord: {
				Coordinate: targetCoord,
				Status:     domain3.NodeFetchFailed,
				Error:      &domain3.StoredError{Type: "fetch_failed", Message: "not found"},
			},
		},
	}
	rec := domain3.NewWalkRecord("01ARZ3NDEKTSV4RRFFQ69G5FAV", "ci-bot", "0.2.0", domain3.WalkScopeCode, domain3.WalkDepthFull, outcome, domain3.DefaultDepthPolicy(), "")
	hashed, err := hasher.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}

	b, err := hasher.Marshal(hashed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	got, err := hasher.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal of failed-walk record must succeed, got: %v", err)
	}
	if (got.Graph.Target != domain2.ModuleCoordinate{}) {
		t.Errorf("Graph.Target: got %+v, want zero coordinate", got.Graph.Target)
	}
	if got.OverallStatus != domain3.WalkFailed {
		t.Errorf("OverallStatus: got %v, want failed", got.OverallStatus)
	}
}

func TestWalkRecordHasher_Unmarshal_PreservesError(t *testing.T) {
	hasher := domain3.WalkRecordHasher{}
	rec := domain3.NewWalkRecord("01ARZ3NDEKTSV4RRFFQ69G5FAV", "bot", "0.2.0", domain3.WalkScopeCode, domain3.WalkDepthFull, buildOutcome(), domain3.DefaultDepthPolicy(), "")
	hashed, err := hasher.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}

	b, err := hasher.Marshal(hashed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := hasher.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	// The depCoord result has an error; ensure it round-trips.
	nodeResult, ok := got.PerNodeResults[depCoord]
	if !ok {
		t.Fatal("depCoord not found in PerNodeResults after unmarshal")
	}
	if nodeResult.Error == nil {
		t.Fatal("expected non-nil Error in depCoord result after unmarshal")
	}
	if nodeResult.Error.Type != "fetch_failed" {
		t.Errorf("Error.Type = %q, want fetch_failed", nodeResult.Error.Type)
	}
}

func TestWalkRecordHasher_Unmarshal_InvalidJSON(t *testing.T) {
	hasher := domain3.WalkRecordHasher{}
	_, err := hasher.Unmarshal([]byte(`not json`))
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

func TestWalkRecordHasher_MultiEdge_Sorting(t *testing.T) {
	hasher := domain3.WalkRecordHasher{}

	a := mustCoord("github.com/example/a", "v1.0.0")
	b := mustCoord("github.com/example/b", "v1.0.0")
	b2 := mustCoord("github.com/example/b", "v2.0.0")
	c := mustCoord("github.com/example/c", "v1.0.0")

	graph := domain3.Graph{
		Target: a,
		Nodes: []domain3.GraphNode{
			{Coordinate: a, ResolutionSource: domain3.ResolutionTarget},
			{Coordinate: b, ResolutionSource: domain3.ResolutionMVS, DirectDependency: true},
			{Coordinate: b2, ResolutionSource: domain3.ResolutionMVS},
			{Coordinate: c, ResolutionSource: domain3.ResolutionMVS, DirectDependency: true},
		},
		Edges: []domain3.GraphEdge{
			{From: a, To: c, ConstraintVersion: "v1.0.0"},
			{From: a, To: b, ConstraintVersion: "v1.0.0"},
			{From: b, To: b2, ConstraintVersion: "v1.5.0"},
		},
		ResolvedAt:      fixedTime,
		PipelineVersion: "0.2.0",
	}
	outcome := domain3.WalkOutcome{
		Target: a,
		Graph:  graph,
		PerNodeResults: map[domain2.ModuleCoordinate]domain3.NodeResult{
			a: {Coordinate: a, Status: domain3.NodeSucceeded},
			b: {Coordinate: b, Status: domain3.NodeSucceeded},
		},
		StartedAt:     fixedTime,
		CompletedAt:   fixedTime.Add(time.Second),
		OverallStatus: domain3.WalkSucceeded,
	}
	rec := domain3.NewWalkRecord("MULTI-EDGE-001", "bot", "0.2.0", domain3.WalkScopeCode, domain3.WalkDepthFull, outcome, domain3.DefaultDepthPolicy(), "")
	hashed, err := hasher.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if err := hasher.VerifyContentHash(hashed); err != nil {
		t.Fatalf("VerifyContentHash: %v", err)
	}

	rawBytes, err := hasher.Marshal(hashed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := hasher.Unmarshal(rawBytes)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(got.Graph.Edges) != 3 {
		t.Errorf("expected 3 edges, got %d", len(got.Graph.Edges))
	}
}

func TestWalkRecordHasher_Unmarshal_BadStartedAt(t *testing.T) {
	hasher := domain3.WalkRecordHasher{}
	raw := `{"schema_version":"1","id":"x","target":{"path":"example.com/a","version":"v1.0.0"},` +
		`"graph":{"edges":[],"has_local_replace":false,"nodes":[],"partial":false,"partial_reason":"",` +
		`"pipeline_version":"","resolved_at":"2025-01-01T00:00:00Z","target":{"path":"example.com/a","version":"v1.0.0"}},` +
		`"operator":"","overall_status":0,"per_node_results":[],"pipeline_version":"",` +
		`"started_at":"not-a-time","completed_at":"2025-01-01T00:00:00Z","content_hash":""}`
	_, err := hasher.Unmarshal([]byte(raw))
	if err == nil {
		t.Error("expected error for bad started_at, got nil")
	}
}

func TestWalkRecordHasher_Unmarshal_BadCompletedAt(t *testing.T) {
	hasher := domain3.WalkRecordHasher{}
	raw := `{"schema_version":"1","id":"x","target":{"path":"example.com/a","version":"v1.0.0"},` +
		`"graph":{"edges":[],"has_local_replace":false,"nodes":[],"partial":false,"partial_reason":"",` +
		`"pipeline_version":"","resolved_at":"2025-01-01T00:00:00Z","target":{"path":"example.com/a","version":"v1.0.0"}},` +
		`"operator":"","overall_status":0,"per_node_results":[],"pipeline_version":"",` +
		`"started_at":"2025-01-01T00:00:00Z","completed_at":"not-a-time","content_hash":""}`
	_, err := hasher.Unmarshal([]byte(raw))
	if err == nil {
		t.Error("expected error for bad completed_at, got nil")
	}
}

func TestWalkRecordHasher_Unmarshal_BadResolvedAt(t *testing.T) {
	hasher := domain3.WalkRecordHasher{}
	raw := `{"schema_version":"1","id":"x","target":{"path":"example.com/a","version":"v1.0.0"},` +
		`"graph":{"edges":[],"has_local_replace":false,"nodes":[],"partial":false,"partial_reason":"",` +
		`"pipeline_version":"","resolved_at":"not-a-time","target":{"path":"example.com/a","version":"v1.0.0"}},` +
		`"operator":"","overall_status":0,"per_node_results":[],"pipeline_version":"",` +
		`"started_at":"2025-01-01T00:00:00Z","completed_at":"2025-01-01T00:00:00Z","content_hash":""}`
	_, err := hasher.Unmarshal([]byte(raw))
	if err == nil {
		t.Error("expected error for bad resolved_at, got nil")
	}
}

func TestWalkRecordHasher_Unmarshal_BadTargetCoord(t *testing.T) {
	hasher := domain3.WalkRecordHasher{}
	// version is not valid semver
	raw := `{"schema_version":"1","id":"x","target":{"path":"example.com/a","version":"notasemver"},` +
		`"graph":{"edges":[],"has_local_replace":false,"nodes":[],"partial":false,"partial_reason":"",` +
		`"pipeline_version":"","resolved_at":"2025-01-01T00:00:00Z","target":{"path":"example.com/a","version":"v1.0.0"}},` +
		`"operator":"","overall_status":0,"per_node_results":[],"pipeline_version":"",` +
		`"started_at":"2025-01-01T00:00:00Z","completed_at":"2025-01-01T00:00:00Z","content_hash":""}`
	_, err := hasher.Unmarshal([]byte(raw))
	if err == nil {
		t.Error("expected error for bad target coordinate, got nil")
	}
}

func TestWalkRecordHasher_Unmarshal_BadNodeCoord(t *testing.T) {
	hasher := domain3.WalkRecordHasher{}
	raw := `{"schema_version":"1","id":"x","target":{"path":"example.com/a","version":"v1.0.0"},` +
		`"graph":{"edges":[],"has_local_replace":false,` +
		`"nodes":[{"coordinate":{"path":"example.com/b","version":"badver"},"direct_dependency":false,"error_detail":"","resolution_source":"mvs","retracted":false}],` +
		`"partial":false,"partial_reason":"","pipeline_version":"","resolved_at":"2025-01-01T00:00:00Z","target":{"path":"example.com/a","version":"v1.0.0"}},` +
		`"operator":"","overall_status":0,"per_node_results":[],"pipeline_version":"",` +
		`"started_at":"2025-01-01T00:00:00Z","completed_at":"2025-01-01T00:00:00Z","content_hash":""}`
	_, err := hasher.Unmarshal([]byte(raw))
	if err == nil {
		t.Error("expected error for bad node coordinate, got nil")
	}
}

func TestWalkRecordHasher_Unmarshal_BadEdgeFrom(t *testing.T) {
	hasher := domain3.WalkRecordHasher{}
	raw := `{"schema_version":"1","id":"x","target":{"path":"example.com/a","version":"v1.0.0"},` +
		`"graph":{"edges":[{"constraint_version":"v1.0.0","from":{"path":"example.com/a","version":"badver"},"to":{"path":"example.com/b","version":"v1.0.0"}}],` +
		`"has_local_replace":false,"nodes":[],"partial":false,"partial_reason":"","pipeline_version":"",` +
		`"resolved_at":"2025-01-01T00:00:00Z","target":{"path":"example.com/a","version":"v1.0.0"}},` +
		`"operator":"","overall_status":0,"per_node_results":[],"pipeline_version":"",` +
		`"started_at":"2025-01-01T00:00:00Z","completed_at":"2025-01-01T00:00:00Z","content_hash":""}`
	_, err := hasher.Unmarshal([]byte(raw))
	if err == nil {
		t.Error("expected error for bad edge from coordinate, got nil")
	}
}

func TestWalkRecordHasher_Unmarshal_BadEdgeTo(t *testing.T) {
	hasher := domain3.WalkRecordHasher{}
	raw := `{"schema_version":"1","id":"x","target":{"path":"example.com/a","version":"v1.0.0"},` +
		`"graph":{"edges":[{"constraint_version":"v1.0.0","from":{"path":"example.com/a","version":"v1.0.0"},"to":{"path":"example.com/b","version":"badver"}}],` +
		`"has_local_replace":false,"nodes":[],"partial":false,"partial_reason":"","pipeline_version":"",` +
		`"resolved_at":"2025-01-01T00:00:00Z","target":{"path":"example.com/a","version":"v1.0.0"}},` +
		`"operator":"","overall_status":0,"per_node_results":[],"pipeline_version":"",` +
		`"started_at":"2025-01-01T00:00:00Z","completed_at":"2025-01-01T00:00:00Z","content_hash":""}`
	_, err := hasher.Unmarshal([]byte(raw))
	if err == nil {
		t.Error("expected error for bad edge to coordinate, got nil")
	}
}

func TestWalkRecordHasher_Unmarshal_BadNodeResultCoord(t *testing.T) {
	hasher := domain3.WalkRecordHasher{}
	raw := `{"schema_version":"1","id":"x","target":{"path":"example.com/a","version":"v1.0.0"},` +
		`"graph":{"edges":[],"has_local_replace":false,"nodes":[],"partial":false,"partial_reason":"","pipeline_version":"",` +
		`"resolved_at":"2025-01-01T00:00:00Z","target":{"path":"example.com/a","version":"v1.0.0"}},` +
		`"operator":"","overall_status":0,` +
		`"per_node_results":[{"coordinate":{"path":"example.com/b","version":"badver"},"duration_ms":0,"error":null,"fetch_record":null,"from_cache":false,"status":0}],` +
		`"pipeline_version":"",` +
		`"started_at":"2025-01-01T00:00:00Z","completed_at":"2025-01-01T00:00:00Z","content_hash":""}`
	_, err := hasher.Unmarshal([]byte(raw))
	if err == nil {
		t.Error("expected error for bad per_node_results coordinate, got nil")
	}
}

func TestWalkRecordHasher_Unmarshal_BadFetchRecord(t *testing.T) {
	hasher := domain3.WalkRecordHasher{}
	// Craft a JSON where the fetch_record field is non-null but invalid JSON for a FactRecord
	raw := `{"schema_version":"1","id":"x","target":{"path":"example.com/a","version":"v1.0.0"},` +
		`"graph":{"edges":[],"has_local_replace":false,"nodes":[],"partial":false,"partial_reason":"","pipeline_version":"",` +
		`"resolved_at":"2025-01-01T00:00:00Z","target":{"path":"example.com/a","version":"v1.0.0"}},` +
		`"operator":"","overall_status":0,` +
		`"per_node_results":[{"coordinate":{"path":"example.com/a","version":"v1.0.0"},"duration_ms":0,"error":null,"fetch_record":{"fetched_at":"badtime"},"from_cache":false,"status":0}],` +
		`"pipeline_version":"",` +
		`"started_at":"2025-01-01T00:00:00Z","completed_at":"2025-01-01T00:00:00Z","content_hash":""}`
	_, err := hasher.Unmarshal([]byte(raw))
	if err == nil {
		t.Error("expected error for bad fetch_record, got nil")
	}
}

func TestWalkRecordHasher_EdgeSort_SameFromDifferentVersion(t *testing.T) {
	// Exercises the a.From.Version != b.From.Version branch in canonicalWalkEdges.
	hasher := domain3.WalkRecordHasher{}

	// Craft a fake graph with edges from same path but different versions.
	a1 := mustCoord("github.com/example/a", "v1.0.0")
	a2 := mustCoord("github.com/example/a", "v2.0.0")
	b := mustCoord("github.com/example/b", "v1.0.0")

	graph := domain3.Graph{
		Target: a1,
		Nodes: []domain3.GraphNode{
			{Coordinate: a1, ResolutionSource: domain3.ResolutionTarget},
		},
		Edges: []domain3.GraphEdge{
			{From: a2, To: b, ConstraintVersion: "v1.0.0"},
			{From: a1, To: b, ConstraintVersion: "v1.0.0"},
		},
		ResolvedAt:      fixedTime,
		PipelineVersion: "0.2.0",
	}
	outcome := domain3.WalkOutcome{
		Target: a1,
		Graph:  graph,
		PerNodeResults: map[domain2.ModuleCoordinate]domain3.NodeResult{
			a1: {Coordinate: a1, Status: domain3.NodeSucceeded},
		},
		StartedAt:     fixedTime,
		CompletedAt:   fixedTime.Add(time.Second),
		OverallStatus: domain3.WalkSucceeded,
	}
	rec := domain3.NewWalkRecord("EDGE-SORT-001", "bot", "0.2.0", domain3.WalkScopeCode, domain3.WalkDepthFull, outcome, domain3.DefaultDepthPolicy(), "")
	hashed, err := hasher.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}

	rawBytes, err := hasher.Marshal(hashed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := hasher.Unmarshal(rawBytes)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(got.Graph.Edges) != 2 {
		t.Errorf("expected 2 edges, got %d", len(got.Graph.Edges))
	}
}

func TestWalkRecordHasher_EdgeSort_SameFromSameToDiffVersion(t *testing.T) {
	// Exercises the a.To.Version != b.To.Version (final return) branch.
	hasher := domain3.WalkRecordHasher{}

	a := mustCoord("github.com/example/a", "v1.0.0")
	b1 := mustCoord("github.com/example/b", "v1.0.0")
	b2 := mustCoord("github.com/example/b", "v2.0.0")

	graph := domain3.Graph{
		Target: a,
		Nodes: []domain3.GraphNode{
			{Coordinate: a, ResolutionSource: domain3.ResolutionTarget},
		},
		Edges: []domain3.GraphEdge{
			{From: a, To: b2, ConstraintVersion: "v1.0.0"},
			{From: a, To: b1, ConstraintVersion: "v1.0.0"},
		},
		ResolvedAt:      fixedTime,
		PipelineVersion: "0.2.0",
	}
	outcome := domain3.WalkOutcome{
		Target: a,
		Graph:  graph,
		PerNodeResults: map[domain2.ModuleCoordinate]domain3.NodeResult{
			a: {Coordinate: a, Status: domain3.NodeSucceeded},
		},
		StartedAt:     fixedTime,
		CompletedAt:   fixedTime.Add(time.Second),
		OverallStatus: domain3.WalkSucceeded,
	}
	rec := domain3.NewWalkRecord("EDGE-SORT-002", "bot", "0.2.0", domain3.WalkScopeCode, domain3.WalkDepthFull, outcome, domain3.DefaultDepthPolicy(), "")
	hashed, err := hasher.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}

	rawBytes, err := hasher.Marshal(hashed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := hasher.Unmarshal(rawBytes)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(got.Graph.Edges) != 2 {
		t.Errorf("expected 2 edges, got %d", len(got.Graph.Edges))
	}
}

// a graph node carrying LocalPath + OriginalCoordinate (the
// representation of a local-path replace) must survive Marshal → Unmarshal
// without losing either field. This is the regression guard for the
// omitempty-pointer trick in canonicalWalkNode.
func TestWalkRecordHasher_LocalReplaceRoundTrip(t *testing.T) {
	hasher := domain3.WalkRecordHasher{}

	originalCoord := mustCoord("example.com/dep", "v1.0.0")
	graph := domain3.Graph{
		Target: targetCoord,
		Nodes: []domain3.GraphNode{
			{Coordinate: targetCoord, ResolutionSource: domain3.ResolutionTarget},
			{
				Coordinate:         originalCoord,
				DirectDependency:   true,
				ResolutionSource:   domain3.ResolutionLocalReplace,
				OriginalCoordinate: originalCoord,
				LocalPath:          "../local/dep",
			},
		},
		ResolvedAt:      fixedTime,
		PipelineVersion: "0.2.0",
		HasLocalReplace: true,
	}
	outcome := domain3.WalkOutcome{
		Target:        targetCoord,
		Graph:         graph,
		StartedAt:     fixedTime,
		CompletedAt:   fixedTime.Add(time.Second),
		OverallStatus: domain3.WalkSucceeded,
		PerNodeResults: map[domain2.ModuleCoordinate]domain3.NodeResult{
			targetCoord: {Coordinate: targetCoord, Status: domain3.NodeSucceeded},
			originalCoord: {
				Coordinate: originalCoord,
				Status:     domain3.NodeLocalReplace,
				Error:      &domain3.StoredError{Type: "local_replace", Message: "local replace at ../local/dep"},
			},
		},
	}

	rec := domain3.NewWalkRecord("01TESTREC000000000000000", "bot", "0.2.0", domain3.WalkScopeCode, domain3.WalkDepthFull, outcome, domain3.DefaultDepthPolicy(), "")
	hashed, err := hasher.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}

	bytes, err := hasher.Marshal(hashed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	round, err := domain3.WalkRecordHasher{}.Unmarshal(bytes)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	var depNode domain3.GraphNode
	for _, n := range round.Graph.Nodes {
		if n.Coordinate.Path == originalCoord.Path {
			depNode = n
		}
	}
	if depNode.ResolutionSource != domain3.ResolutionLocalReplace {
		t.Errorf("ResolutionSource after round-trip = %q, want local_replace", depNode.ResolutionSource)
	}
	if depNode.LocalPath != "../local/dep" {
		t.Errorf("LocalPath after round-trip = %q, want ../local/dep", depNode.LocalPath)
	}
	if depNode.OriginalCoordinate != originalCoord {
		t.Errorf("OriginalCoordinate after round-trip = %v, want %v", depNode.OriginalCoordinate, originalCoord)
	}

	// Re-hashing the round-tripped record yields the original ContentHash.
	rehashed, err := hasher.SetContentHash(round)
	if err != nil {
		t.Fatalf("SetContentHash after round-trip: %v", err)
	}
	if rehashed.ContentHash != hashed.ContentHash {
		t.Errorf("ContentHash drift after round-trip: %q vs %q", rehashed.ContentHash, hashed.ContentHash)
	}
}

// nodes without LocalPath / OriginalCoordinate must hash identically
// to pre- records. The new canonicalWalkNode fields are omitempty so
// every existing record on disk still verifies after upgrade.
func TestWalkRecordHasher_HashUnchangedWhenNewFieldsUnset(t *testing.T) {
	hasher := domain3.WalkRecordHasher{}

	rec := domain3.NewWalkRecord("01ARZ3NDEKTSV4RRFFQ69G5FAV", "ci-bot", "0.2.0", domain3.WalkScopeCode, domain3.WalkDepthFull, buildOutcome(), domain3.DefaultDepthPolicy(), "")
	hashed, err := hasher.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}

	// Re-marshal — the canonical form for a record whose nodes do not set
	// LocalPath or OriginalCoordinate must omit those keys entirely.
	b, err := hasher.Marshal(hashed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(b), "local_path") {
		t.Errorf("canonical JSON unexpectedly contains local_path key for a node without one — omitempty regression")
	}
	if strings.Contains(string(b), "original_coordinate") {
		t.Errorf("canonical JSON unexpectedly contains original_coordinate key for a node without one — omitempty regression")
	}
}

func TestWalkRecordHasher_NilFetchRecord(t *testing.T) {
	// A NodeResult with a nil FetchRecord (failure case) must hash without error.
	hasher := domain3.WalkRecordHasher{}
	outcome := domain3.WalkOutcome{
		Target: targetCoord,
		Graph:  domain3.Graph{Target: targetCoord, ResolvedAt: fixedTime, PipelineVersion: "0.2.0"},
		PerNodeResults: map[domain2.ModuleCoordinate]domain3.NodeResult{
			targetCoord: {
				Coordinate: targetCoord,
				Status:     domain3.NodeFetchFailed,
				Error:      &domain3.StoredError{Type: "fetch_failed", Message: "timeout"},
			},
		},
		StartedAt:     fixedTime,
		CompletedAt:   fixedTime.Add(time.Second),
		OverallStatus: domain3.WalkFailed,
	}

	rec := domain3.NewWalkRecord("ZZZZZZZZZZZZZZZZZZZZZZZZ", "bot", "0.2.0", domain3.WalkScopeCode, domain3.WalkDepthFull, outcome, domain3.DefaultDepthPolicy(), "")
	hashed, err := hasher.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash with nil FetchRecord: %v", err)
	}
	if err := hasher.VerifyContentHash(hashed); err != nil {
		t.Fatalf("VerifyContentHash: %v", err)
	}
}
