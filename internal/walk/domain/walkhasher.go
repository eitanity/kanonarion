package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// WalkRecordHasher computes and embeds a content hash into a WalkRecord.
// The hash is over the canonical JSON serialisation with ContentHash zeroed,
// preventing circular self-reference.
type WalkRecordHasher struct{}

// canonicalWalkRecord is the fixed-field-order struct used for hashing.
// Fields are listed in sorted JSON-key order so json.Marshal produces
// byte-identical output regardless of Go struct field ordering.
//
// Depth uses omitempty: WalkDepthFull is serialised as "" (absent) so that
// records created before the depth field existed continue to verify correctly.
type canonicalWalkRecord struct {
	CompletedAt     string                         `json:"completed_at"`
	ContentHash     string                         `json:"content_hash"`
	Depth           string                         `json:"depth,omitempty"`
	Ecosystem       string                         `json:"ecosystem"`
	Graph           canonicalWalkGraph             `json:"graph"`
	ID              string                         `json:"id"`
	Operator        string                         `json:"operator"`
	OverallStatus   int                            `json:"overall_status"`
	PerNodeResults  []canonicalNodeEntry           `json:"per_node_results"`
	PipelineVersion string                         `json:"pipeline_version"`
	PolicyHash      string                         `json:"policy_hash"`
	PolicyVersion   string                         `json:"policy_version"`
	SchemaVersion   string                         `json:"schema_version"`
	Scope           string                         `json:"scope"`
	StageDepths     map[string]canonicalStageDepth `json:"stage_depths"`
	StartedAt       string                         `json:"started_at"`
	Target          canonicalWalkCoord             `json:"target"`
}

// canonicalStageDepth is the fixed-field-order form of StageDepth.
// Fields are in sorted JSON-key order.
type canonicalStageDepth struct {
	FollowIndirect bool `json:"follow_indirect"`
	FollowReplace  bool `json:"follow_replace"`
	FollowTest     bool `json:"follow_test"`
	MaxDepth       int  `json:"max_depth"`
}

type canonicalWalkGraph struct {
	// BuildEnv is omitempty so records created before the field existed continue
	// to hash and verify identically (a nil pointer is absent from the JSON).
	BuildEnv        *canonicalBuildEnv  `json:"build_env,omitempty"`
	Edges           []canonicalWalkEdge `json:"edges"`
	HasLocalReplace bool                `json:"has_local_replace"`
	Nodes           []canonicalWalkNode `json:"nodes"`
	Partial         bool                `json:"partial"`
	PartialReason   string              `json:"partial_reason"`
	PipelineVersion string              `json:"pipeline_version"`
	ResolvedAt      string              `json:"resolved_at"`
	Target          canonicalWalkCoord  `json:"target"`
}

// canonicalBuildEnv is the fixed-field-order form of BuildEnv, in sorted
// JSON-key order.
type canonicalBuildEnv struct {
	GOARCH    string `json:"goarch"`
	GOOS      string `json:"goos"`
	GoVersion string `json:"go_version"`
}

type canonicalWalkNode struct {
	Coordinate       canonicalWalkCoord `json:"coordinate"`
	DirectDependency bool               `json:"direct_dependency"`
	ErrorDetail      string             `json:"error_detail"`
	// LocalPath is the local filesystem target of a local-replace directive.
	// omitempty so nodes without a local replace produce hashes identical to
	// pre- records.
	LocalPath string `json:"local_path,omitempty"`
	// OriginalCoordinate carries the original require coordinate when this
	// node was produced by a replace directive (ResolutionReplace or
	// ResolutionLocalReplace). Pointer + omitempty so unset values do not
	// appear in the canonical JSON for pre- records.
	OriginalCoordinate *canonicalWalkCoord `json:"original_coordinate,omitempty"`
	ResolutionSource   string              `json:"resolution_source"`
	Retracted          bool                `json:"retracted"`
	// Stdlib carries the standard-library chain-of-custody facts. Pointer +
	// omitempty so every non-stdlib node (and a stdlib node acquired before this
	// field existed) hashes identically to before; when present it is covered by
	// the walk hash.
	Stdlib *canonicalStdlibFacts `json:"stdlib,omitempty"`
	// Raw artefact digests. omitempty so nodes without digests (the local main
	// module, legacy pre-digest records) hash identically to before; when present
	// they are covered by the walk hash.
	ZipSHA256 string `json:"zip_sha256,omitempty"`
	ZipSHA384 string `json:"zip_sha384,omitempty"`
	ZipSHA512 string `json:"zip_sha512,omitempty"`
}

// canonicalStdlibFacts is the fixed-field-order form of StdlibFacts, in sorted
// JSON-key order.
type canonicalStdlibFacts struct {
	LicenseSPDX        string `json:"license_spdx"`
	PublishedSHA256    string `json:"published_sha256"`
	SourceURL          string `json:"source_url"`
	VCSCommit          string `json:"vcs_commit"`
	VCSRef             string `json:"vcs_ref"`
	VCSURL             string `json:"vcs_url"`
	VerificationDetail string `json:"verification_detail"`
	VerificationStatus string `json:"verification_status"`
}

type canonicalWalkEdge struct {
	ConstraintVersion string             `json:"constraint_version"`
	From              canonicalWalkCoord `json:"from"`
	To                canonicalWalkCoord `json:"to"`
}

type canonicalWalkCoord struct {
	Path    string `json:"path"`
	Version string `json:"version"`
}

// canonicalNodeEntry is one element of the per_node_results sorted array.
// PerNodeResults is a map in WalkRecord; the hasher sorts entries by coordinate
// (path, then version) before serialising so the output is always deterministic.
type canonicalNodeEntry struct {
	Coordinate  canonicalWalkCoord  `json:"coordinate"`
	DurationMs  int64               `json:"duration_ms"`
	Error       *canonicalStoredErr `json:"error"`
	FetchRecord json.RawMessage     `json:"fetch_record"`
	FromCache   bool                `json:"from_cache"`
	Status      int                 `json:"status"`
}

type canonicalStoredErr struct {
	Message string `json:"message"`
	Type    string `json:"type"`
}

// SetContentHash computes the canonical hash of r (with ContentHash zeroed),
// sets r.ContentHash, and returns the updated record.
func (WalkRecordHasher) SetContentHash(r WalkRecord) (WalkRecord, error) {
	r.ContentHash = ""
	data, err := marshalCanonicalWalk(r)
	if err != nil {
		return WalkRecord{}, fmt.Errorf("marshalling for hash: %w", err)
	}
	sum := sha256.Sum256(data)
	r.ContentHash = "sha256:" + hex.EncodeToString(sum[:])
	return r, nil
}

// VerifyContentHash re-computes the canonical hash and checks it matches
// r.ContentHash. Returns nil if valid.
func (WalkRecordHasher) VerifyContentHash(r WalkRecord) error {
	saved := r.ContentHash
	r.ContentHash = ""
	data, err := marshalCanonicalWalk(r)
	if err != nil {
		return fmt.Errorf("marshalling for verification: %w", err)
	}
	sum := sha256.Sum256(data)
	expected := "sha256:" + hex.EncodeToString(sum[:])
	if saved != expected {
		return fmt.Errorf("content hash mismatch: stored %q, computed %q", saved, expected)
	}
	return nil
}

// Marshal returns the canonical JSON bytes for a WalkRecord, including its
// ContentHash field. Use SetContentHash before calling this.
func (WalkRecordHasher) Marshal(r WalkRecord) ([]byte, error) {
	return marshalCanonicalWalk(r)
}

func marshalCanonicalWalk(r WalkRecord) ([]byte, error) {
	nodes := canonicalWalkNodes(r.Graph.Nodes)
	edges := canonicalWalkEdges(r.Graph.Edges)

	nodeEntries, err := canonicalNodeResults(r.PerNodeResults)
	if err != nil {
		return nil, fmt.Errorf("canonicalising node results: %w", err)
	}

	stageDepths := make(map[string]canonicalStageDepth, len(r.StageDepths))
	for k, v := range r.StageDepths {
		stageDepths[k] = canonicalStageDepth{
			FollowIndirect: v.FollowIndirect,
			FollowReplace:  v.FollowReplace,
			FollowTest:     v.FollowTest,
			MaxDepth:       v.MaxDepth,
		}
	}

	// WalkDepthFull is serialised as "" (omitempty) so pre-depth records verify correctly.
	depth := string(r.Depth)
	if depth == string(WalkDepthFull) {
		depth = ""
	}

	c := canonicalWalkRecord{
		CompletedAt: r.CompletedAt.UTC().Format(time.RFC3339),
		ContentHash: r.ContentHash,
		Depth:       depth,
		Ecosystem:   r.Ecosystem,
		Graph: canonicalWalkGraph{
			BuildEnv:        toCanonicalBuildEnv(r.Graph.BuildEnv),
			Edges:           edges,
			HasLocalReplace: r.Graph.HasLocalReplace,
			Nodes:           nodes,
			Partial:         r.Graph.Partial,
			PartialReason:   r.Graph.PartialReason,
			PipelineVersion: r.Graph.PipelineVersion,
			ResolvedAt:      r.Graph.ResolvedAt.UTC().Format(time.RFC3339),
			Target:          toCanonicalCoord(r.Graph.Target),
		},
		ID:              r.ID,
		Operator:        r.Operator,
		OverallStatus:   int(r.OverallStatus),
		PerNodeResults:  nodeEntries,
		PipelineVersion: r.PipelineVersion,
		PolicyHash:      r.PolicyHash,
		PolicyVersion:   r.PolicyVersion,
		SchemaVersion:   r.SchemaVersion,
		Scope:           string(r.Scope),
		StageDepths:     stageDepths,
		StartedAt:       r.StartedAt.UTC().Format(time.RFC3339),
		Target:          toCanonicalCoord(r.Target),
	}

	b, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("marshalling canonical walk record: %w", err)
	}
	return b, nil
}

func toCanonicalCoord(c domain2.ModuleCoordinate) canonicalWalkCoord {
	return canonicalWalkCoord{Path: c.Path, Version: c.Version}
}

// fromCanonicalBuildEnv is the inverse of toCanonicalBuildEnv: a nil canonical
// pointer (absent from the JSON) yields the zero BuildEnv.
func fromCanonicalBuildEnv(c *canonicalBuildEnv) BuildEnv {
	if c == nil {
		return BuildEnv{}
	}
	return BuildEnv{GOOS: c.GOOS, GOARCH: c.GOARCH, GoVersion: c.GoVersion}
}

// toCanonicalBuildEnv converts a BuildEnv into its canonical pointer form,
// returning nil for the zero value so the field is omitted from the hash of a
// record that captured no build environment (pre-BuildEnv records and non-project
// walks hash identically to before).
func toCanonicalBuildEnv(e BuildEnv) *canonicalBuildEnv {
	if e.IsZero() {
		return nil
	}
	return &canonicalBuildEnv{
		GOARCH:    e.GOARCH,
		GOOS:      e.GOOS,
		GoVersion: e.GoVersion,
	}
}

// canonicalWalkNodes converts graph nodes into canonical form. The hasher
// sorts them lexicographically by (path, version) so the output is independent
// of whether Graph.Sort has been called.
func canonicalWalkNodes(nodes []GraphNode) []canonicalWalkNode {
	sorted := make([]GraphNode, len(nodes))
	copy(sorted, nodes)
	sort.Slice(sorted, func(i, j int) bool {
		a, b := sorted[i].Coordinate, sorted[j].Coordinate
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Version < b.Version
	})

	out := make([]canonicalWalkNode, len(sorted))
	for i, n := range sorted {
		out[i] = canonicalWalkNode{
			Coordinate:       toCanonicalCoord(n.Coordinate),
			DirectDependency: n.DirectDependency,
			ErrorDetail:      n.ErrorDetail,
			LocalPath:        n.LocalPath,
			ResolutionSource: string(n.ResolutionSource),
			Retracted:        n.Retracted,
			ZipSHA256:        n.Digests.SHA256,
			ZipSHA384:        n.Digests.SHA384,
			ZipSHA512:        n.Digests.SHA512,
		}
		if n.OriginalCoordinate.Path != "" || n.OriginalCoordinate.Version != "" {
			c := toCanonicalCoord(n.OriginalCoordinate)
			out[i].OriginalCoordinate = &c
		}
		out[i].Stdlib = toCanonicalStdlibFacts(n.Stdlib)
	}
	return out
}

// toCanonicalStdlibFacts converts stdlib facts into canonical pointer form,
// returning nil for a nil input so non-stdlib nodes omit the field from the hash.
func toCanonicalStdlibFacts(f *StdlibFacts) *canonicalStdlibFacts {
	if f == nil {
		return nil
	}
	return &canonicalStdlibFacts{
		LicenseSPDX:        f.LicenseSPDX,
		PublishedSHA256:    f.PublishedSHA256,
		SourceURL:          f.SourceURL,
		VCSCommit:          f.VCSCommit,
		VCSRef:             f.VCSRef,
		VCSURL:             f.VCSURL,
		VerificationDetail: f.VerificationDetail,
		VerificationStatus: f.VerificationStatus,
	}
}

// fromCanonicalStdlibFacts is the inverse of toCanonicalStdlibFacts.
func fromCanonicalStdlibFacts(c *canonicalStdlibFacts) *StdlibFacts {
	if c == nil {
		return nil
	}
	return &StdlibFacts{
		LicenseSPDX:        c.LicenseSPDX,
		VerificationStatus: c.VerificationStatus,
		VerificationDetail: c.VerificationDetail,
		PublishedSHA256:    c.PublishedSHA256,
		SourceURL:          c.SourceURL,
		VCSURL:             c.VCSURL,
		VCSRef:             c.VCSRef,
		VCSCommit:          c.VCSCommit,
	}
}

// canonicalWalkEdges converts graph edges into canonical form, sorting by
// (from.path, from.version, to.path, to.version).
func canonicalWalkEdges(edges []GraphEdge) []canonicalWalkEdge {
	sorted := make([]GraphEdge, len(edges))
	copy(sorted, edges)
	sort.Slice(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if a.From.Path != b.From.Path {
			return a.From.Path < b.From.Path
		}
		if a.From.Version != b.From.Version {
			return a.From.Version < b.From.Version
		}
		if a.To.Path != b.To.Path {
			return a.To.Path < b.To.Path
		}
		return a.To.Version < b.To.Version
	})

	out := make([]canonicalWalkEdge, len(sorted))
	for i, e := range sorted {
		out[i] = canonicalWalkEdge{
			ConstraintVersion: e.ConstraintVersion,
			From:              toCanonicalCoord(e.From),
			To:                toCanonicalCoord(e.To),
		}
	}
	return out
}

// canonicalNodeResults converts the per-node results map into a sorted slice
// so the serialised form is independent of map iteration order.
func canonicalNodeResults(results map[domain2.ModuleCoordinate]NodeResult) ([]canonicalNodeEntry, error) {
	keys := make([]domain2.ModuleCoordinate, 0, len(results))
	for k := range results {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Path != keys[j].Path {
			return keys[i].Path < keys[j].Path
		}
		return keys[i].Version < keys[j].Version
	})

	out := make([]canonicalNodeEntry, 0, len(keys))
	for _, k := range keys {
		entry, err := toCanonicalNodeEntry(k, results[k])
		if err != nil {
			return nil, fmt.Errorf("encoding result for %s: %w", k, err)
		}
		out = append(out, entry)
	}
	return out, nil
}

// Unmarshal parses a WalkRecord from its canonical JSON representation.
// It is the inverse of Marshal.
func (WalkRecordHasher) Unmarshal(data []byte) (WalkRecord, error) {
	var c canonicalWalkRecord
	if err := json.Unmarshal(data, &c); err != nil {
		return WalkRecord{}, fmt.Errorf("unmarshalling canonical walk record: %w", err)
	}
	if c.Ecosystem != domain2.EcosystemGo {
		return WalkRecord{}, fmt.Errorf("%w: got %q, want %q", domain2.ErrUnsupportedEcosystem, c.Ecosystem, domain2.EcosystemGo)
	}

	startedAt, err := time.Parse(time.RFC3339, c.StartedAt)
	if err != nil {
		return WalkRecord{}, fmt.Errorf("parsing started_at %q: %w", c.StartedAt, err)
	}
	completedAt, err := time.Parse(time.RFC3339, c.CompletedAt)
	if err != nil {
		return WalkRecord{}, fmt.Errorf("parsing completed_at %q: %w", c.CompletedAt, err)
	}
	resolvedAt, err := time.Parse(time.RFC3339, c.Graph.ResolvedAt)
	if err != nil {
		return WalkRecord{}, fmt.Errorf("parsing graph.resolved_at %q: %w", c.Graph.ResolvedAt, err)
	}

	target, err := domain2.NewModuleCoordinate(c.Target.Path, c.Target.Version)
	if err != nil {
		return WalkRecord{}, fmt.Errorf("parsing target coordinate: %w", err)
	}
	// A walk that failed before the graph was resolved legitimately has no
	// graph target. Treat a fully-empty coordinate as the zero value rather
	// than a fatal parse error, so failed-walk records remain readable.
	var graphTarget domain2.ModuleCoordinate
	if c.Graph.Target.Path != "" || c.Graph.Target.Version != "" {
		graphTarget, err = domain2.NewModuleCoordinate(c.Graph.Target.Path, c.Graph.Target.Version)
		if err != nil {
			return WalkRecord{}, fmt.Errorf("parsing graph target coordinate: %w", err)
		}
	}

	nodes := make([]GraphNode, len(c.Graph.Nodes))
	for i, n := range c.Graph.Nodes {
		coord, nerr := domain2.NewModuleCoordinate(n.Coordinate.Path, n.Coordinate.Version)
		if nerr != nil {
			return WalkRecord{}, fmt.Errorf("parsing node %d coordinate: %w", i, nerr)
		}
		nodes[i] = GraphNode{
			Coordinate:       coord,
			DirectDependency: n.DirectDependency,
			ResolutionSource: ResolutionSource(n.ResolutionSource),
			ErrorDetail:      n.ErrorDetail,
			Retracted:        n.Retracted,
			LocalPath:        n.LocalPath,
			Digests: domain2.ArtifactDigests{
				SHA256: n.ZipSHA256,
				SHA384: n.ZipSHA384,
				SHA512: n.ZipSHA512,
			},
			Stdlib: fromCanonicalStdlibFacts(n.Stdlib),
		}
		if n.OriginalCoordinate != nil {
			oc, oerr := domain2.NewModuleCoordinate(n.OriginalCoordinate.Path, n.OriginalCoordinate.Version)
			if oerr != nil {
				return WalkRecord{}, fmt.Errorf("parsing node %d original coordinate: %w", i, oerr)
			}
			nodes[i].OriginalCoordinate = oc
		}
	}

	edges := make([]GraphEdge, len(c.Graph.Edges))
	for i, e := range c.Graph.Edges {
		from, ferr := domain2.NewModuleCoordinate(e.From.Path, e.From.Version)
		if ferr != nil {
			return WalkRecord{}, fmt.Errorf("parsing edge %d from coordinate: %w", i, ferr)
		}
		to, terr := domain2.NewModuleCoordinate(e.To.Path, e.To.Version)
		if terr != nil {
			return WalkRecord{}, fmt.Errorf("parsing edge %d to coordinate: %w", i, terr)
		}
		edges[i] = GraphEdge{From: from, To: to, ConstraintVersion: e.ConstraintVersion}
	}

	perNode := make(map[domain2.ModuleCoordinate]NodeResult, len(c.PerNodeResults))
	for _, entry := range c.PerNodeResults {
		coord, cerr := domain2.NewModuleCoordinate(entry.Coordinate.Path, entry.Coordinate.Version)
		if cerr != nil {
			return WalkRecord{}, fmt.Errorf("parsing per_node_results coordinate: %w", cerr)
		}
		nr, nerr := unmarshalNodeResult(coord, entry)
		if nerr != nil {
			return WalkRecord{}, fmt.Errorf("parsing node result for %s: %w", coord, nerr)
		}
		perNode[coord] = nr
	}

	stageDepths := make(map[string]StageDepth, len(c.StageDepths))
	for k, v := range c.StageDepths {
		stageDepths[k] = StageDepth{
			MaxDepth:       v.MaxDepth,
			FollowReplace:  v.FollowReplace,
			FollowTest:     v.FollowTest,
			FollowIndirect: v.FollowIndirect,
		}
	}

	scope := WalkScope(c.Scope)
	if scope == "" {
		scope = WalkScopeCode
	}

	// c.Depth is "" for pre-depth records and for full walks (omitempty).
	depth := WalkDepth(c.Depth)
	if depth == "" {
		depth = WalkDepthFull
	}

	return WalkRecord{
		SchemaVersion: c.SchemaVersion,
		Ecosystem:     c.Ecosystem,
		ID:            c.ID,
		Target:        target,
		Scope:         scope,
		Depth:         depth,
		Graph: Graph{
			Target:          graphTarget,
			Nodes:           nodes,
			Edges:           edges,
			ResolvedAt:      resolvedAt.UTC(),
			PipelineVersion: c.Graph.PipelineVersion,
			Partial:         c.Graph.Partial,
			PartialReason:   c.Graph.PartialReason,
			HasLocalReplace: c.Graph.HasLocalReplace,
			BuildEnv:        fromCanonicalBuildEnv(c.Graph.BuildEnv),
		},
		PerNodeResults:  perNode,
		StartedAt:       startedAt.UTC(),
		CompletedAt:     completedAt.UTC(),
		OverallStatus:   WalkStatus(c.OverallStatus),
		PipelineVersion: c.PipelineVersion,
		PolicyVersion:   c.PolicyVersion,
		PolicyHash:      c.PolicyHash,
		StageDepths:     stageDepths,
		Operator:        c.Operator,
		ContentHash:     c.ContentHash,
	}, nil
}

func unmarshalNodeResult(coord domain2.ModuleCoordinate, entry canonicalNodeEntry) (NodeResult, error) {
	nr := NodeResult{
		Coordinate: coord,
		Status:     NodeStatus(entry.Status),
		FromCache:  entry.FromCache,
		DurationMs: entry.DurationMs,
	}
	if entry.Error != nil {
		nr.Error = &StoredError{Type: entry.Error.Type, Message: entry.Error.Message}
	}
	if entry.FetchRecord != nil && string(entry.FetchRecord) != "null" {
		rec, err := domain2.CanonicalHasher{}.Unmarshal(entry.FetchRecord)
		if err != nil {
			return NodeResult{}, fmt.Errorf("unmarshalling fetch record: %w", err)
		}
		nr.FetchRecord = &rec
	}
	return nr, nil
}

func toCanonicalNodeEntry(coord domain2.ModuleCoordinate, r NodeResult) (canonicalNodeEntry, error) {
	var fetchRaw json.RawMessage
	if r.FetchRecord != nil {
		b, err := domain2.CanonicalHasher{}.Marshal(*r.FetchRecord)
		if err != nil {
			return canonicalNodeEntry{}, fmt.Errorf("marshalling fetch record: %w", err)
		}
		fetchRaw = b
	} else {
		fetchRaw = json.RawMessage("null")
	}

	var storedErr *canonicalStoredErr
	if r.Error != nil {
		storedErr = &canonicalStoredErr{
			Message: r.Error.Message,
			Type:    r.Error.Type,
		}
	}

	return canonicalNodeEntry{
		Coordinate:  toCanonicalCoord(coord),
		DurationMs:  r.DurationMs,
		Error:       storedErr,
		FetchRecord: fetchRaw,
		FromCache:   r.FromCache,
		Status:      int(r.Status),
	}, nil
}
