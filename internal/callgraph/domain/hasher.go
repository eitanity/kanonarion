package domain

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// CallGraphRecordHasher computes and embeds a content hash into a CallGraphRecord.
// The hash covers the canonical JSON serialisation with ContentHash zeroed.
type CallGraphRecordHasher struct{}

// SetContentHash computes the canonical hash of r (with ContentHash zeroed),
// sets r.ContentHash, and returns the updated record.
func (CallGraphRecordHasher) SetContentHash(r CallGraphRecord) (CallGraphRecord, error) {
	r.ContentHash = ""
	data, err := marshalCanonical(r)
	if err != nil {
		return CallGraphRecord{}, fmt.Errorf("marshalling for hash: %w", err)
	}
	sum := sha256.Sum256(data)
	r.ContentHash = "sha256:" + hex.EncodeToString(sum[:])
	return r, nil
}

// VerifyContentHash re-computes the canonical hash and checks it matches
// r.ContentHash. Returns nil if valid.
func (CallGraphRecordHasher) VerifyContentHash(r CallGraphRecord) error {
	saved := r.ContentHash
	r.ContentHash = ""
	data, err := marshalCanonical(r)
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

// VerifyBlobHash verifies the content hash directly against the raw serialised
// blob, zeroing the content_hash value in-place rather than deserializing and
// re-serializing the full record. This is the fast path for read verification.
func (CallGraphRecordHasher) VerifyBlobHash(blob []byte, storedHash string) error {
	return verifyBlobHash(blob, storedHash)
}

// Marshal returns the canonical JSON bytes for a CallGraphRecord, including
// its ContentHash field. Call SetContentHash before this.
func (CallGraphRecordHasher) Marshal(r CallGraphRecord) ([]byte, error) {
	return marshalCanonical(r)
}

// Unmarshal parses a CallGraphRecord from its canonical JSON representation.
func (CallGraphRecordHasher) Unmarshal(data []byte) (CallGraphRecord, error) {
	var c canonicalRecord
	if err := json.Unmarshal(data, &c); err != nil {
		return CallGraphRecord{}, fmt.Errorf("unmarshalling canonical callgraph record: %w", err)
	}
	if c.Ecosystem != fetchdomain.EcosystemGo {
		return CallGraphRecord{}, fmt.Errorf("%w: got %q, want %q", fetchdomain.ErrUnsupportedEcosystem, c.Ecosystem, fetchdomain.EcosystemGo)
	}
	extractedAt, err := time.Parse(time.RFC3339, c.ExtractedAt)
	if err != nil {
		return CallGraphRecord{}, fmt.Errorf("parsing extracted_at %q: %w", c.ExtractedAt, err)
	}
	coord, err := fetchdomain.NewModuleCoordinate(c.Coordinate.Path, c.Coordinate.Version)
	if err != nil {
		return CallGraphRecord{}, fmt.Errorf("parsing coordinate: %w", err)
	}
	nodes := make([]CallNode, len(c.Nodes))
	for i, cn := range c.Nodes {
		nodes[i] = CallNode{
			ID:                   cn.ID,
			Module:               cn.Module,
			Package:              cn.Package,
			Symbol:               cn.Symbol,
			Receiver:             cn.Receiver,
			IsExternal:           cn.IsExternal,
			IsExportedAPI:        cn.IsExportedAPI,
			Position:             SourcePosition{File: cn.Position.File, Line: cn.Position.Line},
			UsesUnsafePointer:    cn.UsesUnsafePointer,
			IsAssemblyOrLinkname: cn.IsAssemblyOrLinkname,
		}
	}
	edges := make([]CallEdge, len(c.Edges))
	for i, ce := range c.Edges {
		edges[i] = CallEdge{
			FromID:          ce.FromID,
			ToID:            ce.ToID,
			CallSite:        SourcePosition{File: ce.CallSite.File, Line: ce.CallSite.Line},
			Confidence:      EdgeConfidence(ce.Confidence),
			ReflectDispatch: ce.ReflectDispatch,
		}
	}
	return CallGraphRecord{
		SchemaVersion:   c.SchemaVersion,
		Ecosystem:       c.Ecosystem,
		Coordinate:      coord,
		Algorithm:       CallGraphAlgorithm(c.Algorithm),
		Completeness:    CompletenessLevel(c.Completeness),
		Nodes:           nodes,
		Edges:           edges,
		OverallStatus:   CallGraphStatus(c.OverallStatus),
		FailureDetail:   c.FailureDetail,
		FailedPackages:  c.FailedPackages,
		ExclusionReason: c.ExclusionReason,
		ExclusionList:   c.ExclusionList,
		NodeCount:       c.NodeCount,
		EdgeCount:       c.EdgeCount,
		ExtractedAt:     extractedAt.UTC(),
		PipelineVersion: c.PipelineVersion,
		ContentHash:     c.ContentHash,
	}, nil
}

// verifyBlobHash hashes blob after zeroing the content_hash JSON value in-place.
// Checks both internal consistency (hash embedded in blob matches content) and
// DB-level consistency (DB column matches content). The blob must be valid
// canonical JSON produced by Marshal.
func verifyBlobHash(blob []byte, storedHash string) error {
	const key = `"content_hash":"`
	idx := bytes.Index(blob, []byte(key))
	if idx < 0 {
		return fmt.Errorf("content_hash field not found in blob")
	}
	valueStart := idx + len(key)
	rel := bytes.IndexByte(blob[valueStart:], '"')
	if rel < 0 {
		return fmt.Errorf("content_hash value not terminated in blob")
	}
	valueEnd := valueStart + rel
	blobHash := string(blob[valueStart:valueEnd])
	zeroed := make([]byte, 0, len(blob)-(valueEnd-valueStart))
	zeroed = append(zeroed, blob[:valueStart]...)
	zeroed = append(zeroed, blob[valueEnd:]...)
	sum := sha256.Sum256(zeroed)
	expected := "sha256:" + hex.EncodeToString(sum[:])
	if blobHash != expected {
		return fmt.Errorf("content hash mismatch: blob has %q, computed %q", blobHash, expected)
	}
	if storedHash != expected {
		return fmt.Errorf("content hash mismatch: stored %q, computed %q", storedHash, expected)
	}
	return nil
}

// -- canonical wire types --

type canonicalCoord struct {
	Path    string `json:"path"`
	Version string `json:"version"`
}

type canonicalPos struct {
	File string `json:"file"`
	Line int    `json:"line"`
}

type canonicalNode struct {
	ID                   string       `json:"id"`
	IsAssemblyOrLinkname bool         `json:"is_assembly_or_linkname"`
	IsExportedAPI        bool         `json:"is_exported_api"`
	IsExternal           bool         `json:"is_external"`
	Module               string       `json:"module"`
	Package              string       `json:"package"`
	Position             canonicalPos `json:"position"`
	Receiver             string       `json:"receiver"`
	Symbol               string       `json:"symbol"`
	UsesUnsafePointer    bool         `json:"uses_unsafe_pointer"`
}

type canonicalEdge struct {
	CallSite        canonicalPos `json:"call_site"`
	Confidence      string       `json:"confidence"`
	FromID          string       `json:"from_id"`
	ReflectDispatch bool         `json:"reflect_dispatch"`
	ToID            string       `json:"to_id"`
}

type canonicalRecord struct {
	Algorithm       string          `json:"algorithm"`
	Completeness    string          `json:"completeness,omitempty"`
	ContentHash     string          `json:"content_hash"`
	Coordinate      canonicalCoord  `json:"coordinate"`
	Ecosystem       string          `json:"ecosystem"`
	EdgeCount       int             `json:"edge_count"`
	Edges           []canonicalEdge `json:"edges"`
	ExclusionList   []string        `json:"exclusion_list,omitempty"`
	ExclusionReason string          `json:"exclusion_reason,omitempty"`
	ExtractedAt     string          `json:"extracted_at"`
	FailedPackages  []string        `json:"failed_packages,omitempty"`
	FailureDetail   string          `json:"failure_detail"`
	NodeCount       int             `json:"node_count"`
	Nodes           []canonicalNode `json:"nodes"`
	OverallStatus   int             `json:"overall_status"`
	PipelineVersion string          `json:"pipeline_version"`
	SchemaVersion   string          `json:"schema_version"`
}

func marshalCanonical(r CallGraphRecord) ([]byte, error) {
	nodes := make([]CallNode, len(r.Nodes))
	copy(nodes, r.Nodes)
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })

	edges := make([]CallEdge, len(r.Edges))
	copy(edges, r.Edges)
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].FromID != edges[j].FromID {
			return edges[i].FromID < edges[j].FromID
		}
		if edges[i].ToID != edges[j].ToID {
			return edges[i].ToID < edges[j].ToID
		}
		if edges[i].CallSite.File != edges[j].CallSite.File {
			return edges[i].CallSite.File < edges[j].CallSite.File
		}
		return edges[i].CallSite.Line < edges[j].CallSite.Line
	})

	cNodes := make([]canonicalNode, len(nodes))
	for i, n := range nodes {
		cNodes[i] = canonicalNode{
			ID:                   n.ID,
			IsAssemblyOrLinkname: n.IsAssemblyOrLinkname,
			IsExportedAPI:        n.IsExportedAPI,
			IsExternal:           n.IsExternal,
			Module:               n.Module,
			Package:              n.Package,
			Position:             canonicalPos{File: n.Position.File, Line: n.Position.Line},
			Receiver:             n.Receiver,
			Symbol:               n.Symbol,
			UsesUnsafePointer:    n.UsesUnsafePointer,
		}
	}
	cEdges := make([]canonicalEdge, len(edges))
	for i, e := range edges {
		cEdges[i] = canonicalEdge{
			CallSite:        canonicalPos{File: e.CallSite.File, Line: e.CallSite.Line},
			Confidence:      string(e.Confidence),
			FromID:          e.FromID,
			ReflectDispatch: e.ReflectDispatch,
			ToID:            e.ToID,
		}
	}

	var exclusions []string
	if len(r.ExclusionList) > 0 {
		exclusions = make([]string, len(r.ExclusionList))
		copy(exclusions, r.ExclusionList)
		sort.Strings(exclusions)
	}

	var failedPkgs []string
	if len(r.FailedPackages) > 0 {
		failedPkgs = make([]string, len(r.FailedPackages))
		copy(failedPkgs, r.FailedPackages)
		sort.Strings(failedPkgs)
	}

	c := canonicalRecord{
		Algorithm:       string(r.Algorithm),
		Completeness:    string(r.Completeness),
		ContentHash:     r.ContentHash,
		Coordinate:      canonicalCoord{Path: r.Coordinate.Path, Version: r.Coordinate.Version},
		Ecosystem:       r.Ecosystem,
		EdgeCount:       r.EdgeCount,
		Edges:           cEdges,
		ExclusionList:   exclusions,
		ExclusionReason: r.ExclusionReason,
		ExtractedAt:     r.ExtractedAt.UTC().Format(time.RFC3339),
		FailedPackages:  failedPkgs,
		FailureDetail:   r.FailureDetail,
		NodeCount:       r.NodeCount,
		Nodes:           cNodes,
		OverallStatus:   int(r.OverallStatus),
		PipelineVersion: r.PipelineVersion,
		SchemaVersion:   r.SchemaVersion,
	}
	b, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("marshalling canonical callgraph record: %w", err)
	}
	return b, nil
}
