package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

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
	coord, err := coordinate.NewModuleCoordinate(c.Coordinate.Path, c.Coordinate.Version)
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
			UsesPlugin:           cn.UsesPlugin,
			IsTest:               cn.IsTest,
		}
	}
	var ifaces []InterfaceType
	if len(c.Interfaces) > 0 {
		ifaces = make([]InterfaceType, len(c.Interfaces))
		for i, ci := range c.Interfaces {
			ifaces[i] = InterfaceType{
				ID:       ci.ID,
				Package:  ci.Package,
				Name:     ci.Name,
				Methods:  ci.Methods,
				Position: SourcePosition{File: ci.Position.File, Line: ci.Position.Line},
				IsTest:   ci.IsTest,
			}
		}
	}
	var impls []InterfaceImplementation
	if len(c.Implementations) > 0 {
		impls = make([]InterfaceImplementation, len(c.Implementations))
		for i, ci := range c.Implementations {
			// The wire and domain shapes are deliberately separate types; the
			// conversion is legal only while their fields coincide, so a change
			// to either stops compiling here rather than silently re-encoding.
			methods := make([]ImplementedMethod, len(ci.Methods))
			for j, m := range ci.Methods {
				methods[j] = ImplementedMethod(m)
			}
			impls[i] = InterfaceImplementation{
				InterfaceID: ci.InterfaceID,
				TypeID:      ci.TypeID,
				Package:     ci.Package,
				Position:    SourcePosition{File: ci.Position.File, Line: ci.Position.Line},
				IsTest:      ci.IsTest,
				Methods:     methods,
			}
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
			Kind:            EdgeKind(ce.Kind),
		}
	}
	return CallGraphRecord{
		SchemaVersion:     c.SchemaVersion,
		Ecosystem:         c.Ecosystem,
		Coordinate:        coord,
		Algorithm:         CallGraphAlgorithm(c.Algorithm),
		ArtifactKind:      ArtifactKind(c.ArtifactKind),
		Completeness:      CompletenessLevel(c.Completeness),
		Nodes:             nodes,
		Edges:             edges,
		Interfaces:        ifaces,
		Implementations:   impls,
		TestScope:         TestScope(c.TestScope),
		TestScopeDetail:   c.TestScopeDetail,
		ReferenceScope:    ReferenceScope(c.ReferenceScope),
		OverallStatus:     CallGraphStatus(c.OverallStatus),
		FailureCause:      FailureCause(c.FailureCause),
		FailureDetail:     c.FailureDetail,
		FailedPackages:    c.FailedPackages,
		ExclusionReason:   c.ExclusionReason,
		ExclusionList:     c.ExclusionList,
		NodeCount:         c.NodeCount,
		EdgeCount:         c.EdgeCount,
		ExtractedAt:       extractedAt.UTC(),
		PipelineVersion:   c.PipelineVersion,
		ContentHash:       c.ContentHash,
		ArtefactIdentity:  c.ArtefactIdentity,
		SourceContentHash: c.SourceContentHash,
		AnalysisSource:    AnalysisSource(c.AnalysisSource),
		WorktreeDigest:    c.WorktreeDigest,
		AnalysisRoot:      c.AnalysisRoot,
		BuildListSource:   c.BuildListSource,
		SynthesisedGoMod: SynthesisedGoMod{
			ModulePath:        c.SynthesisedGoMod.ModulePath,
			GoDirective:       c.SynthesisedGoMod.GoDirective,
			VendorTreePresent: c.SynthesisedGoMod.VendorTreePresent,
			Requires:          domainRequires(c.SynthesisedGoMod.Requires),
		},
	}, nil
}

// canonicalRequires renders the pinned require directives onto the wire, keeping
// nil as nil so a module that needed none marshals to the bytes it always did.
func canonicalRequires(reqs []SynthesisedRequire) []canonicalRequire {
	if len(reqs) == 0 {
		return nil
	}
	out := make([]canonicalRequire, 0, len(reqs))
	for _, r := range reqs {
		// The wire and domain shapes are deliberately separate types; the conversion
		// is legal only while their fields coincide, so a field added to either
		// stops compiling here rather than silently changing what stored records
		// hash over. Same rule as canonicalImplementation's methods above.
		out = append(out, canonicalRequire(r))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// domainRequires reads the pinned require directives back off the wire.
func domainRequires(reqs []canonicalRequire) []SynthesisedRequire {
	if len(reqs) == 0 {
		return nil
	}
	out := make([]SynthesisedRequire, 0, len(reqs))
	for _, r := range reqs {
		out = append(out, SynthesisedRequire(r))
	}
	return out
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
	IsTest               bool         `json:"is_test"`
	Module               string       `json:"module"`
	Package              string       `json:"package"`
	Position             canonicalPos `json:"position"`
	Receiver             string       `json:"receiver"`
	Symbol               string       `json:"symbol"`
	UsesPlugin           bool         `json:"uses_plugin"`
	UsesUnsafePointer    bool         `json:"uses_unsafe_pointer"`
}

type canonicalInterface struct {
	ID       string       `json:"id"`
	IsTest   bool         `json:"is_test"`
	Methods  []string     `json:"methods"`
	Name     string       `json:"name"`
	Package  string       `json:"package"`
	Position canonicalPos `json:"position"`
}

type canonicalImplMethod struct {
	Method string `json:"method"`
	NodeID string `json:"node_id"`
}

type canonicalImplementation struct {
	InterfaceID string                `json:"interface_id"`
	IsTest      bool                  `json:"is_test"`
	Methods     []canonicalImplMethod `json:"methods"`
	Package     string                `json:"package"`
	Position    canonicalPos          `json:"position"`
	TypeID      string                `json:"type_id"`
}

type canonicalEdge struct {
	CallSite   canonicalPos `json:"call_site"`
	Confidence string       `json:"confidence"`
	FromID     string       `json:"from_id"`
	// Kind is omitted for a call edge, which is what every edge sealed before
	// the kind existed is. See EdgeKind.
	Kind            string `json:"kind,omitempty"`
	ReflectDispatch bool   `json:"reflect_dispatch"`
	ToID            string `json:"to_id"`
}

type canonicalRecord struct {
	Algorithm string `json:"algorithm"`
	// AnalysisSource and WorktreeDigest are omitted when empty so records written
	// before the analysis source was named keep their stored content hash
	// verifiable, on the same terms every additive field on this shape has used.
	// An absent analysis_source is the "not recorded" value, not a fourth source.
	AnalysisSource string `json:"analysis_source,omitempty"`
	ArtifactKind   string `json:"artifact_kind,omitempty"`
	Completeness   string `json:"completeness,omitempty"`
	// ArtefactIdentity and SourceContentHash are omitted when empty so
	// records that predate them keep their stored content hash verifiable,
	// on the same terms every additive field on this shape has used.
	ArtefactIdentity string `json:"artefact_identity,omitempty"`
	// BuildListSource is omitted when empty on the same terms: no record written
	// before the field existed was offered a build list, so absent is the truth
	// about it rather than an unrecorded third state.
	BuildListSource string          `json:"build_list_source,omitzero"`
	ContentHash     string          `json:"content_hash"`
	Coordinate      canonicalCoord  `json:"coordinate"`
	Ecosystem       string          `json:"ecosystem"`
	EdgeCount       int             `json:"edge_count"`
	Edges           []canonicalEdge `json:"edges"`
	ExclusionList   []string        `json:"exclusion_list,omitempty"`
	ExclusionReason string          `json:"exclusion_reason,omitempty"`
	ExtractedAt     string          `json:"extracted_at"`
	FailedPackages  []string        `json:"failed_packages,omitempty"`
	// FailureCause is omitted when zero so a record written before the cause axis
	// existed — and every record that did not fail, which is almost all of them —
	// marshals to exactly the bytes it always did and keeps its stored content
	// hash verifiable. That is what lets the axis land without a PipelineVersion
	// bump or a purge, on the same terms every additive field on this shape has
	// used. An absent failure_cause is the "not recorded" value, not a third
	// cause.
	FailureCause  string `json:"failure_cause,omitzero"`
	FailureDetail string `json:"failure_detail"`
	// Implementations and Interfaces are omitted when empty so a module that
	// declares no interfaces hashes the same as one analysed before the axis
	// existed would have — the same terms every additive field here has used.
	Implementations   []canonicalImplementation `json:"implementations,omitempty"`
	Interfaces        []canonicalInterface      `json:"interfaces,omitempty"`
	NodeCount         int                       `json:"node_count"`
	Nodes             []canonicalNode           `json:"nodes"`
	OverallStatus     int                       `json:"overall_status"`
	PipelineVersion   string                    `json:"pipeline_version"`
	SchemaVersion     string                    `json:"schema_version"`
	SourceContentHash string                    `json:"source_content_hash,omitempty"`
	// SynthesisedGoMod is omitted when zero so every record sealed before the
	// field existed marshals to exactly the bytes it always did and keeps its
	// stored content hash verifiable — the terms every additive field on this
	// shape has used. An absent value is not "unrecorded": nothing synthesised a
	// go.mod before this field, so absent means the published tree was analysed
	// as published.
	SynthesisedGoMod canonicalSynthesisedGoMod `json:"synthesised_go_mod,omitzero"`
	// ReferenceScope is omitted when unmeasured, which is the truth about every
	// record sealed before reference edges were extracted.
	ReferenceScope  string `json:"reference_scope,omitempty"`
	TestScope       string `json:"test_scope,omitempty"`
	TestScopeDetail string `json:"test_scope_detail,omitempty"`
	WorktreeDigest  string `json:"worktree_digest,omitempty"`
	// AnalysisRoot is omitted when empty, on the terms every additive field on
	// this shape has used: no record written before it stated where its tree was,
	// so absent is the truth about one rather than an unrecorded third state, and
	// every stored record re-marshals to the bytes it was sealed over.
	//
	// It IS inside the sealed shape, which matters for a reason the omission
	// argument does not cover: two checkouts of one module path can hold trees
	// whose contents are identical, and without the root in the hash they would
	// carry one content hash — a primary-key column — and collapse onto one row.
	// The thing that makes them two trees is exactly the field being added.
	AnalysisRoot string `json:"analysis_root,omitempty"`
}

// canonicalSynthesisedGoMod is the wire shape of domain.SynthesisedGoMod. It is
// a separate type on purpose: the sealed bytes are pinned here, so a field added
// to the domain type does not silently change what every stored record hashes
// over.
type canonicalSynthesisedGoMod struct {
	GoDirective string `json:"go_directive"`
	ModulePath  string `json:"module_path"`
	// Requires is omitted when empty so every record sealed while synthesis could
	// only ever produce a require-less file marshals to exactly the bytes it was
	// sealed over. An absent list means the module needed none.
	Requires          []canonicalRequire `json:"requires,omitzero"`
	VendorTreePresent bool               `json:"vendor_tree_present"`
}

// canonicalRequire is the wire shape of domain.SynthesisedRequire.
type canonicalRequire struct {
	Path    string `json:"path"`
	Version string `json:"version"`
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
			IsTest:               n.IsTest,
			Receiver:             n.Receiver,
			Symbol:               n.Symbol,
			UsesPlugin:           n.UsesPlugin,
			UsesUnsafePointer:    n.UsesUnsafePointer,
		}
	}
	cEdges := make([]canonicalEdge, len(edges))
	for i, e := range edges {
		cEdges[i] = canonicalEdge{
			CallSite:        canonicalPos{File: e.CallSite.File, Line: e.CallSite.Line},
			Confidence:      string(e.Confidence),
			FromID:          e.FromID,
			Kind:            string(e.Kind),
			ReflectDispatch: e.ReflectDispatch,
			ToID:            e.ToID,
		}
	}

	var cIfaces []canonicalInterface
	if len(r.Interfaces) > 0 {
		ifaces := make([]InterfaceType, len(r.Interfaces))
		copy(ifaces, r.Interfaces)
		sort.Slice(ifaces, func(i, j int) bool { return ifaces[i].ID < ifaces[j].ID })
		cIfaces = make([]canonicalInterface, len(ifaces))
		for i, it := range ifaces {
			methods := make([]string, len(it.Methods))
			copy(methods, it.Methods)
			sort.Strings(methods)
			cIfaces[i] = canonicalInterface{
				ID:       it.ID,
				IsTest:   it.IsTest,
				Methods:  methods,
				Name:     it.Name,
				Package:  it.Package,
				Position: canonicalPos{File: it.Position.File, Line: it.Position.Line},
			}
		}
	}

	var cImpls []canonicalImplementation
	if len(r.Implementations) > 0 {
		impls := make([]InterfaceImplementation, len(r.Implementations))
		copy(impls, r.Implementations)
		sort.Slice(impls, func(i, j int) bool {
			if impls[i].InterfaceID != impls[j].InterfaceID {
				return impls[i].InterfaceID < impls[j].InterfaceID
			}
			return impls[i].TypeID < impls[j].TypeID
		})
		cImpls = make([]canonicalImplementation, len(impls))
		for i, im := range impls {
			methods := make([]ImplementedMethod, len(im.Methods))
			copy(methods, im.Methods)
			sort.Slice(methods, func(a, b int) bool { return methods[a].Method < methods[b].Method })
			cm := make([]canonicalImplMethod, len(methods))
			for j, m := range methods {
				cm[j] = canonicalImplMethod(m)
			}
			cImpls[i] = canonicalImplementation{
				InterfaceID: im.InterfaceID,
				IsTest:      im.IsTest,
				Methods:     cm,
				Package:     im.Package,
				Position:    canonicalPos{File: im.Position.File, Line: im.Position.Line},
				TypeID:      im.TypeID,
			}
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
		Algorithm:         string(r.Algorithm),
		AnalysisSource:    string(r.AnalysisSource),
		ArtefactIdentity:  r.ArtefactIdentity,
		ArtifactKind:      string(r.ArtifactKind),
		Completeness:      string(r.Completeness),
		ContentHash:       r.ContentHash,
		Coordinate:        canonicalCoord{Path: r.Coordinate.Path(), Version: r.Coordinate.Version()},
		Ecosystem:         r.Ecosystem,
		EdgeCount:         r.EdgeCount,
		Edges:             cEdges,
		ExclusionList:     exclusions,
		ExclusionReason:   r.ExclusionReason,
		ExtractedAt:       r.ExtractedAt.UTC().Format(time.RFC3339),
		FailedPackages:    failedPkgs,
		FailureCause:      string(r.FailureCause),
		FailureDetail:     r.FailureDetail,
		Implementations:   cImpls,
		Interfaces:        cIfaces,
		NodeCount:         r.NodeCount,
		Nodes:             cNodes,
		OverallStatus:     int(r.OverallStatus),
		PipelineVersion:   r.PipelineVersion,
		SchemaVersion:     r.SchemaVersion,
		SourceContentHash: r.SourceContentHash,
		BuildListSource:   r.BuildListSource,
		SynthesisedGoMod: canonicalSynthesisedGoMod{
			GoDirective:       r.SynthesisedGoMod.GoDirective,
			ModulePath:        r.SynthesisedGoMod.ModulePath,
			Requires:          canonicalRequires(r.SynthesisedGoMod.Requires),
			VendorTreePresent: r.SynthesisedGoMod.VendorTreePresent,
		},
		ReferenceScope:  string(r.ReferenceScope),
		TestScope:       string(r.TestScope),
		TestScopeDetail: r.TestScopeDetail,
		WorktreeDigest:  r.WorktreeDigest,
		AnalysisRoot:    r.AnalysisRoot,
	}
	b, err := canonicalMarshal(c)
	if err != nil {
		return nil, fmt.Errorf("marshalling canonical callgraph record: %w", err)
	}
	return b, nil
}

// canonicalMarshal is a seam over json.Marshal used to test the
// marshal-failure guard's wrapping and propagation logic. No field in
// canonicalRecord can currently make json.Marshal fail (no NaN/Inf floats,
// no unsupported types), so this proves the guard's error handling is
// correct, not that the guard is reachable with a real value today — it
// exists for the never-silent-failure invariant, not a known failure mode.
var canonicalMarshal = json.Marshal
