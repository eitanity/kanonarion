package reachability_test

import (
	"errors"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"

	callgraphdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"

	"github.com/eitanity/kanonarion/internal/vuln/adapters/reachability"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

var callSiteCoord = coordinatetest.MustNew("example.com/dep", "v1.2.3")

// callSiteRecord is a module whose graph holds one direct call, one interface
// dispatch it can attribute to an interface it declares, one reflect edge and
// one reference edge — the four things the annotation has to tell apart.
func callSiteRecord() callgraphdomain.CallGraphRecord {
	return callgraphdomain.CallGraphRecord{
		Completeness: callgraphdomain.CompletenessBuiltWithBodies,
		Nodes: []callgraphdomain.CallNode{
			{ID: "example.com/dep/auto.(*Uploader).upload", Module: "example.com/dep", Package: "example.com/dep/auto"},
			{ID: "example.com/dep/aws.(*S3Client).CurrentID", Module: "example.com/dep", Package: "example.com/dep/aws"},
			{ID: "example.com/dep/auto.helper", Module: "example.com/dep", Package: "example.com/dep/auto"},
			{ID: "example.com/other/pkg.Handler", Module: "example.com/other", Package: "example.com/other/pkg"},
			{ID: "example.com/dep/auto.registered", Module: "example.com/dep", Package: "example.com/dep/auto"},
		},
		Edges: []callgraphdomain.CallEdge{
			{
				FromID:     "example.com/dep/auto.(*Uploader).upload",
				ToID:       "example.com/dep/aws.(*S3Client).CurrentID",
				Confidence: callgraphdomain.ConfidenceCHAOverapprox,
				CallSite:   callgraphdomain.SourcePosition{File: "auto/uploader.go", Line: 167},
			},
			{
				FromID:     "example.com/dep/auto.(*Uploader).upload",
				ToID:       "example.com/dep/auto.helper",
				Confidence: callgraphdomain.ConfidenceDirect,
				CallSite:   callgraphdomain.SourcePosition{File: "auto/uploader.go", Line: 12},
			},
			{
				FromID:          "example.com/dep/auto.(*Uploader).upload",
				ToID:            "example.com/other/pkg.Handler",
				Confidence:      callgraphdomain.ConfidenceUnknown,
				ReflectDispatch: true,
			},
			{
				FromID:     "example.com/dep/auto.(*Uploader).upload",
				ToID:       "example.com/dep/auto.registered",
				Confidence: callgraphdomain.ConfidenceDirect,
				Kind:       callgraphdomain.EdgeKindReference,
			},
			// A second row for a call site already recorded: the ledger keeps one
			// edge per site, so a caller invoking the same callee twice produces two.
			{
				FromID:     "example.com/dep/auto.(*Uploader).upload",
				ToID:       "example.com/dep/auto.helper",
				Confidence: callgraphdomain.ConfidenceDirect,
				CallSite:   callgraphdomain.SourcePosition{File: "auto/uploader.go", Line: 40},
			},
			// An edge out of a caller nobody asked about: it must not reach the answer.
			{
				FromID:     "example.com/dep/aws.(*S3Client).CurrentID",
				ToID:       "example.com/dep/auto.helper",
				Confidence: callgraphdomain.ConfidenceDirect,
			},
		},
		Interfaces: []callgraphdomain.InterfaceType{
			{ID: "example.com/dep/auto.StorageClient", Package: "example.com/dep/auto", Name: "StorageClient", Methods: []string{"CurrentID"}},
		},
		Implementations: []callgraphdomain.InterfaceImplementation{
			{
				InterfaceID: "example.com/dep/auto.StorageClient",
				TypeID:      "example.com/dep/aws.(*S3Client)",
				Methods:     []callgraphdomain.ImplementedMethod{{Method: "CurrentID", NodeID: "example.com/dep/aws.(*S3Client).CurrentID"}},
			},
			{
				InterfaceID: "example.com/dep/auto.StorageClient",
				TypeID:      "example.com/dep/file.(*Client)",
				Methods:     []callgraphdomain.ImplementedMethod{{Method: "CurrentID", NodeID: "example.com/dep/file.(*Client).CurrentID"}},
			},
		},
	}
}

// TestReadCallSites_ReadsTheEdgesOfTheCallersItWasAsked checks the reader
// carries each edge's own fields through untouched, attributes the interface
// from the module's own implementation relation, and answers about the callers
// it was asked for and no others.
func TestReadCallSites_ReadsTheEdgesOfTheCallersItWasAsked(t *testing.T) {
	t.Parallel()

	reader := reachability.NewCallSiteStoreReader(&fakeStore{record: callSiteRecord(), found: true}, "p1")
	answer, err := reader.ReadCallSites(t.Context(), callSiteCoord, []string{"example.com/dep/auto.(*Uploader).upload"})
	if err != nil {
		t.Fatalf("ReadCallSites: %v", err)
	}
	if !answer.Served {
		t.Fatal("a held graph was reported as not served")
	}
	if answer.Completeness != string(callgraphdomain.CompletenessBuiltWithBodies) {
		t.Errorf("the graph's completeness is reported as %q", answer.Completeness)
	}
	if !answer.KnownCallers["example.com/dep/auto.(*Uploader).upload"] {
		t.Error("the caller the graph names is not reported as known")
	}
	if len(answer.Edges) != 4 {
		t.Errorf("the answer carries %d call sites, want the 4 out of the one caller asked about: %v",
			len(answer.Edges), answer.Edges)
	}

	iface := answer.Edges[ports.CallSiteKey{
		FromID: "example.com/dep/auto.(*Uploader).upload",
		ToID:   "example.com/dep/aws.(*S3Client).CurrentID",
	}]
	if iface.Confidence != string(callgraphdomain.ConfidenceCHAOverapprox) {
		t.Errorf("the interface edge's confidence is %q", iface.Confidence)
	}
	if iface.InterfaceID != "example.com/dep/auto.StorageClient" {
		t.Errorf("the interface attributed is %q", iface.InterfaceID)
	}
	if iface.Implementers != 2 {
		t.Errorf("the implementer count is %d, want 2", iface.Implementers)
	}
	if iface.ImplementationModule != "example.com/dep" {
		t.Errorf("the implementation module is %q", iface.ImplementationModule)
	}
	if iface.CallSiteFile != "auto/uploader.go" || iface.CallSiteLine != 167 {
		t.Errorf("the call site is %s:%d", iface.CallSiteFile, iface.CallSiteLine)
	}

	reflectEdge := answer.Edges[ports.CallSiteKey{
		FromID: "example.com/dep/auto.(*Uploader).upload",
		ToID:   "example.com/other/pkg.Handler",
	}]
	if !reflectEdge.ReflectDispatch {
		t.Error("the reflect origin was dropped, which is the only field that tells a reflect edge from an unresolved one")
	}
	if reflectEdge.ImplementationModule != "example.com/other" {
		t.Errorf("the callee's module is reported as %q", reflectEdge.ImplementationModule)
	}

	reference := answer.Edges[ports.CallSiteKey{
		FromID: "example.com/dep/auto.(*Uploader).upload",
		ToID:   "example.com/dep/auto.registered",
	}]
	if !reference.Reference {
		t.Error("a reference edge was carried through as a call")
	}

	// The first row for a repeated call site wins, so the answer does not depend
	// on the order the edges arrive in.
	direct := answer.Edges[ports.CallSiteKey{
		FromID: "example.com/dep/auto.(*Uploader).upload",
		ToID:   "example.com/dep/auto.helper",
	}]
	if direct.CallSiteLine != 12 {
		t.Errorf("the repeated call site resolved to line %d, want the first row's 12", direct.CallSiteLine)
	}
}

// TestReadCallSites_AttributesNoInterfaceWhenTheRelationIsAmbiguous checks the
// recovery refuses rather than picking. The edge does not carry the interface it
// dispatched through, so a callee satisfying two of the module's interfaces at
// the same method leaves nothing to name.
func TestReadCallSites_AttributesNoInterfaceWhenTheRelationIsAmbiguous(t *testing.T) {
	t.Parallel()

	rec := callSiteRecord()
	// A duplicate row for an attribution already held: the ledger can record the
	// same pair twice and it must not become two candidate interfaces.
	rec.Implementations = append(rec.Implementations, rec.Implementations[0])
	rec.Implementations = append(rec.Implementations, callgraphdomain.InterfaceImplementation{
		InterfaceID: "example.com/dep/auto.Identified",
		TypeID:      "example.com/dep/aws.(*S3Client)",
		Methods:     []callgraphdomain.ImplementedMethod{{Method: "CurrentID", NodeID: "example.com/dep/aws.(*S3Client).CurrentID"}},
	})
	reader := reachability.NewCallSiteStoreReader(&fakeStore{record: rec, found: true}, "p1")
	answer, err := reader.ReadCallSites(t.Context(), callSiteCoord, []string{"example.com/dep/auto.(*Uploader).upload"})
	if err != nil {
		t.Fatalf("ReadCallSites: %v", err)
	}
	iface := answer.Edges[ports.CallSiteKey{
		FromID: "example.com/dep/auto.(*Uploader).upload",
		ToID:   "example.com/dep/aws.(*S3Client).CurrentID",
	}]
	if iface.InterfaceID != "" {
		t.Errorf("one of two candidate interfaces was picked: %q", iface.InterfaceID)
	}
	if iface.Confidence != string(callgraphdomain.ConfidenceCHAOverapprox) {
		t.Error("the dispatch itself was dropped along with the attribution")
	}
}

// TestReadCallSites_AbsenceIsNotAnError separates a coordinate the ledger holds
// nothing for — the answer this annotation states as a reason — from a store
// that could not be read, which is a failure and must not read as "no graph".
func TestReadCallSites_AbsenceIsNotAnError(t *testing.T) {
	t.Parallel()

	absent := reachability.NewCallSiteStoreReader(&fakeStore{}, "p1")
	answer, err := absent.ReadCallSites(t.Context(), callSiteCoord, []string{"x"})
	if err != nil {
		t.Fatalf("an absent graph was reported as an error: %v", err)
	}
	if answer.Served {
		t.Error("an absent graph was reported as served")
	}

	boom := errors.New("stored hash does not describe its contents")
	broken := reachability.NewCallSiteStoreReader(&fakeStore{err: boom}, "p1")
	if _, err := broken.ReadCallSites(t.Context(), callSiteCoord, []string{"x"}); !errors.Is(err, boom) {
		t.Errorf("a store failure surfaced as %v", err)
	}
}

// TestReadCallSites_AsksNothingForNothing checks the reader does not serve a
// graph for a question with no subject: a zero coordinate names no module, and
// an empty caller list has no site to look up.
func TestReadCallSites_AsksNothingForNothing(t *testing.T) {
	t.Parallel()

	store := &fakeStore{record: callSiteRecord(), found: true}
	reader := reachability.NewCallSiteStoreReader(store, "p1")

	answer, err := reader.ReadCallSites(t.Context(), coordinate.ModuleCoordinate{}, []string{"x"})
	if err != nil || answer.Served {
		t.Errorf("a zero coordinate produced (%v, served=%t)", err, answer.Served)
	}
	answer, err = reader.ReadCallSites(t.Context(), callSiteCoord, nil)
	if err != nil || answer.Served {
		t.Errorf("an empty caller list produced (%v, served=%t)", err, answer.Served)
	}
}
