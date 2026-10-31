package cyclonedx_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"code.eitanity.com/kanonarion/internal/coordinate"
	"code.eitanity.com/kanonarion/internal/sbom/adapters/generator/cyclonedx"

	licensedomain "code.eitanity.com/kanonarion/internal/license/domain"
	nativedomain "code.eitanity.com/kanonarion/internal/native/domain"
	vendordomain "code.eitanity.com/kanonarion/internal/vendortree/domain"
	walkdomain "code.eitanity.com/kanonarion/internal/walk/domain"
)

// serialOf returns a document's serialNumber, failing unless it is an RFC 4122
// version-5 UUID URN.
func serialOf(t *testing.T, content []byte) string {
	t.Helper()
	var doc struct {
		SerialNumber string `json:"serialNumber"`
		Version      int    `json:"version"`
	}
	if err := json.Unmarshal(content, &doc); err != nil {
		t.Fatalf("unmarshal bom: %v", err)
	}
	u, err := uuid.Parse(doc.SerialNumber)
	if err != nil || !strings.HasPrefix(doc.SerialNumber, "urn:uuid:") {
		t.Fatalf("serialNumber %q is not a UUID URN: %v", doc.SerialNumber, err)
	}
	if u.Version() != 5 || u.Variant() != uuid.RFC4122 {
		t.Errorf("serialNumber %q is version %d variant %s, want an RFC 4122 version-5 UUID", doc.SerialNumber, u.Version(), u.Variant())
	}
	if doc.Version != 1 {
		t.Errorf("version = %d, want 1", doc.Version)
	}
	return doc.SerialNumber
}

// Three different documents from one walk — the whole walk, a narrower
// component set and a supplied creation time — carry three serials, and each
// regenerates with its own serial byte for byte. A consumer keeps one document
// per serial, so a shared serial would let it discard a different document.
func TestGenerate_SerialIdentifiesTheDocumentsContent(t *testing.T) {
	a := mustCoord(t, "example.com/a", "v1.0.0")
	b := mustCoord(t, "example.com/b", "v1.0.0")
	whole := makeWalk(t, []coordinate.ModuleCoordinate{a, b})
	scoped := makeWalk(t, []coordinate.ModuleCoordinate{a})
	scoped.ID = whole.ID
	gen := cyclonedx.New(testPipelineVersion)
	generate := func(w walkdomain.WalkRecord, ts string) string {
		t.Helper()
		req := makeGenReq()
		if ts != "" {
			req.DocumentTimestamp = mustTime(ts)
		}
		first, err := gen.Generate(t.Context(), w, nil, req)
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		again, err := gen.Generate(t.Context(), w, nil, req)
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if string(first.Content) != string(again.Content) {
			t.Error("regenerating from the same inputs changed the document")
		}
		return serialOf(t, first.Content)
	}
	serials := map[string]string{
		"whole walk":    generate(whole, ""),
		"scoped":        generate(scoped, ""),
		"supplied time": generate(whole, "2026-01-31T09:00:00Z"),
	}
	seen := map[string]string{}
	for name, s := range serials {
		if other, dup := seen[s]; dup {
			t.Errorf("the %s and %s documents share serial %s", name, other, s)
		}
		seen[s] = name
	}
}

// The tools entry and every annotator name the binary's release, never the
// pipeline version the record is cached under.
func TestGenerate_ToolAndAnnotatorsCarryTheToolVersion(t *testing.T) {
	const tool = "v9.9.9-tool"
	a := mustCoord(t, "example.com/a", "v1.0.0")
	walk := makeWalk(t, []coordinate.ModuleCoordinate{a})
	req := makeGenReq()
	req.VendorScope = &vendordomain.VendorScope{TreeModules: 1, Covered: 1}
	rec, err := cyclonedx.New(tool).Generate(t.Context(), walk, nil, req)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var doc struct {
		Metadata struct {
			Tools struct {
				Components []struct {
					Version string `json:"version"`
				} `json:"components"`
			} `json:"tools"`
		} `json:"metadata"`
		Annotations []struct {
			BOMRef    string `json:"bom-ref"`
			Annotator struct {
				Component struct {
					Version string `json:"version"`
				} `json:"component"`
			} `json:"annotator"`
		} `json:"annotations"`
	}
	if err := json.Unmarshal(rec.Content, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Metadata.Tools.Components) != 1 || doc.Metadata.Tools.Components[0].Version != tool {
		t.Errorf("tools = %+v, want one entry at %s", doc.Metadata.Tools.Components, tool)
	}
	if len(doc.Annotations) != 2 {
		t.Fatalf("annotations = %+v, want the vendor scope and licence completeness", doc.Annotations)
	}
	for _, an := range doc.Annotations {
		if an.Annotator.Component.Version != tool {
			t.Errorf("annotation %s annotator version = %q, want %s", an.BOMRef, an.Annotator.Component.Version, tool)
		}
	}
	if strings.Contains(string(rec.Content), testPipelineVersion) {
		t.Errorf("the document states the pipeline version %s", testPipelineVersion)
	}
}

// removedProperties are kanonarion's internal state and prose that the document
// once carried as properties; the whole kanonarion:tinygo:custody: set is
// checked by prefix.
var removedProperties = []string{
	"kanonarion:pipeline_version",
	"kanonarion:document:timestamp_basis",
	"kanonarion:licence:newest_extraction",
	"kanonarion:stdlib:verification",
	"kanonarion:stdlib:verification_detail",
	"kanonarion:stdlib:published_sha256",
	"kanonarion:stdlib:anchor_limitation",
	"kanonarion:native:generation",
	"kanonarion:native:confidence",
	"kanonarion:native:advisories_searched",
	"kanonarion:native:licence_determined",
	"kanonarion:build:goos",
	"kanonarion:build:goarch",
	"kanonarion:build:go_version",
}

// A document holding every kind of component — module, stdlib with its
// custody, TinyGo with its custody and a native library — states none of the
// removed properties, on any component or on the document.
func TestGenerate_StatesNoInternalProperty(t *testing.T) {
	walk := walkWithStdlibCustody(t)
	dep := mustCoord(t, "github.com/mattn/go-sqlite3", "v1.14.12")
	tg := mustCoord(t, walkdomain.TinyGoModulePath, "v0.42.0")
	walk.Graph.Nodes = append(walk.Graph.Nodes,
		walkdomain.GraphNode{Coordinate: dep, ResolutionSource: walkdomain.ResolutionTarget},
		walkdomain.GraphNode{Coordinate: tg, ResolutionSource: walkdomain.ResolutionTinyGo,
			TinyGo: &walkdomain.TinyGoFacts{Target: "pico", Packages: []string{"machine"}, Custody: &walkdomain.TinyGoCustody{
				Module: "github.com/tinygo-org/tinygo@v0.42.0", ModuleVerification: "Verified",
				ReleaseAsset: "tinygo.tar.gz", ReleaseOutcome: walkdomain.TinyGoReleaseDigestMatched, VerifiedByModule: 1,
			}}})
	req := makeGenReq()
	req.NativeRecords = map[coordinate.ModuleCoordinate]nativedomain.Record{dep: identifiedRecord(dep, "3.38.0")}
	rec, err := cyclonedx.New(testPipelineVersion).Generate(t.Context(), walk,
		map[coordinate.ModuleCoordinate]licensedomain.LicenseRecord{dep: {PrimarySPDX: "MIT"}}, req)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(rec.Content, &doc); err != nil {
		t.Fatal(err)
	}
	var names []string
	collect := func(v any) {
		for _, p := range optAs[[]any](t, v) {
			names = append(names, mustAs[string](t, mustAs[map[string]any](t, p)["name"]))
		}
	}
	metadata := mustAs[map[string]any](t, doc["metadata"])
	collect(metadata["properties"])
	collect(mustAs[map[string]any](t, metadata["component"])["properties"])
	kinds := map[string]bool{}
	for _, c := range mustAs[[]any](t, doc["components"]) {
		comp := mustAs[map[string]any](t, c)
		kinds[mustAs[string](t, comp["name"])] = true
		collect(comp["properties"])
	}
	for _, want := range []string{walkdomain.StdlibModulePath, walkdomain.TinyGoModulePath, "SQLite"} {
		if !kinds[want] {
			t.Fatalf("the document holds no %s component to check", want)
		}
	}
	for _, name := range names {
		for _, removed := range removedProperties {
			if name == removed {
				t.Errorf("the document states %s", name)
			}
		}
		if strings.HasPrefix(name, "kanonarion:tinygo:custody:") {
			t.Errorf("the document states %s", name)
		}
	}
}
